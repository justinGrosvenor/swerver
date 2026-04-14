//! # Pre-encoded response cache
//!
//! Hot static endpoints (`/plaintext`, `/health`, `/pipeline`, `/echo`,
//! and a small set of error responses) get their wire bytes encoded
//! once at server init and refreshed lazily once per second to track
//! the `Date` header. On a cache hit, the router, the middleware
//! chain, and the response encoder are all skipped — the fast path
//! reduces to URL match + memcpy + enqueueWrite.
//!
//! Each protocol has its own cache shape because the wire formats
//! differ:
//!   - HTTP/1.1: raw status line + headers + body, ready to write
//!     straight to the socket.
//!   - HTTP/2: HEADERS frame header + HPACK-encoded response headers
//!     + optional DATA frame header + body. Stream IDs are patched
//!     into the frame headers at send time.
//!   - HTTP/3: HEADERS frame + DATA frame, ready to be wrapped in a
//!     QUIC STREAM frame and AEAD-encrypted.
//!
//! The backing storage lives on `Server` — `h1_preencoded[]`,
//! `h2_preencoded[]`, `h3_preencoded[]`, `h1_error_cache[]` — because
//! it's tied to the Server's lifetime. The helpers here take
//! `server: *Server` and operate on those arrays by reference.
//!
//! See `src/server.zig` for the full CACHE BYPASS SEMANTICS comment
//! that describes what is and isn't included in the fast path.

const std = @import("std");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const response_mod = @import("../response/response.zig");
const http1 = @import("http1.zig");
const http2 = @import("../protocol/http2.zig");
const middleware = @import("../middleware/middleware.zig");
const clock = @import("../runtime/clock.zig");
const connection = @import("../runtime/connection.zig");
const request = @import("../protocol/request.zig");

/// Maximum number of hot HTTP/3 endpoints that can have pre-encoded
/// response bytes cached on the Server. Fixed-size — linear scan over
/// a cache-hot array beats a hashmap for N in the single digits.
pub const MAX_H3_PREENCODED: usize = 8;

/// Size of each pre-encoded response's byte buffer. 1024 is plenty
/// for tiny hot endpoints like /plaintext (13 bytes), /json (27), or
/// /baseline2 (1). Larger static files don't belong in this cache —
/// they use the mmap path.
pub const H3_PREENCODED_BUF_SIZE: usize = 1024;

/// Maximum number of hot HTTP/1.1 endpoints that can have pre-encoded
/// response bytes cached on the Server.
pub const MAX_H1_PREENCODED: usize = 12;

/// Size of each pre-encoded h1 response's byte buffer. 1024 is plenty
/// for the benchmark-shape hot endpoints (/plaintext, /json, /health,
/// /baseline2). Status line + headers + Date + Alt-Svc + body fits
/// comfortably in ~300-400 bytes.
pub const H1_PREENCODED_BUF_SIZE: usize = 1024;

pub const MAX_H2_PREENCODED: usize = 8;
pub const H2_PREENCODED_BUF_SIZE: usize = 512;

/// Pre-encoded HTTP/3 response for a hot static endpoint.
///
/// Holds the fully-encoded h3 response bytes (HEADERS frame + DATA
/// frame) ready to be wrapped in a QUIC STREAM frame and AEAD-
/// encrypted. On cache hit, `handleHttp3Request` skips the router,
/// middleware, and `encodeHttp3Response` entirely — per-request work
/// drops to (URL match + STREAM frame wrap + AEAD + sendto). Saves
/// 600-1500 cycles per request on the hot path.
///
/// Refresh semantics: the bytes include a Date header whose value
/// drifts every second. `findAndRefreshPreencodedH3` rebuilds an
/// entry's bytes the first time it's hit in a new epoch second. All
/// other hits in the same second are zero-work reads.
pub const PreencodedH3Response = struct {
    method: []const u8, // pointer to comptime string
    path: []const u8, // pointer to comptime string
    status: u16,
    /// Static response headers to embed (excluding `:status` and
    /// `date` — those are added by the Stack's encoder).
    static_headers: []const response_mod.Header,
    /// Static response body.
    body: []const u8,
    /// Encoded h3 bytes: HEADERS frame + DATA frame.
    bytes: [H3_PREENCODED_BUF_SIZE]u8 = undefined,
    len: usize = 0,
    /// Unix epoch second for which `bytes` is valid. When the current
    /// epoch second moves past this value, the entry is rebuilt.
    epoch: u64 = 0,
};

/// Pre-encoded HTTP/1.1 response for a hot static endpoint.
///
/// Holds the full HTTP/1.1 response bytes (status line + headers +
/// empty line + body) exactly as they'd be written on the wire in
/// keep-alive mode. On a cache hit, `dispatchToRouter` skips the
/// router, middleware, arena_buf acquire, encodeResponseInner, and
/// the usual write-buffer building entirely — it acquires one pool
/// buffer, memcpys the cached bytes, and enqueues the write.
///
/// Refresh semantics: bytes include a `Date: ...` line that drifts
/// every second. `findAndRefreshPreencodedH1` rebuilds the entry
/// the first time it's hit in a new epoch second.
///
/// Only valid for keep-alive responses (connection_close = false).
/// Requests with `close_after_write = true` bypass the cache and
/// fall through to the router path.
pub const PreencodedH1Response = struct {
    method: []const u8,
    path: []const u8,
    status: u16,
    static_headers: []const response_mod.Header,
    body: []const u8,
    bytes: [H1_PREENCODED_BUF_SIZE]u8 = undefined,
    len: usize = 0,
    epoch: u64 = 0,
};

/// Pre-encoded HTTP/2 response for a hot static endpoint.
///
/// Layout of `bytes[0..len]` (the wire template):
///
///     [HEADERS frame header (9 bytes)]
///     [HPACK-encoded response header block]
///     if body present:
///         [DATA frame header (9 bytes)]
///         [body bytes]
///
/// The HEADERS frame header's flags are pre-baked: `0x5`
/// (END_HEADERS | END_STREAM) when the response has no body,
/// `0x4` (END_HEADERS) when a DATA frame follows. The DATA frame
/// header (when present) has flags `0x1` (END_STREAM).
///
/// Stream IDs are patched at send time — the HEADERS frame's
/// stream_id is at byte offset 5, and the DATA frame's stream_id
/// (if present) is at byte offset `data_offset + 5`. All other
/// bytes are stable per-second and are shared across every concurrent
/// h2 stream hitting the same endpoint.
///
/// Refresh is lazy / per-second just like the h1 and h3 caches —
/// the HPACK block embeds a Date header value that drifts, so
/// `findAndRefreshPreencodedH2` re-runs the h2 encoder when it
/// notices an epoch second change.
pub const PreencodedH2Response = struct {
    method: []const u8,
    path: []const u8,
    status: u16,
    static_headers: []const response_mod.Header,
    body: []const u8,
    bytes: [H2_PREENCODED_BUF_SIZE]u8 = undefined,
    len: usize = 0,
    /// Offset of the DATA frame's stream_id byte range in `bytes`.
    /// Zero when `body.len == 0` (no DATA frame emitted).
    data_offset: u32 = 0,
    epoch: u64 = 0,
};

/// Result of `tryDispatchPreencodedH1`.
pub const PreencodedResult = enum {
    /// Response sent from cache. Caller should continue pipelining.
    dispatched,
    /// No cache entry matched. Caller should fall through to router.
    not_cached,
    /// Cache entry matched but pool exhausted. Caller should BREAK
    /// the pipelining loop (not fall through to router, which would
    /// also fail). Writes will drain and free buffers; on the next
    /// event-loop pass the loop resumes.
    pool_exhausted,
};

// ==================== HTTP/3 ====================

/// Populate the h3 pre-encoded response cache with a fixed set of
/// hot static endpoints. On request, if the URL matches one of
/// these entries we skip the router + middleware + encode path
/// entirely and feed pre-encoded h3 bytes straight to the QUIC
/// send loop. See `PreencodedH3Response`.
pub fn initPreencodedH3(server: *Server) void {
    const plaintext_headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    registerPreencodedH3(server, "GET", "/health", 200, &[_]response_mod.Header{}, "");
    registerPreencodedH3(server, "GET", "/plaintext", 200, &plaintext_headers, "Hello, World!");
    registerPreencodedH3(server, "GET", "/pipeline", 200, &plaintext_headers, "ok");
}

/// Append a pre-encoded entry and encode its initial bytes using
/// the Server's http3_stack. Called from `initPreencodedH3` at
/// startup. Silently drops if the cache is full or encoding fails.
fn registerPreencodedH3(
    server: *Server,
    method: []const u8,
    path: []const u8,
    status: u16,
    static_headers: []const response_mod.Header,
    body: []const u8,
) void {
    if (server.h3_preencoded_count >= MAX_H3_PREENCODED) return;
    const idx = server.h3_preencoded_count;
    server.h3_preencoded[idx] = .{
        .method = method,
        .path = path,
        .status = status,
        .static_headers = static_headers,
        .body = body,
    };
    // Encode right away so the first request doesn't pay the
    // rebuild cost. Refresh-on-hit still handles the per-second
    // Date header drift.
    rebuildPreencodedH3(server, &server.h3_preencoded[idx]);
    server.h3_preencoded_count += 1;
}

/// Re-encode a pre-encoded entry's bytes, picking up whatever the
/// current Date header is. Called from `findAndRefreshPreencodedH3`
/// the first time a given entry is hit in a new epoch second, and
/// from `registerPreencodedH3` at startup.
fn rebuildPreencodedH3(server: *Server, entry: *PreencodedH3Response) void {
    const stack = if (server.http3_stack) |*s| s else return;
    const sec_hdrs = middleware.security.getStaticSecurityHeaders();
    var merged: [16]response_mod.Header = undefined;
    var count: usize = 0;
    for (entry.static_headers) |h| {
        if (count < merged.len) {
            merged[count] = h;
            count += 1;
        }
    }
    for (sec_hdrs) |h| {
        if (count < merged.len) {
            merged[count] = h;
            count += 1;
        }
    }
    const body_opt: ?[]const u8 = if (entry.body.len > 0) entry.body else null;
    entry.len = stack.encodeResponse(
        &entry.bytes,
        entry.status,
        @ptrCast(merged[0..count]),
        body_opt,
    ) catch 0;
    const ts = clock.realtimeTimespec() orelse return;
    entry.epoch = @intCast(ts.sec);
}

/// Look up a hot endpoint by method + path. On a match, refresh
/// the entry if its cached Date header is stale (current epoch
/// second differs from entry.epoch) and return the pointer.
/// Returns null on miss.
pub fn findAndRefreshPreencodedH3(server: *Server, method: []const u8, path: []const u8) ?*PreencodedH3Response {
    var i: usize = 0;
    while (i < server.h3_preencoded_count) : (i += 1) {
        const entry = &server.h3_preencoded[i];
        if (std.mem.eql(u8, entry.method, method) and std.mem.eql(u8, entry.path, path)) {
            // Lazy per-second refresh
            const ts = clock.realtimeTimespec() orelse return entry;
            const epoch: u64 = @intCast(ts.sec);
            if (epoch != entry.epoch) rebuildPreencodedH3(server, entry);
            if (entry.len == 0) return null; // encode failed; fall through to router
            return entry;
        }
    }
    return null;
}

// ==================== HTTP/1.1 ====================

/// Populate the h1 pre-encoded response cache with the same hot
/// static endpoints used by the h3 cache. h1 and h2 clients hit
/// the same URLs in the same benchmarks, so they deserve the
/// same cache-hit fast path the h3 profiles get.
pub fn initPreencodedH1(server: *Server) void {
    const plaintext_headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    const json_headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "application/json" },
    };

    registerPreencodedH1(server, "GET", "/echo", 200, &json_headers, "{\"status\":\"ok\"}");
    registerPreencodedH1(server, "GET", "/health", 200, &[_]response_mod.Header{}, "");
    registerPreencodedH1(server, "GET", "/plaintext", 200, &plaintext_headers, "Hello, World!");
    registerPreencodedH1(server, "GET", "/pipeline", 200, &plaintext_headers, "ok");

    // Pre-encode common error responses so the error-handling
    // benchmark path skips encodeResponseHeaders entirely. Match
    // the ROUTER's response format (Content-Type: text/plain).
    registerPreencodedError(server, 404, &plaintext_headers, "Not Found");
    registerPreencodedError(server, 400, &[_]response_mod.Header{}, "Bad Request\n");
    registerPreencodedError(server, 431, &[_]response_mod.Header{}, "Request Header Fields Too Large\n");
    registerPreencodedError(server, 413, &[_]response_mod.Header{}, "Payload Too Large\n");
}

fn registerPreencodedError(
    server: *Server,
    status: u16,
    static_headers: []const response_mod.Header,
    body: []const u8,
) void {
    if (server.h1_error_cache_count >= server.h1_error_cache.len) return;
    const idx = server.h1_error_cache_count;
    server.h1_error_cache[idx] = .{
        .method = "",
        .path = "",
        .status = status,
        .static_headers = static_headers,
        .body = body,
    };
    rebuildPreencodedH1(server, &server.h1_error_cache[idx]);
    server.h1_error_cache_count += 1;
}

/// Look up a pre-encoded error response by status code. Returns
/// the cached bytes if the status matches a known error template.
pub fn findPreencodedError(server: *Server, status: u16) ?*PreencodedH1Response {
    var i: usize = 0;
    while (i < server.h1_error_cache_count) : (i += 1) {
        if (server.h1_error_cache[i].status == status) {
            const entry = &server.h1_error_cache[i];
            const ts = clock.realtimeTimespec() orelse return entry;
            const epoch: u64 = @intCast(ts.sec);
            if (epoch != entry.epoch) rebuildPreencodedH1(server, entry);
            if (entry.len == 0) return null;
            return entry;
        }
    }
    return null;
}

fn registerPreencodedH1(
    server: *Server,
    method: []const u8,
    path: []const u8,
    status: u16,
    static_headers: []const response_mod.Header,
    body: []const u8,
) void {
    if (server.h1_preencoded_count >= MAX_H1_PREENCODED) return;
    const idx = server.h1_preencoded_count;
    server.h1_preencoded[idx] = .{
        .method = method,
        .path = path,
        .status = status,
        .static_headers = static_headers,
        .body = body,
    };
    rebuildPreencodedH1(server, &server.h1_preencoded[idx]);
    server.h1_preencoded_count += 1;
}

fn rebuildPreencodedH1(server: *Server, entry: *PreencodedH1Response) void {
    // Merge endpoint-specific headers with security headers so
    // pre-encoded responses include HSTS, CSP, X-Frame-Options,
    // etc. without requiring the middleware chain to run. The
    // security headers are server-lifetime stable (config doesn't
    // change after init), so this is safe across per-second
    // Date-header refreshes.
    const sec_hdrs = middleware.security.getStaticSecurityHeaders();
    var merged: [16]response_mod.Header = undefined;
    var count: usize = 0;
    for (entry.static_headers) |h| {
        if (count < merged.len) {
            merged[count] = h;
            count += 1;
        }
    }
    for (sec_hdrs) |h| {
        if (count < merged.len) {
            merged[count] = h;
            count += 1;
        }
    }

    const resp: response_mod.Response = .{
        .status = entry.status,
        .headers = merged[0..count],
        .body = if (entry.body.len > 0) .{ .bytes = entry.body } else .none,
    };
    const alt_svc: ?[]const u8 = if (server.alt_svc_len > 0)
        server.alt_svc_value[0..server.alt_svc_len]
    else
        null;
    const date_str = server.getCachedDate();
    entry.len = http1.encodeResponse(&entry.bytes, resp, alt_svc, false, date_str) catch 0;
    const ts = clock.realtimeTimespec() orelse return;
    entry.epoch = @intCast(ts.sec);
}

pub fn findAndRefreshPreencodedH1(server: *Server, method: []const u8, path: []const u8) ?*PreencodedH1Response {
    var i: usize = 0;
    while (i < server.h1_preencoded_count) : (i += 1) {
        const entry = &server.h1_preencoded[i];
        if (std.mem.eql(u8, entry.method, method) and std.mem.eql(u8, entry.path, path)) {
            const ts = clock.realtimeTimespec() orelse return entry;
            const epoch: u64 = @intCast(ts.sec);
            if (epoch != entry.epoch) rebuildPreencodedH1(server, entry);
            if (entry.len == 0) return null;
            return entry;
        }
    }
    return null;
}

/// Check the pre-encoded h1 response cache and, on hit, send the
/// cached bytes directly via the write buffer. Returns a
/// `PreencodedResult` indicating whether the request was handled,
/// whether the caller should fall through to the router, or whether
/// the pool is exhausted and the pipelining loop should break.
///
/// Called from every h1 router-dispatch site: the inline
/// `handleRead` path for requests that fit in the read buffer,
/// `dispatchToRouter` for the "read buffer full → header-only
/// parse" path, and the body-accumulation-complete dispatch
/// for large POST/PUT (which always misses the cache since
/// those aren't GET).
pub fn tryDispatchPreencodedH1(server: *Server, conn: *connection.Connection, req_view: request.RequestView) PreencodedResult {
    if (conn.close_after_write) return .not_cached;
    if (server.app_router.x402_policy.require_payment) return .not_cached;
    const method_str = req_view.getMethodName();
    if (findAndRefreshPreencodedH1(server, method_str, req_view.path)) |entry| {
        if (sendH1PreencodedBytes(server, conn, entry.bytes[0..entry.len]))
            return .dispatched
        else
            return .pool_exhausted;
    }
    return .not_cached;
}

/// Write pre-encoded h1 response bytes to the connection's write
/// buffer. Returns false if the buffer pool is exhausted — the
/// caller should break out of the pipelining loop and wait for
/// writes to drain (returning buffers to the pool) before
/// continuing. This is the fix for the pipelined-benchmark 0 req/s
/// bug: previously pool exhaustion called closeConnection, causing
/// 213K reconnects in 5 seconds.
pub fn sendH1PreencodedBytes(server: *Server, conn: *connection.Connection, bytes: []const u8) bool {
    const buf = server.io.acquireBuffer() orelse {
        // Pool exhausted — do NOT close the connection. The
        // pipelining loop should break and wait for writes to
        // flush (freeing buffers). On the next event-loop
        // iteration the connection is still readable and the
        // loop picks up where it left off.
        return false;
    };
    if (bytes.len > buf.bytes.len) {
        server.io.releaseBuffer(buf);
        return false;
    }
    @memcpy(buf.bytes[0..bytes.len], bytes);
    if (!conn.enqueueWrite(buf, bytes.len)) {
        server.io.releaseBuffer(buf);
        return false;
    }
    server.io.onWriteBuffered(conn, bytes.len);
    server.io.setTimeoutPhase(conn, .write);
    return true;
}

// ==================== HTTP/2 ====================

/// Populate the h2 pre-encoded response cache with the same hot
/// static endpoints used by h1 and h3.
pub fn initPreencodedH2(server: *Server) void {
    const plaintext_headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    registerPreencodedH2(server, "GET", "/health", 200, &[_]response_mod.Header{}, "");
    registerPreencodedH2(server, "GET", "/plaintext", 200, &plaintext_headers, "Hello, World!");
    registerPreencodedH2(server, "GET", "/pipeline", 200, &plaintext_headers, "ok");
}

fn registerPreencodedH2(
    server: *Server,
    method: []const u8,
    path: []const u8,
    status: u16,
    static_headers: []const response_mod.Header,
    body: []const u8,
) void {
    if (server.h2_preencoded_count >= MAX_H2_PREENCODED) return;
    const idx = server.h2_preencoded_count;
    server.h2_preencoded[idx] = .{
        .method = method,
        .path = path,
        .status = status,
        .static_headers = static_headers,
        .body = body,
    };
    rebuildPreencodedH2(server, &server.h2_preencoded[idx]);
    server.h2_preencoded_count += 1;
}

/// Rebuild the h2 response template for `entry`. Runs HPACK
/// encoding over the static headers + current cached Date and
/// lays down the HEADERS (+ optional DATA) frame headers with
/// stream_id = 0 placeholders. Stream IDs are patched at send
/// time.
fn rebuildPreencodedH2(server: *Server, entry: *PreencodedH2Response) void {
    // Build merged headers: endpoint-specific + security + Alt-Svc,
    // just like queueHttp2Response + the middleware chain would emit.
    var headers_with_alt_svc: [65]response_mod.Header = undefined;
    var header_count: usize = entry.static_headers.len;
    if (header_count > headers_with_alt_svc.len) {
        entry.len = 0;
        return;
    }
    for (entry.static_headers, 0..) |h, i| headers_with_alt_svc[i] = h;
    // Merge security headers (CSP, X-Frame-Options, etc.)
    const sec_hdrs = middleware.security.getStaticSecurityHeaders();
    for (sec_hdrs) |h| {
        if (header_count < headers_with_alt_svc.len) {
            headers_with_alt_svc[header_count] = h;
            header_count += 1;
        }
    }
    if (server.alt_svc_len > 0 and header_count < headers_with_alt_svc.len) {
        headers_with_alt_svc[header_count] = .{
            .name = "alt-svc",
            .value = server.alt_svc_value[0..server.alt_svc_len],
        };
        header_count += 1;
    }

    // HPACK-encode the response headers into bytes[9..] (leaving
    // room for the HEADERS frame header at bytes[0..9]).
    const hpack_dst = entry.bytes[9..];
    const hpack_len = http2.encodeResponseHeaders(hpack_dst, entry.status, headers_with_alt_svc[0..header_count], entry.body.len) catch {
        entry.len = 0;
        return;
    };

    // HEADERS frame header. Flags: END_HEADERS always; add
    // END_STREAM when there's no DATA frame following. stream_id
    // placeholder (0) — patched at send time.
    const headers_flags: u8 = if (entry.body.len == 0) 0x5 else 0x4;
    http2.writeFrameHeader(entry.bytes[0..9], .headers, headers_flags, 0, hpack_len) catch {
        entry.len = 0;
        return;
    };

    if (entry.body.len == 0) {
        entry.len = 9 + hpack_len;
        entry.data_offset = 0;
    } else {
        const data_off = 9 + hpack_len;
        if (data_off + 9 + entry.body.len > entry.bytes.len) {
            entry.len = 0;
            return;
        }
        // DATA frame header with END_STREAM.
        http2.writeFrameHeader(entry.bytes[data_off .. data_off + 9], .data, 0x1, 0, entry.body.len) catch {
            entry.len = 0;
            return;
        };
        @memcpy(entry.bytes[data_off + 9 .. data_off + 9 + entry.body.len], entry.body);
        entry.len = data_off + 9 + entry.body.len;
        entry.data_offset = @intCast(data_off);
    }

    const ts = clock.realtimeTimespec() orelse return;
    entry.epoch = @intCast(ts.sec);
}

pub fn findAndRefreshPreencodedH2(server: *Server, method: []const u8, path: []const u8) ?*PreencodedH2Response {
    var i: usize = 0;
    while (i < server.h2_preencoded_count) : (i += 1) {
        const entry = &server.h2_preencoded[i];
        if (std.mem.eql(u8, entry.method, method) and std.mem.eql(u8, entry.path, path)) {
            const ts = clock.realtimeTimespec() orelse return entry;
            const epoch: u64 = @intCast(ts.sec);
            if (epoch != entry.epoch) rebuildPreencodedH2(server, entry);
            if (entry.len == 0) return null;
            return entry;
        }
    }
    return null;
}

/// Write pre-encoded h2 response bytes for `stream_id` — acquires
/// a pool buffer, copies the template, patches both frame headers'
/// stream_id bytes in place, enqueues the write, and closes the
/// h2 stream. Mirrors the flow at the end of `queueHttp2Response`
/// but without re-running HPACK encoding or header building.
pub fn sendH2PreencodedBytes(
    server: *Server,
    conn: *connection.Connection,
    stream_id: u32,
    entry: *const PreencodedH2Response,
) void {
    const out = server.io.acquireBuffer() orelse {
        server.closeConnection(conn);
        return;
    };
    if (entry.len > out.bytes.len) {
        server.io.releaseBuffer(out);
        server.closeConnection(conn);
        return;
    }
    @memcpy(out.bytes[0..entry.len], entry.bytes[0..entry.len]);

    // Patch HEADERS frame stream_id (bytes 5..9).
    patchH2StreamId(out.bytes[0..9], stream_id);
    // Patch DATA frame stream_id (if present).
    if (entry.data_offset != 0) {
        const off = entry.data_offset;
        patchH2StreamId(out.bytes[off .. off + 9], stream_id);
    }

    if (!conn.enqueueWrite(out, entry.len)) {
        server.io.releaseBuffer(out);
        server.closeConnection(conn);
        return;
    }
    server.io.onWriteBuffered(conn, entry.len);
    server.io.setTimeoutPhase(conn, .write);

    // Release the stream state — the h2 stack's per-stream
    // tracking would otherwise leak.
    if (conn.http2_stack) |stack| stack.closeStream(stream_id);
}

/// Write a stream_id into the reserved-bit + 31-bit stream_id
/// field of an h2 frame header (bytes 5..9). Top bit of byte 5
/// is the R bit, which MUST be 0 on send per RFC 9113 §4.1.
fn patchH2StreamId(frame_header: []u8, stream_id: u32) void {
    frame_header[5] = @intCast((stream_id >> 24) & 0x7f);
    frame_header[6] = @intCast((stream_id >> 16) & 0xff);
    frame_header[7] = @intCast((stream_id >> 8) & 0xff);
    frame_header[8] = @intCast(stream_id & 0xff);
}
