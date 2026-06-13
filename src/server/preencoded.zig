//! # Pre-encoded HTTP/1.1 response cache
//!
//! A small cache of HTTP/1.1 responses whose wire bytes are encoded
//! once at server init and refreshed lazily once per second to track
//! the `Date` header. Two uses:
//!   - Common error responses (404, 400, 431, 413), so the error
//!     path skips the response encoder.
//!   - An optional hot-response register API, for callers that want
//!     specific endpoints served from a pre-encoded template.
//!
//! On a cache hit the router, the middleware chain, and the response
//! encoder are all skipped: the fast path reduces to a URL/status
//! match + memcpy + enqueueWrite.
//!
//! The whole cache is opt-in and off by default; nothing is
//! registered unless a caller asks for it (error responses aside).
//!
//! The backing storage lives on `Server` — `h1_preencoded[]` and
//! `h1_error_cache[]` — because it's tied to the Server's lifetime.
//! The helpers here take `server: *Server` and operate on those
//! arrays by reference.

const std = @import("std");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const response_mod = @import("../response/response.zig");
const http1 = @import("http1.zig");
const middleware = @import("../middleware/middleware.zig");
const connection = @import("../runtime/connection.zig");
const request = @import("../protocol/request.zig");

/// Maximum number of hot HTTP/1.1 endpoints that can have pre-encoded
/// response bytes cached on the Server.
pub const MAX_H1_PREENCODED: usize = 12;

/// Size of each pre-encoded h1 response's byte buffer. 1024 is plenty
/// for a tiny hot endpoint: status line + headers + Date + Alt-Svc +
/// body fits comfortably in ~300-400 bytes. Larger static files don't
/// belong in this cache — they use the mmap path.
pub const H1_PREENCODED_BUF_SIZE: usize = 1024;

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
pub const PreencodedH1Response = struct {
    method: []const u8,
    path: []const u8,
    status: u16,
    static_headers: []const response_mod.Header,
    body: []const u8,
    bytes: [H1_PREENCODED_BUF_SIZE]u8 = undefined,
    len: usize = 0,
    close_bytes: [H1_PREENCODED_BUF_SIZE]u8 = undefined,
    close_len: usize = 0,
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

// ==================== HTTP/1.1 ====================

/// Populate the h1 pre-encoded response cache. By default this only
/// registers common error responses; hot endpoints are opt-in via
/// `registerPreencodedH1`.
pub fn initPreencodedH1(server: *Server) void {
    const plaintext_headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "text/plain" },
    };

    // Pre-encode common error responses so the error-handling path
    // skips encodeResponseHeaders entirely. Match the ROUTER's
    // response format (Content-Type: text/plain).
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
            if (server.cached_date_epoch != entry.epoch) rebuildPreencodedH1(server, entry);
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
    entry.close_len = http1.encodeResponse(&entry.close_bytes, resp, alt_svc, true, date_str) catch 0;
    entry.epoch = server.cached_date_epoch;
}

pub fn findAndRefreshPreencodedH1(server: *Server, method: []const u8, path: []const u8) ?*PreencodedH1Response {
    var i: usize = 0;
    while (i < server.h1_preencoded_count) : (i += 1) {
        const entry = &server.h1_preencoded[i];
        if (std.mem.eql(u8, entry.method, method) and std.mem.eql(u8, entry.path, path)) {
            if (server.cached_date_epoch != entry.epoch) rebuildPreencodedH1(server, entry);
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
    if (req_view.method != .GET) return .not_cached;
    if (server.app_router.has_any_paid_routes) return .not_cached;
    if (findAndRefreshPreencodedH1(server, "GET", req_view.path)) |entry| {
        const resp_bytes = if (conn.close_after_write)
            entry.close_bytes[0..entry.close_len]
        else
            entry.bytes[0..entry.len];
        if (resp_bytes.len == 0) return .not_cached;
        if (sendH1PreencodedBytes(server, conn, resp_bytes))
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
    // Coalesce: if the last write queue entry has room, append
    // instead of acquiring a new buffer. Pipelined pre-encoded
    // responses (~200-300 bytes each) can pack ~200 per 64KB
    // buffer, eliminating per-response buffer acquire/release.
    // Never append while a sendfile body is pending: the last entry would
    // be a static response's headers and these bytes would precede its
    // file body on the wire (the dispatch pipeline loop also guards this).
    if (conn.peekLastWrite()) |entry| {
        if (entry.offset == 0 and !conn.hasPendingFile() and entry.len + bytes.len <= entry.handle.bytes.len) {
            @memcpy(entry.handle.bytes[entry.len..][0..bytes.len], bytes);
            entry.len += bytes.len;
            server.io.onWriteBuffered(conn, bytes.len);
            return true;
        }
    }

    const buf = server.io.acquireBuffer() orelse return false;
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
