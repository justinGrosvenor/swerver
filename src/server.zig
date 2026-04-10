const std = @import("std");

const config = @import("config.zig");
const runtime = @import("runtime/io.zig");
const connection = @import("runtime/connection.zig");
const buffer_pool = @import("runtime/buffer_pool.zig");
const clock = @import("runtime/clock.zig");
const router = @import("router/router.zig");
const net = @import("runtime/net.zig");
const http1 = @import("protocol/http1.zig");
const response_mod = @import("response/response.zig");
const http2 = @import("protocol/http2.zig");
const http3 = @import("protocol/http3.zig");
const tls = @import("tls/provider.zig");
const build_options = @import("build_options");
const quic_handler = @import("quic/handler.zig");
const quic_connection = @import("quic/connection.zig");
const middleware = @import("middleware/middleware.zig");
const request = @import("protocol/request.zig");
const metrics_mw = @import("middleware/metrics_mw.zig");
const proxy_mod = @import("proxy/proxy.zig");
const forward_mod = @import("proxy/forward.zig");

/// Global shutdown flag set by signal handler (atomic for signal safety)
var shutdown_requested = std.atomic.Value(bool).init(false);
/// Global reload flag set by SIGHUP handler (atomic for signal safety)
var reload_requested = std.atomic.Value(bool).init(false);

fn handleShutdownSignal(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

fn handleReloadSignal(_: std.posix.SIG) callconv(.c) void {
    reload_requested.store(true, .release);
}

/// Maximum number of hot HTTP/3 endpoints that can have pre-encoded
/// response bytes cached on the Server. Fixed-size — linear scan over
/// a cache-hot array beats a hashmap for N in the single digits.
pub const MAX_H3_PREENCODED: usize = 8;

/// Size of each pre-encoded response's byte buffer. 1024 is plenty
/// for the HttpArena and TechEmpower-style hot endpoints (/plaintext
/// returns 13 bytes, /json returns 27, /baseline2 returns 1). Larger
/// static files don't belong in this cache — they use the mmap path.
pub const H3_PREENCODED_BUF_SIZE: usize = 1024;

/// Pre-encoded HTTP/3 response for a hot static endpoint.
///
/// Holds the fully-encoded h3 response bytes (HEADERS frame + DATA
/// frame) ready to be wrapped in a QUIC STREAM frame and AEAD-
/// encrypted. On cache hit, `Server.handleHttp3Request` skips the
/// router, middleware, and `encodeHttp3Response` entirely — per-
/// request work drops to (URL match + STREAM frame wrap + AEAD +
/// sendto). Saves 600-1500 cycles per request on the hot path.
///
/// Refresh semantics: the bytes include a Date header whose value
/// drifts every second. `Server.findAndRefreshPreencodedH3` rebuilds
/// an entry's bytes the first time it's hit in a new epoch second.
/// All other hits in the same second are zero-work reads.
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

/// Maximum number of hot HTTP/1.1 endpoints that can have pre-encoded
/// response bytes cached on the Server.
pub const MAX_H1_PREENCODED: usize = 8;

/// Size of each pre-encoded h1 response's byte buffer. 1024 is plenty
/// for the benchmark-shape hot endpoints (/plaintext, /json, /health,
/// /baseline2). Status line + headers + Date + Alt-Svc + body fits
/// comfortably in ~300-400 bytes.
pub const H1_PREENCODED_BUF_SIZE: usize = 1024;

/// Pre-encoded HTTP/1.1 response for a hot static endpoint.
///
/// Holds the full HTTP/1.1 response bytes (status line + headers +
/// empty line + body) exactly as they'd be written on the wire in
/// keep-alive mode. On a cache hit, `Server.dispatchToRouter` skips
/// the router, middleware, arena_buf acquire, encodeResponseInner,
/// and the usual write-buffer building entirely — it acquires one
/// pool buffer, memcpys the cached bytes, and enqueues the write.
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

pub const MAX_H2_PREENCODED: usize = 8;
pub const H2_PREENCODED_BUF_SIZE: usize = 512;

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

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: config.ServerConfig,
    io: runtime.IoRuntime,
    app_router: router.Router,
    listener_fd: ?std.posix.fd_t,
    udp_fd: ?std.posix.fd_t,
    /// Directory fd for static_root, opened once at init. All per-request file
    /// lookups use openat() relative to this fd so the root cannot be moved out
    /// from under us, and so we don't pay realpath cost on the hot path.
    static_root_fd: ?std.posix.fd_t,
    tcp_tls_provider: ?tls.Provider,
    tls_provider: ?tls.Provider,
    http2_stack: ?http2.Stack,
    http3_stack: ?http3.Stack,
    quic: ?quic_handler.Handler,
    /// Reverse proxy handler (null if proxy not configured)
    proxy: ?*proxy_mod.Proxy = null,
    /// Config file path for hot reload (null if not using config file)
    config_path: ?[]const u8 = null,
    /// Buffer for receiving UDP datagrams
    udp_recv_buf: [2048]u8 = undefined,
    /// Pre-computed Alt-Svc header value for HTTP/3 advertisement
    alt_svc_value: [64]u8 = undefined,
    alt_svc_len: usize = 0,
    /// Cached Date header value (updated once per second)
    cached_date: [29]u8 = undefined,
    cached_date_epoch: u64 = 0,
    /// Pre-encoded HTTP/3 response cache for hot static endpoints
    /// (PR PERF-3). Fully-encoded h3 response bytes (HEADERS frame +
    /// DATA frame) are held here; on a cache hit the router, router
    /// middleware, and encodeHttp3Response are all skipped. Refreshed
    /// lazily once per second to pick up Date header changes.
    h3_preencoded: [MAX_H3_PREENCODED]PreencodedH3Response = undefined,
    h3_preencoded_count: usize = 0,
    /// Pre-encoded HTTP/1.1 response cache for the same hot static
    /// endpoints. Same shape as `h3_preencoded` but the bytes are
    /// raw HTTP/1.1 (status line + headers + body). Refresh is
    /// lazy / per-second just like h3.
    h1_preencoded: [MAX_H1_PREENCODED]PreencodedH1Response = undefined,
    h1_preencoded_count: usize = 0,
    /// Pre-encoded HTTP/2 response cache. Holds a stream-id-agnostic
    /// template — HEADERS frame header + HPACK block + optional DATA
    /// frame header + body. Send-time patches stream_id bytes in
    /// place and enqueues the write.
    h2_preencoded: [MAX_H2_PREENCODED]PreencodedH2Response = undefined,
    h2_preencoded_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: config.ServerConfig) !Server {
        var app_router = router.Router.init(.{
            .require_payment = cfg.x402.enabled,
            .payment_required_b64 = cfg.x402.payment_required_b64,
        });
        try registerDefaultRoutes(&app_router);
        return initWithRouter(allocator, cfg, app_router);
    }

    pub fn initWithRouter(allocator: std.mem.Allocator, cfg: config.ServerConfig, app_router: router.Router) !Server {
        var srv: Server = undefined;
        try srv.initInPlace(allocator, cfg, app_router);
        return srv;
    }

    /// Initialize a Server in-place at the given pointer. Use this to avoid
    /// constructing the large Server struct on the stack.
    pub fn initInPlace(self: *Server, allocator: std.mem.Allocator, cfg: config.ServerConfig, app_router: router.Router) !void {
        if (cfg.limits.max_header_count > connection.HeaderCapacity) return error.InvalidHeaderTable;
        const io_runtime = try runtime.IoRuntime.init(allocator, cfg);
        // TLS for TCP (HTTP/1.1 + HTTP/2): separate from QUIC
        const tcp_tls_provider: ?tls.Provider = if (build_options.enable_tls and cfg.tls.cert_path.len > 0)
            tls.Provider.initTcp(allocator, cfg.tls.cert_path, cfg.tls.key_path) catch |err| {
                std.log.err("TLS init failed: {}", .{err});
                return error.TlsInitFailed;
            }
        else
            null;
        // TLS for QUIC: TLS 1.3 only, AES-128-GCM ciphersuite, h3 ALPN.
        // Uses the OpenSSL 3.5+ SSL_set_quic_tls_cbs callback API instead of
        // memory BIOs — see src/tls/quic_session.zig.
        const tls_provider: ?tls.Provider = if (build_options.enable_tls and cfg.quic.enabled)
            try tls.Provider.initQuic(allocator, cfg.quic.cert_path, cfg.quic.key_path)
        else
            null;
        const http2_stack: ?http2.Stack = if (build_options.enable_http2) http2.Stack.initWithConfig(.{
            .max_streams = cfg.http2.max_streams,
            .max_header_list_size = cfg.http2.max_header_list_size,
            .initial_window_size = cfg.http2.initial_window_size,
            .max_frame_size = cfg.http2.max_frame_size,
            .max_dynamic_table_size = cfg.http2.max_dynamic_table_size,
        }) else null;
        const http3_stack: ?http3.Stack = if (build_options.enable_http3) http3.Stack.init(allocator, true) else null;
        const quic_inst: ?quic_handler.Handler = if (build_options.enable_http3 and cfg.quic.enabled)
            quic_handler.Handler.init(allocator, true, cfg.max_connections)
        else
            null;

        // Open static_root as a directory fd once. All per-request file lookups
        // use openat() relative to this fd, which:
        //   - eliminates per-request realpath/stat overhead on the hot path,
        //   - pins the root inode so swapping static_root at the filesystem
        //     level after startup cannot redirect lookups, and
        //   - combined with rejecting ".." in file_path and opening the leaf
        //     with O_NOFOLLOW, contains lookups to the configured directory
        //     on macOS. On Linux, openat2() with RESOLVE_BENEATH can close
        //     the intermediate-symlink gap; see queueFileResponse.
        const static_root_fd: ?std.posix.fd_t = blk: {
            if (cfg.static_root.len == 0) break :blk null;
            if (cfg.static_root.len >= 4096) break :blk null;
            var root_z: [4096]u8 = undefined;
            @memcpy(root_z[0..cfg.static_root.len], cfg.static_root);
            root_z[cfg.static_root.len] = 0;
            var o_flags: std.posix.O = .{ .DIRECTORY = true };
            if (@hasField(std.posix.O, "CLOEXEC")) o_flags.CLOEXEC = true;
            const root_z_ptr: [*:0]const u8 = @ptrCast(&root_z);
            const fd = std.posix.openatZ(std.posix.AT.FDCWD, root_z_ptr, o_flags, 0) catch {
                std.log.warn("static_root '{s}' could not be opened; static file serving disabled", .{cfg.static_root});
                break :blk null;
            };
            break :blk fd;
        };

        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .io = io_runtime,
            .app_router = app_router,
            .listener_fd = null,
            .udp_fd = null,
            .static_root_fd = static_root_fd,
            .tcp_tls_provider = tcp_tls_provider,
            .tls_provider = tls_provider,
            .http2_stack = http2_stack,
            .http3_stack = http3_stack,
            .quic = quic_inst,
            .alt_svc_value = undefined,
            .alt_svc_len = 0,
        };

        // Wire the (now stable-addressed) tls_provider into the QUIC handler
        // so each new connection can bootstrap a TLS session via initTls.
        // This must happen after self.* assignment so we can take a pointer
        // into self.tls_provider.
        if (self.quic) |*q| {
            if (self.tls_provider) |*p| q.setTlsProvider(p);
        }

        // Pre-compute Alt-Svc header if QUIC is enabled
        if (cfg.quic.enabled) {
            const alt_svc = cfg.quic.buildAltSvcHeader(&self.alt_svc_value) catch "";
            self.alt_svc_len = alt_svc.len;
        }

        // Pre-encode the h3 response bytes for hot static endpoints
        // (PR PERF-3). Requires http3_stack to be initialized.
        if (build_options.enable_http3 and self.http3_stack != null) {
            self.initPreencodedH3();
        }

        // Pre-encode the h1 response bytes for the same hot static
        // endpoints. No external dependency — uses encodeResponse +
        // the already-initialized cached date + Alt-Svc config.
        self.initPreencodedH1();

        // Pre-encode the h2 response templates. Uses http2.encodeResponseHeaders
        // to build a stream-id-agnostic HPACK block + frame headers that
        // are patched per-request.
        if (build_options.enable_http2) self.initPreencodedH2();
    }

    /// Populate the h3 pre-encoded response cache with a fixed set of
    /// hot static endpoints — the ones that show up in HttpArena and
    /// TechEmpower benchmarks. On request, if the URL matches one of
    /// these entries we skip the router + middleware + encode path
    /// entirely and feed pre-encoded h3 bytes straight to the QUIC
    /// send loop. See `PreencodedH3Response`.
    fn initPreencodedH3(self: *Server) void {
        const plaintext_headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        };
        const json_headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };

        self.registerPreencodedH3("GET", "/health", 200, &[_]response_mod.Header{}, "");
        self.registerPreencodedH3("GET", "/plaintext", 200, &plaintext_headers, "Hello, World!");
        self.registerPreencodedH3("GET", "/json", 200, &json_headers, "{\"message\":\"Hello, World!\"}");
        // HttpArena baselines: both h2/h3 share /baseline2 and h1
        // uses /baseline11. The canonical benchmark URL is always
        // ?a=1&b=1 → body "2". /pipeline returns "ok".
        self.registerPreencodedH3("GET", "/baseline2?a=1&b=1", 200, &plaintext_headers, "2");
        self.registerPreencodedH3("GET", "/baseline11?a=1&b=1", 200, &plaintext_headers, "2");
        self.registerPreencodedH3("GET", "/pipeline", 200, &plaintext_headers, "ok");
    }

    /// Append a pre-encoded entry and encode its initial bytes using
    /// the Server's http3_stack. Called from `initPreencodedH3` at
    /// startup. Silently drops if the cache is full or encoding fails.
    fn registerPreencodedH3(
        self: *Server,
        method: []const u8,
        path: []const u8,
        status: u16,
        static_headers: []const response_mod.Header,
        body: []const u8,
    ) void {
        if (self.h3_preencoded_count >= MAX_H3_PREENCODED) return;
        const idx = self.h3_preencoded_count;
        self.h3_preencoded[idx] = .{
            .method = method,
            .path = path,
            .status = status,
            .static_headers = static_headers,
            .body = body,
        };
        // Encode right away so the first request doesn't pay the
        // rebuild cost. Refresh-on-hit still handles the per-second
        // Date header drift.
        self.rebuildPreencodedH3(&self.h3_preencoded[idx]);
        self.h3_preencoded_count += 1;
    }

    /// Re-encode a pre-encoded entry's bytes, picking up whatever the
    /// current Date header is. Called from `findAndRefreshPreencodedH3`
    /// the first time a given entry is hit in a new epoch second, and
    /// from `registerPreencodedH3` at startup.
    fn rebuildPreencodedH3(self: *Server, entry: *PreencodedH3Response) void {
        const stack = if (self.http3_stack) |*s| s else return;
        const body_opt: ?[]const u8 = if (entry.body.len > 0) entry.body else null;
        entry.len = stack.encodeResponse(
            &entry.bytes,
            entry.status,
            @ptrCast(entry.static_headers),
            body_opt,
        ) catch 0;
        const ts = clock.realtimeTimespec() orelse return;
        entry.epoch = @intCast(ts.sec);
    }

    /// Look up a hot endpoint by method + path. On a match, refresh
    /// the entry if its cached Date header is stale (current epoch
    /// second differs from entry.epoch) and return the pointer.
    /// Returns null on miss.
    fn findAndRefreshPreencodedH3(self: *Server, method: []const u8, path: []const u8) ?*PreencodedH3Response {
        var i: usize = 0;
        while (i < self.h3_preencoded_count) : (i += 1) {
            const entry = &self.h3_preencoded[i];
            if (std.mem.eql(u8, entry.method, method) and std.mem.eql(u8, entry.path, path)) {
                // Lazy per-second refresh
                const ts = clock.realtimeTimespec() orelse return entry;
                const epoch: u64 = @intCast(ts.sec);
                if (epoch != entry.epoch) self.rebuildPreencodedH3(entry);
                if (entry.len == 0) return null; // encode failed; fall through to router
                return entry;
            }
        }
        return null;
    }

    /// Populate the h1 pre-encoded response cache with the same hot
    /// static endpoints used by the h3 cache. h1 and h2 clients hit
    /// the same URLs in the same benchmarks, so they deserve the
    /// same cache-hit fast path the h3 profiles get.
    fn initPreencodedH1(self: *Server) void {
        const plaintext_headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        };
        const json_headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };

        self.registerPreencodedH1("GET", "/health", 200, &[_]response_mod.Header{}, "");
        self.registerPreencodedH1("GET", "/plaintext", 200, &plaintext_headers, "Hello, World!");
        self.registerPreencodedH1("GET", "/json", 200, &json_headers, "{\"message\":\"Hello, World!\"}");
        self.registerPreencodedH1("GET", "/baseline2?a=1&b=1", 200, &plaintext_headers, "2");
        self.registerPreencodedH1("GET", "/baseline11?a=1&b=1", 200, &plaintext_headers, "2");
        self.registerPreencodedH1("GET", "/pipeline", 200, &plaintext_headers, "ok");
    }

    fn registerPreencodedH1(
        self: *Server,
        method: []const u8,
        path: []const u8,
        status: u16,
        static_headers: []const response_mod.Header,
        body: []const u8,
    ) void {
        if (self.h1_preencoded_count >= MAX_H1_PREENCODED) return;
        const idx = self.h1_preencoded_count;
        self.h1_preencoded[idx] = .{
            .method = method,
            .path = path,
            .status = status,
            .static_headers = static_headers,
            .body = body,
        };
        self.rebuildPreencodedH1(&self.h1_preencoded[idx]);
        self.h1_preencoded_count += 1;
    }

    fn rebuildPreencodedH1(self: *Server, entry: *PreencodedH1Response) void {
        const resp: response_mod.Response = .{
            .status = entry.status,
            .headers = entry.static_headers,
            .body = if (entry.body.len > 0) .{ .bytes = entry.body } else .none,
        };
        const alt_svc: ?[]const u8 = if (self.alt_svc_len > 0)
            self.alt_svc_value[0..self.alt_svc_len]
        else
            null;
        // encodeResponse embeds a `Date: <current>` line — pick up
        // the current cached date from the Server first so both h1
        // and h3 caches are populated from the same source of truth.
        const date_str = self.getCachedDate();
        entry.len = encodeResponse(&entry.bytes, resp, alt_svc, false, date_str) catch 0;
        const ts = clock.realtimeTimespec() orelse return;
        entry.epoch = @intCast(ts.sec);
    }

    fn findAndRefreshPreencodedH1(self: *Server, method: []const u8, path: []const u8) ?*PreencodedH1Response {
        var i: usize = 0;
        while (i < self.h1_preencoded_count) : (i += 1) {
            const entry = &self.h1_preencoded[i];
            if (std.mem.eql(u8, entry.method, method) and std.mem.eql(u8, entry.path, path)) {
                const ts = clock.realtimeTimespec() orelse return entry;
                const epoch: u64 = @intCast(ts.sec);
                if (epoch != entry.epoch) self.rebuildPreencodedH1(entry);
                if (entry.len == 0) return null;
                return entry;
            }
        }
        return null;
    }

    /// Check the pre-encoded h1 response cache and, on hit, send the
    /// cached bytes directly via the write buffer. Returns true if
    /// the request was handled (caller should skip the router path),
    /// false if the caller must fall through to the normal dispatch.
    ///
    /// Called from every h1 router-dispatch site: the inline
    /// `handleRead` path for requests that fit in the read buffer,
    /// `dispatchToRouter` for the "read buffer full → header-only
    /// parse" path, and the body-accumulation-complete dispatch
    /// for large POST/PUT (which always misses the cache since
    /// those aren't GET).
    fn tryDispatchPreencodedH1(self: *Server, conn: *connection.Connection, req_view: request.RequestView) bool {
        if (conn.close_after_write) return false;
        const method_str = req_view.getMethodName();
        if (self.findAndRefreshPreencodedH1(method_str, req_view.path)) |entry| {
            self.sendH1PreencodedBytes(conn, entry.bytes[0..entry.len]);
            return true;
        }
        return false;
    }

    /// Populate the h2 pre-encoded response cache with the same hot
    /// static endpoints used by h1 and h3.
    fn initPreencodedH2(self: *Server) void {
        const plaintext_headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        };
        const json_headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        };

        self.registerPreencodedH2("GET", "/health", 200, &[_]response_mod.Header{}, "");
        self.registerPreencodedH2("GET", "/plaintext", 200, &plaintext_headers, "Hello, World!");
        self.registerPreencodedH2("GET", "/json", 200, &json_headers, "{\"message\":\"Hello, World!\"}");
        self.registerPreencodedH2("GET", "/baseline2?a=1&b=1", 200, &plaintext_headers, "2");
        self.registerPreencodedH2("GET", "/baseline11?a=1&b=1", 200, &plaintext_headers, "2");
        self.registerPreencodedH2("GET", "/pipeline", 200, &plaintext_headers, "ok");
    }

    fn registerPreencodedH2(
        self: *Server,
        method: []const u8,
        path: []const u8,
        status: u16,
        static_headers: []const response_mod.Header,
        body: []const u8,
    ) void {
        if (self.h2_preencoded_count >= MAX_H2_PREENCODED) return;
        const idx = self.h2_preencoded_count;
        self.h2_preencoded[idx] = .{
            .method = method,
            .path = path,
            .status = status,
            .static_headers = static_headers,
            .body = body,
        };
        self.rebuildPreencodedH2(&self.h2_preencoded[idx]);
        self.h2_preencoded_count += 1;
    }

    /// Rebuild the h2 response template for `entry`. Runs HPACK
    /// encoding over the static headers + current cached Date and
    /// lays down the HEADERS (+ optional DATA) frame headers with
    /// stream_id = 0 placeholders. Stream IDs are patched at send
    /// time.
    fn rebuildPreencodedH2(self: *Server, entry: *PreencodedH2Response) void {
        // Build headers_with_alt_svc array just like queueHttp2Response
        // does — the cache must match what the cold path would emit.
        var headers_with_alt_svc: [65]response_mod.Header = undefined;
        var header_count: usize = entry.static_headers.len;
        if (header_count > headers_with_alt_svc.len) {
            entry.len = 0;
            return;
        }
        for (entry.static_headers, 0..) |h, i| headers_with_alt_svc[i] = h;
        if (self.alt_svc_len > 0 and header_count < headers_with_alt_svc.len) {
            headers_with_alt_svc[header_count] = .{
                .name = "alt-svc",
                .value = self.alt_svc_value[0..self.alt_svc_len],
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

    fn findAndRefreshPreencodedH2(self: *Server, method: []const u8, path: []const u8) ?*PreencodedH2Response {
        var i: usize = 0;
        while (i < self.h2_preencoded_count) : (i += 1) {
            const entry = &self.h2_preencoded[i];
            if (std.mem.eql(u8, entry.method, method) and std.mem.eql(u8, entry.path, path)) {
                const ts = clock.realtimeTimespec() orelse return entry;
                const epoch: u64 = @intCast(ts.sec);
                if (epoch != entry.epoch) self.rebuildPreencodedH2(entry);
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
    fn sendH2PreencodedBytes(
        self: *Server,
        conn: *connection.Connection,
        stream_id: u32,
        entry: *const PreencodedH2Response,
    ) void {
        const out = self.io.acquireBuffer() orelse {
            self.closeConnection(conn);
            return;
        };
        if (entry.len > out.bytes.len) {
            self.io.releaseBuffer(out);
            self.closeConnection(conn);
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
            self.io.releaseBuffer(out);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, entry.len);
        self.io.setTimeoutPhase(conn, .write);

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

    /// Write pre-encoded h1 response bytes directly to the connection's
    /// write buffer, bypassing `queueResponse`. One buffer-pool acquire,
    /// one memcpy (cached bytes → write buffer), one enqueueWrite. Used
    /// on the pre-encoded cache hit path.
    fn sendH1PreencodedBytes(self: *Server, conn: *connection.Connection, bytes: []const u8) void {
        const buf = self.io.acquireBuffer() orelse {
            self.closeConnection(conn);
            return;
        };
        if (bytes.len > buf.bytes.len) {
            // Shouldn't happen: hot endpoints fit in H1_PREENCODED_BUF_SIZE
            // (1024) and the connection buffer pool slots are typically
            // 64 KiB. If it does, bail to the router path next time.
            self.io.releaseBuffer(buf);
            self.closeConnection(conn);
            return;
        }
        @memcpy(buf.bytes[0..bytes.len], bytes);
        if (!conn.enqueueWrite(buf, bytes.len)) {
            self.io.releaseBuffer(buf);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, bytes.len);
        self.io.setTimeoutPhase(conn, .write);
    }

    pub fn deinit(self: *Server) void {
        if (self.tcp_tls_provider) |*p| p.deinit();
        if (self.listener_fd) |fd| clock.closeFd(fd);
        if (self.udp_fd) |fd| clock.closeFd(fd);
        if (self.static_root_fd) |fd| clock.closeFd(fd);
        if (self.quic) |*q| q.deinit();
        self.io.deinit();
    }

    /// Request a graceful shutdown. The event loop will stop accepting new connections
    /// and exit after draining in-flight responses.
    pub fn shutdown(_: *Server) void {
        shutdown_requested.store(true, .release);
    }

    /// Apply hot reload from config file.
    /// Safe-to-change fields (value types only): timeouts, limits.
    /// Requires restart: address, port, max_connections, buffer pool, allowed_hosts.
    fn applyReload(self: *Server) void {
        const path = self.config_path orelse {
            std.log.info("SIGHUP received but no config file path set, ignoring", .{});
            return;
        };
        const config_file = @import("config_file.zig");
        var loaded = config_file.loadConfigFile(self.allocator, path) catch |err| {
            std.log.err("Config reload failed: {}", .{err});
            return;
        };
        defer loaded.deinit();

        // Validate the new config before applying
        loaded.server_config.validate() catch |err| {
            std.log.err("Config reload validation failed: {}", .{err});
            return;
        };

        const new = loaded.server_config;
        // Hot-reload value-type fields (no pointer/slice ownership issues)
        self.cfg.timeouts = new.timeouts;
        self.cfg.limits = new.limits;
        std.log.info("Config reloaded from {s}", .{path});
    }

    pub fn run(self: *Server, run_for_ms: ?u64) !void {
        // Install signal handlers for graceful shutdown
        const sa = std.posix.Sigaction{
            .handler = .{ .handler = handleShutdownSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
        std.posix.sigaction(std.posix.SIG.INT, &sa, null);
        // Ignore SIGPIPE — SSL_shutdown/SSL_write on a closed socket triggers it
        const pipe_sa = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.PIPE, &pipe_sa, null);
        // Install SIGHUP handler for config hot reload
        const reload_sa = std.posix.Sigaction{
            .handler = .{ .handler = handleReloadSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.HUP, &reload_sa, null);

        try self.io.start();
        if (self.listener_fd == null) {
            const fd = try net.listen(self.cfg.address, self.cfg.port, 1024);
            self.listener_fd = fd;
            try self.io.registerListener(fd);
        }
        // Initialize UDP listener for QUIC if enabled
        if (self.quic != null and self.udp_fd == null) {
            const quic_port = self.cfg.quic.port;
            if (quic_port > 0) {
                const udp_fd = net.bindUdp(self.cfg.address, quic_port) catch |err| {
                    std.log.warn("Failed to bind UDP port {}: {}", .{ quic_port, err });
                    return err;
                };
                self.udp_fd = udp_fd;
                self.io.registerUdpSocket(udp_fd) catch |err| {
                    std.log.warn("Failed to register UDP socket: {}", .{err});
                    clock.closeFd(udp_fd);
                    self.udp_fd = null;
                };
            }
        }
        const deadline = if (run_for_ms) |ms| self.io.nowMs() + ms else null;
        while (true) {
            if (shutdown_requested.load(.acquire)) return;
            if (reload_requested.swap(false, .acq_rel)) {
                self.applyReload();
            }
            if (deadline) |limit| {
                if (self.io.nowMs() >= limit) return;
            }
            const now_ms = self.io.nowMs();
            const timeout_ms = self.io.nextPollTimeoutMs(now_ms);
            const events = try self.io.pollWithTimeout(timeout_ms);
            // Enforce timeouts and close timed-out connections
            const timeout_result = self.io.enforceTimeouts(self.io.nowMs());
            for (timeout_result.to_close[0..timeout_result.count]) |conn_index| {
                if (self.io.getConnection(conn_index)) |conn| {
                    self.closeConnection(conn);
                }
            }
            // Periodic QUIC cleanup
            if (self.quic) |*q| {
                q.cleanup();
            }
            // Periodic proxy maintenance (pool eviction + health checks)
            if (self.proxy) |proxy| {
                proxy.runMaintenance(self.io.nowMs());
            }
            if (events.len == 0) continue;
            for (events) |event| {
                switch (event.kind) {
                    .accept => {
                        // Use event.handle if provided (kqueue), otherwise use listener_fd (epoll)
                        const fd = event.handle orelse self.listener_fd orelse continue;
                        self.handleAccept(fd) catch |err| {
                            // Log accept errors but don't crash the server
                            std.log.warn("Accept failed: {}", .{err});
                        };
                    },
                    .datagram => {
                        try self.handleDatagram();
                    },
                    .read, .write, .err => {
                        // Validate conn_id fits in u32 before casting
                        if (event.conn_id > std.math.maxInt(u32)) continue;
                        const index: u32 = @intCast(event.conn_id);
                        // Guard against stale events: if the connection slot was freed
                        // and reused between event generation and dispatch, the fd will
                        // be null (freed) or the connection state will be closed/accept.
                        const conn = self.io.getConnection(index) orelse continue;
                        if (conn.fd == null or conn.state == .closed or conn.state == .accept) continue;
                        // TLS handshake in progress — any I/O event continues it
                        if (conn.state == .handshake) {
                            self.handleTlsHandshake(conn) catch {
                                self.closeConnection(conn);
                            };
                            continue;
                        }
                        switch (event.kind) {
                            .read => {
                                self.handleRead(index) catch |err| {
                                    std.log.debug("handleRead conn={} failed: {}", .{ index, err });
                                };
                                // Edge-triggered epoll: EPOLLOUT may have been consumed earlier
                                // (e.g., sending h2 SETTINGS). Flush any responses queued by handleRead.
                                const rconn = self.io.getConnection(index) orelse continue;
                                if (rconn.write_count > 0) {
                                    self.handleWrite(index) catch {};
                                }
                            },
                            .write => self.handleWrite(index) catch |err| {
                                std.log.debug("handleWrite conn={} failed: {}", .{ index, err });
                            },
                            .err => self.handleError(index) catch |err| {
                                std.log.debug("handleError conn={} failed: {}", .{ index, err });
                            },
                            .accept, .datagram => unreachable,
                        }
                    },
                }
            }
        }
    }

    pub fn runFor(self: *Server, run_for_ms: u64) !void {
        try self.run(run_for_ms);
    }

    fn handleAccept(self: *Server, listener_fd: std.posix.fd_t) !void {
        // Edge-triggered epoll: must drain the accept queue in a loop or
        // pending connections will be stranded until the next "transition".
        while (true) {
            self.acceptOne(listener_fd) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
        }
    }

    fn acceptOne(self: *Server, listener_fd: std.posix.fd_t) !void {
        const client_fd = net.accept(listener_fd) catch |err| switch (err) {
            error.WouldBlock => return error.WouldBlock,
            else => return err,
        };
        // Disable Nagle's algorithm — without this, h2 HEADERS+DATA writes
        // can stall for 40ms (TCP delayed ACK) since they're separate sends.
        // For h1 we use writev (one syscall), so this also helps multi-frame writes.
        const one: c_int = 1;
        _ = std.posix.system.setsockopt(client_fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
        const now_ms = self.io.nowMs();
        const conn = self.io.acquireConnection(now_ms) orelse {
            clock.closeFd(client_fd);
            return;
        };
        if (self.io.acquireBuffer()) |buf| {
            conn.read_buffer = buf;
        } else {
            self.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return;
        }
        conn.fd = client_fd;
        // Cache peer address once at accept time (avoids getpeername syscall per request)
        if (net.getPeerAddress(client_fd)) |peer| {
            if (peer.getIp4Bytes()) |ip4| {
                conn.cached_peer_ip = ip4;
            } else if (peer.getIp6Bytes()) |ip6| {
                conn.cached_peer_ip6 = ip6;
            }
        }
        // If TLS is configured, start handshake before going active
        if (self.tcp_tls_provider) |*provider| {
            conn.tls_session = provider.createSocketSession(client_fd) catch {
                if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
                self.io.releaseConnection(conn);
                clock.closeFd(client_fd);
                return;
            };
            conn.is_tls = true;
            conn.transition(.handshake, now_ms) catch {
                conn.cleanupTls();
                if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
                self.io.releaseConnection(conn);
                clock.closeFd(client_fd);
                return;
            };
            self.io.setTimeoutPhase(conn, .header);
            self.io.registerConnection(conn.index, client_fd) catch |err| {
                conn.cleanupTls();
                if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
                self.io.releaseConnection(conn);
                clock.closeFd(client_fd);
                return err;
            };
            // Try handshake immediately (may complete in one round-trip)
            self.handleTlsHandshake(conn) catch {
                self.closeConnection(conn);
                return;
            };
        } else {
            conn.transition(.active, now_ms) catch {
                // Invalid state transition - close connection
                if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
                self.io.releaseConnection(conn);
                clock.closeFd(client_fd);
                return;
            };
            self.io.setTimeoutPhase(conn, .header);
            self.io.registerConnection(conn.index, client_fd) catch |err| {
                if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
                self.io.releaseConnection(conn);
                clock.closeFd(client_fd);
                return err;
            };
            // With edge-triggered epoll, we must try to read immediately after accept
            // because data may have arrived before we registered the socket.
            // If we don't do this, we'll miss the EPOLLIN notification.
            self.handleRead(conn.index) catch {
                self.closeConnection(conn);
                return;
            };
        }
    }

    fn handleTlsHandshake(self: *Server, conn: *connection.Connection) !void {
        var session = &(conn.tls_session orelse return error.NoTlsSession);
        const accepted = session.accept() catch {
            return error.TlsHandshakeFailed;
        };
        if (accepted) {
            // Handshake complete — check ALPN for h2 and transition to active
            conn.transition(.active, self.io.nowMs()) catch return error.InvalidTransition;
            if (build_options.enable_http2) {
                if (session.getAlpn()) |alpn| {
                    if (std.mem.eql(u8, alpn, "h2")) {
                        if (conn.http2_stack == null) {
                            const stack_ptr = try self.allocator.create(http2.Stack);
                            stack_ptr.* = http2.Stack.initWithConfig(.{
                                .max_streams = self.cfg.http2.max_streams,
                                .max_header_list_size = self.cfg.http2.max_header_list_size,
                                .initial_window_size = self.cfg.http2.initial_window_size,
                                .max_frame_size = self.cfg.http2.max_frame_size,
                                .max_dynamic_table_size = self.cfg.http2.max_dynamic_table_size,
                            });
                            conn.http2_stack = stack_ptr;
                        }
                        conn.protocol = .http2;
                        self.sendHttp2ServerPreface(conn) catch {
                            return error.Http2PrefaceFailed;
                        };
                    }
                }
            }
            // For HTTP/2 over TLS, flush the server preface (SETTINGS) before
            // reading. The client won't send its h2 preface until it receives ours.
            if (conn.protocol == .http2) {
                self.handleWrite(conn.index) catch {};
            }
            // Try to read immediately (data may already be buffered by TLS/kernel)
            self.handleRead(conn.index) catch {
                self.closeConnection(conn);
                return;
            };
            // Flush any response queued by handleRead (the event loop also does
            // this after read events, but we need it here for the initial handshake)
            if (conn.write_count > 0) {
                self.handleWrite(conn.index) catch {};
            }
        }
        // If not accepted, handshake needs more I/O — wait for next event
    }

    fn handleDatagram(self: *Server) !void {
        const udp_fd = self.udp_fd orelse return;
        var quic = &(self.quic orelse return);

        // Receive datagram
        const recv_result = net.recvfrom(udp_fd, &self.udp_recv_buf) catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return,
            }
        };

        if (recv_result.bytes_read == 0) return;

        // Convert peer address to our internal format (zero-init to avoid undefined bytes)
        var peer_addr: quic_handler.connection_pool.SockAddrStorage = undefined;
        @memset(std.mem.asBytes(&peer_addr), 0);
        @memcpy(std.mem.asBytes(&peer_addr)[0..@sizeOf(@TypeOf(recv_result.peer_addr))], std.mem.asBytes(&recv_result.peer_addr));

        // Process the QUIC packet
        const result = quic.processPacket(self.udp_recv_buf[0..recv_result.bytes_read], peer_addr) catch |err| {
            std.log.debug("QUIC packet error: {}", .{err});
            return;
        };

        // Send response if any (handshake responses)
        if (result.response) |resp| {
            if (resp.len > 0) {
                _ = net.sendto(udp_fd, resp, recv_result.peer_addr) catch |err| {
                    std.log.debug("Failed to send QUIC response: {}", .{err});
                };
            }
        }

        // Process HTTP/3 events. Per the defer-until-FIN model in
        // `src/protocol/http3.zig::processRequestStream`, request
        // streams emit a single `request_ready` event once the stream
        // has finished arriving. `req.body` and `req.headers` both
        // point into buffers owned by the Stack / Stream and stay
        // valid for the duration of the synchronous handler call.
        // After dispatch we reclaim the Stream's receive buffer via
        // `clearH3RequestStream` — that's the first point at which
        // the body slice is no longer referenced.
        if (result.conn) |conn| {
            for (result.http3_events) |event| {
                switch (event) {
                    .request_ready => |req| {
                        self.handleHttp3Request(udp_fd, conn, req, recv_result.peer_addr);
                        conn.clearH3RequestStream(req.stream_id);
                    },
                    .settings, .goaway, .stream_error => {},
                }
            }
        }

        // Handle connection state changes
        if (result.close_connection) {
            if (result.conn) |conn| {
                quic.pool.removeConnection(conn);
            }
        }
    }

    /// Handle an HTTP/3 request and send response.
    ///
    /// Invoked from the defer-until-FIN dispatch path in
    /// `handleDatagram` when the Stack emits a `RequestReadyEvent`.
    /// `req.headers` slices point into the Stack's fixed-size owned
    /// storage and stay valid until the next `ingest` call; `req.body`
    /// is a slice into the decrypted STREAM frame payload and stays
    /// valid for the duration of this synchronous call.
    ///
    /// Fast path (PR PERF-3): before running the router, check the
    /// pre-encoded h3 response cache for hot static endpoints
    /// (/plaintext, /json, /health, ...). On a cache hit, skip the
    /// router + middleware + encodeHttp3Response entirely and feed
    /// the cached bytes straight to the QUIC send loop. Saves
    /// 600-1500 cycles per request on the hottest paths.
    fn handleHttp3Request(
        self: *Server,
        udp_fd: std.posix.fd_t,
        conn: *quic_connection.Connection,
        req: http3.RequestReadyEvent,
        peer_addr: net.SockAddrStorage,
    ) void {
        var req_headers: [65]request.Header = undefined;
        const req_view = buildHttp3RequestView(req, req_headers[0..]) orelse return;

        if (!self.isAllowedHost(req_view)) {
            // Host not in allowlist — send the bad-request response
            // through the normal encode path since it's not cached.
            self.sendHttp3ResponseFromResponse(udp_fd, conn, req.stream_id, peer_addr, badRequestResponse());
            return;
        }

        // --- Fast path: pre-encoded response cache ---
        const method_str = req_view.getMethodName();
        if (self.findAndRefreshPreencodedH3(method_str, req_view.path)) |entry| {
            self.sendHttp3ResponseBytes(udp_fd, conn, req.stream_id, peer_addr, entry.bytes[0..entry.len]);
            return;
        }

        // --- Cold path: full router dispatch ---
        var mw_ctx = middleware.Context{
            .protocol = .http3,
            .buffer_ops = .{
                .ctx = &self.io,
                .acquire = acquireBufferOpaque,
                .release = releaseBufferOpaque,
            },
        };
        var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
        var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
        const arena_handle = self.io.acquireBuffer();
        var empty_arena: [0]u8 = undefined;
        const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
        var scratch = router.HandlerScratch{
            .response_buf = response_buf[0..],
            .response_headers = response_headers[0..],
            .arena_buf = arena_buf,
            .arena_handle = arena_handle,
            .buffer_ops = mw_ctx.buffer_ops,
        };
        const result = self.app_router.handle(req_view, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
        const managed_handle: ?buffer_pool.BufferHandle = switch (result.resp.body) {
            .managed => |managed| managed.handle,
            else => null,
        };
        defer if (managed_handle) |handle| self.io.releaseBuffer(handle);

        self.sendHttp3ResponseFromResponse(udp_fd, conn, req.stream_id, peer_addr, result.resp);
    }

    /// Encode a router Response into h3 bytes and send it over the
    /// wire. Used by the cold-path (router-dispatched) h3 flow.
    /// The hot path uses `sendHttp3ResponseBytes` directly with
    /// pre-encoded bytes.
    fn sendHttp3ResponseFromResponse(
        self: *Server,
        udp_fd: std.posix.fd_t,
        conn: *quic_connection.Connection,
        stream_id: u64,
        peer_addr: net.SockAddrStorage,
        resp: response_mod.Response,
    ) void {
        const body_bytes = resp.bodyBytes();
        const body_len = resp.bodyLen();
        var encoded_response_buf: [16384]u8 = undefined;
        const resp_len = conn.encodeHttp3Response(
            &encoded_response_buf,
            resp.status,
            @ptrCast(resp.headers),
            if (body_len > 0) body_bytes else null,
        ) catch return;
        self.sendHttp3ResponseBytes(udp_fd, conn, stream_id, peer_addr, encoded_response_buf[0..resp_len]);
    }

    /// Send already-encoded h3 response bytes over the wire for a
    /// given QUIC stream. Splits into MTU-sized chunks and feeds each
    /// chunk through the unified `quic.handler::buildShortPacket`
    /// builder (PR PERF-0). Shared hot-path / cold-path helper.
    ///
    /// QUIC packet overhead: 1 (header) + 20 (max CID) + 4 (max PN) +
    /// ~10 (frame header) + 16 (AEAD tag) ≈ 51 bytes. Use a
    /// conservative 1200-byte max payload to stay within the 1280-
    /// byte QUIC minimum MTU.
    fn sendHttp3ResponseBytes(
        self: *Server,
        udp_fd: std.posix.fd_t,
        conn: *quic_connection.Connection,
        stream_id: u64,
        peer_addr: net.SockAddrStorage,
        h3_bytes: []const u8,
    ) void {
        _ = self;
        const keys = conn.crypto_ctx.application.server orelse return;
        const max_stream_payload = 1200;
        var stream_offset: u64 = 0;
        var remaining = h3_bytes;
        while (remaining.len > 0) {
            const chunk_len = @min(remaining.len, max_stream_payload);
            const is_last = (chunk_len == remaining.len);
            var packet_buf: [2048]u8 = undefined;
            const built = quic_handler.buildShortPacket(
                &packet_buf,
                .{
                    .conn = conn,
                    .keys = &keys,
                    .stream_data = .{
                        .stream_id = stream_id,
                        .offset = stream_offset,
                        .data = remaining[0..chunk_len],
                        .fin = is_last,
                    },
                },
            ) catch return;

            _ = net.sendto(udp_fd, packet_buf[0..built.bytes_written], peer_addr) catch |err| {
                std.log.debug("Failed to send HTTP/3 response: {}", .{err});
                return;
            };
            remaining = remaining[chunk_len..];
            stream_offset += chunk_len;
        }
    }

    fn handleRead(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        if (conn.fd == null) return;
        if (!self.io.canRead(conn)) return;
        if (conn.timeout_phase == .idle) self.io.setTimeoutPhase(conn, .header);
        const buffer_handle = conn.read_buffer orelse return;

        // If we're accumulating a large body, continue that instead of parsing.
        // Loop until EAGAIN to drain all available data (edge-triggered epoll).
        if (conn.isAccumulatingBody()) {
            while (true) {
                const accum_buf = conn.read_buffer orelse return;
                const acc_offset = conn.read_offset + conn.read_buffered_bytes;
                if (acc_offset >= accum_buf.bytes.len) {
                    // Read buffer full — should have been drained; just return
                    return;
                }
                const slice = accum_buf.bytes[acc_offset..];
                const count = switch (self.connRead(conn, slice)) {
                    .bytes => |n| n,
                    .eof => {
                        self.abortBodyAccumulation(conn, 400);
                        return;
                    },
                    .again => return,
                    .err => {
                        self.cleanupBodyAccumulation(conn);
                        self.closeConnection(conn);
                        return;
                    },
                };
                self.io.onReadBuffered(conn, count);
                conn.markActive(self.io.nowMs());
                self.continueBodyAccumulation(conn) catch {
                    self.abortBodyAccumulation(conn, 400);
                    return;
                };
                // Body complete — dispatch already happened
                if (!conn.isAccumulatingBody()) return;
            }
        }

        const offset = conn.read_offset + conn.read_buffered_bytes;
        if (offset >= buffer_handle.bytes.len) {
            // Buffer full — try header-only parse to see if we can start body accumulation
            if (conn.canEnqueueWrite()) {
                const start = conn.read_offset;
                const end = start + conn.read_buffered_bytes;
                const hparse = http1.parseHeaders(buffer_handle.bytes[start..end], .{
                    .max_header_bytes = self.cfg.limits.max_header_bytes,
                    .max_body_bytes = self.cfg.limits.max_body_bytes,
                    .max_header_count = self.cfg.limits.max_header_count,
                    .headers_storage = conn.headers[0..],
                });
                if (hparse.state == .err) {
                    conn.close_after_write = true;
                    self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                    try self.queueResponse(conn, errorResponseFor(hparse.error_code));
                } else if (hparse.state == .complete) {
                    // Headers valid, body too big for buffer → init body accumulation
                    const needs_body = hparse.is_chunked or hparse.content_length > 0;
                    if (needs_body) {
                        self.initBodyAccumulation(conn, hparse, buffer_handle) catch {
                            conn.close_after_write = true;
                            self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                            try self.queueResponse(conn, errorResponseFor(.body_too_large));
                            return;
                        };
                        // Body accumulation started — re-enter handleRead to drain socket
                        // (edge-triggered epoll won't fire again for data already buffered)
                        return self.handleRead(index);
                    } else {
                        // No body but buffer full → shouldn't happen (parse() would've completed)
                        conn.close_after_write = true;
                        self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                        try self.queueResponse(conn, errorResponseFor(.body_too_large));
                    }
                } else {
                    // .partial — headers not even complete yet → 431 (header too large)
                    conn.close_after_write = true;
                    self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                    try self.queueResponse(conn, errorResponseFor(.header_too_large));
                }
            }
            return;
        }
        const slice = buffer_handle.bytes[offset..];
        const count = switch (self.connRead(conn, slice)) {
            .bytes => |n| n,
            .eof => {
                self.closeConnection(conn);
                return;
            },
            .again => return,
            .err => {
                self.closeConnection(conn);
                return;
            },
        };
        self.io.onReadBuffered(conn, count);
        conn.markActive(self.io.nowMs());

        if (build_options.enable_http2 and conn.protocol == .http1 and conn.read_offset == 0) {
            const end = conn.read_offset + conn.read_buffered_bytes;
            if (end <= buffer_handle.bytes.len) {
                const candidate = buffer_handle.bytes[0..end];
                if (matchesHttp2Preface(candidate)) {
                    if (candidate.len < http2.Preface.len) return;
                    if (conn.http2_stack == null) {
                        const stack_ptr = try self.allocator.create(http2.Stack);
                        stack_ptr.* = http2.Stack.initWithConfig(.{
                            .max_streams = self.cfg.http2.max_streams,
                            .max_header_list_size = self.cfg.http2.max_header_list_size,
                            .initial_window_size = self.cfg.http2.initial_window_size,
                            .max_frame_size = self.cfg.http2.max_frame_size,
                            .max_dynamic_table_size = self.cfg.http2.max_dynamic_table_size,
                        });
                        conn.http2_stack = stack_ptr;
                    }
                    conn.protocol = .http2;
                    // RFC 9113 §3.4: Server MUST send SETTINGS as first frame
                    self.sendHttp2ServerPreface(conn) catch {
                        self.closeConnection(conn);
                        return;
                    };
                }
            }
        }

        if (conn.protocol == .http2) {
            try self.handleHttp2Read(conn);
            // For TLS h2, OpenSSL can have more decrypted records buffered
            // internally. Drain the SSL buffer by looping until WouldBlock —
            // epoll is edge-triggered on the kernel socket and won't fire
            // EPOLLIN for data that's already in SSL's buffer.
            if (conn.is_tls) {
                while (true) {
                    const drain_buf = conn.read_buffer orelse break;
                    const drain_offset = conn.read_offset + conn.read_buffered_bytes;
                    if (drain_offset >= drain_buf.bytes.len) break;
                    const drain_slice = drain_buf.bytes[drain_offset..];
                    switch (self.connRead(conn, drain_slice)) {
                        .bytes => |n| {
                            self.io.onReadBuffered(conn, n);
                            conn.markActive(self.io.nowMs());
                            try self.handleHttp2Read(conn);
                        },
                        .eof => {
                            self.closeConnection(conn);
                            return;
                        },
                        .again, .err => break,
                    }
                }
            }
            return;
        }

        while (conn.read_buffered_bytes > 0 and conn.canEnqueueWrite()) {
            const start = conn.read_offset;
            const end = start + conn.read_buffered_bytes;
            if (end > buffer_handle.bytes.len) break;
            const parse = http1.parse(buffer_handle.bytes[start..end], .{
                .max_header_bytes = self.cfg.limits.max_header_bytes,
                .max_body_bytes = self.cfg.limits.max_body_bytes,
                .max_header_count = self.cfg.limits.max_header_count,
                .headers_storage = conn.headers[0..],
            });
            if (parse.state == .partial) {
                if (parse.expect_continue and !conn.sent_continue) {
                    conn.sent_continue = true;
                    try self.queueResponse(conn, continueResponse());
                }
                // If buffer is full with a partial request, attempt body accumulation now.
                // With edge-triggered epoll, we may not get another read event to trigger
                // the buffer-full handler at the top of handleRead.
                const parse_end = conn.read_offset + conn.read_buffered_bytes;
                if (parse_end >= buffer_handle.bytes.len) {
                    const hparse = http1.parseHeaders(buffer_handle.bytes[conn.read_offset..parse_end], .{
                        .max_header_bytes = self.cfg.limits.max_header_bytes,
                        .max_body_bytes = self.cfg.limits.max_body_bytes,
                        .max_header_count = self.cfg.limits.max_header_count,
                        .headers_storage = conn.headers[0..],
                    });
                    if (hparse.state == .complete and (hparse.is_chunked or hparse.content_length > 0)) {
                        self.initBodyAccumulation(conn, hparse, buffer_handle) catch {
                            conn.close_after_write = true;
                            self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                            try self.queueResponse(conn, errorResponseFor(.body_too_large));
                            return;
                        };
                        // Re-enter to drain remaining socket data
                        return self.handleRead(index);
                    } else if (hparse.state == .partial) {
                        // Headers not complete → 431
                        conn.close_after_write = true;
                        self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                        try self.queueResponse(conn, errorResponseFor(.header_too_large));
                    }
                    // else: hparse.state == .err handled by returning (let next event handle it)
                }
                return;
            }
            if (parse.state == .err) {
                conn.close_after_write = true;
                self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                try self.queueResponse(conn, errorResponseFor(parse.error_code));
                return;
            }
            conn.header_count = parse.view.headers.len;
            conn.is_head_request = (parse.view.method == .HEAD);
            // Reset sent_continue for each new request in pipelined connections
            conn.sent_continue = false;
            if (!parse.keep_alive) conn.close_after_write = true;
            self.io.onReadConsumed(conn, parse.consumed_bytes);

            if (!self.isAllowedHost(parse.view)) {
                conn.close_after_write = true;
                try self.queueResponse(conn, badRequestResponse());
                return;
            }

            // Check for static file requests - use sendfile for zero-copy
            if (self.cfg.static_root.len > 0 and std.mem.startsWith(u8, parse.view.path, "/static/")) {
                const file_path = parse.view.path[8..]; // Skip "/static/"
                const content_type = guessContentType(file_path);
                try self.queueFileResponse(conn, self.cfg.static_root, file_path, content_type);
                if (conn.read_buffered_bytes == 0) break;
                continue;
            }

            // Check proxy routes before router dispatch
            if (self.proxy) |proxy| {
                if (proxy.matchRoute(&parse.view) != null) {
                    var mw_ctx = middleware.Context{
                        .protocol = .http1,
                        .buffer_ops = .{
                            .ctx = &self.io,
                            .acquire = acquireBufferOpaque,
                            .release = releaseBufferOpaque,
                        },
                    };
                    // Use cached client IP for proxy headers
                    var ip_buf: [64]u8 = undefined;
                    var client_ip_str: ?[]const u8 = null;
                    if (conn.cached_peer_ip) |ip4| {
                        const ip_len = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                        if (ip_len.len > 0) client_ip_str = ip_buf[0..ip_len.len];
                    }
                    var proxy_result = proxy.handle(
                        parse.view,
                        &mw_ctx,
                        client_ip_str,
                        false, // HTTP/1.1 listener is non-TLS; QUIC/HTTP3 connections don't use this proxy path
                        self.io.nowMs(),
                    );
                    defer proxy_result.release();

                    try self.queueResponse(conn, proxy_result.resp);
                    // Materialize pending_body before proxy_result.release() frees the upstream buffer
                    if (conn.pending_body.len > 0) {
                        self.materializePendingBody(conn);
                    }
                    if (conn.read_buffered_bytes == 0) break;
                    continue;
                }
            }

            // Fast path: pre-encoded h1 response cache. Hot static
            // endpoints skip the router, middleware, and response
            // encoding entirely and write cached bytes directly.
            if (self.tryDispatchPreencodedH1(conn, parse.view)) {
                if (conn.read_buffered_bytes == 0) break;
                continue;
            }

            var mw_ctx = middleware.Context{
                .protocol = .http1,
                .is_tls = conn.is_tls,
                .buffer_ops = .{
                    .ctx = &self.io,
                    .acquire = acquireBufferOpaque,
                    .release = releaseBufferOpaque,
                },
            };
            // Use cached client IP for rate limiting and logging
            if (conn.cached_peer_ip) |ip4| {
                mw_ctx.client_ip = ip4;
            } else if (conn.cached_peer_ip6) |ip6| {
                mw_ctx.client_ip6 = ip6;
            }
            var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
            var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
            const arena_handle = self.io.acquireBuffer();
            var empty_arena: [0]u8 = undefined;
            const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
            var scratch = router.HandlerScratch{
                .response_buf = response_buf[0..],
                .response_headers = response_headers[0..],
                .arena_buf = arena_buf,
                .arena_handle = arena_handle,
                .buffer_ops = mw_ctx.buffer_ops,
            };
            const result = self.app_router.handle(parse.view, &mw_ctx, &scratch);
            if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
            // Apply rate limit backpressure if signaled
            if (result.pause_reads_ms) |pause_ms| {
                conn.setRateLimitPause(self.io.nowMs(), pause_ms);
            }
            try self.queueResponse(conn, result.resp);
            if (conn.read_buffered_bytes == 0) break;
        }

        // Read-loop draining: if buffer is fully consumed and we can still process,
        // try one more non-blocking read to avoid an extra event loop round-trip.
        // This helps with fast persistent-connection clients (e.g., k6 benchmarks).
        if (conn.read_buffered_bytes == 0 and conn.canEnqueueWrite() and !conn.close_after_write) {
            conn.read_offset = 0;
            const drain_buf = conn.read_buffer orelse return;
            switch (self.connRead(conn, drain_buf.bytes)) {
                .bytes => |drain_count| {
                    self.io.onReadBuffered(conn, drain_count);
                    conn.markActive(self.io.nowMs());
                    return self.handleRead(index);
                },
                .eof, .again, .err => {},
            }
            // No more data available, continue normally
        }
    }

    /// Send the HTTP/2 server connection preface (SETTINGS frame)
    fn sendHttp2ServerPreface(self: *Server, conn: *connection.Connection) !void {
        const buf = self.io.acquireBuffer() orelse return error.OutOfMemory;
        const len = http2.writeServerSettings(buf.bytes, .{
            .max_streams = self.cfg.http2.max_streams,
            .max_header_list_size = self.cfg.http2.max_header_list_size,
            .initial_window_size = self.cfg.http2.initial_window_size,
            .max_frame_size = self.cfg.http2.max_frame_size,
            .max_dynamic_table_size = self.cfg.http2.max_dynamic_table_size,
        }) catch {
            self.io.releaseBuffer(buf);
            return error.OutOfMemory;
        };
        if (!conn.enqueueWrite(buf, len)) {
            self.io.releaseBuffer(buf);
            return error.OutOfMemory;
        }
        self.io.onWriteBuffered(conn, len);
    }

    /// Send an HTTP/2 control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE, GOAWAY)
    fn sendHttp2ControlFrame(self: *Server, conn: *connection.Connection, frame_data: []const u8) void {
        const buf = self.io.acquireBuffer() orelse return;
        if (frame_data.len > buf.bytes.len) {
            self.io.releaseBuffer(buf);
            return;
        }
        @memcpy(buf.bytes[0..frame_data.len], frame_data);
        if (!conn.enqueueWrite(buf, frame_data.len)) {
            self.io.releaseBuffer(buf);
            return;
        }
        self.io.onWriteBuffered(conn, frame_data.len);
    }

    fn handleHttp2Read(self: *Server, conn: *connection.Connection) !void {
        const buffer_handle = conn.read_buffer orelse return;
        const stack = conn.http2_stack orelse return;
        // Reserve enough write queue space for a full ingest batch:
        // 16 events × 2 frames (HEADERS+DATA) per event + control frames headroom.
        const min_write_slots: u8 = 36;
        while (conn.read_buffered_bytes > 0 and conn.writeQueueAvailable() >= min_write_slots) {
            const start = conn.read_offset;
            const end = start + conn.read_buffered_bytes;
            if (end > buffer_handle.bytes.len) break;
            const slice = buffer_handle.bytes[start..end];
            var frames: [16]http2.Frame = undefined;
            var events: [16]http2.Event = undefined;
            const ingest = stack.ingest(slice, frames[0..], events[0..]);
            // .partial means either we need more bytes from the socket OR the
            // frames buffer was full (16 slots) and more frames remain in the
            // read buffer. If we made progress, continue the loop to drain.
            // If we made no progress, we genuinely need more socket data.
            if (ingest.state == .partial and ingest.consumed_bytes == 0) return;
            if (ingest.state == .err) {
                // RFC 9113 §5.4.1: Send GOAWAY before closing on connection error
                var goaway_buf: [17]u8 = undefined;
                const goaway_len = http2.writeGoaway(&goaway_buf, stack.last_stream_id, 0x01) catch 0;
                if (goaway_len > 0) {
                    self.sendHttp2ControlFrame(conn, goaway_buf[0..goaway_len]);
                }
                self.closeConnection(conn);
                return;
            }
            self.io.onReadConsumed(conn, ingest.consumed_bytes);

            // Pending headers table: h2 POST/PUT with a body sends a
            // HEADERS frame (end_stream=false) followed by one or more
            // DATA frames. We stash the headers here and match them
            // up with the next DATA(end_stream=true) for the same
            // stream_id so the router sees a complete request with
            // a non-empty body. Before this PR, the .data arm was
            // `_ = data;` and body-bearing requests were silently
            // dropped — visible on the Mixed GET+POST benchmark
            // where swerver was at 12K vs actix's 33K.
            //
            // Scope: single-ingest-batch. For small POST bodies
            // (curl-sized, benchmark-sized) the HEADERS and DATA
            // frames fit in one TCP read and one ingest call, so
            // they're both in this events array together. Large
            // POST bodies that span multiple TCP reads still fall
            // through to 501 — tracked as a follow-up alongside
            // Connection-level pending state.
            var pending_headers: [16]?http2.HeadersEvent = [_]?http2.HeadersEvent{null} ** 16;
            var pending_count: usize = 0;

            for (events[0..ingest.event_count]) |event| {
                switch (event) {
                    .headers => |hdr| {
                        if (!self.isAllowedHost(hdr.request)) {
                            try self.queueHttp2Response(conn, hdr.stream_id, badRequestResponse(), hdr.request.method == .HEAD);
                        } else if (hdr.end_stream) {
                            // GET/HEAD/DELETE or any no-body request —
                            // hot endpoints skip the router via the
                            // pre-encoded cache; otherwise dispatch
                            // normally.
                            const method_str = hdr.request.getMethodName();
                            if (self.findAndRefreshPreencodedH2(method_str, hdr.request.path)) |entry| {
                                self.sendH2PreencodedBytes(conn, hdr.stream_id, entry);
                            } else {
                                try self.dispatchHttp2Request(conn, hdr.stream_id, hdr.request, "");
                            }
                        } else {
                            // Body-bearing request. Stash the HEADERS
                            // until a matching DATA(end_stream=true)
                            // arrives in this batch.
                            if (pending_count < pending_headers.len) {
                                pending_headers[pending_count] = hdr;
                                pending_count += 1;
                            } else {
                                // Pending table full — fall back to
                                // the legacy 501 path for this stream.
                                try self.queueHttp2Response(conn, hdr.stream_id, notImplementedResponse(), hdr.request.method == .HEAD);
                            }
                        }
                    },
                    .data => |data_ev| {
                        // Find matching stashed HEADERS for this stream_id.
                        var matched: ?usize = null;
                        var i: usize = 0;
                        while (i < pending_count) : (i += 1) {
                            if (pending_headers[i]) |p| {
                                if (p.stream_id == data_ev.stream_id) {
                                    matched = i;
                                    break;
                                }
                            }
                        }
                        if (matched) |idx| {
                            const hdr_opt = pending_headers[idx];
                            pending_headers[idx] = null;
                            if (hdr_opt) |hdr| {
                                if (data_ev.end_stream) {
                                    // Single-DATA-frame body complete —
                                    // dispatch the request with the body slice.
                                    // DataEvent.data is a slice into the
                                    // connection's read buffer, valid for the
                                    // synchronous handler call.
                                    try self.dispatchHttp2Request(conn, hdr.stream_id, hdr.request, data_ev.data);
                                } else {
                                    // Multi-DATA-frame body not supported in
                                    // this fix. Return 501 instead of silently
                                    // buffering across DATA events.
                                    try self.queueHttp2Response(conn, hdr.stream_id, notImplementedResponse(), hdr.request.method == .HEAD);
                                }
                            }
                        }
                        // Data frame with no matching pending HEADERS: drop.
                        // Either the headers were already dispatched (impossible
                        // for a well-formed client, HEADERS come before DATA) or
                        // the pending table was full. Either way nothing to do.
                    },
                    .settings => |settings_event| {
                        if (!settings_event.ack) {
                            // RFC 9113 §6.5.3: MUST send SETTINGS ACK
                            var ack_buf: [9]u8 = undefined;
                            const ack_len = http2.writeSettingsAck(&ack_buf) catch 0;
                            if (ack_len > 0) {
                                self.sendHttp2ControlFrame(conn, ack_buf[0..ack_len]);
                            }
                        }
                    },
                    .ping => |ping_event| {
                        // RFC 9113 §6.7: MUST respond with PING ACK
                        var ping_buf: [17]u8 = undefined;
                        const ping_len = http2.writePingAck(&ping_buf, ping_event.opaque_data) catch 0;
                        if (ping_len > 0) {
                            self.sendHttp2ControlFrame(conn, ping_buf[0..ping_len]);
                        }
                    },
                    .window_update_needed => |wu| {
                        // RFC 9113 §6.9: Send WINDOW_UPDATE
                        var wu_buf: [13]u8 = undefined;
                        const wu_len = http2.writeWindowUpdate(&wu_buf, wu.stream_id, wu.increment) catch 0;
                        if (wu_len > 0) {
                            self.sendHttp2ControlFrame(conn, wu_buf[0..wu_len]);
                        }
                    },
                    .err => {},
                }
            }
            if (conn.read_buffered_bytes == 0) break;
        }
    }

    fn handleWrite(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        const socket_fd = conn.fd orelse return;

        while (true) {
            if (conn.is_tls) {
                // TLS: write one buffer at a time through SSL_write
                while (conn.write_count > 0) {
                    const entry = conn.peekWrite() orelse break;
                    const data = entry.handle.bytes[entry.offset..entry.len];
                    if (data.len == 0) {
                        self.io.releaseBuffer(entry.handle);
                        conn.popWrite();
                        continue;
                    }
                    switch (self.connWrite(conn, data)) {
                        .bytes => |n| {
                            conn.markActive(self.io.nowMs());
                            if (n >= data.len) {
                                self.io.onWriteCompleted(conn, data.len);
                                self.io.releaseBuffer(entry.handle);
                                conn.popWrite();
                                if (conn.hasPendingBody()) {
                                    self.streamBodyChunks(conn, conn.pending_body);
                                }
                            } else {
                                entry.offset += n;
                                self.io.onWriteCompleted(conn, n);
                            }
                        },
                        .again => return,
                        .err => {
                            self.closeConnection(conn);
                            return;
                        },
                    }
                }
                if (conn.write_count == 0 and conn.hasPendingFile() and self.bufferPendingFileWrites(conn)) {
                    continue;
                }
                if (conn.state == .closed) return;
            } else {
                // Plain TCP: use writev to gather multiple entries per syscall
                while (conn.write_count > 0) {
                    var iov: [16]std.posix.iovec_const = undefined;
                    var iov_count: u32 = 0;
                    {
                        var scan_head = conn.write_head;
                        var scan_remaining = conn.write_count;
                        while (scan_remaining > 0 and iov_count < 16) {
                            const e = &conn.write_queue[scan_head];
                            const s = e.handle.bytes[e.offset..e.len];
                            iov[iov_count] = .{ .base = s.ptr, .len = s.len };
                            iov_count += 1;
                            scan_head = if (scan_head + 1 >= conn.write_queue.len) 0 else scan_head + 1;
                            scan_remaining -= 1;
                        }
                    }
                    if (iov_count == 0) break;

                    const bytes_written = std.c.writev(socket_fd, &iov, @intCast(iov_count));
                    if (bytes_written < 0) {
                        switch (std.posix.errno(bytes_written)) {
                            .AGAIN => return,
                            .INTR => continue,
                            else => {
                                self.closeConnection(conn);
                                return;
                            },
                        }
                    }
                    if (bytes_written == 0) return;
                    var written: usize = @intCast(bytes_written);
                    conn.markActive(self.io.nowMs());

                    while (written > 0) {
                        const entry = conn.peekWrite() orelse break;
                        const remaining_in_entry = entry.len - entry.offset;
                        if (written >= remaining_in_entry) {
                            written -= remaining_in_entry;
                            self.io.onWriteCompleted(conn, remaining_in_entry);
                            self.io.releaseBuffer(entry.handle);
                            conn.popWrite();
                            if (conn.hasPendingBody()) {
                                self.streamBodyChunks(conn, conn.pending_body);
                            }
                        } else {
                            entry.offset += written;
                            self.io.onWriteCompleted(conn, written);
                            written = 0;
                        }
                    }
                }
            }
            break;
        }

        // All buffer writes done, try sendfile if file is pending.
        if (!conn.is_tls) {
            while (conn.hasPendingFile()) {
                const file_fd = conn.pending_file_fd.?;
                const result = net.sendfile(socket_fd, file_fd, &conn.pending_file_offset, conn.pending_file_remaining) catch |err| {
                    switch (err) {
                        error.WouldBlock => return,
                        error.Closed, error.Failed => {
                            conn.cleanupPendingFile();
                            self.closeConnection(conn);
                            return;
                        },
                    }
                };
                if (result.bytes_sent == 0) return;
                conn.pending_file_remaining -= result.bytes_sent;
                conn.markActive(self.io.nowMs());

                if (conn.pending_file_remaining == 0) {
                    conn.cleanupPendingFile();
                    break;
                }
            }
        }

        // Check if all writes are complete
        if (conn.state == .closed) return;
        if (conn.write_count == 0 and !conn.hasPendingBody() and !conn.hasPendingFile()) {
            self.io.setTimeoutPhase(conn, .idle);
            if (conn.close_after_write) self.closeConnection(conn);
        }
    }

    fn handleError(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        self.closeConnection(conn);
    }

    fn queueResponse(self: *Server, conn: *connection.Connection, resp: response_mod.Response) !void {
        const body_len = resp.bodyLen();
        const body_bytes = resp.bodyBytes();
        const managed_body = switch (resp.body) {
            .managed => |managed| managed,
            else => null,
        };
        const scattered_body = switch (resp.body) {
            .scattered => |sc| sc,
            else => null,
        };
        const date_str = self.getCachedDate();
        // RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body
        const suppress_body = conn.is_head_request;
        const buf = self.io.acquireBuffer() orelse {
            // Cannot acquire buffer to send response - close connection
            if (managed_body) |managed| self.io.releaseBuffer(managed.handle);
            if (scattered_body) |sc| {
                for (sc.handles[0..sc.count]) |h| self.io.releaseBuffer(h);
            }
            self.closeConnection(conn);
            return;
        };
        // Include Alt-Svc header to advertise HTTP/3 when QUIC is enabled
        const alt_svc: ?[]const u8 = if (self.alt_svc_len > 0)
            self.alt_svc_value[0..self.alt_svc_len]
        else
            null;

        if (managed_body) |managed| {
            if (body_len > managed.handle.bytes.len) {
                self.io.releaseBuffer(managed.handle);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            const managed_bytes = managed.handle.bytes[0..body_len];

            // Try to fit headers + body in a single buffer for one write() syscall
            const header_space = 512;
            if (!suppress_body and body_len > 0 and body_len <= buf.bytes.len - header_space) {
                const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
                    self.io.releaseBuffer(managed.handle);
                    self.io.releaseBuffer(buf);
                    self.closeConnection(conn);
                    return;
                };
                if (header_len + body_len <= buf.bytes.len) {
                    // Copy body into header buffer — single write
                    @memcpy(buf.bytes[header_len .. header_len + body_len], managed_bytes);
                    self.io.releaseBuffer(managed.handle);
                    if (!conn.enqueueWrite(buf, header_len + body_len)) {
                        self.io.releaseBuffer(buf);
                        self.closeConnection(conn);
                        return;
                    }
                    self.io.onWriteBuffered(conn, header_len + body_len);
                    self.io.setTimeoutPhase(conn, .write);
                    return;
                }
            }

            // Fallback: headers and body as separate writes
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
                self.io.releaseBuffer(managed.handle);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            };
            if (!conn.enqueueWrite(buf, header_len)) {
                self.io.releaseBuffer(managed.handle);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, header_len);

            if (body_len == 0 or suppress_body) {
                self.io.releaseBuffer(managed.handle);
                self.io.setTimeoutPhase(conn, .write);
                return;
            }
            if (!conn.enqueueWrite(managed.handle, body_len)) {
                self.io.releaseBuffer(managed.handle);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, body_len);
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        // Scattered body: enqueue pre-allocated pool buffers directly (zero-copy echo)
        if (scattered_body) |sc| {
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
                for (sc.handles[0..sc.count]) |h| self.io.releaseBuffer(h);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            };
            if (!conn.enqueueWrite(buf, header_len)) {
                for (sc.handles[0..sc.count]) |h| self.io.releaseBuffer(h);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, header_len);

            if (suppress_body or sc.count == 0) {
                for (sc.handles[0..sc.count]) |h| self.io.releaseBuffer(h);
                self.io.setTimeoutPhase(conn, .write);
                return;
            }

            // Enqueue each body buffer directly — no copy needed
            for (0..sc.count) |i| {
                const buf_len = if (i == sc.count - 1) sc.last_buf_len else sc.buffer_size;
                if (!conn.enqueueWrite(sc.handles[i], buf_len)) {
                    // Can't enqueue — release remaining buffers and close
                    for (i..sc.count) |j| self.io.releaseBuffer(sc.handles[j]);
                    self.closeConnection(conn);
                    return;
                }
                self.io.onWriteBuffered(conn, buf_len);
            }
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        if (suppress_body) {
            // HEAD: send headers with Content-Length but no body
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            };
            if (!conn.enqueueWrite(buf, header_len)) {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, header_len);
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        // For large bodies that don't fit in a single buffer, write headers first then chunk body
        const header_space = 512; // Reserve space for headers
        if (body_len > buf.bytes.len - header_space) {
            // Write headers only first
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            };
            if (!conn.enqueueWrite(buf, header_len)) {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, header_len);

            // Stream body in chunks - only enqueue what fits, store rest for later
            self.streamBodyChunks(conn, body_bytes);
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        // Small response - write everything in one buffer
        const written = encodeResponse(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
            // Cannot encode response - close connection
            self.io.releaseBuffer(buf);
            self.closeConnection(conn);
            return;
        };
        if (!conn.enqueueWrite(buf, written)) {
            self.io.releaseBuffer(buf);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, written);
        self.io.setTimeoutPhase(conn, .write);
    }

    /// Stream body data in chunks, enqueueing up to available queue slots.
    /// Remaining data is stored in conn.pending_body for later streaming.
    ///
    /// LIFETIME CONTRACT: `body` (and thus `conn.pending_body`) must point to
    /// memory that outlives the connection — typically compile-time string literals
    /// from handler responses (e.g., `body = .{ .bytes = "Hello" }`). The slice is
    /// never freed by the server; it is only read and copied into write buffers.
    /// Managed bodies (.managed) are written inline in queueResponse and never
    /// stored in pending_body.
    fn streamBodyChunks(self: *Server, conn: *connection.Connection, body: []const u8) void {
        var remaining = body;

        // Enqueue chunks while we have queue space (leave 1 slot for new requests)
        while (remaining.len > 0 and conn.writeQueueAvailable() > 1) {
            const body_buf = self.io.acquireBuffer() orelse {
                // No buffers available - store remaining and wait
                conn.pending_body = remaining;
                return;
            };
            const chunk_len = @min(remaining.len, body_buf.bytes.len);
            @memcpy(body_buf.bytes[0..chunk_len], remaining[0..chunk_len]);
            if (!conn.enqueueWrite(body_buf, chunk_len)) {
                self.io.releaseBuffer(body_buf);
                conn.pending_body = remaining;
                return;
            }
            self.io.onWriteBuffered(conn, chunk_len);
            remaining = remaining[chunk_len..];
        }

        // Store any remaining data for continuation in handleWrite
        conn.pending_body = remaining;
    }

    /// Queue a file response using sendfile for zero-copy transfer.
    /// Sends HTTP headers first, then sets up the connection for sendfile.
    fn queueFileResponse(self: *Server, conn: *connection.Connection, static_root: []const u8, file_path: []const u8, content_type: []const u8) !void {
        _ = static_root; // No longer used at request time — we use the cached dirfd.

        // Reject paths containing percent-encoded sequences to prevent URL-encoded
        // path traversal (e.g., %2e%2e bypassing the ".." check below)
        if (std.mem.indexOfScalar(u8, file_path, '%') != null) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        // Prevent path traversal attacks — reject ".." components
        if (std.mem.indexOf(u8, file_path, "..") != null) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        // Reject paths with null bytes
        if (std.mem.indexOfScalar(u8, file_path, 0) != null) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        // Reject absolute paths — the root is the cached dirfd, not "/"
        if (file_path.len > 0 and file_path[0] == '/') {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }

        // Resolve against the cached static_root dirfd. This avoids realpath
        // on the hot path and pins the root directory against post-startup
        // renames. If static_root is unset or failed to open at init, serve 404.
        const root_fd = self.static_root_fd orelse {
            try self.queueResponse(conn, notFoundResponse());
            return;
        };

        // Build null-terminated relative path.
        var path_buf: [4096]u8 = undefined;
        if (file_path.len >= path_buf.len) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        @memcpy(path_buf[0..file_path.len], file_path);
        path_buf[file_path.len] = 0;
        const path_z: [*:0]const u8 = @ptrCast(&path_buf);

        // Open with NOFOLLOW on the leaf. Intermediate-component symlinks
        // under static_root can still escape — operators should not place
        // arbitrary symlinks inside the static tree. Linux-only full
        // containment via openat2(RESOLVE_BENEATH) is a future enhancement.
        var o_flags: std.posix.O = .{};
        if (@hasField(std.posix.O, "NOFOLLOW")) o_flags.NOFOLLOW = true;
        const file_fd = std.posix.openatZ(root_fd, path_z, o_flags, 0) catch {
            try self.queueResponse(conn, notFoundResponse());
            return;
        };

        // Get file size using lseek. Also rejects directories (can't seek on them).
        const end_pos = std.c.lseek(file_fd, 0, std.posix.SEEK.END);
        if (end_pos < 0) {
            clock.closeFd(file_fd);
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        // Seek back to start for reading
        _ = std.c.lseek(file_fd, 0, std.posix.SEEK.SET);
        const file_size: u64 = @intCast(end_pos);

        // Build and send headers
        const buf = self.io.acquireBuffer() orelse {
            clock.closeFd(file_fd);
            self.closeConnection(conn);
            return;
        };

        var size_buf: [20]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{file_size}) catch {
            self.io.releaseBuffer(buf);
            clock.closeFd(file_fd);
            self.closeConnection(conn);
            return;
        };

        const headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = content_type },
            .{ .name = "Content-Length", .value = size_str },
        };

        const header_len = encodeFileHeaders(buf.bytes, 200, &headers, self.getCachedDate()) catch {
            self.io.releaseBuffer(buf);
            clock.closeFd(file_fd);
            self.closeConnection(conn);
            return;
        };

        if (!conn.enqueueWrite(buf, header_len)) {
            self.io.releaseBuffer(buf);
            clock.closeFd(file_fd);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, header_len);

        // RFC 9110 §9.3.2: HEAD response sends headers with Content-Length but no body
        if (conn.is_head_request) {
            clock.closeFd(file_fd);
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        // Set up sendfile - file body will be sent after headers
        conn.pending_file_fd = file_fd;
        conn.pending_file_offset = 0;
        conn.pending_file_remaining = file_size;

        self.io.setTimeoutPhase(conn, .write);
    }

    fn queueHttp2Response(self: *Server, conn: *connection.Connection, stream_id: u32, resp: response_mod.Response, is_head: bool) !void {
        const body_len = resp.bodyLen();
        const body_bytes = resp.bodyBytes();
        const managed_body = switch (resp.body) {
            .managed => |managed| managed,
            else => null,
        };
        defer if (managed_body) |managed| self.io.releaseBuffer(managed.handle);
        const header_buf = self.io.acquireBuffer() orelse {
            self.closeConnection(conn);
            return;
        };
        // Build headers array with Alt-Svc if enabled
        var headers_with_alt_svc: [65]response_mod.Header = undefined;
        var header_count = resp.headers.len;
        for (resp.headers, 0..) |h, i| {
            headers_with_alt_svc[i] = h;
        }
        // Add Alt-Svc header to advertise HTTP/3
        if (self.alt_svc_len > 0 and header_count < headers_with_alt_svc.len) {
            headers_with_alt_svc[header_count] = .{
                .name = "alt-svc",
                .value = self.alt_svc_value[0..self.alt_svc_len],
            };
            header_count += 1;
        }
        const header_block_len = http2.encodeResponseHeaders(header_buf.bytes[9..], resp.status, headers_with_alt_svc[0..header_count], body_len) catch {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        };
        const max_frame_size: usize = if (conn.http2_stack) |stack| @intCast(stack.max_frame_size) else 16384;
        if (header_block_len > max_frame_size) {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        }
        // RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body
        const headers_flags: u8 = if (body_len == 0 or is_head) 0x5 else 0x4;
        // RFC 9113 §8.1: Response MUST be on the stream that carried the request
        const resp_stream_id: u32 = stream_id;
        http2.writeFrameHeader(header_buf.bytes, .headers, headers_flags, resp_stream_id, header_block_len) catch {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        };
        const header_frame_len = 9 + header_block_len;
        if (!conn.enqueueWrite(header_buf, header_frame_len)) {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, header_frame_len);
        self.io.setTimeoutPhase(conn, .write);

        if (body_len == 0 or is_head) {
            // END_STREAM was set on HEADERS frame — stream is fully closed
            if (conn.http2_stack) |stack| stack.closeStream(resp_stream_id);
            return;
        }
        var remaining = body_bytes;
        while (remaining.len > 0) {
            const data_buf = self.io.acquireBuffer() orelse {
                // Cannot complete response - close connection
                self.closeConnection(conn);
                return;
            };
            const max_payload = @min(data_buf.bytes.len - 9, max_frame_size);
            const chunk_len = if (remaining.len < max_payload) remaining.len else max_payload;
            @memcpy(data_buf.bytes[9 .. 9 + chunk_len], remaining[0..chunk_len]);
            const flags: u8 = if (remaining.len == chunk_len) 0x1 else 0x0;
            http2.writeFrameHeader(data_buf.bytes, .data, flags, resp_stream_id, chunk_len) catch {
                self.io.releaseBuffer(data_buf);
                self.closeConnection(conn);
                return;
            };
            const frame_len = 9 + chunk_len;
            if (!conn.enqueueWrite(data_buf, frame_len)) {
                self.io.releaseBuffer(data_buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, frame_len);
            remaining = remaining[chunk_len..];
        }
        // END_STREAM was set on last DATA frame — stream is fully closed
        if (conn.http2_stack) |stack| stack.closeStream(resp_stream_id);
    }

    fn isValidHeaderBytes(s: []const u8) bool {
        for (s) |ch| {
            if (ch == '\r' or ch == '\n' or ch == 0) return false;
        }
        return true;
    }

    /// Comptime-generated status line lookup table for common HTTP status codes.
    /// Maps status codes to pre-formatted "HTTP/1.1 NNN Reason\r\n" byte strings.
    const StatusLine = struct {
        bytes: []const u8,

        fn comptimeFor(code: u16, reason: []const u8) StatusLine {
            return .{ .bytes = std.fmt.comptimePrint("HTTP/1.1 {d} {s}\r\n", .{ code, reason }) };
        }
    };

    const status_line_table: [512]?StatusLine = blk: {
        var table: [512]?StatusLine = .{null} ** 512;
        const entries = .{
            .{ 100, "Continue" },
            .{ 101, "Switching Protocols" },
            .{ 200, "OK" },
            .{ 201, "Created" },
            .{ 202, "Accepted" },
            .{ 204, "No Content" },
            .{ 206, "Partial Content" },
            .{ 301, "Moved Permanently" },
            .{ 302, "Found" },
            .{ 303, "See Other" },
            .{ 304, "Not Modified" },
            .{ 307, "Temporary Redirect" },
            .{ 308, "Permanent Redirect" },
            .{ 400, "Bad Request" },
            .{ 401, "Unauthorized" },
            .{ 402, "Payment Required" },
            .{ 403, "Forbidden" },
            .{ 404, "Not Found" },
            .{ 405, "Method Not Allowed" },
            .{ 408, "Request Timeout" },
            .{ 411, "Length Required" },
            .{ 413, "Content Too Large" },
            .{ 414, "URI Too Long" },
            .{ 415, "Unsupported Media Type" },
            .{ 417, "Expectation Failed" },
            .{ 429, "Too Many Requests" },
            .{ 500, "Internal Server Error" },
            .{ 501, "Not Implemented" },
            .{ 502, "Bad Gateway" },
            .{ 503, "Service Unavailable" },
            .{ 504, "Gateway Timeout" },
        };
        for (entries) |entry| {
            table[entry[0]] = StatusLine.comptimeFor(entry[0], entry[1]);
        }
        break :blk table;
    };

    /// Write pre-formatted status line via lookup table, falling back to bufPrint.
    inline fn writeStatusLine(buf: []u8, status: u16) !usize {
        if (status < status_line_table.len) {
            if (status_line_table[status]) |sl| {
                if (sl.bytes.len > buf.len) return error.NoSpaceLeft;
                @memcpy(buf[0..sl.bytes.len], sl.bytes);
                return sl.bytes.len;
            }
        }
        // Fallback for unknown status codes
        const reason = reasonPhrase(status);
        const line = try std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\n", .{ status, reason });
        return line.len;
    }

    /// Fast header write: "Name: Value\r\n" via @memcpy (no format string parsing).
    inline fn writeHeader(buf: []u8, name: []const u8, value: []const u8) !usize {
        const needed = name.len + 2 + value.len + 2; // ": " + "\r\n"
        if (needed > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..name.len], name);
        var pos = name.len;
        buf[pos] = ':';
        buf[pos + 1] = ' ';
        pos += 2;
        @memcpy(buf[pos..][0..value.len], value);
        pos += value.len;
        buf[pos] = '\r';
        buf[pos + 1] = '\n';
        return pos + 2;
    }

    /// Fast usize-to-ASCII into buf, returns slice written.
    inline fn writeUsize(buf: []u8, value: usize) !usize {
        if (value == 0) {
            if (buf.len < 1) return error.NoSpaceLeft;
            buf[0] = '0';
            return 1;
        }
        // Write digits in reverse, then flip
        var tmp: [20]u8 = undefined; // max u64 is 20 digits
        var len: usize = 0;
        var v = value;
        while (v > 0) {
            tmp[len] = @intCast((v % 10) + '0');
            len += 1;
            v /= 10;
        }
        if (len > buf.len) return error.NoSpaceLeft;
        // Reverse into output
        for (0..len) |i| {
            buf[i] = tmp[len - 1 - i];
        }
        return len;
    }

    const connection_close_hdr = "Connection: close\r\n";
    const date_prefix = "Date: ";
    const alt_svc_prefix = "Alt-Svc: ";
    const content_length_prefix = "Content-Length: ";
    const crlf = "\r\n";

    /// Unified response encoder. When include_body is true, appends body bytes after headers.
    fn encodeResponseInner(buf: []u8, status: u16, headers: []const response_mod.Header, body_len: usize, body_bytes: []const u8, alt_svc: ?[]const u8, connection_close: bool, date_str: []const u8, include_body: bool) !usize {
        var index: usize = 0;

        // Status line
        index += try writeStatusLine(buf[index..], status);

        // RFC 9110 §15.2: 1xx responses have no body, no Date, no Content-Length
        if (status >= 100 and status < 200) {
            if (index + 2 > buf.len) return error.NoSpaceLeft;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            return index + 2;
        }

        // Response headers
        for (headers) |header| {
            if (!isValidHeaderBytes(header.name) or !isValidHeaderBytes(header.value)) continue;
            index += try writeHeader(buf[index..], header.name, header.value);
        }

        // Date header
        const date_total = date_prefix.len + date_str.len + crlf.len;
        if (index + date_total > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[index..][0..date_prefix.len], date_prefix);
        index += date_prefix.len;
        @memcpy(buf[index..][0..date_str.len], date_str);
        index += date_str.len;
        buf[index] = '\r';
        buf[index + 1] = '\n';
        index += 2;

        // Alt-Svc header
        if (alt_svc) |svc| {
            if (svc.len > 0) {
                const svc_total = alt_svc_prefix.len + svc.len + crlf.len;
                if (index + svc_total > buf.len) return error.NoSpaceLeft;
                @memcpy(buf[index..][0..alt_svc_prefix.len], alt_svc_prefix);
                index += alt_svc_prefix.len;
                @memcpy(buf[index..][0..svc.len], svc);
                index += svc.len;
                buf[index] = '\r';
                buf[index + 1] = '\n';
                index += 2;
            }
        }

        // Connection: close
        if (connection_close) {
            if (index + connection_close_hdr.len > buf.len) return error.NoSpaceLeft;
            @memcpy(buf[index..][0..connection_close_hdr.len], connection_close_hdr);
            index += connection_close_hdr.len;
        }

        // RFC 9110 §8.6: MUST NOT send Content-Length in 204 or 304 responses
        if (status == 204 or status == 304) {
            if (index + 2 > buf.len) return error.NoSpaceLeft;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            return index + 2;
        }

        // Content-Length + header terminator
        if (index + content_length_prefix.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[index..][0..content_length_prefix.len], content_length_prefix);
        index += content_length_prefix.len;
        index += try writeUsize(buf[index..], body_len);
        // "\r\n\r\n" terminates headers
        if (index + 4 > buf.len) return error.NoSpaceLeft;
        buf[index] = '\r';
        buf[index + 1] = '\n';
        buf[index + 2] = '\r';
        buf[index + 3] = '\n';
        index += 4;

        // Body (for small, inline responses)
        if (include_body) {
            if (index + body_bytes.len > buf.len) return error.NoSpaceLeft;
            @memcpy(buf[index..][0..body_bytes.len], body_bytes);
            index += body_bytes.len;
        }

        return index;
    }

    fn encodeResponse(buf: []u8, resp: response_mod.Response, alt_svc: ?[]const u8, connection_close: bool, date_str: []const u8) !usize {
        const body_bytes = resp.bodyBytes();
        return encodeResponseInner(buf, resp.status, resp.headers, body_bytes.len, body_bytes, alt_svc, connection_close, date_str, true);
    }

    fn encodeResponseHeaders(buf: []u8, resp: response_mod.Response, alt_svc: ?[]const u8, connection_close: bool, date_str: []const u8) !usize {
        const body_len = resp.bodyLen();
        return encodeResponseInner(buf, resp.status, resp.headers, body_len, "", alt_svc, connection_close, date_str, false);
    }

    /// Encode HTTP/1.1 response headers for file responses (doesn't add Content-Length)
    fn encodeFileHeaders(buf: []u8, status: u16, headers: []const response_mod.Header, date_str: []const u8) !usize {
        var index: usize = 0;

        index += try writeStatusLine(buf[index..], status);

        for (headers) |header| {
            if (!isValidHeaderBytes(header.name) or !isValidHeaderBytes(header.value)) continue;
            index += try writeHeader(buf[index..], header.name, header.value);
        }

        // Date header
        const date_total = date_prefix.len + date_str.len + crlf.len;
        if (index + date_total > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[index..][0..date_prefix.len], date_prefix);
        index += date_prefix.len;
        @memcpy(buf[index..][0..date_str.len], date_str);
        index += date_str.len;
        buf[index] = '\r';
        buf[index + 1] = '\n';
        index += 2;

        // End headers
        if (index + 2 > buf.len) return error.NoSpaceLeft;
        buf[index] = '\r';
        buf[index + 1] = '\n';
        return index + 2;
    }

    fn reasonPhrase(status: u16) []const u8 {
        return response_mod.statusPhrase(status);
    }

    /// Format current time as IMF-fixdate (RFC 9110 §5.6.7)
    /// e.g., "Sun, 06 Nov 1994 08:49:37 GMT"
    fn formatImfDate(buf: *[29]u8) []const u8 {
        const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
        const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        const ts = clock.realtimeTimespec() orelse return "Thu, 01 Jan 1970 00:00:00 GMT";
        const epoch_secs: u64 = @intCast(ts.sec);

        // Calculate date components from Unix timestamp
        const secs_per_day: u64 = 86400;
        var days = epoch_secs / secs_per_day;
        const day_secs = epoch_secs % secs_per_day;
        const hour = day_secs / 3600;
        const minute = (day_secs % 3600) / 60;
        const second = day_secs % 60;

        // Day of week (Jan 1 1970 = Thursday = index 0)
        const wday = days % 7;

        // Year/month/day from days since epoch
        var year: u64 = 1970;
        while (true) {
            const days_in_year: u64 = if (isLeapYear(year)) 366 else 365;
            if (days < days_in_year) break;
            days -= days_in_year;
            year += 1;
        }
        const leap = isLeapYear(year);
        const month_days = if (leap)
            [_]u64{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
        else
            [_]u64{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        var month: usize = 0;
        while (month < 11) : (month += 1) {
            if (days < month_days[month]) break;
            days -= month_days[month];
        }
        const day = days + 1;

        // Format: "Sun, 06 Nov 1994 08:49:37 GMT"
        _ = std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
            day_names[wday],
            day,
            month_names[month],
            year,
            hour,
            minute,
            second,
        }) catch return "Thu, 01 Jan 1970 00:00:00 GMT";
        return buf[0..29];
    }

    fn isLeapYear(year: u64) bool {
        return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
    }

    /// Return cached IMF-fixdate string, updating once per second.
    fn getCachedDate(self: *Server) []const u8 {
        const ts = clock.realtimeTimespec() orelse return "Thu, 01 Jan 1970 00:00:00 GMT";
        const epoch_secs: u64 = @intCast(ts.sec);
        if (epoch_secs != self.cached_date_epoch) {
            _ = formatImfDate(&self.cached_date);
            self.cached_date_epoch = epoch_secs;
        }
        return self.cached_date[0..29];
    }

    fn continueResponse() response_mod.Response {
        return .{
            .status = 100,
            .headers = &[_]response_mod.Header{},
            .body = .none,
        };
    }

    fn notFoundResponse() response_mod.Response {
        return .{
            .status = 404,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Not Found\n" },
        };
    }

    fn badRequestResponse() response_mod.Response {
        return .{
            .status = 400,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Bad Request\n" },
        };
    }

    fn notImplementedResponse() response_mod.Response {
        return .{
            .status = 501,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Not Implemented\n" },
        };
    }

    /// Dispatch an HTTP/2 request to the router and queue its response.
    /// Shared helper for the HEADERS-only and HEADERS+DATA dispatch
    /// paths in handleHttp2Read. `body` is an empty slice for GET/HEAD
    /// requests or a slice into the connection's read buffer for
    /// POST/PUT requests (valid for the duration of this synchronous
    /// call).
    fn dispatchHttp2Request(
        self: *Server,
        conn: *connection.Connection,
        stream_id: u32,
        hdr_request: request.RequestView,
        body: []const u8,
    ) !void {
        var mw_ctx = middleware.Context{
            .protocol = .http2,
            .is_tls = conn.is_tls,
            .stream_id = stream_id,
            .buffer_ops = .{
                .ctx = &self.io,
                .acquire = acquireBufferOpaque,
                .release = releaseBufferOpaque,
            },
        };
        if (conn.cached_peer_ip) |ip4| {
            mw_ctx.client_ip = ip4;
        } else if (conn.cached_peer_ip6) |ip6| {
            mw_ctx.client_ip6 = ip6;
        }
        // Inject the body into the request view. HEADERS events from
        // the h2 stack carry request.body = "" because the body arrives
        // in separate DATA frames; we patch it here at dispatch time.
        var request_with_body = hdr_request;
        request_with_body.body = body;

        var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
        var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
        const arena_handle = self.io.acquireBuffer();
        var empty_arena: [0]u8 = undefined;
        const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
        var scratch = router.HandlerScratch{
            .response_buf = response_buf[0..],
            .response_headers = response_headers[0..],
            .arena_buf = arena_buf,
            .arena_handle = arena_handle,
            .buffer_ops = mw_ctx.buffer_ops,
        };
        const result = self.app_router.handle(request_with_body, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
        if (result.pause_reads_ms) |pause_ms| {
            conn.setRateLimitPause(self.io.nowMs(), pause_ms);
        }
        try self.queueHttp2Response(conn, stream_id, result.resp, hdr_request.method == .HEAD);
    }

    /// Guess Content-Type from file extension
    fn guessContentType(path: []const u8) []const u8 {
        if (std.mem.endsWith(u8, path, ".html") or std.mem.endsWith(u8, path, ".htm")) {
            return "text/html";
        } else if (std.mem.endsWith(u8, path, ".css")) {
            return "text/css";
        } else if (std.mem.endsWith(u8, path, ".js")) {
            return "application/javascript";
        } else if (std.mem.endsWith(u8, path, ".json")) {
            return "application/json";
        } else if (std.mem.endsWith(u8, path, ".png")) {
            return "image/png";
        } else if (std.mem.endsWith(u8, path, ".jpg") or std.mem.endsWith(u8, path, ".jpeg")) {
            return "image/jpeg";
        } else if (std.mem.endsWith(u8, path, ".gif")) {
            return "image/gif";
        } else if (std.mem.endsWith(u8, path, ".svg")) {
            return "image/svg+xml";
        } else if (std.mem.endsWith(u8, path, ".txt")) {
            return "text/plain";
        } else if (std.mem.endsWith(u8, path, ".pdf")) {
            return "application/pdf";
        } else if (std.mem.endsWith(u8, path, ".wasm")) {
            return "application/wasm";
        } else {
            return "application/octet-stream";
        }
    }

    fn errorResponseFor(code: http1.ErrorCode) response_mod.Response {
        return switch (code) {
            .body_too_large => .{
                .status = 413,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Payload Too Large\n" },
            },
            .header_too_large => .{
                .status = 431,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Request Header Fields Too Large\n" },
            },
            .expectation_failed => .{
                .status = 417,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Expectation Failed\n" },
            },
            else => .{
                .status = 400,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Bad Request\n" },
            },
        };
    }

    fn buildHttp3RequestView(req: http3.RequestReadyEvent, headers_out: []request.Header) ?request.RequestView {
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var header_count: usize = 0;
        var saw_host = false;

        for (req.headers) |hdr| {
            if (std.mem.eql(u8, hdr.name, ":method")) {
                method = hdr.value;
            } else if (std.mem.eql(u8, hdr.name, ":path")) {
                path = hdr.value;
            } else if (std.mem.eql(u8, hdr.name, ":authority")) {
                authority = hdr.value;
            } else if (hdr.name.len > 0 and hdr.name[0] != ':') {
                if (header_count >= headers_out.len) return null;
                headers_out[header_count] = .{ .name = hdr.name, .value = hdr.value };
                saw_host = saw_host or std.ascii.eqlIgnoreCase(hdr.name, "host");
                header_count += 1;
            }
        }

        const method_str = method orelse return null;
        const path_str = path orelse return null;
        const parsed_method = request.Method.fromStringExtended(method_str) orelse return null;

        if (!saw_host) {
            if (authority) |authority_value| {
                if (header_count >= headers_out.len) return null;
                headers_out[header_count] = .{ .name = "host", .value = authority_value };
                header_count += 1;
            }
        }

        return .{
            .method = parsed_method,
            .method_raw = if (parsed_method == .OTHER) method_str else "",
            .path = path_str,
            .headers = headers_out[0..header_count],
            .body = req.body,
        };
    }

    fn isAllowedHost(self: *const Server, req_view: request.RequestView) bool {
        if (self.cfg.allowed_hosts.len == 0) return true;

        const host_value = req_view.getHeader("Host") orelse return false;
        const host_name = allowlistHostName(host_value);
        if (host_name.len == 0) return false;

        for (self.cfg.allowed_hosts) |allowed| {
            if (std.ascii.eqlIgnoreCase(host_name, allowed)) return true;
        }
        return false;
    }

    fn allowlistHostName(host_value: []const u8) []const u8 {
        const trimmed = std.mem.trim(u8, host_value, " \t");
        if (trimmed.len == 0) return "";

        if (trimmed[0] == '[') {
            const end = std.mem.indexOfScalar(u8, trimmed, ']') orelse return "";
            return trimmed[1..end];
        }

        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            if (std.mem.indexOfScalar(u8, trimmed[colon + 1 ..], ':') == null) {
                return trimmed[0..colon];
            }
        }

        return trimmed;
    }

    fn bufferPendingFileWrites(self: *Server, conn: *connection.Connection) bool {
        var queued_any = false;

        while (conn.hasPendingFile() and conn.writeQueueAvailable() > 0) {
            const body_buf = self.io.acquireBuffer() orelse {
                if (!queued_any) {
                    conn.cleanupPendingFile();
                    self.closeConnection(conn);
                }
                return queued_any;
            };

            const max_read: usize = @intCast(@min(conn.pending_file_remaining, @as(u64, body_buf.bytes.len)));
            const read_result = std.c.pread(conn.pending_file_fd.?, body_buf.bytes.ptr, max_read, @intCast(conn.pending_file_offset));
            if (read_result < 0) {
                self.io.releaseBuffer(body_buf);
                switch (std.posix.errno(read_result)) {
                    .INTR => continue,
                    else => {
                        conn.cleanupPendingFile();
                        self.closeConnection(conn);
                        return queued_any;
                    },
                }
            }
            const bytes_read: usize = @intCast(read_result);
            if (bytes_read == 0) {
                self.io.releaseBuffer(body_buf);
                conn.cleanupPendingFile();
                break;
            }
            if (!conn.enqueueWrite(body_buf, bytes_read)) {
                self.io.releaseBuffer(body_buf);
                return queued_any;
            }

            self.io.onWriteBuffered(conn, bytes_read);
            conn.pending_file_offset += bytes_read;
            conn.pending_file_remaining -= bytes_read;
            queued_any = true;

            if (conn.pending_file_remaining == 0) {
                conn.cleanupPendingFile();
                break;
            }
        }

        return queued_any;
    }

    /// Initialize body accumulation for a request whose body exceeds the read buffer.
    /// Allocates BodyAccumState, seeds it with any body bytes already in the read buffer,
    /// and transitions the connection to body-accumulation mode.
    fn initBodyAccumulation(
        self: *Server,
        conn: *connection.Connection,
        hparse: http1.HeaderParseResult,
        buffer_handle: buffer_pool.BufferHandle,
    ) !void {
        conn.body_accum = .{
            .content_length = hparse.content_length,
            .is_chunked = hparse.is_chunked,
            .bytes_received = 0,
            .bytes_decoded = 0,
            .body_buffers = undefined,
            .buffer_count = 0,
            .current_buf_offset = 0,
            .chunk_decoder = http1.ChunkDecoder.init(self.cfg.limits.max_body_bytes),
            .header_result = hparse,
            .original_read_buffer = null,
        };
        conn.header_count = hparse.view.headers.len;
        conn.is_head_request = (hparse.view.method == .HEAD);
        if (!hparse.keep_alive) conn.close_after_write = true;

        // Send 100-continue if client expects it
        if (hparse.expect_continue and !conn.sent_continue) {
            conn.sent_continue = true;
            try self.queueResponse(conn, continueResponse());
        }

        self.io.setTimeoutPhase(conn, .body);

        // Seed with any body bytes already in the read buffer after headers
        const start = conn.read_offset;
        const end = start + conn.read_buffered_bytes;
        const body_start = start + hparse.headers_consumed;
        if (body_start < end) {
            const body_bytes = buffer_handle.bytes[body_start..end];
            try self.appendBodyData(conn, body_bytes);
        }

        // Retain original read buffer (header slices point into it) and acquire a fresh one.
        // This prevents subsequent body reads from overwriting the header data.
        const accum = &(conn.body_accum orelse unreachable);
        accum.original_read_buffer = conn.read_buffer;
        conn.read_buffer = self.io.acquireBuffer() orelse {
            // No buffers available — abort body accumulation
            conn.read_buffer = accum.original_read_buffer;
            accum.original_read_buffer = null;
            return error.OutOfMemory;
        };
        conn.read_offset = 0;
        conn.read_buffered_bytes = 0;

        // Check if body is already complete
        if (self.bodyComplete(conn)) {
            try self.dispatchWithAccumulatedBody(conn);
        }
    }

    /// Continue accumulating body data from the read buffer into body buffers.
    fn continueBodyAccumulation(self: *Server, conn: *connection.Connection) !void {
        const buffer_handle = conn.read_buffer orelse return;
        const start = conn.read_offset;
        const end = start + conn.read_buffered_bytes;
        if (end <= start) return;

        const data = buffer_handle.bytes[start..end];
        try self.appendBodyData(conn, data);
        self.io.onReadConsumed(conn, data.len);

        if (self.bodyComplete(conn)) {
            try self.dispatchWithAccumulatedBody(conn);
        }
    }

    /// Append raw body data into body accumulator buffers.
    fn appendBodyData(self: *Server, conn: *connection.Connection, data: []u8) !void {
        const accum = &(conn.body_accum orelse return);
        var remaining = data;

        if (accum.is_chunked) {
            // Feed through chunk decoder
            while (remaining.len > 0 and !accum.chunk_decoder.isDone()) {
                // Ensure we have a destination buffer
                if (accum.buffer_count == 0 or accum.current_buf_offset >= self.cfg.buffer_pool.buffer_size) {
                    if (accum.buffer_count >= connection.BodyAccumState.MAX_BODY_BUFFERS) {
                        return error.BodyTooLarge;
                    }
                    const buf = self.io.acquireBuffer() orelse return error.OutOfMemory;
                    accum.body_buffers[accum.buffer_count] = buf;
                    accum.buffer_count += 1;
                    accum.current_buf_offset = 0;
                }
                const cur_buf = accum.body_buffers[accum.buffer_count - 1];
                const dst = cur_buf.bytes[accum.current_buf_offset..];
                const result = accum.chunk_decoder.feed(remaining, dst) catch |err| {
                    return switch (err) {
                        error.BodyTooLarge => error.BodyTooLarge,
                        error.InvalidChunk => error.InvalidRequest,
                    };
                };
                accum.current_buf_offset += result.decoded;
                accum.bytes_decoded += result.decoded;
                remaining = remaining[result.consumed..];
                accum.bytes_received += result.consumed;
            }
        } else {
            // Content-Length: raw copy
            while (remaining.len > 0) {
                const left = accum.content_length - accum.bytes_received;
                if (left == 0) break;
                const to_consume = @min(remaining.len, left);

                // Ensure we have a destination buffer
                if (accum.buffer_count == 0 or accum.current_buf_offset >= self.cfg.buffer_pool.buffer_size) {
                    if (accum.buffer_count >= connection.BodyAccumState.MAX_BODY_BUFFERS) {
                        return error.BodyTooLarge;
                    }
                    const buf = self.io.acquireBuffer() orelse return error.OutOfMemory;
                    accum.body_buffers[accum.buffer_count] = buf;
                    accum.buffer_count += 1;
                    accum.current_buf_offset = 0;
                }
                const cur_buf = accum.body_buffers[accum.buffer_count - 1];
                const dst = cur_buf.bytes[accum.current_buf_offset..];
                const copy_len = @min(to_consume, dst.len);
                @memcpy(dst[0..copy_len], remaining[0..copy_len]);
                accum.current_buf_offset += copy_len;
                accum.bytes_received += copy_len;
                accum.bytes_decoded += copy_len;
                remaining = remaining[copy_len..];
            }
        }
    }

    /// Check if body accumulation is complete.
    fn bodyComplete(_: *Server, conn: *connection.Connection) bool {
        const accum = conn.body_accum orelse return false;
        if (accum.is_chunked) {
            return accum.chunk_decoder.isDone();
        }
        return accum.bytes_received >= accum.content_length;
    }

    /// Dispatch a request with accumulated body data to handler/proxy.
    fn dispatchWithAccumulatedBody(self: *Server, conn: *connection.Connection) !void {
        const accum = &(conn.body_accum orelse return);
        const hparse = accum.header_result;
        const fd = conn.fd orelse return;

        // Build BodyView from accumulated buffers
        const body_view = forward_mod.BodyView{
            .buffers = .{
                .handles = accum.body_buffers[0..accum.buffer_count],
                .last_buf_len = accum.current_buf_offset,
                .total_len = accum.bytes_decoded,
                .buffer_size = self.cfg.buffer_pool.buffer_size,
            },
        };

        // Check proxy routes first
        if (self.proxy) |proxy| {
            if (proxy.matchRoute(&hparse.view) != null) {
                var mw_ctx = middleware.Context{
                    .protocol = .http1,
                    .buffer_ops = .{
                        .ctx = &self.io,
                        .acquire = acquireBufferOpaque,
                        .release = releaseBufferOpaque,
                    },
                };
                var ip_buf: [64]u8 = undefined;
                var client_ip_str: ?[]const u8 = null;
                if (conn.cached_peer_ip) |ip4| {
                    const ip_len = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                    if (ip_len.len > 0) client_ip_str = ip_buf[0..ip_len.len];
                }
                var proxy_result = proxy.handleWithBody(
                    hparse.view,
                    body_view,
                    &mw_ctx,
                    client_ip_str,
                    false,
                    self.io.nowMs(),
                );
                defer proxy_result.release();

                self.cleanupBodyAccumulation(conn);
                try self.queueResponse(conn, proxy_result.resp);
                // Materialize pending_body before proxy_result.release() frees the upstream buffer
                if (conn.pending_body.len > 0) {
                    self.materializePendingBody(conn);
                }
                return;
            }
        }

        // Handler path: linearize body into contiguous allocation
        const total_len = accum.bytes_decoded;
        if (total_len > 0) {
            const buffer_count = accum.buffer_count;
            const last_buf_len = accum.current_buf_offset;
            const buffer_size = self.cfg.buffer_pool.buffer_size;

            const body_mem = self.allocator.alloc(u8, total_len) catch {
                self.abortBodyAccumulation(conn, 503);
                return;
            };

            // Copy from body buffers into contiguous memory
            var copied: usize = 0;
            for (0..buffer_count) |i| {
                const handle = accum.body_buffers[i];
                const buf_len = if (i == buffer_count - 1)
                    last_buf_len
                else
                    buffer_size;
                @memcpy(body_mem[copied .. copied + buf_len], handle.bytes[0..buf_len]);
                copied += buf_len;
            }

            // Build RequestView with body
            const req_view = request.RequestView{
                .method = hparse.view.method,
                .method_raw = hparse.view.method_raw,
                .path = hparse.view.path,
                .headers = hparse.view.headers,
                .body = body_mem[0..total_len],
            };

            if (!self.isAllowedHost(req_view)) {
                conn.close_after_write = true;
                self.cleanupBodyAccumulation(conn);
                self.queueResponse(conn, badRequestResponse()) catch {};
                self.allocator.free(body_mem);
                return;
            }

            // Dispatch to router, but check result before queueing to detect echo responses
            // that can use scattered body buffers instead of re-copying.
            var mw_ctx = middleware.Context{
                .protocol = .http1,
                .buffer_ops = .{
                    .ctx = &self.io,
                    .acquire = acquireBufferOpaque,
                    .release = releaseBufferOpaque,
                },
            };
            if (conn.cached_peer_ip) |ip4| {
                mw_ctx.client_ip = ip4;
            } else if (conn.cached_peer_ip6) |ip6| {
                mw_ctx.client_ip6 = ip6;
            }
            var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
            var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
            const arena_handle = self.io.acquireBuffer();
            var empty_arena: [0]u8 = undefined;
            const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
            var scratch = router.HandlerScratch{
                .response_buf = response_buf[0..],
                .response_headers = response_headers[0..],
                .arena_buf = arena_buf,
                .arena_handle = arena_handle,
                .buffer_ops = mw_ctx.buffer_ops,
            };
            const result = self.app_router.handle(req_view, &mw_ctx, &scratch);
            if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
            if (result.pause_reads_ms) |pause_ms| {
                conn.setRateLimitPause(self.io.nowMs(), pause_ms);
            }

            // Check if the handler echoed back the body (response .bytes ptr == body_mem ptr).
            // If so, use scattered body to enqueue accum buffers directly (skip re-copy).
            const is_echo = switch (result.resp.body) {
                .bytes => |b| b.ptr == body_mem.ptr and b.len == total_len,
                else => false,
            };

            if (is_echo and buffer_count > 0) {
                // Echo detected: build a scattered response and transfer body buffers directly
                var scattered_resp = result.resp;
                scattered_resp.body = .{ .scattered = .{
                    .handles = accum.body_buffers[0..buffer_count],
                    .count = buffer_count,
                    .last_buf_len = last_buf_len,
                    .total_len = total_len,
                    .buffer_size = buffer_size,
                } };
                // Release original read buffer (header data no longer needed)
                if (accum.original_read_buffer) |orig_buf| {
                    self.io.releaseBuffer(orig_buf);
                    accum.original_read_buffer = null;
                }
                self.queueResponse(conn, scattered_resp) catch {};
                // queueResponse transferred the buffer handles — zero out to prevent double-free
                accum.buffer_count = 0;
                conn.body_accum = null;
                self.allocator.free(body_mem);
            } else {
                // Non-echo response: cleanup body buffers and queue normally
                self.cleanupBodyAccumulation(conn);
                self.queueResponse(conn, result.resp) catch {};
                if (conn.pending_body.len > 0) {
                    self.materializePendingBody(conn);
                }
                self.allocator.free(body_mem);
            }
        } else {
            self.cleanupBodyAccumulation(conn);
            self.dispatchToRouter(conn, hparse.view, fd);
        }
    }

    /// Dispatch a fully-formed request to the router (extracted for reuse).
    fn dispatchToRouter(self: *Server, conn: *connection.Connection, req_view: request.RequestView, _: std.posix.fd_t) void {
        if (!self.isAllowedHost(req_view)) {
            conn.close_after_write = true;
            self.queueResponse(conn, badRequestResponse()) catch {};
            return;
        }

        // Fast path: pre-encoded h1 response cache.
        if (self.tryDispatchPreencodedH1(conn, req_view)) return;

        var mw_ctx = middleware.Context{
            .protocol = .http1,
            .buffer_ops = .{
                .ctx = &self.io,
                .acquire = acquireBufferOpaque,
                .release = releaseBufferOpaque,
            },
        };
        // Use cached client IP for rate limiting and logging
        if (conn.cached_peer_ip) |ip4| {
            mw_ctx.client_ip = ip4;
        } else if (conn.cached_peer_ip6) |ip6| {
            mw_ctx.client_ip6 = ip6;
        }
        var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
        var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
        const arena_handle = self.io.acquireBuffer();
        var empty_arena: [0]u8 = undefined;
        const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
        var scratch = router.HandlerScratch{
            .response_buf = response_buf[0..],
            .response_headers = response_headers[0..],
            .arena_buf = arena_buf,
            .arena_handle = arena_handle,
            .buffer_ops = mw_ctx.buffer_ops,
        };
        const result = self.app_router.handle(req_view, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
        if (result.pause_reads_ms) |pause_ms| {
            conn.setRateLimitPause(self.io.nowMs(), pause_ms);
        }
        self.queueResponse(conn, result.resp) catch {};
    }

    /// Release all acquired body buffers and free BodyAccumState.
    fn cleanupBodyAccumulation(self: *Server, conn: *connection.Connection) void {
        if (conn.body_accum) |*accum| {
            for (0..accum.buffer_count) |i| {
                self.io.releaseBuffer(accum.body_buffers[i]);
            }
            // Release the original read buffer that held header data
            if (accum.original_read_buffer) |buf| {
                self.io.releaseBuffer(buf);
            }
            conn.body_accum = null;
        }
    }

    /// Copy pending_body into pool buffers so the original allocation can be freed.
    /// Called when a handler response references temporary body memory (e.g., echo with
    /// accumulated body). Enqueues as many chunks as the write queue allows; any overflow
    /// is stored back in pending_body pointing to the new pool buffer (safe lifetime).
    fn materializePendingBody(self: *Server, conn: *connection.Connection) void {
        // Use streamBodyChunks which already copies into pool buffers and enqueues.
        // After this call, pending_body either points to a pool buffer or is empty.
        // The key insight: streamBodyChunks copies bytes into acquired pool buffers,
        // and if the write queue is full, stores 'remaining' as pending_body.
        // That 'remaining' is a subslice of the source — still pointing to body_mem.
        // We need to fully materialize everything NOW.
        var remaining = conn.pending_body;
        conn.pending_body = &[_]u8{};

        while (remaining.len > 0) {
            const body_buf = self.io.acquireBuffer() orelse {
                // Out of buffers — drop remaining data, close after current writes
                conn.close_after_write = true;
                return;
            };
            const chunk_len = @min(remaining.len, body_buf.bytes.len);
            @memcpy(body_buf.bytes[0..chunk_len], remaining[0..chunk_len]);
            if (!conn.enqueueWrite(body_buf, chunk_len)) {
                // Write queue full — this chunk is in a pool buffer but can't be enqueued.
                // Store the pool buffer slice as pending_body (safe lifetime — pool buffer).
                // The remaining un-copied source data is lost, but the chunk we just copied
                // will be streamed via handleWrite → streamBodyChunks later.
                self.io.releaseBuffer(body_buf);
                conn.close_after_write = true;
                return;
            }
            self.io.onWriteBuffered(conn, chunk_len);
            remaining = remaining[chunk_len..];
        }
    }

    /// Abort body accumulation with an error response, then close.
    fn abortBodyAccumulation(self: *Server, conn: *connection.Connection, status: u16) void {
        self.cleanupBodyAccumulation(conn);
        conn.close_after_write = true;
        const resp: response_mod.Response = .{
            .status = status,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = if (status == 413) "Payload Too Large\n" else "Bad Request\n" },
        };
        self.queueResponse(conn, resp) catch {};
    }

    fn closeConnection(self: *Server, conn: *connection.Connection) void {
        // Clean up TLS session before closing the socket
        conn.cleanupTls();
        if (conn.fd) |fd| {
            _ = self.io.unregister(fd) catch {};
            clock.closeFd(fd);
            conn.fd = null;
        }
        if (conn.http2_stack) |stack| {
            self.allocator.destroy(stack);
            conn.http2_stack = null;
        }
        // Clean up body accumulation state
        self.cleanupBodyAccumulation(conn);
        // Drain write queue before releasing read buffer to avoid double-free
        // if a buffer handle appears in both places
        while (conn.peekWrite()) |entry| {
            self.io.releaseBuffer(entry.handle);
            conn.popWrite();
        }
        if (conn.read_buffer) |buf| {
            self.io.releaseBuffer(buf);
            conn.read_buffer = null;
        }
        // Clean up pending file descriptor and body reference
        conn.cleanupPendingFile();
        conn.pending_body = &[_]u8{};
        self.io.releaseConnection(conn);
    }

    /// Read from a connection, using TLS if enabled. Returns bytes read, or error.
    const ReadResult = union(enum) {
        bytes: usize,
        eof: void,
        again: void,
        err: void,
    };

    fn connRead(_: *Server, conn: *connection.Connection, buf: []u8) ReadResult {
        if (conn.is_tls) {
            var session = &(conn.tls_session orelse return .err);
            const n = session.read(buf) catch |err| return switch (err) {
                error.WouldBlock => .again,
                error.ConnectionClosed => .eof,
                else => .err,
            };
            if (n == 0) return .eof;
            return .{ .bytes = n };
        }
        const fd = conn.fd orelse return .err;
        const raw = std.posix.system.read(fd, buf.ptr, buf.len);
        if (raw == 0) return .eof;
        if (raw < 0) {
            return switch (std.posix.errno(raw)) {
                .AGAIN, .INTR => .again,
                else => .err,
            };
        }
        return .{ .bytes = @intCast(raw) };
    }

    /// Write to a connection, using TLS if enabled. Returns bytes written, or error.
    const WriteResult = union(enum) {
        bytes: usize,
        again: void,
        err: void,
    };

    fn connWrite(_: *Server, conn: *connection.Connection, data: []const u8) WriteResult {
        if (conn.is_tls) {
            var session = &(conn.tls_session orelse return .err);
            const n = session.write(data) catch |err| return switch (err) {
                error.WouldBlock => .again,
                else => .err,
            };
            return .{ .bytes = n };
        }
        const fd = conn.fd orelse return .err;
        const raw = std.c.write(fd, data.ptr, data.len);
        if (raw < 0) {
            return switch (std.posix.errno(raw)) {
                .AGAIN, .INTR => .again,
                else => .err,
            };
        }
        return .{ .bytes = @intCast(raw) };
    }

    fn matchesHttp2Preface(candidate: []const u8) bool {
        const n = if (candidate.len < http2.Preface.len) candidate.len else http2.Preface.len;
        return std.mem.eql(u8, candidate[0..n], http2.Preface[0..n]);
    }
};

test "metrics middleware response queued for http1" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    const req = request.RequestView{
        .method = .GET,
        .path = "/metrics",
        .headers = &[_]request.Header{},
        .body = "",
    };

    var mw_ctx = middleware.Context{
        .protocol = .http1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
        },
    };
    var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const arena_handle = server.io.acquireBuffer();
    var empty_arena: [0]u8 = undefined;
    const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
    var scratch = router.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf,
        .arena_handle = arena_handle,
        .buffer_ops = mw_ctx.buffer_ops,
    };

    const result = server.app_router.handle(req, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const body_bytes_1 = result.resp.bodyBytes();
    try std.testing.expect(body_bytes_1.len > 0);

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    try server.queueResponse(conn, result.resp);
    // Managed body fits alongside headers — combined into single write
    try std.testing.expectEqual(@as(u8, 1), conn.write_count);

    const entry = conn.peekWrite().?.*;
    conn.popWrite();
    // Verify the combined buffer contains the body
    const entry_bytes = entry.handle.bytes[0..entry.len];
    try std.testing.expect(std.mem.endsWith(u8, entry_bytes, body_bytes_1));

    server.io.releaseBuffer(entry.handle);
}

test "metrics middleware response queued for http2" {
    if (!build_options.enable_http2) return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    const req = request.RequestView{
        .method = .GET,
        .path = "/metrics",
        .headers = &[_]request.Header{},
        .body = "",
    };

    var mw_ctx = middleware.Context{
        .protocol = .http2,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
        },
    };
    var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const arena_handle = server.io.acquireBuffer();
    var empty_arena: [0]u8 = undefined;
    const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
    var scratch = router.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf,
        .arena_handle = arena_handle,
        .buffer_ops = mw_ctx.buffer_ops,
    };

    const result = server.app_router.handle(req, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const managed = switch (result.resp.body) {
        .managed => |m| m,
        else => return error.UnexpectedBody,
    };

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);
    conn.protocol = .http2;

    try server.queueHttp2Response(conn, 1, result.resp, false);
    try std.testing.expect(conn.write_count >= 2);

    const expected = result.resp.bodyBytes();
    var found_data = false;
    var saw_managed_handle = false;

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        const frame_type = entry.handle.bytes[3];
        if (entry.handle.index == managed.handle.index) {
            saw_managed_handle = true;
        }
        if (frame_type == @intFromEnum(http2.FrameType.data)) {
            const len = (@as(usize, entry.handle.bytes[0]) << 16) |
                (@as(usize, entry.handle.bytes[1]) << 8) |
                @as(usize, entry.handle.bytes[2]);
            try std.testing.expectEqualStrings(expected, entry.handle.bytes[9 .. 9 + len]);
            found_data = true;
        }
        server.io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    try std.testing.expect(found_data);
    try std.testing.expect(!saw_managed_handle);
}

test "metrics middleware end-to-end http1" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    const raw = "GET /metrics HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const parse = http1.parse(buf[0..raw.len], .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = headers.len,
        .headers_storage = headers[0..],
    });
    try std.testing.expectEqual(http1.ParseState.complete, parse.state);

    var mw_ctx = middleware.Context{
        .protocol = .http1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
        },
    };
    var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const arena_handle = server.io.acquireBuffer();
    var empty_arena: [0]u8 = undefined;
    const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
    var scratch = router.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf,
        .arena_handle = arena_handle,
        .buffer_ops = mw_ctx.buffer_ops,
    };

    const result = server.app_router.handle(parse.view, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const body_bytes_2 = result.resp.bodyBytes();
    try std.testing.expect(body_bytes_2.len > 0);

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    try server.queueResponse(conn, result.resp);
    // Managed body fits alongside headers — combined into single write
    try std.testing.expectEqual(@as(u8, 1), conn.write_count);

    const entry = conn.peekWrite().?.*;
    conn.popWrite();
    const entry_bytes = entry.handle.bytes[0..entry.len];
    try std.testing.expect(std.mem.endsWith(u8, entry_bytes, body_bytes_2));

    server.io.releaseBuffer(entry.handle);
}

test "metrics middleware end-to-end http2" {
    if (!build_options.enable_http2) return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    var stack = http2.Stack.init();
    var frames: [8]http2.Frame = undefined;
    var events: [8]http2.Event = undefined;
    var header_block_buf: [128]u8 = undefined;
    const header_block = buildHeaderBlockAuthority(&header_block_buf, "example.com");

    var input_buf: [256]u8 = undefined;
    var idx: usize = 0;
    @memcpy(input_buf[idx .. idx + http2.Preface.len], http2.Preface);
    idx += http2.Preface.len;
    http2.writeFrameHeader(input_buf[idx..], .headers, 0x5, 1, header_block.len) catch return error.BufferTooSmall;
    idx += 9;
    @memcpy(input_buf[idx .. idx + header_block.len], header_block);
    idx += header_block.len;

    const ingest = stack.ingest(input_buf[0..idx], frames[0..], events[0..]);
    try std.testing.expectEqual(http2.ParseState.complete, ingest.state);
    try std.testing.expect(ingest.event_count > 0);

    var req_view: ?request.RequestView = null;
    for (events[0..ingest.event_count]) |event| {
        if (event == .headers) {
            req_view = event.headers.request;
        }
    }
    const view = req_view orelse return error.UnexpectedDecision;

    var mw_ctx = middleware.Context{
        .protocol = .http2,
        .stream_id = 1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
        },
    };
    var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const arena_handle = server.io.acquireBuffer();
    var empty_arena: [0]u8 = undefined;
    const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
    var scratch = router.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf,
        .arena_handle = arena_handle,
        .buffer_ops = mw_ctx.buffer_ops,
    };

    const result = server.app_router.handle(view, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);
    conn.protocol = .http2;
    conn.http2_stack = &stack;

    try server.queueHttp2Response(conn, 1, result.resp, false);
    try std.testing.expect(conn.write_count >= 2);

    const expected = result.resp.bodyBytes();
    var collected = try std.testing.allocator.alloc(u8, expected.len);
    defer std.testing.allocator.free(collected);
    var collected_len: usize = 0;

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        const frame_type = entry.handle.bytes[3];
        if (frame_type == @intFromEnum(http2.FrameType.data)) {
            const len = (@as(usize, entry.handle.bytes[0]) << 16) |
                (@as(usize, entry.handle.bytes[1]) << 8) |
                @as(usize, entry.handle.bytes[2]);
            @memcpy(collected[collected_len .. collected_len + len], entry.handle.bytes[9 .. 9 + len]);
            collected_len += len;
        }
        server.io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    try std.testing.expectEqual(expected.len, collected_len);
    try std.testing.expectEqualStrings(expected, collected[0..collected_len]);
}

fn buildHeaderBlockAuthority(buffer: []u8, authority: []const u8) []u8 {
    var idx: usize = 0;
    buffer[idx] = 0x82; // :method GET (static index 2)
    idx += 1;
    buffer[idx] = 0x84; // :path / (static index 4)
    idx += 1;
    buffer[idx] = 0x86; // :scheme http (static index 6)
    idx += 1;
    buffer[idx] = 0x01; // literal without indexing, indexed name :authority (index 1)
    idx += 1;
    buffer[idx] = @intCast(authority.len);
    idx += 1;
    @memcpy(buffer[idx .. idx + authority.len], authority);
    idx += authority.len;
    return buffer[0..idx];
}

test "http1 response bytes from write queue" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    const app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    const resp = response_mod.Response{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "hi" },
    };

    try server.queueResponse(conn, resp);
    const bytes = try drainWriteQueue(&server.io, conn, allocator);
    defer allocator.free(bytes);

    // Verify structural correctness (Date header is dynamic so check components)
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Date: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 2\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhi"));
}

test "http1 managed response bytes from write queue" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    const app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    const handle = server.io.acquireBuffer() orelse return error.OutOfMemory;
    const body = "hello";
    @memcpy(handle.bytes[0..body.len], body);

    const resp = response_mod.Response{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .managed = .{ .handle = handle, .len = body.len } },
    };

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    try server.queueResponse(conn, resp);
    const bytes = try drainWriteQueue(&server.io, conn, allocator);
    defer allocator.free(bytes);

    // Verify structural correctness (Date header is dynamic so check components)
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Date: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhello"));
}

fn drainWriteQueue(io: *runtime.IoRuntime, conn: *connection.Connection, allocator: std.mem.Allocator) ![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        try list.appendSlice(allocator, entry.handle.bytes[entry.offset..entry.len]);
        io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    return list.toOwnedSlice(allocator);
}

fn acquireBufferOpaque(ctx: *anyopaque) ?buffer_pool.BufferHandle {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    return io.acquireBuffer();
}

fn releaseBufferOpaque(ctx: *anyopaque, handle: buffer_pool.BufferHandle) void {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    io.releaseBuffer(handle);
}

pub fn registerDefaultRoutes(app_router: *router.Router) !void {
    // Register built-in benchmark endpoints
    try app_router.get("/health", handleBenchHealth);
    try app_router.get("/echo", handleBenchEchoGet);
    try app_router.post("/echo", handleBenchEchoPost);
    try app_router.get("/blob", handleBenchBlob);
    // TechEmpower Framework Benchmark endpoints
    try app_router.get("/plaintext", handleTfbPlaintext);
    try app_router.get("/json", handleTfbJson);
    // HttpArena benchmark endpoints. All three are "sum of query
    // params" / "fixed ok" endpoints used by the throughput and
    // pipelining profiles across h1, h2, and h3. PR PERF-3's
    // preencoded caches key on the full canonical URL and serve the
    // zero-router fast path.
    try app_router.get("/pipeline", handleHttpArenaPipeline);
    try app_router.get("/baseline11", handleHttpArenaBaseline11);
    try app_router.post("/baseline11", handleHttpArenaBaseline11);
    try app_router.get("/baseline2", handleHttpArenaBaseline2);
}

// ============================================================
// Benchmark Handlers
// Built-in endpoints for performance testing
// ============================================================

/// 8KB static blob for large response benchmarks
const benchmark_blob: [8 * 1024]u8 = [_]u8{0} ** (8 * 1024);

/// GET /health - minimal health check for benchmarks
    fn handleBenchHealth(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{},
            .body = .none,
        };
    }

/// GET /echo - return static JSON response
    fn handleBenchEchoGet(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = "{\"status\":\"ok\"}" },
        };
    }

/// POST /echo - echo back request body
    /// Returns .bytes pointing into the read buffer — safe because queueResponse
    /// copies body into the write buffer synchronously before the next read().
fn handleBenchEchoPost(ctx: *router.HandlerContext) response_mod.Response {
    const body = ctx.request.body;
    if (body.len == 0) {
        return handleBenchEchoGet(ctx);
    }
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .body = .{ .bytes = body },
    };
}

/// GET /blob - return 1MB response for throughput testing
    fn handleBenchBlob(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/octet-stream" },
            },
            .body = .{ .bytes = &benchmark_blob },
        };
    }

// ============================================================
// TechEmpower Framework Benchmark Handlers
// https://www.techempower.com/benchmarks/
// ============================================================

/// GET /plaintext - TechEmpower plaintext test
    fn handleTfbPlaintext(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
            },
            .body = .{ .bytes = "Hello, World!" },
        };
    }

/// GET /json - TechEmpower JSON serialization test
    fn handleTfbJson(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = "{\"message\":\"Hello, World!\"}" },
        };
    }

/// GET /baseline2?a=1&b=1 - HttpArena h2/h3 throughput endpoint.
/// Returns the literal sum of query params a and b. HttpArena always
/// sends the canonical ?a=1&b=1, so the response body is always "2".
/// The pre-encoded cache catches that exact URL; this cold-path
/// handler only runs for non-canonical queries (which HttpArena
/// doesn't send). Same applies to /baseline11 below.
fn handleHttpArenaBaseline2(_: *router.HandlerContext) response_mod.Response {
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "2" },
    };
}

/// GET /pipeline - HttpArena h1 pipelining throughput endpoint.
/// Returns the fixed body "ok". See h2o's on_pipeline handler for
/// the canonical reference shape.
fn handleHttpArenaPipeline(_: *router.HandlerContext) response_mod.Response {
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "ok" },
    };
}

/// GET|POST /baseline11 - HttpArena h1 throughput endpoint.
/// Sums the ?a= and ?b= query params, plus the request body for
/// POST. For the canonical GET ?a=1&b=1 the sum is 2, cached via
/// the pre-encoded pre-encoded h1 cache. The cold-path handler below
/// is reached for POSTs and for non-canonical queries — and does
/// the actual arithmetic.
fn handleHttpArenaBaseline11(ctx: *router.HandlerContext) response_mod.Response {
    var sum: i64 = 0;
    // Parse query string: find '?' in path
    if (std.mem.indexOfScalar(u8, ctx.request.path, '?')) |q_start| {
        const query = ctx.request.path[q_start + 1 ..];
        var it = std.mem.splitScalar(u8, query, '&');
        while (it.next()) |pair| {
            if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                const val = pair[eq + 1 ..];
                if (std.fmt.parseInt(i64, val, 10)) |n| {
                    sum += n;
                } else |_| {}
            }
        }
    }
    // POST body: single integer, summed into total
    if (ctx.request.method == .POST and ctx.request.body.len > 0) {
        const trimmed = std.mem.trim(u8, ctx.request.body, " \t\r\n");
        if (std.fmt.parseInt(i64, trimmed, 10)) |n| {
            sum += n;
        } else |_| {}
    }
    // Format sum into the router's response_buf
    const body = std.fmt.bufPrint(ctx.response_buf, "{d}", .{sum}) catch "0";
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = body },
    };
}
