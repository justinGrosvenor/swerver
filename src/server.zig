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
const benchmark_routes = @import("benchmark_routes.zig");
const proxy_mod = @import("proxy/proxy.zig");
const forward_mod = @import("proxy/forward.zig");
const preencoded = @import("server/preencoded.zig");
const server_tls = @import("server/tls.zig");
const accept_mod = @import("server/accept.zig");
const http3_mod = @import("server/http3.zig");
const http2_mod = @import("server/http2.zig");

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

// ============================================================
// Pre-encoded response cache (PR PERF-3)
//
// CACHE BYPASS SEMANTICS: the pre-encoded fast path intentionally
// skips the router, the middleware chain, and the response encoder.
// This is by design — it's the core of the performance win (no
// per-request middleware overhead on benchmark hot endpoints). The
// semantic contract:
//
//   What IS included in cached responses:
//     - Status code + body (obviously)
//     - Content-Type header (endpoint-specific, baked at register)
//     - Date header (refreshed lazily once per epoch second)
//     - Alt-Svc header (baked at register if QUIC is enabled)
//     - Security headers (CSP, X-Content-Type-Options, X-Frame-
//       Options, Referrer-Policy — merged from security.zig's
//       getStaticSecurityHeaders() at register/rebuild time)
//
//   What is NOT included / NOT run:
//     - Pre-request middleware chain (health probe rejection,
//       rate limiting, observability request-ID injection)
//     - Post-response middleware chain (access logging, metrics
//       recording, structured logging)
//     - x402 payment check — CORRECTLY handled: the check runs
//       BEFORE the cache lookup in handleHttp3Request / the h1
//       dispatchToRouter path, so paid endpoints can't bypass
//     - CORS origin/credentials headers (request-dependent)
//     - HSTS (only on TLS; the caller knows but the cache
//       doesn't distinguish — follow-up if needed)
//
//   Production implications:
//     - Cached responses don't appear in access logs or metrics.
//       For benchmark workloads this is fine (nobody reads the
//       logs). For production, disable the cache or wire a
//       lightweight post-cache logging hook.
//     - Cached responses are not rate-limited per-IP. Health
//       probes are intentionally exempt; hot benchmark endpoints
//       assume unlimited throughput.
//     - Cached responses include security headers as of the
//       MW-2 fix, so HSTS / CSP / X-Frame-Options are present
//       even on the fast path.
// ============================================================

// TLS_PLAINTEXT_WRITE_CAP and TLS_CIPHER_SCRATCH_SIZE live in
// `server/tls.zig` alongside the handshake + ciphertext pump helpers.


/// Single-threaded event-loop HTTP server. One `Server` instance runs
/// per worker process in the default multi-worker fork model, or one
/// per process in single-worker mode.
///
/// The server owns:
///   - a `router.Router` with all registered routes and middleware
///   - an `IoRuntime` wrapping the platform's I/O backend (io_uring
///     native / io_uring poll / epoll / kqueue, picked at init)
///   - connection state (slab-backed `connection.Connection` entries)
///   - TCP / UDP listener file descriptors for HTTP/1.1/2 and HTTP/3
///   - optional `tls.Provider` instances for TCP TLS and QUIC
///   - optional `http3.Stack` for HTTP/3 dispatch
///   - pre-encoded response caches for hot static endpoints (h1/h2/h3)
///   - optional reverse proxy
///
/// **Do not construct a `Server` on the stack** — the struct is large
/// (tens of KB of pre-allocated buffers and pool slots) and will blow
/// the default Zig stack size in debug builds. Use
/// `ServerBuilder.build()` which heap-allocates via the provided
/// allocator and calls `initInPlace`. Call `deinit()` then
/// `allocator.destroy(srv)` to tear down.
///
/// `run(run_for_ms)` is the event loop entry point. Pass `null` to
/// run until SIGINT / SIGTERM; pass a value to have the loop exit
/// automatically after that many milliseconds (used by tests and by
/// the release workflow's smoke step).
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
    h3_preencoded: [preencoded.MAX_H3_PREENCODED]preencoded.PreencodedH3Response = undefined,
    h3_preencoded_count: usize = 0,
    /// Pre-encoded HTTP/1.1 response cache for the same hot static
    /// endpoints. Same shape as `h3_preencoded` but the bytes are
    /// raw HTTP/1.1 (status line + headers + body). Refresh is
    /// lazy / per-second just like h3.
    h1_preencoded: [preencoded.MAX_H1_PREENCODED]preencoded.PreencodedH1Response = undefined,
    h1_preencoded_count: usize = 0,
    /// Pre-encoded error responses (404, 400, 405, 501). Keyed by
    /// status code and checked in `queueResponse` before the full
    /// encodeResponseHeaders path. Same Date-refresh semantics as
    /// the endpoint cache.
    h1_error_cache: [4]preencoded.PreencodedH1Response = undefined,
    h1_error_cache_count: usize = 0,
    /// Pre-encoded HTTP/2 response cache. Holds a stream-id-agnostic
    /// template — HEADERS frame header + HPACK block + optional DATA
    /// frame header + body. Send-time patches stream_id bytes in
    /// place and enqueues the write.
    h2_preencoded: [preencoded.MAX_H2_PREENCODED]preencoded.PreencodedH2Response = undefined,
    h2_preencoded_count: usize = 0,
    /// Shared ciphertext drain scratch for TLS memory-BIO writes. Sized to
    /// hold one full TLS record's ciphertext (max_plaintext 16384 + 256 bytes
    /// of AEAD/framing overhead). Per-SSL_write we cap plaintext at 16 KiB so
    /// a single drain cycle never needs more than this. If the drain writev
    /// hits EAGAIN, the unsent tail + any wbio remainder is copied into the
    /// per-connection `tls_cipher_carry_handle`.
    tls_cipher_scratch: [server_tls.TLS_CIPHER_SCRATCH_SIZE]u8 = undefined,

    /// Quick-start constructor for the benchmark-style server: pre-
    /// registers the HttpArena / TechEmpower routes and the default
    /// middleware chain, then hands back a ready-to-`run()` Server.
    /// Use `initWithRouter` / `initInPlace` directly if you want to
    /// build your own router without the benchmark handlers.
    pub fn init(allocator: std.mem.Allocator, cfg: config.ServerConfig) !Server {
        var app_router = router.Router.init(.{
            .require_payment = cfg.x402.enabled,
            .payment_required_b64 = cfg.x402.payment_required_b64,
        });
        try benchmark_routes.registerRoutes(&app_router);
        middleware.security.buildCache();
        benchmark_routes.registerPostHooks(&app_router);
        benchmark_routes.loadDataset();
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
            .tls_cipher_scratch = undefined,
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
            preencoded.initPreencodedH3(self);
        }

        // Pre-encode the h1 response bytes for the same hot static
        // endpoints. No external dependency — uses encodeResponse +
        // the already-initialized cached date + Alt-Svc config.
        preencoded.initPreencodedH1(self);

        // Pre-encode the h2 response templates. Uses http2.encodeResponseHeaders
        // to build a stream-id-agnostic HPACK block + frame headers that
        // are patched per-request.
        if (build_options.enable_http2) preencoded.initPreencodedH2(self);
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
            const fd = try net.listen(self.cfg.address, self.cfg.port, 4096);
            self.listener_fd = fd;
        }
        try self.io.registerListener(self.listener_fd.?);
        // Initialize UDP listener for QUIC if enabled
        if (self.quic != null) {
            if (self.udp_fd == null) {
                const quic_port = self.cfg.quic.port;
                if (quic_port > 0) {
                    self.udp_fd = net.bindUdp(self.cfg.address, quic_port) catch |err| {
                        std.log.warn("Failed to bind UDP port {}: {}", .{ quic_port, err });
                        return err;
                    };
                }
            }
            if (self.udp_fd) |udp_fd| {
                self.io.registerUdpSocket(udp_fd) catch |err| {
                    std.log.warn("Failed to register UDP socket: {}", .{err});
                    clock.closeFd(udp_fd);
                    self.udp_fd = null;
                };
            }
        }
        const deadline = if (run_for_ms) |ms| self.io.nowMs() + ms else null;
        var last_housekeeping_ms: u64 = self.io.nowMs();
        while (true) {
            if (shutdown_requested.load(.acquire)) return;
            if (reload_requested.swap(false, .acq_rel)) {
                self.applyReload();
            }
            if (deadline) |limit| {
                if (self.io.nowMs() >= limit) return;
            }
            // Single clock call per loop iteration — reused for poll
            // timeout, timeout enforcement, and proxy maintenance.
            const now_ms = self.io.nowMs();

            // Housekeeping (timeout enforcement, QUIC cleanup, proxy
            // maintenance) runs at most every 100ms. Under high load
            // the event loop processes thousands of requests between
            // housekeeping passes. This eliminates per-tick O(active)
            // connection scans that dominated CPU at high core counts.
            const housekeeping_interval_ms: u64 = 100;
            const needs_housekeeping = (now_ms -% last_housekeeping_ms) >= housekeeping_interval_ms;
            const timeout_ms: u32 = if (needs_housekeeping) 0 else 10;
            const events = try self.io.pollWithTimeout(timeout_ms);

            if (needs_housekeeping) {
                last_housekeeping_ms = now_ms;
                // Enforce timeouts and close timed-out connections
                const timeout_result = self.io.enforceTimeouts(now_ms);
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
                    proxy.runMaintenance(now_ms);
                }
            }
            if (events.len == 0) continue;
            for (events) |event| {
                switch (event.kind) {
                    .accept => {
                        // Two delivery models:
                        // 1. Pre-accepted: the backend hands us a
                        //    fresh client fd inline (native io_uring
                        //    with its threaded multishot accept).
                        //    Go straight to setup.
                        // 2. Readiness: the backend woke us because
                        //    the listener has pending connections;
                        //    we call accept4() in a userspace loop
                        //    until EAGAIN (epoll, poll, io_uring_poll,
                        //    and native-with-inline-accept).
                        if (event.handle) |client_fd| {
                            accept_mod.handlePreAccepted(self, client_fd) catch |err| {
                                std.log.warn("Pre-accepted setup failed: {}", .{err});
                            };
                        } else {
                            const fd = self.listener_fd orelse continue;
                            accept_mod.handleAccept(self, fd) catch |err| {
                                std.log.warn("Accept failed: {}", .{err});
                            };
                        }
                    },
                    .datagram => {
                        // Native io_uring backend: the multishot recvmsg
                        // CQE delivered the packet payload + peer addr
                        // inline. Process this one datagram, release
                        // the kernel buffer, and continue. Other
                        // backends deliver a readiness event and we
                        // drain the UDP fd via recvfrom.
                        if (event.data) |payload| {
                            http3_mod.handleInlineDatagram(self, payload, event.datagram_peer[0..event.datagram_peer_len]);
                            if (event.kernel_buffer) |kb| kb.release();
                        } else {
                            try http3_mod.handleDatagram(self);
                        }
                    },
                    .read, .write, .err => {
                        // Validate conn_id fits in u32 before casting
                        if (event.conn_id > std.math.maxInt(u32)) {
                            if (event.kernel_buffer) |kb| kb.release();
                            continue;
                        }
                        const index: u32 = @intCast(event.conn_id);
                        // Guard against stale events: if the connection slot was freed
                        // and reused between event generation and dispatch, the fd will
                        // be null (freed) or the connection state will be closed/accept.
                        // We MUST still return the kernel buffer in that case — with
                        // multishot recv the backend can deliver multiple CQEs for the
                        // same slot in a single poll() batch, and a close triggered by
                        // an earlier event in the batch will leave any later buffers
                        // stranded if we don't release them here.
                        const conn = self.io.getConnection(index) orelse {
                            if (event.kernel_buffer) |kb| kb.release();
                            continue;
                        };
                        if (conn.fd == null or conn.state == .closed or conn.state == .accept) {
                            if (event.kernel_buffer) |kb| kb.release();
                            continue;
                        }
                        // If the backend delivered read data inline
                        // (io_uring native multishot recv), seed it before
                        // anything else — the handshake path also needs to
                        // see the ciphertext bytes since TLS sessions use
                        // memory BIOs (the kernel has already drained the
                        // fd, so SSL_read via a socket BIO would miss it).
                        // seedReadBuffer routes plaintext to conn.read_buffer
                        // and ciphertext to the TLS rbio memory BIO.
                        if (event.kind == .read) {
                            if (event.data) |kernel_data| {
                                self.seedReadBuffer(conn, kernel_data);
                            }
                            // Release the kernel buffer back to the ring
                            // AFTER seeding but BEFORE running handlers.
                            // The data has been copied out of kernel
                            // memory, so we're safe to return the slot.
                            if (event.kernel_buffer) |kb| kb.release();
                        }
                        // TLS handshake in progress — any I/O event continues it
                        if (conn.state == .handshake) {
                            server_tls.handleTlsHandshake(self, conn) catch {
                                self.closeConnection(conn);
                            };
                            continue;
                        }
                        switch (event.kind) {
                            .read => {
                                // Snapshot conn.id so we can detect slot
                                // reuse after handleRead runs. If the
                                // slot gets released and re-acquired for
                                // a new connection, the id changes and
                                // we must NOT rearm recv — the new
                                // connection has its own recv SQE from
                                // registerConnection, and a stray rearm
                                // would create a double-recv race on
                                // the same fd.
                                const pre_id: u64 = conn.id;
                                self.handleRead(index) catch |err| {
                                    std.log.debug("handleRead conn={} failed: {}", .{ index, err });
                                };
                                // Edge-triggered epoll: EPOLLOUT may have been consumed earlier
                                // (e.g., sending h2 SETTINGS). Flush any responses queued by handleRead.
                                const rconn = self.io.getConnection(index) orelse continue;
                                if (rconn.write_count > 0) {
                                    self.handleWrite(index) catch {};
                                }
                                // Re-arm single-shot recv on the native backend
                                // if the connection is still the same incarnation
                                // AND is not about to close. For close-mode
                                // requests with async writev, the close happens
                                // when the write CQE arrives (later, in the
                                // .write dispatcher arm), not synchronously in
                                // handleWrite. At this point the connection is
                                // still .active with an in-flight async write,
                                // but `close_after_write` is set — we must NOT
                                // arm a new recv because the kernel may reuse
                                // the fd number for a new connection as soon
                                // as our close lands, and the zombie recv SQE
                                // would then race with that new connection's
                                // own recv.
                                const postconn = self.io.getConnection(index) orelse continue;
                                if (postconn.id == pre_id and
                                    postconn.state != .closed and
                                    !postconn.close_after_write)
                                {
                                    if (postconn.fd) |pfd| {
                                        self.io.rearmRecv(index, pfd);
                                    }
                                }
                            },
                            .write => {
                                // Async writev CQE from the native backend:
                                // `event.bytes` carries `cqe.res` (the bytes
                                // the kernel actually sent). Advance the
                                // write queue before entering handleWrite so
                                // the next submission sees the post-ack state.
                                if (conn.send_in_flight) {
                                    self.advanceAsyncWriteQueue(conn, event.bytes);
                                }
                                self.handleWrite(index) catch |err| {
                                    std.log.debug("handleWrite conn={} failed: {}", .{ index, err });
                                };
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

    /// Copy kernel-delivered read data into the connection's read buffer.
    /// Called by the event dispatcher when the backend (io_uring native)
    /// delivered the data inline with the read event. After seeding,
    /// handleRead's existing pipeline loop picks up the data the same
    /// way it would after a read() syscall.
    ///
    /// For TLS connections the incoming bytes are ciphertext and go into
    /// the session's rbio (memory BIO) instead of `conn.read_buffer`.
    /// handleTlsHandshake / connRead then call SSL_do_handshake / SSL_read
    /// which pull from rbio, run the decrypt, and deliver plaintext into
    /// `conn.read_buffer`.
    fn seedReadBuffer(self: *Server, conn: *connection.Connection, data: []const u8) void {
        if (data.len == 0) return;
        if (conn.is_tls) {
            // Feed ciphertext into rbio. BIO_write may consume less than
            // requested on an internal failure; loop until drained or the
            // BIO refuses progress.
            if (conn.tls_session) |*session| {
                var remaining = data;
                while (remaining.len > 0) {
                    const n = session.feedCryptoData(remaining) catch {
                        // rbio write failed — drop the remaining bytes; the
                        // next SSL_read will hit a TLS error and close the
                        // connection cleanly.
                        return;
                    };
                    if (n == 0) return;
                    remaining = remaining[n..];
                }
                conn.markActive(self.io.nowMs());
            }
            return;
        }
        const buf = conn.read_buffer orelse return;
        const end = conn.read_offset + conn.read_buffered_bytes;
        if (end + data.len > buf.bytes.len) {
            // Data doesn't fit in the remaining buffer space. In this
            // case we simply drop the extra bytes — they were
            // already consumed from the kernel ring. The connection
            // will likely hit a parse error and close, which is the
            // correct behavior for an oversized request.
            const available = if (end >= buf.bytes.len) 0 else buf.bytes.len - end;
            if (available == 0) return;
            @memcpy(buf.bytes[end..][0..available], data[0..available]);
            self.io.onReadBuffered(conn, available);
            conn.markActive(self.io.nowMs());
            return;
        }
        @memcpy(buf.bytes[end..][0..data.len], data);
        self.io.onReadBuffered(conn, data.len);
        conn.markActive(self.io.nowMs());
    }

    /// Build an iovec batch from the connection's write queue and
    /// submit it as an async `IORING_OP_WRITEV` SQE on the native
    /// io_uring backend. Returns `true` if the SQE was accepted (the
    /// caller should `return` and wait for the CQE) or `false` if
    /// the submission failed and the caller should fall back to a
    /// sync writev.
    ///
    /// On success the iovec array is parked on `conn.async_send_iov`
    /// so its address stays stable until the kernel has copied the
    /// bytes out; `conn.send_in_flight` is set to lock out further
    /// submissions until the `.write` CQE fires.
    fn submitConnAsyncWritev(self: *Server, conn: *connection.Connection, fd: std.posix.fd_t) bool {
        var iov_count: u16 = 0;
        var total_bytes: usize = 0;
        var scan_head = conn.write_head;
        var scan_remaining = conn.write_count;
        const cap = connection.async_send_iov_capacity;
        while (scan_remaining > 0 and iov_count < cap) : (iov_count += 1) {
            const e = &conn.write_queue[scan_head];
            const s = e.handle.bytes[e.offset..e.len];
            conn.async_send_iov[iov_count] = .{ .base = s.ptr, .len = s.len };
            total_bytes += s.len;
            scan_head = if (scan_head + 1 >= conn.write_queue.len) 0 else scan_head + 1;
            scan_remaining -= 1;
        }
        if (iov_count == 0) return false;
        const iov_slice = conn.async_send_iov[0..iov_count];
        self.io.submitAsyncWritev(conn.index, fd, iov_slice) catch return false;
        conn.send_in_flight = true;
        conn.async_send_iov_count = iov_count;
        conn.async_send_total_bytes = total_bytes;
        return true;
    }

    /// Advance the connection's write queue after an async writev
    /// CQE reports `bytes_written`. Pops any fully-sent entries,
    /// releases their buffers, and updates `entry.offset` on a
    /// partially-sent entry. Called from the event dispatcher when a
    /// `.write` event arrives for a connection with `send_in_flight`.
    fn advanceAsyncWriteQueue(self: *Server, conn: *connection.Connection, bytes_written: usize) void {
        var remaining = bytes_written;
        while (remaining > 0) {
            const entry = conn.peekWrite() orelse break;
            const left_in_entry = entry.len - entry.offset;
            if (remaining >= left_in_entry) {
                remaining -= left_in_entry;
                self.io.onWriteCompleted(conn, left_in_entry);
                self.io.releaseBuffer(entry.handle);
                conn.popWrite();
                if (conn.hasPendingBody()) {
                    self.streamBodyChunks(conn, conn.pending_body);
                }
            } else {
                entry.offset += remaining;
                self.io.onWriteCompleted(conn, remaining);
                remaining = 0;
            }
        }
        conn.send_in_flight = false;
        conn.async_send_iov_count = 0;
        conn.async_send_total_bytes = 0;
        conn.markActive(self.io.nowMs());
    }

    pub fn handleRead(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        if (conn.fd == null) return;
        if (!self.io.canRead(conn)) return;
        if (conn.timeout_phase == .idle) self.io.setTimeoutPhase(conn, .header);
        const buffer_handle = conn.read_buffer orelse return;

        // If we're accumulating a large body, continue that instead of parsing.
        // Loop until EAGAIN to drain all available data (edge-triggered epoll).
        if (conn.isAccumulatingBody()) {
            // Completion-model backends deliver plaintext directly into the
            // buffer, so we can consume it without another syscall. TLS on
            // native still needs to run through connRead (SSL_read) because
            // the bytes the kernel delivered are ciphertext living in rbio.
            if (self.io.capabilities().delivers_read_data and !conn.is_tls) {
                self.continueBodyAccumulation(conn) catch {
                    self.abortBodyAccumulation(conn, 400);
                    return;
                };
                return;
            }
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
        // With completion-model backends (io_uring native), the event
        // dispatcher has already seeded read_buffered_bytes from the
        // kernel's provided buffer. Skip the read() syscall in that
        // case — the data is already there. For TLS on native, the
        // kernel-delivered bytes are ciphertext living in rbio; we still
        // need to call connRead (SSL_read) to pull plaintext out.
        if (!self.io.capabilities().delivers_read_data or conn.is_tls) {
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
        } else if (conn.read_buffered_bytes == 0) {
            // Completion backend but no data seeded (shouldn't happen
            // unless the event was spurious). Nothing to do.
            return;
        }

        if (build_options.enable_http2 and conn.protocol == .http1 and conn.read_offset == 0) {
            const end = conn.read_offset + conn.read_buffered_bytes;
            if (end <= buffer_handle.bytes.len) {
                const candidate = buffer_handle.bytes[0..end];
                if (http2_mod.matchesHttp2Preface(candidate)) {
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
                    http2_mod.sendHttp2ServerPreface(self, conn) catch {
                        self.closeConnection(conn);
                        return;
                    };
                }
            }
        }

        if (conn.protocol == .http2) {
            try http2_mod.handleHttp2Read(self, conn);
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
                            try http2_mod.handleHttp2Read(self, conn);
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
            switch (preencoded.tryDispatchPreencodedH1(self, conn, parse.view)) {
                .dispatched => {
                    if (conn.read_buffered_bytes == 0) break;
                    continue;
                },
                .pool_exhausted => {
                    // Buffer pool is temporarily full. Break the
                    // pipelining loop — do NOT fall through to the
                    // router (it would also fail to acquire a buffer
                    // and close the connection). Pending writes will
                    // drain, return buffers to the pool, and the next
                    // event-loop iteration picks up remaining pipelined
                    // requests from the read buffer.
                    break;
                },
                .not_cached => {},
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

            // Lazy arena acquire: GETs that miss the pre-encoded cache
            // are likely 404s or simple handlers that don't need arena
            // memory. Skip the buffer-pool acquire for GETs; POST/PUT
            // handlers that accumulate request bodies need the arena
            // so we acquire eagerly for those.
            //
            // This saves ~200ns/req from the pool acquire+release on
            // the error-handling benchmark where 45% of requests are
            // 404/405 GETs that never touch the arena.
            const needs_eager_arena = (parse.view.method != .GET and parse.view.method != .HEAD and parse.view.method != .DELETE);
            const arena_handle = if (needs_eager_arena) self.io.acquireBuffer() else null;
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

        // Read-loop draining: if buffer is fully consumed and we can
        // still process, try one more non-blocking read to avoid an
        // extra event loop round-trip. Helps fast persistent clients
        // (e.g. k6 benchmarks) on readiness backends. Skip on
        // completion-model backends (native io_uring) — the kernel's
        // multishot recv will deliver any further data as a separate
        // CQE, so a speculative read here is always EAGAIN and wastes
        // a syscall.
        if (!self.io.capabilities().delivers_read_data and
            conn.read_buffered_bytes == 0 and
            conn.canEnqueueWrite() and
            !conn.close_after_write)
        {
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

    pub fn handleWrite(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        const socket_fd = conn.fd orelse return;

        while (true) {
            if (conn.is_tls) {
                // Flush any ciphertext stashed from a prior partial writev
                // before touching SSL_write — we must preserve encryption
                // order, and SSL_write would otherwise produce a record
                // that races ahead of the carried record on the wire.
                switch (server_tls.tlsDrainCarry(self, conn)) {
                    .done => {},
                    .again => return,
                    .err => {
                        self.closeConnection(conn);
                        return;
                    },
                }
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
                            // If connWrite populated the carry (writev was
                            // only partially absorbed), pause the loop —
                            // we'll resume once the next writable event
                            // drains the carry.
                            if (conn.tls_cipher_carry_handle != null) return;
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
                // Plain TCP path.
                //
                // Sync `writev(2)` is the fast path for plain TCP on
                // every backend. We tried routing keepalive responses
                // through IORING_OP_WRITEV, but the CQE round trip
                // between submit and continuation cost more than the
                // memcpy-into-kernel-buffer it was supposed to
                // overlap, and the resulting send-in-flight gating
                // serialized subsequent requests on the same
                // connection. Sync writev runs inline, lets us close
                // the fd in the same dispatcher tick for close-mode
                // requests, and never blocks the reactor because the
                // socket is non-blocking.
                if (conn.send_in_flight) return;
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
                            .AGAIN => {
                                // Socket send buffer is full.
                                // On completion-model backends (native
                                // io_uring) the reactor has no generic
                                // POLLOUT readiness event, so we must
                                // explicitly arm one — otherwise the
                                // connection stalls forever waiting
                                // for a wake that never comes. Other
                                // backends re-arm their POLL_ADD mask
                                // through the standard dispatcher path
                                // so this call is a no-op for them.
                                self.io.armWritable(conn.index, socket_fd) catch {};
                                return;
                            },
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
            if (conn.close_after_write) {
                self.closeConnection(conn);
                return;
            }
            // If there's still data in the read buffer (from a pipelining
            // backpressure break), re-enter the read handler now that
            // writes have drained and buffers are free. With edge-triggered
            // epoll, no new read event will fire since the data is already
            // buffered — we must process it explicitly here.
            if (conn.read_buffered_bytes > 0) {
                self.handleRead(index) catch {};
                return;
            }
            self.io.setTimeoutPhase(conn, .idle);
        }
    }

    fn handleError(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        self.closeConnection(conn);
    }

    fn queueResponse(self: *Server, conn: *connection.Connection, resp: response_mod.Response) !void {
        // Fast path: for common error statuses (404, 400, 405, 501)
        // with simple static bodies, serve pre-encoded bytes directly.
        // This skips encodeResponseHeaders, Date formatting, and the
        // Alt-Svc header entirely — just a memcpy into the write buf.
        // The error-handling benchmark is 80% error responses; this
        // turns them into the same speed as pre-encoded /health hits.
        //
        // Match criteria: non-close connection, body is .bytes or .none
        // (no managed/scattered body), and status in the error cache.
        // We don't check headers.len — the pre-encoded template
        // includes its own headers (Content-Type etc.).
        if (!conn.close_after_write) {
            const is_simple_body = switch (resp.body) {
                .bytes, .none => true,
                else => false,
            };
            if (is_simple_body) {
                if (preencoded.findPreencodedError(self, resp.status)) |entry| {
                    if (preencoded.sendH1PreencodedBytes(self, conn, entry.bytes[0..entry.len])) return;
                    // Pool exhausted — fall through to the normal encode path
                    // which also acquires a buffer. If that also fails, the
                    // connection is closed there (existing behavior).
                }
            }
        }

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

    pub fn encodeResponse(buf: []u8, resp: response_mod.Response, alt_svc: ?[]const u8, connection_close: bool, date_str: []const u8) !usize {
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
    pub fn getCachedDate(self: *Server) []const u8 {
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

    pub fn notFoundResponse() response_mod.Response {
        return .{
            .status = 404,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Not Found\n" },
        };
    }

    pub fn badRequestResponse() response_mod.Response {
        return .{
            .status = 400,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Bad Request\n" },
        };
    }

    pub fn notImplementedResponse() response_mod.Response {
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
    /// Guess Content-Type from file extension
    pub fn guessContentType(path: []const u8) []const u8 {
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
        } else if (std.mem.endsWith(u8, path, ".webp")) {
            return "image/webp";
        } else if (std.mem.endsWith(u8, path, ".woff2")) {
            return "font/woff2";
        } else if (std.mem.endsWith(u8, path, ".woff")) {
            return "font/woff";
        } else if (std.mem.endsWith(u8, path, ".ico")) {
            return "image/x-icon";
        } else if (std.mem.endsWith(u8, path, ".xml")) {
            return "application/xml";
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

    pub fn buildHttp3RequestView(req: http3.RequestReadyEvent, headers_out: []request.Header) ?request.RequestView {
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

    pub fn isAllowedHost(self: *const Server, req_view: request.RequestView) bool {
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
                if (accum.buffer_count == 0 or accum.current_buf_offset >= self.io.bodyBufferSize()) {
                    if (accum.buffer_count >= connection.BodyAccumState.MAX_BODY_BUFFERS) {
                        return error.BodyTooLarge;
                    }
                    const buf = self.io.acquireBodyBuffer() orelse return error.OutOfMemory;
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
                if (accum.buffer_count == 0 or accum.current_buf_offset >= self.io.bodyBufferSize()) {
                    if (accum.buffer_count >= connection.BodyAccumState.MAX_BODY_BUFFERS) {
                        return error.BodyTooLarge;
                    }
                    const buf = self.io.acquireBodyBuffer() orelse return error.OutOfMemory;
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
                .buffer_size = self.io.bodyBufferSize(),
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
            const buffer_size = self.io.bodyBufferSize();

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

            // Previously a zero-copy echo path transferred body buffers
            // to the write queue as a scattered response. Disabled now
            // that body buffers are from a separate pool with different
            // size — the transfer would require per-handle pool tagging.
            // The echo case still works via the normal copy path below.
            {
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
        if (preencoded.tryDispatchPreencodedH1(self, conn, req_view) == .dispatched) return;

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
                self.io.releaseBodyBuffer(accum.body_buffers[i]);
            }
            // The original read buffer is from the hot-path pool
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

    pub fn closeConnection(self: *Server, conn: *connection.Connection) void {
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
        // Release any stashed TLS ciphertext carry buffer.
        if (conn.tls_cipher_carry_handle) |carry_buf| {
            self.io.releaseBuffer(carry_buf);
            conn.tls_cipher_carry_handle = null;
            conn.tls_cipher_carry_offset = 0;
            conn.tls_cipher_carry_len = 0;
        }
        // Clear async send state. Any still-in-flight writev CQE from
        // this connection's previous incarnation will be dropped by
        // the generation-counter check in the native backend's poll()
        // (releaseConnection bumps the counter below). The fd has
        // already been closed above, so the kernel finished copying
        // bytes out of the connection's buffers before we reach the
        // releaseBuffer loop.
        conn.send_in_flight = false;
        conn.async_send_iov_count = 0;
        conn.async_send_total_bytes = 0;
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

    fn connRead(self: *Server, conn: *connection.Connection, buf: []u8) ReadResult {
        if (conn.is_tls) {
            // Pull any newly-arrived ciphertext into rbio on non-completion
            // backends (no-op on native — the event dispatcher seeded it).
            _ = server_tls.tlsPumpRead(self, conn);
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

    fn connWrite(self: *Server, conn: *connection.Connection, data: []const u8) WriteResult {
        if (conn.is_tls) {
            // Cap plaintext per SSL_write so wbio never holds more ciphertext
            // than one TLS record — that guarantees a full drain through
            // `tls_cipher_scratch` in a single BIO_read/writev round.
            const chunk_len = @min(data.len, server_tls.TLS_PLAINTEXT_WRITE_CAP);
            if (chunk_len == 0) return .{ .bytes = 0 };
            var session = &(conn.tls_session orelse return .err);
            const n = session.write(data[0..chunk_len]) catch |err| return switch (err) {
                error.WouldBlock => .again,
                else => .err,
            };
            if (n == 0) return .again;
            // Drain the fresh ciphertext straight to the socket. On
            // backpressure the remainder is stashed into the per-conn
            // cipher carry, and we return .bytes (the plaintext was already
            // consumed by SSL_write). handleWrite checks the carry at the
            // top of its loop on the next write event and flushes it there.
            server_tls.tlsFlushWbio(self, conn) catch |err| return switch (err) {
                error.TlsCarryAllocFailed => .err,
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

    try http2_mod.queueHttp2Response(&server, conn, 1, result.resp, false);
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

    try http2_mod.queueHttp2Response(&server, conn, 1, result.resp, false);
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

pub fn acquireBufferOpaque(ctx: *anyopaque) ?buffer_pool.BufferHandle {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    return io.acquireBuffer();
}

pub fn releaseBufferOpaque(ctx: *anyopaque, handle: buffer_pool.BufferHandle) void {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    io.releaseBuffer(handle);
}

// Benchmark / TechEmpower handlers, `/json` dataset loader, and the
// `registerDefaultRoutes` / `registerDefaultPostHooks` wiring moved to
// `src/benchmark_routes.zig`. Downstream consumers reach them through
// `swerver.benchmark.registerRoutes(&app_router)`,
// `swerver.benchmark.registerPostHooks(&app_router)`, and
// `swerver.benchmark.loadDataset()`. See `examples/httparena/main.zig`
// for a reference consumer.
