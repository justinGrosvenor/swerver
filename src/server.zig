const std = @import("std");

const config = @import("config.zig");
const config_fetch = @import("config_fetch.zig");
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
const otel_mod = @import("middleware/otel.zig");
const config_file_mod = @import("config_file.zig");
const accept_mod = @import("server/accept.zig");
const http3_mod = @import("server/http3.zig");
const http2_mod = @import("server/http2.zig");
const http1_mod = @import("server/http1.zig");
const dispatch = @import("server/dispatch.zig");
const write_queue = @import("server/write_queue.zig");

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
pub const PendingReload = struct {
    loaded: config_file_mod.LoadedConfig,
    new_hash: u64,
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
    /// Admin API listener (null if admin API not enabled)
    admin_listener_fd: ?std.posix.fd_t = null,
    /// Spare FD for EMFILE recovery — closed temporarily to accept+close one connection
    spare_fd: ?std.posix.fd_t = null,
    /// OpenTelemetry trace exporter (null if otel not enabled)
    otel: ?*otel_mod.TraceExporter = null,
    /// Config source for hot reload (null if not using external config)
    config_source: ?config_fetch.ConfigSource = null,
    /// Hash of last fetched config bytes — skip rebuild when unchanged
    config_content_hash: u64 = 0,
    /// Arena owning the route/upstream string data from the last config reload.
    /// Freed on next reload or on server deinit. Null when proxy was set up
    /// via ServerBuilder (strings owned by the caller's arena instead).
    reload_arena: ?std.heap.ArenaAllocator = null,
    /// Background reload result, set by the fetch thread, consumed by the event loop.
    pending_reload: std.atomic.Value(?*PendingReload) = std.atomic.Value(?*PendingReload).init(null),
    /// True while a background reload fetch is in flight.
    reload_in_progress: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Buffer for receiving UDP datagrams
    udp_recv_buf: [2048]u8 = undefined,
    /// Pre-computed Alt-Svc header value for HTTP/3 advertisement
    alt_svc_value: [64]u8 = undefined,
    alt_svc_len: usize = 0,
    /// True when proxy, rate limiting, or middleware needs the peer IP.
    /// When false, accept skips the getpeername syscall.
    needs_peer_ip: bool = true,
    /// Monotonic timestamp cached once per event-loop tick. Used by
    /// markActive and other non-critical-timing calls to avoid
    /// repeated clock_gettime syscalls within the same event batch.
    now_ms: u64 = 0,
    last_date_check_sec: u64 = 0,
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
            .payment_required_json = cfg.x402.payment_required_json,
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
        const tcp_tls_provider: ?tls.Provider = if (build_options.enable_tls and cfg.tls.cert_path.len > 0) blk: {
            const extra_certs = cfg.tls.certificates;
            var cert_entries: [tls.MAX_SNI_ENTRIES]tls.Provider.CertEntry = undefined;
            const n = @min(extra_certs.len, tls.MAX_SNI_ENTRIES);
            for (extra_certs[0..n], 0..) |c, i| {
                cert_entries[i] = .{
                    .hostnames = c.hostnames,
                    .cert_path = c.cert_path,
                    .key_path = c.key_path,
                };
            }
            const mtls_cfg: ?tls.Provider.MtlsConfig = if (cfg.tls.client_ca_path.len > 0) .{
                .ca_path = cfg.tls.client_ca_path,
                .require = cfg.tls.client_cert_required,
            } else null;
            break :blk tls.Provider.initTcpSniMtls(
                allocator,
                cfg.tls.cert_path,
                cfg.tls.key_path,
                cert_entries[0..n],
                mtls_cfg,
            ) catch |err| {
                std.log.err("TLS init failed: {}", .{err});
                return error.TlsInitFailed;
            };
        } else null;
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

        if (!self.cfg.disable_preencoded) {
            preencoded.initPreencodedH1(self);
            if (build_options.enable_http2) preencoded.initPreencodedH2(self);
        }

        if (cfg.otel.enabled) {
            const otel_ptr = try allocator.create(otel_mod.TraceExporter);
            otel_ptr.* = otel_mod.TraceExporter.init(cfg.otel);
            self.otel = otel_ptr;
        }

        // Skip getpeername on accept when nothing needs the peer IP.
        self.needs_peer_ip = self.proxy != null or
            app_router.middleware_chain.post.len > 0;
    }

    pub fn deinit(self: *Server) void {
        if (self.tcp_tls_provider) |*p| p.deinit();
        if (self.listener_fd) |fd| clock.closeFd(fd);
        if (self.udp_fd) |fd| clock.closeFd(fd);
        if (self.static_root_fd) |fd| clock.closeFd(fd);
        if (self.admin_listener_fd) |fd| clock.closeFd(fd);
        if (self.quic) |*q| q.deinit();
        if (self.otel) |otel_ptr| self.allocator.destroy(otel_ptr);
        if (self.pending_reload.swap(null, .acq_rel)) |pr| {
            var loaded = pr.loaded;
            loaded.deinit();
            std.heap.page_allocator.destroy(pr);
        }
        if (self.reload_arena) |*a| a.deinit();
        self.io.deinit();
    }

    /// Request a graceful shutdown. The event loop will stop accepting new connections
    /// and exit after draining in-flight responses.
    pub fn shutdown(_: *Server) void {
        dispatch.requestShutdown();
    }

    /// Kick off a background thread to fetch + parse config.
    /// The event loop stays unblocked; call applyPendingReload() each
    /// tick to pick up the result once the fetch completes.
    pub fn startBackgroundReload(self: *Server) void {
        if (self.config_source == null) {
            std.log.info("reload requested but no config source set, ignoring", .{});
            return;
        }
        if (self.reload_in_progress.swap(true, .acq_rel)) return;

        const thread = std.Thread.spawn(.{}, backgroundReloadFetch, .{self}) catch |err| {
            std.log.err("Failed to spawn reload thread: {}", .{err});
            self.reload_in_progress.store(false, .release);
            return;
        };
        thread.detach();
    }

    fn backgroundReloadFetch(server: *Server) void {
        defer server.reload_in_progress.store(false, .release);

        const source = server.config_source.?;
        const alloc = std.heap.page_allocator;

        var loaded: config_file_mod.LoadedConfig = undefined;
        var new_hash: u64 = 0;

        switch (source) {
            .file => |path| {
                loaded = config_file_mod.loadConfigFile(alloc, path) catch |err| {
                    std.log.err("Config reload failed: {}", .{err});
                    return;
                };
            },
            .url => |url_config| {
                const bytes = config_fetch.fetchConfigBytes(alloc, url_config) catch |err| {
                    std.log.err("Config reload from URL failed: {}", .{err});
                    return;
                };
                defer alloc.free(bytes);

                new_hash = std.hash.Wyhash.hash(0, bytes);
                if (new_hash == server.config_content_hash) return;

                std.log.info("config changed, reloading", .{});

                if (url_config.cache_path) |cache_path| {
                    config_fetch.writeCacheFile(cache_path, bytes) catch |err| {
                        std.log.warn("failed to update config cache: {}", .{err});
                    };
                }

                loaded = config_file_mod.parseJsonFromBytes(alloc, bytes) catch |err| {
                    std.log.err("Config reload parse failed: {}", .{err});
                    return;
                };
            },
        }

        loaded.server_config.x402 = server.cfg.x402;

        loaded.server_config.validate() catch |err| {
            std.log.err("Config reload validation failed: {}", .{err});
            loaded.deinit();
            return;
        };

        const result = alloc.create(PendingReload) catch {
            loaded.deinit();
            return;
        };
        result.* = .{ .loaded = loaded, .new_hash = new_hash };

        if (server.pending_reload.swap(result, .acq_rel)) |old| {
            var old_loaded = old.loaded;
            old_loaded.deinit();
            alloc.destroy(old);
        }
    }

    /// Apply a pending reload result produced by the background thread.
    /// Called from the event loop; only does the fast pointer swap.
    pub fn applyPendingReload(self: *Server) void {
        const result = self.pending_reload.swap(null, .acq_rel) orelse return;
        defer std.heap.page_allocator.destroy(result);

        var loaded = result.loaded;
        if (result.new_hash != 0) self.config_content_hash = result.new_hash;

        const new = loaded.server_config;
        self.cfg.timeouts = new.timeouts;
        self.cfg.limits = new.limits;

        if (loaded.upstreams.len > 0 and loaded.routes.len > 0) {
            var new_proxy = proxy_mod.Proxy.init(self.allocator, .{
                .upstreams = loaded.upstreams,
                .routes = loaded.routes,
            }) catch |err| {
                std.log.err("Config reload: proxy rebuild failed: {}", .{err});
                loaded.deinit();
                return;
            };

            const proxy_ptr = self.allocator.create(proxy_mod.Proxy) catch {
                new_proxy.deinit();
                loaded.deinit();
                return;
            };
            proxy_ptr.* = new_proxy;

            const old_proxy = self.proxy;
            const old_arena = self.reload_arena;
            self.proxy = proxy_ptr;
            self.reload_arena = loaded.arena;

            if (old_proxy) |old| {
                old.deinit();
                self.allocator.destroy(old);
            }
            if (old_arena) |*oa| oa.deinit();
            self.needs_peer_ip = true;

            const source = self.config_source.?;
            const src_label: []const u8 = switch (source) {
                .file => |p| p,
                .url => |u| u.url,
            };
            std.log.info("Config reloaded from {s} (routes: {d}, upstreams: {d})", .{
                src_label, loaded.routes.len, loaded.upstreams.len,
            });
        } else {
            if (self.proxy != null and loaded.upstreams.len == 0 and loaded.routes.len == 0) {
                if (self.proxy) |old| {
                    old.deinit();
                    self.allocator.destroy(old);
                    self.proxy = null;
                }
                if (self.reload_arena) |*old_arena| old_arena.deinit();
                self.reload_arena = loaded.arena;
                self.needs_peer_ip = self.app_router.middleware_chain.post.len > 0;
                std.log.info("Config reloaded (proxy removed)", .{});
            } else {
                loaded.deinit();
                std.log.info("Config reloaded", .{});
            }
        }
    }

    /// Synchronous reload (legacy path for SIGHUP with file-based config).
    pub fn applyReload(self: *Server) void {
        self.startBackgroundReload();
    }

    pub fn run(self: *Server, run_for_ms: ?u64) !void {
        return dispatch.runLoop(self, run_for_ms);
    }

    pub fn runFor(self: *Server, run_for_ms: u64) !void {
        try self.run(run_for_ms);
    }

    /// Thin wrappers around `server/dispatch.zig`. The dispatch
    /// body moved out in Extract 7; these methods remain on
    /// `Server` so `server/tls.zig` can schedule a read/write pass
    /// after a handshake completes without importing
    /// `server/dispatch.zig` directly (which would form a cycle:
    /// dispatch → tls → dispatch).
    pub fn handleRead(self: *Server, index: u32) !void {
        return dispatch.handleRead(self, index);
    }

    pub fn handleWrite(self: *Server, index: u32) !void {
        return dispatch.handleWrite(self, index);
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

    /// Refresh the cached date string. Called once per event-loop
    /// iteration so individual responses never hit clock_gettime.
    pub fn refreshCachedDate(self: *Server) void {
        const mono_sec = self.now_ms / 1000;
        if (mono_sec == self.last_date_check_sec and self.cached_date_epoch != 0) return;
        self.last_date_check_sec = mono_sec;
        const ts = clock.realtimeTimespec() orelse return;
        const epoch_secs: u64 = @intCast(ts.sec);
        if (epoch_secs != self.cached_date_epoch) {
            _ = formatImfDate(&self.cached_date);
            self.cached_date_epoch = epoch_secs;
        }
    }

    /// Return the pre-computed IMF-fixdate string.
    pub fn getCachedDate(self: *Server) []const u8 {
        if (self.cached_date_epoch == 0) self.refreshCachedDate();
        return self.cached_date[0..29];
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
            .body = .{ .slice = req.body },
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

    pub fn closeConnection(self: *Server, conn: *connection.Connection) void {
        if (conn.ip_hash != 0) {
            accept_mod.ip_tracker.decrement(conn.ip_hash);
            conn.ip_hash = 0;
        }
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
        if (conn.h2_pending) |pending| {
            for (pending) |*slot| {
                if (slot.body_handle) |bh| {
                    if (slot.body_is_body_pool) self.io.releaseBodyBuffer(bh) else self.io.releaseBuffer(bh);
                }
            }
            self.allocator.destroy(pending);
            conn.h2_pending = null;
        }
        if (conn.h2_pending_files) |files| {
            for (files) |*f| f.cleanup();
            self.allocator.destroy(files);
            conn.h2_pending_files = null;
        }
        if (conn.h2_pending_responses) |resps| {
            for (resps) |*r| r.cleanup(&self.io);
            self.allocator.destroy(resps);
            conn.h2_pending_responses = null;
        }
        // Clean up body accumulation state
        http1_mod.cleanupBodyAccumulation(self, conn);
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


};

test "metrics middleware response queued for http1" {
    var gpa = std.heap.DebugAllocator(.{}){};
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
        .body = .{ .slice = "" },
    };

    var mw_ctx = middleware.Context{
        .protocol = .http1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = write_queue.acquireBufferOpaque,
            .release = write_queue.releaseBufferOpaque,
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

    try http1_mod.queueResponse(&server, conn, result.resp);
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

    var gpa = std.heap.DebugAllocator(.{}){};
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
        .body = .{ .slice = "" },
    };

    var mw_ctx = middleware.Context{
        .protocol = .http2,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = write_queue.acquireBufferOpaque,
            .release = write_queue.releaseBufferOpaque,
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
    var stack = http2.Stack.init();
    _ = stack.openTestStream(1);
    conn.http2_stack = &stack;

    try http2_mod.queueHttp2Response(&server, conn, 1, result.resp, false);
    try std.testing.expect(conn.write_count >= 1);

    const expected = result.resp.bodyBytes();
    var found_data = false;
    var saw_managed_handle = false;

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        if (entry.handle.index == managed.handle.index) {
            saw_managed_handle = true;
        }
        var off: usize = 0;
        while (off + 9 <= entry.len) {
            const frame_type = entry.handle.bytes[off + 3];
            const flen = (@as(usize, entry.handle.bytes[off]) << 16) |
                (@as(usize, entry.handle.bytes[off + 1]) << 8) |
                @as(usize, entry.handle.bytes[off + 2]);
            if (frame_type == @intFromEnum(http2.FrameType.data)) {
                try std.testing.expectEqualStrings(expected, entry.handle.bytes[off + 9 .. off + 9 + flen]);
                found_data = true;
            }
            off += 9 + flen;
        }
        server.io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    try std.testing.expect(found_data);
    try std.testing.expect(!saw_managed_handle);
}

test "metrics middleware end-to-end http1" {
    var gpa = std.heap.DebugAllocator(.{}){};
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
            .acquire = write_queue.acquireBufferOpaque,
            .release = write_queue.releaseBufferOpaque,
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

    try http1_mod.queueResponse(&server, conn, result.resp);
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

    var gpa = std.heap.DebugAllocator(.{}){};
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
            .acquire = write_queue.acquireBufferOpaque,
            .release = write_queue.releaseBufferOpaque,
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
    try std.testing.expect(conn.write_count >= 1);

    const expected = result.resp.bodyBytes();
    var collected = try std.testing.allocator.alloc(u8, expected.len);
    defer std.testing.allocator.free(collected);
    var collected_len: usize = 0;

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        var off: usize = 0;
        while (off + 9 <= entry.len) {
            const frame_type = entry.handle.bytes[off + 3];
            const flen = (@as(usize, entry.handle.bytes[off]) << 16) |
                (@as(usize, entry.handle.bytes[off + 1]) << 8) |
                @as(usize, entry.handle.bytes[off + 2]);
            if (frame_type == @intFromEnum(http2.FrameType.data)) {
                @memcpy(collected[collected_len .. collected_len + flen], entry.handle.bytes[off + 9 .. off + 9 + flen]);
                collected_len += flen;
            }
            off += 9 + flen;
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
    var gpa = std.heap.DebugAllocator(.{}){};
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

    try http1_mod.queueResponse(&server, conn, resp);
    const bytes = try write_queue.drainWriteQueue(&server.io, conn, allocator);
    defer allocator.free(bytes);

    // Verify structural correctness (Date header is dynamic so check components)
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Date: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 2\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhi"));
}

test "http1 managed response bytes from write queue" {
    var gpa = std.heap.DebugAllocator(.{}){};
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

    try http1_mod.queueResponse(&server, conn, resp);
    const bytes = try write_queue.drainWriteQueue(&server.io, conn, allocator);
    defer allocator.free(bytes);

    // Verify structural correctness (Date header is dynamic so check components)
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Date: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhello"));
}

// Benchmark / TechEmpower handlers, `/json` dataset loader, and the
// `registerDefaultRoutes` / `registerDefaultPostHooks` wiring moved to
// `src/benchmark_routes.zig`. Downstream consumers reach them through
// `swerver.benchmark.registerRoutes(&app_router)`,
// `swerver.benchmark.registerPostHooks(&app_router)`, and
// `swerver.benchmark.loadDataset()`. See `examples/httparena/main.zig`
// for a reference consumer.
