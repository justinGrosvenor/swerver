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
const proxy_mod = @import("proxy/proxy.zig");
const upstream_mod = @import("proxy/upstream.zig");
const tenant_mod = @import("proxy/tenant.zig");
const forward_mod = @import("proxy/forward.zig");
const preencoded = @import("server/preencoded.zig");
const server_tls = @import("server/tls.zig");
const otel_mod = @import("middleware/otel.zig");
const config_file_mod = @import("config_file.zig");
// WASM edge filters (design 10.0). Gated; the Server stores the manager as an
// opaque pointer so this file compiles without the vendored wasm3 dependency.
const wasm_manager_mod = if (build_options.enable_wasm) @import("wasm/manager.zig") else struct {};
const wasm_host_call_mod = if (build_options.enable_wasm) @import("wasm/host_call.zig") else struct {};
const wasm_control_mod = if (build_options.enable_wasm) @import("wasm/control_client.zig") else struct {};
const accept_mod = @import("server/accept.zig");
const http3_mod = @import("server/http3.zig");
const http2_mod = @import("server/http2.zig");
const http1_mod = @import("server/http1.zig");
const dispatch = @import("server/dispatch.zig");
const write_queue = @import("server/write_queue.zig");
const pg_client_mod = @import("db/pg/client.zig");

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

/// A bound TCP listener fd paired with the protocol config for its port.
/// Connections accepted on `fd` resolve their config via getsockname → the
/// matching ListenerConfig (see accept.zig).
pub const BoundListener = struct {
    fd: std.posix.fd_t,
    cfg: config.ListenerConfig,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: config.ServerConfig,
    io: runtime.IoRuntime,
    app_router: router.Router,
    listener_fd: ?std.posix.fd_t,
    udp_fd: ?std.posix.fd_t,
    /// All bound TCP listeners with their per-port protocol config. In
    /// multi-listener mode the process binds several ports (each via
    /// SO_REUSEPORT on every worker); listener_fd points at listeners_buf[0]
    /// for backward compat with the legacy drain path. Single-listener configs
    /// still populate exactly one entry here.
    listeners_buf: [8]BoundListener = undefined,
    listeners_count: usize = 0,
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
    /// Declarative WASM edge-filter specs (from config). Set before run();
    /// pools are built per-worker at run() start and rebuilt on config reload.
    wasm_filter_specs: []const config_file_mod.WasmFilterConfig = &.{},
    /// Per-worker WASM filter manager owning the filter pools. Opaque so this
    /// struct needs no build-flag gating; a *wasm.manager.Manager when enabled.
    wasm_manager: ?*anyopaque = null,
    /// Per-worker WASM host-call park table (design 10.0). Inline, lives for the
    /// worker; void when wasm is compiled out.
    wasm_host_calls: if (build_options.enable_wasm) wasm_host_call_mod.Table else void =
        if (build_options.enable_wasm) .{} else {},
    /// Mock host-call transport (e2e mock lane / C2 validation). When enabled, a
    /// parked filter is completed on the next housekeeping tick with
    /// `wasm_mock_reply` instead of a real call. Off in production; the real
    /// control-socket transport (C3, `wasm_control`) takes precedence when set.
    /// The pending ring holds park tokens awaiting mock completion.
    wasm_mock_enabled: bool = false,
    wasm_mock_reply: []const u8 = "ok",
    wasm_mock_pending: [64]u32 = undefined,
    wasm_mock_count: usize = 0,
    /// Nether control-socket path for the real host-call transport (C3). When
    /// non-empty and wasm is enabled, a ControlClient is built at run() start and
    /// drives host calls over the sandbox's control socket (proto_version=1),
    /// superseding the mock. Build-flag-free slice; borrowed, must outlive run().
    wasm_control_socket_path: []const u8 = "",
    /// Park (host_call) deadline in ms: how long a wasm filter may stay parked on
    /// a host call before the host_call.Table fails it closed. Default 30s (the
    /// historical hardcoded value). Plumbed into the H1/H2 binding `deadline_ms`
    /// and into the ControlClient's per-command timeout so the transport does not
    /// out-live the park. Lowerable (e.g. via the e2e env) so timeout assertions
    /// do not wait 30s. Per-server today; a per-route field is a future refinement.
    wasm_host_call_deadline_ms: u64 = 30_000,
    /// Per-worker control-socket client (the real C3 transport). Opaque so the
    /// Server struct needs no build-flag gating; a *wasm.control_client.ControlClient
    /// when enabled and a path is configured, else null.
    wasm_control: ?*anyopaque = null,
    /// Per-worker tenant-to-microVM affinity registry (park-concurrency Phase 1).
    /// Survives config reload (route table churn must not drop warm VM mappings).
    /// Inline; void when wasm is compiled out (tenant routing is reached only via
    /// the wasm cold-start park).
    tenant_registry: if (build_options.enable_wasm) tenant_mod.TenantRegistry else void =
        if (build_options.enable_wasm) .{} else {},
    /// Idle TTL for tenant registry entries (housekeeping reaps older mappings).
    /// Default 10 min; the supervisor owns actual VM reclaim.
    tenant_idle_ttl_ms: u64 = 600_000,
    /// Native PostgreSQL client (null unless the "postgres" config block
    /// is present).
    pg_client: ?*pg_client_mod.PgClient = null,
    /// Client-mode TLS provider for the PG client (null when sslmode is
    /// disable or TLS is compiled out). Owned here — mirrors
    /// tcp_tls_provider — and must outlive pg_client's slot sessions.
    pg_tls_provider: ?tls.Provider = null,
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
    /// True when the kernel supports UDP GSO (UDP_SEGMENT) — probed once
    /// at init. When set, the HTTP/3 send path coalesces a multi-packet
    /// response into one sendmsg instead of one sendto per packet.
    quic_gso: bool = false,
    /// Reused batch buffer for GSO sends (single-threaded reactor, no
    /// reentrancy — each send fully drains it before returning).
    quic_gso_batch: [http3_mod.GSO_BATCH_BYTES]u8 = undefined,
    /// Reused staging buffer for coalescing multiple TLS write-queue entries
    /// into a single SSL_write (one TLS record + one socket write instead of
    /// one per entry). Single-threaded reactor, reused per write event.
    tls_gather: [server_tls.TLS_PLAINTEXT_WRITE_CAP]u8 = undefined,
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
    /// In-memory static file cache (cfg.cache_static_files). Per-worker,
    /// lazy-populated on first serve, keyed by "<path>\x00<accept-class>".
    /// null when the flag is off. Bodies are owned; freed in deinit.
    static_cache: ?std.StringHashMap(StaticCacheEntry) = null,
    /// Total bytes of cached static bodies, bounded by STATIC_CACHE_MAX_BYTES.
    static_cache_bytes: usize = 0,
    /// Pre-encoded HTTP/1.1 response cache for opt-in hot static
    /// endpoints. The bytes are raw HTTP/1.1 (status line + headers +
    /// body). Refresh is lazy / per-second to track the Date header.
    h1_preencoded: [preencoded.MAX_H1_PREENCODED]preencoded.PreencodedH1Response = undefined,
    h1_preencoded_count: usize = 0,
    /// Pre-encoded error responses (404, 400, 405, 501). Keyed by
    /// status code and checked in `queueResponse` before the full
    /// encodeResponseHeaders path. Same Date-refresh semantics as
    /// the endpoint cache.
    h1_error_cache: [4]preencoded.PreencodedH1Response = undefined,
    h1_error_cache_count: usize = 0,
    /// Shared ciphertext drain scratch for TLS memory-BIO writes. Sized to
    /// hold one full TLS record's ciphertext (max_plaintext 16384 + 256 bytes
    /// of AEAD/framing overhead). Per-SSL_write we cap plaintext at 16 KiB so
    /// a single drain cycle never needs more than this. If the drain writev
    /// hits EAGAIN, the unsent tail + any wbio remainder is copied into the
    /// per-connection `tls_cipher_carry_handle`.
    tls_cipher_scratch: [server_tls.TLS_CIPHER_SCRATCH_SIZE]u8 = undefined,

    /// Quick-start constructor: builds a Server with an empty default router
    /// and the standard middleware security cache. Supply your own routes via
    /// `initWithRouter` or `ServerBuilder`.
    pub fn init(allocator: std.mem.Allocator, cfg: config.ServerConfig) !Server {
        const app_router = router.Router.init(.{
            .require_payment = cfg.x402.enabled,
            .payment_required_b64 = cfg.x402.payment_required_b64,
            .payment_required_json = cfg.x402.payment_required_json,
        });
        middleware.security.buildCache();
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
            .listeners_count = 0,
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

        if (cfg.cache_static_files) {
            self.static_cache = std.StringHashMap(StaticCacheEntry).init(allocator);
        }

        // Bind the WASM host-call park table to the worker allocator: each park
        // now heap-allocates a request-sized owned snapshot (freed on slot reuse
        // and at the table's deinit during Server.deinit), replacing the old fixed
        // per-slot embed.
        if (build_options.enable_wasm) {
            self.wasm_host_calls.allocator = allocator;
        }

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
            // Probe once for UDP GSO so the h3 send path can batch packets.
            self.quic_gso = net.supportsGso();
        }

        if (!self.cfg.disable_preencoded) {
            preencoded.initPreencodedH1(self);
        }

        if (cfg.otel.enabled) {
            const otel_ptr = try allocator.create(otel_mod.TraceExporter);
            otel_ptr.* = otel_mod.TraceExporter.init(cfg.otel);
            self.otel = otel_ptr;
        }

        // PostgreSQL client connection bring-up. DNS resolves once
        // here at startup — never on the reactor — so an unreachable
        // resolver can't stall the loop.
        // The actual non-blocking connects start from the housekeeping
        // tick once the event loop runs.
        if (cfg.postgres.enabled) pg_blk: {
            const password: []const u8 = pwd: {
                if (cfg.postgres.password_env.len == 0) break :pwd "";
                var name_z: [256]u8 = undefined;
                if (cfg.postgres.password_env.len >= name_z.len) break :pwd "";
                @memcpy(name_z[0..cfg.postgres.password_env.len], cfg.postgres.password_env);
                name_z[cfg.postgres.password_env.len] = 0;
                const name_z_ptr: [*:0]const u8 = @ptrCast(&name_z);
                const v = std.c.getenv(name_z_ptr) orelse break :pwd "";
                break :pwd std.mem.sliceTo(v, 0);
            };
            // Client-mode TLS: build the provider up front so a bad CA
            // path or a TLS-less build fails the whole
            // postgres block instead of every connect attempt.
            if (cfg.postgres.sslmode != .disable) {
                const ca: ?[:0]const u8 = if (cfg.postgres.ssl_root_cert.len > 0)
                    cfg.postgres.ssl_root_cert
                else
                    null;
                self.pg_tls_provider = tls.Provider.initTcpClient(
                    allocator,
                    cfg.postgres.sslmode == .verify_full,
                    ca,
                ) catch |err| {
                    std.log.warn("postgres: client TLS init failed: {} (sslmode={s}); client disabled", .{
                        err, @tagName(cfg.postgres.sslmode),
                    });
                    break :pg_blk;
                };
            }
            const pgc = allocator.create(pg_client_mod.PgClient) catch break :pg_blk;
            pgc.* = pg_client_mod.PgClient.init(allocator, cfg.max_connections, .{
                .host = cfg.postgres.host,
                .port = cfg.postgres.port,
                .user = cfg.postgres.user,
                .database = cfg.postgres.database,
                .password = password,
                .pool_size = cfg.postgres.pool_size_per_worker,
                .allow_cleartext_password = cfg.postgres.allow_cleartext_password,
                .statement_timeout_ms = cfg.postgres.statement_timeout_ms,
                .sslmode = cfg.postgres.sslmode,
            }) catch |err| {
                std.log.warn("postgres: client init failed: {}; client disabled", .{err});
                allocator.destroy(pgc);
                break :pg_blk;
            };
            // The provider address is stable (it lives in self), so the
            // client may keep the pointer for the server's lifetime.
            if (self.pg_tls_provider) |*p| pgc.installTls(p);
            self.pg_client = pgc;
            std.log.info("postgres: client configured for {s}:{d} (pool {d}, sslmode={s})", .{
                cfg.postgres.host,                 cfg.postgres.port,
                cfg.postgres.pool_size_per_worker, @tagName(cfg.postgres.sslmode),
            });
        }

        // Skip getpeername on accept when nothing needs the peer IP.
        self.needs_peer_ip = self.proxy != null or
            app_router.middleware_chain.post.len > 0;
    }

    pub fn deinit(self: *Server) void {
        // QUIC handler must be freed before its TLS provider
        if (self.quic) |*q| q.deinit();
        if (self.tcp_tls_provider) |*p| p.deinit();
        if (self.tls_provider) |*p| p.deinit();
        if (self.proxy) |p| {
            p.deinit();
            self.allocator.destroy(p);
        }
        // Free WASM filter pools after the proxy that referenced them.
        self.freeWasmManager(self.wasm_manager);
        self.wasm_manager = null;
        // Tear down the control-socket transport (unregisters its fd, fails any
        // in-flight parks closed) before the io runtime goes away.
        self.teardownWasmControl();
        // Reclaim any owned park snapshots (live parks + deferred-free buffers).
        if (build_options.enable_wasm) self.wasm_host_calls.deinit();
        if (self.spare_fd) |fd| clock.closeFd(fd);
        // Close every bound listener. listener_fd aliases listeners_buf[0].fd
        // (multi-listener model), so we drive closing off the array only and do
        // NOT close listener_fd separately to avoid a double-close. The drain
        // path may have already closed and zeroed listeners_count, in which case
        // this loop runs zero times.
        var li: usize = 0;
        while (li < self.listeners_count) : (li += 1) clock.closeFd(self.listeners_buf[li].fd);
        // Fallback for paths that set listener_fd without populating the array
        // (e.g. early error teardown before runLoop binds the listeners).
        if (self.listeners_count == 0) {
            if (self.listener_fd) |fd| clock.closeFd(fd);
        }
        if (self.udp_fd) |fd| clock.closeFd(fd);
        if (self.static_root_fd) |fd| clock.closeFd(fd);
        if (self.static_cache) |*cache| {
            var it = cache.iterator();
            while (it.next()) |kv| {
                self.allocator.free(kv.key_ptr.*);
                self.allocator.free(kv.value_ptr.body);
            }
            cache.deinit();
        }
        if (self.admin_listener_fd) |fd| clock.closeFd(fd);
        if (self.otel) |otel_ptr| self.allocator.destroy(otel_ptr);
        if (self.pending_reload.swap(null, .acq_rel)) |pr| {
            var loaded = pr.loaded;
            loaded.deinit();
            std.heap.page_allocator.destroy(pr);
        }
        if (self.reload_arena) |*a| a.deinit();
        if (self.pg_client) |pgc| {
            pgc.deinit(&self.io);
            self.allocator.destroy(pgc);
        }
        // After pg_client deinit: slot SSL sessions must be freed before
        // their SSL_CTX.
        if (self.pg_tls_provider) |*p| p.deinit();
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

    /// Build a per-worker WASM filter manager from `specs`, attaching its pools
    /// to `routes` (the proxy route table, mutated in place). Returns the opaque
    /// manager pointer, or null if wasm is disabled / no specs. A spec that
    /// fails to load is logged and skipped (its route then runs unfiltered).
    // pub so the admin reload path (admin.zig writeConfigAndReload) can rebuild
    // the manager too; both reload paths must rebuild it or a route edit leaves
    // filters detached (fail-open). Keep the two call sites in sync.
    pub fn buildWasmManager(
        self: *Server,
        specs: []const config_file_mod.WasmFilterConfig,
        routes: []upstream_mod.ProxyRoute,
    ) ?*anyopaque {
        if (!build_options.enable_wasm) return null;
        if (specs.len == 0) return null;
        const mgr = self.allocator.create(wasm_manager_mod.Manager) catch return null;
        mgr.* = wasm_manager_mod.Manager.init(self.allocator);
        for (specs, 0..) |w, wi| {
            // S4: one filter per route. A duplicate `match` would attach a second
            // pool over the first (or, if the second fails to load, be silently
            // skipped while the first still serves -- a fail-open). Warn; only the
            // first spec for a match takes effect.
            var dup = false;
            for (specs[0..wi]) |prev| {
                if (std.mem.eql(u8, prev.match, w.match)) {
                    dup = true;
                    break;
                }
            }
            if (dup) {
                std.log.warn("wasm filter '{s}': duplicate match (a route binds one filter); ignoring this spec, the first wins", .{w.match});
                continue;
            }
            var one = [_]wasm_manager_mod.Spec{.{
                .match = w.match,
                .module_path = w.module_path,
                .instances = w.instances,
                .fuel = w.fuel,
                .response_fail_closed = w.response_fail_closed,
            }};
            const n = mgr.loadAndAttachProxy(routes, &one) catch {
                // S2: do NOT continue with the route unfiltered (fail-open). Mark
                // every route this spec targets as wasm_required so it fails
                // CLOSED (503) at request time instead of forwarding past a
                // security filter that never loaded.
                std.log.warn("wasm filter '{s}': failed to load module '{s}'; routes matching '{s}' will FAIL CLOSED (503), not run unfiltered", .{ w.match, w.module_path, w.match });
                for (routes) |*r| {
                    if (std.mem.eql(u8, r.path_prefix, w.match)) r.wasm_required = true;
                }
                continue;
            };
            if (n == 0) {
                // O3: the match resolved to NO proxy route, so the filter is loaded
                // but never runs. This is almost always a config typo; warn loudly
                // rather than the silent info line it used to be.
                std.log.warn("wasm filter '{s}' (module '{s}') matched NO route (no proxy route has path_prefix '{s}'); it will never run", .{ w.match, w.module_path, w.match });
            } else {
                std.log.info("wasm filter '{s}' -> {s} ({d} route(s), {d} instances)", .{ w.match, w.module_path, n, w.instances });
            }
        }
        return @ptrCast(mgr);
    }

    /// WASM edge-function observability snapshot for the admin API / metrics.
    /// Build-flag-aware: all-zero / false when wasm is compiled out.
    pub const WasmObservability = struct {
        park_active: usize = 0,
        park_capacity: usize = 0,
        pool_instances: usize = 0,
        pool_pinned: usize = 0,
        control_configured: bool = false,
        control_ready: bool = false,
        tenants_active: usize = 0,
        tenant_hits: u64 = 0,
        tenant_misses: u64 = 0,
        tenant_evictions: u64 = 0,
    };

    pub fn wasmObservability(self: *Server) WasmObservability {
        if (!build_options.enable_wasm) return .{};
        var o = WasmObservability{
            .park_capacity = wasm_host_call_mod.Table.CAP,
            .park_active = self.wasm_host_calls.activeCount(),
            .control_configured = self.wasm_control_socket_path.len > 0,
            .tenants_active = self.tenant_registry.count(),
            .tenant_hits = self.tenant_registry.hits,
            .tenant_misses = self.tenant_registry.misses,
            .tenant_evictions = self.tenant_registry.evictions,
        };
        if (self.wasm_manager) |p| {
            const mgr: *wasm_manager_mod.Manager = @ptrCast(@alignCast(p));
            const t = mgr.instanceTotals();
            o.pool_instances = t.total;
            o.pool_pinned = t.pinned;
        }
        if (self.wasmControlClient()) |cc| o.control_ready = cc.isReady();
        return o;
    }

    pub fn freeWasmManager(self: *Server, ptr: ?*anyopaque) void {
        if (!build_options.enable_wasm) return;
        if (ptr) |p| {
            const mgr: *wasm_manager_mod.Manager = @ptrCast(@alignCast(p));
            mgr.deinit();
            self.allocator.destroy(mgr);
        }
    }

    /// Fail-closed completions drained from the park table by a config reload.
    /// Two-step by design: cancel BEFORE the old manager is freed (the pinned
    /// instances live in its pools), deliver AFTER the new manager is in place
    /// (delivery re-drives connection I/O, and a pipelined request dispatched
    /// during that re-drive may park again; it must land in the NEW pools).
    pub const WasmDrainedParks = if (build_options.enable_wasm) struct {
        completions: [wasm_host_call_mod.Table.CAP]wasm_host_call_mod.Completion = undefined,
        count: usize = 0,
    } else struct {};

    /// Reload step 1: cancel every live wasm park, releasing each pinned
    /// instance back to its (old) pool while that memory is still valid. The
    /// returned completions reference only slot-owned snapshots, never the
    /// instances, so they survive freeing the old manager.
    pub fn wasmCancelAllParks(self: *Server) WasmDrainedParks {
        var drained = WasmDrainedParks{};
        if (build_options.enable_wasm) {
            drained.count = self.wasm_host_calls.cancelAll(&drained.completions);
            if (drained.count > 0) {
                std.log.warn("config reload: cancelling {d} in-flight wasm park(s) fail-closed", .{drained.count});
            }
        }
        return drained;
    }

    /// Reload step 2: answer the cancelled parks (fail-closed 500s) through
    /// dispatch's park-resume delivery, which also restarts each connection's
    /// I/O. The slot-owned snapshots are reclaimed lazily on slot reuse.
    pub fn wasmDeliverDrainedParks(self: *Server, drained: *const WasmDrainedParks) void {
        if (build_options.enable_wasm) {
            for (drained.completions[0..drained.count]) |c| dispatch.wasmResume(self, c);
        }
    }

    /// Is a WASM filter parked on this connection (generation-checked)? Used by
    /// handleParkSentinel to set `.wasm_parked`.
    pub fn wasmHasParkFor(self: *Server, conn_index: u32, conn_id: u64) bool {
        if (build_options.enable_wasm) {
            return self.wasm_host_calls.hasParkFor(conn_index, conn_id);
        }
        return false;
    }

    /// Release any WASM park bound to this connection (client disconnect). The
    /// pinned instance is returned to its pool; no response is served.
    pub fn wasmCancelForConn(self: *Server, conn_index: u32, conn_id: u64) void {
        if (build_options.enable_wasm) {
            _ = self.wasm_host_calls.cancelForConn(conn_index, conn_id);
        }
    }

    /// Is a WASM filter parked on this specific stream (generation-checked)? Used
    /// by the H2/H3 dispatch (E2) to confirm a park-sentinel response really
    /// registered a park before suspending the stream.
    pub fn wasmHasParkForStream(self: *Server, conn_index: u32, conn_id: u64, stream_id: u32) bool {
        if (build_options.enable_wasm) {
            return self.wasm_host_calls.hasParkForStream(conn_index, conn_id, stream_id);
        }
        return false;
    }

    /// Release a WASM park bound to a single multiplexed stream (RST_STREAM /
    /// QUIC stream reset). The pinned instance is returned to its pool; the
    /// connection's other parked streams are untouched. The per-stream
    /// counterpart to wasmCancelForConn, used by H2/H3 (E2).
    pub fn wasmCancelForStream(self: *Server, conn_index: u32, conn_id: u64, stream_id: u32) void {
        if (build_options.enable_wasm) {
            _ = self.wasm_host_calls.cancelForStream(conn_index, conn_id, stream_id);
        }
    }

    /// Transport start hook (set as WasmBinding.start_fn). Initiates the host
    /// call for a freshly parked filter. The real control-socket transport (C3)
    /// takes precedence: it writes the staged command line to the sandbox's
    /// control socket and completes the park when the framed reply arrives. With
    /// no control client configured, the mock transport queues the token for
    /// completion on the next tick. `req_bytes` is the filter's staged outbound
    /// command (must NOT be __-prefixed: Nether reserves __*__ for host control
    /// commands and forwards unknown lines to the guest verbatim).
    /// WasmBinding.start_fn adapter: `ctx` is the Server. The canonical thunk
    /// for park sites outside dispatch.zig (the protocol files keep local
    /// copies for now; consolidation is a tracked cleanup).
    pub fn wasmStartThunk(ctx: *anyopaque, token: u32, req_bytes: []const u8) void {
        const self: *Server = @ptrCast(@alignCast(ctx));
        self.wasmStartHostCall(token, req_bytes);
    }

    pub fn wasmStartHostCall(self: *Server, token: u32, req_bytes: []const u8) void {
        if (build_options.enable_wasm) {
            if (self.wasm_control) |p| {
                const cc: *wasm_control_mod.ControlClient = @ptrCast(@alignCast(p));
                cc.startCall(&self.io, token, req_bytes);
                return;
            }
            if (self.wasm_mock_enabled and self.wasm_mock_count < self.wasm_mock_pending.len) {
                self.wasm_mock_pending[self.wasm_mock_count] = token;
                self.wasm_mock_count += 1;
            }
        }
    }

    /// Typed accessor for the control client (null when wasm is off or no path is
    /// configured). Keeps the opaque field's casts in one place. The return type
    /// is comptime-conditional so this signature compiles when wasm is disabled
    /// (the body's wasm references sit past the pruned early return).
    pub fn wasmControlClient(self: *Server) ?*(if (build_options.enable_wasm) wasm_control_mod.ControlClient else anyopaque) {
        if (!build_options.enable_wasm) return null;
        const p = self.wasm_control orelse return null;
        return @ptrCast(@alignCast(p));
    }

    /// Build the control-socket client for this worker if a path is configured.
    /// Called once at run() start (per worker, after fork), before the loop.
    /// Idempotent: tears down any existing client first.
    pub fn setupWasmControl(self: *Server) void {
        if (!build_options.enable_wasm) return;
        self.teardownWasmControl();
        if (self.wasm_control_socket_path.len == 0) return;
        const cc = self.allocator.create(wasm_control_mod.ControlClient) catch return;
        cc.* = wasm_control_mod.ControlClient.init(
            self.wasm_control_socket_path,
            wasm_control_mod.DEFAULT_SLOT,
        );
        // Keep the transport's per-command budget aligned with the park deadline so
        // the socket does not out-live the park (lets a test set a sub-second one).
        cc.command_timeout_ms = self.wasm_host_call_deadline_ms;
        self.wasm_control = @ptrCast(cc);
        std.log.info("wasm control transport -> {s} (slot {d})", .{ self.wasm_control_socket_path, wasm_control_mod.DEFAULT_SLOT });
    }

    fn teardownWasmControl(self: *Server) void {
        if (!build_options.enable_wasm) return;
        if (self.wasmControlClient()) |cc| {
            cc.deinit(&self.io);
            self.allocator.destroy(cc);
            self.wasm_control = null;
        }
    }

    /// Build the WASM filter pools for this worker and attach them to the live
    /// proxy. Called once at run() start (per worker, after fork). Idempotent:
    /// tears down any existing manager first.
    pub fn setupWasmFilters(self: *Server) void {
        if (!build_options.enable_wasm) return;
        const proxy = self.proxy orelse return;
        self.freeWasmManager(self.wasm_manager);
        self.wasm_manager = self.buildWasmManager(
            self.wasm_filter_specs,
            @constCast(proxy.config.routes),
        );
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

        if (loaded.routes.len > 0 and (loaded.upstreams.len > 0 or upstream_mod.anyTenantRoute(loaded.routes))) {
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

            // Cancel in-flight wasm parks BEFORE any old state is freed: the
            // pinned instances live in the old manager's pools, and parked
            // requests hold across event-loop iterations, so "never
            // mid-request" does not cover them. Their fail-closed responses
            // are delivered after the swap (below), so any pipelined request
            // re-driven by that delivery parks against the NEW pools.
            const drained_parks = self.wasmCancelAllParks();

            const old_proxy = self.proxy;
            const old_arena = self.reload_arena;
            const old_wasm = self.wasm_manager;
            self.proxy = proxy_ptr;
            // Same rule as Server.run: the health thread starts only once the
            // proxy sits at its final heap address (init must not start it).
            proxy_ptr.health_manager.startThread();
            self.reload_arena = loaded.arena;

            // Rebuild the WASM filter pools for the new route table, then free
            // the old manager AFTER the old proxy is gone (its routes referenced
            // the old pools). Parked filters were cancelled above; nothing else
            // holds an old instance (applyPendingReload runs in the event loop,
            // never mid-request).
            self.wasm_manager = self.buildWasmManager(loaded.wasm_filters, @constCast(loaded.routes));

            if (old_proxy) |old| {
                old.deinit();
                self.allocator.destroy(old);
            }
            if (old_arena) |*oa| oa.deinit();
            self.freeWasmManager(old_wasm);
            self.needs_peer_ip = true;
            self.wasmDeliverDrainedParks(&drained_parks);

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
                // Same park drain as the rebuild branch: release pinned
                // instances before their pools are freed, answer after.
                const drained_parks = self.wasmCancelAllParks();
                if (self.proxy) |old| {
                    old.deinit();
                    self.allocator.destroy(old);
                    self.proxy = null;
                }
                // Proxy removed: tear down its filter pools too.
                self.freeWasmManager(self.wasm_manager);
                self.wasm_manager = null;
                if (self.reload_arena) |*old_arena| old_arena.deinit();
                self.reload_arena = loaded.arena;
                self.needs_peer_ip = self.app_router.middleware_chain.post.len > 0;
                self.wasmDeliverDrainedParks(&drained_parks);
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
        // Build this worker's WASM filter pools and attach them to the proxy
        // before entering the event loop (per-worker, after fork).
        self.setupWasmFilters();
        // Start the upstream health-check thread at the proxy's FINAL address,
        // in the process that will consume its results. Proxy.init must not
        // start it (the init-local is returned by value; the thread would pin
        // a dead stack frame), and pre-fork threads do not survive into
        // workers - a fork-inherited handle would be joined against a thread
        // that does not exist, and fork-frozen health states would never
        // update. Started here, each worker probes and joins its own thread.
        if (self.proxy) |p| p.health_manager.startThread();
        return dispatch.runLoop(self, run_for_ms);
    }

    pub fn runFor(self: *Server, run_for_ms: u64) !void {
        try self.run(run_for_ms);
    }

    /// Thin wrappers around `server/dispatch.zig`. The dispatch
    /// body lives in that module; these methods remain on
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

    pub fn internalErrorResponse() response_mod.Response {
        return .{
            .status = 500,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Internal Server Error\n" },
        };
    }

    pub fn notImplementedResponse() response_mod.Response {
        return .{
            .status = 501,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Not Implemented\n" },
        };
    }

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

    /// Connection-specific headers that are malformed in HTTP/3 (RFC 9114
    /// §4.2). `te` is special-cased by the caller (allowed with "trailers").
    fn isH3ForbiddenHeader(name: []const u8) bool {
        const forbidden = [_][]const u8{ "connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection", "te" };
        for (forbidden) |f| {
            if (std.ascii.eqlIgnoreCase(name, f)) return true;
        }
        return false;
    }

    pub fn buildHttp3RequestView(req: http3.RequestReadyEvent, headers_out: []request.Header) ?request.RequestView {
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var authority: ?[]const u8 = null;
        var header_count: usize = 0;
        var saw_host = false;
        var saw_regular = false;

        for (req.headers) |hdr| {
            if (hdr.name.len == 0) return null;
            if (hdr.name[0] == ':') {
                // RFC 9114 §4.3.1: all pseudo-headers precede regular fields.
                if (saw_regular) return null;
                if (std.mem.eql(u8, hdr.name, ":method")) {
                    if (method != null) return null; // duplicate
                    method = hdr.value;
                } else if (std.mem.eql(u8, hdr.name, ":path")) {
                    if (path != null) return null;
                    path = hdr.value;
                } else if (std.mem.eql(u8, hdr.name, ":authority")) {
                    if (authority != null) return null;
                    authority = hdr.value;
                } else if (std.mem.eql(u8, hdr.name, ":scheme")) {
                    // accepted, not forwarded
                } else {
                    return null; // unknown/invalid request pseudo-header
                }
            } else {
                // RFC 9114 §4.2: field names must be lowercase, and
                // connection-specific headers are malformed in HTTP/3.
                for (hdr.name) |c| {
                    if (c >= 'A' and c <= 'Z') return null;
                }
                if (isH3ForbiddenHeader(hdr.name)) {
                    // TE is allowed only with the value "trailers".
                    if (!std.ascii.eqlIgnoreCase(hdr.name, "te") or
                        !std.ascii.eqlIgnoreCase(std.mem.trim(u8, hdr.value, " \t"), "trailers"))
                    {
                        return null;
                    }
                }
                saw_regular = true;
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

    /// Open a file relative to `static_root_fd`, rejecting symlinks in ALL
    /// path components (not just the leaf). Walks the path segment-by-segment
    /// with O_NOFOLLOW|O_DIRECTORY, then opens the leaf with O_NOFOLLOW.
    /// Prevents intermediate-symlink escapes from the static root.
    pub fn safeOpenStatic(root_fd: std.posix.fd_t, path: []const u8) ?std.posix.fd_t {
        if (path.len == 0 or path.len >= 4096) return null;
        var buf: [4096]u8 = undefined;
        @memcpy(buf[0..path.len], path);

        var dir_fd = root_fd;
        var need_close_dir = false;
        var pos: usize = 0;

        while (pos < path.len) {
            var end = pos;
            while (end < path.len and buf[end] != '/') end += 1;
            if (end == pos) {
                pos = end + 1;
                continue;
            }

            buf[end] = 0;
            const seg: [*:0]const u8 = @ptrCast(&buf[pos]);

            if (end < path.len) {
                var o: std.posix.O = .{ .DIRECTORY = true };
                if (@hasField(std.posix.O, "NOFOLLOW")) o.NOFOLLOW = true;
                if (@hasField(std.posix.O, "CLOEXEC")) o.CLOEXEC = true;
                const next = std.posix.openatZ(dir_fd, seg, o, 0) catch {
                    if (need_close_dir) clock.closeFd(dir_fd);
                    return null;
                };
                if (need_close_dir) clock.closeFd(dir_fd);
                dir_fd = next;
                need_close_dir = true;
            } else {
                var o: std.posix.O = .{};
                if (@hasField(std.posix.O, "NOFOLLOW")) o.NOFOLLOW = true;
                if (@hasField(std.posix.O, "CLOEXEC")) o.CLOEXEC = true;
                const file_fd = std.posix.openatZ(dir_fd, seg, o, 0) catch {
                    if (need_close_dir) clock.closeFd(dir_fd);
                    return null;
                };
                if (need_close_dir) clock.closeFd(dir_fd);
                return file_fd;
            }
            pos = end + 1;
        }

        if (need_close_dir) clock.closeFd(dir_fd);
        return null;
    }

    /// Encoding of a static file actually served — `identity` for the raw
    /// file, or a precompressed sibling the client accepts.
    pub const StaticEncoding = enum {
        identity,
        gzip,
        br,

        /// The `Content-Encoding` token for this encoding ("" for identity).
        pub fn token(self: StaticEncoding) []const u8 {
            return switch (self) {
                .identity => "",
                .gzip => "gzip",
                .br => "br",
            };
        }
    };

    pub const StaticVariant = struct {
        fd: std.posix.fd_t,
        encoding: StaticEncoding,
    };

    /// True if `token` (e.g. "br", "gzip") appears in an Accept-Encoding
    /// header value with a non-zero qvalue. Case-insensitive; tolerates
    /// q-params. Mirrors the q=0 handling in middleware/compress.zig.
    fn acceptsEncoding(header_value: []const u8, token: []const u8) bool {
        var it = std.mem.splitScalar(u8, header_value, ',');
        while (it.next()) |raw| {
            const trimmed = std.mem.trim(u8, raw, " \t");
            const semi = std.mem.indexOfScalar(u8, trimmed, ';');
            const name = if (semi) |s| std.mem.trim(u8, trimmed[0..s], " \t") else trimmed;
            if (!std.ascii.eqlIgnoreCase(name, token)) continue;
            if (semi) |s| {
                const params = std.mem.trim(u8, trimmed[s + 1 ..], " \t");
                if (std.ascii.startsWithIgnoreCase(params, "q=")) {
                    const qval = std.mem.trim(u8, params[2..], " \t");
                    if (std.mem.eql(u8, qval, "0") or std.mem.eql(u8, qval, "0.0") or
                        std.mem.eql(u8, qval, "0.00") or std.mem.eql(u8, qval, "0.000")) return false;
                }
            }
            return true;
        }
        return false;
    }

    /// Resolve a static file to the best precompressed sibling the client
    /// accepts: tries `<path>.br` then `<path>.gz` (when the matching token
    /// is present and not q=0 in `accept_encoding`), falling back to the
    /// identity file. Returns the open fd + which encoding it is, or null if
    /// nothing opened. The caller derives Content-Type from the ORIGINAL
    /// `file_path`, never the `.br`/`.gz` suffix.
    pub fn resolveStaticVariant(root_fd: std.posix.fd_t, file_path: []const u8, accept_encoding: []const u8) ?StaticVariant {
        // Need room for a 3-byte ".br"/".gz" suffix within safeOpenStatic's cap.
        if (file_path.len > 0 and file_path.len + 3 < 4096) {
            var buf: [4096]u8 = undefined;
            @memcpy(buf[0..file_path.len], file_path);
            if (acceptsEncoding(accept_encoding, "br")) {
                @memcpy(buf[file_path.len..][0..3], ".br");
                if (safeOpenStatic(root_fd, buf[0 .. file_path.len + 3])) |fd| {
                    return .{ .fd = fd, .encoding = .br };
                }
            }
            if (acceptsEncoding(accept_encoding, "gzip")) {
                @memcpy(buf[file_path.len..][0..3], ".gz");
                if (safeOpenStatic(root_fd, buf[0 .. file_path.len + 3])) |fd| {
                    return .{ .fd = fd, .encoding = .gzip };
                }
            }
        }
        if (safeOpenStatic(root_fd, file_path)) |fd| {
            return .{ .fd = fd, .encoding = .identity };
        }
        return null;
    }

    /// An in-memory cached static file: the owned body bytes plus the
    /// metadata needed to re-emit a response. content_type points at a
    /// guessContentType string literal (static, not owned).
    pub const StaticCacheEntry = struct {
        body: []u8,
        content_type: []const u8,
        encoding: StaticEncoding,
    };

    /// Total cached static body bytes never exceed this (per worker).
    /// Once the cap is hit, further files are served uncached rather
    /// than evicting existing entries.
    const STATIC_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;

    /// The Accept-Encoding facts that change which file gets served. Cached
    /// entries are keyed by this so every distinct negotiation outcome is
    /// stored separately and correctly — a client is only ever handed an
    /// encoding it actually accepts.
    const AcceptClass = enum(u8) { none = 0, gzip = 1, br = 2, both = 3 };

    fn classifyAccept(accept_encoding: []const u8) AcceptClass {
        const br = acceptsEncoding(accept_encoding, "br");
        const gz = acceptsEncoding(accept_encoding, "gzip");
        if (br and gz) return .both;
        if (br) return .br;
        if (gz) return .gzip;
        return .none;
    }

    /// Cache-aware static lookup. Returns a cached entry to serve, reading
    /// and storing the resolved file on first miss. Returns null when the
    /// cache is off, the file is missing, or it's too large to cache — in
    /// which case the caller falls back to the normal open+serve path.
    /// `content_type` is supplied by the caller (derived from file_path).
    pub fn staticCacheGetOrLoad(
        self: *Server,
        file_path: []const u8,
        content_type: []const u8,
        accept_encoding: []const u8,
    ) ?*const StaticCacheEntry {
        const cache = if (self.static_cache) |*c| c else return null;

        // Key = "<path>\x00<class>". The class byte captures (accepts_br,
        // accepts_gzip) so the lookup key always matches the store key even
        // when a sibling is absent and resolution falls back.
        var key_buf: [4098]u8 = undefined;
        if (file_path.len + 2 > key_buf.len) return null;
        @memcpy(key_buf[0..file_path.len], file_path);
        key_buf[file_path.len] = 0;
        key_buf[file_path.len + 1] = @intFromEnum(classifyAccept(accept_encoding));
        const key = key_buf[0 .. file_path.len + 2];

        if (cache.getPtr(key)) |entry| return entry;

        // Miss: resolve the variant, read it fully into an owned buffer.
        const root_fd = self.static_root_fd orelse return null;
        const variant = resolveStaticVariant(root_fd, file_path, accept_encoding) orelse return null;
        defer clock.closeFd(variant.fd);

        const end_pos = std.c.lseek(variant.fd, 0, std.posix.SEEK.END);
        if (end_pos < 0) return null;
        _ = std.c.lseek(variant.fd, 0, std.posix.SEEK.SET);
        const size: usize = @intCast(end_pos);

        // Too large to cache → tell the caller to serve it uncached.
        if (self.static_cache_bytes + size > STATIC_CACHE_MAX_BYTES) return null;

        const body = self.allocator.alloc(u8, size) catch return null;
        var off: usize = 0;
        while (off < size) {
            const n = std.c.pread(variant.fd, body.ptr + off, size - off, @intCast(off));
            if (n < 0) {
                switch (std.posix.errno(n)) {
                    .INTR => continue,
                    else => {
                        self.allocator.free(body);
                        return null;
                    },
                }
            }
            if (n == 0) break;
            off += @intCast(n);
        }
        if (off != size) {
            self.allocator.free(body);
            return null;
        }

        const owned_key = self.allocator.dupe(u8, key) catch {
            self.allocator.free(body);
            return null;
        };
        cache.put(owned_key, .{ .body = body, .content_type = content_type, .encoding = variant.encoding }) catch {
            self.allocator.free(owned_key);
            self.allocator.free(body);
            return null;
        };
        self.static_cache_bytes += size;
        return cache.getPtr(owned_key);
    }

    /// Build a Response that serves a cached static entry. The caller owns
    /// `hdrs` (stack storage); the returned Response borrows it and the
    /// entry body, so both must outlive the response-encoding call. Date,
    /// Content-Length, and HEAD handling come from the normal response path.
    pub fn staticCacheResponse(entry: *const StaticCacheEntry, hdrs: *[3]response_mod.Header) response_mod.Response {
        var nh: usize = 0;
        hdrs[nh] = .{ .name = "Content-Type", .value = entry.content_type };
        nh += 1;
        if (entry.encoding != .identity) {
            hdrs[nh] = .{ .name = "Content-Encoding", .value = entry.encoding.token() };
            nh += 1;
            hdrs[nh] = .{ .name = "Vary", .value = "Accept-Encoding" };
            nh += 1;
        }
        return .{ .status = 200, .headers = hdrs[0..nh], .body = .{ .bytes = entry.body } };
    }

    pub fn closeConnection(self: *Server, conn: *connection.Connection) void {
        // Drop any PG park before the slot can be recycled: the
        // in-flight op runs to completion and its outcome is discarded
        // (generation-checked), so the continuation can never write
        // into this slot's next occupant. O(1) when not parked.
        if (self.pg_client) |pgc| pgc.cancelForConn(conn.index, conn.id);
        // Same for a parked WASM filter: release the pinned instance so it does
        // not leak when the client disconnects mid-park. O(1) when not parked.
        self.wasmCancelForConn(conn.index, conn.id);
        if (conn.is_tunnel) {
            if (conn.tunnel_peer_index) |pi| {
                conn.tunnel_peer_index = null;
                conn.is_tunnel = false;
                if (self.io.getConnection(pi)) |peer| {
                    if (peer.is_tunnel and peer.tunnel_peer_id == conn.id) {
                        peer.tunnel_peer_index = null;
                        peer.is_tunnel = false;
                        peer.close_after_write = true;
                    }
                }
            }
        }
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
        if (conn.pending_body_owned) |owned| {
            self.allocator.free(owned);
            conn.pending_body_owned = null;
            conn.pending_body = &[_]u8{};
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
            for (resps) |*r| r.cleanup(&self.io, self.allocator);
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
        // Release settle-park held response buffer
        if (conn.x402_held_buf) |held_buf| {
            self.io.releaseBuffer(held_buf);
            conn.x402_held_buf = null;
        }
        // Clean up pending file descriptor and body reference
        conn.cleanupPendingFile();
        conn.pending_body = &[_]u8{};
        self.io.releaseConnection(conn);
    }
};

test "S2: a wasm filter whose module fails to load fails its routes closed" {
    if (!build_options.enable_wasm) return;
    // buildWasmManager only reads self.allocator; an otherwise-undefined Server
    // is sufficient to exercise the load-failure marking in isolation.
    var srv: Server = undefined;
    srv.allocator = std.testing.allocator;
    var routes = [_]upstream_mod.ProxyRoute{
        .{ .path_prefix = "/guarded", .upstream = "u" },
        .{ .path_prefix = "/open", .upstream = "u" },
    };
    const specs = [_]config_file_mod.WasmFilterConfig{
        .{ .match = "/guarded", .module_path = "/nonexistent/does-not-exist.wasm" },
    };
    const mgr = srv.buildWasmManager(&specs, &routes);
    defer srv.freeWasmManager(mgr);
    // The guarded route must fail CLOSED (wasm_required), not run unfiltered.
    try std.testing.expect(routes[0].wasm_required);
    try std.testing.expect(routes[0].wasm_pool == null);
    // An unrelated route is untouched.
    try std.testing.expect(!routes[1].wasm_required);
}

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

    const server = try allocator.create(Server);
    defer allocator.destroy(server);
    try server.initInPlace(allocator, cfg, app_router);
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

    try http1_mod.queueResponse(server, conn, result.resp);
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

    const server = try allocator.create(Server);
    defer allocator.destroy(server);
    try server.initInPlace(allocator, cfg, app_router);
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

    try http2_mod.queueHttp2Response(server, conn, 1, result.resp, false);
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

    const server = try allocator.create(Server);
    defer allocator.destroy(server);
    try server.initInPlace(allocator, cfg, app_router);
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

    try http1_mod.queueResponse(server, conn, result.resp);
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

    const server = try allocator.create(Server);
    defer allocator.destroy(server);
    try server.initInPlace(allocator, cfg, app_router);
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

    try http2_mod.queueHttp2Response(server, conn, 1, result.resp, false);
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
    const server = try allocator.create(Server);
    defer allocator.destroy(server);
    try server.initInPlace(allocator, cfg, app_router);
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

    try http1_mod.queueResponse(server, conn, resp);
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
    const server = try allocator.create(Server);
    defer allocator.destroy(server);
    try server.initInPlace(allocator, cfg, app_router);
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

    try http1_mod.queueResponse(server, conn, resp);
    const bytes = try write_queue.drainWriteQueue(&server.io, conn, allocator);
    defer allocator.free(bytes);

    // Verify structural correctness (Date header is dynamic so check components)
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Date: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhello"));
}

test "buildHttp3RequestView validates pseudo-headers and field names" {
    var out: [16]request.Header = undefined;

    // Valid request.
    {
        const hdrs = [_]http3.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = "accept", .value = "*/*" },
        };
        const view = Server.buildHttp3RequestView(.{ .stream_id = 0, .headers = &hdrs, .body = "" }, &out);
        try std.testing.expect(view != null);
    }
    // Uppercase field name → malformed.
    {
        const hdrs = [_]http3.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/" },
            .{ .name = "Accept", .value = "*/*" },
        };
        try std.testing.expect(Server.buildHttp3RequestView(.{ .stream_id = 0, .headers = &hdrs, .body = "" }, &out) == null);
    }
    // Connection-specific header → malformed.
    {
        const hdrs = [_]http3.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/" },
            .{ .name = "connection", .value = "keep-alive" },
        };
        try std.testing.expect(Server.buildHttp3RequestView(.{ .stream_id = 0, .headers = &hdrs, .body = "" }, &out) == null);
    }
    // Duplicate :method → malformed.
    {
        const hdrs = [_]http3.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/" },
        };
        try std.testing.expect(Server.buildHttp3RequestView(.{ .stream_id = 0, .headers = &hdrs, .body = "" }, &out) == null);
    }
    // Pseudo-header after a regular field → malformed.
    {
        const hdrs = [_]http3.Header{
            .{ .name = "accept", .value = "*/*" },
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/" },
        };
        try std.testing.expect(Server.buildHttp3RequestView(.{ .stream_id = 0, .headers = &hdrs, .body = "" }, &out) == null);
    }
}

// Benchmark / TechEmpower handlers and the `/json` dataset loader live in
// `src/benchmark_routes.zig`. They are not part of the library API or this
// constructor; the bundled `swerver` CLI (`src/main.zig`) imports that file
// directly and registers them explicitly.
