//! Config-driven bootstrap: the one blessed path from "config + router" to a
//! running server, shared by the swerver binary (src/main.zig) and embedders.
//!
//! Before this module, every entry point (the binary, the gateway example,
//! benchmark apps) hand-rolled the same ~150 lines: load the config (file or
//! URL with cache fallback), build the reverse proxy from upstreams/routes,
//! wire the x402 facilitator, thread the WASM filter specs and control
//! socket, then pick multi-process Master vs single-process ServerBuilder.
//! Each copy drifted, and lifecycle wiring is exactly where bugs hide (a
//! stack-local Proxy handed to a Server that destroys it on the heap path;
//! the health thread started at the wrong address). `run` owns the whole
//! lifecycle in one place with the correct ownership:
//!
//!     const std = @import("std");
//!     const swerver = @import("swerver");
//!
//!     pub fn main(init: std.process.Init) !void {
//!         var app_router = swerver.router.Router.init(.{});
//!         try app_router.get("/hello", hello);
//!         try swerver.bootstrap.run(init.gpa, .{
//!             .config_path = "config.json",
//!             .router = app_router,
//!         });
//!     }
//!
//! The swerver binary itself is `parseArgs` + `optionsFromArgs` + `run`.

const std = @import("std");

const config_mod = @import("config.zig");
const config_file_mod = @import("config_file.zig");
const config_fetch = @import("config_fetch.zig");
const router_mod = @import("router/router.zig");
const x402 = @import("middleware/x402.zig");
const security = @import("middleware/security.zig");
const proxy_mod = @import("proxy/proxy.zig");
const upstream_mod = @import("proxy/upstream.zig");
const Master = @import("master.zig").Master;
const ServerBuilder = @import("server_builder.zig").ServerBuilder;

/// Everything `run` needs. Field-for-field this mirrors the swerver CLI; an
/// embedder usually sets only `config_path` and `router`.
pub const Options = struct {
    /// JSON config file path. Mutually exclusive with `config_url`.
    config_path: ?[]const u8 = null,
    /// Remote config URL (see config_fetch). Mutually exclusive with
    /// `config_path`. `SWERVER_CONFIG_TOKEN` / `SWERVER_CONFIG_HEADERS` env
    /// vars apply, as on the CLI.
    config_url: ?[]const u8 = null,
    /// In-memory JSON config bytes (embedders, tests). Mutually exclusive
    /// with `config_path` and `config_url`; no reload source is wired.
    config_json: ?[]const u8 = null,
    /// Cache file for `config_url`: written on success, used as fallback
    /// when the fetch fails.
    config_cache: ?[]const u8 = null,
    /// Extra headers for the config URL fetch ("Name: value" lines).
    config_headers: []const []const u8 = &.{},
    /// Application router. When null, a proxy-only router is built from the
    /// config's x402 settings. When provided and the config declares an
    /// x402 facilitator, it is wired in unless the router already has one.
    router: ?router_mod.Router = null,
    /// Overrides applied on top of the loaded config (CLI flags).
    static_root: []const u8 = "",
    workers_override: ?u16 = null,
    cert_path: ?[:0]const u8 = null,
    key_path: ?[:0]const u8 = null,
    /// Run for a bounded time then shut down (tests, smoke checks).
    run_for_ms: ?u64 = null,
};

/// Load config, assemble router/proxy/server, and serve until shutdown
/// (or `run_for_ms`). Blocks for the server's lifetime and owns the config
/// arena, the proxy allocation, and the x402 demo-payment allocations for
/// exactly that long.
pub fn run(allocator: std.mem.Allocator, opts: Options) !void {
    {
        var sources: u8 = 0;
        if (opts.config_path != null) sources += 1;
        if (opts.config_url != null) sources += 1;
        if (opts.config_json != null) sources += 1;
        // config_path, config_url, and config_json are mutually exclusive.
        if (sources > 1) return error.ConflictingConfigSources;
    }

    var loaded_config: ?config_file_mod.LoadedConfig = null;
    defer if (loaded_config) |*lc| lc.deinit();

    var url_config: ?config_fetch.UrlConfig = null;

    var cfg: config_mod.ServerConfig = blk: {
        if (opts.config_url) |url| {
            var uc = config_fetch.parseConfigUrl(url) orelse {
                std.log.err("invalid config URL: {s}", .{url});
                return error.InvalidArgs;
            };
            if (std.c.getenv("SWERVER_CONFIG_TOKEN")) |t| uc.token = std.mem.sliceTo(t, 0);
            if (opts.config_cache) |cp| uc.cache_path = cp;
            for (opts.config_headers) |hdr| {
                _ = uc.addHeader(hdr);
            }
            if (std.c.getenv("SWERVER_CONFIG_HEADERS")) |env_hdrs| {
                const env_str: []const u8 = std.mem.sliceTo(env_hdrs, 0);
                var pos: usize = 0;
                while (pos < env_str.len) {
                    const sep = std.mem.indexOfAnyPos(u8, env_str, pos, ",\n") orelse env_str.len;
                    const hdr = std.mem.trim(u8, env_str[pos..sep], " \t\r");
                    if (hdr.len > 0) _ = uc.addHeader(hdr);
                    pos = sep + 1;
                }
            }
            url_config = uc;

            const bytes = config_fetch.fetchConfigBytes(allocator, uc) catch |err| {
                // Fall back to cache file if available
                if (opts.config_cache) |cache_path| {
                    std.log.warn("config URL fetch failed ({}), using cached config from {s}", .{ err, cache_path });
                    loaded_config = config_file_mod.loadConfigFile(allocator, cache_path) catch |cerr| {
                        std.log.err("failed to load cached config: {}", .{cerr});
                        return cerr;
                    };
                    break :blk loaded_config.?.server_config;
                }
                std.log.err("config URL fetch failed: {}", .{err});
                return error.ConfigFetchFailed;
            };
            defer allocator.free(bytes);

            // Write cache before parsing
            if (opts.config_cache) |cache_path| {
                config_fetch.writeCacheFile(cache_path, bytes) catch |werr| {
                    std.log.warn("failed to write config cache: {}", .{werr});
                };
            }

            loaded_config = config_file_mod.parseJsonFromBytes(allocator, bytes) catch |err| {
                std.log.err("failed to parse config from URL: {}", .{err});
                return err;
            };
            break :blk loaded_config.?.server_config;
        } else if (opts.config_path) |path| {
            loaded_config = config_file_mod.loadConfigFile(allocator, path) catch |err| {
                std.log.err("failed to load config file: {}", .{err});
                return err;
            };
            break :blk loaded_config.?.server_config;
        } else if (opts.config_json) |bytes| {
            loaded_config = config_file_mod.parseJsonFromBytes(allocator, bytes) catch |err| {
                std.log.err("failed to parse config_json: {}", .{err});
                return err;
            };
            break :blk loaded_config.?.server_config;
        }
        break :blk config_mod.ServerConfig.default();
    };

    var x402_b64: ?[]const u8 = null;
    var x402_json: ?[]const u8 = null;
    defer if (x402_b64) |p| allocator.free(p);
    defer if (x402_json) |p| allocator.free(p);

    if (cfg.x402.enabled and cfg.x402.payment_required_b64.len == 0) {
        const encoded = try x402.demoPaymentRequiredB64(allocator, "http://localhost:8080/");
        x402_b64 = encoded.b64;
        x402_json = encoded.json;
        cfg.x402.payment_required_b64 = encoded.b64;
        cfg.x402.payment_required_json = encoded.json;
    }

    // Explicit overrides win over the config file.
    if (opts.static_root.len > 0) cfg.static_root = opts.static_root;
    if (opts.workers_override) |w| cfg.workers = w;
    if (opts.cert_path) |c| cfg.tls.cert_path = c;
    if (opts.key_path) |k| cfg.tls.key_path = k;
    try cfg.validate();

    var app_router = opts.router orelse router_mod.Router.init(.{
        .require_payment = cfg.x402.enabled,
        .payment_required_b64 = cfg.x402.payment_required_b64,
        .payment_required_json = cfg.x402.payment_required_json,
    });
    if (app_router.facilitator == null and cfg.x402.facilitator_url.len > 0) {
        if (x402.parseFacilitatorUrl(cfg.x402.facilitator_url)) |fac| {
            var fac_config = fac;
            fac_config.timeout_ms = cfg.x402.facilitator_timeout_ms;
            app_router.facilitator = fac_config;
        }
    }
    if (!cfg.disable_middleware) {
        security.buildCache();
    }

    // Build the reverse proxy from the config's upstreams/routes. Heap
    // allocated: applyReload() and Server.deinit() destroy()/replace it, so a
    // stack-local Proxy must never reach the server.
    var proxy_ptr: ?*proxy_mod.Proxy = null;
    if (loaded_config) |lc| {
        if (lc.routes.len > 0 and (lc.upstreams.len > 0 or upstream_mod.anyTenantRoute(lc.routes))) {
            const p = try allocator.create(proxy_mod.Proxy);
            errdefer allocator.destroy(p);
            p.* = try proxy_mod.Proxy.init(allocator, .{
                .upstreams = lc.upstreams,
                .routes = lc.routes,
            });
            proxy_ptr = p;
        }
    }

    const config_source: ?config_fetch.ConfigSource = if (url_config) |uc|
        .{ .url = uc }
    else if (opts.config_path) |p|
        .{ .file = p }
    else
        null;

    // WASM edge-filter specs (design 10.0), if any. Built into per-worker
    // pools at server run() start. Empty slice when none configured or wasm
    // is off. The Tier-2 control-socket path borrows the loaded_config arena,
    // which outlives run() (deinit is deferred at fn top).
    const wasm_specs: []const config_file_mod.WasmFilterConfig =
        if (loaded_config) |lc| lc.wasm_filters else &.{};
    const wasm_ctl_socket: []const u8 = if (loaded_config) |lc| lc.wasm_control_socket else "";
    const wasm_deadline_ms: u64 = if (loaded_config) |lc| lc.wasm_host_call_deadline_ms else 0;
    const tenant_ttl_ms: u64 = if (loaded_config) |lc| lc.tenant_idle_ttl_ms else 0;

    if (cfg.workers != 1) {
        // Multi-process mode
        var master = try Master.init(allocator, cfg, app_router, proxy_ptr);
        master.config_source = config_source;
        master.wasm_filter_specs = wasm_specs;
        master.wasm_control_socket_path = wasm_ctl_socket;
        master.wasm_host_call_deadline_ms = wasm_deadline_ms;
        master.tenant_idle_ttl_ms = tenant_ttl_ms;
        defer master.deinit();
        try master.run(opts.run_for_ms);
    } else {
        // Single-process mode
        var builder = ServerBuilder
            .config(cfg)
            .router(app_router);
        if (proxy_ptr) |p| {
            builder = builder.withProxy(p);
        }
        const srv = try builder.build(allocator);
        defer {
            srv.deinit();
            allocator.destroy(srv);
        }
        srv.config_source = config_source;
        srv.wasm_filter_specs = wasm_specs;
        srv.wasm_control_socket_path = wasm_ctl_socket;
        if (wasm_deadline_ms != 0) srv.wasm_host_call_deadline_ms = wasm_deadline_ms;
        if (tenant_ttl_ms != 0) srv.tenant_idle_ttl_ms = tenant_ttl_ms;
        try srv.run(opts.run_for_ms);
    }
}

/// Parsed swerver CLI arguments. Slices borrow argv (process lifetime).
pub const Args = struct {
    run_for_ms: ?u64,
    static_root: []const u8,
    workers_override: ?u16,
    config_path: ?[]const u8,
    config_url: ?[]const u8,
    config_cache: ?[]const u8,
    config_headers: [config_fetch.MAX_EXTRA_HEADERS][]const u8,
    config_header_count: u8,
    cert_path: ?[:0]const u8,
    key_path: ?[:0]const u8,
};

/// Build `Options` from parsed CLI args. `args` must outlive the returned
/// Options (config_headers slices into it) - in practice, keep the Args in
/// main's frame and call `run` immediately.
pub fn optionsFromArgs(args: *const Args) Options {
    return .{
        .config_path = args.config_path,
        .config_url = args.config_url,
        .config_cache = args.config_cache,
        .config_headers = args.config_headers[0..args.config_header_count],
        .static_root = args.static_root,
        .workers_override = args.workers_override,
        .cert_path = args.cert_path,
        .key_path = args.key_path,
        .run_for_ms = args.run_for_ms,
    };
}

/// Parse the swerver CLI (--config, --config-url, --config-cache,
/// --config-header, --static-root, --workers, --cert, --key, --run-for-ms;
/// both "--flag value" and "--flag=value" forms).
pub fn parseArgs(args: std.process.Args, allocator: std.mem.Allocator) !Args {
    var result = Args{
        .run_for_ms = null,
        .static_root = "",
        .workers_override = null,
        .config_path = null,
        .config_url = null,
        .config_cache = null,
        .config_headers = .{""} ** config_fetch.MAX_EXTRA_HEADERS,
        .config_header_count = 0,
        .cert_path = null,
        .key_path = null,
    };
    var it = try std.process.Args.Iterator.initAllocator(args, allocator);
    defer it.deinit();
    _ = it.next(); // Skip program name
    while (it.next()) |arg_z| {
        const arg = std.mem.sliceTo(arg_z, 0);
        if (std.mem.eql(u8, arg, "--run-for-ms")) {
            const value = it.next() orelse return error.InvalidRunForMs;
            result.run_for_ms = std.fmt.parseInt(u64, std.mem.sliceTo(value, 0), 10) catch return error.InvalidRunForMs;
        } else if (std.mem.startsWith(u8, arg, "--run-for-ms=")) {
            const value = arg["--run-for-ms=".len..];
            result.run_for_ms = std.fmt.parseInt(u64, value, 10) catch return error.InvalidRunForMs;
        } else if (std.mem.eql(u8, arg, "--static-root")) {
            const value = it.next() orelse return error.InvalidStaticRoot;
            result.static_root = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--static-root=")) {
            result.static_root = arg["--static-root=".len..];
        } else if (std.mem.eql(u8, arg, "--workers")) {
            const value = it.next() orelse return error.InvalidWorkerCount;
            result.workers_override = std.fmt.parseInt(u16, std.mem.sliceTo(value, 0), 10) catch return error.InvalidWorkerCount;
        } else if (std.mem.startsWith(u8, arg, "--workers=")) {
            const value = arg["--workers=".len..];
            result.workers_override = std.fmt.parseInt(u16, value, 10) catch return error.InvalidWorkerCount;
        } else if (std.mem.eql(u8, arg, "--config")) {
            const value = it.next() orelse return error.InvalidConfigPath;
            result.config_path = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--config=")) {
            result.config_path = arg["--config=".len..];
        } else if (std.mem.eql(u8, arg, "--config-url")) {
            const value = it.next() orelse return error.InvalidConfigPath;
            result.config_url = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--config-url=")) {
            result.config_url = arg["--config-url=".len..];
        } else if (std.mem.eql(u8, arg, "--config-cache")) {
            const value = it.next() orelse return error.InvalidConfigPath;
            result.config_cache = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--config-cache=")) {
            result.config_cache = arg["--config-cache=".len..];
        } else if (std.mem.eql(u8, arg, "--config-header")) {
            const value = it.next() orelse return error.InvalidArgs;
            if (result.config_header_count < config_fetch.MAX_EXTRA_HEADERS) {
                result.config_headers[result.config_header_count] = std.mem.sliceTo(value, 0);
                result.config_header_count += 1;
            }
        } else if (std.mem.startsWith(u8, arg, "--config-header=")) {
            if (result.config_header_count < config_fetch.MAX_EXTRA_HEADERS) {
                result.config_headers[result.config_header_count] = arg["--config-header=".len..];
                result.config_header_count += 1;
            }
        } else if (std.mem.eql(u8, arg, "--cert")) {
            const value = it.next() orelse return error.InvalidCertPath;
            result.cert_path = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--cert=")) {
            result.cert_path = @ptrCast(arg["--cert=".len..]);
        } else if (std.mem.eql(u8, arg, "--key")) {
            const value = it.next() orelse return error.InvalidKeyPath;
            result.key_path = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--key=")) {
            result.key_path = @ptrCast(arg["--key=".len..]);
        }
    }
    return result;
}

// -- Tests -------------------------------------------------------------------

const net = @import("runtime/net.zig");

test "optionsFromArgs maps every CLI field" {
    var args = Args{
        .run_for_ms = 250,
        .static_root = "/srv/static",
        .workers_override = 4,
        .config_path = "/etc/swerver.json",
        .config_url = null,
        .config_cache = "/tmp/cache.json",
        .config_headers = .{""} ** config_fetch.MAX_EXTRA_HEADERS,
        .config_header_count = 2,
        .cert_path = "/tls/cert.pem",
        .key_path = "/tls/key.pem",
    };
    args.config_headers[0] = "X-A: 1";
    args.config_headers[1] = "X-B: 2";

    const opts = optionsFromArgs(&args);
    try std.testing.expectEqual(@as(?u64, 250), opts.run_for_ms);
    try std.testing.expectEqualStrings("/srv/static", opts.static_root);
    try std.testing.expectEqual(@as(?u16, 4), opts.workers_override);
    try std.testing.expectEqualStrings("/etc/swerver.json", opts.config_path.?);
    try std.testing.expectEqual(@as(usize, 2), opts.config_headers.len);
    try std.testing.expectEqualStrings("X-B: 2", opts.config_headers[1]);
}

test "run rejects conflicting config sources" {
    try std.testing.expectError(error.ConflictingConfigSources, run(std.testing.allocator, .{
        .config_path = "/a.json",
        .config_url = "http://x/cfg",
    }));
    try std.testing.expectError(error.ConflictingConfigSources, run(std.testing.allocator, .{
        .config_path = "/a.json",
        .config_json = "{}",
    }));
}

fn bootstrapPingHandler(_: *router_mod.HandlerContext) @import("response/response.zig").Response {
    return .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .body = .{ .bytes = "pong" },
    };
}

fn sleepMs(ms: u64) void {
    var ts = std.posix.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    var rem: std.posix.timespec = .{ .sec = 0, .nsec = 0 };
    while (std.posix.system.nanosleep(&ts, &rem) != 0) ts = rem;
}

const SmokeClient = struct {
    port: u16,
    got_pong: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn drive(self: *SmokeClient) void {
        // Retry until the server is listening (bounded).
        var attempt: usize = 0;
        const fd = while (attempt < 40) : (attempt += 1) {
            if (net.connectBlocking("127.0.0.1", self.port, 250)) |fd| break fd else |_| {}
            sleepMs(25);
        } else return;
        defer @import("runtime/clock.zig").closeFd(fd);

        net.sendAll(fd, "GET /bootstrap-ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") catch return;
        var buf: [1024]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len) {
            const n = net.recvBlocking(fd, buf[total..]) catch break;
            if (n == 0) break;
            total += n;
            if (std.mem.indexOf(u8, buf[0..total], "pong") != null) break;
        }
        const resp = buf[0..total];
        if (std.mem.startsWith(u8, resp, "HTTP/1.1 200") and std.mem.indexOf(u8, resp, "pong") != null) {
            self.got_pong.store(true, .release);
        }
    }
};

test "bootstrap.run serves a config-driven single-process server end to end" {
    const allocator = std.testing.allocator;

    var app_router = router_mod.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    try app_router.get("/bootstrap-ping", bootstrapPingHandler);

    var client = SmokeClient{ .port = 39471 };
    const t = try std.Thread.spawn(.{}, SmokeClient.drive, .{&client});

    // Blocks for the bounded run window, then tears the server down.
    try run(allocator, .{
        .config_json = "{ \"server\": { \"address\": \"127.0.0.1\", \"port\": 39471, \"workers\": 1 } }",
        .router = app_router,
        .run_for_ms = 1500,
    });
    t.join();

    try std.testing.expect(client.got_pong.load(.acquire));
}
