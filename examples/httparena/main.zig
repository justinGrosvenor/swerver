//! HttpArena / TechEmpower benchmark server — reference consumer of
//! swerver-as-library.
//!
//! This example shows how to wire the benchmark route handlers on top
//! of the swerver public API. It's the structural counterpart to the
//! old `registerDefaultRoutes` pattern that used to live inside
//! `src/server.zig`: a downstream project embeds swerver, registers
//! routes, and runs the event loop. Nothing here is load-bearing for
//! the core library — if you want a stripped-down HTTP server you can
//! drop `swerver.benchmark.registerRoutes` and register your own.
//!
//! Build standalone (from this directory):
//!
//!     zig build -Doptimize=ReleaseFast
//!     ./zig-out/bin/swerver-httparena --config path/to/config.json
//!
//! Or via the main swerver repo's build.zig (which also wires this
//! example in as a secondary artifact):
//!
//!     cd ../..  &&  zig build example-httparena

const std = @import("std");
const swerver = @import("swerver");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try parseArgs(init.minimal.args, allocator);

    // Load a config file if one was passed; otherwise fall back to
    // sensible defaults so `./swerver-httparena` with no args is a
    // working HTTP server.
    var loaded_config: ?swerver.config_file.LoadedConfig = null;
    defer if (loaded_config) |*lc| lc.deinit();

    var cfg: swerver.config.ServerConfig = blk: {
        if (args.config_path) |path| {
            loaded_config = swerver.config_file.loadConfigFile(allocator, path) catch |err| {
                std.log.err("failed to load config file: {}", .{err});
                return err;
            };
            break :blk loaded_config.?.server_config;
        }
        break :blk swerver.config.ServerConfig.default();
    };

    // CLI overrides
    if (args.static_root.len > 0) cfg.static_root = args.static_root;
    if (args.workers_override) |w| cfg.workers = w;
    if (args.cert_path) |c| cfg.tls.cert_path = c;
    if (args.key_path) |k| cfg.tls.key_path = k;
    try cfg.validate();

    // Build the router and register the benchmark endpoints. This is
    // the entire reason this example exists: one call to
    // `swerver.benchmark.registerRoutes` wires up the full HttpArena +
    // TechEmpower handler set against the router.
    var app_router = swerver.router.Router.init(.{
        .require_payment = cfg.x402.enabled,
        .payment_required_b64 = cfg.x402.payment_required_b64,
    });
    try swerver.benchmark.registerRoutes(&app_router);
    swerver.benchmark.loadDataset();

    if (!cfg.disable_middleware) {
        swerver.middleware.security.buildCache();
        swerver.benchmark.registerPostHooks(&app_router);
    }

    // Build proxy from config file if upstreams/routes defined
    var proxy_instance: ?swerver.proxy.handler.Proxy = null;
    if (loaded_config) |lc| {
        if (lc.upstreams.len > 0 and lc.routes.len > 0) {
            proxy_instance = try swerver.proxy.handler.Proxy.init(allocator, .{
                .upstreams = lc.upstreams,
                .routes = lc.routes,
            });
        }
    }

    if (cfg.workers != 1) {
        var master = try swerver.Master.init(allocator, cfg, app_router, if (proxy_instance) |*p| p else null);
        defer master.deinit();
        try master.run(args.run_for_ms);
    } else {
        var builder = swerver.ServerBuilder
            .config(cfg)
            .router(app_router);
        if (proxy_instance) |*p| {
            builder = builder.withProxy(p);
        }
        const srv = try builder.build(allocator);
        defer {
            srv.deinit();
            allocator.destroy(srv);
        }
        srv.config_path = args.config_path;
        try srv.run(args.run_for_ms);
    }
}

const Args = struct {
    run_for_ms: ?u64 = null,
    static_root: []const u8 = "",
    workers_override: ?u16 = null,
    config_path: ?[]const u8 = null,
    cert_path: ?[:0]const u8 = null,
    key_path: ?[:0]const u8 = null,
};

fn parseArgs(args: std.process.Args, allocator: std.mem.Allocator) !Args {
    var result: Args = .{};
    var it = try std.process.Args.Iterator.initAllocator(args, allocator);
    defer it.deinit();
    _ = it.next(); // skip program name
    while (it.next()) |arg_z| {
        const arg = std.mem.sliceTo(arg_z, 0);
        if (std.mem.eql(u8, arg, "--run-for-ms")) {
            const value = it.next() orelse return error.InvalidRunForMs;
            result.run_for_ms = std.fmt.parseInt(u64, std.mem.sliceTo(value, 0), 10) catch return error.InvalidRunForMs;
        } else if (std.mem.startsWith(u8, arg, "--run-for-ms=")) {
            result.run_for_ms = std.fmt.parseInt(u64, arg["--run-for-ms=".len..], 10) catch return error.InvalidRunForMs;
        } else if (std.mem.eql(u8, arg, "--static-root")) {
            const value = it.next() orelse return error.InvalidStaticRoot;
            result.static_root = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--static-root=")) {
            result.static_root = arg["--static-root=".len..];
        } else if (std.mem.eql(u8, arg, "--workers")) {
            const value = it.next() orelse return error.InvalidWorkerCount;
            result.workers_override = std.fmt.parseInt(u16, std.mem.sliceTo(value, 0), 10) catch return error.InvalidWorkerCount;
        } else if (std.mem.startsWith(u8, arg, "--workers=")) {
            result.workers_override = std.fmt.parseInt(u16, arg["--workers=".len..], 10) catch return error.InvalidWorkerCount;
        } else if (std.mem.eql(u8, arg, "--config")) {
            const value = it.next() orelse return error.InvalidConfigPath;
            result.config_path = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--config=")) {
            result.config_path = arg["--config=".len..];
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
