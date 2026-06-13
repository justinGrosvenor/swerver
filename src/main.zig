const std = @import("std");

const swerver = @import("swerver");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try parseArgs(init.minimal.args, allocator);

    if (args.config_path != null and args.config_url != null) {
        std.log.err("--config and --config-url are mutually exclusive", .{});
        return error.InvalidArgs;
    }

    var loaded_config: ?swerver.config_file.LoadedConfig = null;
    defer if (loaded_config) |*lc| lc.deinit();

    var url_config: ?swerver.config_fetch.UrlConfig = null;

    var cfg: swerver.config.ServerConfig = blk: {
        if (args.config_url) |url| {
            var uc = swerver.config_fetch.parseConfigUrl(url) orelse {
                std.log.err("invalid config URL: {s}", .{url});
                return error.InvalidArgs;
            };
            if (std.c.getenv("SWERVER_CONFIG_TOKEN")) |t| uc.token = std.mem.sliceTo(t, 0);
            if (args.config_cache) |cp| uc.cache_path = cp;
            for (args.config_headers[0..args.config_header_count]) |hdr| {
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

            const bytes = swerver.config_fetch.fetchConfigBytes(allocator, uc) catch |err| {
                // Fall back to cache file if available
                if (args.config_cache) |cache_path| {
                    std.log.warn("config URL fetch failed ({}), using cached config from {s}", .{ err, cache_path });
                    loaded_config = swerver.config_file.loadConfigFile(allocator, cache_path) catch |cerr| {
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
            if (args.config_cache) |cache_path| {
                swerver.config_fetch.writeCacheFile(cache_path, bytes) catch |werr| {
                    std.log.warn("failed to write config cache: {}", .{werr});
                };
            }

            loaded_config = swerver.config_file.parseJsonFromBytes(allocator, bytes) catch |err| {
                std.log.err("failed to parse config from URL: {}", .{err});
                return err;
            };
            break :blk loaded_config.?.server_config;
        } else if (args.config_path) |path| {
            loaded_config = swerver.config_file.loadConfigFile(allocator, path) catch |err| {
                std.log.err("failed to load config file: {}", .{err});
                return err;
            };
            break :blk loaded_config.?.server_config;
        }
        break :blk swerver.config.ServerConfig.default();
    };

    var x402_b64: ?[]const u8 = null;
    var x402_json: ?[]const u8 = null;
    defer if (x402_b64) |p| allocator.free(p);
    defer if (x402_json) |p| allocator.free(p);

    if (cfg.x402.enabled and cfg.x402.payment_required_b64.len == 0) {
        const encoded = try swerver.middleware.x402.demoPaymentRequiredB64(allocator, "http://localhost:8080/");
        x402_b64 = encoded.b64;
        x402_json = encoded.json;
        cfg.x402.payment_required_b64 = encoded.b64;
        cfg.x402.payment_required_json = encoded.json;
    }

    // CLI args override config file
    if (args.static_root.len > 0) cfg.static_root = args.static_root;
    if (args.workers_override) |w| cfg.workers = w;
    if (args.cert_path) |c| cfg.tls.cert_path = c;
    if (args.key_path) |k| cfg.tls.key_path = k;
    try cfg.validate();

    var app_router = swerver.router.Router.init(.{
        .require_payment = cfg.x402.enabled,
        .payment_required_b64 = cfg.x402.payment_required_b64,
        .payment_required_json = cfg.x402.payment_required_json,
    });
    if (cfg.x402.facilitator_url.len > 0) {
        if (swerver.middleware.x402.parseFacilitatorUrl(cfg.x402.facilitator_url)) |fac| {
            var fac_config = fac;
            fac_config.timeout_ms = cfg.x402.facilitator_timeout_ms;
            app_router.facilitator = fac_config;
        }
    }
    if (!cfg.disable_middleware) {
        swerver.middleware.security.buildCache();
    }

    // Build proxy from config file if upstreams/routes defined.
    // Heap-allocate so applyReload() can destroy()/replace it uniformly.
    var proxy_ptr: ?*swerver.proxy.handler.Proxy = null;
    if (loaded_config) |lc| {
        if (lc.upstreams.len > 0 and lc.routes.len > 0) {
            const p = try allocator.create(swerver.proxy.handler.Proxy);
            p.* = try swerver.proxy.handler.Proxy.init(allocator, .{
                .upstreams = lc.upstreams,
                .routes = lc.routes,
            });
            proxy_ptr = p;
        }
    }

    const config_source: ?swerver.config_fetch.ConfigSource = if (url_config) |uc|
        .{ .url = uc }
    else if (args.config_path) |p|
        .{ .file = p }
    else
        null;

    if (cfg.workers != 1) {
        // Multi-process mode
        var master = try swerver.Master.init(allocator, cfg, app_router, proxy_ptr);
        master.config_source = config_source;
        defer master.deinit();
        try master.run(args.run_for_ms);
    } else {
        // Single-process mode (default, backward compatible)
        var builder = swerver.ServerBuilder
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
        try srv.run(args.run_for_ms);
    }
}

const Args = struct {
    run_for_ms: ?u64,
    static_root: []const u8,
    workers_override: ?u16,
    config_path: ?[]const u8,
    config_url: ?[]const u8,
    config_cache: ?[]const u8,
    config_headers: [swerver.config_fetch.MAX_EXTRA_HEADERS][]const u8,
    config_header_count: u8,
    cert_path: ?[:0]const u8,
    key_path: ?[:0]const u8,
};

fn parseArgs(args: std.process.Args, allocator: std.mem.Allocator) !Args {
    var result = Args{
        .run_for_ms = null,
        .static_root = "",
        .workers_override = null,
        .config_path = null,
        .config_url = null,
        .config_cache = null,
        .config_headers = .{""} ** swerver.config_fetch.MAX_EXTRA_HEADERS,
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
            if (result.config_header_count < swerver.config_fetch.MAX_EXTRA_HEADERS) {
                result.config_headers[result.config_header_count] = std.mem.sliceTo(value, 0);
                result.config_header_count += 1;
            }
        } else if (std.mem.startsWith(u8, arg, "--config-header=")) {
            if (result.config_header_count < swerver.config_fetch.MAX_EXTRA_HEADERS) {
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
