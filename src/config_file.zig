const std = @import("std");
const config_mod = @import("config.zig");
const upstream_mod = @import("proxy/upstream.zig");
const balancer_mod = @import("proxy/balancer.zig");
const clock = @import("runtime/clock.zig");

/// Loaded configuration from a JSON file.
/// Owns all parsed string data via an arena allocator.
pub const LoadedConfig = struct {
    server_config: config_mod.ServerConfig,
    upstreams: []const upstream_mod.Upstream,
    routes: []const upstream_mod.ProxyRoute,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *LoadedConfig) void {
        self.arena.deinit();
    }
};

/// Load and parse a JSON configuration file.
pub fn loadConfigFile(allocator: std.mem.Allocator, path: []const u8) !LoadedConfig {
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0) catch |err| {
        std.log.err("config: failed to open '{s}': {}", .{ path, err });
        return err;
    };
    defer clock.closeFd(fd);

    // Read the file contents into a temporary buffer on the stack + heap fallback
    // We avoid creating a separate arena just for reading — the parse arena
    // will own all parsed data, and we free the read buffer after parsing.
    const max_size = 1024 * 1024;
    const buf = try allocator.alloc(u8, max_size);
    defer allocator.free(buf);

    var total: usize = 0;
    while (total < max_size) {
        const n = std.posix.read(fd, buf[total..]) catch return error.ConfigFileReadError;
        if (n == 0) break;
        total += n;
    }
    if (total == max_size) return error.ConfigFileTooLarge;

    return parseJsonFromBytes(allocator, buf[0..total]);
}

fn parseJsonFromBytes(parent_alloc: std.mem.Allocator, bytes: []const u8) !LoadedConfig {
    var arena = std.heap.ArenaAllocator.init(parent_alloc);
    errdefer arena.deinit();
    const alloc = arena.allocator();

    const file_cfg = std.json.parseFromSliceLeaky(FileConfig, alloc, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch {
        return error.ConfigParseError;
    };

    var cfg = config_mod.ServerConfig.default();

    // Server settings
    if (file_cfg.server) |s| {
        if (s.address) |a| cfg.address = a;
        if (s.port) |p| cfg.port = p;
        if (s.max_connections) |m| {
            // Cap max_connections to prevent integer overflow in buffer pool calculation
            if (m > 1_000_000) return error.ConfigParseError;
            cfg.max_connections = m;
        }
        if (s.workers) |w| cfg.workers = w;
        if (s.static_root) |r| cfg.static_root = r;
        if (s.allowed_hosts) |hosts| cfg.allowed_hosts = hosts;
    }

    // Timeouts
    if (file_cfg.timeouts) |t| {
        if (t.idle_ms) |v| cfg.timeouts.idle_ms = v;
        if (t.header_ms) |v| cfg.timeouts.header_ms = v;
        if (t.body_ms) |v| cfg.timeouts.body_ms = v;
        if (t.write_ms) |v| cfg.timeouts.write_ms = v;
    }

    // Limits
    if (file_cfg.limits) |l| {
        if (l.max_header_bytes) |v| cfg.limits.max_header_bytes = v;
        if (l.max_body_bytes) |v| cfg.limits.max_body_bytes = v;
        if (l.max_header_count) |v| cfg.limits.max_header_count = v;
    }

    // HTTP/2
    if (file_cfg.http2) |h2| {
        if (h2.max_streams) |v| cfg.http2.max_streams = v;
        if (h2.max_header_list_size) |v| cfg.http2.max_header_list_size = v;
        if (h2.initial_window_size) |v| cfg.http2.initial_window_size = v;
        if (h2.max_frame_size) |v| cfg.http2.max_frame_size = v;
    }

    // Upstreams
    const upstream_defs = file_cfg.upstreams orelse &[_]UpstreamJson{};
    const upstreams_out = try alloc.alloc(upstream_mod.Upstream, upstream_defs.len);
    for (upstream_defs, 0..) |u, ui| {
        if (u.servers.len > balancer_mod.Balancer.MAX_SERVERS) return error.ConfigParseError;
        const servers_out = try alloc.alloc(upstream_mod.Server, u.servers.len);
        for (u.servers, 0..) |s, si| {
            // Validate server address doesn't contain control characters
            if (!isSafeHttpValue(s.address)) return error.ConfigParseError;
            servers_out[si] = .{
                .address = s.address,
                .port = s.port,
                .weight = s.weight orelse 1,
                .max_fails = s.max_fails orelse 3,
                .fail_timeout_ms = s.fail_timeout_ms orelse 30_000,
                .backup = s.backup orelse false,
            };
        }

        var health_check: ?upstream_mod.HealthCheck = null;
        if (u.health_check) |hc| {
            const hc_path = hc.path orelse "/health";
            // Reject paths with control characters to prevent HTTP request smuggling
            if (!isSafeHttpValue(hc_path)) return error.ConfigParseError;
            health_check = .{
                .interval_ms = hc.interval_ms orelse 5_000,
                .timeout_ms = hc.timeout_ms orelse 2_000,
                .path = hc_path,
                .expected_status = hc.expected_status orelse 200,
                .expected_body = hc.expected_body,
                .healthy_threshold = hc.healthy_threshold orelse 2,
                .unhealthy_threshold = hc.unhealthy_threshold orelse 3,
            };
        }

        var pool_config = upstream_mod.PoolConfig{};
        if (u.connection_pool) |pc| {
            if (pc.max_connections) |v| pool_config.max_connections = v;
            if (pc.max_idle) |v| pool_config.max_idle = v;
            if (pc.idle_timeout_ms) |v| pool_config.idle_timeout_ms = v;
            if (pc.connect_timeout_ms) |v| pool_config.connect_timeout_ms = v;
        }

        upstreams_out[ui] = .{
            .name = u.name,
            .servers = servers_out,
            .load_balancer = parseLoadBalancer(u.load_balancer),
            .health_check = health_check,
            .connection_pool = pool_config,
        };
    }

    // Routes
    const route_defs = file_cfg.routes orelse &[_]RouteJson{};
    const routes_out = try alloc.alloc(upstream_mod.ProxyRoute, route_defs.len);
    for (route_defs, 0..) |r, ri| {
        var rewrite: ?upstream_mod.RewriteRule = null;
        if (r.rewrite_pattern) |pattern| {
            const replacement = r.rewrite_replacement orelse "";
            // Reject rewrite patterns/replacements with control characters
            if (!isSafeHttpValue(pattern) or !isSafeHttpValue(replacement)) return error.ConfigParseError;
            rewrite = .{
                .pattern = pattern,
                .replacement = replacement,
            };
        }

        routes_out[ri] = .{
            .path_prefix = r.path_prefix,
            .host = r.host,
            .upstream = r.upstream,
            .rewrite = rewrite,
            .timeouts = .{
                .connect_ms = r.connect_timeout_ms orelse 5_000,
                .send_ms = r.send_timeout_ms orelse 30_000,
                .read_ms = r.read_timeout_ms orelse 60_000,
                .total_ms = r.total_timeout_ms orelse 120_000,
            },
        };
    }

    return .{
        .server_config = cfg,
        .upstreams = upstreams_out,
        .routes = routes_out,
        .arena = arena,
    };
}

/// Validate that a string contains no control characters (CR, LF, null)
/// that could cause HTTP header injection or request smuggling.
fn isSafeHttpValue(value: []const u8) bool {
    for (value) |ch| {
        if (ch == '\r' or ch == '\n' or ch == 0) return false;
    }
    return true;
}

fn parseLoadBalancer(name: ?[]const u8) upstream_mod.LoadBalancer {
    const n = name orelse return .round_robin;
    if (std.mem.eql(u8, n, "least_conn")) return .least_conn;
    if (std.mem.eql(u8, n, "ip_hash")) return .ip_hash;
    if (std.mem.eql(u8, n, "random")) return .random;
    if (std.mem.eql(u8, n, "weighted_round_robin")) return .weighted_round_robin;
    return .round_robin;
}

// JSON schema types — nullable fields for optional overrides

const FileConfig = struct {
    server: ?ServerJson = null,
    timeouts: ?TimeoutsJson = null,
    limits: ?LimitsJson = null,
    http2: ?Http2Json = null,
    upstreams: ?[]const UpstreamJson = null,
    routes: ?[]const RouteJson = null,
};

const ServerJson = struct {
    address: ?[]const u8 = null,
    port: ?u16 = null,
    max_connections: ?usize = null,
    workers: ?u16 = null,
    static_root: ?[]const u8 = null,
    allowed_hosts: ?[]const []const u8 = null,
};

const TimeoutsJson = struct {
    idle_ms: ?u32 = null,
    header_ms: ?u32 = null,
    body_ms: ?u32 = null,
    write_ms: ?u32 = null,
};

const LimitsJson = struct {
    max_header_bytes: ?usize = null,
    max_body_bytes: ?usize = null,
    max_header_count: ?usize = null,
};

const Http2Json = struct {
    max_streams: ?usize = null,
    max_header_list_size: ?usize = null,
    initial_window_size: ?u32 = null,
    max_frame_size: ?u32 = null,
};

const UpstreamJson = struct {
    name: []const u8,
    servers: []const ServerEntryJson,
    load_balancer: ?[]const u8 = null,
    health_check: ?HealthCheckJson = null,
    connection_pool: ?PoolConfigJson = null,
};

const ServerEntryJson = struct {
    address: []const u8,
    port: u16,
    weight: ?u16 = null,
    max_fails: ?u16 = null,
    fail_timeout_ms: ?u32 = null,
    backup: ?bool = null,
};

const HealthCheckJson = struct {
    interval_ms: ?u32 = null,
    timeout_ms: ?u32 = null,
    path: ?[]const u8 = null,
    expected_status: ?u16 = null,
    expected_body: ?[]const u8 = null,
    healthy_threshold: ?u16 = null,
    unhealthy_threshold: ?u16 = null,
};

const PoolConfigJson = struct {
    max_connections: ?u16 = null,
    max_idle: ?u16 = null,
    idle_timeout_ms: ?u32 = null,
    connect_timeout_ms: ?u32 = null,
};

const RouteJson = struct {
    path_prefix: []const u8,
    host: ?[]const u8 = null,
    upstream: []const u8,
    rewrite_pattern: ?[]const u8 = null,
    rewrite_replacement: ?[]const u8 = null,
    connect_timeout_ms: ?u32 = null,
    send_timeout_ms: ?u32 = null,
    read_timeout_ms: ?u32 = null,
    total_timeout_ms: ?u32 = null,
};

// Tests

test "parse minimal config" {
    const json =
        \\{
        \\  "server": { "port": 9090 }
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(u16, 9090), loaded.server_config.port);
    try std.testing.expectEqualStrings("0.0.0.0", loaded.server_config.address);
    try std.testing.expectEqual(@as(usize, 0), loaded.upstreams.len);
    try std.testing.expectEqual(@as(usize, 0), loaded.routes.len);
}

test "parse full config with upstreams and routes" {
    const json =
        \\{
        \\  "server": { "port": 8080, "workers": 4, "max_connections": 4096 },
        \\  "timeouts": { "idle_ms": 30000, "header_ms": 5000 },
        \\  "limits": { "max_body_bytes": 1048576 },
        \\  "upstreams": [{
        \\    "name": "api",
        \\    "servers": [
        \\      { "address": "10.0.0.1", "port": 8080 },
        \\      { "address": "10.0.0.2", "port": 8080, "weight": 2 }
        \\    ],
        \\    "load_balancer": "round_robin",
        \\    "health_check": { "path": "/healthz", "interval_ms": 10000 }
        \\  }],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "api",
        \\    "rewrite_pattern": "/api",
        \\    "rewrite_replacement": ""
        \\  }]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(u16, 8080), loaded.server_config.port);
    try std.testing.expectEqual(@as(u16, 4), loaded.server_config.workers);
    try std.testing.expectEqual(@as(usize, 4096), loaded.server_config.max_connections);
    try std.testing.expectEqual(@as(u32, 30000), loaded.server_config.timeouts.idle_ms);
    try std.testing.expectEqual(@as(u32, 5000), loaded.server_config.timeouts.header_ms);
    try std.testing.expectEqual(@as(usize, 1048576), loaded.server_config.limits.max_body_bytes);

    try std.testing.expectEqual(@as(usize, 1), loaded.upstreams.len);
    try std.testing.expectEqualStrings("api", loaded.upstreams[0].name);
    try std.testing.expectEqual(@as(usize, 2), loaded.upstreams[0].servers.len);
    try std.testing.expectEqualStrings("10.0.0.1", loaded.upstreams[0].servers[0].address);
    try std.testing.expectEqual(@as(u16, 1), loaded.upstreams[0].servers[0].weight);
    try std.testing.expectEqual(@as(u16, 2), loaded.upstreams[0].servers[1].weight);
    try std.testing.expect(loaded.upstreams[0].health_check != null);
    try std.testing.expectEqualStrings("/healthz", loaded.upstreams[0].health_check.?.path);
    try std.testing.expectEqual(@as(u32, 10000), loaded.upstreams[0].health_check.?.interval_ms);

    try std.testing.expectEqual(@as(usize, 1), loaded.routes.len);
    try std.testing.expectEqualStrings("/api/", loaded.routes[0].path_prefix);
    try std.testing.expectEqualStrings("api", loaded.routes[0].upstream);
    try std.testing.expect(loaded.routes[0].rewrite != null);
    try std.testing.expectEqualStrings("/api", loaded.routes[0].rewrite.?.pattern);
    try std.testing.expectEqualStrings("", loaded.routes[0].rewrite.?.replacement);
}

test "parse empty config uses defaults" {
    const json = "{}";
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();

    const defaults = config_mod.ServerConfig.default();
    try std.testing.expectEqual(defaults.port, loaded.server_config.port);
    try std.testing.expectEqual(defaults.max_connections, loaded.server_config.max_connections);
    try std.testing.expectEqual(defaults.timeouts.idle_ms, loaded.server_config.timeouts.idle_ms);
}

test "parse load balancer names" {
    try std.testing.expect(parseLoadBalancer(null) == .round_robin);
    try std.testing.expect(parseLoadBalancer("round_robin") == .round_robin);
    try std.testing.expect(parseLoadBalancer("least_conn") == .least_conn);
    try std.testing.expect(parseLoadBalancer("ip_hash") == .ip_hash);
    try std.testing.expect(parseLoadBalancer("random") == .random);
    try std.testing.expect(parseLoadBalancer("weighted_round_robin") == .weighted_round_robin);
    try std.testing.expect(parseLoadBalancer("unknown_thing") == .round_robin);
}

test "reject invalid JSON" {
    const json = "{ not valid json";
    const result = parseJsonFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ConfigParseError, result);
}
