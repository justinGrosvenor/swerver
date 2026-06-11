const std = @import("std");
const config_mod = @import("config.zig");
const upstream_mod = @import("proxy/upstream.zig");
const balancer_mod = @import("proxy/balancer.zig");
const auth_mod = @import("middleware/auth.zig");
const ratelimit_mod = @import("middleware/ratelimit.zig");
const cache_mod = @import("proxy/cache.zig");
const dns_mod = @import("proxy/dns.zig");
const consul_mod = @import("proxy/consul.zig");
const body_schema_mod = @import("middleware/body_schema.zig");
const clock = @import("runtime/clock.zig");

/// Config file schema version. Bump the minor component when fields are
/// added (backward-compatible), the major component when a field is
/// renamed or removed (breaking).
///
/// Stable at alpha for the alpha.N series:
///   - server.{address, port, workers, max_connections, static_root,
///     disable_middleware, allowed_hosts}
///   - timeouts.{idle_ms, header_ms, body_ms, write_ms}
///   - limits.{max_header_bytes, max_body_bytes}
///   - buffer_pool.{buffer_size, buffer_count, body_buffer_size, body_buffer_count}
///   - tls.{cert_path, key_path}
///   - quic.{enabled, port, cert_path, key_path}
///   - upstreams[].{name, servers, load_balancer, health_check}
///   - routes[].{path_prefix, upstream, strip_prefix}
///
/// Unstable / may move before 1.0:
///   - access_log and metrics sub-schemas (feature in flux)
///   - rate_limit sub-schema (new in alpha)
///   - x402 sub-schema (niche feature, schema still driven by spec updates)
pub const SCHEMA_VERSION = "1.0";

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

pub fn parseJsonFromBytes(parent_alloc: std.mem.Allocator, bytes: []const u8) !LoadedConfig {
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
        if (s.disable_middleware) |v| cfg.disable_middleware = v;
        if (s.disable_preencoded) |v| cfg.disable_preencoded = v;
        if (s.cache_static_files) |v| cfg.cache_static_files = v;
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

    // Buffer pool
    if (file_cfg.buffer_pool) |bp| {
        if (bp.buffer_size) |v| cfg.buffer_pool.buffer_size = v;
        if (bp.buffer_count) |v| cfg.buffer_pool.buffer_count = v;
        if (bp.body_buffer_size) |v| cfg.buffer_pool.body_buffer_size = v;
        if (bp.body_buffer_count) |v| cfg.buffer_pool.body_buffer_count = v;
    }

    // Limits
    if (file_cfg.limits) |l| {
        if (l.max_header_bytes) |v| cfg.limits.max_header_bytes = v;
        if (l.max_body_bytes) |v| cfg.limits.max_body_bytes = v;
        if (l.max_header_count) |v| cfg.limits.max_header_count = v;
    }

    // TLS
    if (file_cfg.tls) |t| {
        if (t.cert_path) |c| cfg.tls.cert_path = c;
        if (t.key_path) |k| cfg.tls.key_path = k;
        if (t.client_ca_path) |v| cfg.tls.client_ca_path = v;
        if (t.client_cert_required) |v| cfg.tls.client_cert_required = v;
        if (t.certificates) |json_certs| {
            const certs = try alloc.alloc(config_mod.TlsCertificate, json_certs.len);
            for (json_certs, 0..) |jc, ci| {
                certs[ci] = .{
                    .hostnames = jc.hostnames,
                    .cert_path = jc.cert_path,
                    .key_path = jc.key_path,
                };
            }
            cfg.tls.certificates = certs;
        }
    }

    // HTTP/2
    if (file_cfg.http2) |h2| {
        if (h2.max_streams) |v| cfg.http2.max_streams = v;
        if (h2.max_header_list_size) |v| cfg.http2.max_header_list_size = v;
        if (h2.initial_window_size) |v| cfg.http2.initial_window_size = v;
        if (h2.max_frame_size) |v| cfg.http2.max_frame_size = v;
        if (h2.h2c_only) |v| cfg.http2.h2c_only = v;
    }

    // QUIC / HTTP/3
    if (file_cfg.quic) |q| {
        if (q.enabled) |v| cfg.quic.enabled = v;
        if (q.port) |v| cfg.quic.port = v;
        if (q.cert_path) |v| cfg.quic.cert_path = v;
        if (q.key_path) |v| cfg.quic.key_path = v;
        if (q.max_idle_timeout_ms) |v| cfg.quic.max_idle_timeout_ms = v;
        if (q.max_streams_bidi) |v| cfg.quic.max_streams_bidi = v;
        if (q.max_streams_uni) |v| cfg.quic.max_streams_uni = v;
    }

    // Admin API
    if (file_cfg.admin) |a| {
        if (a.enabled) |v| cfg.admin.enabled = v;
        if (a.port) |v| cfg.admin.port = v;
        if (a.address) |v| cfg.admin.address = v;
        if (a.api_key) |v| cfg.admin.api_key = v;
    }

    // x402
    if (file_cfg.x402) |x| {
        if (x.enabled) |v| cfg.x402.enabled = v;
        if (x.facilitator_url) |v| cfg.x402.facilitator_url = v;
        if (x.facilitator_timeout_ms) |v| cfg.x402.facilitator_timeout_ms = v;
        if (x.payment_required_b64) |v| cfg.x402.payment_required_b64 = v;
    }

    // OpenTelemetry
    if (file_cfg.otel) |o| {
        if (o.enabled) |v| cfg.otel.enabled = v;
        if (o.collector_url) |v| cfg.otel.collector_url = v;
        if (o.service_name) |v| cfg.otel.service_name = v;
        if (o.flush_interval_s) |v| cfg.otel.flush_interval_s = v;
        if (o.sample_rate) |v| cfg.otel.sample_rate = v;
        if (o.max_batch_size) |v| cfg.otel.max_batch_size = v;
        if (o.headers) |v| cfg.otel.headers = v;
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

        var dns_discovery: ?dns_mod.DnsConfig = null;
        if (u.dns_discovery) |dd| {
            dns_discovery = .{
                .hostname = dd.hostname,
                .port = dd.port orelse 80,
                .interval_s = dd.interval_s orelse 30,
            };
        }

        var consul_discovery: ?consul_mod.ConsulConfig = null;
        if (u.consul_discovery) |cd| {
            consul_discovery = .{
                .service = cd.service,
                .address = cd.address orelse "127.0.0.1",
                .port = cd.port orelse 8500,
                .interval_s = cd.interval_s orelse 15,
                .token = cd.token orelse "",
            };
        }

        upstreams_out[ui] = .{
            .name = u.name,
            .servers = servers_out,
            .load_balancer = parseLoadBalancer(u.load_balancer),
            .health_check = health_check,
            .connection_pool = pool_config,
            .dns_discovery = dns_discovery,
            .consul_discovery = consul_discovery,
            .allow_private = u.allow_private orelse true,
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

        var route_x402: ?upstream_mod.ProxyRouteX402 = null;
        if (r.x402) |x| {
            var extensions_json: []const u8 = "";
            if (x.extensions) |ext| {
                var ext_list = std.ArrayList(u8).empty;
                var ext_writer = std.Io.Writer.Allocating.fromArrayList(alloc, &ext_list);
                defer ext_writer.deinit();
                std.json.Stringify.value(ext, .{}, &ext_writer.writer) catch return error.ConfigParseError;
                ext_list = ext_writer.toArrayList();
                const ext_copy = try alloc.alloc(u8, ext_list.items.len);
                @memcpy(ext_copy, ext_list.items);
                extensions_json = ext_copy;
            }
            route_x402 = .{
                .price = x.price orelse return error.ConfigParseError,
                .asset = x.asset orelse return error.ConfigParseError,
                .network = x.network orelse return error.ConfigParseError,
                .pay_to = x.pay_to orelse return error.ConfigParseError,
                .scheme = x.scheme orelse "exact",
                .max_timeout_seconds = x.max_timeout_seconds orelse 60,
                .settlement_url = x.settlement_url orelse "",
                .gateway_id = x.gateway_id orelse "",
                .extra_name = x.extra_name orelse "",
                .extra_version = x.extra_version orelse "",
                .facilitator_url = x.facilitator_url orelse "",
                .extensions_json = extensions_json,
                .resource_url = x.resource_url orelse "",
                .inline_receipt = x.inline_receipt orelse false,
            };
        }

        var route_auth: auth_mod.AuthMethod = .none;
        if (r.auth) |a| {
            route_auth = try parseAuthMethod(alloc, a);
        }

        var route_rate_limit: ?ratelimit_mod.RouteRateLimit = null;
        if (r.rate_limit) |rl| {
            route_rate_limit = .{
                .requests_per_second = rl.requests_per_second orelse 100,
                .burst_size = rl.burst_size orelse 200,
                .key = if (rl.key) |k|
                    if (std.mem.eql(u8, k, "ip")) .ip else .consumer
                else
                    .consumer,
            };
        }

        var route_cache: ?cache_mod.CacheConfig = null;
        if (r.cache) |c| {
            var vary: []const []const u8 = &.{};
            if (c.vary) |v| {
                const vary_copy = try alloc.alloc([]const u8, v.len);
                for (v, 0..) |vk, vi| vary_copy[vi] = vk;
                vary = vary_copy;
            }
            route_cache = .{
                .ttl_s = c.ttl_s orelse 60,
                .max_entries = c.max_entries orelse 1024,
                .vary = vary,
            };
        }

        var traffic_split: ?[]const upstream_mod.TrafficTarget = null;
        if (r.traffic_split) |ts_json| {
            const targets = try alloc.alloc(upstream_mod.TrafficTarget, ts_json.len);
            for (ts_json, 0..) |t, ti| {
                targets[ti] = .{
                    .upstream = t.upstream,
                    .weight = t.weight orelse 100,
                };
            }
            traffic_split = targets;
        }

        var route_body_schema: ?*const body_schema_mod.Schema = null;
        if (r.body_schema) |bs_val| {
            const schema_ptr = try alloc.create(body_schema_mod.Schema);
            schema_ptr.* = body_schema_mod.parseSchema(alloc, bs_val) catch return error.ConfigParseError;
            route_body_schema = schema_ptr;
        }

        var route_headers: upstream_mod.HeaderRules = .{};
        if (r.upstream_headers) |uh| {
            const hdrs = try alloc.alloc(upstream_mod.Header, uh.len);
            for (uh, 0..) |h, hi| {
                if (!isSafeHttpValue(h.name) or !isSafeHttpValue(h.value)) return error.ConfigParseError;
                hdrs[hi] = .{ .name = h.name, .value = h.value };
            }
            route_headers.set_request = hdrs;
        }

        routes_out[ri] = .{
            .path_prefix = r.path_prefix,
            .host = r.host,
            .upstream = r.upstream,
            .rewrite = rewrite,
            .headers = route_headers,
            .timeouts = .{
                .connect_ms = r.connect_timeout_ms orelse 5_000,
                .send_ms = r.send_timeout_ms orelse 30_000,
                .read_ms = r.read_timeout_ms orelse 60_000,
                .total_ms = r.total_timeout_ms orelse 120_000,
            },
            .max_response_bytes = r.max_response_bytes orelse (32 * 1024 * 1024),
            .x402 = route_x402,
            .auth = route_auth,
            .rate_limit = route_rate_limit,
            .traffic_split = traffic_split,
            .cache = route_cache,
            .body_schema = route_body_schema,
            .mirror = r.mirror,
        };
    }

    // Validate that every route references a valid upstream name
    for (routes_out) |route| {
        var found = false;
        for (upstreams_out) |u| {
            if (std.mem.eql(u8, route.upstream, u.name)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return error.ConfigParseError;
        }

        if (route.traffic_split) |targets| {
            for (targets) |t| {
                var t_found = false;
                for (upstreams_out) |u| {
                    if (std.mem.eql(u8, t.upstream, u.name)) {
                        t_found = true;
                        break;
                    }
                }
                if (!t_found) {
                    return error.ConfigParseError;
                }
            }
        }

        if (route.mirror) |mirror_name| {
            var m_found = false;
            for (upstreams_out) |u| {
                if (std.mem.eql(u8, mirror_name, u.name)) {
                    m_found = true;
                    break;
                }
            }
            if (!m_found) {
                return error.ConfigParseError;
            }
        }
    }

    return .{
        .server_config = cfg,
        .upstreams = upstreams_out,
        .routes = routes_out,
        .arena = arena,
    };
}

fn parseAuthMethod(alloc: std.mem.Allocator, a: RouteAuthJson) !auth_mod.AuthMethod {
    return parseAuthMethodDepth(alloc, a, 0);
}

fn parseAuthMethodDepth(alloc: std.mem.Allocator, a: RouteAuthJson, depth: u8) !auth_mod.AuthMethod {
    if (depth > 3) return error.ConfigParseError;
    if (std.mem.eql(u8, a.type, "api_key")) {
        const json_keys = a.keys orelse return error.ConfigParseError;
        const keys_out = try alloc.alloc(auth_mod.ApiKey, json_keys.len);
        for (json_keys, 0..) |k, ki| {
            if (k.key == null and k.key_hash == null) return error.ConfigParseError;
            keys_out[ki] = .{
                .key = k.key orelse "",
                .key_hash = k.key_hash orelse "",
                .name = k.name,
            };
        }
        return .{ .api_key = .{
            .keys = keys_out,
            .header_name = a.header_name orelse "X-API-Key",
            .query_param = a.query_param orelse "api_key",
        } };
    } else if (std.mem.eql(u8, a.type, "jwt")) {
        var claims_to_headers: []const auth_mod.ClaimHeader = &.{};
        if (a.claims_to_headers) |json_mappings| {
            const mappings = try alloc.alloc(auth_mod.ClaimHeader, json_mappings.len);
            for (json_mappings, 0..) |m, mi| {
                mappings[mi] = .{ .claim = m.claim, .header = m.header };
            }
            claims_to_headers = mappings;
        }
        return .{ .jwt = .{
            .secret = a.secret orelse return error.ConfigParseError,
            .issuer = a.issuer,
            .audience = a.audience,
            .claims_to_headers = claims_to_headers,
        } };
    } else if (std.mem.eql(u8, a.type, "anonymous")) {
        return .{ .anonymous = .{
            .subject = a.subject orelse "anonymous",
        } };
    } else if (std.mem.eql(u8, a.type, "forward_auth")) {
        return .{ .forward_auth = .{
            .url = a.url orelse return error.ConfigParseError,
            .headers_forward = a.headers_forward orelse &.{},
            .headers_upstream = a.headers_upstream orelse &.{},
            .timeout_ms = a.timeout_ms orelse 5000,
        } };
    } else if (std.mem.eql(u8, a.type, "chain")) {
        const json_methods = a.methods orelse return error.ConfigParseError;
        const methods = try alloc.alloc(auth_mod.AuthMethod, json_methods.len);
        for (json_methods, 0..) |m, mi| {
            methods[mi] = try parseAuthMethodDepth(alloc, m, depth + 1);
        }
        return .{ .chain = .{ .methods = methods } };
    } else {
        return error.ConfigParseError;
    }
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
    buffer_pool: ?BufferPoolJson = null,
    tls: ?TlsJson = null,
    http2: ?Http2Json = null,
    quic: ?QuicJson = null,
    x402: ?X402Json = null,
    admin: ?AdminJson = null,
    otel: ?OtelJson = null,
    upstreams: ?[]const UpstreamJson = null,
    routes: ?[]const RouteJson = null,
};

const ServerJson = struct {
    address: ?[]const u8 = null,
    port: ?u16 = null,
    max_connections: ?usize = null,
    workers: ?u16 = null,
    disable_middleware: ?bool = null,
    disable_preencoded: ?bool = null,
    cache_static_files: ?bool = null,
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

const BufferPoolJson = struct {
    buffer_size: ?usize = null,
    buffer_count: ?usize = null,
    body_buffer_size: ?usize = null,
    body_buffer_count: ?usize = null,
};

const TlsJson = struct {
    cert_path: ?[:0]const u8 = null,
    key_path: ?[:0]const u8 = null,
    certificates: ?[]const TlsCertJson = null,
    client_ca_path: ?[:0]const u8 = null,
    client_cert_required: ?bool = null,
};

const TlsCertJson = struct {
    hostnames: []const [:0]const u8,
    cert_path: [:0]const u8,
    key_path: [:0]const u8,
};

const Http2Json = struct {
    max_streams: ?usize = null,
    max_header_list_size: ?usize = null,
    initial_window_size: ?u32 = null,
    max_frame_size: ?u32 = null,
    h2c_only: ?bool = null,
};

const QuicJson = struct {
    enabled: ?bool = null,
    port: ?u16 = null,
    cert_path: ?[:0]const u8 = null,
    key_path: ?[:0]const u8 = null,
    max_idle_timeout_ms: ?u32 = null,
    max_streams_bidi: ?u64 = null,
    max_streams_uni: ?u64 = null,
};

const X402Json = struct {
    enabled: ?bool = null,
    facilitator_url: ?[]const u8 = null,
    facilitator_timeout_ms: ?u32 = null,
    payment_required_b64: ?[]const u8 = null,
};

const AdminJson = struct {
    enabled: ?bool = null,
    port: ?u16 = null,
    address: ?[]const u8 = null,
    api_key: ?[]const u8 = null,
};

const OtelJson = struct {
    enabled: ?bool = null,
    collector_url: ?[]const u8 = null,
    service_name: ?[]const u8 = null,
    flush_interval_s: ?u32 = null,
    sample_rate: ?u16 = null,
    max_batch_size: ?u16 = null,
    headers: ?[]const u8 = null,
};

const RouteX402Json = struct {
    price: ?[]const u8 = null,
    asset: ?[]const u8 = null,
    network: ?[]const u8 = null,
    pay_to: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    max_timeout_seconds: ?u32 = null,
    settlement_url: ?[]const u8 = null,
    gateway_id: ?[]const u8 = null,
    extra_name: ?[]const u8 = null,
    extra_version: ?[]const u8 = null,
    facilitator_url: ?[]const u8 = null,
    extensions: ?std.json.Value = null,
    resource_url: ?[]const u8 = null,
    inline_receipt: ?bool = null,
};

const UpstreamJson = struct {
    name: []const u8,
    servers: []const ServerEntryJson,
    load_balancer: ?[]const u8 = null,
    health_check: ?HealthCheckJson = null,
    connection_pool: ?PoolConfigJson = null,
    dns_discovery: ?DnsDiscoveryJson = null,
    consul_discovery: ?ConsulDiscoveryJson = null,
    allow_private: ?bool = null,
};

const DnsDiscoveryJson = struct {
    hostname: []const u8,
    port: ?u16 = null,
    interval_s: ?u32 = null,
};

const ConsulDiscoveryJson = struct {
    service: []const u8,
    address: ?[]const u8 = null,
    port: ?u16 = null,
    interval_s: ?u32 = null,
    token: ?[]const u8 = null,
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

const HeaderJson = struct {
    name: []const u8,
    value: []const u8,
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
    max_response_bytes: ?usize = null,
    x402: ?RouteX402Json = null,
    auth: ?RouteAuthJson = null,
    rate_limit: ?RateLimitJson = null,
    traffic_split: ?[]const TrafficSplitJson = null,
    cache: ?CacheJson = null,
    body_schema: ?std.json.Value = null,
    mirror: ?[]const u8 = null,
    upstream_headers: ?[]const HeaderJson = null,
};

const CacheJson = struct {
    ttl_s: ?u32 = null,
    max_entries: ?u16 = null,
    vary: ?[]const []const u8 = null,
};

const RouteAuthJson = struct {
    type: []const u8,
    keys: ?[]const ApiKeyJson = null,
    header_name: ?[]const u8 = null,
    query_param: ?[]const u8 = null,
    secret: ?[]const u8 = null,
    algorithm: ?[]const u8 = null,
    issuer: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    claims_to_headers: ?[]const ClaimHeaderJson = null,
    // anonymous
    subject: ?[]const u8 = null,
    // forward_auth
    url: ?[]const u8 = null,
    headers_forward: ?[]const []const u8 = null,
    headers_upstream: ?[]const []const u8 = null,
    timeout_ms: ?u32 = null,
    // chain
    methods: ?[]const RouteAuthJson = null,
};

const ApiKeyJson = struct {
    key: ?[]const u8 = null,
    key_hash: ?[]const u8 = null,
    name: []const u8,
};

const ClaimHeaderJson = struct {
    claim: []const u8,
    header: []const u8,
};

const RateLimitJson = struct {
    requests_per_second: ?u32 = null,
    burst_size: ?u32 = null,
    key: ?[]const u8 = null,
};

const TrafficSplitJson = struct {
    upstream: []const u8,
    weight: ?u16 = null,
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

test "parse route with rate_limit" {
    const json =
        \\{
        \\  "upstreams": [{
        \\    "name": "api",
        \\    "servers": [{ "address": "10.0.0.1", "port": 8080 }]
        \\  }],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "api",
        \\    "rate_limit": {
        \\      "requests_per_second": 50,
        \\      "burst_size": 100,
        \\      "key": "ip"
        \\    }
        \\  }]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(usize, 1), loaded.routes.len);
    const rl = loaded.routes[0].rate_limit orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 50), rl.requests_per_second);
    try std.testing.expectEqual(@as(u32, 100), rl.burst_size);
    try std.testing.expect(rl.key == .ip);
}

test "parse route with rate_limit defaults" {
    const json =
        \\{
        \\  "upstreams": [{
        \\    "name": "api",
        \\    "servers": [{ "address": "10.0.0.1", "port": 8080 }]
        \\  }],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "api",
        \\    "rate_limit": {}
        \\  }]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();

    const rl = loaded.routes[0].rate_limit orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 100), rl.requests_per_second);
    try std.testing.expectEqual(@as(u32, 200), rl.burst_size);
    try std.testing.expect(rl.key == .consumer);
}

test "parse route with traffic_split" {
    const json =
        \\{
        \\  "upstreams": [
        \\    { "name": "v1", "servers": [{ "address": "10.0.0.1", "port": 8080 }] },
        \\    { "name": "v2", "servers": [{ "address": "10.0.0.2", "port": 8080 }] }
        \\  ],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "v1",
        \\    "traffic_split": [
        \\      { "upstream": "v1", "weight": 90 },
        \\      { "upstream": "v2", "weight": 10 }
        \\    ]
        \\  }]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();

    const ts = loaded.routes[0].traffic_split orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), ts.len);
    try std.testing.expectEqualStrings("v1", ts[0].upstream);
    try std.testing.expectEqual(@as(u16, 90), ts[0].weight);
    try std.testing.expectEqualStrings("v2", ts[1].upstream);
    try std.testing.expectEqual(@as(u16, 10), ts[1].weight);
}

test "parse route with cache config" {
    const json =
        \\{
        \\  "upstreams": [
        \\    { "name": "backend", "servers": [{ "address": "10.0.0.1", "port": 8080 }] }
        \\  ],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "backend",
        \\    "cache": {
        \\      "ttl_s": 120,
        \\      "max_entries": 500,
        \\      "vary": ["Accept", "Accept-Encoding"]
        \\    }
        \\  }]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();
    const cc = loaded.routes[0].cache orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 120), cc.ttl_s);
    try std.testing.expectEqual(@as(u16, 500), cc.max_entries);
    try std.testing.expectEqual(@as(usize, 2), cc.vary.len);
    try std.testing.expectEqualStrings("Accept", cc.vary[0]);
    try std.testing.expectEqualStrings("Accept-Encoding", cc.vary[1]);
}

test "parse upstream with dns_discovery" {
    const json =
        \\{
        \\  "upstreams": [
        \\    {
        \\      "name": "api",
        \\      "servers": [],
        \\      "dns_discovery": {
        \\        "hostname": "api.internal.svc.cluster.local",
        \\        "port": 8080,
        \\        "interval_s": 15
        \\      }
        \\    }
        \\  ]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();
    const dd = loaded.upstreams[0].dns_discovery orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("api.internal.svc.cluster.local", dd.hostname);
    try std.testing.expectEqual(@as(u16, 8080), dd.port);
    try std.testing.expectEqual(@as(u32, 15), dd.interval_s);
}

test "parse upstream with consul_discovery" {
    const json =
        \\{
        \\  "upstreams": [
        \\    {
        \\      "name": "api",
        \\      "servers": [],
        \\      "consul_discovery": {
        \\        "service": "api-prod",
        \\        "address": "consul.internal",
        \\        "port": 8501,
        \\        "interval_s": 10,
        \\        "token": "secret-token"
        \\      }
        \\    }
        \\  ]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();
    const cd = loaded.upstreams[0].consul_discovery orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("api-prod", cd.service);
    try std.testing.expectEqualStrings("consul.internal", cd.address);
    try std.testing.expectEqual(@as(u16, 8501), cd.port);
    try std.testing.expectEqual(@as(u32, 10), cd.interval_s);
    try std.testing.expectEqualStrings("secret-token", cd.token);
}

test "parse otel config" {
    const json =
        \\{
        \\  "otel": {
        \\    "enabled": true,
        \\    "collector_url": "http://otel.internal:4318",
        \\    "service_name": "my-gateway",
        \\    "flush_interval_s": 10,
        \\    "sample_rate": 50,
        \\    "max_batch_size": 128
        \\  }
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expect(loaded.server_config.otel.enabled);
    try std.testing.expectEqualStrings("http://otel.internal:4318", loaded.server_config.otel.collector_url);
    try std.testing.expectEqualStrings("my-gateway", loaded.server_config.otel.service_name);
    try std.testing.expectEqual(@as(u32, 10), loaded.server_config.otel.flush_interval_s);
    try std.testing.expectEqual(@as(u16, 50), loaded.server_config.otel.sample_rate);
    try std.testing.expectEqual(@as(u16, 128), loaded.server_config.otel.max_batch_size);
}

test "parse route with body_schema" {
    const json =
        \\{
        \\  "upstreams": [
        \\    { "name": "api", "servers": [{ "address": "10.0.0.1", "port": 8080 }] }
        \\  ],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "api",
        \\    "body_schema": {
        \\      "type": "object",
        \\      "required": ["name", "email"],
        \\      "properties": {
        \\        "name": { "type": "string", "minLength": 1, "maxLength": 100 },
        \\        "age": { "type": "integer", "minimum": 0, "maximum": 150 }
        \\      }
        \\    }
        \\  }]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(usize, 1), loaded.routes.len);
    const schema = loaded.routes[0].body_schema orelse return error.MissingSchema;
    try std.testing.expect(schema.schema_type == .object);
    try std.testing.expectEqual(@as(usize, 2), schema.required.len);
    try std.testing.expectEqual(@as(usize, 2), schema.properties.len);
}

test "parse route with mirror" {
    const json =
        \\{
        \\  "upstreams": [
        \\    { "name": "api", "servers": [{ "address": "10.0.0.1", "port": 8080 }] },
        \\    { "name": "shadow", "servers": [{ "address": "10.0.0.2", "port": 8080 }] }
        \\  ],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "api",
        \\    "mirror": "shadow"
        \\  }]
        \\}
    ;
    var loaded = try parseJsonFromBytes(std.testing.allocator, json);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(usize, 1), loaded.routes.len);
    try std.testing.expectEqualStrings("shadow", loaded.routes[0].mirror.?);
}

test "mirror rejects unknown upstream" {
    const json =
        \\{
        \\  "upstreams": [
        \\    { "name": "api", "servers": [{ "address": "10.0.0.1", "port": 8080 }] }
        \\  ],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "api",
        \\    "mirror": "nonexistent"
        \\  }]
        \\}
    ;
    const result = parseJsonFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ConfigParseError, result);
}

test "traffic_split rejects unknown upstream" {
    const json =
        \\{
        \\  "upstreams": [
        \\    { "name": "v1", "servers": [{ "address": "10.0.0.1", "port": 8080 }] }
        \\  ],
        \\  "routes": [{
        \\    "path_prefix": "/api/",
        \\    "upstream": "v1",
        \\    "traffic_split": [
        \\      { "upstream": "v1", "weight": 90 },
        \\      { "upstream": "v2_missing", "weight": 10 }
        \\    ]
        \\  }]
        \\}
    ;
    const result = parseJsonFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ConfigParseError, result);
}
