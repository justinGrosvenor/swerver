const std = @import("std");
const auth = @import("../middleware/auth.zig");
const ratelimit = @import("../middleware/ratelimit.zig");
const cache_mod = @import("cache.zig");
const dns_mod = @import("dns.zig");
const consul_mod = @import("consul.zig");
const body_schema = @import("../middleware/body_schema.zig");

/// Upstream Configuration
///
/// Defines upstream server groups for reverse proxy load balancing.
/// Supports weighted servers, backup servers, and health-based routing.

/// Configuration for an upstream server group
pub const Upstream = struct {
    /// Unique name for this upstream (used in proxy routes)
    name: []const u8,
    /// List of backend servers
    servers: []const Server,
    /// Load balancing strategy
    load_balancer: LoadBalancer = .round_robin,
    /// Optional health check configuration
    health_check: ?HealthCheck = null,
    /// Connection pool settings
    connection_pool: PoolConfig = .{},
    /// DNS service discovery configuration
    dns_discovery: ?dns_mod.DnsConfig = null,
    /// Consul service discovery configuration
    consul_discovery: ?consul_mod.ConsulConfig = null,
    /// Allow connections to private/loopback addresses (default true for backwards compat).
    /// Set false to enable SSRF protection on this upstream.
    allow_private: bool = true,
};

/// Individual backend server definition
pub const Server = struct {
    /// Server address (hostname or IP)
    address: []const u8,
    /// Server port
    port: u16,
    /// Weight for weighted load balancing (higher = more traffic)
    weight: u16 = 1,
    /// Number of failures before marking unavailable
    max_fails: u16 = 3,
    /// Time in ms to wait before retrying failed server
    fail_timeout_ms: u32 = 30_000,
    /// Whether this is a backup server (only used when primaries fail)
    backup: bool = false,
};

/// Connection pool configuration
pub const PoolConfig = struct {
    /// Maximum total connections to this upstream
    max_connections: u16 = 64,
    /// Maximum idle connections to keep
    max_idle: u16 = 16,
    /// Time in ms before closing idle connections
    idle_timeout_ms: u32 = 60_000,
    /// Connection establishment timeout in ms
    connect_timeout_ms: u32 = 5_000,
};

/// Load balancing strategies
pub const LoadBalancer = union(enum) {
    /// Rotate through servers sequentially
    round_robin,
    /// Select server with fewest active connections
    least_conn,
    /// Consistent hashing based on client IP
    ip_hash,
    /// Random selection
    random,
    /// Round-robin respecting server weights
    weighted_round_robin,
};

/// Active health check configuration
pub const HealthCheck = struct {
    /// Interval between health checks in ms
    interval_ms: u32 = 5_000,
    /// Timeout for health check request in ms
    timeout_ms: u32 = 2_000,
    /// Path to probe
    path: []const u8 = "/health",
    /// Expected HTTP status code
    expected_status: u16 = 200,
    /// Expected response body (null = don't check body)
    expected_body: ?[]const u8 = null,
    /// Number of consecutive successes to mark healthy
    healthy_threshold: u16 = 2,
    /// Number of consecutive failures to mark unhealthy
    unhealthy_threshold: u16 = 3,
};

/// Proxy route configuration
pub const TrafficTarget = struct {
    upstream: []const u8,
    weight: u16 = 100,
};

var split_counter: u32 = 0;

pub const ProxyRoute = struct {
    /// Path prefix to match (e.g., "/api/")
    path_prefix: []const u8,
    /// Optional host header to match
    host: ?[]const u8 = null,
    /// Name of upstream to forward to
    upstream: []const u8,
    /// Optional path rewrite rule
    rewrite: ?RewriteRule = null,
    /// Header manipulation rules
    headers: HeaderRules = .{},
    /// Timeout configuration for this route
    timeouts: ProxyTimeouts = .{},
    /// Maximum upstream response size (headers + body) the proxy will
    /// buffer for this route. Responses that fit the fixed pool buffer are
    /// served with zero allocation; larger ones grow into a bounded heap
    /// allocation. Above the cap the proxy answers 502.
    max_response_bytes: usize = 32 * 1024 * 1024,
    /// Retry configuration
    retry: RetryConfig = .{},
    /// Per-route x402 payment gating
    x402: ?ProxyRouteX402 = null,
    /// Per-route authentication
    auth: auth.AuthMethod = .none,
    /// Per-route rate limiting (consumer or IP keyed)
    rate_limit: ?ratelimit.RouteRateLimit = null,
    /// Traffic splitting: weighted routing to multiple upstreams (canary/blue-green).
    /// When set, overrides `upstream` — the upstream is selected by weight.
    traffic_split: ?[]const TrafficTarget = null,
    /// Per-route response caching configuration.
    cache: ?cache_mod.CacheConfig = null,
    /// Per-route request body JSON schema validation.
    body_schema: ?*const body_schema.Schema = null,
    /// Traffic mirroring: name of upstream to shadow-send requests to.
    /// Fire-and-forget — mirror response is discarded.
    mirror: ?[]const u8 = null,
    /// Per-route WASM edge filter (design 10.0). Opaque `*wasm.filter.Pool`,
    /// invoked before forwarding: it can allow or reject (auth/policy gate).
    /// Set by the filter manager at startup; null means no filter. See proxy.zig.
    wasm_pool: ?*anyopaque = null,
    wasm_fuel: i64 = 0,

    /// Resolve the upstream name, applying traffic split if configured.
    pub fn selectUpstream(self: *const ProxyRoute) []const u8 {
        const targets = self.traffic_split orelse return self.upstream;
        if (targets.len == 0) return self.upstream;
        if (targets.len == 1) return targets[0].upstream;

        var total_weight: u32 = 0;
        for (targets) |t| total_weight += t.weight;
        if (total_weight == 0) return self.upstream;

        split_counter +%= 1;
        const pick = split_counter % total_weight;
        var cumulative: u32 = 0;
        for (targets) |t| {
            cumulative += t.weight;
            if (pick < cumulative) return t.upstream;
        }
        return targets[targets.len - 1].upstream;
    }
};

pub const ProxyRouteX402 = struct {
    price: []const u8,
    asset: []const u8,
    network: []const u8,
    pay_to: []const u8,
    scheme: []const u8 = "exact",
    max_timeout_seconds: u32 = 60,
    settlement_url: []const u8 = "",
    gateway_id: []const u8 = "",
    extra_name: []const u8 = "",
    extra_version: []const u8 = "",
    facilitator_url: []const u8 = "",
    extensions_json: []const u8 = "",
    resource_url: []const u8 = "",
    inline_receipt: bool = false,
};

/// Path rewrite rule
pub const RewriteRule = struct {
    /// Pattern to match (supports simple prefix replacement)
    pattern: []const u8,
    /// Replacement string
    replacement: []const u8,
};

/// Header manipulation rules for proxy
pub const HeaderRules = struct {
    /// Headers to add/set on forwarded request
    set_request: []const Header = &.{},
    /// Headers to remove from forwarded request
    remove_request: []const []const u8 = &.{},
    /// Headers to add/set on returned response
    set_response: []const Header = &.{},
    /// Headers to remove from returned response
    remove_response: []const []const u8 = &.{},
    /// Add standard proxy headers (X-Forwarded-For, etc.)
    add_proxy_headers: bool = true,
    /// Preserve Host header from client (don't replace with upstream host)
    preserve_host: bool = false,
};

/// Simple header name-value pair
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Timeout configuration for proxy operations
pub const ProxyTimeouts = struct {
    /// Timeout for establishing upstream connection
    connect_ms: u32 = 5_000,
    /// Timeout for sending request to upstream
    send_ms: u32 = 30_000,
    /// Timeout for receiving response from upstream
    read_ms: u32 = 60_000,
    /// Total time limit for entire proxy operation
    total_ms: u32 = 120_000,
};

/// Retry configuration
pub const RetryConfig = struct {
    /// Maximum number of retry attempts
    max_retries: u8 = 1,
    /// HTTP status codes that trigger retry
    retry_statuses: []const u16 = &.{ 502, 503, 504 },
    /// HTTP methods that are safe to retry
    retry_methods: []const []const u8 = &.{ "GET", "HEAD", "OPTIONS" },
    /// Whether to retry non-idempotent methods (dangerous)
    retry_non_idempotent: bool = false,
};

/// Hop-by-hop headers that must not be forwarded
pub const hop_by_hop_headers = [_][]const u8{
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
};

/// Check if a header name is a hop-by-hop header
pub fn isHopByHop(name: []const u8) bool {
    for (hop_by_hop_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

/// For gRPC requests: `te: trailers` and `trailer` must be forwarded.
pub fn isHopByHopGrpc(name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, "te")) return false;
    if (std.ascii.eqlIgnoreCase(name, "trailer")) return false;
    return isHopByHop(name);
}

/// Headers the proxy sets authoritatively (trusted identity / forwarding
/// metadata). Any client-supplied copy must be stripped before forwarding,
/// otherwise a client could spoof e.g. `X-Consumer-Name: admin` or
/// `X-Client-Cert-DN` and have an upstream that reads the first occurrence
/// trust it. The proxy re-injects the genuine values (X-Forwarded-* /
/// X-Real-IP / X-Client-Cert-DN via addProxyHeaders; X-Consumer-Name via
/// the auth identity headers).
const proxy_trusted_headers = [_][]const u8{
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-client-cert-dn",
    "x-consumer-name",
};

pub fn isProxyTrustedHeader(name: []const u8) bool {
    for (proxy_trusted_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

// Tests
test "isHopByHop identifies hop-by-hop headers" {
    try std.testing.expect(isHopByHop("Connection"));
    try std.testing.expect(isHopByHop("connection"));
    try std.testing.expect(isHopByHop("Keep-Alive"));
    try std.testing.expect(isHopByHop("Transfer-Encoding"));
    try std.testing.expect(!isHopByHop("Content-Type"));
    try std.testing.expect(!isHopByHop("X-Custom-Header"));
}

test "isProxyTrustedHeader identifies proxy-managed identity headers" {
    try std.testing.expect(isProxyTrustedHeader("X-Consumer-Name"));
    try std.testing.expect(isProxyTrustedHeader("x-consumer-name"));
    try std.testing.expect(isProxyTrustedHeader("X-Client-Cert-DN"));
    try std.testing.expect(isProxyTrustedHeader("X-Real-IP"));
    try std.testing.expect(isProxyTrustedHeader("X-Forwarded-For"));
    try std.testing.expect(isProxyTrustedHeader("X-Forwarded-Proto"));
    try std.testing.expect(isProxyTrustedHeader("X-Forwarded-Host"));
    try std.testing.expect(!isProxyTrustedHeader("X-Custom-Header"));
    try std.testing.expect(!isProxyTrustedHeader("User-Agent"));
}

test "isHopByHopGrpc preserves te and trailer" {
    try std.testing.expect(!isHopByHopGrpc("te"));
    try std.testing.expect(!isHopByHopGrpc("TE"));
    try std.testing.expect(!isHopByHopGrpc("trailer"));
    try std.testing.expect(!isHopByHopGrpc("Trailer"));
    try std.testing.expect(isHopByHopGrpc("Connection"));
    try std.testing.expect(isHopByHopGrpc("Keep-Alive"));
    try std.testing.expect(isHopByHopGrpc("Transfer-Encoding"));
}

test "default configurations are valid" {
    const server = Server{
        .address = "127.0.0.1",
        .port = 8080,
    };
    try std.testing.expectEqual(@as(u16, 1), server.weight);
    try std.testing.expectEqual(@as(u16, 3), server.max_fails);
    try std.testing.expect(!server.backup);

    const pool = PoolConfig{};
    try std.testing.expectEqual(@as(u16, 64), pool.max_connections);
    try std.testing.expectEqual(@as(u16, 16), pool.max_idle);
}
