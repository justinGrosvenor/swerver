const std = @import("std");

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
    /// Retry configuration
    retry: RetryConfig = .{},
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

// Tests
test "isHopByHop identifies hop-by-hop headers" {
    try std.testing.expect(isHopByHop("Connection"));
    try std.testing.expect(isHopByHop("connection"));
    try std.testing.expect(isHopByHop("Keep-Alive"));
    try std.testing.expect(isHopByHop("Transfer-Encoding"));
    try std.testing.expect(!isHopByHop("Content-Type"));
    try std.testing.expect(!isHopByHop("X-Custom-Header"));
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
