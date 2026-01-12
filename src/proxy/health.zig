const std = @import("std");
const upstream = @import("upstream.zig");
const pool_mod = @import("pool.zig");
const forward = @import("forward.zig");

/// Health Check System
///
/// Implements active health checking for upstream servers.
/// Periodically probes servers to determine availability.

/// Health state for a server
pub const HealthState = enum {
    /// Initial state, not yet checked
    unknown,
    /// Server is healthy
    healthy,
    /// Server is unhealthy
    unhealthy,
};

/// Tracker for a single server's health
pub const ServerHealth = struct {
    /// Current health state
    state: HealthState = .unknown,
    /// Consecutive successful checks
    success_count: u16 = 0,
    /// Consecutive failed checks
    failure_count: u16 = 0,
    /// Last check timestamp (ms)
    last_check_ms: u64 = 0,
    /// Last successful check timestamp (ms)
    last_success_ms: u64 = 0,
    /// Last failure timestamp (ms)
    last_failure_ms: u64 = 0,
    /// Last response time (ms)
    last_response_time_ms: u32 = 0,
    /// Average response time (ms, exponential moving average)
    avg_response_time_ms: u32 = 0,

    /// Record a successful health check
    pub fn recordSuccess(self: *ServerHealth, now_ms: u64, response_time_ms: u32, config: *const upstream.HealthCheck) void {
        self.last_check_ms = now_ms;
        self.last_success_ms = now_ms;
        self.last_response_time_ms = response_time_ms;
        self.failure_count = 0;
        self.success_count += 1;

        // Update average response time (EMA with alpha = 0.2)
        if (self.avg_response_time_ms == 0) {
            self.avg_response_time_ms = response_time_ms;
        } else {
            self.avg_response_time_ms = @intCast((@as(u64, self.avg_response_time_ms) * 4 + response_time_ms) / 5);
        }

        // Transition to healthy if threshold met
        if (self.success_count >= config.healthy_threshold) {
            self.state = .healthy;
        }
    }

    /// Record a failed health check
    pub fn recordFailure(self: *ServerHealth, now_ms: u64, config: *const upstream.HealthCheck) void {
        self.last_check_ms = now_ms;
        self.last_failure_ms = now_ms;
        self.success_count = 0;
        self.failure_count += 1;

        // Transition to unhealthy if threshold met
        if (self.failure_count >= config.unhealthy_threshold) {
            self.state = .unhealthy;
        }
    }

    /// Check if this server is due for a health check
    pub fn needsCheck(self: *const ServerHealth, now_ms: u64, interval_ms: u32) bool {
        if (self.last_check_ms == 0) return true;
        return now_ms >= self.last_check_ms + interval_ms;
    }

    /// Check if server is currently healthy
    pub fn isHealthy(self: *const ServerHealth) bool {
        return self.state == .healthy or self.state == .unknown;
    }
};

/// Health checker for an upstream
pub const HealthChecker = struct {
    allocator: std.mem.Allocator,
    /// The upstream definition
    upstream_def: *const upstream.Upstream,
    /// Health check configuration
    config: upstream.HealthCheck,
    /// Health state for each server
    server_health: []ServerHealth,
    /// Buffer for health check requests
    request_buf: []u8,
    /// Buffer for health check responses
    response_buf: []u8,

    const REQUEST_BUF_SIZE = 512;
    const RESPONSE_BUF_SIZE = 4096;

    pub fn init(allocator: std.mem.Allocator, upstream_def: *const upstream.Upstream) !HealthChecker {
        const config = upstream_def.health_check orelse upstream.HealthCheck{};
        const server_health = try allocator.alloc(ServerHealth, upstream_def.servers.len);
        errdefer allocator.free(server_health);
        @memset(server_health, ServerHealth{});

        const request_buf = try allocator.alloc(u8, REQUEST_BUF_SIZE);
        errdefer allocator.free(request_buf);

        const response_buf = try allocator.alloc(u8, RESPONSE_BUF_SIZE);

        return .{
            .allocator = allocator,
            .upstream_def = upstream_def,
            .config = config,
            .server_health = server_health,
            .request_buf = request_buf,
            .response_buf = response_buf,
        };
    }

    pub fn deinit(self: *HealthChecker) void {
        self.allocator.free(self.server_health);
        self.allocator.free(self.request_buf);
        self.allocator.free(self.response_buf);
    }

    /// Run health checks on all servers that need it
    pub fn runChecks(self: *HealthChecker, now_ms: u64, conn_pool: *pool_mod.Pool) void {
        for (self.upstream_def.servers, 0..) |server, i| {
            const health = &self.server_health[i];

            if (!health.needsCheck(now_ms, self.config.interval_ms)) {
                continue;
            }

            // Perform health check
            const result = self.checkServer(&server, i, now_ms);

            // Update pool availability based on health state
            if (health.state == .unhealthy) {
                conn_pool.server_failures[i].available = false;
            } else if (health.state == .healthy) {
                conn_pool.server_failures[i].available = true;
                conn_pool.server_failures[i].consecutive_failures = 0;
            }

            _ = result;
        }
    }

    /// Check a single server's health
    fn checkServer(self: *HealthChecker, server: *const upstream.Server, index: usize, now_ms: u64) bool {
        const health = &self.server_health[index];
        const start_ms = now_ms;

        // Build health check request
        const request_len = self.buildHealthRequest(server) catch {
            health.recordFailure(now_ms, &self.config);
            return false;
        };

        // In a real implementation, we would:
        // 1. Open a connection to the server
        // 2. Send the request
        // 3. Wait for response (with timeout)
        // 4. Parse and validate the response
        //
        // For now, this is a skeleton that tracks state.
        // The actual network I/O would be integrated with the event loop.

        _ = request_len;

        // Simulated check - in production this would do actual I/O
        // For now, assume success if server is configured
        const response_time_ms: u32 = @intCast(now_ms - start_ms);
        health.recordSuccess(now_ms, response_time_ms, &self.config);

        return true;
    }

    /// Build HTTP health check request
    fn buildHealthRequest(self: *HealthChecker, server: *const upstream.Server) !usize {
        var pos: usize = 0;

        // GET /health HTTP/1.1\r\n
        pos += (std.fmt.bufPrint(self.request_buf[pos..], "GET {s} HTTP/1.1\r\n", .{self.config.path}) catch return error.BufferFull).len;

        // Host header
        pos += (std.fmt.bufPrint(self.request_buf[pos..], "Host: {s}:{d}\r\n", .{ server.address, server.port }) catch return error.BufferFull).len;

        // User-Agent
        pos += (std.fmt.bufPrint(self.request_buf[pos..], "User-Agent: swerver-health-check/1.0\r\n", .{}) catch return error.BufferFull).len;

        // Connection: close (don't keep health check connections alive)
        pos += (std.fmt.bufPrint(self.request_buf[pos..], "Connection: close\r\n", .{}) catch return error.BufferFull).len;

        // End headers
        if (pos + 2 > self.request_buf.len) return error.BufferFull;
        self.request_buf[pos] = '\r';
        self.request_buf[pos + 1] = '\n';
        pos += 2;

        return pos;
    }

    /// Validate health check response
    fn validateResponse(self: *HealthChecker, response_data: []const u8) bool {
        const parsed = forward.parseUpstreamResponse(response_data) catch return false;

        // Check status code
        if (parsed.status != self.config.expected_status) {
            return false;
        }

        // Check body if configured
        if (self.config.expected_body) |expected| {
            const body = response_data[parsed.body_start..parsed.body_end];
            if (!std.mem.eql(u8, body, expected)) {
                return false;
            }
        }

        return true;
    }

    /// Get health state for a server
    pub fn getServerHealth(self: *const HealthChecker, server_index: usize) ?*const ServerHealth {
        if (server_index >= self.server_health.len) return null;
        return &self.server_health[server_index];
    }

    /// Get overall upstream health status
    pub fn getUpstreamStatus(self: *const HealthChecker) UpstreamStatus {
        var healthy_count: u16 = 0;
        var unhealthy_count: u16 = 0;
        var unknown_count: u16 = 0;

        for (self.server_health) |health| {
            switch (health.state) {
                .healthy => healthy_count += 1,
                .unhealthy => unhealthy_count += 1,
                .unknown => unknown_count += 1,
            }
        }

        return .{
            .total_servers = @intCast(self.server_health.len),
            .healthy = healthy_count,
            .unhealthy = unhealthy_count,
            .unknown = unknown_count,
        };
    }
};

/// Summary of upstream health status
pub const UpstreamStatus = struct {
    total_servers: u16,
    healthy: u16,
    unhealthy: u16,
    unknown: u16,

    pub fn hasHealthyServers(self: UpstreamStatus) bool {
        return self.healthy > 0 or self.unknown > 0;
    }

    pub fn allHealthy(self: UpstreamStatus) bool {
        return self.unhealthy == 0 and self.unknown == 0;
    }
};

/// Manager for all health checkers
pub const HealthManager = struct {
    allocator: std.mem.Allocator,
    checkers: std.StringHashMap(*HealthChecker),

    pub fn init(allocator: std.mem.Allocator) HealthManager {
        return .{
            .allocator = allocator,
            .checkers = std.StringHashMap(*HealthChecker).init(allocator),
        };
    }

    pub fn deinit(self: *HealthManager) void {
        var it = self.checkers.valueIterator();
        while (it.next()) |checker| {
            checker.*.deinit();
            self.allocator.destroy(checker.*);
        }
        self.checkers.deinit();
    }

    /// Register an upstream for health checking
    pub fn registerUpstream(self: *HealthManager, upstream_def: *const upstream.Upstream) !void {
        // Only register if health check is configured
        if (upstream_def.health_check == null) return;

        if (self.checkers.contains(upstream_def.name)) return;

        const checker = try self.allocator.create(HealthChecker);
        errdefer self.allocator.destroy(checker);

        checker.* = try HealthChecker.init(self.allocator, upstream_def);
        errdefer checker.deinit();

        try self.checkers.put(upstream_def.name, checker);
    }

    /// Run all health checks
    pub fn runAllChecks(self: *HealthManager, now_ms: u64, pool_manager: *pool_mod.PoolManager) void {
        var it = self.checkers.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const checker = entry.value_ptr.*;

            if (pool_manager.getPool(name)) |pool| {
                checker.runChecks(now_ms, pool);
            }
        }
    }

    /// Get health checker for an upstream
    pub fn getChecker(self: *HealthManager, name: []const u8) ?*HealthChecker {
        return self.checkers.get(name);
    }
};

// Tests
test "ServerHealth state transitions" {
    var health = ServerHealth{};
    const config = upstream.HealthCheck{
        .healthy_threshold = 2,
        .unhealthy_threshold = 3,
    };

    // Initial state is unknown
    try std.testing.expectEqual(HealthState.unknown, health.state);

    // Two successes should transition to healthy
    health.recordSuccess(1000, 50, &config);
    try std.testing.expectEqual(HealthState.unknown, health.state);
    health.recordSuccess(2000, 45, &config);
    try std.testing.expectEqual(HealthState.healthy, health.state);

    // Three failures should transition to unhealthy
    health.recordFailure(3000, &config);
    try std.testing.expectEqual(HealthState.healthy, health.state);
    health.recordFailure(4000, &config);
    try std.testing.expectEqual(HealthState.healthy, health.state);
    health.recordFailure(5000, &config);
    try std.testing.expectEqual(HealthState.unhealthy, health.state);
}

test "ServerHealth check timing" {
    const health = ServerHealth{ .last_check_ms = 1000 };
    const interval_ms: u32 = 5000;

    // Should not need check before interval
    try std.testing.expect(!health.needsCheck(2000, interval_ms));
    try std.testing.expect(!health.needsCheck(5999, interval_ms));

    // Should need check after interval
    try std.testing.expect(health.needsCheck(6000, interval_ms));
    try std.testing.expect(health.needsCheck(10000, interval_ms));
}

test "ServerHealth response time averaging" {
    var health = ServerHealth{};
    const config = upstream.HealthCheck{};

    // First check sets the average
    health.recordSuccess(1000, 100, &config);
    try std.testing.expectEqual(@as(u32, 100), health.avg_response_time_ms);

    // Subsequent checks use EMA
    health.recordSuccess(2000, 50, &config);
    // EMA: (100 * 4 + 50) / 5 = 90
    try std.testing.expectEqual(@as(u32, 90), health.avg_response_time_ms);
}

test "UpstreamStatus aggregation" {
    const status = UpstreamStatus{
        .total_servers = 5,
        .healthy = 3,
        .unhealthy = 1,
        .unknown = 1,
    };

    try std.testing.expect(status.hasHealthyServers());
    try std.testing.expect(!status.allHealthy());

    const all_healthy = UpstreamStatus{
        .total_servers = 3,
        .healthy = 3,
        .unhealthy = 0,
        .unknown = 0,
    };
    try std.testing.expect(all_healthy.allHealthy());
}
