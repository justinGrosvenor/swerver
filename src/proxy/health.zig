const std = @import("std");
const upstream = @import("upstream.zig");
const pool_mod = @import("pool.zig");
const forward = @import("forward.zig");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");

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
    /// Health state for each server (owned by background thread after start)
    server_health: []ServerHealth,
    /// Atomic published states — written by background thread, read by reactor
    published_states: []std.atomic.Value(u8),
    /// Buffer for health check requests
    request_buf: []u8,
    /// Buffer for health check responses
    response_buf: []u8,

    const REQUEST_BUF_SIZE = 512;
    const RESPONSE_BUF_SIZE = 4096;

    pub fn init(allocator: std.mem.Allocator, upstream_def: *const upstream.Upstream) !HealthChecker {
        const config = upstream_def.health_check orelse upstream.HealthCheck{};
        const server_count = upstream_def.servers.len;

        const server_health = try allocator.alloc(ServerHealth, server_count);
        errdefer allocator.free(server_health);
        @memset(server_health, ServerHealth{});

        const published_states = try allocator.alloc(std.atomic.Value(u8), server_count);
        errdefer allocator.free(published_states);
        for (published_states) |*s| s.* = std.atomic.Value(u8).init(@intFromEnum(HealthState.unknown));

        const request_buf = try allocator.alloc(u8, REQUEST_BUF_SIZE);
        errdefer allocator.free(request_buf);

        const response_buf = try allocator.alloc(u8, RESPONSE_BUF_SIZE);

        return .{
            .allocator = allocator,
            .upstream_def = upstream_def,
            .config = config,
            .server_health = server_health,
            .published_states = published_states,
            .request_buf = request_buf,
            .response_buf = response_buf,
        };
    }

    pub fn deinit(self: *HealthChecker) void {
        self.allocator.free(self.server_health);
        self.allocator.free(self.published_states);
        self.allocator.free(self.request_buf);
        self.allocator.free(self.response_buf);
    }

    /// Run health checks (called from background thread). Updates server_health
    /// and publishes state atomically for the reactor to read.
    pub fn runChecks(self: *HealthChecker, now_ms: u64) void {
        for (self.upstream_def.servers, 0..) |server, i| {
            const health = &self.server_health[i];

            if (!health.needsCheck(now_ms, self.config.interval_ms)) {
                continue;
            }

            _ = self.checkServer(&server, i, now_ms);
            self.published_states[i].store(@intFromEnum(health.state), .release);
        }
    }

    /// Apply published health states to pool availability (called from reactor — non-blocking).
    pub fn applyHealthToPool(self: *const HealthChecker, conn_pool: *pool_mod.Pool) void {
        for (0..self.published_states.len) |i| {
            const state: HealthState = @enumFromInt(self.published_states[i].load(.acquire));
            if (state == .unhealthy) {
                conn_pool.server_failures[i].available = false;
            } else if (state == .healthy) {
                conn_pool.server_failures[i].available = true;
                conn_pool.server_failures[i].consecutive_failures = 0;
            }
        }
    }

    /// Check a single server's health via a real TCP connection.
    fn checkServer(self: *HealthChecker, server: *const upstream.Server, index: usize, now_ms: u64) bool {
        const health_state = &self.server_health[index];
        const start_ms = getMonotonicMs();

        // Build health check request
        const request_len = self.buildHealthRequest(server) catch {
            health_state.recordFailure(now_ms, &self.config);
            return false;
        };

        // Connect to the server (UNIX-socket backends probe over their path)
        const fd = (if (server.unix_path.len > 0)
            net.connectUnixBlocking(server.unix_path, self.config.timeout_ms)
        else
            net.connectBlocking(server.address, server.port, self.config.timeout_ms)) catch {
            health_state.recordFailure(now_ms, &self.config);
            return false;
        };
        defer clock.closeFd(fd);

        // Set socket timeouts
        net.setSocketTimeouts(fd, self.config.timeout_ms, self.config.timeout_ms);

        // Send health check request
        net.sendAll(fd, self.request_buf[0..request_len]) catch {
            health_state.recordFailure(now_ms, &self.config);
            return false;
        };

        // Read response
        var total_read: usize = 0;
        while (total_read < self.response_buf.len) {
            const n = net.recvBlocking(fd, self.response_buf[total_read..]) catch break;
            if (n == 0) break;
            total_read += n;

            // Try to parse — stop if complete
            if (forward.parseUpstreamResponse(self.response_buf[0..total_read], false)) |_| {
                break;
            } else |_| {}
        }

        if (total_read == 0) {
            health_state.recordFailure(now_ms, &self.config);
            return false;
        }

        // Validate the response
        if (!self.validateResponse(self.response_buf[0..total_read])) {
            health_state.recordFailure(now_ms, &self.config);
            return false;
        }

        // Calculate response time using monotonic clock
        const end_ms = getMonotonicMs();
        const response_time_ms: u32 = if (end_ms > start_ms)
            @intCast(@min(end_ms - start_ms, std.math.maxInt(u32)))
        else
            0;
        health_state.recordSuccess(now_ms, response_time_ms, &self.config);
        return true;
    }

    /// Build HTTP health check request
    fn buildHealthRequest(self: *HealthChecker, server: *const upstream.Server) !usize {
        var pos: usize = 0;

        // GET /health HTTP/1.1\r\n
        pos += (std.fmt.bufPrint(self.request_buf[pos..], "GET {s} HTTP/1.1\r\n", .{self.config.path}) catch return error.BufferFull).len;

        // Host header (unix-socket backends have no address:port)
        if (server.unix_path.len > 0) {
            pos += (std.fmt.bufPrint(self.request_buf[pos..], "Host: localhost\r\n", .{}) catch return error.BufferFull).len;
        } else {
            pos += (std.fmt.bufPrint(self.request_buf[pos..], "Host: {s}:{d}\r\n", .{ server.address, server.port }) catch return error.BufferFull).len;
        }

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
        const parsed = forward.parseUpstreamResponse(response_data, false) catch return false;

        // Check status code
        if (parsed.status != self.config.expected_status) {
            return false;
        }

        if (self.config.expected_body) |expected| {
            const raw_body = response_data[parsed.body_start..parsed.body_end];
            if (parsed.is_chunked) {
                var decoded_buf: [4096]u8 = undefined;
                const decoded_len = forward.decodeChunkedInto(raw_body, &decoded_buf) orelse return false;
                if (!std.mem.eql(u8, decoded_buf[0..decoded_len], expected)) return false;
            } else {
                if (!std.mem.eql(u8, raw_body, expected)) return false;
            }
        }

        return true;
    }

    /// Get published health state for a server (safe for cross-thread reads)
    pub fn getServerHealthState(self: *const HealthChecker, server_index: usize) ?HealthState {
        if (server_index >= self.published_states.len) return null;
        return @enumFromInt(self.published_states[server_index].load(.acquire));
    }

    /// Get overall upstream health status (safe for cross-thread reads via atomics)
    pub fn getUpstreamStatus(self: *const HealthChecker) UpstreamStatus {
        var healthy_count: u16 = 0;
        var unhealthy_count: u16 = 0;
        var unknown_count: u16 = 0;

        for (0..self.published_states.len) |i| {
            const state: HealthState = @enumFromInt(self.published_states[i].load(.acquire));
            switch (state) {
                .healthy => healthy_count += 1,
                .unhealthy => unhealthy_count += 1,
                .unknown => unknown_count += 1,
            }
        }

        return .{
            .total_servers = @intCast(self.published_states.len),
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
    thread_handle: ?std.Thread = null,
    shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(allocator: std.mem.Allocator) HealthManager {
        return .{
            .allocator = allocator,
            .checkers = std.StringHashMap(*HealthChecker).init(allocator),
        };
    }

    pub fn deinit(self: *HealthManager) void {
        self.stopThread();
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

    pub fn startThread(self: *HealthManager) void {
        if (self.thread_handle != null) return;
        if (self.checkers.count() == 0) return;
        self.shutdown_flag.store(false, .release);
        self.thread_handle = std.Thread.spawn(.{}, threadLoop, .{self}) catch |err| {
            std.log.warn("health: failed to spawn thread: {}", .{err});
            return;
        };
    }

    pub fn stopThread(self: *HealthManager) void {
        self.shutdown_flag.store(true, .release);
        if (self.thread_handle) |t| {
            t.join();
            self.thread_handle = null;
        }
    }

    fn threadLoop(self: *HealthManager) void {
        while (!self.shutdown_flag.load(.acquire)) {
            const now_ms = getMonotonicMs();
            var it = self.checkers.valueIterator();
            while (it.next()) |checker| {
                if (self.shutdown_flag.load(.acquire)) return;
                checker.*.runChecks(now_ms);
            }
            sleepNs(1_000_000_000);
        }
    }

    /// Apply published health states to pools (called from reactor — non-blocking).
    pub fn applyResults(self: *HealthManager, pool_manager: *pool_mod.PoolManager) void {
        var it = self.checkers.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const checker = entry.value_ptr.*;
            if (pool_manager.getPool(name)) |pool| {
                checker.applyHealthToPool(pool);
            }
        }
    }

    /// Run all health checks inline and apply results (blocking — fallback when thread not started).
    pub fn runAllChecks(self: *HealthManager, now_ms: u64, pool_manager: *pool_mod.PoolManager) void {
        var it = self.checkers.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const checker = entry.value_ptr.*;
            checker.runChecks(now_ms);
            if (pool_manager.getPool(name)) |pool| {
                checker.applyHealthToPool(pool);
            }
        }
    }

    /// Get health checker for an upstream
    pub fn getChecker(self: *HealthManager, name: []const u8) ?*HealthChecker {
        return self.checkers.get(name);
    }
};

fn getMonotonicMs() u64 {
    const instant = clock.Instant.now() orelse return 0;
    return instant.ns / @as(u64, std.time.ns_per_ms);
}

fn sleepNs(ns: u64) void {
    var ts = std.posix.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: std.posix.timespec = .{ .sec = 0, .nsec = 0 };
    while (true) {
        const rc = std.posix.system.nanosleep(&ts, &rem);
        if (rc == 0) return;
        switch (std.posix.errno(rc)) {
            .INTR => ts = rem,
            else => return,
        }
    }
}

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
