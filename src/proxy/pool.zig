const std = @import("std");
const upstream = @import("upstream.zig");
const clock = @import("../runtime/clock.zig");

/// Upstream Connection Pool
///
/// Manages persistent connections to upstream servers for efficient
/// request forwarding. Supports connection reuse, idle timeouts,
/// and per-upstream limits.

/// State of an upstream connection
pub const ConnectionState = enum {
    /// Connection establishment in progress
    connecting,
    /// Connection available for use
    idle,
    /// Connection currently handling a request
    active,
    /// Connection being gracefully closed (HTTP/2 GOAWAY received)
    draining,
    /// Connection has failed
    failed,
};

/// Protocol for upstream communication
pub const UpstreamProtocol = enum {
    http1,
    http2,
};

/// A single connection to an upstream server
pub const UpstreamConnection = struct {
    /// File descriptor for the socket
    fd: std.posix.fd_t,
    /// Index of the server in the upstream's server list
    server_index: u16,
    /// Current state of this connection
    state: ConnectionState,
    /// Protocol negotiated with upstream
    protocol: UpstreamProtocol,
    /// Timestamp when connection was created (ms)
    created_ms: u64,
    /// Timestamp of last activity (ms)
    last_used_ms: u64,
    /// Number of requests served on this connection
    requests_served: u32,
    /// Position in the pool's connection list
    pool_index: u32,
    /// For HTTP/2: current stream count
    active_streams: u16,
    /// For HTTP/2: max concurrent streams from SETTINGS
    max_streams: u16,

    pub fn init(fd: std.posix.fd_t, server_index: u16, now_ms: u64, pool_index: u32) UpstreamConnection {
        return .{
            .fd = fd,
            .server_index = server_index,
            .state = .connecting,
            .protocol = .http1,
            .created_ms = now_ms,
            .last_used_ms = now_ms,
            .requests_served = 0,
            .pool_index = pool_index,
            .active_streams = 0,
            .max_streams = 100, // Default, updated by SETTINGS
        };
    }

    /// Check if connection is available for a new request
    pub fn isAvailable(self: *const UpstreamConnection) bool {
        return switch (self.state) {
            .idle => true,
            // HTTP/2 connections can handle multiple concurrent streams
            .active => self.protocol == .http2 and self.active_streams < self.max_streams,
            else => false,
        };
    }

    /// Check if connection has expired due to idle timeout
    pub fn isIdleExpired(self: *const UpstreamConnection, now_ms: u64, idle_timeout_ms: u32) bool {
        if (self.state != .idle) return false;
        return now_ms >= self.last_used_ms + idle_timeout_ms;
    }

    /// Mark connection as active for a new request
    pub fn acquire(self: *UpstreamConnection, now_ms: u64) void {
        self.state = .active;
        self.last_used_ms = now_ms;
        if (self.protocol == .http2) {
            self.active_streams += 1;
        }
    }

    /// Release connection back to pool after request completes
    pub fn release(self: *UpstreamConnection, now_ms: u64, keep_alive: bool) void {
        self.last_used_ms = now_ms;
        self.requests_served += 1;

        if (self.protocol == .http2) {
            if (self.active_streams > 0) {
                self.active_streams -= 1;
            }
            // HTTP/2 connection stays active if streams remain
            if (self.active_streams == 0 and self.state != .draining) {
                self.state = .idle;
            }
        } else {
            // HTTP/1.1: return to idle if keep-alive, otherwise mark for closure
            self.state = if (keep_alive) .idle else .draining;
        }
    }

    /// Mark connection as failed
    pub fn markFailed(self: *UpstreamConnection) void {
        self.state = .failed;
    }

    /// Mark connection as draining (no new requests, finish existing)
    pub fn markDraining(self: *UpstreamConnection) void {
        self.state = .draining;
    }
};

/// Pool of connections for a single upstream group
pub const Pool = struct {
    allocator: std.mem.Allocator,
    /// Configuration for this upstream
    config: upstream.PoolConfig,
    /// All connection slots
    connections: []?UpstreamConnection,
    /// Number of active (non-null) connections
    connection_count: u32,
    /// Number of idle connections
    idle_count: u32,
    /// Round-robin index for connection selection
    next_index: u32,
    /// Timestamps for server failure tracking
    server_failures: []ServerFailureState,

    /// Tracks failure state for passive health checks
    pub const ServerFailureState = struct {
        consecutive_failures: u16 = 0,
        last_failure_ms: u64 = 0,
        available: bool = true,
    };

    pub fn init(allocator: std.mem.Allocator, config: upstream.PoolConfig, server_count: usize) !Pool {
        const connections = try allocator.alloc(?UpstreamConnection, config.max_connections);
        errdefer allocator.free(connections);
        @memset(connections, null);

        const server_failures = try allocator.alloc(ServerFailureState, server_count);
        @memset(server_failures, ServerFailureState{});

        return .{
            .allocator = allocator,
            .config = config,
            .connections = connections,
            .connection_count = 0,
            .idle_count = 0,
            .next_index = 0,
            .server_failures = server_failures,
        };
    }

    pub fn deinit(self: *Pool) void {
        // Close any remaining connections
        for (self.connections) |maybe_conn| {
            if (maybe_conn) |conn| {
                // Only close valid file descriptors
                if (conn.fd >= 0) {
                    clock.closeFd(conn.fd);
                }
            }
        }
        self.allocator.free(self.connections);
        self.allocator.free(self.server_failures);
    }

    /// Acquire an available connection to the specified server.
    /// Returns null if no connection available and pool is at max capacity.
    pub fn acquireForServer(self: *Pool, server_index: u16, now_ms: u64) ?*UpstreamConnection {
        // First, try to find an existing idle connection to this server
        for (self.connections) |*maybe_conn| {
            if (maybe_conn.*) |*conn| {
                if (conn.server_index == server_index and conn.isAvailable()) {
                    // Track if was idle BEFORE acquire changes state
                    const was_idle = conn.state == .idle;
                    conn.acquire(now_ms);
                    if (was_idle) {
                        self.idle_count -= 1;
                    }
                    return conn;
                }
            }
        }

        // No available connection found
        return null;
    }

    /// Find a free slot and reserve it for a new connection
    pub fn reserveSlot(self: *Pool) ?u32 {
        if (self.connection_count >= self.config.max_connections) {
            return null;
        }

        // Find first null slot
        for (self.connections, 0..) |maybe_conn, i| {
            if (maybe_conn == null) {
                return @intCast(i);
            }
        }
        return null;
    }

    /// Add a newly established connection to the pool
    pub fn addConnection(self: *Pool, slot: u32, conn: UpstreamConnection) void {
        self.connections[slot] = conn;
        self.connection_count += 1;
        if (conn.state == .idle) {
            self.idle_count += 1;
        }
    }

    /// Release a connection back to the pool
    pub fn release(self: *Pool, conn: *UpstreamConnection, now_ms: u64, keep_alive: bool) void {
        const was_active = conn.state == .active;
        conn.release(now_ms, keep_alive);

        if (conn.state == .idle) {
            if (was_active) {
                self.idle_count += 1;
            }
            // Check if we have too many idle connections
            if (self.idle_count > self.config.max_idle) {
                // Close this connection instead of keeping it
                self.removeConnection(conn);
            }
        } else if (conn.state == .draining) {
            // Connection should be closed
            if (conn.protocol == .http1 or conn.active_streams == 0) {
                self.removeConnection(conn);
            }
        }
    }

    /// Remove a connection from the pool and close it
    pub fn removeConnection(self: *Pool, conn: *UpstreamConnection) void {
        const index = conn.pool_index;
        if (conn.state == .idle) {
            self.idle_count -= 1;
        }
        // Only close valid file descriptors
        if (conn.fd >= 0) {
            clock.closeFd(conn.fd);
        }
        self.connections[index] = null;
        self.connection_count -= 1;
    }

    /// Mark a connection as failed and update server failure tracking
    pub fn markConnectionFailed(self: *Pool, conn: *UpstreamConnection, now_ms: u64, max_fails: u16) void {
        conn.markFailed();

        // Update server failure state
        if (conn.server_index < self.server_failures.len) {
            var state = &self.server_failures[conn.server_index];
            state.consecutive_failures += 1;
            state.last_failure_ms = now_ms;

            if (state.consecutive_failures >= max_fails) {
                state.available = false;
            }
        }

        self.removeConnection(conn);
    }

    /// Record a successful request to a server (resets failure counter)
    pub fn markServerSuccess(self: *Pool, server_index: u16) void {
        if (server_index < self.server_failures.len) {
            self.server_failures[server_index].consecutive_failures = 0;
            self.server_failures[server_index].available = true;
        }
    }

    /// Check if a server is available (not marked as failed)
    pub fn isServerAvailable(self: *Pool, server_index: u16, now_ms: u64, fail_timeout_ms: u32) bool {
        if (server_index >= self.server_failures.len) return false;

        const state = &self.server_failures[server_index];
        if (state.available) return true;

        // Check if failure timeout has elapsed (server can be retried)
        if (now_ms >= state.last_failure_ms + fail_timeout_ms) {
            state.available = true;
            state.consecutive_failures = 0;
            return true;
        }

        return false;
    }

    /// Evict expired idle connections
    pub fn evictExpired(self: *Pool, now_ms: u64) u32 {
        var evicted: u32 = 0;

        for (self.connections) |*maybe_conn| {
            if (maybe_conn.*) |*conn| {
                if (conn.isIdleExpired(now_ms, self.config.idle_timeout_ms)) {
                    self.removeConnection(conn);
                    evicted += 1;
                }
            }
        }

        return evicted;
    }

    /// Get count of connections by state
    pub fn getStats(self: *const Pool) PoolStats {
        var stats = PoolStats{};

        for (self.connections) |maybe_conn| {
            if (maybe_conn) |conn| {
                switch (conn.state) {
                    .connecting => stats.connecting += 1,
                    .idle => stats.idle += 1,
                    .active => stats.active += 1,
                    .draining => stats.draining += 1,
                    .failed => {}, // Should be removed immediately
                }
            }
        }

        return stats;
    }
};

/// Statistics for a connection pool
pub const PoolStats = struct {
    connecting: u32 = 0,
    idle: u32 = 0,
    active: u32 = 0,
    draining: u32 = 0,
};

/// Manager for all upstream connection pools
pub const PoolManager = struct {
    allocator: std.mem.Allocator,
    /// Map of upstream name to pool
    pools: std.StringHashMap(*Pool),

    pub fn init(allocator: std.mem.Allocator) PoolManager {
        return .{
            .allocator = allocator,
            .pools = std.StringHashMap(*Pool).init(allocator),
        };
    }

    pub fn deinit(self: *PoolManager) void {
        var it = self.pools.valueIterator();
        while (it.next()) |pool| {
            pool.*.deinit();
            self.allocator.destroy(pool.*);
        }
        self.pools.deinit();
    }

    /// Get or create a pool for an upstream
    pub fn getOrCreatePool(
        self: *PoolManager,
        upstream_def: *const upstream.Upstream,
    ) !*Pool {
        if (self.pools.get(upstream_def.name)) |pool| {
            return pool;
        }

        const pool = try self.allocator.create(Pool);
        errdefer self.allocator.destroy(pool);

        pool.* = try Pool.init(
            self.allocator,
            upstream_def.connection_pool,
            upstream_def.servers.len,
        );
        errdefer pool.deinit();

        try self.pools.put(upstream_def.name, pool);
        return pool;
    }

    /// Get an existing pool by name
    pub fn getPool(self: *PoolManager, name: []const u8) ?*Pool {
        return self.pools.get(name);
    }

    /// Evict expired connections from all pools
    pub fn evictAllExpired(self: *PoolManager, now_ms: u64) u32 {
        var total_evicted: u32 = 0;
        var it = self.pools.valueIterator();
        while (it.next()) |pool| {
            total_evicted += pool.*.evictExpired(now_ms);
        }
        return total_evicted;
    }

    /// Get aggregate stats across all pools
    pub fn getAggregateStats(self: *const PoolManager) PoolStats {
        var stats = PoolStats{};
        var it = self.pools.valueIterator();
        while (it.next()) |pool| {
            const pool_stats = pool.*.getStats();
            stats.connecting += pool_stats.connecting;
            stats.idle += pool_stats.idle;
            stats.active += pool_stats.active;
            stats.draining += pool_stats.draining;
        }
        return stats;
    }
};

/// Error for connection operations
pub const ConnectError = error{
    NoAvailableServer,
    PoolFull,
    ConnectFailed,
    Timeout,
};

// Tests
test "Pool basic operations" {
    const allocator = std.testing.allocator;

    const config = upstream.PoolConfig{
        .max_connections = 4,
        .max_idle = 2,
        .idle_timeout_ms = 60_000,
        .connect_timeout_ms = 5_000,
    };

    var pool = try Pool.init(allocator, config, 2);
    defer pool.deinit();

    // Reserve a slot
    const slot = pool.reserveSlot();
    try std.testing.expect(slot != null);
    try std.testing.expectEqual(@as(u32, 0), slot.?);

    // Add a connection
    const conn = UpstreamConnection.init(-1, 0, 1000, slot.?);
    pool.addConnection(slot.?, conn);
    try std.testing.expectEqual(@as(u32, 1), pool.connection_count);
}

test "Pool server availability tracking" {
    const allocator = std.testing.allocator;

    const config = upstream.PoolConfig{};
    var pool = try Pool.init(allocator, config, 2);
    defer pool.deinit();

    // Server starts available
    try std.testing.expect(pool.isServerAvailable(0, 0, 30_000));

    // Mark failures
    pool.server_failures[0].consecutive_failures = 3;
    pool.server_failures[0].last_failure_ms = 1000;
    pool.server_failures[0].available = false;

    // Server unavailable
    try std.testing.expect(!pool.isServerAvailable(0, 2000, 30_000));

    // Server available after timeout
    try std.testing.expect(pool.isServerAvailable(0, 35_000, 30_000));
}

test "UpstreamConnection availability" {
    var conn = UpstreamConnection.init(-1, 0, 1000, 0);

    // Connecting state is not available
    try std.testing.expect(!conn.isAvailable());

    // Idle is available
    conn.state = .idle;
    try std.testing.expect(conn.isAvailable());

    // Active HTTP/1.1 is not available
    conn.state = .active;
    conn.protocol = .http1;
    try std.testing.expect(!conn.isAvailable());

    // Active HTTP/2 with capacity is available
    conn.protocol = .http2;
    conn.active_streams = 1;
    conn.max_streams = 100;
    try std.testing.expect(conn.isAvailable());

    // Active HTTP/2 at capacity is not available
    conn.active_streams = 100;
    try std.testing.expect(!conn.isAvailable());
}

test "Pool idle eviction" {
    const allocator = std.testing.allocator;

    const config = upstream.PoolConfig{
        .max_connections = 4,
        .max_idle = 4,
        .idle_timeout_ms = 1000,
        .connect_timeout_ms = 5_000,
    };

    var pool = try Pool.init(allocator, config, 1);
    defer pool.deinit();

    // Add an idle connection
    const slot = pool.reserveSlot().?;
    var conn = UpstreamConnection.init(-1, 0, 0, slot);
    conn.state = .idle;
    pool.addConnection(slot, conn);
    pool.idle_count = 1;

    // Not expired yet
    const evicted_early = pool.evictExpired(500);
    try std.testing.expectEqual(@as(u32, 0), evicted_early);
    try std.testing.expectEqual(@as(u32, 1), pool.connection_count);

    // Expired
    const evicted = pool.evictExpired(2000);
    try std.testing.expectEqual(@as(u32, 1), evicted);
    try std.testing.expectEqual(@as(u32, 0), pool.connection_count);
}
