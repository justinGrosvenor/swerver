const std = @import("std");
const upstream = @import("upstream.zig");
const pool_mod = @import("pool.zig");

/// Load Balancer
///
/// Implements various load balancing strategies for selecting
/// upstream servers to handle requests.

/// Result of server selection
pub const SelectionResult = struct {
    /// Index of the selected server
    server_index: u16,
    /// The selected server configuration
    server: *const upstream.Server,
};

/// Load balancer state
pub const Balancer = struct {
    /// The upstream configuration
    upstream_def: *const upstream.Upstream,
    /// Connection pool for this upstream
    pool: *pool_mod.Pool,
    /// Round-robin counter (wraps)
    round_robin_index: u32,
    /// Weighted round-robin state
    weighted_state: WeightedState,
    /// Random number generator
    rng: std.Random.DefaultPrng,

    /// Maximum number of servers per upstream (bounds the fixed-size current_weights array).
    pub const MAX_SERVERS = 256;

    /// State for smooth weighted round-robin (nginx-style SWRR)
    pub const WeightedState = struct {
        current_weights: [MAX_SERVERS]i32 = [_]i32{0} ** MAX_SERVERS,
        max_weight: u16 = 0,
        gcd_weight: u16 = 1,
    };

    pub fn init(upstream_def: *const upstream.Upstream, conn_pool: *pool_mod.Pool) error{TooManyServers}!Balancer {
        if (upstream_def.servers.len > MAX_SERVERS) return error.TooManyServers;

        var balancer = Balancer{
            .upstream_def = upstream_def,
            .pool = conn_pool,
            .round_robin_index = 0,
            .weighted_state = .{},
            .rng = std.Random.DefaultPrng.init(0),
        };

        // Initialize weighted state if using weighted_round_robin
        if (upstream_def.load_balancer == .weighted_round_robin) {
            balancer.initWeightedState();
        }

        return balancer;
    }

    fn initWeightedState(self: *Balancer) void {
        var max_weight: u16 = 0;
        var gcd_weight: u16 = 0;

        for (self.upstream_def.servers) |server| {
            if (server.weight > max_weight) {
                max_weight = server.weight;
            }
            gcd_weight = gcd(gcd_weight, server.weight);
        }

        self.weighted_state.max_weight = max_weight;
        self.weighted_state.gcd_weight = if (gcd_weight == 0) 1 else gcd_weight;
    }

    /// Seed the RNG for consistent testing or randomized production use
    pub fn seed(self: *Balancer, seed_value: u64) void {
        self.rng = std.Random.DefaultPrng.init(seed_value);
    }

    /// Select a server based on the configured load balancing strategy
    pub fn select(self: *Balancer, client_ip: ?u32, now_ms: u64) ?SelectionResult {
        return switch (self.upstream_def.load_balancer) {
            .round_robin => self.selectRoundRobin(now_ms, false),
            .least_conn => self.selectLeastConn(now_ms),
            .ip_hash => self.selectIpHash(client_ip orelse 0, now_ms),
            .random => self.selectRandom(now_ms),
            .weighted_round_robin => self.selectRoundRobin(now_ms, true),
        };
    }

    /// Round-robin selection (optionally weighted)
    fn selectRoundRobin(self: *Balancer, now_ms: u64, weighted: bool) ?SelectionResult {
        const servers = self.upstream_def.servers;
        if (servers.len == 0) return null;

        if (weighted) {
            return self.selectWeightedRoundRobin(now_ms);
        }

        // Simple round-robin: try each server starting from current index
        const start_index = self.round_robin_index;
        var attempts: usize = 0;

        while (attempts < servers.len) {
            const index: u16 = @intCast(self.round_robin_index % servers.len);
            self.round_robin_index = (self.round_robin_index + 1) % @as(u32, @intCast(servers.len));
            attempts += 1;

            const server = &servers[index];

            // Skip backup servers unless no primary available
            if (server.backup) continue;

            // Check if server is available
            if (!self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                continue;
            }

            return .{ .server_index = index, .server = server };
        }

        // Try backup servers
        for (servers, 0..) |*server, i| {
            if (!server.backup) continue;

            const index: u16 = @intCast(i);
            if (self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                return .{ .server_index = index, .server = server };
            }
        }

        // Fallback: reset failure state and return first server
        if (servers.len > 0) {
            const index = @as(u32, @intCast(start_index % servers.len));
            return .{ .server_index = @intCast(index), .server = &servers[index] };
        }

        return null;
    }

    /// Smooth weighted round-robin (nginx-style SWRR algorithm).
    /// Each round: add effective weight to current_weight for each server,
    /// pick the server with highest current_weight, subtract total_weight from winner.
    /// With weights 3:2:1 this produces the smooth sequence: 0,1,0,2,0,1 (period 6).
    fn selectWeightedRoundRobin(self: *Balancer, now_ms: u64) ?SelectionResult {
        const servers = self.upstream_def.servers;
        if (servers.len == 0) return null;

        var best_index: ?u16 = null;
        var best_current_weight: i32 = std.math.minInt(i32);
        var total_weight: i32 = 0;

        for (servers, 0..) |server, i| {
            const index: u16 = @intCast(i);

            if (server.backup) continue;
            if (!self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) continue;

            const weight: i32 = @intCast(server.weight);
            self.weighted_state.current_weights[index] += weight;
            total_weight += weight;

            if (self.weighted_state.current_weights[index] > best_current_weight) {
                best_current_weight = self.weighted_state.current_weights[index];
                best_index = index;
            }
        }

        if (best_index) |index| {
            self.weighted_state.current_weights[index] -= total_weight;
            return .{ .server_index = index, .server = &servers[index] };
        }

        // Try backup servers
        for (servers, 0..) |*server, i| {
            if (!server.backup) continue;

            const index: u16 = @intCast(i);
            if (self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                return .{ .server_index = index, .server = server };
            }
        }

        return null;
    }

    /// Least connections: select server with fewest active connections
    fn selectLeastConn(self: *Balancer, now_ms: u64) ?SelectionResult {
        const servers = self.upstream_def.servers;
        if (servers.len == 0) return null;

        var best_index: ?u16 = null;
        var best_conn_count: u32 = std.math.maxInt(u32);
        var best_weighted_count: u64 = std.math.maxInt(u64);

        for (servers, 0..) |server, i| {
            const index: u16 = @intCast(i);

            // Skip unavailable and backup servers
            if (server.backup) continue;
            if (!self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                continue;
            }

            // Count active connections to this server
            const conn_count = self.countActiveConnections(index);

            // Weight-adjusted connection count (lower is better)
            // conn_count / weight (multiply by 1000 to avoid float)
            const weighted_count: u64 = if (server.weight > 0)
                (@as(u64, conn_count) * 1000) / server.weight
            else
                std.math.maxInt(u64);

            if (weighted_count < best_weighted_count or
                (weighted_count == best_weighted_count and conn_count < best_conn_count))
            {
                best_weighted_count = weighted_count;
                best_conn_count = conn_count;
                best_index = index;
            }
        }

        if (best_index) |index| {
            return .{ .server_index = index, .server = &servers[index] };
        }

        // Try backup servers
        for (servers, 0..) |*server, i| {
            if (!server.backup) continue;

            const index: u16 = @intCast(i);
            if (self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                return .{ .server_index = index, .server = server };
            }
        }

        return null;
    }

    /// Count active connections to a specific server
    fn countActiveConnections(self: *Balancer, server_index: u16) u32 {
        var count: u32 = 0;
        for (self.pool.connections) |maybe_conn| {
            if (maybe_conn) |conn| {
                if (conn.server_index == server_index and conn.state == .active) {
                    count += 1;
                }
            }
        }
        return count;
    }

    /// IP hash: consistent hashing based on client IP
    fn selectIpHash(self: *Balancer, client_ip: u32, now_ms: u64) ?SelectionResult {
        const servers = self.upstream_def.servers;
        if (servers.len == 0) return null;

        // Count available non-backup servers
        var available_count: u16 = 0;
        var available_indices: [256]u16 = undefined;

        for (servers, 0..) |server, i| {
            if (server.backup) continue;

            const index: u16 = @intCast(i);
            if (self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                if (available_count < 256) {
                    available_indices[available_count] = index;
                    available_count += 1;
                }
            }
        }

        if (available_count > 0) {
            // Simple hash: multiply by prime and mod
            const hash = hashIp(client_ip);
            const selected = hash % available_count;
            const index = available_indices[selected];
            return .{ .server_index = index, .server = &servers[index] };
        }

        // Try backup servers
        for (servers, 0..) |*server, i| {
            if (!server.backup) continue;

            const index: u16 = @intCast(i);
            if (self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                return .{ .server_index = index, .server = server };
            }
        }

        return null;
    }

    /// Random selection
    fn selectRandom(self: *Balancer, now_ms: u64) ?SelectionResult {
        const servers = self.upstream_def.servers;
        if (servers.len == 0) return null;

        // Collect available non-backup servers
        var available_count: u16 = 0;
        var available_indices: [256]u16 = undefined;
        var total_weight: u32 = 0;

        for (servers, 0..) |server, i| {
            if (server.backup) continue;

            const index: u16 = @intCast(i);
            if (self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                if (available_count < 256) {
                    available_indices[available_count] = index;
                    available_count += 1;
                    total_weight += server.weight;
                }
            }
        }

        if (available_count > 0) {
            // Weighted random selection
            if (total_weight > 0) {
                var target = self.rng.random().intRangeAtMost(u32, 1, total_weight);
                for (available_indices[0..available_count]) |index| {
                    const weight = servers[index].weight;
                    if (target <= weight) {
                        return .{ .server_index = index, .server = &servers[index] };
                    }
                    target -= weight;
                }
            }

            // Fallback to uniform random if weights are zero
            const selected = self.rng.random().intRangeLessThan(u16, 0, available_count);
            const index = available_indices[selected];
            return .{ .server_index = index, .server = &servers[index] };
        }

        // Try backup servers
        for (servers, 0..) |*server, i| {
            if (!server.backup) continue;

            const index: u16 = @intCast(i);
            if (self.pool.isServerAvailable(index, now_ms, server.fail_timeout_ms)) {
                return .{ .server_index = index, .server = server };
            }
        }

        return null;
    }
};

/// Hash an IPv4 address for consistent hashing
fn hashIp(ip: u32) u16 {
    // FNV-1a inspired hash for good distribution
    var hash: u32 = 2166136261;
    hash ^= (ip >> 24) & 0xFF;
    hash *%= 16777619;
    hash ^= (ip >> 16) & 0xFF;
    hash *%= 16777619;
    hash ^= (ip >> 8) & 0xFF;
    hash *%= 16777619;
    hash ^= ip & 0xFF;
    hash *%= 16777619;
    return @truncate(hash);
}

/// Calculate GCD using Euclidean algorithm
fn gcd(a: u16, b: u16) u16 {
    if (a == 0) return b;
    if (b == 0) return a;

    var x = a;
    var y = b;
    while (y != 0) {
        const t = y;
        y = x % y;
        x = t;
    }
    return x;
}

// Tests
test "round robin selection" {
    const allocator = std.testing.allocator;

    const servers = [_]upstream.Server{
        .{ .address = "10.0.0.1", .port = 8080 },
        .{ .address = "10.0.0.2", .port = 8080 },
        .{ .address = "10.0.0.3", .port = 8080 },
    };

    const upstream_def = upstream.Upstream{
        .name = "test",
        .servers = &servers,
        .load_balancer = .round_robin,
    };

    var conn_pool = try pool_mod.Pool.init(allocator, upstream_def.connection_pool, servers.len);
    defer conn_pool.deinit();

    var balancer = try Balancer.init(&upstream_def, &conn_pool);

    // Should cycle through servers
    const s1 = balancer.select(null, 0);
    try std.testing.expect(s1 != null);
    try std.testing.expectEqual(@as(u16, 0), s1.?.server_index);

    const s2 = balancer.select(null, 0);
    try std.testing.expect(s2 != null);
    try std.testing.expectEqual(@as(u16, 1), s2.?.server_index);

    const s3 = balancer.select(null, 0);
    try std.testing.expect(s3 != null);
    try std.testing.expectEqual(@as(u16, 2), s3.?.server_index);

    // Wraps around
    const s4 = balancer.select(null, 0);
    try std.testing.expect(s4 != null);
    try std.testing.expectEqual(@as(u16, 0), s4.?.server_index);
}

test "ip hash consistent selection" {
    const allocator = std.testing.allocator;

    const servers = [_]upstream.Server{
        .{ .address = "10.0.0.1", .port = 8080 },
        .{ .address = "10.0.0.2", .port = 8080 },
        .{ .address = "10.0.0.3", .port = 8080 },
    };

    const upstream_def = upstream.Upstream{
        .name = "test",
        .servers = &servers,
        .load_balancer = .ip_hash,
    };

    var conn_pool = try pool_mod.Pool.init(allocator, upstream_def.connection_pool, servers.len);
    defer conn_pool.deinit();

    var balancer = try Balancer.init(&upstream_def, &conn_pool);

    const client_ip: u32 = 0xC0A80001; // 192.168.0.1

    // Same IP should always select same server
    const s1 = balancer.select(client_ip, 0);
    const s2 = balancer.select(client_ip, 0);
    const s3 = balancer.select(client_ip, 0);

    try std.testing.expect(s1 != null);
    try std.testing.expect(s2 != null);
    try std.testing.expect(s3 != null);
    try std.testing.expectEqual(s1.?.server_index, s2.?.server_index);
    try std.testing.expectEqual(s2.?.server_index, s3.?.server_index);
}

test "backup server fallback" {
    const allocator = std.testing.allocator;

    const servers = [_]upstream.Server{
        .{ .address = "10.0.0.1", .port = 8080 },
        .{ .address = "10.0.0.99", .port = 8080, .backup = true },
    };

    const upstream_def = upstream.Upstream{
        .name = "test",
        .servers = &servers,
        .load_balancer = .round_robin,
    };

    var conn_pool = try pool_mod.Pool.init(allocator, upstream_def.connection_pool, servers.len);
    defer conn_pool.deinit();

    var balancer = try Balancer.init(&upstream_def, &conn_pool);

    // Primary available - should select primary
    const s1 = balancer.select(null, 0);
    try std.testing.expect(s1 != null);
    try std.testing.expectEqual(@as(u16, 0), s1.?.server_index);
    try std.testing.expect(!s1.?.server.backup);

    // Mark primary as unavailable
    conn_pool.server_failures[0].available = false;
    conn_pool.server_failures[0].last_failure_ms = 1000;

    // Should fall back to backup
    const s2 = balancer.select(null, 2000);
    try std.testing.expect(s2 != null);
    try std.testing.expectEqual(@as(u16, 1), s2.?.server_index);
    try std.testing.expect(s2.?.server.backup);
}

test "hashIp distribution" {
    // Test that different IPs produce different hashes
    const ip1 = hashIp(0xC0A80001); // 192.168.0.1
    const ip2 = hashIp(0xC0A80002); // 192.168.0.2
    const ip3 = hashIp(0x0A000001); // 10.0.0.1

    try std.testing.expect(ip1 != ip2);
    try std.testing.expect(ip2 != ip3);
    try std.testing.expect(ip1 != ip3);
}

test "gcd calculation" {
    try std.testing.expectEqual(@as(u16, 5), gcd(10, 15));
    try std.testing.expectEqual(@as(u16, 1), gcd(7, 13));
    try std.testing.expectEqual(@as(u16, 6), gcd(12, 18));
    try std.testing.expectEqual(@as(u16, 4), gcd(0, 4));
    try std.testing.expectEqual(@as(u16, 4), gcd(4, 0));
}

test "smooth weighted round-robin distribution" {
    const allocator = std.testing.allocator;

    const servers = [_]upstream.Server{
        .{ .address = "10.0.0.1", .port = 8080, .weight = 3 },
        .{ .address = "10.0.0.2", .port = 8080, .weight = 2 },
        .{ .address = "10.0.0.3", .port = 8080, .weight = 1 },
    };

    const upstream_def = upstream.Upstream{
        .name = "test",
        .servers = &servers,
        .load_balancer = .weighted_round_robin,
    };

    var conn_pool = try pool_mod.Pool.init(allocator, upstream_def.connection_pool, servers.len);
    defer conn_pool.deinit();

    var balancer = try Balancer.init(&upstream_def, &conn_pool);

    // Run 6 selections (one full cycle for weights 3:2:1)
    var counts = [_]u32{ 0, 0, 0 };
    for (0..6) |_| {
        const result = balancer.select(null, 0);
        try std.testing.expect(result != null);
        counts[result.?.server_index] += 1;
    }

    // Server 0 (weight 3) should be selected 3 times
    try std.testing.expectEqual(@as(u32, 3), counts[0]);
    // Server 1 (weight 2) should be selected 2 times
    try std.testing.expectEqual(@as(u32, 2), counts[1]);
    // Server 2 (weight 1) should be selected 1 time
    try std.testing.expectEqual(@as(u32, 1), counts[2]);
}
