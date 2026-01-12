const std = @import("std");
const upstream = @import("upstream.zig");
const pool_mod = @import("pool.zig");
const balancer = @import("balancer.zig");
const forward = @import("forward.zig");
const health = @import("health.zig");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("../middleware/middleware.zig");
const router = @import("../router/router.zig");

/// Reverse Proxy Handler
///
/// Main entry point for proxying requests to upstream servers.
/// Handles route matching, server selection, request forwarding,
/// response streaming, and retry logic.

/// Proxy configuration
pub const ProxyConfig = struct {
    /// All configured upstreams
    upstreams: []const upstream.Upstream,
    /// All proxy routes
    routes: []const upstream.ProxyRoute,
    /// Default retry configuration
    default_retry: upstream.RetryConfig = .{},
    /// Default timeouts
    default_timeouts: upstream.ProxyTimeouts = .{},
};

/// Proxy handler state
pub const Proxy = struct {
    allocator: std.mem.Allocator,
    /// Configuration
    config: ProxyConfig,
    /// Connection pools for each upstream
    pool_manager: pool_mod.PoolManager,
    /// Load balancers for each upstream
    balancers: std.StringHashMap(*balancer.Balancer),
    /// Health managers for each upstream
    health_manager: health.HealthManager,
    /// Upstream definitions by name for lookup
    upstreams_by_name: std.StringHashMap(*const upstream.Upstream),
    /// Request buffer pool
    request_bufs: [][REQUEST_BUF_SIZE]u8,
    /// Response buffer pool
    response_bufs: [][RESPONSE_BUF_SIZE]u8,
    /// Free buffer index stack
    free_request_stack: []usize,
    free_response_stack: []usize,
    /// Number of free buffers
    free_request_count: usize,
    free_response_count: usize,

    const REQUEST_BUF_SIZE = 8192;
    const RESPONSE_BUF_SIZE = 65536;
    const BUFFER_POOL_SIZE = 64;

    pub fn init(allocator: std.mem.Allocator, config: ProxyConfig) !Proxy {
        // Use a helper struct to manage partial initialization cleanup
        // This avoids double-free issues with errdefer + defer combinations
        return initImpl(allocator, config) catch |err| {
            return err;
        };
    }

    fn initImpl(allocator: std.mem.Allocator, config: ProxyConfig) !Proxy {
        // Phase 1: Allocate buffers with proper cleanup on partial failure
        const free_request_stack = try allocator.alloc(usize, BUFFER_POOL_SIZE);
        errdefer allocator.free(free_request_stack);

        const free_response_stack = try allocator.alloc(usize, BUFFER_POOL_SIZE);
        errdefer allocator.free(free_response_stack);

        const request_bufs = try allocator.alloc([REQUEST_BUF_SIZE]u8, BUFFER_POOL_SIZE);
        errdefer allocator.free(request_bufs);

        const response_bufs = try allocator.alloc([RESPONSE_BUF_SIZE]u8, BUFFER_POOL_SIZE);
        errdefer allocator.free(response_bufs);

        // Initialize free stacks with all indices
        for (0..BUFFER_POOL_SIZE) |i| {
            free_request_stack[i] = BUFFER_POOL_SIZE - 1 - i;
            free_response_stack[i] = BUFFER_POOL_SIZE - 1 - i;
        }

        // Phase 2: Create proxy with empty upstream registrations
        var proxy = Proxy{
            .allocator = allocator,
            .config = config,
            .pool_manager = pool_mod.PoolManager.init(allocator),
            .balancers = std.StringHashMap(*balancer.Balancer).init(allocator),
            .health_manager = health.HealthManager.init(allocator),
            .upstreams_by_name = std.StringHashMap(*const upstream.Upstream).init(allocator),
            .request_bufs = request_bufs,
            .response_bufs = response_bufs,
            .free_request_stack = free_request_stack,
            .free_response_stack = free_response_stack,
            .free_request_count = BUFFER_POOL_SIZE,
            .free_response_count = BUFFER_POOL_SIZE,
        };

        // Phase 3: Register upstreams - use errdefer to cleanup proxy internals only
        // Note: The buffer errdefers above handle the allocations.
        // We only need to clean up what the proxy's managers created.
        errdefer {
            // Clean up balancers that were added
            var bal_it = proxy.balancers.valueIterator();
            while (bal_it.next()) |bal| {
                allocator.destroy(bal.*);
            }
            proxy.balancers.deinit();
            proxy.upstreams_by_name.deinit();
            proxy.pool_manager.deinit();
            proxy.health_manager.deinit();
        }

        for (config.upstreams) |*up| {
            try proxy.upstreams_by_name.put(up.name, up);

            // Create connection pool
            const pool = try proxy.pool_manager.getOrCreatePool(up);

            // Create load balancer
            const bal = try allocator.create(balancer.Balancer);
            errdefer allocator.destroy(bal);

            bal.* = balancer.Balancer.init(up, pool);
            try proxy.balancers.put(up.name, bal);

            // Register for health checking
            try proxy.health_manager.registerUpstream(up);
        }

        return proxy;
    }

    pub fn deinit(self: *Proxy) void {
        // Clean up balancers
        var bal_it = self.balancers.valueIterator();
        while (bal_it.next()) |bal| {
            self.allocator.destroy(bal.*);
        }
        self.balancers.deinit();

        self.upstreams_by_name.deinit();
        self.pool_manager.deinit();
        self.health_manager.deinit();

        self.allocator.free(self.free_request_stack);
        self.allocator.free(self.free_response_stack);
        self.allocator.free(self.request_bufs);
        self.allocator.free(self.response_bufs);
    }

    /// Find a matching proxy route for a request
    pub fn matchRoute(self: *const Proxy, req: *const request.RequestView) ?*const upstream.ProxyRoute {
        for (self.config.routes) |*route| {
            // Check host match if configured
            if (route.host) |expected_host| {
                const req_host = req.getHeader("Host") orelse continue;
                if (!std.mem.eql(u8, req_host, expected_host)) continue;
            }

            // Check path prefix
            if (std.mem.startsWith(u8, req.path, route.path_prefix)) {
                return route;
            }
        }
        return null;
    }

    /// Handle a proxy request
    pub fn handle(
        self: *Proxy,
        req: request.RequestView,
        mw_ctx: *middleware.Context,
        client_ip: ?[]const u8,
        client_tls: bool,
        now_ms: u64,
    ) router.RouteResult {
        // Find matching route
        const route = self.matchRoute(&req) orelse {
            return .{ .resp = forward.createErrorResponse(502) };
        };

        // Get upstream configuration
        const upstream_def = self.upstreams_by_name.get(route.upstream) orelse {
            return .{ .resp = forward.createErrorResponse(502) };
        };

        // Get balancer and pool
        const bal = self.balancers.get(route.upstream) orelse {
            return .{ .resp = forward.createErrorResponse(502) };
        };

        const pool = self.pool_manager.getPool(route.upstream) orelse {
            return .{ .resp = forward.createErrorResponse(502) };
        };

        // Acquire buffers
        const req_buf_idx = self.acquireRequestBuffer() orelse {
            return .{ .resp = forward.createErrorResponse(503) };
        };
        defer self.releaseRequestBuffer(req_buf_idx);

        const resp_buf_idx = self.acquireResponseBuffer() orelse {
            return .{ .resp = forward.createErrorResponse(503) };
        };
        defer self.releaseResponseBuffer(resp_buf_idx);

        // Get client IP as u32 for IP hash (simplified)
        const client_ip_u32: ?u32 = if (client_ip) |ip| parseIpToU32(ip) else null;

        // Retry loop
        const retry_config = route.retry;
        var attempts: u8 = 0;
        const max_attempts = retry_config.max_retries + 1;

        while (attempts < max_attempts) {
            attempts += 1;

            // Select upstream server
            const selection = bal.select(client_ip_u32, now_ms) orelse {
                // No healthy servers available
                return .{ .resp = forward.createErrorResponse(502) };
            };

            // Try to get an existing connection or create a new one
            var conn = pool.acquireForServer(selection.server_index, now_ms);

            if (conn == null) {
                // Need to create new connection
                const slot = pool.reserveSlot() orelse {
                    // Pool is full, try another server or fail
                    if (attempts < max_attempts) continue;
                    return .{ .resp = forward.createErrorResponse(503) };
                };

                // In production, we would actually connect here.
                // For now, simulate by creating a placeholder connection.
                // Real implementation would integrate with the event loop.
                const new_conn = pool_mod.UpstreamConnection.init(
                    -1, // Placeholder fd
                    selection.server_index,
                    now_ms,
                    slot,
                );
                pool.addConnection(slot, new_conn);
                conn = pool.acquireForServer(selection.server_index, now_ms);
            }

            if (conn) |c| {
                // Build forward context
                const ctx = forward.ForwardContext{
                    .client_request = req,
                    .client_ip = client_ip,
                    .client_tls = client_tls,
                    .route = route,
                    .server = selection.server,
                    .upstream_conn = c,
                    .request_buf = &self.request_bufs[req_buf_idx],
                    .response_buf = &self.response_bufs[resp_buf_idx],
                };

                // Build upstream request
                const request_len = forward.buildUpstreamRequest(&self.request_bufs[req_buf_idx], &ctx) catch {
                    pool.markConnectionFailed(c, now_ms, selection.server.max_fails);
                    continue;
                };

                // In production: send request, receive response
                // For now, simulate success
                _ = request_len;
                _ = mw_ctx;
                _ = upstream_def;

                // Record success
                pool.markServerSuccess(selection.server_index);
                pool.release(c, now_ms, true);

                // Return simulated success response
                // In production, this would be the parsed upstream response
                return .{
                    .resp = .{
                        .status = 200,
                        .headers = &[_]response.Header{},
                        .body = "Proxy response placeholder",
                    },
                };
            }
        }

        // All retries exhausted
        return .{ .resp = forward.createErrorResponse(502) };
    }

    /// Run periodic maintenance tasks
    pub fn runMaintenance(self: *Proxy, now_ms: u64) void {
        // Evict expired connections
        _ = self.pool_manager.evictAllExpired(now_ms);

        // Run health checks
        self.health_manager.runAllChecks(now_ms, &self.pool_manager);
    }

    /// Get proxy statistics
    pub fn getStats(self: *const Proxy) ProxyStats {
        const pool_stats = self.pool_manager.getAggregateStats();
        return .{
            .active_connections = pool_stats.active,
            .idle_connections = pool_stats.idle,
            .connecting = pool_stats.connecting,
            .draining = pool_stats.draining,
            .upstreams = @intCast(self.config.upstreams.len),
            .routes = @intCast(self.config.routes.len),
        };
    }

    fn acquireRequestBuffer(self: *Proxy) ?usize {
        if (self.free_request_count == 0) return null;
        self.free_request_count -= 1;
        return self.free_request_stack[self.free_request_count];
    }

    fn releaseRequestBuffer(self: *Proxy, idx: usize) void {
        if (self.free_request_count < BUFFER_POOL_SIZE) {
            self.free_request_stack[self.free_request_count] = idx;
            self.free_request_count += 1;
        }
    }

    fn acquireResponseBuffer(self: *Proxy) ?usize {
        if (self.free_response_count == 0) return null;
        self.free_response_count -= 1;
        return self.free_response_stack[self.free_response_count];
    }

    fn releaseResponseBuffer(self: *Proxy, idx: usize) void {
        if (self.free_response_count < BUFFER_POOL_SIZE) {
            self.free_response_stack[self.free_response_count] = idx;
            self.free_response_count += 1;
        }
    }
};

/// Proxy statistics
pub const ProxyStats = struct {
    active_connections: u32,
    idle_connections: u32,
    connecting: u32,
    draining: u32,
    upstreams: u16,
    routes: u16,
};

/// Parse IPv4 string to u32
fn parseIpToU32(ip: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var part_idx: usize = 0;

    var it = std.mem.splitScalar(u8, ip, '.');
    while (it.next()) |part| {
        if (part_idx >= 4) return null;
        parts[part_idx] = std.fmt.parseInt(u8, part, 10) catch return null;
        part_idx += 1;
    }

    if (part_idx != 4) return null;

    return (@as(u32, parts[0]) << 24) |
        (@as(u32, parts[1]) << 16) |
        (@as(u32, parts[2]) << 8) |
        @as(u32, parts[3]);
}

/// Create a proxy handler function for use with router
pub fn createProxyHandler(proxy: *Proxy) router.HandlerFn {
    // Note: In practice, we'd need a way to pass the proxy instance
    // to the handler. This would typically use a closure or context.
    // For now, return a placeholder handler.
    _ = proxy;
    return struct {
        fn handler(ctx: *router.HandlerContext) response.Response {
            // In production, this would access the proxy instance
            // and call proxy.handle()
            _ = ctx;
            return .{
                .status = 502,
                .headers = &[_]response.Header{},
                .body = "Proxy not configured",
            };
        }
    }.handler;
}

// Tests
test "parseIpToU32" {
    const ip1 = parseIpToU32("192.168.1.1");
    try std.testing.expect(ip1 != null);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), ip1.?);

    const ip2 = parseIpToU32("10.0.0.1");
    try std.testing.expect(ip2 != null);
    try std.testing.expectEqual(@as(u32, 0x0A000001), ip2.?);

    // Invalid IPs
    try std.testing.expect(parseIpToU32("invalid") == null);
    try std.testing.expect(parseIpToU32("192.168.1") == null);
    try std.testing.expect(parseIpToU32("192.168.1.1.1") == null);
}

test "Proxy route matching" {
    const routes = [_]upstream.ProxyRoute{
        .{
            .path_prefix = "/api/v1/",
            .upstream = "api_v1",
        },
        .{
            .path_prefix = "/api/v2/",
            .upstream = "api_v2",
        },
        .{
            .path_prefix = "/",
            .host = "example.com",
            .upstream = "default",
        },
    };

    const config = ProxyConfig{
        .upstreams = &.{},
        .routes = &routes,
    };

    // Create minimal proxy for testing route matching
    const allocator = std.testing.allocator;
    var proxy = Proxy{
        .allocator = allocator,
        .config = config,
        .pool_manager = pool_mod.PoolManager.init(allocator),
        .balancers = std.StringHashMap(*balancer.Balancer).init(allocator),
        .health_manager = health.HealthManager.init(allocator),
        .upstreams_by_name = std.StringHashMap(*const upstream.Upstream).init(allocator),
        .request_bufs = &.{},
        .response_bufs = &.{},
        .free_request_stack = &.{},
        .free_response_stack = &.{},
        .free_request_count = 0,
        .free_response_count = 0,
    };
    defer {
        proxy.pool_manager.deinit();
        proxy.balancers.deinit();
        proxy.health_manager.deinit();
        proxy.upstreams_by_name.deinit();
    }

    // Test /api/v1/ matching
    const req1 = request.RequestView{
        .method = .GET,
        .path = "/api/v1/users",
        .headers = &.{},
        .body = "",
    };
    const match1 = proxy.matchRoute(&req1);
    try std.testing.expect(match1 != null);
    try std.testing.expectEqualStrings("api_v1", match1.?.upstream);

    // Test /api/v2/ matching
    const req2 = request.RequestView{
        .method = .GET,
        .path = "/api/v2/items",
        .headers = &.{},
        .body = "",
    };
    const match2 = proxy.matchRoute(&req2);
    try std.testing.expect(match2 != null);
    try std.testing.expectEqualStrings("api_v2", match2.?.upstream);
}
