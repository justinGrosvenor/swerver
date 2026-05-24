const std = @import("std");
const upstream = @import("upstream.zig");
const pool_mod = @import("pool.zig");
const balancer = @import("balancer.zig");
const forward = @import("forward.zig");
const health = @import("health.zig");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("../middleware/middleware.zig");
const auth_mod = @import("../middleware/auth.zig");
const x402 = @import("../middleware/x402.zig");
const cache_mod = @import("cache.zig");
const dns_mod = @import("dns.zig");
const consul_mod = @import("consul.zig");
const compress_mod = @import("../middleware/compress.zig");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");

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

/// Scratch buffer for percent-decoding paths during route matching
threadlocal var decode_scratch: [4096]u8 = undefined;

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
    /// Stable header storage paired with each response buffer slot
    response_header_bufs: [][64]response.Header,
    /// Free buffer index stack
    free_request_stack: []usize,
    free_response_stack: []usize,
    /// Number of free buffers
    free_request_count: usize,
    free_response_count: usize,
    /// Pre-computed x402 policies for proxy routes (parallel to config.routes)
    route_x402_policies: []x402.RoutePaymentConfig,
    /// Per-route response caches (parallel to config.routes, null if route has no cache config)
    route_caches: []?cache_mod.ResponseCache,
    /// DNS service discovery (resolves upstream addresses periodically)
    dns_discovery: dns_mod.DnsDiscovery,
    /// Consul service discovery (polls Consul HTTP API periodically)
    consul_discovery: consul_mod.ConsulDiscovery,

    const REQUEST_BUF_SIZE = 8192;
    const RESPONSE_BUF_SIZE = 65536;
    const BUFFER_POOL_SIZE = 64;

    threadlocal var compress_scratch: [RESPONSE_BUF_SIZE]u8 = undefined;
    threadlocal var compress_ce_header: response.Header = .{ .name = "Content-Encoding", .value = "gzip" };

    fn maybeCompress(
        resp: *response.Response,
        client_headers: []const request.Header,
        header_buf: []response.Header,
    ) void {
        const body_bytes = switch (resp.body) {
            .bytes => |b| b,
            else => return,
        };
        if (body_bytes.len < 256) return;
        if (compress_mod.alreadyEncoded(resp.headers)) return;

        var accept_enc: ?[]const u8 = null;
        var content_type: ?[]const u8 = null;
        for (client_headers) |hdr| {
            if (accept_enc == null and std.ascii.eqlIgnoreCase(hdr.name, "accept-encoding"))
                accept_enc = hdr.value;
            if (content_type == null and std.ascii.eqlIgnoreCase(hdr.name, "content-type"))
                content_type = hdr.value;
        }
        // Also check upstream response Content-Type
        if (content_type == null) {
            for (resp.headers) |hdr| {
                if (std.ascii.eqlIgnoreCase(hdr.name, "Content-Type")) {
                    content_type = hdr.value;
                    break;
                }
            }
        }
        const ct = content_type orelse return;
        if (!compress_mod.isCompressible(ct)) return;
        const ae = accept_enc orelse return;
        const encoding = compress_mod.parseAcceptEncoding(ae);
        if (encoding == .identity) return;

        const compressed_len = switch (encoding) {
            .gzip => compress_mod.gzipCompress(body_bytes, &compress_scratch),
            .deflate => compress_mod.deflateCompress(body_bytes, &compress_scratch),
            .identity => null,
        } orelse return;

        compress_ce_header = .{ .name = "Content-Encoding", .value = compress_mod.encodingName(encoding) };
        if (resp.headers.len < header_buf.len) {
            @memcpy(header_buf[0..resp.headers.len], resp.headers);
            header_buf[resp.headers.len] = compress_ce_header;
            resp.headers = header_buf[0 .. resp.headers.len + 1];
        }
        resp.body = .{ .bytes = compress_scratch[0..compressed_len] };
    }

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

        const response_header_bufs = try allocator.alloc([64]response.Header, BUFFER_POOL_SIZE);
        errdefer allocator.free(response_header_bufs);

        // Initialize free stacks with all indices
        for (0..BUFFER_POOL_SIZE) |i| {
            free_request_stack[i] = BUFFER_POOL_SIZE - 1 - i;
            free_response_stack[i] = BUFFER_POOL_SIZE - 1 - i;
        }

        // Pre-compute x402 policies for proxy routes
        const route_x402_policies = try allocator.alloc(x402.RoutePaymentConfig, config.routes.len);
        errdefer allocator.free(route_x402_policies);
        for (config.routes, 0..) |route, i| {
            if (route.x402) |rx| {
                route_x402_policies[i] = x402.configFromProxyRoute(&rx, allocator, route.path_prefix) catch {
                    route_x402_policies[i] = .{};
                    continue;
                };
            } else {
                route_x402_policies[i] = .{};
            }
        }

        // Initialize per-route response caches
        const route_caches = try allocator.alloc(?cache_mod.ResponseCache, config.routes.len);
        errdefer allocator.free(route_caches);
        for (config.routes, 0..) |route, i| {
            if (route.cache) |cc| {
                route_caches[i] = cache_mod.ResponseCache.init(allocator, cc.max_entries) catch null;
            } else {
                route_caches[i] = null;
            }
        }

        // Initialize DNS service discovery
        var dns_discovery = try dns_mod.DnsDiscovery.init(allocator, config.upstreams);
        errdefer dns_discovery.deinit();

        // Initialize Consul service discovery
        var consul_discovery = try consul_mod.ConsulDiscovery.init(allocator, config.upstreams);
        errdefer consul_discovery.deinit();

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
            .response_header_bufs = response_header_bufs,
            .free_request_stack = free_request_stack,
            .free_response_stack = free_response_stack,
            .free_request_count = BUFFER_POOL_SIZE,
            .free_response_count = BUFFER_POOL_SIZE,
            .route_x402_policies = route_x402_policies,
            .route_caches = route_caches,
            .dns_discovery = dns_discovery,
            .consul_discovery = consul_discovery,
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

            bal.* = try balancer.Balancer.init(up, pool);
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

        self.dns_discovery.deinit();
        self.consul_discovery.deinit();
        for (self.route_caches) |*rc| {
            if (rc.*) |*c| c.deinit();
        }
        self.allocator.free(self.route_caches);
        self.allocator.free(self.route_x402_policies);
        self.allocator.free(self.free_request_stack);
        self.allocator.free(self.free_response_stack);
        self.allocator.free(self.request_bufs);
        self.allocator.free(self.response_bufs);
        self.allocator.free(self.response_header_bufs);
    }

    /// Return the index of a matched route (for looking up parallel arrays like x402 policies).
    pub fn routeIndex(self: *const Proxy, route: *const upstream.ProxyRoute) usize {
        const base = @intFromPtr(self.config.routes.ptr);
        const this = @intFromPtr(route);
        return (this - base) / @sizeOf(upstream.ProxyRoute);
    }

    /// Find a matching proxy route for a request.
    /// Decodes percent-encoded paths for prefix matching to prevent URL-encoding
    /// bypasses while still allowing legitimate encoded paths.
    pub fn matchRoute(self: *const Proxy, req: *const request.RequestView) ?*const upstream.ProxyRoute {
        // If path contains percent-encoding, decode it for matching
        const match_path = if (std.mem.indexOfScalar(u8, req.path, '%') != null) blk: {
            const decoded = percentDecodePath(req.path) orelse return null;
            break :blk decoded;
        } else req.path;

        for (self.config.routes) |*route| {
            // Check host match if configured
            if (route.host) |expected_host| {
                const req_host = req.getHeader("Host") orelse continue;
                if (!std.mem.eql(u8, req_host, expected_host)) continue;
            }

            // Check path prefix against decoded path
            if (std.mem.startsWith(u8, match_path, route.path_prefix)) {
                return route;
            }
        }
        return null;
    }

    /// Decode percent-encoded path for safe prefix matching.
    /// Returns null if path contains %00 (null byte) or invalid encoding.
    fn percentDecodePath(path: []const u8) ?[]const u8 {
        const buf = &decode_scratch;
        var src: usize = 0;
        var dst: usize = 0;
        while (src < path.len) {
            if (dst >= buf.len) return null;
            if (path[src] == '%') {
                if (src + 2 >= path.len) return null; // truncated encoding
                const hi = hexDigit(path[src + 1]) orelse return null;
                const lo = hexDigit(path[src + 2]) orelse return null;
                const byte = (hi << 4) | lo;
                if (byte == 0) return null; // reject null bytes
                buf[dst] = byte;
                src += 3;
            } else {
                buf[dst] = path[src];
                src += 1;
            }
            dst += 1;
        }
        return buf[0..dst];
    }

    fn hexDigit(c: u8) ?u8 {
        return switch (c) {
            '0'...'9' => c - '0',
            'A'...'F' => c - 'A' + 10,
            'a'...'f' => c - 'a' + 10,
            else => null,
        };
    }

    /// Handle a proxy request with real upstream I/O.
    /// Connects to the selected backend, sends the request, reads the response,
    /// and returns it to the client. Supports connection reuse and retry.
    ///
    /// The caller MUST call `result.release()` after the response has been
    /// fully consumed (e.g., after queueResponse).
    pub fn handle(
        self: *Proxy,
        req: request.RequestView,
        mw_ctx: *middleware.Context,
        client_ip: ?[]const u8,
        client_tls: bool,
        now_ms: u64,
        auth_info: ?*const auth_mod.AuthInfo,
        client_cert_dn: ?[]const u8,
    ) ProxyResult {
        _ = mw_ctx;

        // Find matching route
        const route = self.matchRoute(&req) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        const effective_upstream = route.selectUpstream();

        // Get upstream configuration
        const upstream_def = self.upstreams_by_name.get(effective_upstream) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };
        _ = upstream_def;

        // Get balancer and pool
        const bal = self.balancers.get(effective_upstream) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        const pool = self.pool_manager.getPool(effective_upstream) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        // Acquire buffers
        const req_buf_idx = self.acquireRequestBuffer() orelse {
            return .{ .resp = forward.createErrorResponse(503), .proxy = self };
        };
        defer self.releaseRequestBuffer(req_buf_idx);

        const resp_buf_idx = self.acquireResponseBuffer() orelse {
            return .{ .resp = forward.createErrorResponse(503), .proxy = self };
        };
        // NOTE: response buffer is NOT released here on success path.
        // The caller releases it via ProxyResult.release().

        // Get client IP as u32 for IP hash
        const client_ip_u32: ?u32 = if (client_ip) |ip| parseIpToU32(ip) else null;

        // Retry loop
        const retry_config = route.retry;
        var attempts: u8 = 0;
        const max_attempts = retry_config.max_retries + 1;
        const start_instant = clock.Instant.now();
        const total_limit_ns: u64 = @as(u64, route.timeouts.total_ms) * 1_000_000;

        while (attempts < max_attempts) {
            attempts += 1;

            // Enforce total_ms deadline on retries
            if (attempts > 1) {
                if (start_instant) |start| {
                    if (clock.Instant.now()) |current| {
                        if (current.since(start) >= total_limit_ns) {
                            self.releaseResponseBuffer(resp_buf_idx);
                            return .{ .resp = forward.createErrorResponse(504), .proxy = self };
                        }
                    }
                }
            }

            // Select upstream server — prefer dynamically-discovered addresses
            const discovered_server = self.selectDnsServer(effective_upstream) orelse self.selectConsulServer(effective_upstream);
            const selection = bal.select(client_ip_u32, now_ms) orelse if (discovered_server == null) {
                self.releaseResponseBuffer(resp_buf_idx);
                return .{ .resp = forward.createErrorResponse(502), .proxy = self };
            } else null;
            const connect_server = discovered_server orelse selection.?.server;

            // Try to get an existing idle connection
            const server_idx = if (selection) |s| s.server_index else 0;
            var conn = pool.acquireForServer(server_idx, now_ms);
            var created_new = false;

            if (conn == null) {
                // Need to create a new TCP connection
                const slot = pool.reserveSlot() orelse {
                    if (attempts < max_attempts) continue;
                    self.releaseResponseBuffer(resp_buf_idx);
                    return .{ .resp = forward.createErrorResponse(503), .proxy = self };
                };

                const fd = net.connectBlocking(
                    connect_server.address,
                    connect_server.port,
                    route.timeouts.connect_ms,
                ) catch {
                    // Connect failed — mark server failure
                    if (selection) |s| {
                        if (s.server_index < pool.server_failures.len) {
                            pool.server_failures[s.server_index].consecutive_failures += 1;
                            pool.server_failures[s.server_index].last_failure_ms = now_ms;
                            if (pool.server_failures[s.server_index].consecutive_failures >= s.server.max_fails) {
                                pool.server_failures[s.server_index].available = false;
                            }
                        }
                    }
                    continue;
                };

                net.setSocketTimeouts(fd, route.timeouts.send_ms, route.timeouts.read_ms);
                net.setNoDelay(fd);

                var new_conn = pool_mod.UpstreamConnection.init(fd, server_idx, now_ms, slot);
                new_conn.state = .idle;
                pool.addConnection(slot, new_conn);
                conn = pool.acquireForServer(server_idx, now_ms);
                created_new = true;
            }

            if (conn) |c| {
                // Verify existing connection is still alive (not newly created)
                if (!created_new and c.fd >= 0) {
                    var pfd = [1]std.posix.pollfd{.{
                        .fd = c.fd,
                        .events = std.posix.POLL.IN,
                        .revents = 0,
                    }};
                    const poll_rc = std.posix.system.poll(&pfd, 1, 0);
                    if (poll_rc > 0 and (pfd[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR)) != 0) {
                        pool.removeConnection(c);
                        continue;
                    }
                }

                // Build upstream request
                const ctx = forward.ForwardContext{
                    .client_request = req,
                    .client_ip = client_ip,
                    .client_tls = client_tls,
                    .route = route,
                    .server = connect_server,
                    .upstream_conn = c,
                    .request_buf = &self.request_bufs[req_buf_idx],
                    .response_buf = &self.response_bufs[resp_buf_idx],
                    .auth_headers = if (auth_info) |ai| ai.headers() else &.{},
                    .client_cert_dn = client_cert_dn,
                };

                const request_len = forward.buildUpstreamRequest(&self.request_bufs[req_buf_idx], &ctx) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    continue;
                };

                // Send request to upstream
                const body_sent = req.body.len() > 0;
                net.sendAll(c.fd, self.request_bufs[req_buf_idx][0..request_len]) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    // RFC 9110 §9.2.2: Only retry if method is idempotent or body not sent
                    if (body_sent and !forward.isIdempotent(req.method)) {
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    }
                    continue;
                };

                // Read response from upstream
                var total_read: usize = 0;
                var read_failed = false;
                while (total_read < RESPONSE_BUF_SIZE) {
                    const n = net.recvBlocking(c.fd, self.response_bufs[resp_buf_idx][total_read..]) catch {
                        pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                        read_failed = true;
                        break;
                    };
                    if (n == 0) break; // EOF
                    total_read += n;

                    // Try to parse — if we have a complete response, stop reading
                    // For close-delimited responses, keep reading until EOF
                    if (forward.parseUpstreamResponse(self.response_bufs[resp_buf_idx][0..total_read])) |parsed_check| {
                        if (!parsed_check.close_delimited) break;
                    } else |_| {}
                }

                if (read_failed) {
                    // RFC 9110 §9.2.2: Don't retry non-idempotent after body sent
                    if (body_sent and !forward.isIdempotent(req.method)) {
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    }
                    continue;
                }

                if (total_read == 0) {
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    continue;
                }

                // Parse the upstream response
                const parsed = forward.parseUpstreamResponse(self.response_bufs[resp_buf_idx][0..total_read]) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    continue;
                };

                // Check if we should retry on this status code
                if (forward.shouldRetry(parsed.status, &retry_config) and
                    forward.isMethodRetryable(req.method, &retry_config) and
                    attempts < max_attempts)
                {
                    pool.release(c, now_ms, parsed.keep_alive);
                    continue;
                }

                var normalized = forward.normalizeUpstreamResponse(
                    &parsed,
                    self.response_bufs[resp_buf_idx][0..],
                    route,
                    self.response_header_bufs[resp_buf_idx][0..],
                ) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    continue;
                };
                pool.markServerSuccess(server_idx);
                pool.release(c, now_ms, parsed.keep_alive);

                maybeCompress(&normalized, req.headers, self.response_header_bufs[resp_buf_idx][0..]);
                if (route.mirror) |mirror_name| {
                    self.fireMirror(mirror_name, req, null, now_ms);
                }
                return .{
                    .resp = normalized,
                    .proxy = self,
                    .resp_buf_idx = resp_buf_idx,
                };
            }
        }

        // All retries exhausted
        self.releaseResponseBuffer(resp_buf_idx);
        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
    }

    /// Handle a proxy request with a body provided as a BodyView (multi-buffer).
    /// Sends request headers first, then streams body chunks to upstream.
    /// The caller MUST call `result.release()` after the response has been consumed.
    pub fn handleWithBody(
        self: *Proxy,
        req: request.RequestView,
        body_view: forward.BodyView,
        mw_ctx: *middleware.Context,
        client_ip: ?[]const u8,
        client_tls: bool,
        now_ms: u64,
        auth_info: ?*const auth_mod.AuthInfo,
        client_cert_dn: ?[]const u8,
    ) ProxyResult {
        _ = mw_ctx;

        // Find matching route
        const route = self.matchRoute(&req) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        const effective_upstream_b = route.selectUpstream();

        // Get upstream configuration
        const upstream_def_b = self.upstreams_by_name.get(effective_upstream_b) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };
        _ = upstream_def_b;

        // Get balancer and pool
        const bal = self.balancers.get(effective_upstream_b) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        const pool = self.pool_manager.getPool(effective_upstream_b) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        // Acquire buffers
        const req_buf_idx = self.acquireRequestBuffer() orelse {
            return .{ .resp = forward.createErrorResponse(503), .proxy = self };
        };
        defer self.releaseRequestBuffer(req_buf_idx);

        const resp_buf_idx = self.acquireResponseBuffer() orelse {
            return .{ .resp = forward.createErrorResponse(503), .proxy = self };
        };

        const client_ip_u32: ?u32 = if (client_ip) |ip| parseIpToU32(ip) else null;

        const retry_config = route.retry;
        var attempts: u8 = 0;
        const max_attempts = retry_config.max_retries + 1;
        const body_len = body_view.totalLen();
        const start_instant = clock.Instant.now();
        const total_limit_ns: u64 = @as(u64, route.timeouts.total_ms) * 1_000_000;

        while (attempts < max_attempts) {
            attempts += 1;

            if (attempts > 1) {
                if (start_instant) |start| {
                    if (clock.Instant.now()) |current| {
                        if (current.since(start) >= total_limit_ns) {
                            self.releaseResponseBuffer(resp_buf_idx);
                            return .{ .resp = forward.createErrorResponse(504), .proxy = self };
                        }
                    }
                }
            }

            const discovered_server_b = self.selectDnsServer(effective_upstream_b) orelse self.selectConsulServer(effective_upstream_b);
            const selection = bal.select(client_ip_u32, now_ms) orelse if (discovered_server_b == null) {
                self.releaseResponseBuffer(resp_buf_idx);
                return .{ .resp = forward.createErrorResponse(502), .proxy = self };
            } else null;
            const connect_server_b = discovered_server_b orelse selection.?.server;
            const server_idx_b = if (selection) |s| s.server_index else 0;

            var conn = pool.acquireForServer(server_idx_b, now_ms);
            var created_new = false;

            if (conn == null) {
                const slot = pool.reserveSlot() orelse {
                    if (attempts < max_attempts) continue;
                    self.releaseResponseBuffer(resp_buf_idx);
                    return .{ .resp = forward.createErrorResponse(503), .proxy = self };
                };

                const fd = net.connectBlocking(
                    connect_server_b.address,
                    connect_server_b.port,
                    route.timeouts.connect_ms,
                ) catch {
                    if (selection) |s| {
                        if (s.server_index < pool.server_failures.len) {
                            pool.server_failures[s.server_index].consecutive_failures += 1;
                            pool.server_failures[s.server_index].last_failure_ms = now_ms;
                            if (pool.server_failures[s.server_index].consecutive_failures >= s.server.max_fails) {
                                pool.server_failures[s.server_index].available = false;
                            }
                        }
                    }
                    continue;
                };

                net.setSocketTimeouts(fd, route.timeouts.send_ms, route.timeouts.read_ms);
                net.setNoDelay(fd);

                var new_conn = pool_mod.UpstreamConnection.init(fd, server_idx_b, now_ms, slot);
                new_conn.state = .idle;
                pool.addConnection(slot, new_conn);
                conn = pool.acquireForServer(server_idx_b, now_ms);
                created_new = true;
            }

            if (conn) |c| {
                // Verify existing connection is still alive
                if (!created_new and c.fd >= 0) {
                    var pfd = [1]std.posix.pollfd{.{
                        .fd = c.fd,
                        .events = std.posix.POLL.IN,
                        .revents = 0,
                    }};
                    const poll_rc = std.posix.system.poll(&pfd, 1, 0);
                    if (poll_rc > 0 and (pfd[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR)) != 0) {
                        pool.removeConnection(c);
                        continue;
                    }
                }

                // Build upstream request headers only (no body in buffer)
                const ctx = forward.ForwardContext{
                    .client_request = req,
                    .client_ip = client_ip,
                    .client_tls = client_tls,
                    .route = route,
                    .server = connect_server_b,
                    .upstream_conn = c,
                    .request_buf = &self.request_bufs[req_buf_idx],
                    .response_buf = &self.response_bufs[resp_buf_idx],
                    .auth_headers = if (auth_info) |ai| ai.headers() else &.{},
                    .client_cert_dn = client_cert_dn,
                };

                const header_len = forward.buildUpstreamRequestHeaders(&self.request_bufs[req_buf_idx], &ctx, body_len) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                    continue;
                };

                // Send headers to upstream
                net.sendAll(c.fd, self.request_bufs[req_buf_idx][0..header_len]) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                    if (!forward.isIdempotent(req.method)) {
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    }
                    continue;
                };

                // Stream body chunks to upstream
                var body_send_failed = false;
                var body_iter = body_view.iterator();
                while (body_iter.next()) |chunk| {
                    net.sendAll(c.fd, chunk) catch {
                        pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                        body_send_failed = true;
                        break;
                    };
                }

                if (body_send_failed) {
                    if (!forward.isIdempotent(req.method)) {
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    }
                    continue;
                }

                // Read response from upstream
                var total_read: usize = 0;
                var read_failed = false;
                while (total_read < RESPONSE_BUF_SIZE) {
                    const n = net.recvBlocking(c.fd, self.response_bufs[resp_buf_idx][total_read..]) catch {
                        pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                        read_failed = true;
                        break;
                    };
                    if (n == 0) break;
                    total_read += n;

                    if (forward.parseUpstreamResponse(self.response_bufs[resp_buf_idx][0..total_read])) |parsed_check| {
                        if (!parsed_check.close_delimited) break;
                    } else |_| {}
                }

                if (read_failed) {
                    if (!forward.isIdempotent(req.method)) {
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    }
                    continue;
                }

                if (total_read == 0) {
                    pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                    continue;
                }

                const parsed = forward.parseUpstreamResponse(self.response_bufs[resp_buf_idx][0..total_read]) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                    continue;
                };

                if (forward.shouldRetry(parsed.status, &retry_config) and
                    forward.isMethodRetryable(req.method, &retry_config) and
                    attempts < max_attempts)
                {
                    pool.release(c, now_ms, parsed.keep_alive);
                    continue;
                }

                var normalized_b = forward.normalizeUpstreamResponse(
                    &parsed,
                    self.response_bufs[resp_buf_idx][0..],
                    route,
                    self.response_header_bufs[resp_buf_idx][0..],
                ) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                    continue;
                };
                pool.markServerSuccess(server_idx_b);
                pool.release(c, now_ms, parsed.keep_alive);

                maybeCompress(&normalized_b, req.headers, self.response_header_bufs[resp_buf_idx][0..]);
                if (route.mirror) |mirror_name| {
                    self.fireMirror(mirror_name, req, body_view, now_ms);
                }
                return .{
                    .resp = normalized_b,
                    .proxy = self,
                    .resp_buf_idx = resp_buf_idx,
                };
            }
        }

        self.releaseResponseBuffer(resp_buf_idx);
        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
    }

    threadlocal var dns_rr_counter: u32 = 0;

    fn selectDnsServer(self: *const Proxy, upstream_name: []const u8) ?*const upstream.Server {
        const servers = self.dns_discovery.resolvedServers(upstream_name) orelse return null;
        if (servers.len == 0) return null;
        dns_rr_counter +%= 1;
        return &servers[dns_rr_counter % servers.len];
    }

    threadlocal var consul_rr_counter: u32 = 0;

    fn selectConsulServer(self: *const Proxy, upstream_name: []const u8) ?*const upstream.Server {
        const servers = self.consul_discovery.resolvedServers(upstream_name) orelse return null;
        if (servers.len == 0) return null;
        consul_rr_counter +%= 1;
        return &servers[consul_rr_counter % servers.len];
    }

    threadlocal var mirror_req_buf: [REQUEST_BUF_SIZE]u8 = undefined;

    fn fireMirror(
        self: *Proxy,
        mirror_name: []const u8,
        req: request.RequestView,
        body_view: ?forward.BodyView,
        now_ms: u64,
    ) void {
        const bal_m = self.balancers.get(mirror_name) orelse return;
        const selection = bal_m.select(null, now_ms) orelse return;
        const server_m = selection.server;

        const fd = net.connectBlocking(server_m.address, server_m.port, 500) catch return;
        defer clock.closeFd(fd);

        const dummy_route = upstream.ProxyRoute{
            .path_prefix = "",
            .upstream = mirror_name,
        };
        const ctx = forward.ForwardContext{
            .client_request = req,
            .client_ip = null,
            .client_tls = false,
            .route = &dummy_route,
            .server = server_m,
            .upstream_conn = undefined,
            .request_buf = &mirror_req_buf,
            .response_buf = undefined,
        };

        if (body_view) |bv| {
            const header_len = forward.buildUpstreamRequestHeaders(&mirror_req_buf, &ctx, bv.totalLen()) catch return;
            net.sendAll(fd, mirror_req_buf[0..header_len]) catch return;
            var it = bv.iterator();
            while (it.next()) |chunk| {
                net.sendAll(fd, chunk) catch return;
            }
        } else {
            const req_len = forward.buildUpstreamRequest(&mirror_req_buf, &ctx) catch return;
            net.sendAll(fd, mirror_req_buf[0..req_len]) catch return;
        }
    }

    /// Run periodic maintenance tasks
    pub fn runMaintenance(self: *Proxy, now_ms: u64) void {
        // Evict expired connections
        _ = self.pool_manager.evictAllExpired(now_ms);

        // Run health checks
        self.health_manager.runAllChecks(now_ms, &self.pool_manager);

        // DNS service discovery re-resolution
        _ = self.dns_discovery.tick(now_ms);

        // Consul service discovery polling
        _ = self.consul_discovery.tick(now_ms);
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
        std.debug.assert(self.free_request_count < BUFFER_POOL_SIZE);
        self.free_request_stack[self.free_request_count] = idx;
        self.free_request_count += 1;
    }

    fn acquireResponseBuffer(self: *Proxy) ?usize {
        if (self.free_response_count == 0) return null;
        self.free_response_count -= 1;
        return self.free_response_stack[self.free_response_count];
    }

    fn releaseResponseBuffer(self: *Proxy, idx: usize) void {
        std.debug.assert(self.free_response_count < BUFFER_POOL_SIZE);
        self.free_response_stack[self.free_response_count] = idx;
        self.free_response_count += 1;
    }
};

/// Result of a proxy request. Caller must call `release()` after
/// the response has been fully consumed (e.g., after queueResponse).
pub const ProxyResult = struct {
    resp: response.Response,
    proxy: *Proxy,
    /// Response buffer index to release, or null if none held.
    resp_buf_idx: ?usize = null,

    pub fn release(self: *ProxyResult) void {
        if (self.resp_buf_idx) |idx| {
            self.proxy.releaseResponseBuffer(idx);
            self.resp_buf_idx = null;
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
        .response_header_bufs = &.{},
        .free_request_stack = &.{},
        .free_response_stack = &.{},
        .free_request_count = 0,
        .free_response_count = 0,
        .route_x402_policies = &.{},
        .route_caches = &.{},
        .dns_discovery = .{ .allocator = allocator, .entries = &.{}, .entry_count = 0 },
        .consul_discovery = .{ .allocator = allocator, .entries = &.{}, .entry_count = 0 },
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
        .body = .{ .slice = "" },
    };
    const match1 = proxy.matchRoute(&req1);
    try std.testing.expect(match1 != null);
    try std.testing.expectEqualStrings("api_v1", match1.?.upstream);

    // Test /api/v2/ matching
    const req2 = request.RequestView{
        .method = .GET,
        .path = "/api/v2/items",
        .headers = &.{},
        .body = .{ .slice = "" },
    };
    const match2 = proxy.matchRoute(&req2);
    try std.testing.expect(match2 != null);
    try std.testing.expectEqualStrings("api_v2", match2.?.upstream);

    // Test percent-encoded path matches after decoding
    const req_encoded = request.RequestView{
        .method = .GET,
        .path = "/api/v1/users%2Fjohn%20smith",
        .headers = &.{},
        .body = .{ .slice = "" },
    };
    const match_enc = proxy.matchRoute(&req_encoded);
    try std.testing.expect(match_enc != null);
    try std.testing.expectEqualStrings("api_v1", match_enc.?.upstream);

    // Test percent-encoded null byte rejected
    const req_null = request.RequestView{
        .method = .GET,
        .path = "/api/v1/%00admin",
        .headers = &.{},
        .body = .{ .slice = "" },
    };
    const match_null = proxy.matchRoute(&req_null);
    try std.testing.expect(match_null == null);

    // Test invalid percent encoding rejected
    const req_bad = request.RequestView{
        .method = .GET,
        .path = "/api/v1/%GG",
        .headers = &.{},
        .body = .{ .slice = "" },
    };
    const match_bad = proxy.matchRoute(&req_bad);
    try std.testing.expect(match_bad == null);
}

test "percentDecodePath" {
    // Normal path without encoding passes through
    const plain = Proxy.percentDecodePath("/api/v1/users").?;
    try std.testing.expectEqualStrings("/api/v1/users", plain);

    // Space encoding
    const space = Proxy.percentDecodePath("/hello%20world").?;
    try std.testing.expectEqualStrings("/hello world", space);

    // Slash encoding
    const slash = Proxy.percentDecodePath("/a%2Fb").?;
    try std.testing.expectEqualStrings("/a/b", slash);

    // Null byte rejected
    try std.testing.expect(Proxy.percentDecodePath("/bad%00path") == null);

    // Truncated encoding rejected
    try std.testing.expect(Proxy.percentDecodePath("/bad%2") == null);

    // Invalid hex digits rejected
    try std.testing.expect(Proxy.percentDecodePath("/bad%GG") == null);
}
