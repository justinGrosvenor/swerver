const std = @import("std");
const upstream = @import("upstream.zig");
const tenant_mod = @import("tenant.zig");
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
const buffer_pool = @import("../runtime/buffer_pool.zig");
const build_options = @import("build_options");
// WASM edge filters (design 10.0). Gated; ProxyRoute stores the pool as an
// opaque pointer so this module compiles without the vendored wasm3 dependency.
const wasm_filter = if (build_options.enable_wasm) @import("../wasm/filter.zig") else struct {};
const wasm_host_call = if (build_options.enable_wasm) @import("../wasm/host_call.zig") else struct {};

/// WASM park binding, threaded from the H1 dispatch layer into the proxy filter
/// hook (mirror of router.WasmBinding). Empty (`.{}`) means no park support: the
/// filter runs terminally and fails closed on a park (the path H2/H3 and the
/// body-accumulation path use). When `table` + `start_fn` are wired (H1 dispatch),
/// a parking filter registers in the table and returns the park sentinel;
/// `resume_decision` carries the resumed decision on the re-dispatch after the
/// host call completes (the filter is then skipped and the request forwarded).
pub const WasmBinding = struct {
    table: ?*anyopaque = null,
    conn_index: u32 = 0,
    conn_id: u64 = 0,
    /// Stream within the connection. H1 uses the sentinel 0; H2/H3 (E2) pass the
    /// real stream id so a parked stream resumes independently of its siblings.
    stream_id: u32 = 0,
    /// Protocol of the parked stream; stored on the park slot so `wasmResume`
    /// routes response delivery (H1 queueResponse vs H2/H3 stream sends in E2).
    protocol: middleware.Context.Protocol = .http1,
    deadline_ms: u64 = 0,
    /// Opaque resumed-path context carried into the park slot (E1; null in E0).
    resume_ctx: ?*anyopaque = null,
    resume_decision: ?middleware.Decision = null,
    start_fn: ?*const fn (ctx: *anyopaque, token: u32, request: []const u8) void = null,
    start_ctx: ?*anyopaque = null,
    /// Tenant-as-upstream (park-concurrency plan Phase 1). The per-worker
    /// `*tenant.TenantRegistry` (opaque so this struct stays build-flag-free);
    /// null disables tenant routing. On a warm HIT the proxy forwards straight
    /// to the VM's UNIX socket, skipping the filter.
    tenant_registry: ?*anyopaque = null,
    /// Socket path a resumed cold-start filter named via set_upstream: THIS
    /// request forwards there and the mapping is registered. Null otherwise.
    upstream_override: ?[]const u8 = null,
};

/// Map a proxy BodyView onto a RequestView body so a WASM filter can read it via
/// body_len/read_body. Zero-copy: the two share the scattered-buffer layout.
/// Connect to a backend server: UNIX-domain when the server carries a socket
/// path, else TCP. The single choke point for the request path, handleWithBody,
/// and the mirror; unix paths skip SSRF validation (they are vetted at config
/// parse / tenant registration, and isPrivateAddress is meaningless for them).
fn connectToServer(server: *const upstream.Server, connect_ms: u32, allow_private: bool) net.ConnectError!std.posix.fd_t {
    if (server.unix_path.len > 0) return net.connectUnixBlocking(server.unix_path, connect_ms);
    return net.proxyConnect(server.address, server.port, connect_ms, allow_private);
}

/// Extract the tenant key from a request per the route's TenantRouting. Returns
/// null when the header is absent/empty/oversized. For the default "host" key
/// the :port suffix is stripped so "t.example.com" and "t.example.com:8443"
/// map to the same VM.
fn extractTenantKey(req: *const request.RequestView, tc: upstream.TenantRouting) ?[]const u8 {
    const raw = req.getHeader(tc.header) orelse return null;
    var key = raw;
    if (std.ascii.eqlIgnoreCase(tc.header, "host")) {
        if (std.mem.indexOfScalar(u8, key, ':')) |ci| key = key[0..ci];
    }
    if (key.len == 0 or key.len > tenant_mod.TENANT_KEY_MAX) return null;
    return key;
}

fn bodyViewToRequestBody(bv: forward.BodyView) request.RequestBody {
    return switch (bv) {
        .slice => |s| .{ .slice = s },
        .buffers => |b| .{ .scattered = .{
            .handles = b.handles,
            .last_buf_len = b.last_buf_len,
            .total_len = b.total_len,
            .buffer_size = b.buffer_size,
        } },
    };
}

var proxy_modify_warned = false;

/// Run a route's WASM edge filter (if any) against `req_view`. Returns a
/// short-circuit Response when the filter rejects (or fails closed); null to
/// proceed with forwarding. A request-phase `.modify` (response-header injection
/// from on_request) is not honored on the proxy path: the proper mechanism for
/// rewriting a proxied response is the Phase 2b response hook (on_response), which
/// runs on the upstream response via runWasmResponseFilter and supersedes it. We
/// log once and forward rather than silently dropping. See design 10.0.
/// Run the request-phase WASM filter for a proxy route. Returns:
///   - null              -> proceed to forward,
///   - Response.parked   -> the filter parked (the caller returns it; H1 dispatch
///                          suspends the connection and resumes later),
///   - any other Response -> a terminal reject/error to serve.
/// With an empty binding (no table) the filter runs terminally and fails closed
/// on a park (H2/H3 + the body path). With a table wired (H1 dispatch) a parking
/// filter registers and returns the park sentinel; a `resume_decision` skips the
/// filter on the post-host-call re-dispatch.
/// A short-circuit outcome from the request-phase WASM filter: a Response to
/// serve instead of forwarding, plus an optional connection-backpressure window
/// (set on pool/park-table exhaustion so the caller pauses reads, smoothing the
/// G2 concurrency cliff). `pause_reads_ms == null` means serve `resp` with no
/// pacing (the prior behavior for reject/error). Returning `null` from
/// runWasmFilter still means "proceed to forward".
const WasmShortCircuit = struct {
    resp: response.Response,
    pause_reads_ms: ?u64 = null,
};

fn runWasmFilter(route: *const upstream.ProxyRoute, req_view: *const request.RequestView, wb: WasmBinding) ?WasmShortCircuit {
    if (!build_options.enable_wasm) return null;
    const pool_ptr = route.wasm_pool orelse {
        // S2: the configured filter for this route failed to load. Fail CLOSED
        // (503) rather than forwarding unfiltered. buildWasmManager sets
        // wasm_required on routes whose module failed to load.
        if (route.wasm_required) return .{ .resp = forward.createErrorResponse(503) };
        return null;
    };
    const fpool: *wasm_filter.Pool = @ptrCast(@alignCast(pool_ptr));

    // Re-dispatch after a completed host call: apply the resumed decision,
    // skipping the filter. A proxy ignores request-phase modify headers (the
    // response phase is the mechanism); allow/skip/modify all forward.
    if (wb.resume_decision) |rd| {
        return switch (rd) {
            .allow, .skip, .modify => null,
            .reject => |resp| .{ .resp = resp },
            .rate_limit_backpressure => |bp| .{ .resp = bp.resp },
        };
    }

    // Park-capable path (H1 dispatch wired the binding).
    if (wb.table) |tbl_ptr| {
        const table: *wasm_host_call.Table = @ptrCast(@alignCast(tbl_ptr));
        // Pool exhausted: fail closed (503) AND apply connection backpressure
        // (pause reads briefly) so a flood self-throttles instead of burning the
        // event loop fast-failing excess parks (the G2 cliff). The 503 is still
        // served; the connection is just paced.
        const inst = fpool.acquire() orelse return .{
            .resp = forward.createErrorResponse(503),
            .pause_reads_ms = wasm_filter.POOL_BACKPRESSURE_MS,
        };
        switch (wasm_filter.invokeOutcome(inst, req_view, route.wasm_fuel)) {
            .decision => |d| return switch (d) {
                .allow, .skip => null,
                .reject => |resp| .{ .resp = resp },
                .modify => null, // proxy ignores request-phase modify (see above)
                .rate_limit_backpressure => |bp| .{ .resp = bp.resp },
            },
            .parked => |call_request| {
                if (table.park(inst, req_view.*, wb.conn_index, wb.conn_id, wb.stream_id, wb.protocol, wb.deadline_ms, route.wasm_fuel, wb.resume_ctx)) |token| {
                    if (wb.start_fn) |start| start(wb.start_ctx.?, token, call_request);
                    return .{ .resp = response.Response.parked };
                }
                // Park table full: unpin, fail closed (503) + backpressure.
                _ = wasm_filter.cancelPark(inst);
                return .{
                    .resp = forward.createErrorResponse(503),
                    .pause_reads_ms = wasm_filter.POOL_BACKPRESSURE_MS,
                };
            },
        }
    }

    // No binding (terminal caller: H2/H3, body path): fail closed on a park.
    switch (fpool.run(req_view, route.wasm_fuel)) {
        .reject => |resp| return .{ .resp = resp },
        .modify => {
            if (!proxy_modify_warned) {
                proxy_modify_warned = true;
                std.log.warn("wasm filter returned modify on a proxy route; request-phase response-header injection is not honored on proxy routes (use the on_response Phase 2b hook instead); forwarding", .{});
            }
        },
        else => {},
    }
    return null;
}

/// Merge buffer for response-phase WASM headers on the proxy path. Holds the
/// upstream response headers plus the filter's staged headers; the repointed
/// slice is valid until the response is serialized (single-threaded worker).
threadlocal var wasm_resp_headers_tls: [128]response.Header = undefined;

/// Phase 2b: run the response-phase WASM filter (on_response) on a proxied
/// upstream response, BEFORE compression. Applies the filter's edits in place:
/// status override, body replacement (the encoder recomputes Content-Length from
/// the body -- normalize already stripped the upstream's), and added response
/// headers (merged into the tls buffer). FAIL-OPEN: a trap leaves `resp`
/// untouched (the request already passed policy). No-op without a response hook.
fn runWasmResponseFilter(
    route: *const upstream.ProxyRoute,
    req_view: *const request.RequestView,
    resp: *response.Response,
) void {
    if (!build_options.enable_wasm) return;
    const pool_ptr = route.wasm_pool orelse return;
    const fpool: *wasm_filter.Pool = @ptrCast(@alignCast(pool_ptr));
    if (!fpool.hasResponseHook()) return;
    const edit = fpool.runResponse(req_view, resp, route.wasm_fuel);
    // S3: a trapping response hook fails OPEN by default (serve original); for a
    // redaction/scrub filter that would leak the un-redacted response, so a pool
    // marked response_fail_closed serves a fresh 503 instead (drops the original
    // body AND headers -- no partial leak).
    if (edit.trapped and fpool.response_fail_closed) {
        resp.* = forward.createErrorResponse(503);
        return;
    }
    if (edit.new_status) |s| resp.status = s;
    if (edit.new_body) |b| resp.body = .{ .bytes = b };
    if (edit.add_headers.len > 0) {
        const cap = wasm_resp_headers_tls.len;
        var i: usize = 0;
        for (resp.headers) |h| {
            if (i >= cap) break;
            wasm_resp_headers_tls[i] = h;
            i += 1;
        }
        for (edit.add_headers) |h| {
            if (i >= cap) break;
            wasm_resp_headers_tls[i] = h;
            i += 1;
        }
        resp.headers = wasm_resp_headers_tls[0..i];
    }
}

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
    /// Per-route facilitator configs (parallel to config.routes, null = use global)
    route_facilitators: []?x402.FacilitatorConfig,
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
        // Output must fit the 64KB scratch; don't burn CPU deflating large
        // bodies whose compressed form can't possibly fit.
        if (body_bytes.len > compress_scratch.len) return;
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
            std.mem.copyForwards(response.Header, header_buf[0..resp.headers.len], resp.headers);
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
        const route_facilitators = try allocator.alloc(?x402.FacilitatorConfig, config.routes.len);
        errdefer allocator.free(route_facilitators);
        for (config.routes, 0..) |route, i| {
            if (route.x402) |rx| {
                route_x402_policies[i] = x402.configFromProxyRoute(&rx, allocator, route.path_prefix) catch {
                    route_x402_policies[i] = .{};
                    route_facilitators[i] = null;
                    continue;
                };
                if (rx.facilitator_url.len > 0) {
                    route_facilitators[i] = x402.parseFacilitatorUrl(rx.facilitator_url);
                } else {
                    route_facilitators[i] = null;
                }
            } else {
                route_x402_policies[i] = .{};
                route_facilitators[i] = null;
            }
        }

        // Initialize per-route response caches
        const route_caches = try allocator.alloc(?cache_mod.ResponseCache, config.routes.len);
        errdefer {
            for (route_caches) |*rc| {
                if (rc.*) |*c| c.deinit();
            }
            allocator.free(route_caches);
        }
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
            .route_facilitators = route_facilitators,
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

        // The health thread is NOT started here: `proxy` is a stack local that
        // the caller copies to its final (heap) address, and the thread captures
        // `&health_manager`. Starting it here pins a dead stack frame - the
        // thread then reads garbage checker state (Linux ReleaseFast segfault,
        // layout-dependent). Server.run() starts it at the final address, once
        // per process (per worker, after fork - so every worker owns and joins
        // its own thread and sees live health state).
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
        for (self.route_x402_policies) |policy| {
            if (policy.payment_required_b64.len > 0) self.allocator.free(policy.payment_required_b64);
            if (policy.payment_required_json.len > 0) self.allocator.free(policy.payment_required_json);
        }
        self.allocator.free(self.route_x402_policies);
        self.allocator.free(self.route_facilitators);
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

    const UpstreamRead = struct {
        /// Full response bytes read so far (headers + body).
        data: []u8,
        /// Non-null when the response outgrew the fixed buffer and `data`
        /// is backed by this heap allocation (data.ptr == owned.ptr).
        owned: ?[]u8,
    };

    const UpstreamReadError = error{ ReadFailed, Empty, TooLarge };

    /// Read a complete upstream HTTP response. Fast path reads entirely
    /// into `fixed` (zero allocation — unchanged from the historical
    /// behavior for responses that fit). If the response is larger, the
    /// bytes are moved into a heap allocation that doubles as needed, up
    /// to `cap` bytes (route.max_response_bytes). Completion is decided
    /// the same way at every step: a successful parse that is not
    /// close-delimited, or EOF.
    fn readUpstreamResponse(
        self: *Proxy,
        fd: std.posix.fd_t,
        fixed: []u8,
        is_head: bool,
        cap: usize,
    ) UpstreamReadError!UpstreamRead {
        var total: usize = 0;
        while (total < fixed.len) {
            const n = net.recvBlocking(fd, fixed[total..]) catch return error.ReadFailed;
            if (n == 0) break; // EOF
            total += n;
            if (forward.parseUpstreamResponse(fixed[0..total], is_head)) |parsed| {
                if (!parsed.close_delimited) return .{ .data = fixed[0..total], .owned = null };
            } else |_| {}
        }
        if (total == 0) return error.Empty;
        if (total < fixed.len) {
            // EOF before the buffer filled — close-delimited response.
            return .{ .data = fixed[0..total], .owned = null };
        }
        // Buffer is full. The response may be exactly complete (parse
        // succeeded above and returned), complete-but-close-delimited, or
        // (the common case for large bodies) incomplete: grow to the heap.
        var capacity: usize = @min(fixed.len * 4, cap);
        if (capacity <= fixed.len) return error.TooLarge;
        var owned = self.allocator.alloc(u8, capacity) catch return error.ReadFailed;
        @memcpy(owned[0..total], fixed[0..total]);
        while (true) {
            if (total == capacity) {
                if (capacity >= cap) {
                    self.allocator.free(owned);
                    return error.TooLarge;
                }
                const new_capacity = @min(capacity * 2, cap);
                owned = self.allocator.realloc(owned, new_capacity) catch {
                    self.allocator.free(owned);
                    return error.ReadFailed;
                };
                capacity = new_capacity;
            }
            const n = net.recvBlocking(fd, owned[total..capacity]) catch {
                self.allocator.free(owned);
                return error.ReadFailed;
            };
            if (n == 0) break; // EOF — close-delimited end or truncation (parse decides)
            total += n;
            if (forward.parseUpstreamResponse(owned[0..total], is_head)) |parsed| {
                if (!parsed.close_delimited) break;
            } else |_| {}
        }
        return .{ .data = owned[0..total], .owned = owned };
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
        wasm: WasmBinding,
    ) ProxyResult {
        _ = mw_ctx;

        // Find matching route
        const route = self.matchRoute(&req) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        // Tenant-as-upstream (park-concurrency Phase 1): a warm registry HIT (or
        // the socket a just-resumed cold-start filter named via set_upstream)
        // forwards straight to the VM. A miss falls through to the filter, which
        // parks for a Tier-2 cold start.
        if (build_options.enable_wasm) {
            if (route.tenant) |tc| {
                if (self.tenantRegistryOf(wasm)) |reg| {
                    const key = extractTenantKey(&req, tc);
                    if (wasm.upstream_override) |ovr| { // resume: filter named the socket
                        if (key) |k| reg.register(k, ovr, now_ms);
                        return self.forwardToTenant(route, req, null, ovr, client_ip, client_tls, now_ms, auth_info, client_cert_dn, reg, key orelse "");
                    }
                    if (key) |k| if (reg.lookup(k, now_ms)) |path| {
                        if (!tc.skip_filter_when_warm) {
                            if (runWasmFilter(route, &req, wasm)) |sc| return .{ .resp = sc.resp, .proxy = self, .pause_reads_ms = sc.pause_reads_ms };
                        }
                        return self.forwardToTenant(route, req, null, path, client_ip, client_tls, now_ms, auth_info, client_cert_dn, reg, k);
                    };
                }
            }
        }

        // Per-route WASM edge filter (design 10.0): authenticate/policy-gate
        // before forwarding. This entry handles bodyless / small-body requests,
        // so req.body already carries any body for body_len/read_body. A parking
        // filter returns the park sentinel (H1 dispatch suspends + resumes).
        if (runWasmFilter(route, &req, wasm)) |sc| return .{ .resp = sc.resp, .proxy = self, .pause_reads_ms = sc.pause_reads_ms };

        const effective_upstream = route.selectUpstream();

        // Get upstream configuration
        const upstream_def = self.upstreams_by_name.get(effective_upstream) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };
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
        const max_attempts = @as(u16, retry_config.max_retries) + 1;
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

                const fd = connectToServer(
                    connect_server,
                    route.timeouts.connect_ms,
                    upstream_def.allow_private,
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

                // Build the upstream request. Requests whose headers + body fit
                // the pooled request buffer go out in one send. Larger inline
                // bodies (between REQUEST_BUF_SIZE and the read-buffer
                // accumulation threshold, which routes through handleWithBody)
                // fall back to sending headers and the body slice separately.
                const inline_body: []const u8 = req.body.sliceOrNull() orelse "";
                var split_body = false;
                const request_len = forward.buildUpstreamRequest(&self.request_bufs[req_buf_idx], &ctx) catch blk: {
                    split_body = true;
                    break :blk forward.buildUpstreamRequestHeaders(&self.request_bufs[req_buf_idx], &ctx, inline_body.len) catch {
                        // Even the headers overflow the buffer: a request-shaping
                        // problem, not an upstream failure - hand the untouched
                        // connection back and fail without retrying other servers.
                        pool.release(c, now_ms, true);
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    };
                };

                // Send request to upstream
                const body_sent = !split_body and req.body.len() > 0;
                net.sendAll(c.fd, self.request_bufs[req_buf_idx][0..request_len]) catch {
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    // RFC 9110 §9.2.2: Only retry if method is idempotent or body not sent
                    if (body_sent and !forward.isIdempotent(req.method)) {
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    }
                    continue;
                };
                if (split_body and inline_body.len > 0) {
                    net.sendAll(c.fd, inline_body) catch {
                        pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                        // Body (partially) on the wire: only idempotent methods retry.
                        if (!forward.isIdempotent(req.method)) {
                            self.releaseResponseBuffer(resp_buf_idx);
                            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                        }
                        continue;
                    };
                }

                // Read response from upstream. Fits-in-pool-buffer responses
                // stay zero-allocation; larger ones grow into a heap buffer
                // bounded by route.max_response_bytes.
                const is_head = req.method == .HEAD;
                const ur = self.readUpstreamResponse(
                    c.fd,
                    self.response_bufs[resp_buf_idx][0..],
                    is_head,
                    route.max_response_bytes,
                ) catch |err| switch (err) {
                    error.Empty => {
                        pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                        continue;
                    },
                    error.ReadFailed => {
                        pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                        // RFC 9110 §9.2.2: Don't retry non-idempotent after body sent
                        if (body_sent and !forward.isIdempotent(req.method)) {
                            self.releaseResponseBuffer(resp_buf_idx);
                            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                        }
                        continue;
                    },
                    error.TooLarge => {
                        // Deterministic for this route config — retrying would
                        // produce the same result, and the upstream isn't
                        // unhealthy. The connection was abandoned mid-body,
                        // so it can't go back to the keep-alive pool.
                        std.log.warn("proxy: upstream response for {s} exceeded max_response_bytes ({d})", .{ req.path, route.max_response_bytes });
                        pool.release(c, now_ms, false);
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    },
                };

                // Parse the upstream response
                const parsed = forward.parseUpstreamResponse(ur.data, is_head) catch {
                    if (ur.owned) |ob| self.allocator.free(ob);
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    continue;
                };

                // Check if we should retry on this status code
                if (forward.shouldRetry(parsed.status, &retry_config) and
                    forward.isMethodRetryable(req.method, &retry_config) and
                    attempts < max_attempts)
                {
                    if (ur.owned) |ob| self.allocator.free(ob);
                    // Close (don't keep-alive) so the retry opens a fresh
                    // connection: under SO_REUSEPORT that can land on a
                    // different upstream worker, which is the whole point of
                    // retrying a transient 5xx (the original worker just told
                    // us it couldn't serve this request).
                    pool.release(c, now_ms, false);
                    continue;
                }

                // The parse offsets index into ur.data; pass the full backing
                // region so normalize has tail room for the Via append.
                const backing: []u8 = if (ur.owned) |ob| ob else self.response_bufs[resp_buf_idx][0..];
                var normalized = forward.normalizeUpstreamResponse(
                    &parsed,
                    backing,
                    route,
                    self.response_header_bufs[resp_buf_idx][0..],
                    is_head,
                ) catch {
                    if (ur.owned) |ob| self.allocator.free(ob);
                    pool.markConnectionFailed(c, now_ms, connect_server.max_fails);
                    continue;
                };
                pool.markServerSuccess(server_idx);
                pool.release(c, now_ms, parsed.keep_alive);

                // Phase 2b response filter runs before compression (sees the
                // uncompressed body); maybeCompress copies its headers forward.
                runWasmResponseFilter(route, &req, &normalized);
                maybeCompress(&normalized, req.headers, self.response_header_bufs[resp_buf_idx][0..]);
                if (route.mirror) |mirror_name| {
                    self.fireMirror(mirror_name, req, null, now_ms);
                }
                return .{
                    .resp = normalized,
                    .proxy = self,
                    .resp_buf_idx = resp_buf_idx,
                    .owned_buf = ur.owned,
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
        wasm: WasmBinding,
    ) ProxyResult {
        _ = mw_ctx;

        // Find matching route
        const route = self.matchRoute(&req) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

        // Tenant-as-upstream warm HIT / resume forward (see handle()). The body
        // streams to the VM via forwardToTenant's body_view arm.
        if (build_options.enable_wasm) {
            if (route.tenant) |tc| {
                if (self.tenantRegistryOf(wasm)) |reg| {
                    const key = extractTenantKey(&req, tc);
                    if (wasm.upstream_override) |ovr| {
                        if (key) |k| reg.register(k, ovr, now_ms);
                        return self.forwardToTenant(route, req, body_view, ovr, client_ip, client_tls, now_ms, auth_info, client_cert_dn, reg, key orelse "");
                    }
                    if (key) |k| if (reg.lookup(k, now_ms)) |path| {
                        if (!tc.skip_filter_when_warm) {
                            var filter_req = req;
                            filter_req.body = bodyViewToRequestBody(body_view);
                            if (runWasmFilter(route, &filter_req, wasm)) |sc| return .{ .resp = sc.resp, .proxy = self, .pause_reads_ms = sc.pause_reads_ms };
                        }
                        return self.forwardToTenant(route, req, body_view, path, client_ip, client_tls, now_ms, auth_info, client_cert_dn, reg, k);
                    };
                }
            }
        }

        // Per-route WASM edge filter (design 10.0); see handle() for rationale.
        // The accumulated body lives in body_view, not req.body, so expose it to
        // the filter (body_len/read_body) on a request copy. The mapping is
        // zero-copy: BodyView and RequestBody share the scattered-buffer shape.
        {
            var filter_req = req;
            filter_req.body = bodyViewToRequestBody(body_view);
            if (runWasmFilter(route, &filter_req, wasm)) |sc| return .{ .resp = sc.resp, .proxy = self, .pause_reads_ms = sc.pause_reads_ms };
        }

        const effective_upstream_b = route.selectUpstream();

        // Get upstream configuration
        const upstream_def_b = self.upstreams_by_name.get(effective_upstream_b) orelse {
            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
        };

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
        const max_attempts = @as(u16, retry_config.max_retries) + 1;
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

                const fd = connectToServer(
                    connect_server_b,
                    route.timeouts.connect_ms,
                    upstream_def_b.allow_private,
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
                    // Headers overflow the request buffer: a request-shaping
                    // problem, not an upstream failure - hand the untouched
                    // connection back and fail without retrying other servers.
                    pool.release(c, now_ms, true);
                    self.releaseResponseBuffer(resp_buf_idx);
                    return .{ .resp = forward.createErrorResponse(502), .proxy = self };
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

                // Read response from upstream (grows to heap beyond the
                // fixed buffer — see readUpstreamResponse).
                const is_head_b = req.method == .HEAD;
                const ur = self.readUpstreamResponse(
                    c.fd,
                    self.response_bufs[resp_buf_idx][0..],
                    is_head_b,
                    route.max_response_bytes,
                ) catch |err| switch (err) {
                    error.Empty => {
                        pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                        continue;
                    },
                    error.ReadFailed => {
                        pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                        if (!forward.isIdempotent(req.method)) {
                            self.releaseResponseBuffer(resp_buf_idx);
                            return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                        }
                        continue;
                    },
                    error.TooLarge => {
                        std.log.warn("proxy: upstream response for {s} exceeded max_response_bytes ({d})", .{ req.path, route.max_response_bytes });
                        pool.release(c, now_ms, false);
                        self.releaseResponseBuffer(resp_buf_idx);
                        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
                    },
                };

                const parsed = forward.parseUpstreamResponse(ur.data, is_head_b) catch {
                    if (ur.owned) |ob| self.allocator.free(ob);
                    pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                    continue;
                };

                if (forward.shouldRetry(parsed.status, &retry_config) and
                    forward.isMethodRetryable(req.method, &retry_config) and
                    attempts < max_attempts)
                {
                    if (ur.owned) |ob| self.allocator.free(ob);
                    // Fresh connection on retry — see handle(); lands on a
                    // different SO_REUSEPORT worker.
                    pool.release(c, now_ms, false);
                    continue;
                }

                const backing_b: []u8 = if (ur.owned) |ob| ob else self.response_bufs[resp_buf_idx][0..];
                var normalized_b = forward.normalizeUpstreamResponse(
                    &parsed,
                    backing_b,
                    route,
                    self.response_header_bufs[resp_buf_idx][0..],
                    is_head_b,
                ) catch {
                    if (ur.owned) |ob| self.allocator.free(ob);
                    pool.markConnectionFailed(c, now_ms, connect_server_b.max_fails);
                    continue;
                };
                pool.markServerSuccess(server_idx_b);
                pool.release(c, now_ms, parsed.keep_alive);

                runWasmResponseFilter(route, &req, &normalized_b);
                maybeCompress(&normalized_b, req.headers, self.response_header_bufs[resp_buf_idx][0..]);
                if (route.mirror) |mirror_name| {
                    self.fireMirror(mirror_name, req, body_view, now_ms);
                }
                return .{
                    .resp = normalized_b,
                    .proxy = self,
                    .resp_buf_idx = resp_buf_idx,
                    .owned_buf = ur.owned,
                };
            }
        }

        self.releaseResponseBuffer(resp_buf_idx);
        return .{ .resp = forward.createErrorResponse(502), .proxy = self };
    }

    /// Forward a request directly to a warm tenant microVM's UNIX data socket
    /// (park-concurrency plan Phase 1), bypassing the upstream registry, the
    /// balancer, and the connection pool. v1 opens a FRESH connection per
    /// request (an on-host unix connect is microseconds; the guest bridge caps
    /// per-VM conns) with no retry. Reuses the same response tail as handle()
    /// (normalize + Phase 2b response filter + compression) for parity. On any
    /// connect/send/read failure the tenant mapping is evicted and a 503 with a
    /// backpressure window is returned so the client's retry takes the cold
    /// path, paced. `body_view` is null for the bodyless/small-body entry.
    fn forwardToTenant(
        self: *Proxy,
        route: *const upstream.ProxyRoute,
        req: request.RequestView,
        body_view: ?forward.BodyView,
        socket_path: []const u8,
        client_ip: ?[]const u8,
        client_tls: bool,
        now_ms: u64,
        auth_info: ?*const auth_mod.AuthInfo,
        client_cert_dn: ?[]const u8,
        registry: *tenant_mod.TenantRegistry,
        tenant_key: []const u8,
    ) ProxyResult {
        _ = now_ms; // v1: fresh connect per request, no pool timestamps
        const server = upstream.Server{ .address = "", .port = 0, .unix_path = socket_path };

        const backpressure = ProxyResult{
            .resp = forward.createErrorResponse(503),
            .proxy = self,
            .pause_reads_ms = wasm_filter.POOL_BACKPRESSURE_MS,
        };

        const req_buf_idx = self.acquireRequestBuffer() orelse return backpressure;
        defer self.releaseRequestBuffer(req_buf_idx);
        const resp_buf_idx = self.acquireResponseBuffer() orelse return backpressure;
        // Released by the caller via ProxyResult.release() on the success path.

        const fd = net.connectUnixBlocking(socket_path, route.timeouts.connect_ms) catch {
            registry.evict(tenant_key);
            self.releaseResponseBuffer(resp_buf_idx);
            return backpressure;
        };
        defer clock.closeFd(fd);
        net.setSocketTimeouts(fd, route.timeouts.send_ms, route.timeouts.read_ms);
        // No setNoDelay here: this is an AF_UNIX data socket, and TCP_NODELAY on
        // a unix fd fails with EPROTONOSUPPORT (errno 102), dumping a stack trace
        // on every tenant forward. Nagle does not apply to unix sockets anyway.

        const ctx = forward.ForwardContext{
            .client_request = req,
            .client_ip = client_ip,
            .client_tls = client_tls,
            .route = route,
            .server = &server,
            .upstream_conn = undefined, // unused: buildUpstreamRequest reads only server/route/req
            .request_buf = &self.request_bufs[req_buf_idx],
            .response_buf = &self.response_bufs[resp_buf_idx],
            .auth_headers = if (auth_info) |ai| ai.headers() else &.{},
            .client_cert_dn = client_cert_dn,
        };

        // Send request (headers + body). Small-body requests carry the body in
        // req and go through buildUpstreamRequest; accumulated bodies stream.
        if (body_view) |bv| {
            const header_len = forward.buildUpstreamRequestHeaders(&self.request_bufs[req_buf_idx], &ctx, bv.totalLen()) catch {
                self.releaseResponseBuffer(resp_buf_idx);
                return backpressure;
            };
            net.sendAll(fd, self.request_bufs[req_buf_idx][0..header_len]) catch {
                registry.evict(tenant_key);
                self.releaseResponseBuffer(resp_buf_idx);
                return backpressure;
            };
            var it = bv.iterator();
            while (it.next()) |chunk| {
                net.sendAll(fd, chunk) catch {
                    registry.evict(tenant_key);
                    self.releaseResponseBuffer(resp_buf_idx);
                    return backpressure;
                };
            }
        } else {
            // Same split fallback as handle(): inline bodies that overflow the
            // pooled request buffer send headers and body separately.
            const inline_body: []const u8 = req.body.sliceOrNull() orelse "";
            var split_body = false;
            const request_len = forward.buildUpstreamRequest(&self.request_bufs[req_buf_idx], &ctx) catch blk: {
                split_body = true;
                break :blk forward.buildUpstreamRequestHeaders(&self.request_bufs[req_buf_idx], &ctx, inline_body.len) catch {
                    self.releaseResponseBuffer(resp_buf_idx);
                    return backpressure;
                };
            };
            net.sendAll(fd, self.request_bufs[req_buf_idx][0..request_len]) catch {
                registry.evict(tenant_key);
                self.releaseResponseBuffer(resp_buf_idx);
                return backpressure;
            };
            if (split_body and inline_body.len > 0) {
                net.sendAll(fd, inline_body) catch {
                    registry.evict(tenant_key);
                    self.releaseResponseBuffer(resp_buf_idx);
                    return backpressure;
                };
            }
        }

        const is_head = req.method == .HEAD;
        const ur = self.readUpstreamResponse(fd, self.response_bufs[resp_buf_idx][0..], is_head, route.max_response_bytes) catch {
            registry.evict(tenant_key);
            self.releaseResponseBuffer(resp_buf_idx);
            return backpressure;
        };
        const parsed = forward.parseUpstreamResponse(ur.data, is_head) catch {
            if (ur.owned) |ob| self.allocator.free(ob);
            registry.evict(tenant_key);
            self.releaseResponseBuffer(resp_buf_idx);
            return backpressure;
        };
        const backing: []u8 = if (ur.owned) |ob| ob else self.response_bufs[resp_buf_idx][0..];
        var normalized = forward.normalizeUpstreamResponse(&parsed, backing, route, self.response_header_bufs[resp_buf_idx][0..], is_head) catch {
            if (ur.owned) |ob| self.allocator.free(ob);
            registry.evict(tenant_key);
            self.releaseResponseBuffer(resp_buf_idx);
            return backpressure;
        };

        runWasmResponseFilter(route, &req, &normalized);
        maybeCompress(&normalized, req.headers, self.response_header_bufs[resp_buf_idx][0..]);
        return .{ .resp = normalized, .proxy = self, .resp_buf_idx = resp_buf_idx, .owned_buf = ur.owned };
    }

    /// Typed accessor for the opaque tenant registry carried in the binding.
    fn tenantRegistryOf(self: *Proxy, wasm: WasmBinding) ?*tenant_mod.TenantRegistry {
        _ = self;
        const p = wasm.tenant_registry orelse return null;
        return @ptrCast(@alignCast(p));
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

    /// Per-worker (single event loop thread) — safe because each worker is a separate process.
    threadlocal var mirror_req_buf: [REQUEST_BUF_SIZE]u8 = undefined;

    fn fireMirror(
        self: *Proxy,
        mirror_name: []const u8,
        req: request.RequestView,
        body_view: ?forward.BodyView,
        now_ms: u64,
    ) void {
        const bal_m = self.balancers.get(mirror_name) orelse return;
        const upstream_m = self.upstreams_by_name.get(mirror_name) orelse return;
        const selection = bal_m.select(null, now_ms) orelse return;
        const server_m = selection.server;

        const fd = connectToServer(server_m, 500, upstream_m.allow_private) catch return;
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
            // Same split fallback as handle(): mirror the full body even when
            // headers + body overflow the request buffer.
            const inline_body: []const u8 = req.body.sliceOrNull() orelse "";
            var split_body = false;
            const req_len = forward.buildUpstreamRequest(&mirror_req_buf, &ctx) catch blk: {
                split_body = true;
                break :blk forward.buildUpstreamRequestHeaders(&mirror_req_buf, &ctx, inline_body.len) catch return;
            };
            net.sendAll(fd, mirror_req_buf[0..req_len]) catch return;
            if (split_body and inline_body.len > 0) {
                net.sendAll(fd, inline_body) catch return;
            }
        }
    }

    /// Run periodic maintenance tasks
    pub fn runMaintenance(self: *Proxy, now_ms: u64) void {
        // Evict expired connections
        _ = self.pool_manager.evictAllExpired(now_ms);

        // Apply health check results (non-blocking — checks run on background thread)
        self.health_manager.applyResults(&self.pool_manager);

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
    /// Connection-backpressure window (ms) requested by the request-phase WASM
    /// filter on pool/park-table exhaustion: serve `resp` (a fail-closed 503)
    /// AND pause reads on the connection for this long so a flood self-throttles
    /// (the G2 cliff). null = no pacing (the common path). The transport applies
    /// it via conn.setRateLimitPause, mirroring router HandleResult.pause_reads_ms.
    pause_reads_ms: ?u64 = null,
    /// Response buffer index to release, or null if none held.
    resp_buf_idx: ?usize = null,
    /// Heap allocation backing `resp` when the upstream response outgrew
    /// the fixed pool buffer. Freed by release() unless the caller takes
    /// ownership via takeOwnedBuf() (needed when part of the body remains
    /// queued as conn.pending_body after the response is enqueued).
    owned_buf: ?[]u8 = null,

    pub fn release(self: *ProxyResult) void {
        if (self.resp_buf_idx) |idx| {
            self.proxy.releaseResponseBuffer(idx);
            self.resp_buf_idx = null;
        }
        if (self.owned_buf) |buf| {
            self.proxy.allocator.free(buf);
            self.owned_buf = null;
        }
    }

    /// Transfer ownership of the heap-backed response buffer to the caller
    /// (who must free it with the proxy's allocator once the body bytes are
    /// no longer referenced). Returns null for pool-buffer responses.
    pub fn takeOwnedBuf(self: *ProxyResult) ?[]u8 {
        const buf = self.owned_buf;
        self.owned_buf = null;
        return buf;
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

test "extractTenantKey: host strips port, custom header verbatim, bounds" {
    const tc_host = upstream.TenantRouting{ .socket_dir = "/tmp/" };
    // host with :port -> port stripped.
    const r1 = request.RequestView{ .method = .GET, .path = "/vm/x", .headers = &.{
        .{ .name = "host", .value = "alpha.example.com:8443" },
    } };
    try std.testing.expectEqualStrings("alpha.example.com", extractTenantKey(&r1, tc_host).?);
    // host without a port -> verbatim.
    const r2 = request.RequestView{ .method = .GET, .path = "/vm/x", .headers = &.{
        .{ .name = "host", .value = "beta.example.com" },
    } };
    try std.testing.expectEqualStrings("beta.example.com", extractTenantKey(&r2, tc_host).?);
    // Missing header -> null.
    const r3 = request.RequestView{ .method = .GET, .path = "/vm/x", .headers = &.{} };
    try std.testing.expect(extractTenantKey(&r3, tc_host) == null);

    // A custom header is used verbatim (no port stripping).
    const tc_hdr = upstream.TenantRouting{ .header = "x-tenant", .socket_dir = "/tmp/" };
    const r4 = request.RequestView{ .method = .GET, .path = "/vm/x", .headers = &.{
        .{ .name = "x-tenant", .value = "tenant-42:with-colon" },
    } };
    try std.testing.expectEqualStrings("tenant-42:with-colon", extractTenantKey(&r4, tc_hdr).?);
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
        .route_facilitators = &.{},
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

test "wasm: proxy BodyView (scattered) is filter-readable via body ABI" {
    if (build_options.enable_wasm) {
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");
        var pool = try wasm_filter.Pool.init(std.testing.allocator, FILTER, .{ .instances = 1 });
        defer pool.deinit();

        // A scattered body "deny me now" split across two pool buffers. Maps to
        // RequestBody.scattered, which the filter materializes and inspects.
        var b0 = "deny ".*; // non-last chunk: buffer_size bytes
        var b1 = "me now".*; // last chunk: last_buf_len bytes
        var handles = [_]buffer_pool.BufferHandle{
            .{ .index = 0, .bytes = b0[0..] },
            .{ .index = 1, .bytes = b1[0..] },
        };
        const bv = forward.BodyView{ .buffers = .{
            .handles = handles[0..],
            .last_buf_len = b1.len,
            .total_len = b0.len + b1.len,
            .buffer_size = b0.len,
        } };

        var r = request.RequestView{
            .method = .POST,
            .path = "/submit",
            .headers = &.{},
            .body = bodyViewToRequestBody(bv),
        };
        const d = pool.run(&r, wasm_filter.DEFAULT_FUEL);
        try std.testing.expect(d == .reject);
        try std.testing.expectEqual(@as(u16, 403), d.reject.status);

        // A clean scattered body is allowed.
        var c0 = "hello ".*;
        var c1 = "world".*;
        var handles2 = [_]buffer_pool.BufferHandle{
            .{ .index = 0, .bytes = c0[0..] },
            .{ .index = 1, .bytes = c1[0..] },
        };
        const bv2 = forward.BodyView{ .buffers = .{
            .handles = handles2[0..],
            .last_buf_len = c1.len,
            .total_len = c0.len + c1.len,
            .buffer_size = c0.len,
        } };
        var r2 = request.RequestView{
            .method = .POST,
            .path = "/submit",
            .headers = &.{},
            .body = bodyViewToRequestBody(bv2),
        };
        try std.testing.expect(pool.run(&r2, wasm_filter.DEFAULT_FUEL) == .allow);
    } else return error.SkipZigTest;
}

test "wasm: proxy request filter parks, registers in the table, fires start_fn" {
    if (build_options.enable_wasm) {
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");
        var pool = try wasm_filter.Pool.init(std.testing.allocator, FILTER, .{ .instances = 2 });
        defer pool.deinit();
        var route = upstream.ProxyRoute{
            .path_prefix = "/enrich",
            .upstream = "backend",
            .wasm_pool = @ptrCast(&pool),
            .wasm_fuel = wasm_filter.DEFAULT_FUEL,
        };
        var table = wasm_host_call.Table.init(std.testing.allocator);
        defer table.deinit();

        const Rec = struct {
            var token: ?u32 = null;
            var req_bytes_len: usize = 0;
            fn start(_: *anyopaque, t: u32, req_bytes: []const u8) void {
                token = t;
                req_bytes_len = req_bytes.len;
            }
        };
        Rec.token = null;
        var dummy: u8 = 0;
        const binding = WasmBinding{
            .table = @ptrCast(&table),
            .conn_index = 5,
            .conn_id = 99,
            .deadline_ms = 1_000,
            .start_fn = Rec.start,
            .start_ctx = @ptrCast(&dummy),
        };

        // /enrich stages a host_call and parks.
        const req = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
        const out = runWasmFilter(&route, &req, binding);
        try std.testing.expect(out != null and out.?.resp.isParked());
        try std.testing.expectEqual(@as(usize, 1), table.liveCount());
        try std.testing.expect(Rec.token != null); // start_fn fired with the park token
        try std.testing.expect(Rec.req_bytes_len > 0); // staged command forwarded

        // Resume decisions skip the filter: allow -> proceed (null), reject -> serve.
        try std.testing.expect(runWasmFilter(&route, &req, .{ .resume_decision = .allow }) == null);
        const rej = runWasmFilter(&route, &req, .{ .resume_decision = .{ .reject = .{
            .status = 403,
            .headers = &.{},
            .body = .{ .bytes = "no" },
        } } });
        try std.testing.expect(rej != null);
        try std.testing.expectEqual(@as(u16, 403), rej.?.resp.status);
    } else return error.SkipZigTest;
}

test "wasm: proxy Phase 2b response filter injects a header and rewrites a body" {
    if (build_options.enable_wasm) {
        const RESP_FILTER = @embedFile("../wasm/testdata/response_probe.wasm");
        var pool = try wasm_filter.Pool.init(std.testing.allocator, RESP_FILTER, .{ .instances = 1 });
        defer pool.deinit();
        var route = upstream.ProxyRoute{
            .path_prefix = "/api/",
            .upstream = "backend",
            .wasm_pool = @ptrCast(&pool),
            .wasm_fuel = wasm_filter.DEFAULT_FUEL,
        };
        const req = request.RequestView{ .method = .GET, .path = "/api/widgets", .headers = &.{} };

        // Default path: the response filter adds the x-wasm-response header.
        var resp = response.Response{ .status = 200, .headers = &.{}, .body = .{ .bytes = "upstream body" } };
        runWasmResponseFilter(&route, &req, &resp);
        var found = false;
        for (resp.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "x-wasm-response")) found = true;
        }
        try std.testing.expect(found);

        // "boom" body: the filter blocks it (403 + replacement body).
        var resp2 = response.Response{ .status = 200, .headers = &.{}, .body = .{ .bytes = "boom leak" } };
        runWasmResponseFilter(&route, &req, &resp2);
        try std.testing.expectEqual(@as(u16, 403), resp2.status);
        try std.testing.expectEqualStrings("blocked by edge", resp2.bodyBytes());
    } else return error.SkipZigTest;
}

// --- D2 security probing through the proxy filter hook -----------------------

test "D2-4 fail-closed: a trapping proxy request filter never forwards upstream" {
    if (build_options.enable_wasm) {
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");
        var pool = try wasm_filter.Pool.init(std.testing.allocator, FILTER, .{ .instances = 2 });
        defer pool.deinit();
        var route = upstream.ProxyRoute{
            .path_prefix = "/",
            .upstream = "backend",
            .wasm_pool = @ptrCast(&pool),
            .wasm_fuel = 200_000,
        };
        // runWasmFilter returns null to mean "forward to upstream". A trapping
        // filter must NEVER return null -- it must return a fail-closed reject
        // (500) so the upstream is never reached.
        for ([_][]const u8{ "/oob", "/loop" }) |p| {
            const req = request.RequestView{ .method = .GET, .path = p, .headers = &.{} };
            const out = runWasmFilter(&route, &req, .{});
            try std.testing.expect(out != null);
            try std.testing.expectEqual(@as(u16, 500), out.?.resp.status);
        }
    } else return error.SkipZigTest;
}

test "D2-5 fail-closed: proxy filter pool exhaustion -> 503 then recovery" {
    if (build_options.enable_wasm) {
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");
        var pool = try wasm_filter.Pool.init(std.testing.allocator, FILTER, .{ .instances = 1 });
        defer pool.deinit();
        var route = upstream.ProxyRoute{
            .path_prefix = "/enrich",
            .upstream = "backend",
            .wasm_pool = @ptrCast(&pool),
            .wasm_fuel = wasm_filter.DEFAULT_FUEL,
        };
        var table = wasm_host_call.Table.init(std.testing.allocator);
        defer table.deinit();
        const binding = WasmBinding{
            .table = @ptrCast(&table),
            .conn_index = 1,
            .conn_id = 1,
            .deadline_ms = 9_999_999,
        };
        const req = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };

        // Pin the only instance: the park path's acquire() fails -> fail closed 503.
        const pinned = pool.acquire() orelse return error.AcquireFailed;
        const out = runWasmFilter(&route, &req, binding);
        try std.testing.expect(out != null);
        try std.testing.expectEqual(@as(u16, 503), out.?.resp.status);
        try std.testing.expectEqual(@as(usize, 0), table.liveCount()); // nothing parked
        // G2: the 503 now also carries a connection-backpressure window so the
        // proxy path paces the flood (conn.setRateLimitPause) instead of
        // CPU-burning bare 503s. Fail-closed (the 503) is unchanged.
        try std.testing.expect(out.?.pause_reads_ms != null);
        try std.testing.expectEqual(wasm_filter.POOL_BACKPRESSURE_MS, out.?.pause_reads_ms.?);

        // Release -> recovery: the filter now parks (registers in the table).
        pinned.state = .idle;
        const out2 = runWasmFilter(&route, &req, binding);
        try std.testing.expect(out2 != null and out2.?.resp.isParked());
        try std.testing.expectEqual(@as(usize, 1), table.liveCount());
    } else return error.SkipZigTest;
}

test "Proxy.init does not start the health thread (Server.run starts it at the final address)" {
    // Regression guard: init used to call health_manager.startThread() on the
    // stack-local Proxy it returns BY VALUE. The spawned thread captured
    // &health_manager of the dead init frame and read garbage checker state,
    // a layout-dependent segfault on Linux ReleaseFast (found via the
    // load-balancer benchmark scenario, 2026-07-07).
    const allocator = std.testing.allocator;
    const servers = [_]upstream.Server{.{ .address = "127.0.0.1", .port = 1 }};
    const upstreams = [_]upstream.Upstream{.{
        .name = "hc",
        .servers = &servers,
        .health_check = .{},
    }};
    const routes = [_]upstream.ProxyRoute{.{ .path_prefix = "/", .upstream = "hc" }};

    var proxy = try Proxy.init(allocator, .{ .upstreams = &upstreams, .routes = &routes });
    defer proxy.deinit();

    // The checker is registered, but no thread may run until the struct sits
    // at its final address (Server.run / the reload swap call startThread).
    try std.testing.expectEqual(@as(u32, 1), proxy.health_manager.checkers.count());
    try std.testing.expect(proxy.health_manager.thread_handle == null);
}

test "handle() forwards inline bodies larger than the request buffer (8KB-64KB 502 regression)" {
    // Regression: buildUpstreamRequest copies headers + body into the pooled
    // REQUEST_BUF_SIZE (8KB) request buffer. Requests whose headers + body land
    // between that and the connection read buffer (below which dispatch still
    // takes the small-body handle() path) got a 502 - and each attempt counted
    // a failure against a healthy upstream connection. handle() now falls back
    // to sending headers and the body slice separately.
    const allocator = std.testing.allocator;

    const lfd = net.listen("127.0.0.1", 0, 4) catch return error.SkipZigTest;
    defer clock.closeFd(lfd);
    const port = net.getLocalPort(lfd) orelse return error.SkipZigTest;

    const Upstream = struct {
        fn setBlocking(fd: std.posix.fd_t) void {
            const flags = std.c.fcntl(fd, std.posix.F.GETFL);
            if (flags < 0) return;
            const nonblock: c_int = @bitCast(@as(c_uint, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK"));
            _ = std.c.fcntl(fd, std.posix.F.SETFL, flags & ~nonblock);
        }

        fn serve(listen_fd: std.posix.fd_t, got_body_len: *usize) void {
            // net.listen/net.accept are nonblocking (built for the event
            // loop); spin until the proxy connects, then flip the accepted
            // fd back to blocking for the simple request/response exchange.
            const cfd = while (true) {
                const fd = net.accept(listen_fd) catch |err| switch (err) {
                    error.WouldBlock => {
                        std.Thread.yield() catch {};
                        continue;
                    },
                    else => return,
                };
                break fd;
            };
            defer clock.closeFd(cfd);
            setBlocking(cfd);
            var buf: [64 * 1024]u8 = undefined;
            var total: usize = 0;
            var header_end: ?usize = null;
            var content_length: usize = 0;
            while (total < buf.len) {
                const n = net.recvBlocking(cfd, buf[total..]) catch return;
                if (n == 0) break;
                total += n;
                if (header_end == null) {
                    if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |he| {
                        header_end = he + 4;
                        var it = std.mem.splitSequence(u8, buf[0..he], "\r\n");
                        while (it.next()) |line| {
                            const prefix = "content-length:";
                            if (line.len > prefix.len and std.ascii.startsWithIgnoreCase(line, prefix)) {
                                const v = std.mem.trim(u8, line[prefix.len..], " \t");
                                content_length = std.fmt.parseInt(usize, v, 10) catch 0;
                            }
                        }
                    }
                }
                if (header_end) |he| {
                    if (total >= he + content_length) break;
                }
            }
            if (header_end) |he| got_body_len.* = total - he;
            net.sendAll(cfd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") catch {};
        }
    };

    var got_body_len: usize = 0;
    const upstream_thread = try std.Thread.spawn(.{}, Upstream.serve, .{ lfd, &got_body_len });

    const servers = [_]upstream.Server{.{ .address = "127.0.0.1", .port = port }};
    const upstreams = [_]upstream.Upstream{.{ .name = "u", .servers = &servers }};
    const routes = [_]upstream.ProxyRoute{.{ .path_prefix = "/", .upstream = "u" }};
    var proxy = try Proxy.init(allocator, .{ .upstreams = &upstreams, .routes = &routes });
    defer proxy.deinit();

    // 16KB body: well under the 64KB read buffer (so real dispatch would take
    // the small-body handle() path) but overflows the 8KB request buffer
    // together with the headers.
    const body = try allocator.alloc(u8, 16 * 1024);
    defer allocator.free(body);
    @memset(body, 'b');

    const req = request.RequestView{
        .method = .POST,
        .path = "/big",
        .headers = &.{.{ .name = "host", .value = "test.local" }},
        .body = .{ .slice = body },
    };
    var mw_ctx: middleware.Context = undefined;
    var pr = proxy.handle(req, &mw_ctx, null, false, 12345, null, null, .{});
    defer pr.release();
    upstream_thread.join();

    try std.testing.expectEqual(@as(u16, 200), pr.resp.status);
    try std.testing.expectEqual(body.len, got_body_len);
}
