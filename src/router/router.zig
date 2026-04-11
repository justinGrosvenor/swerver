const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const x402 = @import("../middleware/x402.zig");
const middleware = @import("../middleware/middleware.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");
const clock = @import("../runtime/clock.zig");

pub const RouterError = error{
    RouteLimitExceeded,
    SegmentLimitExceeded,
    ParamLimitExceeded,
    PatternTooLong,
    NoBufferOps,
    NoBuffers,
};

/// Result of routing a request
pub const RouteResult = struct {
    /// Response to send
    resp: response.Response,
    /// If non-null, pause reads for this many milliseconds (rate limiting)
    pause_reads_ms: ?u64 = null,
};

/// Handler function type
pub const HandlerFn = *const fn (ctx: *HandlerContext) response.Response;

/// Context passed to route handlers
pub const HandlerContext = struct {
    request: request.RequestView,
    middleware_ctx: *middleware.Context,
    app_state: ?*anyopaque = null,
    app_services: ?*anyopaque = null,
    app_services_get: ?ServiceGetter = null,
    buffer_ops: ?middleware.BufferOps = null,
    /// Path parameters extracted from route (e.g., /users/:id)
    params: [MAX_PARAMS]Param = undefined,
    param_count: u8 = 0,
    /// Response buffer for building dynamic responses
    response_buf: []u8,
    /// Response headers built for default responses
    response_headers: []response.Header,
    response_header_count: usize = 0,
    /// Request-scoped arena allocator
    arena: std.heap.FixedBufferAllocator,

    pub const Param = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const ResponseBuilder = struct {
        handle: buffer_pool.BufferHandle,
        len: usize = 0,
        used: bool = false,

        pub const BuildError = error{BufferFull};

        pub fn init(handle: buffer_pool.BufferHandle) ResponseBuilder {
            return .{ .handle = handle };
        }

        pub fn reset(self: *ResponseBuilder) void {
            self.len = 0;
        }

        pub fn append(self: *ResponseBuilder, data: []const u8) BuildError!void {
            if (self.len + data.len > self.handle.bytes.len) return error.BufferFull;
            @memcpy(self.handle.bytes[self.len .. self.len + data.len], data);
            self.len += data.len;
        }

        pub fn bytes(self: *const ResponseBuilder) []const u8 {
            return self.handle.bytes[0..self.len];
        }

        pub fn text(self: *ResponseBuilder, status: u16, body: []const u8) BuildError!response.Response {
            self.reset();
            try self.append(body);
            self.used = true;
            return .{
                .status = status,
                .headers = &[_]response.Header{
                    .{ .name = "Content-Type", .value = "text/plain" },
                },
                .body = .{ .managed = .{ .handle = self.handle, .len = self.len } },
            };
        }

        pub fn json(self: *ResponseBuilder, status: u16, body: []const u8) BuildError!response.Response {
            self.reset();
            try self.append(body);
            self.used = true;
            return .{
                .status = status,
                .headers = &[_]response.Header{
                    .{ .name = "Content-Type", .value = "application/json" },
                },
                .body = .{ .managed = .{ .handle = self.handle, .len = self.len } },
            };
        }

        pub fn html(self: *ResponseBuilder, status: u16, body: []const u8) BuildError!response.Response {
            self.reset();
            try self.append(body);
            self.used = true;
            return .{
                .status = status,
                .headers = &[_]response.Header{
                    .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
                },
                .body = .{ .managed = .{ .handle = self.handle, .len = self.len } },
            };
        }

        pub fn release(self: *ResponseBuilder, ops: middleware.BufferOps) void {
            if (!self.used) {
                ops.release(ops.ctx, self.handle);
            }
        }
    };

    /// Start building a response in the request-scoped buffer.
    pub fn respond(self: *HandlerContext) RouterError!ResponseBuilder {
        const ops = self.buffer_ops orelse return error.NoBufferOps;
        const handle = ops.acquire(ops.ctx) orelse return error.NoBuffers;
        return ResponseBuilder.init(handle);
    }

    pub fn releaseBuilder(self: *HandlerContext, builder: *ResponseBuilder) void {
        const ops = self.buffer_ops orelse return;
        builder.release(ops);
    }

    /// Access app state (set via ServerBuilder.withState).
    /// NOTE: T must match the type originally passed to withState(). The pointer
    /// must be naturally aligned for T — misaligned pointers cause a safety
    /// check panic in Debug/ReleaseSafe modes and UB in ReleaseFast.
    pub fn state(self: *const HandlerContext, comptime T: type) *T {
        std.debug.assert(self.app_state != null);
        return @ptrCast(@alignCast(self.app_state.?));
    }

    /// Access typed services (set via ServerBuilder.withServices).
    /// NOTE: T must match the type originally passed to withServices(). The pointer
    /// must be naturally aligned for T.
    pub fn services(self: *const HandlerContext, comptime T: type) *T {
        std.debug.assert(self.app_services != null);
        return @ptrCast(@alignCast(self.app_services.?));
    }

    /// Typed lookup from services (optional sugar).
    /// Returns null if the service type is not registered.
    pub fn get(self: *const HandlerContext, comptime T: type) ?*T {
        const services_ptr = self.app_services orelse return null;
        const getter = self.app_services_get orelse return null;
        const raw = getter(services_ptr, @typeName(T)) orelse return null;
        return @ptrCast(@alignCast(raw));
    }

    /// Request-scoped allocator (valid only during handler execution).
    pub fn arenaAllocator(self: *HandlerContext) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Get path parameter by name
    pub fn getParam(self: *const HandlerContext, name: []const u8) ?[]const u8 {
        for (self.params[0..self.param_count]) |p| {
            if (std.mem.eql(u8, p.name, name)) {
                return p.value;
            }
        }
        return null;
    }

    /// Build a JSON response
    pub fn json(_: *HandlerContext, status: u16, body: []const u8) response.Response {
        return .{
            .status = status,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = body },
        };
    }

    /// Build a text response
    pub fn text(self: *HandlerContext, status: u16, body: []const u8) response.Response {
        _ = self;
        return .{
            .status = status,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
            },
            .body = .{ .bytes = body },
        };
    }

    /// Build an HTML response
    pub fn html(self: *HandlerContext, status: u16, body: []const u8) response.Response {
        _ = self;
        return .{
            .status = status,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
            },
            .body = .{ .bytes = body },
        };
    }
};

pub const RouteBuilder = struct {
    router: *Router,
    method: request.Method,
    pattern: []const u8,
    handler: HandlerFn,
    middleware_chain: ?*middleware.Chain = null,

    pub fn withMiddleware(self: *RouteBuilder, chain: *middleware.Chain) *RouteBuilder {
        self.middleware_chain = chain;
        return self;
    }

    pub fn register(self: *RouteBuilder) RouterError!void {
        return self.router.routeWithChain(self.method, self.pattern, self.handler, self.middleware_chain);
    }
};

pub const GroupBuilder = struct {
    router: *Router,
    prefix: []const u8,
    middleware_chain: ?*middleware.Chain = null,

    pub fn withMiddleware(self: *GroupBuilder, chain: *middleware.Chain) *GroupBuilder {
        self.middleware_chain = chain;
        return self;
    }

    pub fn get(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefix(.GET, self.prefix, pattern, handler, self.middleware_chain);
    }

    pub fn post(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefix(.POST, self.prefix, pattern, handler, self.middleware_chain);
    }

    pub fn put(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefix(.PUT, self.prefix, pattern, handler, self.middleware_chain);
    }

    pub fn delete(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefix(.DELETE, self.prefix, pattern, handler, self.middleware_chain);
    }

    pub fn patch(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefix(.PATCH, self.prefix, pattern, handler, self.middleware_chain);
    }
};

pub const HandlerScratch = struct {
    response_buf: []u8,
    response_headers: []response.Header,
    arena_buf: []u8,
    arena_handle: ?buffer_pool.BufferHandle = null,
    buffer_ops: ?middleware.BufferOps = null,
};

pub const RouterLimits = struct {
    max_routes: usize = MAX_ROUTES,
    max_segments: u8 = MAX_SEGMENTS,
    max_params: u8 = MAX_PARAMS,
};

/// Route entry
pub const Route = struct {
    method: request.Method,
    pattern: []const u8,
    handler: HandlerFn,
    middleware_chain: ?*middleware.Chain = null,
    pattern_buf: [MAX_PATTERN_LEN]u8 = undefined,
    pattern_len: usize = 0,
    param_count: u8 = 0,
    /// Pre-parsed pattern segments for matching
    segments: [16]Segment = undefined,
    segment_count: u8 = 0,

    const Segment = union(enum) {
        literal: []const u8,
        param: []const u8, // parameter name without ':'
        wildcard, // matches rest of path (*)
    };

    fn compile(pattern: []const u8, limits: RouterLimits) RouterError!Route {
        var route = Route{
            .method = .GET,
            .pattern = pattern,
            .handler = undefined,
        };

        var it = std.mem.splitScalar(u8, pattern, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            if (route.segment_count >= limits.max_segments) return error.SegmentLimitExceeded;

            if (seg[0] == ':') {
                if (route.param_count >= limits.max_params) return error.ParamLimitExceeded;
                route.segments[route.segment_count] = .{ .param = seg[1..] };
                route.param_count += 1;
            } else if (seg[0] == '*') {
                route.segments[route.segment_count] = .wildcard;
            } else {
                route.segments[route.segment_count] = .{ .literal = seg };
            }
            route.segment_count += 1;
        }

        return route;
    }

    fn compileWithPrefix(prefix: []const u8, pattern: []const u8, limits: RouterLimits) RouterError!Route {
        var route = Route{
            .method = .GET,
            .pattern = pattern,
            .handler = undefined,
        };

        try appendSegments(&route, prefix, limits);
        try appendSegments(&route, pattern, limits);
        return route;
    }

    fn appendSegments(route: *Route, value: []const u8, limits: RouterLimits) RouterError!void {
        var it = std.mem.splitScalar(u8, value, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            if (route.segment_count >= limits.max_segments) return error.SegmentLimitExceeded;

            if (seg[0] == ':') {
                if (route.param_count >= limits.max_params) return error.ParamLimitExceeded;
                route.segments[route.segment_count] = .{ .param = seg[1..] };
                route.param_count += 1;
            } else if (seg[0] == '*') {
                route.segments[route.segment_count] = .wildcard;
            } else {
                route.segments[route.segment_count] = .{ .literal = seg };
            }
            route.segment_count += 1;
        }
    }
};

/// Maximum number of routes
const MAX_ROUTES = 128;
const MAX_SEGMENTS = 16;
const MAX_PARAMS = 8;
const MAX_PATTERN_LEN = 256;

pub const RESPONSE_BUF_SIZE = 8192;
pub const MAX_RESPONSE_HEADERS = 4;
pub const ARENA_BUF_SIZE = 16 * 1024;

pub const ServiceGetter = *const fn (*anyopaque, []const u8) ?*anyopaque;

/// Router with route registration and matching
pub const Router = struct {
    routes: [MAX_ROUTES]Route = undefined,
    route_count: usize = 0,
    x402_policy: x402.Policy,
    middleware_chain: middleware.Chain,
    limits: RouterLimits = .{},
    app_state: ?*anyopaque = null,
    app_services: ?*anyopaque = null,
    app_services_get: ?ServiceGetter = null,
    /// Default 404 handler
    not_found_handler: ?HandlerFn = null,
    /// Default 405 handler
    method_not_allowed_handler: ?HandlerFn = null,
    /// Default 500 handler
    error_handler: ?HandlerFn = null,
    /// Bloom filter over registered routes' first path segments.
    /// A request whose first segment's hash bit is NOT set in this
    /// filter cannot match any route — the handle() loop can return
    /// 404 immediately without iterating routes or running middleware.
    /// False positives (bit set but no actual match) fall through to
    /// the normal route scan. 64 bits → ~50% false-positive rate at
    /// 10 routes, which still cuts the no-match path in half.
    first_segment_bloom: u64 = 0,

    pub fn init(policy: x402.Policy) Router {
        return .{
            .x402_policy = policy,
            .middleware_chain = middleware.Chain.init(&.{}, &.{}),
        };
    }

    pub fn initWithLimits(policy: x402.Policy, limits: RouterLimits) Router {
        std.debug.assert(limits.max_routes <= MAX_ROUTES);
        std.debug.assert(limits.max_segments <= MAX_SEGMENTS);
        std.debug.assert(limits.max_params <= MAX_PARAMS);
        return .{
            .x402_policy = policy,
            .middleware_chain = middleware.Chain.init(&.{}, &.{}),
            .limits = limits,
        };
    }

    /// Set middleware chain
    pub fn setMiddleware(self: *Router, chain: middleware.Chain) void {
        self.middleware_chain = chain;
    }

    /// Set app state pointer (for HandlerContext.state).
    pub fn setState(self: *Router, state: ?*anyopaque) void {
        self.app_state = state;
    }

    /// Set services pointer (for HandlerContext.services).
    pub fn setServices(self: *Router, services: ?*anyopaque) void {
        self.app_services = services;
    }

    pub fn setServicesWithGetter(self: *Router, services: ?*anyopaque, getter: ?ServiceGetter) void {
        self.app_services = services;
        self.app_services_get = getter;
    }

    /// Create a grouped router with a path prefix.
    pub fn group(self: *Router, prefix: []const u8) GroupBuilder {
        return .{ .router = self, .prefix = prefix };
    }

    /// Register a GET route builder.
    pub fn routeBuilder(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn) RouteBuilder {
        return .{
            .router = self,
            .method = method,
            .pattern = pattern,
            .handler = handler,
        };
    }

    /// Register a GET route
    pub fn get(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.GET, pattern, handler);
    }

    /// Register a POST route
    pub fn post(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.POST, pattern, handler);
    }

    /// Register a PUT route
    pub fn put(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.PUT, pattern, handler);
    }

    /// Register a DELETE route
    pub fn delete(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.DELETE, pattern, handler);
    }

    /// Register a PATCH route
    pub fn patch(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.PATCH, pattern, handler);
    }

    /// Register a route with any method
    pub fn route(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.routeWithChain(method, pattern, handler, null);
    }

    /// Register a route with a custom middleware chain.
    pub fn routeWithChain(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn, chain: ?*middleware.Chain) RouterError!void {
        if (self.route_count >= self.limits.max_routes) return error.RouteLimitExceeded;

        var r = try Route.compile(pattern, self.limits);
        try self.storePattern(&r, pattern);
        r.method = method;
        r.handler = handler;
        r.middleware_chain = chain;
        self.routes[self.route_count] = r;
        self.route_count += 1;
        self.updateBloomFilter(pattern);
    }

    pub fn routeWithPrefix(self: *Router, method: request.Method, prefix: []const u8, pattern: []const u8, handler: HandlerFn, chain: ?*middleware.Chain) RouterError!void {
        if (self.route_count >= self.limits.max_routes) return error.RouteLimitExceeded;

        var r = try Route.compileWithPrefix(prefix, pattern, self.limits);
        try self.storePatternWithPrefix(&r, prefix, pattern);
        r.method = method;
        r.handler = handler;
        r.middleware_chain = chain;
        self.routes[self.route_count] = r;
        self.route_count += 1;
        // For prefixed routes, hash the combined first segment
        if (prefix.len > 0) {
            self.updateBloomFilter(prefix);
        } else {
            self.updateBloomFilter(pattern);
        }
    }

    /// Add the first path segment's hash to the bloom filter.
    fn updateBloomFilter(self: *Router, pattern: []const u8) void {
        const seg = firstPathSegment(pattern);
        if (seg.len > 0) {
            const hash = std.hash.Wyhash.hash(0, seg);
            self.first_segment_bloom |= @as(u64, 1) << @intCast(hash % 64);
        }
    }

    /// Extract the first non-empty path segment from a path/pattern.
    fn firstPathSegment(path: []const u8) []const u8 {
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |seg| {
            if (seg.len > 0) return seg;
        }
        return "";
    }

    /// Set custom 404 handler
    pub fn setNotFound(self: *Router, handler: HandlerFn) void {
        self.not_found_handler = handler;
    }

    /// Set custom 404 handler (alias).
    pub fn fallback(self: *Router, handler: HandlerFn) void {
        self.setNotFound(handler);
    }

    /// Set custom 405 handler.
    pub fn methodNotAllowed(self: *Router, handler: HandlerFn) void {
        self.method_not_allowed_handler = handler;
    }

    /// Set custom error handler
    pub fn setErrorHandler(self: *Router, handler: HandlerFn) void {
        self.error_handler = handler;
    }

    /// Handle an incoming request
    /// Returns RouteResult with response and optional backpressure signal
    pub fn handle(self: *Router, req: request.RequestView, mw_ctx: *middleware.Context, scratch: *HandlerScratch) RouteResult {
        // Bloom filter fast-reject: if the request's first path
        // segment doesn't have its hash bit set in the filter, no
        // registered route can match. Return 404 immediately without
        // running x402 checks, middleware, or the route loop. This
        // cuts the error-handling benchmark's 404 path from O(N
        // routes) to O(1).
        if (self.first_segment_bloom != 0) {
            // Strip query string before hashing — registered routes
            // don't include query params, but request paths do.
            const clean = if (std.mem.indexOfScalar(u8, req.path, '?')) |qi| req.path[0..qi] else req.path;
            const seg = firstPathSegment(clean);
            if (seg.len > 0) {
                const hash = std.hash.Wyhash.hash(0, seg);
                const bit = @as(u64, 1) << @intCast(hash % 64);
                if ((self.first_segment_bloom & bit) == 0) {
                    return .{ .resp = notFound() };
                }
            }
        }

        // Run x402 check first
        switch (x402.evaluate(req, self.x402_policy)) {
            .allow => {},
            .reject => |resp| return .{ .resp = resp },
        }

        // Run middleware chain
        switch (self.middleware_chain.executePre(mw_ctx, req)) {
            .allow => {},
            .reject => |resp| return .{ .resp = resp },
            .backpressure => |bp| return .{
                .resp = bp.resp,
                .pause_reads_ms = if (bp.pause_reads) bp.resume_after_ms else null,
            },
        }

        // Find matching route
        var ctx = HandlerContext{
            .request = req,
            .middleware_ctx = mw_ctx,
            .app_state = self.app_state,
            .app_services = self.app_services,
            .app_services_get = self.app_services_get,
            .buffer_ops = scratch.buffer_ops,
            .params = undefined,
            .param_count = 0,
            .response_buf = scratch.response_buf,
            .response_headers = scratch.response_headers,
            .response_header_count = 0,
            .arena = std.heap.FixedBufferAllocator.init(scratch.arena_buf),
        };

        // Capture the request start time for post-response elapsed
        // calculation. Set it here (after pre-middleware) so elapsed
        // reflects handler time, not middleware overhead.
        mw_ctx.request_start = clock.Instant.now();

        var result_resp: response.Response = undefined;
        const result_pause: ?u64 = null;
        var ran_handler = false;

        var path_matched = false;
        for (self.routes[0..self.route_count]) |r| {
            if (!self.matchRoute(&r, req.path, &ctx)) continue;
            if (r.method != req.method) {
                path_matched = true;
                continue;
            }
            mw_ctx.route = r.pattern;
            if (r.middleware_chain) |chain| {
                switch (chain.executePre(mw_ctx, req)) {
                    .allow => {},
                    .reject => |resp| {
                        result_resp = resp;
                        return .{ .resp = result_resp };
                    },
                    .backpressure => |bp| {
                        return .{
                            .resp = bp.resp,
                            .pause_reads_ms = if (bp.pause_reads) bp.resume_after_ms else null,
                        };
                    },
                }
            }
            result_resp = r.handler(&ctx);
            ran_handler = true;
            break;
        }

        if (!ran_handler) {
            // No route matched - 404 / 405
            if (path_matched) {
                result_resp = if (self.method_not_allowed_handler) |handler|
                    handler(&ctx)
                else
                    self.defaultMethodNotAllowed(&ctx);
            } else {
                result_resp = if (self.not_found_handler) |handler|
                    handler(&ctx)
                else
                    notFound();
            }
        }

        // Post-response hooks: access logging, structured logging,
        // metrics recording. Runs for every request that made it past
        // the pre-request middleware chain — including 404s and 405s
        // from the router (those are real requests that deserve logs).
        // Does NOT run for x402 rejects, rate-limit rejects, or
        // bloom-filter fast-rejects (those exit before this point).
        const elapsed_ns: u64 = if (mw_ctx.request_start) |start|
            if (clock.Instant.now()) |now_inst| now_inst.since(start) else 0
        else
            0;
        self.middleware_chain.executePost(mw_ctx, req, result_resp, elapsed_ns);

        return .{ .resp = result_resp, .pause_reads_ms = result_pause };
    }

    /// Quick O(route_count) check: does ANY registered route's path
    /// pattern match `path` (ignoring method)? Used by the server to
    /// fast-reject 404s before setting up middleware/arena/scratch.
    /// Does NOT run middleware or handlers — purely structural.
    pub fn hasAnyRouteForPath(self: *Router, path: []const u8) bool {
        // Strip query string for matching (same as matchRoute).
        const clean_path = if (std.mem.indexOfScalar(u8, path, '?')) |qi| path[0..qi] else path;
        for (self.routes[0..self.route_count]) |r| {
            if (pathMatchesPattern(r.pattern, clean_path)) return true;
        }
        return false;
    }

    /// Lightweight path-vs-pattern match (no param extraction).
    fn pathMatchesPattern(pattern: []const u8, path: []const u8) bool {
        // Exact match fast path
        if (std.mem.eql(u8, pattern, path)) return true;

        // Static prefix check — if the pattern has no `:` params, it
        // must match exactly or with a trailing `/` difference.
        if (std.mem.indexOfScalar(u8, pattern, ':') == null) {
            // Check for trailing-slash tolerance
            if (pattern.len > 0 and path.len > 0) {
                if (pattern.len == path.len + 1 and pattern[pattern.len - 1] == '/') {
                    return std.mem.eql(u8, pattern[0 .. pattern.len - 1], path);
                }
                if (path.len == pattern.len + 1 and path[path.len - 1] == '/') {
                    return std.mem.eql(u8, path[0 .. path.len - 1], pattern);
                }
            }
            return false;
        }

        // Pattern has params — do segment-by-segment comparison.
        // `:name` segments match any non-empty segment.
        var pat_it = std.mem.splitScalar(u8, if (pattern.len > 0 and pattern[0] == '/') pattern[1..] else pattern, '/');
        var path_it = std.mem.splitScalar(u8, if (path.len > 0 and path[0] == '/') path[1..] else path, '/');

        while (true) {
            const pat_seg = pat_it.next();
            const path_seg = path_it.next();
            if (pat_seg == null and path_seg == null) return true;
            if (pat_seg == null or path_seg == null) return false;
            if (pat_seg.?.len > 0 and pat_seg.?[0] == ':') continue; // param matches anything
            if (!std.mem.eql(u8, pat_seg.?, path_seg.?)) return false;
        }
    }

    fn matchRoute(self: *Router, r: *const Route, path: []const u8, ctx: *HandlerContext) bool {
        _ = self;
        ctx.param_count = 0;

        // Strip the query string before segment matching. RFC 3986
        // §3.3: the path ends at the first `?` or `#`. Pre-this-fix
        // the router did literal segment compare on the full
        // request-target so `/baseline2?a=1&b=1` failed to match
        // a route registered as `/baseline2`.
        const path_only = blk: {
            if (std.mem.indexOfScalar(u8, path, '?')) |q| break :blk path[0..q];
            if (std.mem.indexOfScalar(u8, path, '#')) |f| break :blk path[0..f];
            break :blk path;
        };

        var path_it = std.mem.splitScalar(u8, path_only, '/');
        var seg_idx: u8 = 0;

        while (path_it.next()) |path_seg| {
            if (path_seg.len == 0) continue;

            if (seg_idx >= r.segment_count) {
                // More path segments than pattern segments
                return false;
            }

            switch (r.segments[seg_idx]) {
                .literal => |lit| {
                    if (!std.mem.eql(u8, lit, path_seg)) {
                        return false;
                    }
                },
                .param => |name| {
                    if (ctx.param_count < MAX_PARAMS) {
                        ctx.params[ctx.param_count] = .{
                            .name = name,
                            .value = path_seg,
                        };
                        ctx.param_count += 1;
                    }
                },
                .wildcard => {
                    // Wildcard matches rest of path
                    return true;
                },
            }
            seg_idx += 1;
        }

        // All path segments consumed - check we matched all pattern segments
        return seg_idx == r.segment_count;
    }

    fn defaultMethodNotAllowed(self: *Router, ctx: *HandlerContext) response.Response {
        ctx.response_header_count = 0;
        const allow_value = self.buildAllowHeader(ctx.request.path, ctx);
        if (allow_value.len > 0 and ctx.response_headers.len > 0) {
            ctx.response_headers[0] = .{ .name = "Allow", .value = allow_value };
            ctx.response_header_count = 1;
        }
        return .{
            .status = 405,
            .headers = ctx.response_headers[0..ctx.response_header_count],
            .body = .{ .bytes = "Method Not Allowed" },
        };
    }

    fn buildAllowHeader(self: *Router, path: []const u8, ctx: *HandlerContext) []const u8 {
        const method_count = @typeInfo(request.Method).@"enum".fields.len;
        var allowed: [method_count]bool = [_]bool{false} ** method_count;
        var temp_ctx = HandlerContext{
            .request = ctx.request,
            .middleware_ctx = ctx.middleware_ctx,
            .app_state = ctx.app_state,
            .app_services = ctx.app_services,
            .app_services_get = ctx.app_services_get,
            .buffer_ops = null,
            .params = undefined,
            .param_count = 0,
            .response_buf = ctx.response_buf,
            .response_headers = ctx.response_headers,
            .response_header_count = 0,
            .arena = std.heap.FixedBufferAllocator.init(&[_]u8{}),
        };

        for (self.routes[0..self.route_count]) |r| {
            if (self.matchRoute(&r, path, &temp_ctx)) {
                const idx = @intFromEnum(r.method);
                allowed[idx] = true;
            }
        }

        var out = ctx.response_buf[0..];
        var pos: usize = 0;
        var first = true;
        for (allowed, 0..) |is_allowed, idx| {
            if (!is_allowed) continue;
            const method = @as(request.Method, @enumFromInt(idx));
            const name = method.toString();
            const extra: usize = if (first) 0 else 2;
            if (pos + extra + name.len > out.len) break;
            if (!first) {
                out[pos] = ',';
                out[pos + 1] = ' ';
                pos += 2;
            }
            @memcpy(out[pos .. pos + name.len], name);
            pos += name.len;
            first = false;
        }

        return out[0..pos];
    }

    fn storePattern(self: *Router, r: *Route, pattern: []const u8) RouterError!void {
        _ = self;
        if (pattern.len > MAX_PATTERN_LEN) return error.PatternTooLong;
        @memcpy(r.pattern_buf[0..pattern.len], pattern);
        r.pattern_len = pattern.len;
        r.pattern = r.pattern_buf[0..r.pattern_len];
    }

    fn storePatternWithPrefix(self: *Router, r: *Route, prefix: []const u8, pattern: []const u8) RouterError!void {
        _ = self;
        var full_len = prefix.len + pattern.len;
        var needs_slash = false;
        if (prefix.len > 0 and pattern.len > 0) {
            const prefix_slash = prefix[prefix.len - 1] == '/';
            const pattern_slash = pattern[0] == '/';
            if (!prefix_slash and !pattern_slash) {
                needs_slash = true;
                full_len += 1;
            }
            if (prefix_slash and pattern_slash) {
                full_len -= 1;
            }
        }

        if (full_len > MAX_PATTERN_LEN) return error.PatternTooLong;

        var pos: usize = 0;
        @memcpy(r.pattern_buf[pos .. pos + prefix.len], prefix);
        pos += prefix.len;
        if (needs_slash) {
            r.pattern_buf[pos] = '/';
            pos += 1;
        } else if (prefix.len > 0 and pattern.len > 0 and prefix[prefix.len - 1] == '/' and pattern[0] == '/') {
            // Skip the leading slash in pattern
        }

        if (prefix.len > 0 and pattern.len > 0 and prefix[prefix.len - 1] == '/' and pattern[0] == '/') {
            @memcpy(r.pattern_buf[pos .. pos + pattern.len - 1], pattern[1..]);
            pos += pattern.len - 1;
        } else {
            @memcpy(r.pattern_buf[pos .. pos + pattern.len], pattern);
            pos += pattern.len;
        }

        r.pattern_len = pos;
        r.pattern = r.pattern_buf[0..r.pattern_len];
    }
};

/// Default 404 response
fn notFound() response.Response {
    return .{
        .status = 404,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "Not Found" },
    };
}

/// Default 405 response
/// Default 500 response
pub fn internalError() response.Response {
    return .{
        .status = 500,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "Internal Server Error" },
    };
}

// Tests
test "route compilation" {
    const r = try Route.compile("/users/:id/posts/:post_id", .{});
    try std.testing.expectEqual(@as(u8, 4), r.segment_count);
    try std.testing.expectEqualStrings("users", r.segments[0].literal);
    try std.testing.expectEqualStrings("id", r.segments[1].param);
    try std.testing.expectEqualStrings("posts", r.segments[2].literal);
    try std.testing.expectEqualStrings("post_id", r.segments[3].param);
}

test "route matching with params" {
    var router = Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });

    const handler = struct {
        fn h(_: *HandlerContext) response.Response {
            return response.Response.ok();
        }
    }.h;

    try router.get("/users/:id", handler);

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/users/123",
        .headers = &.{},
        .body = "",
    };
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var arena_buf: [ARENA_BUF_SIZE]u8 = undefined;
    var scratch = HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };

    const result = router.handle(req, &mw_ctx, &scratch);
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
}

test "route not found" {
    var router = Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/nonexistent",
        .headers = &.{},
        .body = "",
    };
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var arena_buf: [ARENA_BUF_SIZE]u8 = undefined;
    var scratch = HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };

    const result = router.handle(req, &mw_ctx, &scratch);
    try std.testing.expectEqual(@as(u16, 404), result.resp.status);
}

test "method mismatch" {
    var router = Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });

    const handler = struct {
        fn h(_: *HandlerContext) response.Response {
            return response.Response.ok();
        }
    }.h;

    try router.get("/users", handler);

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .POST,
        .path = "/users",
        .headers = &.{},
        .body = "",
    };
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var arena_buf: [ARENA_BUF_SIZE]u8 = undefined;
    var scratch = HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };

    const result = router.handle(req, &mw_ctx, &scratch);
    try std.testing.expectEqual(@as(u16, 405), result.resp.status);
}
