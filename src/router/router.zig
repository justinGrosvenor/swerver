const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const x402 = @import("../middleware/x402.zig");
const middleware = @import("../middleware/middleware.zig");

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
    /// Path parameters extracted from route (e.g., /users/:id)
    params: [8]Param = undefined,
    param_count: u8 = 0,
    /// Response buffer for building dynamic responses
    response_buf: [RESPONSE_BUF_SIZE]u8 = undefined,

    const RESPONSE_BUF_SIZE = 8192;

    pub const Param = struct {
        name: []const u8,
        value: []const u8,
    };

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
            .body = body,
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
            .body = body,
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
            .body = body,
        };
    }
};

/// Route entry
pub const Route = struct {
    method: request.Method,
    pattern: []const u8,
    handler: HandlerFn,
    /// Pre-parsed pattern segments for matching
    segments: [16]Segment = undefined,
    segment_count: u8 = 0,

    const Segment = union(enum) {
        literal: []const u8,
        param: []const u8, // parameter name without ':'
        wildcard, // matches rest of path (*)
    };

    fn compile(pattern: []const u8) Route {
        var route = Route{
            .method = .GET,
            .pattern = pattern,
            .handler = undefined,
        };

        var it = std.mem.splitScalar(u8, pattern, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            if (route.segment_count >= 16) break;

            if (seg[0] == ':') {
                route.segments[route.segment_count] = .{ .param = seg[1..] };
            } else if (seg[0] == '*') {
                route.segments[route.segment_count] = .wildcard;
            } else {
                route.segments[route.segment_count] = .{ .literal = seg };
            }
            route.segment_count += 1;
        }

        return route;
    }
};

/// Maximum number of routes
const MAX_ROUTES = 128;

/// Router with route registration and matching
pub const Router = struct {
    routes: [MAX_ROUTES]Route = undefined,
    route_count: usize = 0,
    x402_policy: x402.Policy,
    middleware_chain: middleware.Chain,
    /// Default 404 handler
    not_found_handler: ?HandlerFn = null,
    /// Default 500 handler
    error_handler: ?HandlerFn = null,

    pub fn init(policy: x402.Policy) Router {
        return .{
            .x402_policy = policy,
            .middleware_chain = middleware.Chain.init(&.{}, &.{}),
        };
    }

    /// Set middleware chain
    pub fn setMiddleware(self: *Router, chain: middleware.Chain) void {
        self.middleware_chain = chain;
    }

    /// Register a GET route
    pub fn get(self: *Router, pattern: []const u8, handler: HandlerFn) void {
        self.route(.GET, pattern, handler);
    }

    /// Register a POST route
    pub fn post(self: *Router, pattern: []const u8, handler: HandlerFn) void {
        self.route(.POST, pattern, handler);
    }

    /// Register a PUT route
    pub fn put(self: *Router, pattern: []const u8, handler: HandlerFn) void {
        self.route(.PUT, pattern, handler);
    }

    /// Register a DELETE route
    pub fn delete(self: *Router, pattern: []const u8, handler: HandlerFn) void {
        self.route(.DELETE, pattern, handler);
    }

    /// Register a PATCH route
    pub fn patch(self: *Router, pattern: []const u8, handler: HandlerFn) void {
        self.route(.PATCH, pattern, handler);
    }

    /// Register a route with any method
    pub fn route(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn) void {
        if (self.route_count >= MAX_ROUTES) return;

        var r = Route.compile(pattern);
        r.method = method;
        r.handler = handler;
        self.routes[self.route_count] = r;
        self.route_count += 1;
    }

    /// Set custom 404 handler
    pub fn setNotFound(self: *Router, handler: HandlerFn) void {
        self.not_found_handler = handler;
    }

    /// Set custom error handler
    pub fn setErrorHandler(self: *Router, handler: HandlerFn) void {
        self.error_handler = handler;
    }

    /// Handle an incoming request
    /// Returns RouteResult with response and optional backpressure signal
    pub fn handle(self: *Router, req: request.RequestView, mw_ctx: *middleware.Context) RouteResult {
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
        };

        for (self.routes[0..self.route_count]) |r| {
            if (r.method != req.method) continue;

            if (self.matchRoute(&r, req.path, &ctx)) {
                mw_ctx.route = r.pattern;
                return .{ .resp = r.handler(&ctx) };
            }
        }

        // No route matched - 404
        if (self.not_found_handler) |handler| {
            return .{ .resp = handler(&ctx) };
        }

        return .{ .resp = notFound() };
    }

    fn matchRoute(self: *Router, r: *const Route, path: []const u8, ctx: *HandlerContext) bool {
        _ = self;
        ctx.param_count = 0;

        var path_it = std.mem.splitScalar(u8, path, '/');
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
                    if (ctx.param_count < 8) {
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
};

/// Default 404 response
fn notFound() response.Response {
    return .{
        .status = 404,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = "Not Found",
    };
}

/// Default 500 response
pub fn internalError() response.Response {
    return .{
        .status = 500,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = "Internal Server Error",
    };
}

// Tests
test "route compilation" {
    const r = Route.compile("/users/:id/posts/:post_id");
    try std.testing.expectEqual(@as(u8, 4), r.segment_count);
    try std.testing.expectEqualStrings("users", r.segments[0].literal);
    try std.testing.expectEqualStrings("id", r.segments[1].param);
    try std.testing.expectEqualStrings("posts", r.segments[2].literal);
    try std.testing.expectEqualStrings("post_id", r.segments[3].param);
}

test "route matching with params" {
    var router = Router.init(.{ .require_payment = false });

    const handler = struct {
        fn h(_: *HandlerContext) response.Response {
            return response.Response.ok();
        }
    }.h;

    router.get("/users/:id", handler);

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/users/123",
        .headers = &.{},
        .body = "",
    };

    const result = router.handle(req, &mw_ctx);
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
}

test "route not found" {
    var router = Router.init(.{ .require_payment = false });

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/nonexistent",
        .headers = &.{},
        .body = "",
    };

    const result = router.handle(req, &mw_ctx);
    try std.testing.expectEqual(@as(u16, 404), result.resp.status);
}

test "method mismatch" {
    var router = Router.init(.{ .require_payment = false });

    const handler = struct {
        fn h(_: *HandlerContext) response.Response {
            return response.Response.ok();
        }
    }.h;

    router.get("/users", handler);

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .POST,
        .path = "/users",
        .headers = &.{},
        .body = "",
    };

    const result = router.handle(req, &mw_ctx);
    try std.testing.expectEqual(@as(u16, 404), result.resp.status);
}
