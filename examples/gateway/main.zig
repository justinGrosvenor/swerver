const std = @import("std");
const swerver = @import("swerver");

const router = swerver.router;
const response = swerver.response;
const middleware = swerver.middleware;

fn dashboard(ctx: *router.HandlerContext) response.Response {
    return ctx.text(200,
        \\<!DOCTYPE html>
        \\<html><head><title>Gateway Dashboard</title></head>
        \\<body>
        \\<h1>swerver gateway</h1>
        \\<ul>
        \\  <li><a href="/health">/health</a></li>
        \\  <li><a href="/metrics">/metrics</a> &mdash; Prometheus</li>
        \\  <li>/api/v1/* &rarr; round-robin backends (auth required)</li>
        \\  <li>/api/v2/* &rarr; single backend (cached, auth required)</li>
        \\  <li>/canary/* &rarr; 90/10 traffic split</li>
        \\  <li>/static/* &rarr; static files</li>
        \\</ul>
        \\</body></html>
    );
}

fn metrics(_: *router.HandlerContext) response.Response {
    return response.Response{ .status = 500, .headers = &.{}, .body = .{ .bytes = "metrics middleware not loaded" } };
}

fn health(_: *router.HandlerContext) response.Response {
    return response.Response{ .status = 200, .headers = &.{}, .body = .none };
}

fn version(ctx: *router.HandlerContext) response.Response {
    var builder = ctx.respond() catch return response.Response{
        .status = 503,
        .headers = &.{},
        .body = .{ .bytes = "no buffers" },
    };
    defer ctx.releaseBuilder(&builder);
    return builder.json(200,
        \\{"name":"swerver-gateway","version":"0.1.0"}
    ) catch response.Response{
        .status = 500,
        .headers = &.{},
        .body = .{ .bytes = "buffer full" },
    };
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Build the router with custom handler routes.
    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    try app_router.get("/", dashboard);
    try app_router.get("/version", version);
    // Placeholder route so the bloom filter admits /metrics; the
    // metrics_mw.evaluate pre-hook intercepts before this handler runs.
    try app_router.get("/metrics", metrics);

    try app_router.get("/health", health);

    // Middleware: metrics endpoint (/metrics), security headers, access logging.
    const pre_hooks = [_]middleware.MiddlewareFn{
        middleware.metrics.evaluate,
        middleware.security.evaluate,
    };
    const post_hooks = [_]middleware.PostResponseFn{
        middleware.metrics.postResponse,
        middleware.access_log.postResponseCombined,
    };
    var chain = app_router.middleware_chain;
    chain.pre = &pre_hooks;
    chain.post = &post_hooks;
    app_router.setMiddleware(chain);

    // The bootstrap owns the rest: it loads config.json, builds the reverse
    // proxy from its upstreams/routes (heap-allocated, so the server can
    // reload/destroy it safely), and serves until shutdown.
    try swerver.bootstrap.run(allocator, .{
        .config_path = "examples/gateway/config.json",
        .router = app_router,
    });
}
