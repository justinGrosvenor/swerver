# Embedded API

Swerver can embed as a library with a public server/router API while preserving zero-copy parsing and zero-alloc hot paths.

## Quick start

```zig
const std = @import("std");
const swerver = @import("swerver");

const AppState = struct {
    greeting: []const u8,
};

fn hello(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const state = ctx.state(AppState);
    return ctx.text(200, state.greeting);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var state = AppState{ .greeting = "hello, galaxy" };

    var router = swerver.router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    try router.get("/hello", hello);

    var server = try swerver.ServerBuilder
        .configDefault()
        .router(router)
        .withState(&state)
        .build(gpa.allocator());
    defer server.deinit();

    try server.run(null);
}
```

## Server + builder

- `ServerBuilder.config(ServerConfig)` or `ServerBuilder.configDefault()`
- `ServerBuilder.router(Router)`
- `ServerBuilder.middleware(MiddlewareChain)`
- `ServerBuilder.withState(*AppState)`
- `ServerBuilder.withServices(*Services)`
- `ServerBuilder.build(allocator)` -> `Server`
- `Server.run(run_for_ms: ?u64)`

## Router + routes

- `Router.get/post/put/delete/patch/route`
- `Router.initWithLimits(policy, limits)` to configure route/segment/param limits
- `Router.group(prefix)` for scoped route registration
- `Router.fallback(handler)` for 404 and `Router.methodNotAllowed(handler)` for 405
- `RouteBuilder.withMiddleware(...)` for route-scoped middleware
- Route registration returns errors when limits are exceeded (no silent drops)

## Requests

`RequestView` is zero-copy:

- `method`, `method_raw`
- `path`
- `headers`
- `body`

Use helpers to access headers or path params without allocations.

## Responses

Responses are explicit and zero-copy. You can return a `response.Response` directly:

```zig
fn handler(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.json(200, "{\"status\":\"ok\"}");
}
```

You can also use the request-scoped response buffer via `ctx.respond()`:

```zig
fn handler(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    var builder = ctx.respond() catch return swerver.response.Response{
        .status = 503,
        .headers = &.{},
        .body = .{ .bytes = "No buffers available" },
    };
    defer ctx.releaseBuilder(&builder);
    return builder.json(200, "{\"status\":\"ok\"}") catch swerver.response.Response{
        .status = 500,
        .headers = &.{},
        .body = .{ .bytes = "Buffer full" },
    };
}
```

Response bodies should either be:

- static slices that outlive the response, or
- slices created via `ctx.respond()` (managed buffer), or
- slices allocated from the request-scoped arena (only safe if copied before return).

## Dependency injection

### App state

```zig
const state = ctx.state(AppState);
```

### Services struct

```zig
const services = ctx.services(Services);
const db = services.db;
```

Optional typed lookup can be provided via `ctx.get(T)` for power users.
If multiple service fields share the same type, `get(T)` resolves to the first match.

## Request-scoped allocator

```zig
const allocator = ctx.arenaAllocator();
const msg = try std.fmt.allocPrint(allocator, "hello {s}", .{"world"});
return ctx.text(200, msg);
```

## Middleware

Middleware runs pre-request and post-response, is allocation-free on the hot path, and can be scoped:

- global chain via `ServerBuilder.middleware(...)`
- route-scoped via `RouteBuilder.withMiddleware(...)`

Middleware can access app state and services through `HandlerContext`.
Middleware that needs to build dynamic bodies should use `middleware.respondManaged(ctx, status, content_type, body)` so the body lives in a managed buffer; return a static fallback (e.g., `503`) if no buffers are available.

## Limits and error handling

Route registration returns errors when limits are exceeded:

- `error.RouteLimitExceeded`
- `error.SegmentLimitExceeded`
- `error.ParamLimitExceeded`

These should be treated as configuration errors during startup.

## Design constraints

- No heap allocation in hot paths unless explicitly enabled.
- Response bodies must respect lifetimes (static or arena-backed).
- Middleware should be deterministic and side-effect limited.
