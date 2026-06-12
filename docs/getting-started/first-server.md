# Your first server

This walks through a complete, compiling embedded server: import swerver, define a couple of handlers, register routes on a `Router`, and run it. It assumes you've already [added swerver as a package](installation.md#depend-on-swerver-as-a-zig-package).

## A complete program

```zig
const std = @import("std");
const swerver = @import("swerver");

fn hello(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.text(200, "hello, galaxy");
}

fn item(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    // Return any Zig value — swerver serializes it with std.json.
    return ctx.jsonValue(200, .{
        .id = ctx.getParam("id"),
        .active = true,
    });
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // 1. Build a router and register routes.
    var router = swerver.router.Router.init(.{});
    try router.get("/hello", hello);
    try router.get("/items/:id", item);

    // 2. Hand the router to the builder and build the server.
    const server = try swerver.ServerBuilder
        .configDefault()
        .router(router)
        .build(alloc);
    defer {
        server.deinit();
        alloc.destroy(server);
    }

    // 3. Run the event loop. Pass null to run until terminated.
    try server.run(null); // listens on 0.0.0.0:8080
}
```

Build and run it, then:

```bash
curl localhost:8080/hello
# hello, galaxy

curl localhost:8080/items/42
# {"id":"42","active":true}
```

## What each piece does

**`Router.init(.{})`** creates an empty router. The argument is the x402 payment policy; `.{}` uses the defaults (no payment required), so you can ignore it until you need paid routes.

**`router.get(path, handler)`** registers a handler for `GET`. There's a method for each verb — `get`, `post`, `put`, `delete`, `patch` — plus path params like `:id`. See [Routing](../guide/routing.md) for groups, params, and 404/405 handling.

**A handler** is a plain function taking `*swerver.router.HandlerContext` and returning a `swerver.response.Response`. No allocator, no error union — build a response and return it. The two response helpers used above:

| Helper | Returns |
| --- | --- |
| `ctx.text(status, bytes)` | a `text/plain` body |
| `ctx.jsonValue(status, value)` | any Zig value, serialized as JSON with `std.json` |

`ctx.getParam("id")` reads the `:id` path parameter as `?[]const u8`. See [Handlers & responses](../guide/handlers.md) for the full context API — JSON, headers, request body, the request arena, and app state.

**`ServerBuilder.configDefault()`** starts a builder with the default `ServerConfig` (address `0.0.0.0`, port `8080`). `.router(router)` installs your routes and `.build(alloc)` validates the config and returns a heap-allocated `*Server` — so remember `server.deinit()` and `alloc.destroy(server)`.

**`server.run(null)`** enters the event loop. Pass a `u64` of milliseconds instead of `null` to run for a fixed duration and exit (useful in tests).

!!! note "Listens on 0.0.0.0:8080"
    `configDefault()` binds `0.0.0.0:8080`. To change the address, port, worker count, or limits, build a `ServerConfig` and pass it to `ServerBuilder.config(cfg)`, or run the prebuilt server from a [config file](config-file.md).

## Where to go next

- **More examples** — see `examples/embedded/` for a self-contained app and `examples/gateway/` for a full API-gateway setup (auth, rate limiting, proxy, config) in the repo.
- **[Routing](../guide/routing.md)** — path params, route groups, custom 404/405, route-scoped middleware.
- **[Handlers & responses](../guide/handlers.md)** — JSON, request bodies, the request arena, dependency injection.
