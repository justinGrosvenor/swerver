# swerver

A bare-metal **HTTP/1.1 + HTTP/2 + HTTP/3** server and application framework written in pure [Zig](https://ziglang.org). No garbage collector, no hidden allocations, no per-request heap churn — fixed-size buffer pools and stack-allocated parsing on every hot path.

```
HTTP/1.1 ──┐
HTTP/2   ──┼──► swerver ──► kqueue / epoll / io_uring ──► your handlers
HTTP/3   ──┘      │
                  └── QUIC (RFC 9000–9002)
```

!!! warning "Alpha"
    The public API in `src/lib.zig` may change between alpha versions while it's iterated on; breaking changes are noted in release notes. See [Limitations & roadmap](about/limitations.md) for what's in and out of scope today.

## Why swerver

- **Three protocols, one binary.** HTTP/1.1, HTTP/2 (HPACK), and HTTP/3 over QUIC are served by a unified router — handlers don't care which protocol a request arrived on.
- **A real framework, not just an engine.** Trie router, a zero-allocation middleware chain (auth, rate limiting, caching, compression, OpenTelemetry, body validation), a reverse proxy / API gateway, a native async PostgreSQL client, TLS termination, static file serving, and JSON config with hot reload.
- **Top-tier performance.** Holds **#1 on JSON-over-TLS** on the [HttpArena](https://www.http-arena.com/) 64-core benchmark (1.95M req/s) and runs at the front across baseline, pipelined, HTTP/2, and HTTP/3 — while carrying the full middleware chain. See [Benchmarks](about/benchmarks.md).
- **Embed it or run it.** Use the prebuilt server with a JSON config, or depend on swerver as a Zig package and wire your own routes and handlers into the binary.

## A minimal server

```zig
const std = @import("std");
const swerver = @import("swerver");

fn hello(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.text(200, "hello, galaxy");
}

fn item(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    // Return a struct — swerver serializes it with std.json.
    return ctx.jsonValue(200, .{ .id = ctx.getParam("id"), .active = true });
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var router = swerver.router.Router.init(.{});
    try router.get("/hello", hello);
    try router.get("/items/:id", item);

    const server = try swerver.ServerBuilder
        .configDefault()
        .router(router)
        .build(gpa.allocator());
    defer { server.deinit(); gpa.allocator().destroy(server); }

    try server.run(null); // listens on 0.0.0.0:8080
}
```

## Where to next

<div class="grid cards" markdown>

- :material-rocket-launch: **[Getting started](getting-started/installation.md)** — install, write your first server, run from a config file.
- :material-book-open-variant: **[Guide](guide/routing.md)** — routing, handlers & responses, middleware, configuration, protocols, proxy, PostgreSQL.
- :material-server: **[Operations](operations/deployment.md)** — deployment, observability, the admin API.
- :material-information: **[Reference](reference/cli.md)** — CLI flags, build options, the full config schema.

</div>
