# Handlers & responses

A handler is a plain function that takes a `*HandlerContext` and returns a `response.Response`:

```zig
const HandlerFn = *const fn (ctx: *swerver.router.HandlerContext) swerver.response.Response;
```

Handlers are **synchronous** — they run to completion between `recv()` calls on the connection. That's what lets `ctx.request.headers` and `ctx.request.body` be `[]const u8` slices straight into the receive buffer, with no copy. There is no allocator parameter and no error union: build a `Response` and return it.

## The request

`ctx.request` is a zero-copy `RequestView`:

| Field / method | Description |
| --- | --- |
| `ctx.request.method` | `.GET`, `.POST`, `.PUT`, `.DELETE`, `.PATCH`, … |
| `ctx.request.path` | Request target, including the query string |
| `ctx.request.headers` | Slice of `{ name, value }` views into the receive buffer |
| `ctx.request.getHeader("accept-encoding")` | Case-insensitive header lookup → `?[]const u8` |
| `ctx.request.body` | Request body (see [Reading the body](#reading-the-body)) |
| `ctx.getParam("id")` | Path parameter from the route pattern (`/items/:id`) → `?[]const u8` |

```zig
fn show(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const id = ctx.getParam("id") orelse return ctx.text(400, "missing id");
    return ctx.text(200, id);
}
```

## Returning responses

`HandlerContext` provides helpers that build a `Response` with the right `Content-Type` and no heap allocation:

| Helper | Body | Content-Type |
| --- | --- | --- |
| `ctx.text(status, bytes)` | `[]const u8` | `text/plain` |
| `ctx.html(status, bytes)` | `[]const u8` | `text/html; charset=utf-8` |
| `ctx.json(status, bytes)` | a body you already encoded | `application/json` |
| `ctx.jsonValue(status, value)` | **any Zig value**, encoded with `std.json` | `application/json` |

### Returning JSON the idiomatic way

`ctx.jsonValue` serializes any value — a struct, a slice, a map — with the standard library's JSON encoder. Define a type for your payload and return it; you never format JSON by hand:

```zig
const Item = struct {
    id: u32,
    name: []const u8,
    tags: []const []const u8,
    price: f64,
    in_stock: bool,
};

fn item(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const it = Item{
        .id = 7,
        .name = "Prime Gear",
        .tags = &.{ "popular", "new" },
        .price = 49.95,
        .in_stock = true,
    };
    return ctx.jsonValue(200, it);
    // → {"id":7,"name":"Prime Gear","tags":["popular","new"],"price":49.95,"in_stock":true}
}
```

The encoded bytes are written into the request arena, or into a managed pool buffer when no arena is available (HTTP/2 GETs), so `jsonValue` works on every protocol path. It returns `500` if the value is too large to encode. Use `ctx.json(status, bytes)` instead when you already have a serialized body (e.g. a cached blob, or output you produced with your own encoder).

### Returning a `Response` directly

The helpers are sugar over a plain struct, which you can also build yourself:

```zig
fn ok(_: *swerver.router.HandlerContext) swerver.response.Response {
    return .{
        .status = 200,
        .headers = &[_]swerver.response.Header{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "Cache-Control", .value = "no-store" },
        },
        .body = .{ .bytes = "{\"ok\":true}" },
    };
}
```

Return only ordinary headers — the HTTP/2 and HTTP/3 encoders add `:status` and `content-length` for you.

## Response body lifetimes

A response body is a `[]const u8` that **must outlive the handler return**. The body is copied into the connection's write queue synchronously, before the next request on that worker runs, so anything valid at return time is safe. Three sources are valid:

1. **Static slices** — string literals and `const` data.
2. **The managed pool buffer** — `ctx.respond()` (below) or `ctx.jsonValue`, which the framework releases for you after the response is serialized.
3. **The request arena** — `ctx.arenaAllocator()`, valid for the life of the handler.

Don't return a slice into a stack buffer that goes out of scope, and don't stash request slices in module-level state across requests.

### Larger bodies: `ctx.respond()`

`ctx.response_buf` is a small (8 KB) scratch buffer. For a bigger dynamic body, acquire a managed buffer from the pool with `ctx.respond()`:

```zig
fn report(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    var rb = ctx.respond() catch return ctx.text(503, "no buffers available");
    // build into rb.handle.bytes, or:
    return rb.json(200, big_json_slice) catch ctx.text(500, "response buffer full");
}
```

The pool handle is released automatically once the response has been written. (`ctx.jsonValue` uses this path internally for responses that don't fit the arena, so most handlers never touch `respond()` directly.)

### The request arena

`ctx.arenaAllocator()` is a request-scoped allocator backed by a pooled buffer. Use it for one-request-lifetime structured data:

```zig
fn greet(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const msg = std.fmt.allocPrint(ctx.arenaAllocator(), "hello {s}", .{
        ctx.getParam("name") orelse "world",
    }) catch return ctx.text(500, "oom");
    return ctx.text(200, msg);
}
```

## Reading the body

`ctx.request.body` is a `BodyView`. For small bodies you can borrow a contiguous slice; for large or fragmented bodies, copy into a buffer:

```zig
fn echo(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    if (ctx.request.body.sliceOrNull()) |bytes| {
        return ctx.json(200, bytes);
    }
    // Fragmented — copy into the scratch buffer.
    const copied = ctx.request.body.copyTo(ctx.response_buf) orelse
        return ctx.text(413, "body too large");
    return ctx.json(200, copied);
}
```

## App state & dependencies

Handlers reach shared, app-wide state through the context — no globals:

```zig
const Services = struct { db: *Database, cache: *Cache };

fn list(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const svc = ctx.services(Services);
    const rows = svc.db.query(...);
    return ctx.jsonValue(200, rows);
}
```

Install state once on the `Router` / `ServerBuilder` before the event loop starts. See [Dependency injection](#) — `ctx.state(T)` for a single app-state value, `ctx.services(T)` for a struct of typed dependencies, and `ctx.get(T)` for a typed lookup. For database access specifically, see [PostgreSQL](postgres.md).
