# Routing

The router maps an incoming method + path to one handler. It's a fixed-size trie-style table compiled once at startup: registration parses each pattern, and the hot path just walks segments — no allocation, no regex. A 64-bit bloom filter over first path segments fast-rejects most 404s before the route loop even runs.

Build the router at startup, register every route, then hand it to the [`ServerBuilder`](../getting-started/first-server.md). Routes can't be added after `server.run()` starts.

## Creating a router

```zig
var router = swerver.router.Router.init(.{});
```

The argument is the x402 payment policy; `.{}` takes the defaults (no payment required). To raise the compiled-in route/segment/param limits, use `Router.initWithLimits(policy, limits)`.

## Registering routes

There's a method per HTTP verb. Each takes a path pattern and a [`HandlerFn`](handlers.md), and returns an error if a limit is exceeded:

```zig
try router.get("/users", listUsers);
try router.post("/users", createUser);
try router.get("/users/:id", showUser);
try router.put("/users/:id", replaceUser);
try router.patch("/users/:id", updateUser);
try router.delete("/users/:id", deleteUser);
```

| Method | Verb |
| --- | --- |
| `router.get(path, handler)` | `GET` |
| `router.post(path, handler)` | `POST` |
| `router.put(path, handler)` | `PUT` |
| `router.delete(path, handler)` | `DELETE` |
| `router.patch(path, handler)` | `PATCH` |
| `router.route(method, path, handler)` | any `request.Method` |

!!! note "HEAD is automatic"
    A `GET` route also answers `HEAD` for the same path (RFC 9110 §9.3.2) — you don't register it separately.

## Path parameters

A segment beginning with `:` is a named parameter that matches any single non-empty segment. Read it in the handler with `ctx.getParam(name)`, which returns `?[]const u8`:

```zig
fn showUser(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const id = ctx.getParam("id") orelse return ctx.text(400, "missing id");
    return ctx.jsonValue(200, .{ .id = id });
}

try router.get("/users/:id", showUser);
try router.get("/users/:id/posts/:post_id", showPost);
```

`/users/42` matches the first route with `id = "42"`. `/users/42/posts/7` matches the second with `id = "42"` and `post_id = "7"`. The returned slice is a zero-copy view into the request path — valid for the duration of the handler call.

A trailing `*` wildcard segment matches the rest of the path.

## Route groups

`router.group(prefix)` returns a scoped builder that prepends `prefix` to every route registered through it. The handler still sees the full path, so params work as normal:

```zig
var api = router.group("/api/v1");
try api.get("/users", listUsers);          // → /api/v1/users
try api.post("/users", createUser);         // → /api/v1/users
try api.get("/users/:id", showUser);        // → /api/v1/users/:id
```

`group` returns the builder **by value**, so bind it with `var`. It exposes the same `get` / `post` / `put` / `delete` / `patch` methods as the router. You can chain `.withMiddleware(&chain)` on the group to apply one middleware chain to every route it registers.

## Custom 404 and 405

By default the router returns a plain `404 Not Found`, or `405 Method Not Allowed` (with an `Allow` header) when the path matches but the method doesn't. Override either with your own handler:

```zig
router.fallback(notFound);          // 404 — no route matched the path
router.methodNotAllowed(notAllowed); // 405 — path matched, method didn't
```

```zig
fn notFound(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.jsonValue(404, .{ .@"error" = "not found", .path = ctx.request.path });
}
```

Both take an ordinary `HandlerFn`. The router always produces a valid `Response`, so these are purely for customizing the body.

## Route-scoped middleware

Most apps set one middleware chain on the router (`Router.setMiddleware`) and let every route share it. When a single route needs a different chain — stricter auth on an admin endpoint, or skipping rate limiting on a health check — use the fluent route builder:

```zig
var admin_chain = buildAdminChain();

try router
    .routeBuilder(.GET, "/admin/stats", adminStats)
    .withMiddleware(&admin_chain)
    .register();
```

`routeBuilder(method, pattern, handler)` returns a `RouteBuilder`; `.withMiddleware(&chain)` attaches the per-route chain and `.register()` finalizes it (returning the same limit errors as the plain methods). The route's chain runs in addition to the router's global chain. See [Middleware](middleware.md) for building chains.

## Registration errors

Registration is fail-fast: the route table is fixed-size, so exceeding a limit returns an error rather than silently dropping the route. Treat these as **startup configuration errors** — the `try` in your setup code will surface them before the event loop starts.

| Error | Cause |
| --- | --- |
| `error.RouteLimitExceeded` | More routes than the router's `max_routes`. |
| `error.SegmentLimitExceeded` | A pattern has more path segments than `max_segments`. |
| `error.ParamLimitExceeded` | A pattern has more `:params` than `max_params`. |
| `error.PatternTooLong` | The pattern (with any group prefix) exceeds the compiled pattern-length cap. |

If you legitimately need more, raise the ceilings with `Router.initWithLimits(policy, .{ .max_routes = …, .max_segments = …, .max_params = … })`.

## Next

- **[Handlers & responses](handlers.md)** — the `HandlerContext` API, JSON, request bodies, app state.
- **[Middleware](middleware.md)** — auth, rate limiting, caching, and the chain model.
