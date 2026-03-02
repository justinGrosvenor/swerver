# API Reference (#27)

This document summarizes the surface exposed by the Swerver runtime and middleware to downstream applications or operators. Everything is served over HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) with unified parsing + routing (`request.RequestView`).

## Embedded API surface

Swerver is designed to embed as a library with a public server/router API. The primary entry point is a builder that wires config, router, middleware, and optional DI.

### Server + builder

- `ServerBuilder.config(ServerConfig)` or `ServerBuilder.configDefault()`
- `ServerBuilder.router(Router)`
- `ServerBuilder.middleware(MiddlewareChain)`
- `ServerBuilder.withState(*AppState)` for app-wide state
- `ServerBuilder.withServices(*Services)` for typed dependencies
- `ServerBuilder.build(allocator)` -> `Server`
- `Server.run(run_for_ms: ?u64)`

### Router + handlers

- `Router.get/post/put/delete/patch/route` to register routes
- `Router.initWithLimits(policy, limits)` to configure route/segment/param limits
- `Router.group(prefix)` for scoped route registration
- `RouteBuilder.withMiddleware(...)` for route-scoped middleware
- `Router.fallback(handler)` for 404 and `Router.methodNotAllowed(handler)` for 405
- Handlers take `*HandlerContext` and return `response.Response`

### Request + response

- `RequestView` is zero-copy: `method`, `path`, `headers`, `body`
- `HandlerContext.json/text/html` helper methods build safe responses without heap allocation
- `HandlerContext.respond()` provides a request-scoped `ResponseBuilder` backed by the buffer pool (may fail if no buffers are available; use `releaseBuilder` if unused)
- `HandlerContext.arenaAllocator()` provides a request-scoped allocator (valid during handler execution)
- `middleware.respondManaged(ctx, status, content_type, body)` copies into a managed buffer for middleware-generated responses (returns null if no buffers available)

### Dependency injection (DI)

- `HandlerContext.state(AppState)` -> `*AppState`
- `HandlerContext.services(Services)` -> `*Services`
- Optional `HandlerContext.get(T)` for typed lookup from services
  If multiple service fields share the same type, `get(T)` resolves to the first match.

The DI story favors explicit, typed dependencies while keeping the runtime allocation-free.

## Core endpoints

| Path/result | Protocols | Description |
| --- | --- | --- |
| `/.healthz` | HTTP/1.1, HTTP/2, HTTP/3 | Liveness probe, always returns `200 OK` with `Content-Length: 0`. Served by the health middleware, cached per connection. |
| `/.ready` | HTTP/1.1, HTTP/2, HTTP/3 | Readiness probe. Returns `200 OK` when the buffer pools, listeners, TLS, and QUIC subsystems are initialized; otherwise `503`. No body. |
| `/metrics` | HTTP/1.1 (HTTP/2/3 stream also supported) | Prometheus text exposition of request/response counters, histograms, and QUIC stats. Generated with zero heap allocations and labeled per protocol. |

## Middleware hooks

- **Health**: Intercepts the probe paths before the router, so the app router never sees those requests.
- **Metrics**: Registers both a pre-routing decision (rejected responses for `/metrics`) and a post-response hook that records status, protocol, latency, and byte counts.
- **Rate limiting**: Applies token buckets keyed by client IP; premium routes (e.g., x402-protected) can request higher weights before the request reaches the router.
- **Security headers**: Injects CSP/HSTS/CORS headers after the router but before writes leave the connection. Honors route-level TLS checks.
- **Observability**: Normalizes request IDs, emits structured logs, and exposes `Request-Id` response headers.
- **x402**: When enabled, any router route tagged with `require_payment` returns `402 Payment Required` with the `PAYMENT-REQUIRED` challenge payload and optional signature.

## Router contract

Routers consume `request.RequestView` and emit `response.Response`. Responses should include only non-pseudo headers; the HTTP/2 encoder adds `:status` + `content-length` automatically. Route handlers can attach route-scoped middleware and use `HandlerContext` to access request-scoped state, services, and response builders.

Route registration returns errors on capacity issues (route/segment/param limits) rather than failing silently.

## HTTP/2 / HTTP/3 translation

- HPACK handles HEADERS/CONTINUATION frames for incoming requests.
- The runtime exposes `http2.Event` structures to the router so handlers can operate per stream.
- Response encoding happens via `http2.encodeResponseHeaders` + `http2.writeFrame(…)`; streaming bodies are split into DATA frames within `queueHttp2Response`.
