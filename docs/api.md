# API Reference

This document summarizes the surface exposed by the Swerver runtime and middleware to downstream applications or operators. Everything is served over HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) with unified parsing + routing (`request.RequestView`).

## Embedded API surface

Swerver is designed to embed as a library with a public server/router API. The primary entry point is a builder that wires config, router, middleware, and optional DI.

### Server + builder

- `ServerBuilder.config(ServerConfig)` or `ServerBuilder.configDefault()`
- `ServerBuilder.router(Router)`
- `ServerBuilder.middleware(MiddlewareChain)`
- `ServerBuilder.withState(*AppState)` for app-wide state
- `ServerBuilder.withServices(*Services)` for typed dependencies
- `ServerBuilder.withProxy()` to enable the reverse proxy subsystem
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
| `/metrics` | HTTP/1.1, HTTP/2, HTTP/3 | Prometheus text exposition of request/response counters, histograms, and QUIC stats. Generated with zero heap allocations and labeled per protocol. |

## Reverse proxy

Swerver includes a reverse proxy with load balancing, health checks, and connection pooling. Proxy routes are defined in the JSON config file under `upstreams` and `routes`.

### Load balancing

- `round_robin` (default), `least_connections`, `random`, `ip_hash`
- Per-server weights, backup servers, and max-fails with fail timeout
- Active health checks with configurable path, interval, thresholds, and expected status/body

### Service discovery

Upstreams can discover backends dynamically:

- **DNS**: periodic A-record resolution with configurable interval
- **Consul**: service catalog polling with optional ACL token

### Response caching

Per-route LRU response cache with configurable TTL, max entries, and `Vary` header support.

### Traffic management

- **Traffic splitting**: weighted distribution across upstreams (canary/blue-green deployments)
- **Traffic mirroring**: shadow traffic to a secondary upstream for testing

### WebSocket proxy

WebSocket connections are tunneled through the proxy with bidirectional relay. The proxy detects the `Upgrade: websocket` header and switches to tunnel mode.

### gRPC-aware proxy

The proxy maps gRPC status codes to HTTP status codes and handles gRPC trailers.

## Admin API

When enabled (`admin.enabled: true` in config), an admin API listens on a separate port for runtime management. Protected by an API key.

- `GET /routes` — list current routes
- `POST /routes` — add a route
- `DELETE /routes/{prefix}` — remove a route
- `GET /upstreams` — list upstreams
- `POST /upstreams` — add an upstream
- `PUT /upstreams/{name}` — update an upstream
- `DELETE /upstreams/{name}` — remove an upstream

## Authentication

Per-route authentication configured in the JSON config under `routes[].auth`. Supported types:

| Type | Description |
| --- | --- |
| `api_key` | Match against a list of named keys, looked up from a header or query param |
| `jwt` | Validate JWT tokens (HS256/HS384/HS512/RS256), check issuer/audience, forward claims as headers |
| `forward_auth` | Delegate auth to an external service; forward/return configurable headers |
| `anonymous` | Allow unauthenticated access with a fixed subject |
| `chain` | Try multiple auth methods in order; first success wins |

## Middleware hooks

- **Health**: Intercepts the probe paths before the router, so the app router never sees those requests.
- **Metrics**: Registers both a pre-routing decision (rejected responses for `/metrics`) and a post-response hook that records status, protocol, latency, and byte counts.
- **Rate limiting**: Per-route token bucket (`requests_per_second`, `burst_size`) keyed by client IP or a configurable key. When a bucket is empty, the middleware returns `429` with a `Retry-After` header.
- **Security headers**: Injects CSP/HSTS/CORS headers after the router but before writes leave the connection. Honors route-level TLS checks.
- **Access logging**: Combined or JSON format access logs. Configurable via `access_log` in the server config.
- **Response compression**: gzip and deflate compression based on `Accept-Encoding`. Applied automatically to compressible content types above a minimum size threshold.
- **Request body validation**: JSON Schema validation on request bodies, configured per-route via `body_schema`.
- **Observability**: Normalizes request IDs, emits structured logs, and exposes `Request-Id` response headers.
- **OpenTelemetry**: Trace export to an OTLP collector with configurable service name, sample rate, flush interval, and batch size.
- **x402**: When enabled, any router route tagged with `x402` config returns `402 Payment Required` with the payment challenge payload.

## TLS

- TLS 1.3 via OpenSSL/BoringSSL
- SNI-based multi-certificate support: configure multiple `{hostnames, cert_path, key_path}` entries under `tls.certificates`
- mTLS: set `tls.client_ca_path` and `tls.client_cert_required` to require and verify client certificates

## Router contract

Routers consume `request.RequestView` and emit `response.Response`. Responses should include only non-pseudo headers; the HTTP/2 encoder adds `:status` + `content-length` automatically. Route handlers can attach route-scoped middleware and use `HandlerContext` to access request-scoped state, services, and response builders.

Route registration returns errors on capacity issues (route/segment/param limits) rather than failing silently.

## HTTP/2 / HTTP/3 translation

- HPACK handles HEADERS/CONTINUATION frames for incoming requests.
- The runtime exposes `http2.Event` structures to the router so handlers can operate per stream.
- Response encoding happens via `http2.encodeResponseHeaders` + `http2.writeFrame(…)`; streaming bodies are split into DATA frames within `queueHttp2Response`.
- HTTP/2 flow control uses separate send and receive windows per RFC 9113. Connection and stream windows are tracked independently.

## Configuration hot reload

Sending `SIGHUP` to the server process reloads `config.json`. Value-type fields (timeouts, limits) are updated in place without restarting connections. Structural changes (routes, upstreams, TLS certificates) require a restart.

## Static file serving

When `server.static_root` is set, the server serves static files from the specified directory using `sendfile(2)` for zero-copy file transfer. Files are served for any path not matched by a registered route or proxy rule.
