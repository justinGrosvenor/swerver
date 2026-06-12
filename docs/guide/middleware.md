# Middleware

Middleware is opt-in policy that runs around your handlers: a **pre-request** hook that returns a `Decision`, and a **post-response** hook that observes or rewrites the outgoing response. The same middleware runs on HTTP/1.1, HTTP/2, and HTTP/3; it operates on the unified `RequestView` and `Response`, not on a protocol. Like the rest of swerver, the chain is **allocation-free on the hot path**; middleware that needs to produce a body borrows a managed pool buffer (`middleware.respondManaged`) rather than allocating.

## The decision

A pre-request middleware returns a `Decision` that tells the chain what to do next:

```zig
pub const Decision = union(enum) {
    allow,                           // continue to the next middleware
    skip,                            // skip the remaining middleware
    reject: Response,                // stop and return this response
    modify: struct {                 // add headers, then continue
        response_headers: []Header,
        continue_chain: bool,
    },
    rate_limit_backpressure: u64,    // pause reads for N ms (backpressure)
};
```

You rarely write `Decision` by hand: the built-in middleware below covers the common policies, and `reject`/`rate_limit_backpressure` are how they short-circuit (a `402`, a `429`, an auth `401`).

## Wiring middleware

| Scope | How |
| --- | --- |
| **Global** | `ServerBuilder.middleware(chain)`: runs on every request. |
| **Route / group** | `RouteBuilder.withMiddleware(...)` on a route, or a `Router.group(prefix)`: localized policy. |

Several built-ins are also driven by configuration rather than wired in code: when you run the prebuilt server, **auth, rate limiting, body validation, and response caching are configured per-route in the JSON config** (`routes[].auth`, `routes[].rate_limit`, `routes[].body_schema`, `routes[].cache`). See [Reverse proxy & gateway](reverse-proxy.md) and [Configuration](configuration.md) for those route blocks.

## Built-in middleware

| Middleware | What it does |
| --- | --- |
| **Authentication** | Per-route auth: `api_key` (named keys from a header or query param), `jwt` (HS256/384/512, RS256; checks issuer/audience, forwards claims as headers), `forward_auth` (delegate to an external service), `anonymous` (fixed subject), and `chain` (try methods in order, first success wins). |
| **Rate limiting** | Token bucket (`requests_per_second`, `burst_size`), keyed per-IP or per-consumer. Returns `429 Too Many Requests` with a `Retry-After` header when the bucket is empty, and integrates with read backpressure. |
| **Security headers** | Injects HSTS, CSP, Referrer-Policy, and CORS headers before responses leave the connection, with TLS-aware behavior (e.g. HSTS only over TLS). |
| **Response compression** | gzip/deflate based on `Accept-Encoding`, applied automatically to compressible content types above a size threshold. |
| **Access logging** | Combined or JSON access logs, configured via the `access_log` block. |
| **Request body validation** | JSON Schema validation of request bodies, configured per-route via `routes[].body_schema` (`type`, `required`, `properties`, length/range constraints). Invalid bodies are rejected before the handler runs. |
| **OpenTelemetry** | Exports traces to an OTLP collector with configurable service name, sample rate, flush interval, and batch size. |
| **Prometheus metrics** | Serves `/metrics` as Prometheus text (request/response counters, latency histograms, and QUIC stats, labeled per protocol) generated with zero heap allocations. |
| **Health probes** | Intercepts `GET /.healthz` (liveness, always `200`) and `GET /.ready` (readiness, `200` when pools/listeners/TLS/QUIC are up, else `503`) before the router sees them. Bodies are empty. |
| **x402 payments** | On a route tagged with x402 config, returns `402 Payment Required` with the payment challenge until a valid payment is presented. |

## Order and short-circuiting

The chain runs in registration order, with health and metrics intercepting their probe paths before the app router ever sees them. Any middleware can short-circuit with `reject` (auth failures, rate-limit `429`, x402 `402`); later middleware and the handler don't run. Post-response hooks (security headers, access logging, metrics, OpenTelemetry) then observe or decorate whatever response was produced, including short-circuited ones.

!!! tip "Probes never hit your router"
    Because the health and metrics middleware intercept `/.healthz`, `/.ready`, and `/metrics` ahead of routing, you can't accidentally shadow them with an app route, and your router never has to handle them.

For per-route config blocks (`auth`, `rate_limit`, `body_schema`, `cache`) and the upstream/proxy gateway features, continue to [Reverse proxy & gateway](reverse-proxy.md). For the metrics and tracing surface in production, see [Observability](../operations/observability.md).
