# Reverse proxy & gateway

swerver is also a reverse proxy and API gateway. The same router that dispatches your in-process [handlers](handlers.md) can instead forward a request to a pool of upstream servers — with load balancing, active health checks, response caching, traffic splitting, retries, and the full middleware chain (auth, rate limiting, compression) in front.

The proxy is configured entirely in JSON, under two top-level keys: `upstreams` (named pools of backend servers) and `routes` (path prefixes that map to an upstream, plus per-route policy). No code required.

!!! info "Build flag"
    The proxy is compiled in only with `-Denable-proxy=true`. When the flag is off, all proxy code is excluded from the binary.

    ```sh
    zig build -Doptimize=ReleaseFast -Denable-proxy=true \
        -Denable-tls=true -Denable-http2=true -Denable-http3=true
    ```

    When embedding swerver as a library, call `ServerBuilder.withProxy()` to enable the subsystem.

## Upstreams

An upstream is a named set of backend servers plus the policy for picking and pooling connections to them.

```json
{
  "upstreams": [
    {
      "name": "api",
      "servers": [
        { "address": "10.0.0.1", "port": 8080 },
        { "address": "10.0.0.2", "port": 8080, "weight": 2 },
        { "address": "10.0.0.3", "port": 8080, "backup": true }
      ],
      "load_balancer": "round_robin",
      "health_check": {
        "path": "/health",
        "interval_ms": 10000,
        "timeout_ms": 2000,
        "expected_status": 200,
        "healthy_threshold": 2,
        "unhealthy_threshold": 3
      },
      "connection_pool": {
        "max_connections": 64,
        "max_idle": 16,
        "idle_timeout_ms": 60000
      }
    }
  ]
}
```

### Servers

Each entry in `servers` is an object, not a bare `host:port` string:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | string | — | Backend host or IP (required) |
| `port` | number | — | Backend port (required) |
| `weight` | number | `1` | Relative share for weighted balancing |
| `max_fails` | number | `3` | Consecutive failures before the server is taken out of rotation |
| `fail_timeout_ms` | number | `30000` | How long a failed server stays out before re-trying |
| `backup` | bool | `false` | Only used when all primaries are unavailable |

### Load balancing

Set `load_balancer` on the upstream:

| Value | Strategy |
| --- | --- |
| `round_robin` | Rotate through servers sequentially (default) |
| `least_conn` | Pick the server with the fewest active connections |
| `ip_hash` | Consistent hashing on the client IP — sticky per client |
| `random` | Random selection |
| `weighted_round_robin` | Round-robin honoring per-server `weight` |

!!! note
    The config key is `least_conn` (not `least_connections`).

### Active health checks

When `health_check` is present, swerver probes each server on the configured `path` at `interval_ms`. A server flips to unhealthy after `unhealthy_threshold` consecutive failures and back to healthy after `healthy_threshold` successes. Passive health tracking (the per-server `max_fails` / `fail_timeout_ms` counters) runs regardless, off real request failures.

| Field | Default | Description |
| --- | --- | --- |
| `path` | `/health` | Probe path |
| `interval_ms` | `5000` | Time between probes |
| `timeout_ms` | `2000` | Probe timeout |
| `expected_status` | `200` | Status that counts as healthy |
| `expected_body` | — | Optional substring the body must contain |
| `healthy_threshold` | `2` | Successes to mark healthy |
| `unhealthy_threshold` | `3` | Failures to mark unhealthy |

### Connection pool

Each worker keeps its own pool of persistent connections to each upstream server.

| Field | Default | Description |
| --- | --- | --- |
| `max_connections` | `64` | Cap on connections per server |
| `max_idle` | `16` | Idle connections kept warm |
| `idle_timeout_ms` | `60000` | Idle connection lifetime |
| `connect_timeout_ms` | `5000` | Connect deadline |

## Routes

A route binds a path prefix to an upstream and layers on per-route policy. The longest matching `path_prefix` wins.

```json
{
  "routes": [
    {
      "path_prefix": "/api/",
      "upstream": "api",
      "rewrite_pattern": "/api/",
      "rewrite_replacement": "/",
      "retry": { "max_retries": 2 }
    }
  ]
}
```

| Field | Description |
| --- | --- |
| `path_prefix` | Match prefix (required) |
| `upstream` | Name of the target upstream (required) |
| `host` | Optional Host header match |
| `rewrite_pattern` / `rewrite_replacement` | Rewrite the matched prefix before forwarding |
| `retry` | Retry policy — see [Retries](#retries) |
| `auth` | Per-route authentication — see [Authentication](#authentication) |
| `rate_limit` | Token-bucket limiting (`requests_per_second`, `burst_size`, `key`) |
| `cache` | Per-route response cache — see [Response caching](#response-caching) |
| `traffic_split` | Weighted split across upstreams — see [Traffic splitting](#traffic-splitting) |
| `mirror` | Name of an upstream to shadow traffic to |
| `upstream_headers` | Extra `{name, value}` headers added to the forwarded request |
| `connect_timeout_ms` / `send_timeout_ms` / `read_timeout_ms` / `total_timeout_ms` | Per-route proxy timeouts |
| `max_response_bytes` | Cap on the upstream response size |
| `body_schema` | JSON Schema validated against the request body |

### Path rewriting

`rewrite_pattern` is matched against the start of the request path and replaced with `rewrite_replacement` before the request leaves for the upstream. The common case strips a gateway prefix:

```json
{ "path_prefix": "/api/v1/", "upstream": "api", "rewrite_pattern": "/api/v1/", "rewrite_replacement": "/" }
```

`GET /api/v1/users` is forwarded to the backend as `GET /users`.

### Standard proxy headers

Forwarded requests carry the usual reverse-proxy headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`, `Via: 1.1 swerver`), and hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade` except for WebSocket, `Proxy-Authenticate`, `Proxy-Authorization`) are stripped.

## Retries

Retries are configured per route via `retry.max_retries` (default `1`):

```json
{ "path_prefix": "/api/", "upstream": "api", "retry": { "max_retries": 2 } }
```

The retry policy is deliberately narrow and safe:

- **Retryable statuses:** `502`, `503`, `504`.
- **Retryable methods:** `GET`, `HEAD`, `OPTIONS` (idempotent only — a non-idempotent `POST` is never retried).

!!! tip "Why a retry can succeed"
    On a retryable 5xx, the upstream connection is released **closed** rather than returned to the pool, so the retry opens a **fresh** connection. Under a SO_REUSEPORT upstream, that fresh connection can land on a different upstream worker than the one that just returned the transient 5xx — which is the whole point of retrying. On a connection failure (reset / read error), the connection is marked failed and evicted before the next attempt.

When all attempts are exhausted, the client still gets a response: `502` if no upstream was reachable, `504` on timeout.

## Response caching

Add a `cache` block to a route for a per-route LRU response cache:

```json
{
  "path_prefix": "/catalog/",
  "upstream": "api",
  "cache": { "ttl_s": 60, "max_entries": 1000, "vary": ["Accept", "Authorization"] }
}
```

| Field | Description |
| --- | --- |
| `ttl_s` | Time-to-live for a cached response, in seconds |
| `max_entries` | LRU capacity for this route |
| `vary` | Header names that partition the cache key |

## Traffic splitting

`traffic_split` distributes requests across upstreams by weight — the mechanism for canary and blue-green rollouts. Weights are relative; below sends 10% to the canary:

```json
{
  "path_prefix": "/api/",
  "upstream": "api",
  "traffic_split": [
    { "upstream": "api", "weight": 90 },
    { "upstream": "api_canary", "weight": 10 }
  ]
}
```

`upstream` on the route remains the default target; `traffic_split` overrides selection when present.

### Mirroring

`mirror` shadows live traffic to a second upstream without affecting the client response — useful for load-testing a new version against production traffic. The mirrored response is discarded.

```json
{ "path_prefix": "/api/", "upstream": "api", "mirror": "api_shadow" }
```

## WebSocket proxying

WebSocket upgrades are tunneled transparently. The proxy detects the `Upgrade: websocket` header, forwards the handshake to the upstream, and on a `101 Switching Protocols` response switches to a bidirectional byte tunnel (no HTTP framing). The tunnel closes when either side disconnects.

## gRPC-aware proxying

gRPC runs over HTTP/2, which the proxy forwards natively. It maps gRPC status codes to HTTP status codes and preserves gRPC trailers.

## Authentication

Per-route auth is configured under `routes[].auth`. Set `type` and the fields it needs:

| Type | Description |
| --- | --- |
| `api_key` | Match against a list of named keys, looked up from a header or query param |
| `jwt` | Validate JWT tokens (HS256/HS384/HS512/RS256), check issuer/audience, forward claims as headers |
| `forward_auth` | Delegate auth to an external service; forward/return configurable headers |
| `anonymous` | Allow unauthenticated access with a fixed subject |
| `chain` | Try multiple methods in order; first success wins |

```json
{
  "path_prefix": "/api/",
  "upstream": "api",
  "auth": { "type": "jwt", "secret": "your-jwt-secret", "algorithm": "HS256", "issuer": "auth.example.com" }
}
```

`api_key` example, with keys in a custom header:

```json
{
  "type": "api_key",
  "header_name": "X-API-Key",
  "keys": [
    { "key": "demo-key-1", "name": "dev-user" },
    { "key": "demo-key-2", "name": "test-user" }
  ]
}
```

A `chain` nests other auth blocks under `methods`, trying each in order until one succeeds.

## Service discovery

Instead of a static `servers` list, an upstream can discover backends at runtime:

=== "DNS"

    ```json
    {
      "name": "api",
      "servers": [],
      "dns_discovery": { "hostname": "api.internal", "port": 8080, "interval_s": 30 }
    }
    ```

    Periodic A-record resolution; the resolved addresses populate the pool.

=== "Consul"

    ```json
    {
      "name": "api",
      "servers": [],
      "consul_discovery": { "service": "api", "address": "127.0.0.1", "port": 8500, "interval_s": 10, "token": "..." }
    }
    ```

    Polls the Consul service catalog; `token` is an optional ACL token.

## A complete gateway config

A realistic gateway: two upstreams, an API-key tier, a JWT tier with caching and rate limiting, and a canary split.

```json
{
  "server": { "address": "0.0.0.0", "port": 8080 },
  "upstreams": [
    {
      "name": "api",
      "servers": [
        { "address": "10.0.0.1", "port": 8080 },
        { "address": "10.0.0.2", "port": 8080, "weight": 2 }
      ],
      "load_balancer": "least_conn",
      "health_check": { "path": "/health", "interval_ms": 5000, "expected_status": 200 },
      "connection_pool": { "max_connections": 100, "max_idle": 20 }
    },
    {
      "name": "api_canary",
      "servers": [ { "address": "10.0.0.9", "port": 8080 } ],
      "load_balancer": "round_robin"
    }
  ],
  "routes": [
    {
      "path_prefix": "/public/",
      "upstream": "api",
      "rewrite_pattern": "/public/",
      "rewrite_replacement": "/",
      "auth": {
        "type": "api_key",
        "header_name": "X-API-Key",
        "keys": [ { "key": "demo-key-1", "name": "dev-user" } ]
      },
      "cache": { "ttl_s": 30, "max_entries": 256 }
    },
    {
      "path_prefix": "/api/",
      "upstream": "api",
      "auth": { "type": "jwt", "secret": "your-jwt-secret", "algorithm": "HS256", "issuer": "auth.example.com" },
      "rate_limit": { "requests_per_second": 100, "burst_size": 200, "key": "ip" },
      "retry": { "max_retries": 2 },
      "traffic_split": [
        { "upstream": "api", "weight": 90 },
        { "upstream": "api_canary", "weight": 10 }
      ]
    }
  ]
}
```

All fields are optional with sensible defaults — see `src/config_file.zig` for the authoritative schema, and `docs/design/5.0-reverse-proxy.md` in the repo for the full architecture.

## Where to next

- [Deployment](../operations/deployment.md) — building with the proxy flag, the fork model, running behind a load balancer.
- [Observability](../operations/observability.md) — proxy metrics, health, access logs.
- [Admin API](../operations/admin-api.md) — add/remove routes and upstreams at runtime, no restart.
