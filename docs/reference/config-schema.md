# Config schema

swerver reads a single JSON config file (`--config config.json`). This page is the field-by-field reference, organized by top-level section. Every key here is parsed by `src/config_file.zig`; defaults come from the struct definitions in `src/config.zig`.

The schema is at version **`1.0`** (`SCHEMA_VERSION` in `src/config_file.zig`). The core sections (`server`, `timeouts`, `limits`, `buffer_pool`, `tls`, `quic`, `upstreams`, `routes`) are stable across the `v0.1.0-alpha.N` series. Newer sub-schemas (`x402`, `rate_limit`, access-log/metrics) may still move before 1.0.

!!! note "Everything is optional"
    Unknown keys are ignored, and every section can be omitted: an empty `{}` config starts swerver on its defaults. Set only what you need to override.

A minimal config:

```json
{
  "server": { "port": 8080, "workers": 4, "static_root": "./public" }
}
```

---

## `server`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | string | `"0.0.0.0"` | Bind address for the legacy single listener. |
| `port` | integer | `8080` | Bind port for the legacy single listener. |
| `workers` | integer | `0` | Worker processes. `0` = auto-detect CPU count (default); `1` = single-process (no fork). Overridden by `--workers`. With a `wasm_control_socket` set, only one worker becomes the Nether primary; use a `{worker}` placeholder in the socket path (a per-worker endpoint) or set `1` if parking filters / tenant routing must work on every worker. Auto-detect reads host CPUs and is NOT cgroup-quota-clamped, so pin `workers` explicitly in a constrained container. |
| `max_connections` | integer | `2048` | Max concurrent connections. Capped at 1,000,000; must be ≤ `buffer_pool.buffer_count / 2`. |
| `static_root` | string | `""` (off) | Directory for static file serving. Empty disables it. Overridden by `--static-root`. |
| `disable_middleware` | bool | `false` | Disable security headers, metrics, and access logging, for pure-benchmark mode. |
| `cache_static_files` | bool | `false` | Cache static files (and precompressed siblings) in memory per worker on first serve. |
| `preencoded` | bool | `false` | Opt-in pre-encoded fast path for canned error responses (and any registered hot endpoints). Off by default; set `true` to enable. |
| `allowed_hosts` | string[] | `[]` (all) | If non-empty, requests whose `Host` isn't in the list are rejected with 400. |
| `listeners` | object[] | `[]` | Explicit per-port listeners (see below). Absent → single-listener mode using `address`/`port`. |

### `server.listeners[]`

Each entry is one TCP port with its own protocol config. When present, the process binds every entry on every worker (`SO_REUSEPORT`) and resolves the protocol per connection from the accepted local port.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | string | `"0.0.0.0"` | Bind address for this listener. |
| `port` | integer | *required* | Bind port. |
| `use_tls` | bool | `false` | Terminate TLS on this port. |
| `h2c_only` | bool | `false` | Require the HTTP/2 prior-knowledge preface (plaintext h2c); refuse non-h2 connections rather than serving them as HTTP/1.1. |
| `quic_enabled` | bool | `false` | Advertise/serve an HTTP/3 endpoint for this listener. |
| `quic_port` | integer | `0` | UDP port for the QUIC endpoint. |

---

## `timeouts`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `idle_ms` | integer | `60000` | Idle connection timeout. Must be ≥ `header_ms` and `write_ms`. |
| `header_ms` | integer | `10000` | Max time to receive the full request head. |
| `body_ms` | integer | `30000` | Max time to receive the request body. |
| `write_ms` | integer | `30000` | Max time to flush a response. |

---

## `limits`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_header_bytes` | integer | `32768` | Max total request-header bytes. |
| `max_body_bytes` | integer | `33554432` | Max request body size (32 MiB). |
| `max_header_count` | integer | `128` | Max number of request headers. |

---

## `buffer_pool`

Fixed-size pools allocated once at startup. The hot-path pool serves request/response buffers; the body pool isolates large uploads.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer_size` | integer | `65536` | Hot-path buffer size (64 KiB). |
| `buffer_count` | integer | `4096` | Hot-path buffer count. Must be ≥ `2 × max_connections`. |
| `body_buffer_size` | integer | `1048576` | Upload-accumulation buffer size (1 MiB). |
| `body_buffer_count` | integer | `32` | Upload-accumulation buffer count. |

---

## `tls`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `cert_path` | string | `""` | PEM certificate path. Empty disables TLS on the TCP listener. Overridden by `--cert`. |
| `key_path` | string | `""` | PEM private key path. Must be set/empty together with `cert_path`. Overridden by `--key`. |
| `certificates` | object[] | `[]` | Additional SNI certificates (see below). |
| `client_ca_path` | string | `""` | mTLS: CA bundle for client-certificate verification. Empty disables mTLS. |
| `client_cert_required` | bool | `true` | mTLS: require a client certificate (vs. optional verification). |

### `tls.certificates[]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `hostnames` | string[] | *required* | SNI hostnames this certificate serves. |
| `cert_path` | string | *required* | PEM certificate path. |
| `key_path` | string | *required* | PEM private key path. |

---

## `http2`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_streams` | integer | `128` | Max concurrent streams per connection. |
| `max_header_list_size` | integer | `8192` | Max decoded header-list size in bytes. |
| `initial_window_size` | integer | `1048576` | Initial flow-control window (1 MiB; the RFC default is 65535). |
| `max_frame_size` | integer | `16384` | Max frame size. Must be in `16384..16777215` (RFC 9113 §4.2). |
| `h2c_only` | bool | `false` | Require the prior-knowledge h2c preface on the legacy plaintext listener. |

!!! note
    `max_dynamic_table_size` exists on the internal struct but is not read from the config file; it stays at its 4096-byte default.

---

## `quic`

Only the keys below are parsed from the config file. The remaining QUIC transport parameters (`initial_max_data`, stream-data windows, `ack_delay_exponent`, `max_ack_delay_ms`, `active_connection_id_limit`, `alt_svc_max_age`) use the defaults in `src/config.zig` and are not config-file-tunable.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the QUIC/HTTP/3 endpoint. Requires `cert_path` and `key_path`. |
| `port` | integer | `443` | UDP port for QUIC. |
| `cert_path` | string | `""` | PEM certificate path (required when `enabled`). |
| `key_path` | string | `""` | PEM private key path (required when `enabled`). |
| `max_idle_timeout_ms` | integer | `30000` | QUIC idle timeout. Must be non-zero when `enabled`. |
| `max_streams_bidi` | integer | `100` | Max concurrent bidirectional streams. |
| `max_streams_uni` | integer | `100` | Max concurrent unidirectional streams. |

---

## `admin`

Runtime route/upstream management API. Disabled by default.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable the admin API. Requires `api_key`. |
| `port` | integer | `9180` | Admin listener port. |
| `address` | string | `"127.0.0.1"` | Admin listener address. |
| `api_key` | string | `""` | Bearer key required for admin requests. |

---

## `otel`

OpenTelemetry trace export. Disabled by default.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable OTLP trace export. |
| `collector_url` | string | `"http://localhost:4318"` | OTLP/HTTP collector endpoint. |
| `service_name` | string | `"swerver"` | `service.name` resource attribute. |
| `flush_interval_s` | integer | `5` | Export flush interval (seconds). |
| `sample_rate` | integer | `100` | Sample percentage (0-100). |
| `max_batch_size` | integer | `256` | Max spans per export batch. |
| `headers` | string | `""` | Extra OTLP headers, `key1=value1,key2=value2` (e.g. backend auth). |

---

## `x402`

x402 payment middleware. Disabled by default. (Schema may move before 1.0.) For the payment flow, facilitator protocol, and scheme details, see the [x402 documentation](https://x402.swerver.net/docs).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable x402. Requires a `payment_required_b64` (a demo one is synthesized if omitted). |
| `facilitator_url` | string | `""` | Facilitator endpoint for verify/settle. |
| `facilitator_timeout_ms` | integer | `5000` | Facilitator request timeout. |
| `payment_required_b64` | string | `""` | Base64-encoded `402 Payment Required` payload. |

---

## `postgres`

Native async PostgreSQL client. Enabled implicitly when `url` is set. The password is **never** read from the config file, only from the environment variable named by `password_env`.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | string | (none) | `postgres://user@host:port/db?sslmode=…`. Host, port, user, database, and sslmode are parsed from it. A password in the URL is ignored with a warning. |
| `password_env` | string | `""` | Name of the env var holding the password. |
| `pool_size_per_worker` | integer | `2` | Connections per worker. Must be **1-4**. |
| `statement_timeout_ms` | integer | `5000` | Per-statement timeout. |
| `allow_cleartext_password` | bool | `false` | Allow answering a cleartext-password request over a *plaintext* connection (cleartext over TLS is always allowed). |
| `ssl_root_cert` | string | `""` | CA bundle (PEM) replacing the system trust store for `sslmode=verify-full`. |

!!! note "sslmode comes from the URL"
    `sslmode` is parsed out of `url`, not given as its own key. Accepted values: `disable`, `require`, `verify-full`. The default (no `sslmode`) is `verify-full`. Unknown values disable the client (fail-closed).

---

## `upstreams[]`

Backend pools for the reverse proxy (requires an `-Denable-proxy=true` build). Each route references an upstream by `name`.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | *required* | Upstream identifier referenced by routes. |
| `servers` | object[] | *required* | Backend servers (see below). |
| `load_balancer` | string | `"round_robin"` | One of `round_robin`, `least_conn`, `ip_hash`, `random`, `weighted_round_robin`. Unknown → `round_robin`. |
| `health_check` | object | (none) | Active health checking (see below). |
| `connection_pool` | object | (none) | Upstream connection-pool tuning (see below). |
| `dns_discovery` | object | (none) | DNS-based server discovery. |
| `consul_discovery` | object | (none) | Consul-based server discovery. |
| `allow_private` | bool | `true` | Allow private/loopback backend addresses. |

### `upstreams[].servers[]`

A server is EITHER a TCP `address`+`port` OR a UNIX-domain socket `unix` path,
not both.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | string | *required (TCP)* | Backend host/IP. Omit when `unix` is set. |
| `port` | integer | *required (TCP)* | Backend port. Omit when `unix` is set. |
| `unix` | string | (none) | UNIX-domain stream socket path (absolute, <= 103 bytes). For on-host backends: local daemons, tenant microVM data sockets. Mutually exclusive with `address`/`port`; no SSRF check applies. |
| `weight` | integer | `1` | Load-balancing weight. |
| `max_fails` | integer | `3` | Failures before marking down. |
| `fail_timeout_ms` | integer | `30000` | Down-period before retrying. |
| `backup` | bool | `false` | Only used when primaries are down. |

### `upstreams[].health_check`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `interval_ms` | integer | `5000` | Probe interval. |
| `timeout_ms` | integer | `2000` | Probe timeout. |
| `path` | string | `"/health"` | Probe request path. |
| `expected_status` | integer | `200` | Healthy status code. |
| `expected_body` | string | (none) | Optional body substring to require. |
| `healthy_threshold` | integer | `2` | Consecutive successes to mark up. |
| `unhealthy_threshold` | integer | `3` | Consecutive failures to mark down. |

### `upstreams[].connection_pool`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_connections` | integer | pool default | Max pooled connections per backend. |
| `max_idle` | integer | pool default | Max idle pooled connections. |
| `idle_timeout_ms` | integer | pool default | Idle connection eviction time. |
| `connect_timeout_ms` | integer | pool default | Connect timeout. |

### `upstreams[].dns_discovery`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `hostname` | string | *required* | Hostname to resolve into backends. |
| `port` | integer | `80` | Port for resolved addresses. |
| `interval_s` | integer | `30` | Re-resolution interval. |

### `upstreams[].consul_discovery`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `service` | string | *required* | Consul service name. |
| `address` | string | `"127.0.0.1"` | Consul agent address. |
| `port` | integer | `8500` | Consul agent port. |
| `interval_s` | integer | `15` | Refresh interval. |
| `token` | string | `""` | Consul ACL token. |

---

## `routes[]`

Proxy routes, matched by path prefix (and optional host). Every route must
reference a defined `upstream`, UNLESS it sets `tenant` (then the upstream is a
per-request microVM and `upstream` must be omitted).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `path_prefix` | string | *required* | Path prefix to match. |
| `host` | string | (none) | Optional host match. |
| `upstream` | string | *required (non-tenant)* | Target upstream `name`. Omit for a `tenant` route. |
| `tenant` | object | (none) | Tenant-as-upstream routing (see below). Mutually exclusive with `upstream`, `cache`, `traffic_split`, `mirror`. |
| `rewrite_pattern` | string | (none) | Prefix to strip/replace in the upstream path. |
| `rewrite_replacement` | string | `""` | Replacement for `rewrite_pattern`. |
| `connect_timeout_ms` | integer | `5000` | Upstream connect timeout. |
| `send_timeout_ms` | integer | `30000` | Upstream send timeout. |
| `read_timeout_ms` | integer | `60000` | Upstream read timeout. |
| `total_timeout_ms` | integer | `120000` | Total request timeout. |
| `max_response_bytes` | integer | `33554432` | Max upstream response size (32 MiB). |
| `auth` | object | `none` | Per-route auth (see below). |
| `rate_limit` | object | (none) | Per-route rate limit (see below). |
| `cache` | object | (none) | Per-route response cache (see below). |
| `traffic_split` | object[] | (none) | Weighted split across upstreams (canary/blue-green). |
| `mirror` | string | (none) | Upstream to shadow-copy requests to. |
| `body_schema` | object | (none) | JSON-Schema request-body validation. |
| `upstream_headers` | object[] | (none) | `{ name, value }` headers added to the upstream request. |
| `retry` | object | (none) | `{ max_retries }` (default `1`) on connection failure / retryable 5xx. |
| `x402` | object | (none) | Per-route x402 pricing (see below). |

### `routes[].tenant`

Routes a request to a warm tenant microVM (park-concurrency Phase 1). A request
is keyed to a VM by a header value; a warm mapping (learned on cold start) is
proxied straight to the VM's UNIX data socket, skipping the wasm filter. A miss
runs the route's wasm filter, which parks for a Tier-2 cold start whose reply
names the socket (staged via the `set_upstream` ABI). Requires a `wasm_filter`
bound to the same route and (typically) a `wasm_control_socket`. HTTP/1 cold
start only; warm hits also work for accumulated-body requests. Cold-start parks
are bounded by the 64 KiB request snapshot cap (larger requests fail closed).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `socket_dir` | string | *required* | Allowed absolute path prefix for VM sockets. A supervisor-named socket outside it is refused (the trust boundary). |
| `header` | string | `"host"` | Request header carrying the tenant key. For `host` the `:port` suffix is stripped. A tenant key is a routing key, not an auth grant. |
| `skip_filter_when_warm` | bool | `true` | On a warm hit, bypass the filter and proxy directly (the Phase 1 goal). Set `false` to run the filter every request (it must then allow without parking when warm). |

The registry is per-worker and survives config reload; idle entries are reaped
after `tenant_idle_ttl_ms`. `GET /v1/tenants` on the admin API lists the current
worker's warm mappings.

### `routes[].rate_limit`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `requests_per_second` | integer | `100` | Sustained rate. |
| `burst_size` | integer | `200` | Token-bucket burst. |
| `key` | string | `"consumer"` | `"ip"` or `"consumer"`. |

### `routes[].cache`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `ttl_s` | integer | `60` | Cache TTL (seconds). |
| `max_entries` | integer | `1024` | Max cached entries (LRU). |
| `vary` | string[] | `[]` | Headers to vary the cache key on. |

### `routes[].auth`

`type` selects the method; the other keys depend on it.

| `type` | Keys |
| --- | --- |
| `api_key` | `keys[]` (`{ key \| key_hash, name }`), `header_name` (`"X-API-Key"`), `query_param` (`"api_key"`) |
| `jwt` | `secret` (required), `issuer`, `audience`, `claims_to_headers[]` (`{ claim, header }`) |
| `forward_auth` | `url` (required), `headers_forward[]`, `headers_upstream[]`, `timeout_ms` (`5000`) |
| `anonymous` | `subject` (`"anonymous"`) |
| `chain` | `methods[]`, a list of nested auth methods (max depth 3) |

### `routes[].x402`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `price` | string | *required* | Price for the resource. |
| `asset` | string | *required* | Payment asset. |
| `network` | string | *required* | Payment network. |
| `pay_to` | string | *required* | Recipient address. |
| `scheme` | string | `"exact"` | `exact` or `upto`. |
| `max_timeout_seconds` | integer | `60` | Payment validity window. |
| `settlement_url` | string | `""` | Settlement endpoint. |
| `gateway_id` | string | `""` | Gateway identifier. |
| `extra_name` | string | `""` | EIP-712 domain name. |
| `extra_version` | string | `""` | EIP-712 domain version. |
| `facilitator_url` | string | `""` | Per-route facilitator override. |
| `extensions` | object | (none) | Free-form extension object, serialized into the payment payload. |
| `resource_url` | string | `""` | Resource URL advertised in the 402. |
| `inline_receipt` | bool | `false` | Inline the settlement receipt in the response. |

---

## `wasm_filters[]`

WASM edge filters (design 10.0) run at the edge before forwarding, to allow /
reject / modify a request, and optionally park on a Tier-2 sandbox host call.
Config-attached filters bind to **proxy routes** (matched by `path_prefix`); a
`match` that resolves to no route is logged and the filter never runs. Author
filters with the `examples/wasm_filter/abi.zig` binding (build with `-mcpu=mvp`).
Requires a build with WASM enabled.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `match` | string | *required* | Proxy route `path_prefix` to attach to. |
| `module` | string | *required* | Path to the `.wasm` module on disk. |
| `instances` | integer | `1` | Pre-instantiated instances per worker. Size to the expected CONCURRENT parked (Tier-2) requests; the next park past the pool gets backpressure. |
| `fuel` | integer | `5000000` | Per-invocation loop-back-edge budget; exhaustion fails closed. |
| `response_fail_closed` | bool | `false` | Serve a 503 if the `on_response` hook traps (default fails open, serving the original response). Set for redaction/scrub filters. |

## `wasm_control_socket`

Top-level string (default `""`). The Nether Tier-2 control-socket path. Set it to
enable the real host-call transport so parking filters drive a sandbox; empty
leaves the transport off (a parking filter then fails closed). One global socket
per server.

## `wasm_host_call_deadline_ms`

Top-level integer (default `30000`). How long a filter may stay parked on a host
call before it fails closed. Also bounds the control-socket per-command timeout.

## `tenant_idle_ttl_ms`

Top-level integer (default `600000`, 10 min). How long a warm tenant-to-microVM
mapping (see `routes[].tenant`) survives without use before housekeeping reaps
it. Only garbage-collects swerver's view; the Nether supervisor owns actual VM
reclaim (a later miss just re-parks the cold start).

### Two-tier example

```json
{
  "upstreams": [{ "name": "api", "servers": [{ "address": "127.0.0.1", "port": 9001 }] }],
  "routes": [{ "path_prefix": "/agent/", "upstream": "api" }],
  "wasm_filters": [{ "match": "/agent/", "module": "./agent_filter.wasm", "instances": 8 }],
  "wasm_control_socket": "/run/nether/agent.sock",
  "wasm_host_call_deadline_ms": 5000
}
```

A request to `/agent/*` runs `agent_filter.wasm`, which may park on a host call
over `/run/nether/agent.sock`; on allow it forwards to the `api` upstream. See
`examples/two-tier.config.json`.

---

## Hot reload

Config is hot-reloaded on `SIGHUP` (routes, upstreams, and value-typed settings such as timeouts and limits). See [Deployment](../operations/deployment.md).

## Related

- [CLI flags](cli.md): `--config`, plus the overrides that win over the file.
- [Build options](build-options.md): proxy, TLS, and HTTP/3 features must be compiled in.
