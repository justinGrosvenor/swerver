# Configuration

swerver is configured one of two ways, and they describe the same thing:

- **A JSON config file**, loaded with `--config config.json`. This is how you run the prebuilt server.
- **The embedded `ServerConfig` Zig struct**, passed to `ServerBuilder.config(...)` when you depend on swerver as a library.

The JSON parser fills in a `ServerConfig` (see `src/config.zig`) and then validates it, so both paths share the same field set, the same defaults, and the same validation rules. This page walks the main sections with a realistic file. For the complete field-by-field reference, see [Config schema](../reference/config-schema.md).

!!! info "Schema version"
    The config file schema is at `SCHEMA_VERSION = "1.0"`. The core sections — `server`, `timeouts`, `limits`, `buffer_pool`, `tls`, `http2`, `quic`, `upstreams`, `routes` — are stable across the `v0.1.0-alpha.N` series. Newer sub-schemas (`access_log`, `metrics`, `rate_limit`, `x402`) may move before 1.0; a config that sets only the core fields survives alpha version bumps. Unknown keys are ignored, so a config can carry settings a given build doesn't understand.

## A realistic config

```json
{
  "server": {
    "address": "0.0.0.0",
    "port": 8080,
    "workers": 0,
    "max_connections": 4096,
    "static_root": "./public",
    "cache_static_files": true,
    "preencoded": true
  },
  "timeouts": {
    "idle_ms": 60000,
    "header_ms": 10000,
    "body_ms": 30000,
    "write_ms": 30000
  },
  "limits": {
    "max_header_bytes": 32768,
    "max_body_bytes": 8388608
  },
  "buffer_pool": {
    "buffer_size": 65536,
    "buffer_count": 8192
  },
  "tls": {
    "cert_path": "/etc/swerver/cert.pem",
    "key_path": "/etc/swerver/key.pem"
  },
  "http2": {
    "max_streams": 128,
    "initial_window_size": 1048576
  },
  "quic": {
    "enabled": true,
    "port": 8443,
    "cert_path": "/etc/swerver/cert.pem",
    "key_path": "/etc/swerver/key.pem"
  }
}
```

Run it:

```bash
swerver --config config.json
```

## `server`

The listener and the global resource budget.

| Key | Default | Description |
| --- | --- | --- |
| `address` | `"0.0.0.0"` | Bind address for the single listener. |
| `port` | `8080` | Bind port for the single listener. |
| `workers` | `1` | Worker processes. **`0` = one per CPU** (fork + `SO_REUSEPORT`). `1` = single process, no fork. |
| `max_connections` | `2048` | Hard cap on concurrent connections. Capped at 1,000,000. |
| `static_root` | `""` | Directory served for paths not matched by a route or proxy rule. Empty disables static serving. See [Static files](static-files.md). |
| `cache_static_files` | `false` | Cache static bodies (and precompressed siblings) in memory per worker, skipping per-request file syscalls. |
| `preencoded` | `true` | Keep the pre-encoded response cache (canned error responses, benchmark fast-paths). Set `false` to route every path through the normal pipeline. |
| `allowed_hosts` | `[]` | Accepted `Host` values. Empty accepts all; otherwise a non-matching `Host` is rejected with `400`. |
| `listeners` | `[]` | Explicit per-port listeners (multi-listener mode). When empty, the single `address`/`port` above is bound. See [TLS, HTTP/2 & HTTP/3](protocols.md). |

!!! note "`workers` and CPU count"
    `workers: 0` forks one worker per detected CPU, each with its own event loop and buffer pools, all sharing the listening socket via `SO_REUSEPORT`. This is the usual production setting. Use `1` for development or when you want a single process to attach a debugger to.

## `timeouts`

All values are milliseconds; all must be non-zero. `header_ms` and `write_ms` must each be `<= idle_ms`.

| Key | Default | Description |
| --- | --- | --- |
| `idle_ms` | `60000` | Idle keep-alive timeout between requests. |
| `header_ms` | `10000` | Deadline to receive a complete request head. |
| `body_ms` | `30000` | Deadline to receive a request body. |
| `write_ms` | `30000` | Deadline to flush a response. |

## `limits`

| Key | Default | Description |
| --- | --- | --- |
| `max_header_bytes` | `32768` | Maximum total request header size. |
| `max_body_bytes` | `33554432` | Maximum request body size (32 MiB). |
| `max_header_count` | `128` | Maximum number of request header fields. Must be non-zero. |

## `buffer_pool`

Fixed-size buffers are allocated once at startup; nothing is allocated per request.

| Key | Default | Description |
| --- | --- | --- |
| `buffer_size` | `65536` | Bytes per hot-path buffer (64 KiB). |
| `buffer_count` | `4096` | Number of hot-path buffers. Must be `>= max_connections * 2` (one read + one write per connection). |
| `body_buffer_size` | `1048576` | Bytes per large-upload buffer (1 MiB). |
| `body_buffer_count` | `32` | Number of large-upload buffers, kept separate so uploads can't exhaust the hot-path pool. |

## `tls`, `http2`, `quic`, `postgres`

These sections enable and tune the protocol and database subsystems:

- **`tls`** — certificate paths, SNI multi-cert, and mTLS. See [TLS, HTTP/2 & HTTP/3](protocols.md).
- **`http2`** — stream limits, flow-control window, and the `h2c_only` cleartext switch. See [TLS, HTTP/2 & HTTP/3](protocols.md).
- **`quic`** — HTTP/3 over QUIC: `enabled`, `port`, cert/key, idle timeout, stream limits. See [TLS, HTTP/2 & HTTP/3](protocols.md).
- **`postgres`** — the native async PostgreSQL client (disabled by default; the password is read from `password_env`, never the file). See [PostgreSQL](postgres.md).

Proxy `upstreams` and `routes` (load balancing, health checks, per-route auth / rate limiting / caching / body validation) are covered in [Reverse proxy & gateway](reverse-proxy.md).

## Embedded `ServerConfig`

When embedding swerver, build a `ServerConfig` directly — every JSON section above maps to a struct field of the same name. Start from `ServerConfig.default()` or `ServerBuilder.configDefault()` and override what you need:

```zig
const cfg = swerver.ServerConfig{
    .address = "0.0.0.0",
    .port = 8080,
    .max_connections = 4096,
    .workers = 0, // one worker per CPU
    .timeouts = .{ .idle_ms = 60_000, .header_ms = 10_000, .body_ms = 30_000, .write_ms = 30_000 },
    .limits = .{ .max_header_bytes = 32 * 1024, .max_body_bytes = 8 * 1024 * 1024 },
    .buffer_pool = .{ .buffer_size = 64 * 1024, .buffer_count = 8192 },
    .static_root = "./public",
    .cache_static_files = true,
    .quic = .{
        .enabled = true,
        .port = 8443,
        .cert_path = "cert.pem",
        .key_path = "key.pem",
    },
    // …remaining sections use their defaults
};

const server = try swerver.ServerBuilder
    .config(cfg)
    .router(router)
    .build(allocator);
```

`ServerConfig.validate()` runs the same checks the JSON loader does, so an invalid struct fails fast at `build` time with a descriptive error (e.g. `error.InvalidBufferPool`, `error.InvalidTimeouts`).

## Hot reload on `SIGHUP`

Send `SIGHUP` to the server process to reload `config.json` without dropping connections:

```bash
kill -HUP "$(pgrep -o swerver)"
```

| Change | Effect |
| --- | --- |
| **Value-type fields** — `timeouts`, `limits` | Reloaded in place; existing connections keep running. |
| **Structural changes** — `routes`, `upstreams`, TLS certificates | Require a restart to take effect. |

For runtime route/upstream changes without a restart, use the [Admin API](../operations/admin-api.md).
