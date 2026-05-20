# Deployment Guide

## Prerequisites

- Zig 0.16.0 (stable) toolchain installed and on `PATH`.
- OpenSSL 3.5+ for TLS / HTTP/2 / HTTP/3.
- Optional: TLS certificates (PEM key/cert).
- Optional: systemd unit file or container entrypoint.

## Building the binary

```sh
zig build -Doptimize=ReleaseFast \
    -Denable-tls=true \
    -Denable-http2=true \
    -Denable-http3=true
```

- `-Denable-tls=true` enables TLS 1.3 via OpenSSL/BoringSSL. Supply keys via `config.json`.
- HTTP/2 and HTTP/3 flags wire ALPN and QUIC stacks respectively.
- Optimization levels: `ReleaseFast` (max throughput), `ReleaseSmall` (binary size), `ReleaseSafe` (safety checks). Defaults to `Debug` if omitted.

## Configuration

Create `config.json`:

```json
{
  "server": {
    "address": "0.0.0.0",
    "port": 8080,
    "workers": 4,
    "max_connections": 4096,
    "static_root": "./public"
  },
  "timeouts": {
    "idle_ms": 60000,
    "header_ms": 5000,
    "body_ms": 30000,
    "write_ms": 5000
  },
  "limits": {
    "max_header_bytes": 8192,
    "max_body_bytes": 8388608,
    "max_header_count": 128
  },
  "buffer_pool": {
    "buffer_size": 65536,
    "buffer_count": 4096,
    "body_buffer_size": 1048576,
    "body_buffer_count": 32
  },
  "tls": {
    "cert_path": "cert.pem",
    "key_path": "key.pem",
    "certificates": [
      {
        "hostnames": ["api.example.com"],
        "cert_path": "api-cert.pem",
        "key_path": "api-key.pem"
      }
    ],
    "client_ca_path": "ca.pem",
    "client_cert_required": false
  },
  "http2": {
    "max_streams": 256,
    "max_header_list_size": 65536,
    "initial_window_size": 65535,
    "max_frame_size": 16384
  },
  "quic": {
    "enabled": true,
    "port": 443,
    "cert_path": "cert.pem",
    "key_path": "key.pem",
    "max_idle_timeout_ms": 30000
  },
  "admin": {
    "enabled": true,
    "port": 9090,
    "api_key": "secret-admin-key"
  },
  "otel": {
    "enabled": true,
    "collector_url": "http://localhost:4318",
    "service_name": "swerver",
    "flush_interval_s": 10,
    "sample_rate": 100,
    "max_batch_size": 512
  },
  "upstreams": [
    {
      "name": "api",
      "servers": [
        { "address": "10.0.0.1", "port": 8080 },
        { "address": "10.0.0.2", "port": 8080, "weight": 2 }
      ],
      "load_balancer": "round_robin",
      "health_check": {
        "path": "/healthz",
        "interval_ms": 10000,
        "timeout_ms": 2000,
        "healthy_threshold": 2,
        "unhealthy_threshold": 3
      },
      "connection_pool": {
        "max_connections": 64,
        "max_idle": 16,
        "idle_timeout_ms": 60000
      }
    }
  ],
  "routes": [
    {
      "path_prefix": "/api/",
      "upstream": "api",
      "auth": {
        "type": "jwt",
        "secret": "your-jwt-secret",
        "algorithm": "HS256",
        "issuer": "auth.example.com"
      },
      "rate_limit": {
        "requests_per_second": 100,
        "burst_size": 200,
        "key": "ip"
      },
      "cache": {
        "ttl_s": 60,
        "max_entries": 1000,
        "vary": ["Accept", "Authorization"]
      },
      "body_schema": { "type": "object" },
      "traffic_split": [
        { "upstream": "api", "weight": 90 },
        { "upstream": "api_canary", "weight": 10 }
      ],
      "mirror": "api_shadow"
    }
  ]
}
```

See `src/config_file.zig` for the full schema (all fields are optional with sensible defaults).

### Config hot reload

Send `SIGHUP` to reload `config.json` at runtime:

```sh
kill -HUP $(pidof swerver)
```

Value-type fields (timeouts, limits) are updated in place without dropping connections. Structural changes (routes, upstreams, TLS certificates) require a restart.

## Running

```sh
./zig-out/bin/swerver --config config.json
```

### CLI flags

| Flag | Description |
|------|-------------|
| `--config <path>` | Load JSON configuration file |
| `--workers <n>` | Number of worker processes (default: CPU count) |
| `--static-root <path>` | Serve static files from directory |
| `--run-for-ms <ms>` | Run for specified duration then exit (testing) |

### Multi-worker mode

With `--workers N` (or `server.workers` in config), swerver forks N worker processes. Each worker binds to the same port via `SO_REUSEPORT`, distributing connections across cores. The master process monitors workers and restarts any that exit unexpectedly.

## Observability

### Health probes

- `/.healthz` — liveness, always `200 OK`
- `/.ready` — readiness, `200` when subsystems are initialized, `503` otherwise

### Metrics

`GET /metrics` returns Prometheus text exposition format. Includes request/response counters, latency histograms, and protocol labels. Generated with zero heap allocations.

### Access logging

Access logs are written to stderr in combined or JSON format. Configure via the server config.

### OpenTelemetry

When `otel.enabled` is true, traces are exported to the configured OTLP collector. Configure `sample_rate` (1-10000, where 10000 = 100%), `flush_interval_s`, and `max_batch_size` to control export behavior.

### Structured logging

The observability middleware normalizes request IDs and exposes `Request-Id` response headers for distributed tracing.

## TLS

Swerver handles TLS 1.3 natively via OpenSSL/BoringSSL:

- **Single certificate**: set `tls.cert_path` and `tls.key_path`
- **SNI multi-cert**: add entries to `tls.certificates` with hostname lists
- **mTLS**: set `tls.client_ca_path` and `tls.client_cert_required: true`

For TLS termination, either let swerver handle it directly or run it behind a proxy.

## Static files

Set `server.static_root` to serve files from a directory. Files are transferred via `sendfile(2)` for zero-copy I/O. Static file paths are checked after route and proxy matching.

## Request shaping

### Rate limiting

Per-route token bucket rate limiting configured under `routes[].rate_limit`:

- `requests_per_second` — sustained rate
- `burst_size` — max burst above sustained rate
- `key` — bucket key (`ip` for per-IP limiting)

Returns `429 Too Many Requests` with `Retry-After` header when the bucket is exhausted.

### Response compression

gzip and deflate compression applied automatically based on `Accept-Encoding`. Compressible content types above a minimum size threshold are compressed transparently.

## Authentication

Per-route authentication configured under `routes[].auth`:

- **api_key**: named keys checked from a header or query parameter
- **jwt**: HS256/HS384/HS512/RS256 validation with issuer/audience checks and claim-to-header forwarding
- **forward_auth**: delegate to an external auth service
- **anonymous**: allow unauthenticated access with a fixed subject
- **chain**: try multiple methods in sequence

## Admin API

When `admin.enabled` is true, a separate HTTP listener starts on `admin.port` (protected by `admin.api_key`). Supports runtime route and upstream management without restarts.

## Docker

The recommended production Dockerfile uses `debian:trixie` (OpenSSL 3.5) for full TLS/HTTP/2/HTTP/3 support. See the [HttpArena repo](https://github.com/justinGrosvenor/HttpArena) for the Dockerfile and docker-compose setup.

### io_uring in Docker

Docker's default seccomp profile blocks io_uring syscalls. When benchmarking or running the native io_uring backend in containers, pass:

```sh
docker run --security-opt seccomp=unconfined ...
```
