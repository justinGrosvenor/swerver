# Deployment

This page covers running swerver in production: building a release binary, the multi-worker fork model, containers, running behind a load balancer, graceful shutdown, and orchestrator health probes.

## Prerequisites

- Zig 0.16.0 (stable) toolchain on `PATH`.
- OpenSSL 3.5+ for TLS / HTTP/2 / HTTP/3.
- TLS certificates (PEM key/cert) if you terminate TLS in swerver.

## Building a release binary

Build `ReleaseFast` with the protocol features you need wired in:

```sh
zig build -Doptimize=ReleaseFast \
    -Denable-tls=true \
    -Denable-http2=true \
    -Denable-http3=true \
    -Denable-proxy=true
```

| Flag | Effect |
| --- | --- |
| `-Denable-tls=true` | TLS 1.3 via OpenSSL/BoringSSL |
| `-Denable-http2=true` | HTTP/2 (ALPN negotiation, HPACK) |
| `-Denable-http3=true` | HTTP/3 over QUIC |
| `-Denable-proxy=true` | Reverse proxy / gateway subsystem |

| Optimize mode | Use for |
| --- | --- |
| `ReleaseFast` | Production — maximum throughput |
| `ReleaseSafe` | Production with safety checks |
| `ReleaseSmall` | Smallest binary |
| (omitted) | `Debug` — development only |

The result is a single static binary at `zig-out/bin/swerver`.

## Running

```sh
./zig-out/bin/swerver --config config.json
```

| Flag | Description |
| --- | --- |
| `--config <path>` | Load a JSON config file |
| `--workers <n>` | Worker process count (default: CPU count) |
| `--static-root <path>` | Serve static files from a directory |
| `--run-for-ms <ms>` | Run for a fixed duration then exit (testing) |

See [Running from a config file](../getting-started/config-file.md) for the full config and the [Config schema](../reference/config-schema.md) reference. The deployment-relevant blocks:

```json
{
  "server": { "address": "0.0.0.0", "port": 8080, "workers": 0, "max_connections": 4096 },
  "tls": { "cert_path": "cert.pem", "key_path": "key.pem" },
  "quic": { "enabled": true, "port": 443, "cert_path": "cert.pem", "key_path": "key.pem" }
}
```

## The multi-worker fork model

swerver runs a single-threaded event loop per process and scales by forking worker processes. With `server.workers` (or `--workers`) set to **`0`**, it forks **one worker per CPU**. Each worker binds the same port with `SO_REUSEPORT`, so the kernel spreads incoming connections across cores — no shared accept lock, no cross-core contention. On Linux, workers are pinned to CPUs.

```json
{ "server": { "port": 8080, "workers": 0 } }
```

The master process supervises the workers and restarts any that exit unexpectedly. Because each worker is a separate process, per-worker state — connection pools, the PostgreSQL pool, rate-limit buckets — is **not** shared across workers; size limits accordingly (e.g. an upstream `connection_pool.max_connections` of 64 across 8 workers is up to 512 connections to that backend).

## Docker

The recommended production base image is **`debian:trixie`**, which provides OpenSSL 3.5 for full TLS / HTTP/2 / HTTP/3 support. See the [HttpArena repo](https://github.com/justinGrosvenor/HttpArena) for a complete Dockerfile and compose setup.

!!! warning "io_uring needs an unconfined seccomp profile"
    Docker's default seccomp profile blocks the io_uring syscalls. To run (or benchmark) the native io_uring backend inside a container, pass:

    ```sh
    docker run --security-opt seccomp=unconfined ...
    ```

    Without this, the io_uring backend cannot initialize in the container.

## Running behind a load balancer

swerver can terminate TLS itself or sit behind an L4/L7 load balancer or another proxy:

- **TLS at swerver:** set `tls.cert_path` / `tls.key_path` (and `tls.certificates` for SNI multi-cert, `tls.client_ca_path` + `tls.client_cert_required` for mTLS). The front load balancer passes TCP straight through.
- **TLS at the load balancer:** terminate upstream and forward cleartext to swerver. Trust the `X-Forwarded-For` / `X-Forwarded-Proto` headers the LB sets.

Either way, run multiple swerver instances behind the LB and let `SO_REUSEPORT` plus the worker count handle per-host concurrency.

## Graceful shutdown & config reload

- **Drain on shutdown:** the master stops accepting new connections and lets workers finish in-flight requests before exiting.
- **Config hot reload:** send `SIGHUP` to reload `config.json` without dropping connections:

    ```sh
    kill -HUP $(pidof swerver)
    ```

    Value-type fields (timeouts, limits) update in place. **Structural changes** — routes, upstreams, TLS certificates — require a restart. For runtime route/upstream edits without any restart, use the [Admin API](admin-api.md).

## Health probes for orchestrators

swerver exposes two probe endpoints over all three protocols, served ahead of the router so your application never sees them:

| Path | Probe | Behavior |
| --- | --- | --- |
| `/.healthz` | Liveness | Always `200 OK`, empty body — the process is up |
| `/.ready` | Readiness | `200` once buffer pools, listeners, TLS, and QUIC are initialized; otherwise `503` |

Wire them into your orchestrator. Kubernetes example:

```yaml
livenessProbe:
  httpGet: { path: /.healthz, port: 8080 }
readinessProbe:
  httpGet: { path: /.ready, port: 8080 }
```

Liveness tells the orchestrator the process is alive; readiness gates traffic until the worker can actually serve it. See [Observability](observability.md) for metrics and logs.

## Static files

Set `server.static_root` to serve files from a directory via `sendfile(2)` (zero-copy). Static paths are checked after route and proxy matching. See [Static files](../guide/static-files.md).
