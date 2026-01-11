# Deployment Guide (#28)

## Prerequisites

- Zig 0.16+ toolchain installed and on `PATH`.
- Optional: TLS certificates (PEM key/cert) for TLS/HTTP2/QUIC.
- Optional: Systemd/unit file or container entrypoint that calls `zig build run`.

## Building the binary

```sh
zig build -Doptimize=ReleaseSmall \
    -Denable-tls \
    -Denable-http2 \
    -Denable-http3
```

- `-Denable-tls` turns on the TLS provider (BoringSSL shim). Supply keys via `config.yaml`.
- HTTP/2/3 flags automatically wire ALPN/QUIC stacks.
- Release builds default to `ReleaseFast` if `optimize` omitted; specify `ReleaseSmall` or `Debug` as needed.

## Configuration

Create `config.yaml` (or JSON/TOML) describing:

```yaml
address: "0.0.0.0"
port: 8080
tls:
  cert_path: "/etc/ssl/certs/server.crt"
  key_path: "/etc/ssl/private/server.key"
limits:
  max_header_bytes: 8192
  max_body_bytes: 65536
  max_header_count: 128
  buffer_size: 16384
  buffer_count: 4096
x402:
  enabled: true
  payment_required_b64: ABCE...
timeouts:
  idle_ms: 60000
  header_ms: 5000
  body_ms: 30000
  write_ms: 5000
```

- `x402.payment_required_b64` holds the base64-encoded JSON challenge payload documented in `docs/design/4.0-x402-payments.md`.
- Use the `config` module to load the file at startup (currently part of `src/main.zig`).

## Running

```sh
./zig-out/bin/swerver --config config.yaml
```

- On Linux, wrap this in systemd, runit, or containers. Ensure `/metrics`, `/.healthz`, and `/.ready` are reachable from monitoring systems.
- For TLS termination, either let Swerver handle TLS or run it behind a proxy (the middleware docs assume TLS-aware contexts).

## Observability

- Health/readiness probes: `/.healthz` (`200`), `/.ready` (`503` until readiness flags are set via runtime initialization).
- Metrics: `GET /metrics` (Prometheus text). Requires the metrics middleware to be enabled (enabled by default).
- Logging: configure `middleware/observability.zig::config` to set log level/format, request ID header, and `log_stderr`.
- Metrics output now includes `protocol` + `stream_id` labels for active HTTP/2 streams; take care not to scrape it with high label cardinality. The `/metrics` exporter already uses a thread-local buffer to avoid allocations, and the ring buffer described in `docs/design/6.0-middleware.md` keeps the latest 256 stream records.
- Observability exposes `registerOnExit()` so you can hook eBPF (or userland) consumers that run when a request/connection drains; the bundled `EbpfCounters` struct is safe to call from kernel proxies or shared memory exporters.
 
## Request shaping / backpressure

- Rate limiting is implemented by the `ratelimit` middleware, which tracks token buckets per IP and supports `premium_weight` multipliers for x402 routes.
- When a bucket is empty, the middleware sets `BackpressureInfo.pause_reads` and schedules `resume_after_ms`. The runtime honor this by pausing reads on that connection until tokens refill, preventing the parser from over-consuming the buffer.
- Configure the middleware to exclude probes (`/.healthz`, `/.ready`, `/metrics`) from shaping so monitoring paths stay fast.

## eBPF / Advanced telemetry

- The deployment guide in `docs/design/6.0-middleware.md` mentions registering `onExit` callbacks for congestion alerts. Hook those callbacks into your eBPF toolchain by calling `middleware.Context.logMessage`/`observability.log`.
- If you have an eBPF program, map it to the `EbpfCounters` layout (counts for requests, bytes, errors, stream IDs) and call `registerOnExit(my_hook)` at startup so that every completed stream can publish the necessary values. Observability already includes a userland fallback that writes the same counters to shared memory, so you can run without eBPF while keeping the same API.

## Zero-downtime upgrades

- Drain existing connections by toggling `conn.close_after_write` via runtime hooks (not yet implemented), or restart behind a load balancer that drains in-flight streams.
