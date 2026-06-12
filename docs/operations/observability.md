# Observability

swerver exposes its health and runtime behavior through four surfaces: a Prometheus metrics endpoint, health probes, access logging, and OpenTelemetry trace export. All of them are part of the zero-allocation middleware chain, so they add no per-request heap churn.

## Metrics

`GET /metrics` returns Prometheus text exposition format over HTTP/1.1, HTTP/2, and HTTP/3. The output is generated with **zero heap allocations** and series are **labeled per protocol**, so you can compare H1 vs H2 vs H3 behavior on the same server.

What's exported:

- **Request / response counters**: totals by protocol and status class.
- **Latency histograms**: request duration distributions.
- **Byte counters**: bytes in / out.
- **QUIC stats**: connection and packet-level counters for the HTTP/3 path.

When the reverse proxy is enabled, proxy-specific series are included (proxied request totals and durations, upstream connect time, active/idle pool gauges, upstream health status, retries, and proxy errors by type).

Scrape it like any Prometheus target:

```yaml
scrape_configs:
  - job_name: swerver
    static_configs:
      - targets: ["swerver-host:8080"]
```

The metrics middleware also registers a pre-routing decision so `/metrics` itself is handled before the application router, and a post-response hook that records status, protocol, latency, and byte counts for every request.

## Health probes

Two endpoints, served ahead of the router (the application never sees them):

| Path | Probe | Behavior |
| --- | --- | --- |
| `/.healthz` | Liveness | Always `200 OK` with `Content-Length: 0`: the process is up. Cached per connection. |
| `/.ready` | Readiness | `200` once the buffer pools, listeners, TLS, and QUIC subsystems are initialized; otherwise `503`. No body. |

Use liveness to detect a hung process and readiness to gate traffic until a worker can serve it. See [Deployment](deployment.md#health-probes-for-orchestrators) for orchestrator wiring.

## Access logging

The access-logging middleware writes one line per request to **stderr**, in either **combined** (Apache-style) or **JSON** format, controlled by the `access_log` server config. For proxied requests it adds upstream fields: the selected upstream address, the upstream response status, and upstream timing (time to first byte, connect time).

!!! note
    The `access_log` sub-schema is still being stabilized across alpha releases. Check the [Config schema](../reference/config-schema.md) reference for the exact keys in your build.

The observability middleware also normalizes request IDs and emits a `Request-Id` response header so logs and traces can be correlated end to end.

## OpenTelemetry tracing

When `otel.enabled` is true, swerver exports spans to an OTLP collector over HTTP:

```json
{
  "otel": {
    "enabled": true,
    "collector_url": "http://localhost:4318",
    "service_name": "swerver",
    "sample_rate": 100,
    "flush_interval_s": 10,
    "max_batch_size": 512
  }
}
```

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Turn trace export on |
| `collector_url` | (none) | OTLP collector endpoint |
| `service_name` | `swerver` | `service.name` resource attribute |
| `sample_rate` | `100` | Percent of requests sampled, `0` to `100` (`100` = all) |
| `flush_interval_s` | (none) | How often batched spans are flushed |
| `max_batch_size` | (none) | Max spans per export batch |
| `headers` | (none) | Optional extra OTLP request headers |

Spans carry the request ID, so a trace in your collector lines up with the `Request-Id` header and the matching access-log entry.

## See also

- [Deployment](deployment.md): health probes and the worker model.
- [Admin API](admin-api.md): runtime introspection of routes and upstreams.
- [Reverse proxy & gateway](../guide/reverse-proxy.md): the proxy metrics referenced above.
