# Architecture

swerver is a single-threaded event loop **per process**. There is no thread pool and no work-stealing — each worker process owns one event loop, one set of buffer pools, and the connections the kernel hands it. Concurrency comes from running N of these processes, not from threads sharing state. That's what lets the hot path stay allocation-free and lock-free: nothing on a request is contended.

## Process and listener model

A server runs as **N worker processes** under a fork manager (`master.zig`), one per CPU by default. Set `server.workers` (or `--workers`) to override; `workers: 1` runs single-process with no fork.

Every worker binds the **same ports** with `SO_REUSEPORT`, so the kernel load-balances new connections across workers with no userspace coordination — no accept lock, no shared accept queue. On Linux, workers are CPU-pinned.

A single worker can bind **multiple TCP ports at once** (the multi-listener model). Each listener carries its own protocol config: plaintext HTTP/1.1, h2c-only, TLS HTTP/1.1+HTTP/2 via ALPN, plus an optional QUIC/HTTP/3 endpoint over UDP. A plain `address`/`port` config is treated as a one-element listener set.

**Protocol is resolved at accept.** When a connection arrives, the worker reads the local port (`getsockname`) and looks up the matching listener config. The I/O backends never need to know about per-port protocol differences — by the time bytes flow, the connection already knows whether it's plaintext h1, h2c, TLS+ALPN, or QUIC.

## I/O backends

Platform I/O is abstracted behind a single event-loop interface (`runtime/io.zig`), with one of four backends selected at runtime:

| Backend | Platform | Notes |
| --- | --- | --- |
| `kqueue` | macOS / BSD | Readiness notification. |
| `epoll` | Linux | Readiness notification. |
| `io_uring_poll` | Linux (modern) | io_uring used as a poll/readiness layer. |
| `io_uring_native` | Linux (modern) | io_uring completion model — inline accept, vectored writes, single-shot recv. |

The `io_uring` backends require `-Denable-io-uring=true` at build time. The event loop owns socket lifecycle and readiness; everything above it (TLS, protocol parsing, routing) is backend-agnostic.

## Buffer pools

All request/response memory is allocated **once at startup** into fixed-size pools. There is no per-request `malloc`. A buffer is acquired from the pool when a connection needs one and returned when the response is written.

```zig
const cfg = BufferPoolConfig{
    .buffer_size = 64 * 1024,   // 64 KB per buffer
    .buffer_count = 4096,        // 64 MB total, per worker
};
```

A separate **body pool** (default 32 × 1 MB) isolates large uploads so a few big POSTs can't starve the hot-path pool. Pool sizes are config-tunable under `buffer_pool` — see the [config schema](../reference/config-schema.md#buffer_pool).

## Zero-copy parsing

Request parsing happens **directly on the receive buffer**. Header names and values are `[]const u8` slices into the bytes the kernel delivered — not copies:

```zig
pub const Header = struct {
    name: []const u8,   // slice into the receive buffer, not owned
    value: []const u8,  // slice, not owned
};
```

This is why [handlers are synchronous](../guide/handlers.md): they run to completion before the next `recv()` on that connection, so `ctx.request.headers` and `ctx.request.body` stay valid for the life of the handler with zero copying. The HPACK (HTTP/2) and QPACK (HTTP/3) decoders use fixed-size internal tables rather than growing allocations. Static files transfer zero-copy via platform primitives (`sendfile`).

## The source tree

```
src/
├── server/
│   ├── dispatch.zig       # Event loop dispatch (read/write/accept)
│   ├── accept.zig         # Connection accept path + per-port protocol resolution
│   ├── http1.zig          # HTTP/1.1 dispatch + body accumulation
│   ├── http2.zig          # HTTP/2 dispatch + response encoding
│   ├── http3.zig          # HTTP/3 dispatch + send path
│   ├── tls.zig            # TLS handshake + ciphertext pump
│   ├── preencoded.zig     # Pre-encoded response cache
│   └── write_queue.zig    # Write-queue + buffer-op helpers
├── runtime/
│   ├── buffer_pool.zig    # Fixed-size buffer management
│   ├── connection.zig     # Connection state machine
│   ├── clock.zig          # Monotonic clock, timers
│   ├── io.zig             # Event loop abstraction
│   └── backend/
│       ├── kqueue.zig     # macOS/BSD
│       ├── epoll.zig      # Linux
│       └── io_uring.zig   # Linux (io_uring native + poll emulation)
├── protocol/
│   ├── http1.zig          # HTTP/1.1 parser
│   ├── http2.zig          # HTTP/2 + HPACK
│   └── http3.zig          # HTTP/3 + QPACK
├── proxy/
│   ├── proxy.zig          # Reverse proxy + load balancing
│   ├── websocket.zig      # WebSocket tunnel relay
│   ├── cache.zig          # Response cache (LRU)
│   ├── consul.zig         # Consul service discovery
│   └── dns.zig            # DNS service discovery
├── admin/
│   └── admin.zig          # Runtime route/upstream management API
├── quic/
│   ├── connection.zig     # QUIC state machine
│   ├── stream.zig         # QUIC streams
│   ├── crypto.zig         # Packet protection
│   ├── recovery.zig       # Loss detection
│   └── congestion.zig     # Congestion control (NewReno)
├── middleware/
│   ├── auth.zig           # API key / JWT / forward-auth
│   ├── ratelimit.zig      # Token bucket rate limiting (IP + consumer)
│   ├── security.zig       # Security headers
│   ├── compress.zig       # Response compression (gzip/deflate)
│   ├── grpc.zig           # gRPC status mapping
│   ├── body_schema.zig    # Request body validation
│   ├── otel.zig           # OpenTelemetry trace export
│   ├── metrics_mw.zig     # Prometheus exporter
│   ├── health.zig         # Liveness/readiness probes
│   ├── access_log.zig     # Access logging (combined/JSON)
│   └── observability.zig  # Structured logging
├── config_file.zig        # JSON config parser
├── master.zig             # Multi-process fork manager
└── server.zig             # Main server loop
```

## Request lifecycle, end to end

1. The kernel delivers a connection to a worker via `SO_REUSEPORT`; the accept path resolves its protocol from the local port.
2. TLS terminates (if the listener uses it); ALPN picks h1/h2, or QUIC carries h3.
3. The protocol stack parses the request as slices into the receive buffer.
4. The router selects a handler, static file, or proxy route, running the zero-allocation middleware chain.
5. The response pipeline batches headers and body into vectored writes back through TLS and the I/O backend.

The middleware chain returns a small `Decision` union (allow / skip / reject / modify / backpressure) and allocates nothing per request.

## Related

- [Build options](../reference/build-options.md) — selecting the io_uring backend and protocol features.
- [Benchmarks](benchmarks.md) — how this design performs under saturation.
- [Handlers & responses](../guide/handlers.md) — why handlers are synchronous and how buffer lifetimes work.
