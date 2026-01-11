# swerver

A zero-copy, zero-allocation HTTP server written in pure Zig.

```
HTTP/1.1 ──┐
HTTP/2   ──┼──► swerver ──► kqueue/epoll ──► your code
HTTP/3   ──┘      │
                  └── QUIC (RFC 9000-9002)
```

## Why

Because allocators are for the weak. Because `malloc` is a syscall in disguise. Because the fastest memory operation is the one you don't do.

Swerver processes HTTP requests using fixed-size buffer pools and stack-allocated parsing. No garbage collection. No hidden allocations. No surprises.

## Features

| Feature | Status |
|---------|--------|
| HTTP/1.1 with keep-alive | ✓ |
| HTTP/2 with HPACK compression | ✓ |
| HTTP/3 over QUIC | ✓ |
| Zero-copy request parsing | ✓ |
| Fixed-size buffer pools | ✓ |
| Backpressure handling | ✓ |
| kqueue (macOS/BSD) | ✓ |
| epoll (Linux) | ✓ |
| TLS 1.3 (via OpenSSL/BoringSSL) | ✓ |
| Prometheus metrics (`/metrics`) | ✓ |
| Health probes (`/.healthz`, `/.ready`) | ✓ |
| Rate limiting (token bucket) | ✓ |
| Security headers (HSTS, CSP, CORS) | ✓ |
| x402 payment protocol | ✓ |

## Quick Start

```bash
# Build
zig build

# Run
zig build run

# Run with HTTP/3 enabled
zig build -Denable-http3=true -Denable-tls=true run

# Test
zig build test

# Benchmark
zig build bench
```

The server listens on `0.0.0.0:8080` by default.

## Architecture

```
src/
├── runtime/
│   ├── buffer_pool.zig    # Fixed-size buffer management
│   ├── connection.zig     # Connection state machine
│   ├── io.zig             # Event loop abstraction
│   └── backend/
│       ├── kqueue.zig     # macOS/BSD
│       └── epoll.zig      # Linux
├── protocol/
│   ├── http1.zig          # HTTP/1.1 parser
│   ├── http2.zig          # HTTP/2 + HPACK
│   └── http3.zig          # HTTP/3 + QPACK
├── quic/
│   ├── connection.zig     # QUIC state machine
│   ├── stream.zig         # QUIC streams
│   ├── crypto.zig         # Packet protection
│   ├── recovery.zig       # Loss detection
│   └── congestion.zig     # Congestion control (NewReno)
├── middleware/
│   ├── ratelimit.zig      # Token bucket rate limiting
│   ├── security.zig       # Security headers
│   ├── metrics_mw.zig     # Prometheus exporter
│   ├── health.zig         # Liveness/readiness probes
│   └── observability.zig  # Structured logging
└── server.zig             # Main server loop
```

## Zero-Copy Design

Request parsing happens directly on receive buffers. Headers are slices into the original packet data, not copies. The HTTP/2 HPACK and HTTP/3 QPACK decoders use fixed-size internal tables.

```zig
// Headers are views into the receive buffer
pub const Header = struct {
    name: []const u8,   // slice, not owned
    value: []const u8,  // slice, not owned
};
```

The buffer pool pre-allocates all memory at startup:

```zig
const cfg = BufferPoolConfig{
    .buffer_size = 16 * 1024,   // 16KB per buffer
    .buffer_count = 4096,        // 64MB total
};
```

## Configuration

```zig
const cfg = ServerConfig{
    .address = "0.0.0.0",
    .port = 8080,
    .max_connections = 2048,
    .timeouts = .{
        .idle_ms = 60_000,
        .header_ms = 10_000,
        .body_ms = 30_000,
    },
    .limits = .{
        .max_header_bytes = 32 * 1024,
        .max_body_bytes = 8 * 1024 * 1024,
    },
    .quic = .{
        .enabled = true,
        .port = 443,
        .cert_path = "cert.pem",
        .key_path = "key.pem",
    },
};
```

## QUIC Implementation

Full RFC 9000-9002 implementation:

- **Packet Protection**: AES-128-GCM with header protection
- **Loss Detection**: RTT estimation, PTO calculation
- **Congestion Control**: NewReno with pacing
- **Flow Control**: Connection and stream-level
- **Stream Multiplexing**: Bidirectional and unidirectional

## Middleware

Middleware runs in a chain with zero allocations:

```zig
// Middleware returns a decision
pub const Decision = union(enum) {
    allow,                           // Continue to next middleware
    reject: Response,                // Stop and return response
    modify: struct {                 // Add headers, continue
        response_headers: []Header,
        continue_chain: bool,
    },
};
```

## Build Options

| Flag | Description |
|------|-------------|
| `-Denable-tls=true` | Enable TLS 1.3 support |
| `-Denable-http2=true` | Enable HTTP/2 support |
| `-Denable-http3=true` | Enable HTTP/3 over QUIC |
| `-Doptimize=ReleaseFast` | Maximum performance |

## Requirements

- Zig 0.14.0 or later
- OpenSSL/BoringSSL (for TLS)
- macOS, Linux, or BSD

## Performance

Buffer pool operations: ~15-25 ns/op
Connection pool operations: ~20-30 ns/op
HTTP/1.1 request parsing: ~200-400 ns

Run `zig build bench` for microbenchmarks.

## License

MIT

---

*Built with Zig. No allocators were harmed in the making of this server.*
