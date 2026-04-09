# swerver

A zero-copy, zero-allocation HTTP server written in pure Zig.

```
HTTP/1.1 ──┐
HTTP/2   ──┼──► swerver ──► kqueue/epoll ──► your code
HTTP/3   ──┘      │
                  └── QUIC (RFC 9000-9002)
```

## Why

Because the fastest memory operation is the one you don't do.

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
| Reverse proxy (load balancing, health checks) | ✓ |
| Multi-worker (fork + SO_REUSEPORT) | ✓ |
| JSON config file (`--config`) | ✓ |
| io_uring backend (Linux) | ✓ |
| Access logging (combined/JSON) | ✓ |
| Static file serving (sendfile) | ✓ |
| Rate limiting (token bucket) | ✓ |
| Security headers (HSTS, CSP, CORS) | ✓ |
| x402 payment protocol | ✓ |

## Quick Start

```bash
# Build
zig build

# Run
zig build run

# Run with a config file
zig build run -- --config config.json

# Run with HTTP/3 enabled
zig build -Denable-http3=true -Denable-tls=true run

# Test
zig build test

# Test matrix (runs tests under multiple feature flag combinations)
zig build test-matrix

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
│   ├── clock.zig          # Monotonic clock, timers
│   ├── io.zig             # Event loop abstraction
│   └── backend/
│       ├── kqueue.zig     # macOS/BSD
│       ├── epoll.zig      # Linux
│       └── io_uring.zig   # Linux (io_uring)
├── protocol/
│   ├── http1.zig          # HTTP/1.1 parser
│   ├── http2.zig          # HTTP/2 + HPACK
│   └── http3.zig          # HTTP/3 + QPACK
├── proxy/
│   └── proxy.zig          # Reverse proxy + load balancing
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
│   ├── access_log.zig     # Access logging (combined/JSON)
│   └── observability.zig  # Structured logging
├── config_file.zig        # JSON config parser
├── master.zig             # Multi-process fork manager
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
    .buffer_size = 64 * 1024,   // 64KB per buffer
    .buffer_count = 4096,        // 64MB total
};
```

## Configuration

### JSON config file

```bash
zig build run -- --config config.json
```

```json
{
  "server": {
    "port": 8080,
    "workers": 4,
    "max_connections": 4096,
    "static_root": "./public"
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
  "upstreams": [
    {
      "name": "api_backend",
      "servers": ["127.0.0.1:3000", "127.0.0.1:3001"],
      "load_balancer": "round_robin"
    }
  ],
  "routes": [
    {
      "path_prefix": "/api",
      "upstream": "api_backend"
    }
  ]
}
```

Config is hot-reloaded on `SIGHUP` (timeouts, limits, and other value types).

### Embedded (Zig API)

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
// Middleware returns a decision (simplified — actual type has 5 variants)
pub const Decision = union(enum) {
    allow,                           // Continue to next middleware
    skip,                            // Skip remaining middleware
    reject: Response,                // Stop and return response
    modify: struct {                 // Add headers, continue
        response_headers: []Header,
        continue_chain: bool,
    },
    rate_limit_backpressure: u64,    // Apply backpressure (ms)
};
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--config <path>` | Load JSON configuration file |
| `--workers <n>` | Number of worker processes (default: CPU count) |
| `--static-root <path>` | Serve static files from directory |
| `--run-for-ms <ms>` | Run for specified duration then exit (testing) |

## Build Options

| Flag | Description |
|------|-------------|
| `-Denable-tls=true` | Enable TLS 1.3 support |
| `-Denable-http2=true` | Enable HTTP/2 support |
| `-Denable-http3=true` | Enable HTTP/3 over QUIC |
| `-Denable-proxy=true` | Enable reverse proxy |
| `-Denable-io-uring=true` | Enable io_uring backend (Linux) |
| `-Doptimize=ReleaseFast` | Maximum performance |

### CI note

Some environments restrict access to Zig's global cache. If tests fail with `PermissionDenied`, set:

```bash
export ZIG_GLOBAL_CACHE_DIR="$(pwd)/.zig-cache-global"
export ZIG_LOCAL_CACHE_DIR="$(pwd)/.zig-cache"
```

## Requirements

- Zig 0.16.0-dev or later
- OpenSSL/BoringSSL (for TLS)
- macOS, Linux, or BSD

## Performance

### Native (wrk, single process, macOS Apple Silicon)

| Endpoint | Connections | Requests/sec | Avg Latency | Transfer/sec |
|----------|------------|-------------|-------------|--------------|
| GET /health | 100 | **274,617** | 328us | 19.6 MB/s |
| GET /echo | 50 | **264,698** | 163us | 31.1 MB/s |
| GET /plaintext | 100 | **285,606** | 321us | 31.3 MB/s |
| GET /json | 100 | **267,543** | 335us | 34.5 MB/s |
| GET /blob (1MB) | 50 | **6,811** | 7.35ms | 6.65 GB/s |

### Docker k6 (100 VUs, 30s, 2 CPU / 512MB per container)

| Scenario | swerver | actix (Rust) | nginx |
|----------|---------|-------------|-------|
| **Throughput** (req/s) | **168,588** | 129,903 | 121,745 |
| **Concurrent** ramp to 1000 VUs (req/s) | **196,990** | 159,399 | 132,025 |
| **Connections** new conn/req (conn/s) | **86,971** | 64,733 | 23,928 |
| **Latency** p99 (ms) | **5.02** | 5.52 | 5.18 |
| **Mixed** GET+POST+blob (req/s) | **36,405** | 35,970 | 34,781 |

### Microbenchmarks

```
zig build bench
buffer_pool acquire/release: 21 ns/op
connection_pool acquire/release: 30 ns/op
```

## License

MIT

---

*Built with Zig. No allocators were harmed in the making of this server.*
