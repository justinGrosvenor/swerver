<p align="center">
  <img src="logo.png" width="128" height="128" alt="swerver">
</p>

<h1 align="center">swerver</h1>

<p align="center">A zero-copy, zero-allocation HTTP server written in pure Zig.</p>

```
HTTP/1.1 ──┐
HTTP/2   ──┼──► swerver ──► kqueue/epoll/io_uring ──► your code
HTTP/3   ──┘      │
                  └── QUIC (RFC 9000-9002)
```

> **Alpha release.** The public library API in `src/lib.zig` will change between alpha versions as it's iterated on. Breaking changes are announced in release notes. See [Known limitations](#known-limitations) for what's in and out of scope for the current release.

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

## Install

### Build from source

The canonical install path, and currently the only way to get a binary with TLS / HTTP/2 / HTTP/3 enabled. Requires Zig `0.16.0-dev.2135+7c0b42ba0` and OpenSSL 3.5+.

```bash
git clone https://github.com/justinGrosvenor/swerver.git
cd swerver
zig build -Doptimize=ReleaseFast -Denable-tls=true -Denable-http2=true -Denable-http3=true
./zig-out/bin/swerver --config config.json
```

### Pre-built binaries (GitHub Releases)

Tagged alpha releases publish cross-compiled binaries for linux-{x86_64, aarch64} and macos-{x86_64, aarch64} on the [Releases page](https://github.com/justinGrosvenor/swerver/releases). Download, extract, and run:

```bash
curl -LO https://github.com/justinGrosvenor/swerver/releases/download/v0.1.0-alpha.1/swerver-v0.1.0-alpha.1-linux-x86_64.tar.gz
tar -xzf swerver-v0.1.0-alpha.1-linux-x86_64.tar.gz
./swerver-v0.1.0-alpha.1-linux-x86_64 --config config.json
```

> **Release binaries are built without TLS, HTTP/2, or HTTP/3.** OpenSSL linking requires the host toolchain, so the cross-compiled binaries ship as HTTP/1.1-only. If you need HTTPS / HTTP/2 / HTTP/3 support, build from source (above) or use the Docker image (below). A future release may split the matrix into TLS and no-TLS variants.

### Docker

For a full-featured (TLS / HTTP/2 / HTTP/3) runtime image:

```bash
# Build from the repo root
docker build -t swerver -f httparena/Dockerfile --build-arg USE_LOCAL=1 .
docker run -p 8080:8080 -p 8443:8443 -p 8443:8443/udp swerver
```

The Dockerfile uses `debian:trixie` (OpenSSL 3.5) in the build stage and `debian:trixie-slim` at runtime, matching the ABI the HttpArena submission targets.

## Use as a library

Swerver ships as a Zig package — you can depend on it from another Zig project and embed the server into your own binary.

In your downstream project's `build.zig.zon`:

```zig
.{
    .name = .my_app,
    .version = "0.1.0",
    .dependencies = .{
        .swerver = .{
            .url = "https://github.com/justinGrosvenor/swerver/archive/refs/tags/v0.1.0-alpha.1.tar.gz",
            // .hash will be filled in by `zig fetch --save`
        },
    },
    .paths = .{""},
}
```

In your `build.zig`:

```zig
const swerver_dep = b.dependency("swerver", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("swerver", swerver_dep.module("swerver"));
```

In your application code:

```zig
const std = @import("std");
const swerver = @import("swerver");

fn handleHello(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    _ = ctx;
    return .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .body = .{ .bytes = "Hello, World!\n" },
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app_router = swerver.router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    try app_router.get("/hello", handleHello);

    var builder = swerver.ServerBuilder.configDefault().router(app_router);
    const srv = try builder.build(allocator);
    defer {
        srv.deinit();
        allocator.destroy(srv);
    }
    try srv.run(null);
}
```

See `examples/embedded/` for a complete, compiling example.

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

The config file schema is at version `1.0` (see `SCHEMA_VERSION` in `src/config_file.zig`). Core fields — `server`, `timeouts`, `limits`, `buffer_pool`, `tls`, `quic`, `upstreams`, `routes` — are stable for the `v0.1.0-alpha.N` series. Newer sub-schemas (`access_log`, `metrics`, `rate_limit`, `x402`) may move before 1.0; config files that set only the core fields will survive alpha version bumps.

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

## Requirements

- Zig 0.16.0-dev or later
- OpenSSL/BoringSSL (for TLS)
- macOS, Linux, or BSD

## Performance

### Local sanity check (wrk, single process, macOS Apple Silicon)

These are reproducible laptop numbers for people checking the repo out. They're not the authoritative competitive benchmark — see the HttpArena submission for that.

| Endpoint | Connections | Requests/sec | Avg Latency | Transfer/sec |
|----------|------------|-------------|-------------|--------------|
| GET /health | 100 | **274,617** | 328us | 19.6 MB/s |
| GET /echo | 50 | **264,698** | 163us | 31.1 MB/s |
| GET /plaintext | 100 | **285,606** | 321us | 31.3 MB/s |
| GET /json | 100 | **267,543** | 335us | 34.5 MB/s |
| GET /blob (1MB) | 50 | **6,811** | 7.35ms | 6.65 GB/s |

### HttpArena leaderboard

<!-- CRITICAL: backfill with v0.1.0-alpha.1 Linux benchmark numbers before tagging alpha.1. -->

Swerver is submitted to [HttpArena's](https://www.http-arena.com/) engine-tier cohort, which runs every framework in the same Docker-compose environment on the same 64-core hardware with the same wrk/gcannon/oha harness. Numbers for the `v0.1.0-alpha.1` submission will land here once the Linux benchmark run is complete — see the HttpArena leaderboard directly for the current state.

### Microbenchmarks

```
zig build bench
buffer_pool acquire/release: 21 ns/op
connection_pool acquire/release: 30 ns/op
```

## Known limitations

Forward-looking notes about API stability and feature scope. **These are not known bugs** — they're promises about what is and isn't in the current release.

- **API surface is not frozen.** Public types in `src/lib.zig` may change between alpha versions while the library surface is iterated on. Breaking changes are announced in release notes. The API will be frozen at the 1.0 release.
- **HTTP/3 is a young stack.** The RFC 9000-9002 + 9114 implementation is complete and handles real workloads (GET and POST/PUT both work end-to-end, verified by `scripts/test-h3-interop.sh`), but it hasn't seen the hardening that the HTTP/1.1 and HTTP/2 paths have. Treat it as production-capable but new.
- **Platform support is Linux and macOS only.** Windows is cross-compile-only — no IOCP backend, no sendfile. On the long-term roadmap but not part of the alpha.
- **WebSocket server support is not implemented.** On the 1.0 roadmap.
- **Full QUIC 0-RTT / early data is not implemented.** The handshake works and post-handshake throughput is competitive; 0-RTT adds replay protection and per-session token storage that are deferred to a later release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, build options, test matrix, and repo-specific style conventions. Security issues go through [SECURITY.md](SECURITY.md) — please don't open public issues for vulnerabilities.

## License

MIT

---

*Built with Zig. No allocators were harmed in the making of this server.*
