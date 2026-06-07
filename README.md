<p align="center">
  <img src="logo.png" width="128" height="128" alt="swerver">
</p>

<h1 align="center">swerver</h1>

<p align="center">A bare metal HTTP server written in pure Zig.</p>

```
HTTP/1.1 ──┐
HTTP/2   ──┼──► swerver ──► kqueue/epoll/io_uring ──► your code
HTTP/3   ──┘      │
                  └── QUIC (RFC 9000-9002)
```

> **Alpha release.** The public library API in `src/lib.zig` will change between alpha versions as it's iterated on. Breaking changes are announced in release notes. See [Known limitations](#known-limitations) for what's in and out of scope for the current release.

## What

Swerver is a bare-metal HTTP/1.1 + HTTP/2 + HTTP/3 server. It holds **#1 on JSON-over-TLS** on HttpArena's 64-core benchmark (1.95M req/s) and runs top-tier across baseline, pipelined, HTTP/2, and HTTP/3, carrying a full middleware chain, TLS termination, and routing.

Fixed-size buffer pools. Stack-allocated parsing. No garbage collection. No hidden allocations. No surprises.

## Quick Start

```bash
# Build
zig build

# Build with TLS + HTTP/2 + HTTP/3
zig build -Denable-tls=true -Denable-http2=true -Denable-http3=true

# Run
zig build run

# Run with a config file
zig build run -- --config config.json

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

Requires Zig `0.16.0` (stable). OpenSSL 3.5+ for TLS/HTTP/2/HTTP/3.

```bash
git clone https://github.com/justinGrosvenor/swerver.git
cd swerver
zig build -Doptimize=ReleaseFast -Denable-tls=true -Denable-http2=true -Denable-http3=true
./zig-out/bin/swerver --config config.json
```

### Pre-built binaries (GitHub Releases)

Tagged alpha releases publish cross-compiled binaries for linux-{x86_64, aarch64} and macos-{x86_64, aarch64} on the [Releases page](https://github.com/justinGrosvenor/swerver/releases). Download, extract, and run:

```bash
curl -LO https://github.com/justinGrosvenor/swerver/releases/download/v0.1.0-alpha.12/swerver-v0.1.0-alpha.12-linux-x86_64.tar.gz
tar -xzf swerver-v0.1.0-alpha.12-linux-x86_64.tar.gz
./swerver-v0.1.0-alpha.12-linux-x86_64 --config config.json
```

> **Release binaries are built without TLS, HTTP/2, or HTTP/3.** OpenSSL linking requires the host toolchain, so the cross-compiled binaries ship as HTTP/1.1-only. Build from source or use the Docker image for full protocol support.

### Docker

The HttpArena submission includes a Dockerfile that builds a full-featured (TLS / HTTP/2 / HTTP/3) runtime image using `debian:trixie` (OpenSSL 3.5). See the [HttpArena repo](https://github.com/justinGrosvenor/HttpArena) for the Dockerfile and docker-compose setup.

## Use as a library

Swerver ships as a Zig package — you can depend on it from another Zig project and embed the server into your own binary.

In your downstream project's `build.zig.zon`:

```zig
.{
    .name = .my_app,
    .version = "0.1.0",
    .dependencies = .{
        .swerver = .{
            .url = "https://github.com/justinGrosvenor/swerver/archive/refs/tags/v0.1.0-alpha.12.tar.gz",
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

const AppState = struct { greeting: []const u8 };

fn hello(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const state = ctx.state(AppState);
    return ctx.text(200, state.greeting);
}

fn echo(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    var builder = ctx.respond() catch return ctx.text(503, "No buffers available");
    defer ctx.releaseBuilder(&builder);
    return builder.json(200, ctx.request.body.sliceOrNull() orelse "") catch
        ctx.text(500, "Response buffer full");
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var state = AppState{ .greeting = "hello, galaxy" };

    var router = swerver.router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    var api = router.group("/api");
    try api.get("/hello", hello);
    try api.post("/echo", echo);

    var server = try swerver.ServerBuilder
        .configDefault()
        .router(router)
        .withState(&state)
        .build(gpa.allocator());
    defer server.deinit();

    try server.run(null);
}
```

See `examples/embedded/` and `examples/gateway/` for complete, compiling examples.

## Architecture

```
src/
├── server/
│   ├── dispatch.zig       # Event loop dispatch (read/write/accept)
│   ├── accept.zig         # Connection accept path
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

| Flag | Default | Description |
|------|---------|-------------|
| `-Denable-tls` | false | TLS 1.3 support (requires OpenSSL) |
| `-Denable-http2` | false | HTTP/2 support |
| `-Denable-http3` | false | HTTP/3 over QUIC |
| `-Denable-proxy` | false | Reverse proxy |
| `-Denable-io-uring` | false | io_uring backend (Linux) |
| `-Denable-compression` | false | Response compression (requires zlib) |
| `-Denable-x402-crypto` | false | x402 local signature verification (secp256k1) |
| `-Doptimize=ReleaseFast` | | Maximum performance |

## Requirements

- Zig 0.16.0 (stable)
- OpenSSL 3.5+ (for TLS / HTTP/2 / HTTP/3)
- macOS or Linux

## Benchmarks

[HttpArena](https://www.http-arena.com/) leaderboard (64-core dedicated hardware, same Docker-compose environment for every framework):

| Test | Conns | Requests/sec | |
|---|---:|---:|---|
| **json-tls** (TLS + JSON serialize) | 4096 | **1,950,310** | **#1** |
| baseline (HTTP/1.1 plaintext) | 4096 | 3,664,110 | |
| pipelined (HTTP/1.1) | 4096 | 24,907,762 | |
| limited-conn (connection churn) | 4096 | 2,556,130 | |
| json (HTTP/1.1) | 4096 | 2,366,920 | |
| static file serving | 6800 | 1,197,205 | |
| baseline (HTTP/2) | 1024 | 2,267,290 | |
| baseline (HTTP/3) | 64 | 872,911 | |

Zero errors at 64-core saturation. ~222us average latency on limited-conn.

**A note on "fastest":** on raw HTTP/1.1 microbenchmarks (plaintext baseline, pipelined, limited-conn), feature-stripped reference servers edge swerver by 1-2%. Neither implements TLS, HTTP/2, or HTTP/3, so neither appears on json-tls, baseline-h2, or baseline-h3. Swerver is the fastest server that does the full job: three protocols, TLS termination, routing, and a complete middleware chain.

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
| io_uring backend (Linux) | ✓ |
| TLS 1.3 (via OpenSSL/BoringSSL) | ✓ |
| SNI multi-certificate TLS | ✓ |
| mTLS client certificate verification | ✓ |
| Reverse proxy (load balancing, health checks) | ✓ |
| WebSocket proxy | ✓ |
| gRPC-aware proxy | ✓ |
| Response caching (LRU) | ✓ |
| Response compression (gzip/deflate) | ✓ |
| Traffic splitting (canary/blue-green) | ✓ |
| Traffic mirroring (shadow testing) | ✓ |
| DNS / Consul service discovery | ✓ |
| Admin API (runtime route management) | ✓ |
| SIGHUP hot reload (routes + upstreams) | ✓ |
| API key / JWT authentication | ✓ |
| Forward-auth proxy | ✓ |
| Request body validation (JSON Schema) | ✓ |
| OpenTelemetry trace export | ✓ |
| Multi-worker (fork + SO_REUSEPORT) | ✓ |
| JSON config file (`--config`) | ✓ |
| Access logging (combined/JSON) | ✓ |
| Static file serving (sendfile) | ✓ |
| Prometheus metrics (`/metrics`) | ✓ |
| Health probes (`/.healthz`, `/.ready`) | ✓ |
| Rate limiting (per-IP / per-consumer) | ✓ |
| Security headers (HSTS, CSP, CORS) | ✓ |
| x402 payment protocol | ✓ |

## Known limitations

Forward-looking notes about API stability and feature scope. **These are not known bugs** — they're promises about what is and isn't in the current release.

- **API surface is not frozen.** Public types in `src/lib.zig` may change between alpha versions while the library surface is iterated on. Breaking changes are announced in release notes. The API will be frozen at the 1.0 release.
- **HTTP/3 is a young stack.** The RFC 9000-9002 + 9114 implementation is complete and handles real workloads (GET and POST/PUT both work end-to-end), but it hasn't seen the hardening that the HTTP/1.1 and HTTP/2 paths have. Treat it as production-capable but new.
- **Platform support is Linux and macOS only.** Windows is cross-compile-only — no IOCP backend, no sendfile. On the long-term roadmap but not part of the alpha.
- **Full QUIC 0-RTT / early data is not implemented.** The handshake works and post-handshake throughput is competitive; 0-RTT adds replay protection and per-session token storage that are deferred to a later release.

## Roadmap

- **Alpha iteration:** public API refinement based on feedback, HttpArena re-submissions across kernel/hardware variation, expanded examples.
- **Beta:** API surface frozen, PostgreSQL-backed REST benchmark added to HttpArena, long-form operational documentation.
- **1.0:** WebSocket server support, full QUIC 0-RTT / early data, security audit, stable C ABI for embedding in non-Zig programs, Windows support.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, build options, test matrix, and repo-specific style conventions. Security issues go through [SECURITY.md](SECURITY.md) - please don't open public issues for vulnerabilities.

## License

MIT

---

*Built with Zig. No allocators were harmed in the making of this server.*
