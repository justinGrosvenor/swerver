# Contributing to Swerver

Thanks for your interest in contributing to swerver! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork and create a branch for your change
3. Install [Zig 0.16.0-dev](https://ziglang.org/download/) (nightly)
4. Build and run tests:
   ```bash
   zig build
   zig build test
   ```

## Development

### Project Structure

- `src/` — All source code
- `src/server.zig` — Main event loop
- `src/master.zig` — Multi-process fork manager
- `src/proxy/` — Reverse proxy and load balancer
- `src/quic/` — QUIC protocol implementation
- `src/runtime/` — Platform backends (kqueue, epoll, io_uring)
- `src/middleware/` — Middleware chain (access log, metrics, x402)
- `docs/` — Design documents
- `bench/` — Benchmarks

### Build Options

```bash
zig build                          # default build
zig build -Doptimize=ReleaseFast   # optimized build
zig build -Denable-tls=true        # with TLS support
zig build test                     # run all tests
zig build test-matrix              # run tests across every feature-flag combination
zig build test-flags               # compile-only variant of test-matrix (faster smoke check)
```

Always run `zig build test-matrix` before submitting a PR that touches the
core server, router, protocol, or runtime layers. A change can pass `zig build
test` and still break a feature-flag combination — the matrix step is what
catches that.

### Style Conventions

A few repo-specific conventions that diverge from the typical Zig stdlib style.
These are intentional — please don't "fix" them in PRs:

- **SCREAMING_CASE module-level constants** (e.g. `MAX_TRACKED_IPS`,
  `DEFAULT_WORKER_COUNT`) are used throughout. The stdlib uses `camelCase` for
  constants; swerver doesn't. If you're sending a PR that touches constants,
  keep the existing casing.
- **Offset-based `bufPrint` / custom writer helpers** instead of
  `std.io.fixedBufferStream`. The fbs API was removed in 0.16.0-dev; the
  replacement pattern is hand-tracked offsets. See `src/runtime/json_write.zig`
  and `src/middleware/access_log.zig:formatJson` for the canonical shape.
- **`src/runtime/clock.zig`** is the one-stop replacement for the removed
  `std.time.nanoTimestamp`, `std.time.Instant`, `std.posix.close`,
  `std.posix.clock_gettime`, and related stdlib calls. Use it, don't reach
  for the removed stdlib APIs.

## Submitting Changes

1. Keep changes focused — one feature or fix per PR
2. Add tests for new functionality
3. Make sure `zig build test-matrix` passes (not just `zig build test`)
4. Write a clear commit message describing what and why

## Reporting Bugs

Open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Zig version and OS

## Security

If you find a security vulnerability, please see [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
