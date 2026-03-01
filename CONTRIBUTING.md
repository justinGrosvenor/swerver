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
```

## Submitting Changes

1. Keep changes focused — one feature or fix per PR
2. Add tests for new functionality
3. Make sure `zig build test` passes
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
