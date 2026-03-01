# Changelog

## Unreleased

- Streaming request body support (bodies up to 8MB via buffer accumulation)
- Buffer size increased from 16KB to 64KB
- Fix edge-triggered epoll stall on large body uploads

## 2026-03-01

- Fix load balancer out-of-bounds on empty server list
- Fix HEAD response sending body bytes
- Fix HTTP/3 packet buffer overflow on large payloads
- Fix QUIC packet number encoding for multi-byte values
- Prepare for public release (gitignore cleanup)
- Multi-worker proxy with SO_REUSEPORT
- Real eBPF maps for per-CPU counters
- Smooth Weighted Round Robin (SWRR) balancer
- DNS resolution for upstream addresses
- QUIC congestion control and flow control improvements

## 2026-02-24

- Benchmark fairness audit (8KB blob to match other servers)
- Add Docker k6 benchmark results to README
- Combine managed body into single write, cache Date header

## 2026-02-22

- Upgrade to Zig 0.16.0-dev.2637
- Protocol compliance and security hardening (stack overflow fix)
- Comprehensive security audit — 53 findings across 4 rounds

## 2026-01-12

- Dependency injection and server composition (`ServerBuilder`)
- Reverse proxy with real TCP I/O

## 2026-01-11

- Spec compliance fixes and benchmark endpoints
- Fix QUIC/HTTP/3 compilation errors
- QUIC/HTTP/3 tier 4 implementation

## 2026-01-10

- HTTP/3 over QUIC, middleware (rate limiting, security headers, metrics, health probes)
- Initial commit — HTTP/1.1 server with kqueue/epoll, zero-copy parsing, buffer pools
