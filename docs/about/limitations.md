# Limitations & roadmap

Honest, forward-looking notes about what's in and out of scope for the current alpha. **These are not known bugs** — they're promises about the surface and where it's headed.

## Limitations

!!! warning "The public API is not frozen"
    Public types in `src/lib.zig` may change between alpha versions while the library surface is iterated on. Breaking changes are announced in release notes. The API freezes at the **1.0** release.

**HTTP/3 is a young stack.** The RFC 9000–9002 + 9114 implementation is complete and handles real workloads — GET and POST/PUT both work end to end — but it hasn't seen the hardening the HTTP/1.1 and HTTP/2 paths have. Treat it as production-capable but new.

**Linux and macOS only.** Windows is cross-compile-only today: no IOCP backend, no `sendfile`. It's on the long-term roadmap but not part of the alpha.

**No QUIC 0-RTT / early data.** The handshake works and post-handshake throughput is competitive. Full 0-RTT adds replay protection and per-session token storage, deferred to a later release.

## Roadmap

| Milestone | What lands |
| --- | --- |
| **Alpha** (current) | Public API refinement based on feedback, HttpArena re-submissions across kernel/hardware variation, expanded examples. |
| **Beta** | API surface frozen, a PostgreSQL-backed REST benchmark added to HttpArena, long-form operational docs. |
| **1.0** | WebSocket *server* support, full QUIC 0-RTT / early data, security audit, a stable C ABI for embedding in non-Zig programs, and Windows support. |

## Related

- [Benchmarks](benchmarks.md) — where the implementation stands today.
- [Architecture](architecture.md) — the design these milestones build on.
