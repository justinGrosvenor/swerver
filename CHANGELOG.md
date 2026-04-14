# Changelog

## Unreleased — targeting `v0.1.0-alpha.1`

**Headline:** swerver is now consumable as a Zig package via `b.dependency` + `b.addModule`. HttpArena benchmark handlers decoupled out of the core server module into a standalone `examples/httparena/` downstream example. QUIC multi-range ACK encoding added for lossy-path throughput. 26 previously-invisible modules now analyzed by the test runner, which surfaced and fixed 8 latent bugs. Public API types have real doc comments. CI runs `test-matrix` on a native Linux runner. Release workflow publishes cross-platform binaries on tag push. No known bugs ship with the tag.

### Packaging
- `build.zig.zon` added (name, version, pinned Zig 0.16.0-dev.2135+7c0b42ba0, paths, empty dependencies) — swerver is now consumable as a Zig package via `b.dependency("swerver").module("swerver")`.
- `build.zig` swapped `b.createModule` → `b.addModule("swerver", …)` so downstream projects can actually import the library.

### JSON hygiene
- New `src/runtime/json_write.zig` with `writeEscaped`, a spec-complete RFC 8259 string escape (control chars as `\u00XX`, hand-rolled to avoid bufPrint error-set drift).
- `src/middleware/access_log.zig`: `formatJson` rewritten to use the shared helper and an offset-based bufPrint pattern (the old 1 KB `safe_path` buffer silently truncated long paths; bumped the output buffer to 4 KB).
- `src/middleware/observability.zig`: `formatJson` and `formatLogfmt` rewritten off the removed `std.io.fixedBufferStream` API onto the offset pattern; new `writeEscapedField` helper.
- `src/middleware/x402.zig`: payment header validation replaced with a typed `parseFromSliceLeaky` into `struct { signature, payload }` (was a fragile substring search for `"signature"`/`"payload"`).
- `src/server.zig`: `loadJsonDataset` converted to a typed `DatasetItem` struct + scoped `ArenaAllocator` (fixing a `page_allocator` leak) and split into a pure `renderJsonDataset` inner function with four unit tests.

### Stdlib 0.16-dev API catchups
- `src/runtime/clock.zig`: new `realtimeNanos() ?i128` wrapper, replacing the removed `std.time.nanoTimestamp()`.
- `src/middleware/observability.zig`: 3 `std.time.nanoTimestamp()` call sites migrated; `std.io.getStdErr().writeAll(output)` replaced with `std.posix.system.write(2, …)`.
- `src/middleware/ratelimit.zig`: 3 `std.time.nanoTimestamp()` call sites migrated; comptime branch-quota bumps for `RateLimiter.init` and `retry_after_strings`.
- `src/middleware/health.zig`, `src/middleware/ratelimit.zig`: removed dead `req.path orelse` / `if (req.path) |path|` paths — `req.path` is non-optional and has been for a while; both files had stale code from a prior refactor.

### Correctness
- `src/quic/sent_ring.zig`: `markAckedRange` now returns `AckResult { largest_sent_time, total_bytes }` so `markPacketsAcked` can feed exact acked-byte counts into the congestion controller instead of a `count × 1200` estimate.
- `src/quic/connection.zig`, `src/quic/frame.zig`, `src/quic/handler.zig`: **multi-range ACK encoding** for 1-RTT packets (RFC 9000 §19.3.1). New `frame.writeAckMultiRange` + `PacketNumberSpace.collectAckRanges` walk the 64-bit receive bitmap backward from `largest_received` and encode up to 32 disjoint ranges of received packets in a single ACK frame. Previously, lossy paths (gaps in the bitmap) forced the peer to retransmit everything below the first gap because we only emitted a single range. Five new unit tests cover single-range, one-gap, two-gaps, output-buffer-limit, and empty-out-delegation-to-firstAckRange. Initial / Handshake packets stay single-range — they rarely see loss.
- `src/middleware/middleware.zig`: fixed latent `std.time.nanoTimestamp()` use in `Context.generateRequestId` (found during the doc comment pass). Now uses `clock.realtimeNanos`. Another one of the bugs that was hiding in lazy-analyzed code — the method had no callers in the current tree, so it never tripped the compile.

### Library surface documentation
- Top-of-file `//!` module doc in `src/lib.zig` with a "Getting started" example, the full public-surface map (core, reverse proxy, config, benchmark helpers), and an explicit stability note about the alpha API surface.
- Doc comments on the public types the launch post encourages readers to open: `Server`, `ServerBuilder`, `Master`, `router.Router`, `router.HandlerContext`, `router.HandlerFn`, `router.RouteBuilder`, `router.GroupBuilder`, `router.RouterError`, `router.RouteResult`, `response.Response`, `response.Body`, `response.BodyType`, `response.Header`, `response.ManagedBody`, `response.ScatteredBody`, `request.RequestView`, `request.Method`, `request.Header`, `middleware.Chain`, `middleware.MiddlewareFn`, `middleware.PostResponseFn`, `middleware.Decision`, `middleware.Context`, `middleware.PreResult`. Each one gets the "what it is / how to use it / lifetime rules" treatment — IDE hover now returns a paragraph instead of a bare identifier.
- `middleware.zig` now has a proper top-level `//!` docblock explaining the pre/post chain design, the cross-protocol identity property, and the zero-allocation discipline.

### HttpArena subscription
- Added `json` to `httparena/meta.json` subscribed tests. The `/json` handler (already in `benchmark_routes.zig`) matches the HttpArena validator's requirements: 50 items, `count` field, `items[].total = price × quantity` rounded to 2 decimals, Content-Type `application/json`. `api-4` was originally queued alongside but scoped out — reading the HttpArena harness shows it's a composite test that requires PostgreSQL via `/async-db?min=X&max=Y`, which is new infrastructure rather than a new handler. See `known-issues-triage.md#3.3` for the written reason.

### Deferred to `v0.1.0-alpha.2`
Three items from the original alpha.1 grind list are explicitly scoped out of this tag with a written reason. None of them ship as silent omissions — each has a named target alpha and a concrete unblock condition:

- **2.1 Reverse proxy benchmarked at HttpArena-level load.** Needs real Linux bench hardware (the Docker Desktop 2-vCPU linuxkit VM can't simulate the 64-core HttpArena shape, and the proxy's failure modes under high concurrency only surface under load). Landing next weekend alongside 2.4 pipelined-512 + 1.2 static-h2 4xx. The alpha.1 README marks the proxy as "functional, benchmarked informally, not yet load-tested at HttpArena scale" — not "experimental."
- **2.11 HTTP/2 optimization pass.** Speculative hot-path rewrites without bench validation aren't worth the review time; this becomes a measure → optimize → re-measure loop once the Linux box is up. The alpha.1 tag ships with swerver at rank 5 on `baseline-h2` and acknowledges the gap directly rather than hiding it. Target for alpha.2: parity with actix / aspnet-minimal.
- **3.7 QUIC cipher suite negotiation (TLS_AES_256_GCM_SHA384 support).** The multi-range ACK half of 3.7 landed. The cipher half needs `Aes256Gcm` code paths in `protectPayload`/`unprotectPayload`, a `Keys.init256` + SHA-384 48-byte-secret `deriveKeysFromSecret` variant, runtime cipher detection via `SSL_get_current_cipher` plumbed from `tls/quic_session.zig` down to every key-derivation call site, and removal of the `setCiphersuites(ctx, "TLS_AES_128_GCM_SHA256")` pin in `tls/ffi.zig`. All four together is multi-day work with real risk of breaking the handshake against real clients, and testing requires a SHA-384-preferring QUIC client. AES-128-GCM is the universal baseline every mainstream QUIC client supports, so this is a feature-breadth gap, not a correctness loss. Revisits post-alpha.

The other Pass 3 items (1.1 upload re-bench, 1.2 static-h2 4xx, 2.4 pipelined-512) are also deferred to alpha.2 for the same reason — they need bench hardware. See `known-issues-triage.md` for the full list.

### Test surface expansion + bug catches
- `src/tests.zig`: structural fix, not a cosmetic one. Zig uses lazy analysis — modules that aren't `_ = module` in a comptime block are *completely invisible to the compiler*, which means bugs inside them go undetected until someone actually calls the affected code. This pass added 26 modules to the comptime list (`config`, `config_file`, `server_builder`, `router`, `middleware/middleware`, `middleware/health`, `middleware/ratelimit`, `middleware/security`, `runtime/clock`, `runtime/io`, `runtime/net`, `runtime/buffer_pool`, `runtime/connection`, `runtime/json_write`, `protocol/http1`, `protocol/http2`, `protocol/http3`, `protocol/huffman`, `protocol/request`, `response/response`, `tls/provider`, `quic/connection_pool`, `quic/connection`, `quic/handler`, `benchmark_routes`, and OS-gated backends `epoll` / `io_uring_native` / `kqueue`), and surfaced 8 latent bugs that had been invisible the entire time:
  - `health.zig` and `ratelimit.zig` had dead `req.path orelse` checks on a non-optional field — only catchable by analyzing those test files.
  - `observability.zig` had 3 `std.time.nanoTimestamp()` call sites plus `std.io.fixedBufferStream` / `std.io.getStdErr()` that wouldn't compile on current Zig — invisible because the module was never analyzed.
  - `ratelimit.zig` `RateLimiter.init` and `retry_after_strings` both blew the comptime branch quota when finally analyzed (required `@setEvalBranchQuota` bumps).
  - Multiple `RequestView{}` test literals were missing a `body` field that had been added in a prior refactor.
  - The stale "excluded because of TLS FFI" comment on `quic/connection`, `quic/handler`, and `protocol/http3` turned out to be wrong — OpenSSL is already linked in the test build, those modules compile fine.
  - The OS-gated split for `epoll`/`kqueue`/`io_uring_native` is documented in `CONTRIBUTING.md` to keep the pattern intact going forward.

## `v0.1.0-alpha.0` — 2026-04-12

HttpArena-internal reference tag, not a public release. Created to give the
HttpArena submission Dockerfile a stable pin while main continued to churn.
Not announced. The first public alpha will be `v0.1.0-alpha.1`.

Key changes since the previous dated entry:

- Separate buffer pool for upload body accumulation (32 × 1 MB body pool per worker, separate from the hot-path request/response pool) — fixes the 4.9 GiB memory exhaustion on the HttpArena upload test at 256 concurrent connections
- `io_uring_native` backend now handles TLS, QUIC, and async writes; default picker choice for non-TLS processes; default picker choice for TLS/QUIC too after a generation-counter bug fix
- Native io_uring backend wiring: heap-allocated `*IoUring` (fixes dangling pointer through `BufferGroup`), custom `.inc=false` provided-buffer ring management (bypasses stdlib's incremental consumption assumption), generation counter fired on connection release (prevents multishot recv CQEs leaking into reused slots)
- `SOCK_NONBLOCK | SOCK_CLOEXEC` passed to multishot accept
- Eliminated per-accept `setsockopt` + `getpeername` syscalls (TCP_NODELAY moved to the listener, getpeername gated on `self.proxy != null`)
- Native recv switched to single-shot to eliminate a mixed-workload race on the accept path
- HTTP/3 body dispatch via defer-until-FIN + zero-copy body path (PR A from `docs/design/8.0-h3-performance-plan.md`) — POST/PUT bodies now work end-to-end over h3 for the first time, verified against `curl --http3-only`
- HTTP/2 POST body dispatch for single-ingest-batch requests (adjacent fix caught during the PR A audit)
- `io_uring` `IORING_SETUP_SINGLE_ISSUER` + `IORING_SETUP_DEFER_TASKRUN` flags — 7× per-core throughput unlock on the HttpArena baseline benchmark (420K → 2.94M req/s at 64-core saturation)
- HttpArena production-tier compliance: removed `disable_middleware` from benchmark configs, removed pre-encoded cache entries for specific benchmark URLs
- Pre-encoded response cache for h1 and h2 hot static endpoints
- TLS for TCP connections (HTTPS for HTTP/1.1 and HTTP/2):
  - `--cert` / `--key` CLI flags and `tls` config section
  - Non-blocking TLS handshake with automatic HTTP/2 upgrade via ALPN
  - TLS-aware read/write path (SSL_read/SSL_write), plain TCP retains writev
  - SIGPIPE ignored for clean TLS connection teardown
- Fix HTTP/2 response headers sent with mixed case (RFC 9113 §8.2 requires lowercase)
- Fix edge-triggered epoll not flushing h2 responses queued during read dispatch
- Fix edge-triggered epoll dropping pending TCP connections (drain accept queue in loop)
- Fix h2 ingest stranding frames when 16-slot frames buffer fills mid-batch
- Fix TLS read path stranding data in OpenSSL's internal buffer (drain until WouldBlock — epoll's edge-triggered mode can't signal SSL-layer buffering)
- Fix SSL_read error handling: ret=0 now distinguishes close_notify from transient errors via SSL_get_error (was incorrectly treating WANT_READ as EOF)
- Set TCP_NODELAY on accepted sockets (eliminates 40ms Nagle delay for h2 multi-frame writes)
- Increase per-connection write queue from 32 to 128 entries for h2 multiplexing
- Streaming request body support (bodies up to 8MB via buffer accumulation)
- Buffer size increased from 16 KB to 64 KB
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
