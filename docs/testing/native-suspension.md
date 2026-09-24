# Native handler suspension validation

Implemented on `feat/handler-suspension`, based on `af272be` (alpha.32).

The implementation follows four steps:

1. Add a lazy, bounded registry with generation tokens, an indexed deadline heap,
   and per-connection cancellation lists.
2. Expose timers and explicit completion through the same typed continuation API.
   Capture request metadata only when a handler actually suspends.
3. Integrate delivery and cancellation with HTTP/1.1, HTTP/2, and HTTP/3, preserving
   response finalization and pipeline/stream behavior.
4. Verify lifecycle failures, concurrent traffic, feature combinations, and the
   synchronous path. Provide a runnable example and usage guide.

## Correctness

`zig build test-matrix test-matrix-h3 check --summary all` passed all 32 build
steps: 5,880 passing test executions, 392 skips, across eight feature combinations.
The new tests cover 32,000 shuffled waits, capacity exhaustion, slot reuse,
duplicate/late completion, no early timers, allocation failures, cancellation
reentrancy, metadata ownership, chained waits at capacity one, abandoned waits,
HTTP/3 reset/cancellation with full-width stream IDs, and an empty writable
queue while a `Connection: close` request is still suspended.

`zig build check` passed all 16 steps. `zig build -Doptimize=ReleaseFast` and
the strict MkDocs build passed. The async example cross-compiles for both
`x86_64-linux-gnu` and `aarch64-linux-gnu`.

On macOS/kqueue, `examples/async/test.py` passed:

- 0, 10, and 500 ms delays; prompt idle delivery; 32 different overlapping waits.
- 512 concurrent delayed HTTP/1.1 requests on one worker.
- Ready traffic during a wait, explicit completion, timeout, chained waits,
  persistent/pipelined requests, and prompt cleanup on disconnect.
- HTTP/2 sibling progress, chained waits, and per-stream reset cancellation.

The same live suite passed on Linux/epoll in an ARM64 Debian container using
ReleaseFast, including all 512 close-mode requests. Native io_uring was not
exercised. Cross-compiled Debug executables closed connections in this Docker
setup; that behavior also reproduced with the untouched alpha.32 embedded
example. Linux runtime validation used the optimized executable.

HTTP/3 has in-process integration coverage in the feature matrix; a real QUIC
client was not used for this change.

## Synchronous throughput smoke check

Compare alpha.32 and the changed embedded example in ReleaseFast on the same
Apple M4 Max, one server process at a time. Each run used a two-second warmup,
then `wrk -t4 -c128 -d10s http://127.0.0.1:8080/api/hello`. Order was baseline,
current, current, baseline, baseline, current. No socket errors or non-2xx
responses occurred.

| Build | Requests/second, three runs | Median |
| --- | --- | --- |
| alpha.32 | 251,053; 217,127; 250,574 | 250,574 |
| suspension | 246,546; 233,984; 242,385 | 242,385 |

The changed median was 3.3% lower. Variation within each build was substantial;
this is a local smoke check, not evidence of a precise regression size or an
HttpArena result. Connection layout and configured buffer sizes are unchanged.
