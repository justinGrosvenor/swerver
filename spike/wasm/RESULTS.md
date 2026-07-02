# WASM Edge Functions — Phase 0 Spike Results

Status: complete (2026-06-27). Decision spike for design 10.0 (`docs/design/10.0-edge-functions.md`).

This is the single go/no-go measurement the design calls for, plus the runtime
choice (open question #1) collapsed into the same spike. Throwaway code; the
whole thing lives under `spike/wasm/` and deletes cleanly.

## TL;DR

- **GO on feasibility.** Both candidate interpreters clear the design bar (a
  trivial filter must approach single-digit microseconds) by a wide margin: the
  representative filter runs in **54 ns (wasm3)** / **167 ns (zware)** per
  invocation, vs a 1000 ns bar. The actual Phase 1 build stays demand-gated per
  the spec; this only says the mechanism is viable.
- **Runtime recommendation: wasm3.** This is the non-obvious call. The
  ethos-instinct pick is zware (pure Zig), but its headline advantage turns out
  to be illusory and it carries a hidden recurring tax. See "The decision" below.

## What was built

| Piece | File |
|---|---|
| Filter (Zig -> wasm32-freestanding), same bytes for both runtimes | `filter/filter.zig` (396-byte .wasm) |
| Native-Zig baseline (identical logic, no runtime boundary) | `src/native_baseline.zig` |
| wasm3 wrapper (vendored C, v0.5.0) | `src/runtime_wasm3.zig` |
| zware wrapper (pure-Zig, pinned commit `8384227`) | `src/runtime_zware.zig` |
| In-process ns/op harness + correctness gate + fuel demo | `src/main.zig` |
| Self-contained build (own build.zig/.zon, no touch to main tree) | `build.zig`, `build.zig.zon` |

The filter is representative, not a toy: it checks the request path prefix AND
reads one header by name (`x-api-key`), returning an allow/reject Decision —
the "read only what you touch, on demand" pattern the design's ABI is built
around. All three implementations are verified to return identical decisions on
every request shape before timing.

## Performance (10M iterations, ReleaseFast)

macOS (Apple Silicon, native build), stable across runs:

| impl   | ns/op | vs native | notes |
|--------|------:|----------:|-------|
| native | ~3    | 1x        | near the timer floor; baseline only |
| wasm3  | ~54   | ~15-20x   | rock-stable 54.0-54.8 across runs |
| zware  | ~167  | ~45-70x   | rock-stable 166.7-168.4 across runs |

- **wasm3 is ~3.1x faster than zware.** Both are interpreters; wasm3's
  threaded-code C core genuinely out-dispatches zware's pure-Zig tail-call loop.
- The `vs native` multiple swings only because native is at the measurement
  floor (2-4 ns); trust the absolute interpreter ns/op, which is stable.
- Fairness caveats (both favor closing the gap, neither does materially):
  - zware's `invoke` does a per-call export-name lookup (1-2 `mem.eql`); wasm3
    pre-resolved its function pointer once. Negligible (a few ns), does not
    explain a 113 ns gap.
  - zware rebuilds VM operand/frame/label stacks per call ON THE STACK (zero
    heap alloc, matching the spec requirement); sized down to 64 operands so the
    default 8 KB zeroing does not penalize it. This is zware measured at its best.

## Resource bounding (the security-critical dimension)

The design calls interruption *mandatory*: the single-threaded reactor means a
runaway filter wedges the whole worker, and a housekeeping-tick deadline CANNOT
save you (the tick never runs while the guest spins). Only in-interpreter
preemption works. **Neither runtime ships fuel/op-count metering.** This was the
load-bearing unknown.

- **wasm3: solved, proven, and free.** A ~5-line patch to `op_Loop`'s back-edge
  (`vendor/wasm3/source/m3_exec.h`) charges one fuel unit per loop iteration and
  traps on exhaustion. Empirically interrupts an infinite `spin()` guest:
  `spin() with 100000 fuel -> TRAPPED (interrupted)`. Overhead on the normal
  filter is within noise (53.8 ns unpatched -> 54.3 ns patched). The patch is a
  diff against frozen vendored source, so it will not bitrot.
- **zware: harder.** Its only per-instruction chokepoint is the `inline fn
  dispatch` (each opcode handler tail-calls it). A fuel charge there is possible
  but (a) inlines into every handler -> per-instruction cost on the whole
  interpreter, heavier than wasm3's loop-only charge, and (b) is a fork of an
  actively-moving alpha codebase. Not demonstrated; calling `spin()` on zware
  would simply hang, so the harness does not invoke it.

## Build posture — the spec's central objection, tested

The design leans zware partly because "wasm3 ... kills the cross-compiled
static-binary posture." **This is empirically false for wasm3.**

- The full harness (vendored wasm3 C + zware + libc via `c_allocator`)
  cross-compiles to `x86_64-linux-musl` and produces a **statically linked**
  ELF (`file` reports "statically linked"). wasm3 needs libc, but static musl
  satisfies that and the result is still a single static binary.
- The thing that actually breaks the static-binary posture is **wasmtime** (JIT,
  dynamic, W^X executable memory), which this spike correctly never considered.
- One real wrinkle found: Zig's `@cImport` (aro translate-c) does not take
  wasm3_defs.h's clang `bswap` branch and falls through to `<endian.h>`, absent
  on macOS. Fixed with a 10-line shim header (`vendor/wasm3/shim/endian.h`); the
  actual `.c` files compile fine via `zig cc`. Trivial, documented.

## Zig 0.16.0 compatibility

- **zware:** builds on 0.16.0 only as of community port commit `8384227`
  (PR #242, 2026-06-21 — six days before this spike). Its README still claims
  Zig 0.15.1. **This is the key liability:** zware couples to the Zig version and
  broke on the 0.16 upgrade until a third party re-ported it. swerver already
  fights 0.16 std API churn constantly; adopting zware means every future Zig
  upgrade can block on an alpha project's re-port.
- **wasm3:** C source, immune to Zig std/version churn entirely. Compiles
  unchanged.

## The decision

| Dimension | wasm3 | zware |
|---|---|---|
| Filter ns/op | **54** | 167 (3.1x slower) |
| Clears 1µs bar | yes (~18x margin) | yes (~6x margin) |
| Resource bounding | **proven**, ~5-line loop patch, ~0 overhead | needs forking inline dispatch, per-instruction cost, unproven |
| Single static binary | **preserved** (static musl proven) | preserved |
| Zig-version coupling | **none** (frozen C) | high (broke on 0.16, alpha, re-ported days ago) |
| Upstream | dormant since 2021 (stable, merges PRs) | active but alpha, no benchmarks, SIMD WIP |
| In-tree cost | first vendored C dep + libc + carry fuel patch | pure Zig, no C |

**Recommendation: wasm3.** The pure-Zig instinct (zware) is the trap here. Its
one decisive-looking advantage — preserving the single static binary — is
illusory, because wasm3 preserves it too (proven above). What remains is: wasm3
is 3x faster, has a proven and nearly-free resource-bounding story, and is immune
to Zig-version churn; zware is slower, alpha, has a heavier/unproven fuel path,
and adds a recurring re-port tax on every Zig upgrade to a project that already
spends real effort tracking Zig stable.

The price of wasm3 is honest and small: it is the first vendored C in the tree
(libc-only, ~64 KB documented code footprint, upstream `build.zig` blesses the
`addCSourceFiles` path), and Phase 1 must carry the ~5-line fuel patch against
frozen source. Both are acceptable for a security-critical hot-path component.

Pick zware only if "zero C in the codebase, ever" is a hard non-negotiable line —
in which case accept 3x perf, own the dispatch fuel fork, and budget for
re-pinning zware on every Zig upgrade.

## If Phase 1 proceeds (not now — demand-gated)

1. Vendor wasm3 properly (the 13 core `.c` files used here; keep the endian shim
   and the fuel patch as clearly-marked diffs).
2. Make fuel thread-local (or hang it off runtime userdata) instead of the
   single global used here.
3. Add the wall-clock deadline (housekeeping tick) and linear-memory cap on top
   of fuel — fuel handles compute, the deadline backstops host-call stalls.
4. Build the per-worker instance pool (mirror the PG slot pool) and the real ABI
   against the middleware `Decision` union.
5. Port the resource-bounding tests from the design's test plan; they gate
   shippability.

## Reproduce

```
cd spike/wasm
~/Library/zig/0.16.0/zig build --release=fast && ./zig-out/bin/wasm-spike
# static-binary check:
~/Library/zig/0.16.0/zig build --release=fast -Dtarget=x86_64-linux-musl
file zig-out/bin/wasm-spike   # -> "statically linked"
```
