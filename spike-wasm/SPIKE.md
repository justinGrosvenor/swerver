# Edge Functions Phase 0 Spike (design 10.0)

**Question:** is an interpreted WASM filter fast enough to run on the request
hot path, or does Tier-1 edge functions need a JIT (wasmtime) and its weight?

**Answer: GO with an interpreter.** wasm3 invocation overhead is far below the
noise floor of any route that would carry a user filter. No wasmtime needed.

## Numbers (Apple M4 Max, ReleaseFast, 5M iterations, two runs)

| Path | ns/op |
|---|---|
| wasm bare invocation (`noop`) | ~6-9 |
| wasm realistic filter (invoke + read linear memory + 11-byte API-key scan + get result) | ~26 |
| native equivalent (optimizer-resistant byte compare) | ~0.25 |

The ~26ns realistic filter means ~38M filter calls/sec/core: faster than
swerver's per-core request rate on every workload except pipelined-plaintext,
and edge functions only run on routes that opt in (which by definition do real
work: auth, a backend, a DB, or a Nether guest). The interpreter is not the
bottleneck.

## Runtime decision: wasm3 (vendored C), not zware

- **zware (pure-Zig, the ethos pick) does NOT build on Zig 0.16.0.** Its
  `build.zig` calls `b.modules.put(key, value)` (2-arg) but 0.16's
  `ArrayHashMap.put` now requires the allocator (`put(self, gpa, key, value)`).
  It targets an older Zig; adopting it means a maintained fork chasing every
  Zig release. Revisit only if/when it gains 0.16 support.
- **wasm3 builds trivially** (15 C files, ~10K LOC, clean `wasm3.h`), the C ABI
  is version-stable across Zig upgrades, and it is the fast-interpreter
  reference. It would be swerver's first vendored C dependency (today only
  OpenSSL/zlib are linked, none vendored) - an acceptable, contained cost.

## What this spike did NOT measure (deferred to later phases)

- Instance acquire/release from a per-worker pool (Phase 1).
- Host-call + park-and-resume overhead (Phase 3).
- Request-body materialization, the real zero-copy tax (Phase 2).
- Module parse/load cost (one-time per worker at config time, not per request).
- A Linux x86 number: this is M4 Max. The c7i (Sapphire Rapids) bench box would
  be ~1.5-2x slower per op (~40-50ns realistic) - still trivial; the GO does not
  flip. Rerun on the bench box before Phase 1 commits.

## Reproduce

```sh
# 1. wasm3 source (vendor it for real; cloned to /tmp for the spike)
git clone --depth 1 https://github.com/wasm3/wasm3 /tmp/wasm3

# 2. build the filter (Zig -> wasm; no wat toolchain needed)
~/Library/zig/0.16.0/zig build-exe filter.zig -target wasm32-freestanding \
    -fno-entry -rdynamic -OReleaseFast --name filter

# 3. build + run the harness (links wasm3 C sources)
~/Library/zig/0.16.0/zig build-exe bench.zig /tmp/wasm3/source/*.c \
    -I/tmp/wasm3/source -lc -OReleaseFast --name bench
./bench
```
