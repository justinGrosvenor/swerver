# Vendored wasm3

Upstream: https://github.com/wasm3/wasm3 tag **v0.5.0** (the last tagged release;
project is in minimal-maintenance mode but the interpreter is stable). Pulled
for swerver's WASM edge functions (design 10.0). Only `source/*.c` and
`source/*.h` are vendored; `m3_api_uvwasi.c` is dropped (needs the external
uvwasi lib). The build compiles the 13 core translation units (see `build.zig`,
`WASM3_FILES`); the WASI/tracer/meta API bindings are intentionally not
compiled (a sandboxed filter has no ambient syscall surface).

## swerver patches (kept minimal and clearly marked)

All edits are tagged `swerver FUEL PATCH` in-source. Total surface: two new
globals, one include, one `if`.

1. **`source/m3_fuel.h`** (new file) — externs for the fuel counter and trap
   message.

2. **`source/m3_core.c`** — defines `int64_t m3_swerver_fuel = INT64_MAX;` and
   `const char* const m3Err_trapFuel`.

3. **`source/m3_exec.h`** — `#include "m3_fuel.h"`, and in `op_Loop`'s back-edge
   `do { ... } while (r == _pc)` loop, charge one fuel unit per iteration:
   `if (M3_UNLIKELY (--m3_swerver_fuel < 0)) { newTrap (m3Err_trapFuel); }`.
   This is the only per-iteration cost; measured overhead is within noise
   (~0.5 ns/op on the Phase 0 filter).

Why a source patch: upstream wasm3 has no fuel/op-count metering and is frozen,
so the diff will not bitrot. The single-threaded reactor makes interruption
mandatory (a runaway filter wedges the worker, and a tick-based deadline cannot
fire while the guest spins). Process-global is correct because swerver runs one
single-threaded worker per process.

## macOS build shim

`shim/endian.h` satisfies Zig's `@cImport` (aro translate-c), which does not
take wasm3_defs.h's clang `bswap` branch and falls through to `<endian.h>`
(absent on macOS). The actual `.c` files compile via `zig cc` (clang) and never
include it. Searched after `source/`; harmless to the real compile.
