# Authoring a swerver WASM edge filter

A filter is a tiny `wasm32-freestanding` module that swerver runs at the edge to
allow / reject / modify a request (and optionally call a Tier-2 sandbox). This
directory is the SDK: `abi.zig` is the canonical host-ABI binding you `@import`
instead of hand-declaring `extern "env"` functions.

## Why abi.zig

Hand-copying the host imports is the #1 authoring footgun: a wrong signature
compiles fine but fails the **host** at load with an opaque `LinkFunction` error,
and the per-import boilerplate (17 externs + the decision constants) is easy to
get subtly wrong. `abi.zig` ships the verified signatures plus safe helper
wrappers that handle the clamp-the-true-length details for you. Its signatures
are checked against the host's `linkAbi` by a conformance test
(`src/wasm/filter.zig` "D2: abi.zig SDK example links ..."), so they cannot
silently drift.

## Minimal filter

```zig
const abi = @import("abi.zig");
const std = @import("std");

var path_buf: [1024]u8 = undefined;
var tok_buf: [512]u8 = undefined;

export fn on_request() i32 {
    const p = abi.path(&path_buf);
    if (!std.mem.startsWith(u8, p, "/secure")) return abi.ALLOW;
    if (abi.header("authorization", &tok_buf).len == 0) {
        abi.respond(401, "missing credential");
        return abi.REJECT;
    }
    return abi.ALLOW;
}
```

See `example_filter.zig` here for a fuller example (auth gate + response-header
injection + a Tier-2 `host_call`) that also exercises the whole ABI surface.

## Build

```sh
zig build-exe my_filter.zig -target wasm32-freestanding -mcpu=mvp \
    -fno-entry -rdynamic -OReleaseSmall -femit-bin=my_filter.wasm
```

`-mcpu=mvp` is **required**. Zig's default `wasm32-freestanding` CPU enables
`reference_types`, which the vendored wasm3 cannot compile -- the module then
fails to load with an opaque `FunctionNotFound: on_request`. `-mcpu=mvp` strips
it. (Ordinary `@memcpy` / `std.fmt` are fine under `-mcpu=mvp`.)

## Exports the host calls

- `export fn on_request() i32` -- required. Return a decision code:
  `abi.ALLOW` (0), `abi.REJECT` (1, serves your staged `respond`),
  `abi.MODIFY` (2, applies staged response headers), `abi.PARKED` (3, after a
  successful `abi.hostCall`).
- `export fn on_resume() i32` -- only if you `hostCall`/park. Read the Tier-2
  result with `abi.callResult(buf)`, then return a terminal decision.
- `export fn on_response() i32` -- optional. Edit the outgoing response
  (`abi.setResponseStatus`, `abi.setResponseHeader`, `abi.replaceResponseBody`);
  return 0 to apply the edits.

## Sharp edges abi.zig does / doesn't paper over

- **Handled:** the "host returns the TRUE length, clamp before slicing" trap --
  every `abi.path/header/readBody/callResult/...` returns an already-clamped
  slice.
- **Not (yet) hidden:**
  - `abi.header(...)` returns an empty slice for BOTH an absent and a
    present-but-empty header (the host cannot distinguish them yet).
  - `abi.logMsg` is dropped in release host builds -- a dev aid only.
  - `abi.respond` / `abi.setResponseHeader` truncate / drop silently past the
    host caps; `abi.hostCall` / `abi.replaceResponseBody` return `false` on
    overflow (check them).
  - A filter is STATELESS per request but instances are pooled and reused:
    a module-level `var` persists across requests. Do not stash per-request state
    in globals.

## Keeping the binding honest

`abi.zig` is verified by building `example_filter.zig` through it into
`src/wasm/testdata/abi_example_filter.wasm` (via `testdata/build_probe.sh`) and
loading that in the conformance test. If you change the host ABI (`linkAbi`),
rerun `build_probe.sh` and the test will confirm the binding still matches.
