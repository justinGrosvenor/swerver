# Fuzz Testing (#26)

We ship a simple fuzz harness that exercises the HTTP/1.1 parser to uncover framing or header parsing bugs before they reach production. The harness uses Zig's native fuzz runner so there are no external dependencies.

## Running

```sh
zig build fuzz
```

This builds and runs `fuzz/http1_parser.zig`, which feeds random byte buffers into `src/protocol/http1.zig::parse` with conservative limits (`8K` headers, `32K` body, 128 header slots). Zig's fuzz driver will keep iterating until it either finds a crash or is interrupted.

The harness is wired via `build.zig` so it respects `-Doptimize`, `-Denable-tls`, and other options; just pass them through the CLI the same way you do for `zig build test`.

## Goals

- Validate chunked decoding + trailer validation against malformed data.
- Ensure absolute-form, authority-form, and Expect/Connection semantics cannot panic.
- Catch unwanted heap allocations or buffer overruns by replaying interesting inputs generated during fuzz runs.
