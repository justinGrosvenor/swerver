#!/bin/sh
# Phase 0 spike build. Requires wasm3 cloned to /tmp/wasm3 (see SPIKE.md).
set -e
ZIG="${ZIG:-$HOME/Library/zig/0.16.0/zig}"
"$ZIG" build-exe filter.zig -target wasm32-freestanding -fno-entry -rdynamic -OReleaseFast --name filter
"$ZIG" build-exe bench.zig /tmp/wasm3/source/*.c -I/tmp/wasm3/source -lc -OReleaseFast --name bench
./bench
