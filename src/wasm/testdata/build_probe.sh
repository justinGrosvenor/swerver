#!/bin/sh
# Regenerate probe.wasm from probe.zig. Committed as a binary test fixture so
# the test suite does not need a wasm cross-build step.
set -e
cd "$(dirname "$0")"
ZIG="${ZIG:-$HOME/Library/zig/0.16.0/zig}"
for m in probe filter_probe response_probe; do
    "$ZIG" build-exe "$m.zig" -target wasm32-freestanding -fno-entry -rdynamic \
        -OReleaseSmall -femit-bin="$m.wasm"
    echo "wrote $m.wasm ($(wc -c < "$m.wasm") bytes)"
done
