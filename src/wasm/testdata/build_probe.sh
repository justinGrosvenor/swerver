#!/bin/sh
# Regenerate probe.wasm from probe.zig. Committed as a binary test fixture so
# the test suite does not need a wasm cross-build step.
set -e
cd "$(dirname "$0")"
ZIG="${ZIG:-$HOME/Library/zig/0.16.0/zig}"
# -mcpu=mvp is REQUIRED on every filter build: Zig's default wasm CPU enables
# reference_types, which the vendored wasm3 cannot compile (loads fail with an
# opaque FunctionNotFound).
for m in probe filter_probe response_probe; do
    "$ZIG" build-exe "$m.zig" -target wasm32-freestanding -mcpu=mvp -fno-entry -rdynamic \
        -OReleaseSmall -femit-bin="$m.wasm"
    echo "wrote $m.wasm ($(wc -c < "$m.wasm") bytes)"
done

# The ABI conformance fixture: the canonical examples/wasm_filter SDK example,
# built through abi.zig. -mcpu=mvp is REQUIRED (wasm3 cannot compile the default
# reference_types). The abi-example load test loads this and fails if any abi.zig
# signature drifts from the host linkAbi. Rebuild this when linkAbi changes.
"$ZIG" build-exe ../../../examples/wasm_filter/example_filter.zig \
    -target wasm32-freestanding -mcpu=mvp -fno-entry -rdynamic \
    -OReleaseSmall -femit-bin=abi_example_filter.wasm
echo "wrote abi_example_filter.wasm ($(wc -c < abi_example_filter.wasm) bytes)"
