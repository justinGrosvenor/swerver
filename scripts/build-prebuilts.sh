#!/bin/bash
# Build the per-platform prebuilt packages consumed by swerverts. Each
# @swerver/<os>-<arch> package holds the swerver binary and libswerver for one
# platform and is published so swerverts can list them as optionalDependencies
# (npm/bun install only the one matching the host, esbuild/@swc style).
#
# Usage: VERSION=0.1.0 scripts/build-prebuilts.sh
# Output: dist/npm/<os>-<arch>/ (package.json + swerver + libswerver.*)
set -euo pipefail

ZIG="${ZIG:-$HOME/Library/zig/0.16.0/zig}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo 0.0.0)}"
OUT="$ROOT/dist/npm"
command -v "$ZIG" >/dev/null || { echo "zig not found at $ZIG (set ZIG=...)"; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"

# node-os  node-cpu  zig-target          lib-file
TARGETS=(
  "darwin arm64 aarch64-macos     libswerver.dylib"
  "darwin x64   x86_64-macos      libswerver.dylib"
  "linux  arm64 aarch64-linux-gnu libswerver.so"
  "linux  x64   x86_64-linux-gnu  libswerver.so"
)

for t in "${TARGETS[@]}"; do
  read -r OS CPU ZT LIB <<<"$t"
  echo "==> @swerver/$OS-$CPU  ($ZT)  v$VERSION"
  ( cd "$ROOT" && "$ZIG" build -Dtarget="$ZT" >/dev/null && "$ZIG" build lib -Dtarget="$ZT" >/dev/null )
  PKG="$OUT/$OS-$CPU"
  mkdir -p "$PKG"
  cp "$ROOT/zig-out/bin/swerver" "$PKG/swerver"
  cp "$ROOT/zig-out/lib/$LIB" "$PKG/$LIB"
  chmod +x "$PKG/swerver"
  cat > "$PKG/package.json" <<JSON
{
  "name": "@swerver/$OS-$CPU",
  "version": "$VERSION",
  "description": "Prebuilt swerver engine (binary + libswerver) for $OS-$CPU.",
  "os": ["$OS"],
  "cpu": ["$CPU"],
  "files": ["swerver", "$LIB"],
  "license": "MIT",
  "repository": "github:justingrosvenor/swerver"
}
JSON
  echo "    -> $PKG ($(du -h "$PKG/swerver" | cut -f1) bin, $(du -h "$PKG/$LIB" | cut -f1) lib)"
done

echo "prebuilts written to $OUT (publish each with: cd <dir> && npm publish --access public)"
