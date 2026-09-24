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

# Zig target triple for this build host. The target that matches it must be
# built WITHOUT -Dtarget: an explicit -Dtarget puts Zig in cross mode and drops
# the host's system library search paths, so the native build (which defaults
# enable_compression=is_native and thus links system zlib) fails to find -lz.
# The host build keeps those paths, links zlib, and ships with compression.
case "$(uname -m)" in arm64 | aarch64) HOST_ARCH=aarch64 ;; x86_64 | amd64) HOST_ARCH=x86_64 ;; *) HOST_ARCH=unknown ;; esac
case "$(uname -s)" in Darwin) HOST_OS=macos ;; Linux) HOST_OS=linux-gnu ;; *) HOST_OS=unknown ;; esac
HOST_ZT="$HOST_ARCH-$HOST_OS"
echo "host target: $HOST_ZT"

for t in "${TARGETS[@]}"; do
  read -r OS CPU ZT LIB <<<"$t"
  echo "==> @swerver/$OS-$CPU  ($ZT)  v$VERSION"
  # Prebuilts ship optimized: standardOptimizeOption defaults to Debug, which
  # would make the "prebuilt engine" both huge and slow.
  # Native target: no -Dtarget (see HOST_ZT note above). Cross targets pass it.
  if [ "$ZT" = "$HOST_ZT" ]; then
    TARGET_ARGS=(-Doptimize=ReleaseFast)
  else
    TARGET_ARGS=(-Dtarget="$ZT" -Doptimize=ReleaseFast)
  fi
  # A cross target can still be unbuildable from this host (e.g. a macOS target
  # from a different arch, where libswerver would need system zlib Zig can't
  # resolve for a foreign macOS target). Skip that platform rather than aborting
  # the whole run so the buildable targets still publish. zig's own errors stay
  # on stderr for diagnosis; only the build summary is suppressed.
  if ! ( cd "$ROOT" && "$ZIG" build "${TARGET_ARGS[@]}" >/dev/null && "$ZIG" build lib "${TARGET_ARGS[@]}" >/dev/null ); then
    echo "    !! build failed for $OS-$CPU ($ZT); skipping this platform" >&2
    continue
  fi
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
