#!/bin/sh
# Wipe .zig-cache once it grows past a size threshold.
#
# Zig never garbage-collects its local cache: every edit-and-rebuild leaves a
# new ~20MB output directory under .zig-cache/o (test binaries, *_zcu.o
# objects, one set per test-matrix variant). Left alone it reaches tens of GB.
# Outputs in .zig-cache/o are referenced by manifests in .zig-cache/h, so the
# only safe prune is the whole directory; a cold rebuild is cheap.
#
# Usage: scripts/prune-zig-cache.sh [-q]
#   ZIG_CACHE_LIMIT_GB   threshold in GB (default 10)
#   -q                   quiet unless something is deleted
set -eu

quiet=0
[ "${1:-}" = "-q" ] && quiet=1

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cache="$root/.zig-cache"
limit_gb=${ZIG_CACHE_LIMIT_GB:-10}

[ -d "$cache" ] || exit 0

# Never yank the cache out from under a running build.
if pgrep -x zig >/dev/null 2>&1; then
    [ $quiet -eq 1 ] || echo "prune-zig-cache: zig is running, skipping"
    exit 0
fi

size_kb=$(du -sk "$cache" | cut -f1)
size_gb=$((size_kb / 1024 / 1024))

if [ "$size_kb" -lt $((limit_gb * 1024 * 1024)) ]; then
    [ $quiet -eq 1 ] || echo "prune-zig-cache: $cache is ${size_gb}G (limit ${limit_gb}G), keeping"
    exit 0
fi

echo "prune-zig-cache: $cache is ${size_gb}G (limit ${limit_gb}G), removing"
rm -rf "$cache"
