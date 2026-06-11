#!/bin/bash
# Precompressed static serving + in-memory static cache regression test.
#
# Verifies that the static file path serves a `.br`/`.gz` sibling when the
# client's Accept-Encoding allows it, with correct Content-Encoding + Vary
# headers, a Content-Type derived from the ORIGINAL path (never the .br/.gz
# suffix), byte-identical bodies, q=0 refusal, identity fallback when no
# sibling exists, and correct HEAD framing.
#
# The full matrix runs twice: with cache_static_files OFF and ON, so the
# in-memory cache must produce byte-identical results. Two extra cache-only
# checks assert hit consistency and a fresh (per-response) Date header.
#
# Usage: ./scripts/test-static-precompressed.sh  (builds + starts the server)
set -euo pipefail

cd "$(dirname "$0")/.."

PORT=18943
TMPDIR=$(mktemp -d)
SERVER_PID=""
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

# Static root: app.js with distinct .br/.gz siblings (distinct contents so we
# can prove WHICH file was served), and plain.txt with no siblings.
mkdir -p "$TMPDIR/static"
printf 'console.log("identity");' > "$TMPDIR/static/app.js"
printf 'BROTLI-BYTES-app.js'      > "$TMPDIR/static/app.js.br"
printf 'GZIP-BYTES-app.js'        > "$TMPDIR/static/app.js.gz"
printf 'no siblings here'         > "$TMPDIR/static/plain.txt"

zig build >/dev/null

BASE="http://127.0.0.1:$PORT/static"
PASS=0
FAIL=0

start_server() { # <cache:true|false>
    cat > "$TMPDIR/config.json" <<EOF
{
  "server": {
    "address": "127.0.0.1",
    "port": $PORT,
    "workers": 1,
    "static_root": "$TMPDIR/static",
    "cache_static_files": $1
  }
}
EOF
    ./zig-out/bin/swerver --config "$TMPDIR/config.json" &
    SERVER_PID=$!
    for i in $(seq 1 50); do
        if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/health"; then return; fi
        sleep 0.1
        if [ "$i" = 50 ]; then echo "FAIL: server did not start"; exit 1; fi
    done
}
stop_server() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; }

# fetch <name> <accept-encoding> <method> -> writes headers to $TMPDIR/h, body to $TMPDIR/b
fetch() {
    local path="$1" ae="$2" method="${3:-GET}"
    : > "$TMPDIR/b"
    if [ "$method" = "HEAD" ]; then
        # --head is curl's proper HEAD mode: it does not wait for a body
        # (plain `-X HEAD` makes curl expect one and errors with exit 18).
        curl -s -D "$TMPDIR/h" -o /dev/null --head \
            ${ae:+-H "Accept-Encoding: $ae"} "$BASE/$path"
    else
        curl -s -D "$TMPDIR/h" -o "$TMPDIR/b" -X "$method" \
            ${ae:+-H "Accept-Encoding: $ae"} "$BASE/$path"
    fi
}

check_header()    { if grep -qiE "$1" "$TMPDIR/h"; then echo "  ok: $2"; PASS=$((PASS+1)); else echo "  FAIL: $2"; cat "$TMPDIR/h"; FAIL=$((FAIL+1)); fi; }
check_no_header() { if grep -qiE "$1" "$TMPDIR/h"; then echo "  FAIL: $2 (present)"; cat "$TMPDIR/h"; FAIL=$((FAIL+1)); else echo "  ok: $2"; PASS=$((PASS+1)); fi; }
check_body_matches() { if cmp -s "$TMPDIR/b" "$1"; then echo "  ok: $2"; PASS=$((PASS+1)); else echo "  FAIL: $2 (body mismatch)"; FAIL=$((FAIL+1)); fi; }

run_suite() { # <mode-label>
    echo "[1/$1] Accept-Encoding: br  -> serves .br"
    fetch app.js "br"
    check_header   "^HTTP/1.1 200" "200 OK"
    check_header   "content-encoding: *br" "Content-Encoding: br"
    check_header   "vary: *accept-encoding" "Vary: Accept-Encoding"
    check_header   "content-type: *application/javascript" "Content-Type from original path"
    check_body_matches "$TMPDIR/static/app.js.br" "body is the .br sibling"

    echo "[2/$1] Accept-Encoding: gzip -> serves .gz"
    fetch app.js "gzip"
    check_header   "content-encoding: *gzip" "Content-Encoding: gzip"
    check_body_matches "$TMPDIR/static/app.js.gz" "body is the .gz sibling"

    echo "[3/$1] Accept-Encoding: br, gzip -> prefers br"
    fetch app.js "br, gzip"
    check_header   "content-encoding: *br" "br preferred over gzip"
    check_body_matches "$TMPDIR/static/app.js.br" "body is the .br sibling"

    echo "[4/$1] Accept-Encoding: br;q=0, gzip -> br refused, serves gzip"
    fetch app.js "br;q=0, gzip"
    check_header   "content-encoding: *gzip" "q=0 br refused, gzip chosen"
    check_body_matches "$TMPDIR/static/app.js.gz" "body is the .gz sibling"

    echo "[5/$1] No Accept-Encoding -> identity"
    fetch app.js ""
    check_no_header "content-encoding:" "no Content-Encoding"
    check_body_matches "$TMPDIR/static/app.js" "body is the identity file"

    echo "[6/$1] Accept-Encoding: br on file with no siblings -> identity fallback"
    fetch plain.txt "br"
    check_header   "^HTTP/1.1 200" "200 OK"
    check_no_header "content-encoding:" "no Content-Encoding (fallback)"
    check_body_matches "$TMPDIR/static/plain.txt" "body is the identity file"

    echo "[7/$1] HEAD with Accept-Encoding: br -> br headers, no body"
    fetch app.js "br" HEAD
    check_header   "content-encoding: *br" "HEAD advertises Content-Encoding: br"
    local br_size; br_size=$(wc -c < "$TMPDIR/static/app.js.br" | tr -d ' ')
    check_header   "content-length: *$br_size" "Content-Length matches .br size ($br_size)"
    if [ ! -s "$TMPDIR/b" ]; then echo "  ok: HEAD has empty body"; PASS=$((PASS+1)); else echo "  FAIL: HEAD returned a body"; FAIL=$((FAIL+1)); fi
}

echo "##### cache_static_files = false #####"
start_server false
run_suite "off"
stop_server

echo
echo "##### cache_static_files = true #####"
start_server true
run_suite "on"

echo "[8/on] cache hit returns byte-identical body across requests"
fetch app.js "br"; cp "$TMPDIR/b" "$TMPDIR/b1"
fetch app.js "br"; cp "$TMPDIR/b" "$TMPDIR/b2"
if cmp -s "$TMPDIR/b1" "$TMPDIR/b2" && cmp -s "$TMPDIR/b1" "$TMPDIR/static/app.js.br"; then
    echo "  ok: two cached hits identical to .br sibling"; PASS=$((PASS+1))
else echo "  FAIL: cached hits diverged"; FAIL=$((FAIL+1)); fi

echo "[9/on] Date header is fresh (re-encoded per response, not baked into cache)"
fetch app.js "br"; D1=$(grep -i '^date:' "$TMPDIR/h" | tr -d '\r')
sleep 1.1
fetch app.js "br"; D2=$(grep -i '^date:' "$TMPDIR/h" | tr -d '\r')
if [ -n "$D1" ] && [ -n "$D2" ] && [ "$D1" != "$D2" ]; then
    echo "  ok: Date advanced across a 1s gap ('$D1' -> '$D2')"; PASS=$((PASS+1))
else echo "  FAIL: Date not fresh ('$D1' vs '$D2')"; FAIL=$((FAIL+1)); fi
stop_server

echo
echo "===================="
echo "PASS=$PASS  FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then echo "RESULT: FAIL"; exit 1; fi
echo "RESULT: PASS"
