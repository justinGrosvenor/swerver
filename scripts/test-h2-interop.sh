#!/bin/bash
# scripts/test-h2-interop.sh
#
# End-to-end HTTP/2 interop smoke test against system curl. Builds
# swerver with TLS + HTTP/2 enabled, generates a self-signed cert,
# starts swerver on a free port, and hits a few benchmark endpoints
# including POST cases that previously failed (silent drop of body)
# pre-PR "h2 POST body dispatch".
#
# Usage:
#   ./scripts/test-h2-interop.sh
#   ./scripts/test-h2-interop.sh --port 9544

set -euo pipefail

cd "$(dirname "$0")/.."

# ---- Configuration ----
PORT="9544"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---- Locate curl ----
CURL=$(command -v curl)
if [[ -z "$CURL" ]]; then
    echo "ERROR: curl not found" >&2
    exit 1
fi
# System curl on macOS and Linux both support HTTP/2 via nghttp2.
# We don't need an h3-capable curl here.

# ---- Build swerver with TLS + h2 ----
echo "==> Building swerver with -Denable-tls=true -Denable-http2=true ..."
zig build -Denable-tls=true -Denable-http2=true -Doptimize=Debug

if [[ ! -x ./zig-out/bin/swerver ]]; then
    echo "ERROR: build did not produce zig-out/bin/swerver" >&2
    exit 1
fi

# ---- Temp work dir with cert + config ----
WORK_DIR=$(mktemp -d -t swerver-h2-XXXXXX)
trap 'cleanup' EXIT

cleanup() {
    if [[ -n "${SWERVER_PID:-}" ]] && kill -0 "$SWERVER_PID" 2>/dev/null; then
        kill "$SWERVER_PID" 2>/dev/null || true
        wait "$SWERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}

echo "==> Generating self-signed cert in $WORK_DIR ..."
openssl req -x509 -newkey rsa:2048 \
    -keyout "$WORK_DIR/key.pem" -out "$WORK_DIR/cert.pem" \
    -sha256 -days 1 -nodes -subj '/CN=localhost' >/dev/null 2>&1

cat > "$WORK_DIR/config.json" <<EOF
{
  "server": { "port": $PORT, "max_connections": 256 },
  "tls":  { "cert_path": "$WORK_DIR/cert.pem", "key_path": "$WORK_DIR/key.pem" }
}
EOF

# ---- Start swerver in the background ----
echo "==> Starting swerver on TCP/$PORT ..."
./zig-out/bin/swerver --config "$WORK_DIR/config.json" > "$WORK_DIR/server.log" 2>&1 &
SWERVER_PID=$!

# Wait for the listener to be bound on TCP/PORT.
for _ in $(seq 1 30); do
    if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | grep -q swerver; then
        break
    fi
    sleep 0.1
done
if ! kill -0 "$SWERVER_PID" 2>/dev/null; then
    echo "ERROR: swerver exited during startup. Log:" >&2
    cat "$WORK_DIR/server.log" >&2
    exit 1
fi

# Warmup: hit /health once to establish the h2 connection loop.
"$CURL" --http2 -k --max-time 2 -sS \
    -o /dev/null \
    "https://localhost:$PORT/health" 2>/dev/null || true

# ---- Smoke tests ----
fail=0
check() {
    local path="$1" expected_status="$2" expected_body="$3"
    local out
    out=$("$CURL" --http2 -k --max-time 5 -sS \
        -o "$WORK_DIR/body" -w '%{http_code}' \
        "https://localhost:$PORT$path" 2>&1) || {
        echo "  FAIL $path: curl exited non-zero — $out" >&2
        fail=$((fail + 1))
        return
    }
    if [[ "$out" != "$expected_status" ]]; then
        echo "  FAIL $path: status $out, expected $expected_status" >&2
        fail=$((fail + 1))
        return
    fi
    local body
    body=$(cat "$WORK_DIR/body")
    if [[ "$body" == "$expected_body" ]]; then
        echo "  OK   $path: status $out, body: $body"
    else
        echo "  FAIL $path: body '$body', expected '$expected_body'" >&2
        fail=$((fail + 1))
    fi
}

check_post() {
    local path="$1" post_body="$2" expected_status="$3" expected_body="$4"
    local out
    out=$("$CURL" --http2 -k --max-time 5 -sS \
        -o "$WORK_DIR/body" -w '%{http_code}' \
        -X POST --data-binary "$post_body" \
        "https://localhost:$PORT$path" 2>&1) || {
        echo "  FAIL POST $path: curl exited non-zero — $out" >&2
        fail=$((fail + 1))
        return
    }
    if [[ "$out" != "$expected_status" ]]; then
        echo "  FAIL POST $path: status $out, expected $expected_status" >&2
        fail=$((fail + 1))
        return
    fi
    local body
    body=$(cat "$WORK_DIR/body")
    if [[ "$body" == "$expected_body" ]]; then
        echo "  OK   POST $path: status $out, body: $body"
    else
        echo "  FAIL POST $path: body '$body', expected '$expected_body'" >&2
        fail=$((fail + 1))
    fi
}

echo "==> Smoke testing h2 endpoints ..."
check /health                  200 ""
check /echo                    200 '{"status":"ok"}'
check /plaintext               200 "Hello, World!"
check /json                    200 '{"message":"Hello, World!"}'
check_post /echo "hello h2 body"        200 "hello h2 body"
check_post /echo "{\"msg\":\"ship it\"}" 200 "{\"msg\":\"ship it\"}"

if [[ $fail -gt 0 ]]; then
    echo "==> $fail HTTP/2 smoke test failure(s). Server log:"
    cat "$WORK_DIR/server.log"
    exit 1
fi

echo "==> All HTTP/2 smoke tests passed."
