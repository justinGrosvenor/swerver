#!/bin/bash
# scripts/test-h3-interop.sh
#
# End-to-end HTTP/3 interop smoke test against an h3-capable curl.
# Builds swerver with --enable-http3, generates a self-signed cert,
# starts swerver on a free port, and hits a few benchmark endpoints
# with `curl --http3-only`. Fails if any endpoint doesn't return the
# expected status code and body.
#
# Requires:
#   - Zig 0.16.0-dev (the version this repo is pinned to)
#   - OpenSSL CLI (for `openssl req -x509 ...`)
#   - An h3-capable curl. On macOS: `brew install curl` installs an
#     ngtcp2/nghttp3-linked build at /opt/homebrew/opt/curl/bin/curl.
#     The system curl on macOS does NOT support HTTP/3.
#
# Usage:
#   ./scripts/test-h3-interop.sh
#   ./scripts/test-h3-interop.sh --port 9543
#   CURL=/path/to/curl ./scripts/test-h3-interop.sh

set -euo pipefail

cd "$(dirname "$0")/.."

# ---- Configuration ----
PORT="9543"
CURL="${CURL:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---- Locate an h3-capable curl ----
if [[ -z "$CURL" ]]; then
    if [[ -x /opt/homebrew/opt/curl/bin/curl ]]; then
        CURL=/opt/homebrew/opt/curl/bin/curl
    else
        CURL=$(command -v curl || true)
    fi
fi
if [[ -z "$CURL" || ! -x "$CURL" ]]; then
    echo "ERROR: no curl found. Install via 'brew install curl' or set CURL=/path/to/curl" >&2
    exit 1
fi
if ! "$CURL" --version 2>&1 | grep -q HTTP3; then
    echo "ERROR: $CURL does not list HTTP3 in features. Install an h3-capable curl:" >&2
    echo "       brew install curl    # macOS" >&2
    "$CURL" --version | head -2 >&2
    exit 1
fi

# ---- Build swerver with h3 enabled ----
echo "==> Building swerver with -Denable-http3=true ..."
zig build -Denable-tls=true -Denable-http2=true -Denable-http3=true -Doptimize=Debug

if [[ ! -x ./zig-out/bin/swerver ]]; then
    echo "ERROR: build did not produce zig-out/bin/swerver" >&2
    exit 1
fi

# ---- Set up a temporary work dir with cert + config ----
WORK_DIR=$(mktemp -d -t swerver-h3-XXXXXX)
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
  "tls":  { "cert_path": "$WORK_DIR/cert.pem", "key_path": "$WORK_DIR/key.pem" },
  "quic": {
    "enabled": true,
    "port": $PORT,
    "cert_path": "$WORK_DIR/cert.pem",
    "key_path": "$WORK_DIR/key.pem"
  }
}
EOF

# ---- Start swerver in the background ----
echo "==> Starting swerver on UDP/$PORT ..."
./zig-out/bin/swerver --config "$WORK_DIR/config.json" > "$WORK_DIR/server.log" 2>&1 &
SWERVER_PID=$!

# Wait for the listener to be bound on UDP/PORT. Then warm the event loop
# with a couple of throw-away curl requests — the very first request after
# startup is racy (event loop may not have polled yet), but once any
# packet has been processed the loop is established.
for _ in $(seq 1 30); do
    if lsof -nP -iUDP:"$PORT" 2>/dev/null | grep -q swerver; then
        break
    fi
    sleep 0.1
done
if ! kill -0 "$SWERVER_PID" 2>/dev/null; then
    echo "ERROR: swerver exited during startup. Log:" >&2
    cat "$WORK_DIR/server.log" >&2
    exit 1
fi

# Warmup: hit /health a few times until we get a successful round trip,
# discarding the result. Stops after the first OK or 5 attempts.
for _ in 1 2 3 4 5; do
    if "$CURL" --http3-only -k --max-time 2 -sS \
        --resolve "localhost:$PORT:127.0.0.1" \
        -o /dev/null -w '%{http_code}' \
        "https://localhost:$PORT/health" 2>/dev/null | grep -q '^200$'; then
        break
    fi
done

# ---- Run the smoke tests ----
fail=0
check() {
    local path="$1" expected_status="$2" expected_body="$3"
    local out
    out=$("$CURL" --http3-only -k --max-time 5 -sS \
        --resolve "localhost:$PORT:127.0.0.1" \
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
    if [[ "$expected_body" == "*" ]]; then
        echo "  OK   $path: status $out, body: $body"
    elif [[ "$body" == "$expected_body" ]]; then
        echo "  OK   $path: status $out, body: $body"
    else
        echo "  FAIL $path: body '$body', expected '$expected_body'" >&2
        fail=$((fail + 1))
    fi
}

# POST case: verify h3 body dispatch. PR A added defer-until-FIN parsing
# with zero-copy single-DATA-frame bodies. POST /echo echoes the request
# body in the response, so a 200 with matching body is proof that the
# request body made it through the Stack → router → response path.
check_post() {
    local path="$1" post_body="$2" expected_status="$3" expected_body="$4"
    local out
    out=$("$CURL" --http3-only -k --max-time 5 -sS \
        --resolve "localhost:$PORT:127.0.0.1" \
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

echo "==> Smoke testing h3 endpoints ..."
check /health     200 ""
check /echo       200 '{"status":"ok"}'
check /plaintext  200 "Hello, World!"
check /json       200 '{"message":"Hello, World!"}'
check_post /echo "hello h3 body"        200 "hello h3 body"
check_post /echo "{\"msg\":\"ship it\"}" 200 "{\"msg\":\"ship it\"}"

if [[ $fail -gt 0 ]]; then
    echo "==> $fail HTTP/3 smoke test failure(s). Server log:"
    cat "$WORK_DIR/server.log"
    exit 1
fi

echo "==> All HTTP/3 smoke tests passed."
