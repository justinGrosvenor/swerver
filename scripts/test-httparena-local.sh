#!/bin/bash
# scripts/test-httparena-local.sh
#
# Local end-to-end smoke test of the HttpArena submission container.
#
# Mirrors the subset of HttpArena's `scripts/run.sh` that swerver
# uses: generates a self-signed cert into httparena/certs/, writes
# a minimal /data/static tree with the 20 asset names h2o uses,
# builds httparena/Dockerfile, starts the container with the same
# volume mounts HttpArena's harness uses, and hits every subscribed
# endpoint with curl.
#
# Usage:
#   ./scripts/test-httparena-local.sh
#
# Requires:
#   - Docker Desktop running
#   - curl (system curl is fine for h1 + h2; h3 uses brew curl)

set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="httparena-swerver-local"
CONTAINER="httparena-swerver-local-run"
WORK_DIR="$(pwd)/httparena/.local-test"
CERTS_DIR="$WORK_DIR/certs"
STATIC_DIR="$WORK_DIR/static"

# ---- locate curl (h3-capable preferred for the h3 checks) ----
CURL="${CURL:-}"
if [[ -z "$CURL" && -x /opt/homebrew/opt/curl/bin/curl ]]; then
    CURL=/opt/homebrew/opt/curl/bin/curl
fi
CURL="${CURL:-$(command -v curl)}"
if [[ -z "$CURL" ]]; then
    echo "ERROR: curl not found" >&2
    exit 1
fi

cleanup() {
    docker rm -f "$CONTAINER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

rm -rf "$WORK_DIR"
mkdir -p "$CERTS_DIR" "$STATIC_DIR"

echo "==> Generating self-signed cert in $CERTS_DIR ..."
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERTS_DIR/server.key" -out "$CERTS_DIR/server.crt" \
    -sha256 -days 1 -nodes -subj '/CN=localhost' >/dev/null 2>&1

echo "==> Seeding /data/static with HttpArena-shape assets ..."
# Create minimal stand-ins for the 20 static files HttpArena expects.
# Real benchmark runs mount the real dataset via `-v $DATA_DIR/static:`.
for f in reset.css layout.css theme.css components.css utilities.css; do
    echo "/* $f */" > "$STATIC_DIR/$f"
done
for f in analytics.js helpers.js app.js vendor.js router.js; do
    echo "// $f" > "$STATIC_DIR/$f"
done
for f in header.html footer.html; do
    echo "<!-- $f -->" > "$STATIC_DIR/$f"
done
for f in regular.woff2 bold.woff2; do
    printf '\x00\x01\x00\x00' > "$STATIC_DIR/$f"  # WOFF2 magic bytes
done
echo '<svg/>' > "$STATIC_DIR/logo.svg"
echo '<svg/>' > "$STATIC_DIR/icon-sprite.svg"
for f in hero.webp thumb1.webp thumb2.webp; do
    printf 'RIFF\x00\x00\x00\x00WEBP' > "$STATIC_DIR/$f"  # WebP magic bytes
done
echo '{"name":"swerver"}' > "$STATIC_DIR/manifest.json"

echo "==> Building Docker image $IMAGE ..."
docker build -f httparena/Dockerfile --build-arg USE_LOCAL=1 -t "$IMAGE" . >/dev/null

# ---- Start the container ----
docker rm -f "$CONTAINER" 2>/dev/null || true
echo "==> Starting container $CONTAINER ..."
docker run -d --rm --name "$CONTAINER" \
    -p 18080:8080 \
    -p 18443:8443/tcp \
    -p 18443:8443/udp \
    -v "$CERTS_DIR:/certs:ro" \
    -v "$STATIC_DIR:/data/static:ro" \
    "$IMAGE" >/dev/null

# Wait for both listeners to be ready.
for _ in $(seq 1 50); do
    if curl --http1.1 -k --max-time 1 -sS -o /dev/null "http://localhost:18080/health" 2>/dev/null && \
       curl --http1.1 -k --max-time 1 -sS -o /dev/null "https://localhost:18443/health" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

# ---- Smoke tests ----
fail=0
h1() {
    local path="$1" expected="$2"
    local body
    body=$("$CURL" --http1.1 -sS --max-time 5 "http://localhost:18080$path" 2>&1) || {
        echo "  FAIL h1 $path: curl error ($body)" >&2; fail=$((fail+1)); return
    }
    if [[ "$body" == "$expected" ]]; then
        echo "  OK   h1 $path: $body"
    else
        echo "  FAIL h1 $path: '$body' != '$expected'" >&2; fail=$((fail+1))
    fi
}
h2() {
    local path="$1" expected="$2"
    local body
    body=$("$CURL" --http2 -k -sS --max-time 5 "https://localhost:18443$path" 2>&1) || {
        echo "  FAIL h2 $path: curl error ($body)" >&2; fail=$((fail+1)); return
    }
    if [[ "$body" == "$expected" ]]; then
        echo "  OK   h2 $path: $body"
    else
        echo "  FAIL h2 $path: '$body' != '$expected'" >&2; fail=$((fail+1))
    fi
}
h3() {
    local path="$1" expected="$2"
    if ! "$CURL" --version 2>&1 | grep -q HTTP3; then
        echo "  SKIP h3 $path: curl has no HTTP3 support"
        return
    fi
    local body
    body=$("$CURL" --http3-only -k -sS --max-time 5 --resolve "localhost:18443:127.0.0.1" "https://localhost:18443$path" 2>&1) || {
        echo "  FAIL h3 $path: curl error ($body)" >&2; fail=$((fail+1)); return
    }
    if [[ "$body" == "$expected" ]]; then
        echo "  OK   h3 $path: $body"
    else
        echo "  FAIL h3 $path: '$body' != '$expected'" >&2; fail=$((fail+1))
    fi
}

echo "==> Smoke testing h1 on :18080 ..."
h1 "/pipeline"              "ok"
h1 "/baseline11?a=1&b=1"    "2"
h1 "/baseline11?a=5&b=7"    "12"
h1 "/plaintext"             "Hello, World!"
h1 "/json"                  '{"message":"Hello, World!"}'

echo "==> Smoke testing h2 on :18443 ..."
h2 "/baseline2?a=1&b=1"     "2"
h2 "/plaintext"             "Hello, World!"

echo "==> Smoke testing h3 on :18443 ..."
h3 "/baseline2?a=1&b=1"     "2"
h3 "/plaintext"             "Hello, World!"

if [[ $fail -gt 0 ]]; then
    echo "==> $fail failure(s). Container logs:" >&2
    docker logs "$CONTAINER" 2>&1 | tail -40
    exit 1
fi
echo "==> All HttpArena local smoke tests passed."
