#!/bin/bash
# Gateway example: start mock backends, build and launch swerver, run smoke tests.
#
# Usage:
#   ./examples/gateway/run.sh          # build + test, then stay running
#   ./examples/gateway/run.sh --test   # build + test, then exit
#
# Prerequisites: zig, python3, curl
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

TEST_ONLY=false
[[ "${1:-}" == "--test" ]] && TEST_ONLY=true

# ---- Build ----
echo "Building gateway example..."
zig build 2>&1

# ---- Static files ----
mkdir -p examples/gateway/static
echo "hello from static" > examples/gateway/static/index.html

# ---- Mock backends ----
PIDS=()
cleanup() {
    echo ""
    echo "Stopping..."
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

start_backend() {
    local port=$1 name=$2
    python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'backend':'$name','path':self.path})
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())
    def do_POST(self):
        length = int(self.headers.get('Content-Length',0))
        data = self.rfile.read(length) if length else b''
        body = json.dumps({'backend':'$name','path':self.path,'echo':data.decode()})
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',$port),H).serve_forever()
" &
    PIDS+=($!)
}

echo "Starting backends on :9001 :9002 :9003..."
start_backend 9001 "api-v1-a"
start_backend 9002 "api-v1-b"
start_backend 9003 "api-v2"
sleep 0.3

# ---- Start gateway ----
echo "Starting gateway on :8080..."
./zig-out/bin/swerver-gateway-example &
PIDS+=($!)

echo -n "  Waiting for gateway..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        echo " ready (${i}s)"
        break
    fi
    sleep 1
    if [ "$i" -eq 30 ]; then
        echo " TIMEOUT"
        exit 1
    fi
done

# ---- Smoke tests ----
echo ""
echo "=== Smoke Tests ==="
PASS=0
FAIL=0

check() {
    local desc="$1" expect="$2" url="$3"
    shift 3
    local body status
    body=$(curl -s -o - -w "\n%{http_code}" "$@" "$url" 2>/dev/null) || body=$'\n000'
    status="${body##*$'\n'}"
    body="${body%$'\n'*}"

    if echo "$body" | grep -q "$expect" 2>/dev/null || [ "$status" = "$expect" ]; then
        echo "  PASS  $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $desc  (expected '$expect', status=$status, body='${body:0:120}')"
        FAIL=$((FAIL+1))
    fi
}

# Built-in routes
check "GET /health returns 200"                "200"               http://localhost:8080/health
check "GET /metrics has prometheus data"        "swerver_requests"  http://localhost:8080/metrics

# Auth enforcement
check "GET /api/v1/ without key returns 401"   "401"               http://localhost:8080/api/v1/health

# Proxy with auth — round-robin across v1 backends
check "GET /api/v1/ with key proxies to v1"    "api-v1"            http://localhost:8080/api/v1/health -H "X-API-Key: demo-key-1"

# v2 backend
check "GET /api/v2/ with key proxies to v2"    "api-v2"            http://localhost:8080/api/v2/health -H "X-API-Key: demo-key-1"

# Static files served from examples/gateway/static/
check "GET /static/ serves files"              "hello from static" http://localhost:8080/static/index.html

# Canary route — traffic split 90/10 between v1 and v2, no auth
check "GET /canary/ reaches a backend"         "api-v"             http://localhost:8080/canary/health

# Custom handler routes (defined in main.zig, not config)
check "GET / returns dashboard HTML"           "swerver gateway"   http://localhost:8080/
check "GET /version returns JSON"              "swerver-gateway"   http://localhost:8080/version

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

if [ "$TEST_ONLY" = true ]; then
    echo ""
    echo "All tests passed."
    exit 0
fi

echo ""
echo "Gateway running on http://localhost:8080 — press Ctrl+C to stop"
wait "${PIDS[-1]}"
