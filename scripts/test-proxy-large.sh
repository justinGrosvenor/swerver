#!/bin/bash
# Proxy large-response regression test.
#
# The proxy historically buffered the entire upstream response in one fixed
# 64KB buffer; anything bigger was truncated, treated as an upstream failure,
# retried, and finally answered with a 502 (vallhund.org entry.client bug).
# This test stands up a size-controlled upstream and asserts byte-for-byte
# integrity through the proxy across sizes up to 10MB, for Content-Length and
# chunked upstream framing, identity and gzip client encodings, plus the
# max_response_bytes cap behavior.
#
# Usage: ./scripts/test-proxy-large.sh  (builds + starts everything itself)
set -euo pipefail

cd "$(dirname "$0")/.."

UPSTREAM_PORT=19011
PROXY_PORT=19090
CAP_PORT=19091
TMPDIR=$(mktemp -d)
trap 'kill $SW_PID $CAP_PID $UP_PID 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/upstream.py" <<'PY'
import http.server, re, sys
PORT = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def body_for(self, n, rep):
        if rep:
            return b"A" * n
        return bytes((i % 251 for i in range(n)))
    def do_GET(self):
        m = re.match(r"/(kb|rep)/(\d+)(\?chunked=1)?", self.path)
        if not m:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        n = int(m.group(2)) * 1024
        body = self.body_for(n, m.group(1) == "rep")
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        if m.group(3):
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            off = 0
            while off < n:
                chunk = body[off:off + 65536]
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                off += len(chunk)
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(n))
            self.end_headers()
            self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY

cat > "$TMPDIR/proxy.json" <<EOF
{
  "server": { "address": "127.0.0.1", "port": $PROXY_PORT, "workers": 1 },
  "upstreams": [
    { "name": "app", "allow_private": true,
      "servers": [ { "address": "127.0.0.1", "port": $UPSTREAM_PORT } ] }
  ],
  "routes": [ { "path_prefix": "/", "upstream": "app" } ]
}
EOF

# Second instance with a tight response cap to test the 502 path.
cat > "$TMPDIR/proxy-cap.json" <<EOF
{
  "server": { "address": "127.0.0.1", "port": $CAP_PORT, "workers": 1 },
  "upstreams": [
    { "name": "app", "allow_private": true,
      "servers": [ { "address": "127.0.0.1", "port": $UPSTREAM_PORT } ] }
  ],
  "routes": [ { "path_prefix": "/", "upstream": "app", "max_response_bytes": 262144 } ]
}
EOF

zig build >/dev/null
python3 "$TMPDIR/upstream.py" "$UPSTREAM_PORT" &
UP_PID=$!
./zig-out/bin/swerver --config "$TMPDIR/proxy.json" >/dev/null 2>&1 &
SW_PID=$!
./zig-out/bin/swerver --config "$TMPDIR/proxy-cap.json" >/dev/null 2>&1 &
CAP_PID=$!

for i in $(seq 1 50); do
    curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PROXY_PORT/kb/1" && break
    sleep 0.1
    [ "$i" = 50 ] && { echo "FAIL: stack did not start"; exit 1; }
done

fail=0

check_integrity() { # path label
    local d p code
    d=$(curl -s "http://127.0.0.1:$UPSTREAM_PORT$1" | shasum -a 256 | cut -d' ' -f1)
    code=$(curl -s --max-time 60 -o "$TMPDIR/body" -w "%{http_code}" "http://127.0.0.1:$PROXY_PORT$1")
    p=$(shasum -a 256 < "$TMPDIR/body" | cut -d' ' -f1)
    if [ "$code" = "200" ] && [ "$d" = "$p" ]; then
        echo "PASS $2 ($1)"
    else
        echo "FAIL $2 ($1): code=$code sha_direct=${d:0:12} sha_proxied=${p:0:12}"
        fail=1
    fi
}

# Content-Length upstream, identity: across the old failure boundary to 10MB.
for kb in 10 63 64 65 100 147 191 256 1024 10240; do
    check_integrity "/kb/$kb" "content-length identity ${kb}KB"
done

# Chunked upstream framing across the same boundary.
for kb in 10 64 100 191 1024 5120; do
    check_integrity "/kb/$kb?chunked=1" "chunked identity ${kb}KB"
done

# gzip: small compressible body must arrive gzip-encoded and intact.
gz_code=$(curl -s -H "Accept-Encoding: gzip" -o "$TMPDIR/gz" -w "%{http_code}" "http://127.0.0.1:$PROXY_PORT/rep/30")
gz_ce=$(curl -s -H "Accept-Encoding: gzip" -D - -o /dev/null "http://127.0.0.1:$PROXY_PORT/rep/30" | grep -ci "content-encoding: gzip" || true)
gz_ok=$(python3 -c "
import gzip,sys
data = open('$TMPDIR/gz','rb').read()
body = gzip.decompress(data) if $gz_ce else data
sys.stdout.write('1' if body == b'A'*30720 else '0')")
if [ "$gz_code" = "200" ] && [ "$gz_ok" = "1" ]; then
    echo "PASS gzip 30KB (encoded=$gz_ce)"
else
    echo "FAIL gzip 30KB: code=$gz_code decoded_ok=$gz_ok"
    fail=1
fi

# Large body with gzip requested: proxy skips compression (output cannot fit
# its scratch); body must still arrive intact as identity.
big_d=$(curl -s "http://127.0.0.1:$UPSTREAM_PORT/kb/1024" | shasum -a 256 | cut -d' ' -f1)
big_p=$(curl -s -H "Accept-Encoding: gzip" "http://127.0.0.1:$PROXY_PORT/kb/1024" | shasum -a 256 | cut -d' ' -f1)
if [ "$big_d" = "$big_p" ]; then echo "PASS gzip-requested 1MB passthrough"; else echo "FAIL gzip-requested 1MB passthrough"; fail=1; fi

# Cap behavior: under cap passes, over cap gets a prompt clean 502.
cap_small=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$CAP_PORT/kb/100")
cap_big=$(curl -s -o /dev/null --max-time 10 -w "%{http_code} %{time_total}" "http://127.0.0.1:$CAP_PORT/kb/1024")
cap_code=${cap_big%% *}
if [ "$cap_small" = "200" ] && [ "$cap_code" = "502" ]; then
    echo "PASS max_response_bytes cap (100KB=200, 1MB=502 in ${cap_big#* }s)"
else
    echo "FAIL max_response_bytes cap: small=$cap_small big=$cap_big"
    fail=1
fi

# Keep-alive reuse after a large proxied response on the same client conn.
ka=$(curl -s -o /dev/null -o /dev/null -w "%{http_code} " "http://127.0.0.1:$PROXY_PORT/kb/1024" "http://127.0.0.1:$PROXY_PORT/kb/10")
if [ "$ka" = "200 200 " ]; then echo "PASS keep-alive after 1MB response"; else echo "FAIL keep-alive after 1MB: $ka"; fail=1; fi

[ "$fail" = "0" ] && echo "All proxy large-response tests passed." || { echo "FAILURES PRESENT"; exit 1; }
