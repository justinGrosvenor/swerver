#!/bin/bash
# HTTP/1.1 pipelining regression test.
#
# Sends batches of pipelined requests in a single TCP write and verifies
# every response comes back complete, in order, and correctly framed.
# Exercises the write-queue coalescing paths (preencoded + router) and the
# sendfile wire-ordering invariant: a static (sendfile) response followed by
# pipelined dynamic requests must emit the file body BEFORE the next
# response's bytes.
#
# Usage: ./scripts/test-h1-pipeline.sh  (builds + starts the server itself)
set -euo pipefail

cd "$(dirname "$0")/.."

PORT=18941
TMPDIR=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

# Static root with one known asset, large enough to exceed the inline
# header buffer so the sendfile pending-file path engages.
mkdir -p "$TMPDIR/static"
python3 -c "import sys; sys.stdout.write('A'*100000)" > "$TMPDIR/static/blob.bin"

cat > "$TMPDIR/config.json" <<EOF
{
  "server": {
    "address": "127.0.0.1",
    "port": $PORT,
    "workers": 1,
    "static_root": "$TMPDIR/static"
  }
}
EOF

zig build >/dev/null
./zig-out/bin/swerver --config "$TMPDIR/config.json" &
SERVER_PID=$!

for i in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/health"; then break; fi
    sleep 0.1
    if [ "$i" = 50 ]; then echo "FAIL: server did not start"; exit 1; fi
done

python3 - "$PORT" <<'PY'
import socket, sys

PORT = int(sys.argv[1])

def read_responses(sock, count, timeout=5.0):
    """Parse exactly `count` HTTP/1.1 responses off the socket; returns
    a list of (status, body) and fails hard on any framing error."""
    sock.settimeout(timeout)
    buf = b""
    out = []
    while len(out) < count:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                raise AssertionError(f"connection closed after {len(out)}/{count} responses")
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n", 1)[0]
        status = int(status_line.split()[1])
        cl = None
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                cl = int(v.strip())
        if cl is None:
            raise AssertionError(f"response {len(out)}: no Content-Length (chunked unexpected here)")
        while len(rest) < cl:
            chunk = sock.recv(65536)
            if not chunk:
                raise AssertionError(f"connection closed mid-body on response {len(out)}")
            rest += chunk
        out.append((status, rest[:cl]))
        buf = rest[cl:]
    if buf:
        raise AssertionError(f"trailing bytes after {count} responses: {buf[:80]!r}")
    return out

def pipeline(requests, expect):
    s = socket.create_connection(("127.0.0.1", PORT))
    try:
        s.sendall(b"".join(requests))
        got = read_responses(s, len(expect))
        for i, ((st, body), (est, ebody)) in enumerate(zip(got, expect)):
            assert st == est, f"resp {i}: status {st} != {est}"
            assert body == ebody, f"resp {i}: body {body[:60]!r}... != expected {ebody[:60]!r}..."
    finally:
        s.close()

def get(path):
    return f"GET {path} HTTP/1.1\r\nHost: t\r\n\r\n".encode()

BLOB = b"A" * 100000

# 1. Router-path coalescing: many small computed responses in one batch.
pipeline([get(f"/baseline11?a={i}&b={i+1}") for i in range(16)],
         [(200, str(2 * i + 1).encode()) for i in range(16)])
print("PASS pipeline x16 router (/baseline11)")

# 2. Preencoded coalescing: /pipeline repeated.
pipeline([get("/pipeline")] * 16, [(200, b"ok")] * 16)
print("PASS pipeline x16 preencoded (/pipeline)")

# 3. Mixed preencoded + router interleaved.
reqs, exp = [], []
for i in range(8):
    reqs += [get("/pipeline"), get(f"/baseline11?a={i}&b=1")]
    exp += [(200, b"ok"), (200, str(i + 1).encode())]
pipeline(reqs, exp)
print("PASS pipeline x16 mixed preencoded/router")

# 4. THE ORDERING CASE: static (sendfile) followed by dynamic requests in
#    one batch. The file body must arrive complete before the next response.
pipeline([get("/static/blob.bin"), get("/baseline11?a=2&b=3"), get("/pipeline")],
         [(200, BLOB), (200, b"5"), (200, b"ok")])
print("PASS pipeline static->router->preencoded ordering")

# 5. Static sandwich: dynamic, static, dynamic.
pipeline([get("/pipeline"), get("/static/blob.bin"), get("/baseline11?a=7&b=8")],
         [(200, b"ok"), (200, BLOB), (200, b"15")])
print("PASS pipeline dynamic->static->dynamic ordering")

# 6. Two statics back to back, pipelined.
pipeline([get("/static/blob.bin"), get("/static/blob.bin")],
         [(200, BLOB), (200, BLOB)])
print("PASS pipeline static x2 ordering")
PY

echo "All h1 pipelining tests passed."
