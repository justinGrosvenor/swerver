#!/bin/bash
# Exercise cache policy through real upstream and gateway HTTP connections.
set -euo pipefail
cd "$(dirname "$0")/.."
zig build -Denable-proxy=true
python3 - <<'PY'
import collections
import http.client
import http.server
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

counts = collections.Counter()

class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        counts[self.path] += 1
        language = self.headers.get("Accept-Language", "none")
        body = f"{language}:{counts[self.path]}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        if self.path in ("/keyed", "/unkeyed"):
            self.send_header("Vary", "accept-language")
            self.send_header("Vary", "Accept-Encoding")
        if self.path == "/private":
            self.send_header("Cache-Control", 'Private="X-User, X-Role", Max-Age=60')
        elif self.path == "/nostore":
            self.send_header("Cache-Control", "NO-STORE")
        else:
            self.send_header("Cache-Control", 'x-private=yes, note="no-store, private"')
            self.send_header("Cache-Control", 'MaX-aGe="60"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
thread = threading.Thread(target=upstream.serve_forever, daemon=True)
thread.start()
try:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="swerver-cache-") as directory:
        config = pathlib.Path(directory) / "config.json"
        config.write_text(json.dumps({
            "server": {"address": "127.0.0.1", "port": port, "workers": 1, "max_connections": 32},
            "buffer_pool": {"buffer_count": 64, "buffer_size": 65536},
            "upstreams": [{"name": "app", "allow_private": True, "servers": [
                {"address": "127.0.0.1", "port": upstream.server_port}
            ]}],
            "routes": [
                {"path_prefix": path, "upstream": "app", "cache": {
                    "ttl_s": 60, "max_entries": 16,
                    "vary": ["Accept-Language"] if path == "/keyed" else [],
                }} for path in ("/keyed", "/unkeyed", "/private", "/nostore", "/public")
            ],
        }))
        with (pathlib.Path(directory) / "server.log").open("w+") as log:
            process = subprocess.Popen(["./zig-out/bin/swerver", "--config", str(config)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        log.seek(0)
                        raise RuntimeError("gateway failed to start: " + log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.02)

                def get(path, language="en"):
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        conn.request("GET", path, headers={"Accept-Language": language})
                        response = conn.getresponse()
                        body = response.read().decode()
                        assert response.status == 200, (path, response.status, body)
                        return body
                    finally:
                        conn.close()

                for path in ("/private", "/nostore"):
                    assert [get(path), get(path)] == ["en:1", "en:2"], path
                assert [get("/unkeyed", language) for language in ("en", "fr", "en")] == ["en:1", "fr:2", "en:3"]
                assert [get("/keyed", language) for language in ("en", "fr", "en")] == ["en:1", "fr:2", "en:1"]
                assert [get("/public"), get("/public")] == ["en:1", "en:1"]
                print("proxy cache: private/no-store, Vary bypass, configured variants, and quoted directives passed")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
finally:
    upstream.shutdown()
    upstream.server_close()
    thread.join()
PY
