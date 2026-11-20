#!/usr/bin/env python3
"""Check a locally built TLS, HTTP/2, HTTP/3 and proxy-enabled swerver.

Run with python3 scripts/test-gateway-admission.py [path/to/swerver].
Set CURL to an HTTP/3-capable curl executable.
"""
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        identities = self.headers.get_all("X-Consumer-Name") or []
        self.server.observed.append(identities)
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.send_response(101)
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "websocket")
            self.end_headers()
            self.close_connection = True
            return
        body = ",".join(identities).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def check_gateway(binary, work, upstream):
    curl = os.environ.get("CURL", "curl")
    with socket.socket() as tcp:
        tcp.bind(("127.0.0.1", 0))
        port = tcp.getsockname()[1]
    cert, key = work / "cert.pem", work / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls = {"cert_path": str(cert), "key_path": str(key)}
    config = {
        "server": {"address": "127.0.0.1", "port": port, "workers": 1, "max_connections": 32},
        "tls": tls,
        "quic": {**tls, "enabled": True, "address": "127.0.0.1", "port": port},
        "upstreams": [{"name": "local", "allow_private": True,
                       "servers": [{"address": "127.0.0.1", "port": upstream.server_port}]}],
        "routes": [{"path_prefix": "/who", "upstream": "local", "cache": {"ttl_s": 30},
                    "auth": {"type": "api_key", "keys": [{"key": "first", "name": "alice"},
                                                         {"key": "second", "name": "bob"}]}}],
    }
    config_path = work / "config.json"
    config_path.write_text(json.dumps(config))
    server = subprocess.Popen([binary, "--config", config_path])
    try:
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError(f"gateway exited with code {server.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError("gateway did not start")

        for flag, version in [("--http1.1", "1.1"), ("--http2", "2"), ("--http3-only", "3")]:
            for credential, code, name in [(None, 401, ""), ("first", 200, "alice"), ("second", 200, "bob")]:
                args = [curl, flag, "--noproxy", "*", "-ksS", "--max-time", "5",
                        "-w", "\n%{response_code} %{http_version}"]
                if credential:
                    args.extend(["-H", f"X-API-Key: {credential}"])
                start = len(upstream.observed)
                args.append(f"https://127.0.0.1:{port}/who")
                result = subprocess.run(args, check=True, capture_output=True, text=True)
                body, meta = result.stdout.rsplit("\n", 1)
                assert meta == f"{code} {version}", (meta, body)
                assert upstream.observed[start:] == ([[name]] if credential else [])
                if credential:
                    assert body == name, (body, name)
            print(f"HTTP/{version} admission and identity passed")

        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=str(cert))
            with context.wrap_socket(raw, server_hostname="localhost") as client:
                client.sendall(b"GET /who HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                               b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                               b"Sec-WebSocket-Version: 13\r\nX-API-Key: first\r\n\r\n")
                with client.makefile("rb") as response:
                    assert response.readline().startswith(b"HTTP/1.1 101 ")
                assert upstream.observed[-1] == ["alice"]
        print("WebSocket upgrade identity passed")
    finally:
        if server.poll() is None:
            server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == "__main__":
    executable = Path(sys.argv[1] if len(sys.argv) > 1 else "zig-out/bin/swerver").resolve()
    with tempfile.TemporaryDirectory() as workdir:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend) as upstream:
            upstream.observed = []
            thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            thread.start()
            try:
                check_gateway(executable, Path(workdir), upstream)
            finally:
                upstream.shutdown()
                thread.join()
