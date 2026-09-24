"""Live regression checks: python3 examples/async/test.py [port].

Start `zig build async-example -Denable-http2=true`, then run the installed
example with a config listening on localhost. Install `h2` to include HTTP/2.
"""
import concurrent.futures
import asyncio
import http.client
import json
import random
import socket
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


def get(path):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    start = time.monotonic()
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read(), time.monotonic() - start
    finally:
        conn.close()


def timed(ms):
    status, body, elapsed = get(f"/delay/{ms}")
    assert (status, body) == (200, str(ms).encode()), (ms, status, body)
    assert elapsed >= ms / 1000, (ms, elapsed)
    return elapsed


for ms in (0, 10, 500):
    timed(ms)
# Idle timer delivery must not wait for the 100 ms housekeeping sweep. Warm
# requests and use the median to tolerate occasional scheduler interruptions.
idle_samples = [timed(10) for _ in range(9)]
assert sorted(idle_samples)[4] < 0.060, idle_samples
random.seed(42)
delays = [random.randrange(0, 501) for _ in range(32)]
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
    list(pool.map(timed, delays))
    pending = pool.submit(timed, 500)
    time.sleep(0.04)
    assert get("/plain")[:2] == (200, b"ok")
    assert not pending.done(), "ready requests were blocked behind the timer"
    pending.result()
    for key in range(8):
        waiter = pool.submit(get, f"/wait/{key}/2000")
        time.sleep(0.02)
        assert get(f"/complete/{key}")[:2] == (200, b"completed")
        assert waiter.result()[:2] == (200, b"2000")
        assert get(f"/complete/{key}")[0] == 404

assert get("/wait/0/10")[:2] == (504, b"timeout")
status, body, elapsed = get("/chain/10")
assert (status, body) == (200, b"10") and elapsed >= 0.020

# Pipelined bytes remain in order across successive suspensions.
with socket.create_connection(("127.0.0.1", PORT), timeout=5) as sock:
    paths = ["/delay/10", "/plain", "/chain/10", "/delay/0"]
    sock.sendall(b"".join(f"GET {p} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode() for p in paths))
    stream = sock.makefile("rb")
    for expected in (b"10", b"ok", b"10", b"0"):
        assert stream.readline().startswith(b"HTTP/1.1 200")
        headers = {}
        while (line := stream.readline()) != b"\r\n":
            assert line, "truncated headers"
            key, value = line.split(b":", 1)
            headers[key.lower()] = value.strip()
        assert stream.read(int(headers[b"content-length"])) == expected
    stream.close()

# Disconnect must free the wait promptly, before its 60-second timeout.
before = json.loads(get("/stats")[1])["cancelled"]
sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
sock.sendall(b"GET /wait/99/60000 HTTP/1.1\r\nHost: localhost\r\n\r\n")
time.sleep(0.03)
sock.close()
deadline = time.monotonic() + 2
while json.loads(get("/stats")[1])["cancelled"] == before:
    assert time.monotonic() < deadline, "disconnect did not release wait"
    time.sleep(0.01)
assert get("/complete/99")[0] == 404


async def many_waits():
    async def one():
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        try:
            writer.write(b"GET /delay/200 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            await writer.drain()
            reply = await asyncio.wait_for(reader.read(), timeout=5)
            headers, body = reply.split(b"\r\n\r\n", 1)
            assert headers.startswith(b"HTTP/1.1 200") and body == b"200"
        finally:
            writer.close()
            await writer.wait_closed()

    await asyncio.gather(*(one() for _ in range(512)))


asyncio.run(many_waits())
print("HTTP/1: timings, 32 overlaps, ready traffic, completion, timeout, chains, pipeline, disconnect passed")
print("HTTP/1: 512 concurrent delayed requests passed")

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    print("HTTP/2 skipped (install the optional h2 package)")
    sys.exit(0)

with socket.create_connection(("127.0.0.1", PORT), timeout=5) as sock:
    h = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    h.initiate_connection()
    for sid, path in ((1, "/delay/200"), (3, "/plain"), (5, "/wait/100/60000"), (7, "/chain/10")):
        h.send_headers(sid, [(":method", "GET"), (":scheme", "http"), (":authority", "localhost"), (":path", path)], end_stream=True)
    sock.sendall(h.data_to_send())
    bodies, statuses, ended = {}, {}, []
    reset_sent = False
    start = time.monotonic()
    while len(ended) < 3:
        data = sock.recv(65536)
        assert data, "HTTP/2 closed unexpectedly"
        for event in h.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                statuses[event.stream_id] = dict(event.headers)[b":status"]
            if isinstance(event, h2.events.DataReceived):
                bodies[event.stream_id] = bodies.get(event.stream_id, b"") + event.data
                h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            if isinstance(event, h2.events.StreamEnded):
                ended.append(event.stream_id)
                if event.stream_id == 3 and not reset_sent:
                    h.reset_stream(5)
                    reset_sent = True
        sock.sendall(h.data_to_send())
    assert ended.index(3) < ended.index(1), ended
    assert time.monotonic() - start >= 0.2
    assert statuses == {1: b"200", 3: b"200", 7: b"200"}, statuses
    assert bodies == {1: b"200", 3: b"ok", 7: b"10"}, bodies
assert get("/complete/100")[0] == 404
print("HTTP/2: independent streams, chain, stream reset, sibling response passed")
