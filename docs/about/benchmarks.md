# Benchmarks

These are [HttpArena](https://www.http-arena.com/) leaderboard numbers from swerver's most recent submission, measured on dedicated **64-core hardware** in the same Docker-compose environment for every framework. swerver ranks among the fastest on json-tls, the realistic workload of TLS termination plus JSON serialization. Live rankings move as other entries land.

| Test | Conns | Requests/sec | |
| --- | ---: | ---: | --- |
| **json-tls** (TLS + JSON serialize) | 4096 | **1,950,310** | |
| baseline (HTTP/1.1 plaintext) | 4096 | 3,664,110 | |
| pipelined (HTTP/1.1) | 4096 | 24,907,762 | |
| limited-conn (connection churn) | 4096 | 2,556,130 | |
| json (HTTP/1.1) | 4096 | 2,366,920 | |
| static file serving | 6800 | 1,197,205 | |
| baseline (HTTP/2) | 1024 | 2,267,290 | |
| baseline (HTTP/3) | 64 | 872,911 | |

Zero errors at 64-core saturation. ~222 µs average latency on limited-conn.

!!! note "A note on \"fastest\""
    On raw HTTP/1.1 microbenchmarks (plaintext baseline, pipelined, limited-conn), feature-stripped reference servers edge swerver by 1-2%. Neither implements TLS, HTTP/2, or HTTP/3, so neither appears on json-tls, baseline-h2, or baseline-h3. swerver is among the fastest servers that do the **full job**: three protocols, TLS termination, routing, and a complete middleware chain.

## Reproducing

The numbers above come from the public HttpArena leaderboard, not a local run. They reflect dedicated 64-core hardware under HttpArena's harness, with every framework in the same containerized environment. To compare on your own hardware, submit to or run [HttpArena](https://www.http-arena.com/) directly; results vary with kernel, NIC, and core count.

Builds are `-Doptimize=ReleaseFast` with the full protocol stack (`-Denable-tls -Denable-http2 -Denable-http3`). See [Build options](../reference/build-options.md).


## Related

- [Architecture](architecture.md): the design choices behind these numbers.
- [Limitations & roadmap](limitations.md): what's young and what's coming.
