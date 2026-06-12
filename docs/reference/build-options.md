# Build options

swerver compiles features in or out at build time with `-D` flags. The base build is HTTP/1.1-only with no external dependencies; protocols and subsystems that pull in OpenSSL or zlib are opt-in. This keeps the default binary small and dependency-free, and lets you ship exactly the surface you need.

```bash
# HTTP/1.1 only — no OpenSSL, no zlib
zig build

# Full protocol stack, optimized for production
zig build -Doptimize=ReleaseFast \
  -Denable-tls=true -Denable-http2=true -Denable-http3=true
```

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-Denable-tls` | `false` | TLS 1.3 termination. Requires OpenSSL 3.x on the host. |
| `-Denable-http2` | `false` | HTTP/2 (HPACK, multiplexing, flow control). |
| `-Denable-http3` | `false` | HTTP/3 over QUIC. Implies TLS — needs OpenSSL **3.5+** for the QUIC TLS APIs. |
| `-Denable-proxy` | `false` | Reverse proxy / API gateway (upstreams, load balancing, health checks). |
| `-Denable-io-uring` | `false` | io_uring event-loop backend (Linux only). |
| `-Denable-compression` | native: `true` | Response compression (gzip/deflate). Requires zlib. Defaults on for native builds, off when cross-compiling. |
| `-Denable-x402-crypto` | `false` | Local x402 signature verification (secp256k1). Links `libcrypto`. |
| `-Doptimize=ReleaseFast` | — | Standard Zig optimize mode. Use `ReleaseFast` for maximum performance. |

## Feature dependencies

Some flags imply or require others. The build resolves these automatically — the *effective* value of a flag may be lower than what you asked for:

!!! info "Resolved at build time"
    - **HTTP/3 implies TLS.** `-Denable-http3=true` only takes effect when TLS is also effective; QUIC's handshake is TLS 1.3. Enabling HTTP/3 pulls OpenSSL into the link.
    - **TLS and HTTP/3 require a native target.** TLS, HTTP/3, and x402-crypto are silently disabled when cross-compiling (the target OS/arch differs from the host), because they link the host's OpenSSL. Cross-compiled binaries are HTTP/1.1-only — build from source on the target, or use the Docker image, for full protocol support.
    - **The reverse proxy needs `-Denable-proxy=true`.** Upstreams and routes in the config file only take effect in a proxy-enabled build.
    - **Compression needs zlib**, and **x402-crypto needs libcrypto** (a subset of OpenSSL) — both are linked only when their flag is effective.

## Requirements

- Zig **0.16.0** (stable).
- OpenSSL **3.5+** for the full TLS / HTTP/2 / HTTP/3 stack (3.5 is the minimum for QUIC).
- zlib for compression.
- Linux or macOS.

## Related

- [CLI flags](cli.md) — runtime flags for the built binary.
- [Architecture](../about/architecture.md) — the I/O backends `-Denable-io-uring` selects between.
- [Benchmarks](../about/benchmarks.md) — all numbers are from `-Doptimize=ReleaseFast` full-stack builds.
