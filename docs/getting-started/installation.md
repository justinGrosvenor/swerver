# Installation

There are three ways to get swerver: build the full-featured server from source, grab a pre-built release binary, or depend on it as a Zig package and embed it in your own program.

## Requirements

| Requirement | Notes |
| --- | --- |
| **Zig 0.16.0** (stable) | The build is pinned to the stable toolchain. Dev builds remove APIs swerver uses. |
| **OpenSSL 3.5+** | Required only for TLS, HTTP/2, and HTTP/3. Plain HTTP/1.1 needs no external dependency. |
| **macOS or Linux** | kqueue on macOS/BSD, epoll or io_uring on Linux. Windows is cross-compile-only (no IOCP backend). |

## Build from source

```bash
git clone https://github.com/justinGrosvenor/swerver.git
cd swerver
zig build -Doptimize=ReleaseFast -Denable-tls=true -Denable-http2=true -Denable-http3=true
./zig-out/bin/swerver --config config.json
```

The protocol features are opt-in build flags so a minimal HTTP/1.1 build pulls in no OpenSSL. The most common flags:

| Flag | Default | Description |
| --- | --- | --- |
| `-Doptimize=ReleaseFast` | — | Maximum performance. Use for any real deployment. |
| `-Denable-tls=true` | `false` | TLS 1.3 (requires OpenSSL). |
| `-Denable-http2=true` | `false` | HTTP/2 with HPACK. |
| `-Denable-http3=true` | `false` | HTTP/3 over QUIC. |

See [Build options](../reference/build-options.md) for the full flag list (proxy, compression, io_uring, x402).

!!! tip "A bare HTTP/1.1 build"
    `zig build -Doptimize=ReleaseFast` with no feature flags produces an HTTP/1.1-only binary with no OpenSSL dependency — handy for a quick start or a constrained container.

## Pre-built release binaries

Tagged alpha releases publish cross-compiled binaries for `linux-{x86_64, aarch64}` and `macos-{x86_64, aarch64}` on the [Releases page](https://github.com/justinGrosvenor/swerver/releases):

```bash
curl -LO https://github.com/justinGrosvenor/swerver/releases/download/v0.1.0-alpha.23/swerver-v0.1.0-alpha.23-linux-x86_64.tar.gz
tar -xzf swerver-v0.1.0-alpha.23-linux-x86_64.tar.gz
./swerver-v0.1.0-alpha.23-linux-x86_64 --config config.json
```

!!! warning "Release binaries are HTTP/1.1 only"
    OpenSSL linking requires the host toolchain, so the cross-compiled release binaries ship **without TLS, HTTP/2, or HTTP/3**. For full protocol support, build from source or use the Docker image.

## Docker

The [HttpArena submission](https://github.com/justinGrosvenor/HttpArena) includes a Dockerfile that builds a full-featured (TLS / HTTP/2 / HTTP/3) runtime image on `debian:trixie` (OpenSSL 3.5), along with a docker-compose setup.

!!! note "io_uring under Docker"
    The default Docker seccomp profile blocks the io_uring syscalls. If you run the native io_uring backend in a container, pass `--security-opt seccomp=unconfined`.

## Depend on swerver as a Zig package

swerver ships as a Zig package — depend on it from another Zig project and embed the server into your own binary.

In your downstream project's `build.zig.zon`:

```zig
.{
    .name = .my_app,
    .version = "0.1.0",
    .dependencies = .{
        .swerver = .{
            .url = "https://github.com/justinGrosvenor/swerver/archive/refs/tags/v0.1.0-alpha.23.tar.gz",
            // .hash will be filled in by `zig fetch --save`
        },
    },
    .paths = .{""},
}
```

Run `zig fetch --save https://github.com/justinGrosvenor/swerver/archive/refs/tags/v0.1.0-alpha.23.tar.gz` to populate the `.hash` field automatically.

In your `build.zig`:

```zig
const swerver_dep = b.dependency("swerver", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("swerver", swerver_dep.module("swerver"));
```

You can now `const swerver = @import("swerver");` from your application code.

!!! warning "Alpha API"
    The public library API in `src/lib.zig` may change between alpha versions. Breaking changes are announced in release notes. The API will be frozen at 1.0.

## Next

Continue to [Your first server](first-server.md) to wire up routes and handlers, or [Running from a config file](config-file.md) to drive the prebuilt server with JSON.
