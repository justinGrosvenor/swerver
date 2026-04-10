# HttpArena framework container for swerver.
#
# Build stage: debian:trixie (OpenSSL 3.5 — required for h3's
# SSL_set_quic_tls_cbs API from the OpenSSL 3.5+ QUIC-TLS callback
# interface) + Zig 0.16.0-dev toolchain.
#
# Runtime stage: debian:trixie-slim with libssl3 to match the build-
# time OpenSSL ABI.
#
# Build context: the swerver repo root (not this directory). Invoke as:
#     docker build -f httparena/Dockerfile -t httparena-swerver .
#
# Run (mimicking HttpArena's `scripts/run.sh` framework harness):
#     docker run --network host \
#       -v $PWD/httparena/certs:/certs:ro \
#       -v $PWD/httparena/static:/data/static:ro \
#       httparena-swerver

FROM debian:trixie AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        xz-utils \
        libssl-dev \
        pkg-config \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Zig by resolving the current master tarball URL from
# ziglang.org/download/index.json. Pinning a specific dev build
# doesn't work long-term (ziglang.org rotates dev builds daily).
# Architecture detection uses `dpkg --print-architecture` at RUN
# time (not a build ARG) so the container always matches the
# platform Docker actually builds for.
RUN set -eux; \
    DPKG_ARCH=$(dpkg --print-architecture); \
    case "${DPKG_ARCH}" in \
        amd64) ZIG_ARCH=x86_64 ;; \
        arm64) ZIG_ARCH=aarch64 ;; \
        *) echo "unsupported arch: ${DPKG_ARCH}" >&2; exit 1 ;; \
    esac; \
    ZIG_URL=$(curl -fsSL https://ziglang.org/download/index.json | \
        python3 -c "import json,sys; d=json.load(sys.stdin)['master']; print(d['${ZIG_ARCH}-linux']['tarball'])"); \
    echo "downloading ${ZIG_URL}"; \
    curl -fsSL "${ZIG_URL}" -o /tmp/zig.tar.xz; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    zig version

WORKDIR /src
COPY . /src

# Debian puts OpenSSL libs in the multiarch `/usr/lib/$arch-linux-gnu/`
# path. Zig's built-in linker (lld) doesn't search multiarch subdirs
# by default and ignores LIBRARY_PATH. Symlink libssl + libcrypto to
# /usr/lib/ which lld DOES search.
RUN MULTIARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH); \
    for lib in libssl.so libssl.a libcrypto.so libcrypto.a; do \
        ln -sf "/usr/lib/${MULTIARCH}/${lib}" "/usr/lib/${lib}"; \
    done

# Build swerver with every feature HttpArena exercises. ReleaseFast
# for maximum throughput on the benchmark; the AES-128-GCM + h3 path
# plus TLS + h2 + h1 all get compiled in. The binary lands at
# /src/zig-out/bin/swerver.
RUN zig build \
        -Denable-tls=true \
        -Denable-http2=true \
        -Denable-http3=true \
        -Doptimize=ReleaseFast \
        --summary all

# ----- runtime stage -----
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/zig-out/bin/swerver /usr/local/bin/swerver
COPY httparena/config-h1.json /etc/swerver/config-h1.json
COPY httparena/config-tls.json /etc/swerver/config-tls.json
COPY httparena/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# HttpArena's harness mounts /certs/ and /data/static/ read-only
# into the container at run time. The entrypoint starts two swerver
# processes:
#   - :8080 plaintext HTTP/1.1 + HTTP/2
#   - :8443 TLS HTTP/1.1 + HTTP/2 (ALPN) + QUIC HTTP/3
# See httparena/entrypoint.sh for rationale.
EXPOSE 8080 8443/tcp 8443/udp

CMD ["/usr/local/bin/entrypoint.sh"]
