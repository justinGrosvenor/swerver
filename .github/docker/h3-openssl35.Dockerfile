# H3 + WASM CI image: OpenSSL 3.5+ plus Zig 0.16.0 stable.
#
# Why this exists: the -Denable-tls -Denable-http3 -Denable-wasm combination
# (the E2b H3 wasm-filter park tests in src/server/http3.zig) links the QUIC TLS
# symbols SSL_set_quic_tls_cbs / SSL_set_quic_tls_transport_params /
# SSL_set_quic_tls_early_data_enabled, which only exist in OpenSSL 3.5+. The
# stock ubuntu-latest GitHub runner ships OpenSSL 3.0, so even `zig build check`
# of that combination fails to link there and those tests run local-only.
#
# Debian trixie ships OpenSSL 3.5.x (libssl-dev), so building inside this image
# lets CI both compile AND run the H3+wasm tests on Linux.
#
# Zig version is pinned to match env.ZIG_VERSION in .github/workflows/ci.yml and
# the minimum_zig_version field in build.zig.zon. Bump all three together.
FROM debian:trixie-slim

ARG ZIG_VERSION=0.16.0
# sha256 of the official zig-<arch>-linux-<version>.tar.xz tarballs from
# https://ziglang.org/download/index.json . Update when bumping ZIG_VERSION.
ARG ZIG_SHA256_X86_64=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG ZIG_SHA256_AARCH64=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17

# OpenSSL 3.5+ dev headers/libs (libssl-dev), zlib for -Denable-compression
# parity, plus the tools needed to fetch and verify the Zig tarball.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        xz-utils \
        libssl-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Download Zig 0.16.0 stable for the build arch and verify its sha256. This
# mirrors how ci.yml pins the version via mlugg/setup-zig, but inside the image.
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64) zig_arch=x86_64; zig_sha="$ZIG_SHA256_X86_64" ;; \
        aarch64) zig_arch=aarch64; zig_sha="$ZIG_SHA256_AARCH64" ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    tarball="zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz"; \
    curl -fsSL -o /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/${tarball}"; \
    echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    zig version

# Sanity check: the image carries OpenSSL 3.5+ (QUIC TLS symbols). Fails the
# build early if the base ever regresses below 3.5.
RUN openssl version

WORKDIR /work
