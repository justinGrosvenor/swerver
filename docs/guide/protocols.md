# TLS, HTTP/2 & HTTP/3

swerver speaks HTTP/1.1, HTTP/2, and HTTP/3 from one binary, and a single process can bind several ports at once, each with its own protocol. Handlers don't care which protocol or which port a request arrived on; this page is about the transport configuration in front of them.

!!! note "Build flags"
    TLS, HTTP/2, and HTTP/3 are compile-time features. Build with `-Denable-tls=true -Denable-http2=true -Denable-http3=true` (HTTP/3 requires TLS) and an OpenSSL 3.5+ toolchain. See [Build options](../reference/build-options.md). The prebuilt release binaries are HTTP/1.1-only.

## TLS

Set a certificate and key under `tls`. Providing both turns on TLS 1.3 for the (legacy) single listener; providing neither leaves it plaintext. It's an error to set one without the other.

```json
{
  "tls": {
    "cert_path": "/etc/swerver/cert.pem",
    "key_path": "/etc/swerver/key.pem"
  }
}
```

### SNI multi-certificate

Serve different certificates per hostname by listing them under `tls.certificates`. Each entry binds one or more `hostnames` to a cert/key pair; the matching certificate is selected from the TLS SNI extension during the handshake. `cert_path`/`key_path` above act as the default for connections that don't match a listed hostname.

```json
{
  "tls": {
    "cert_path": "/etc/swerver/default.pem",
    "key_path": "/etc/swerver/default.key",
    "certificates": [
      {
        "hostnames": ["api.example.com", "api2.example.com"],
        "cert_path": "/etc/swerver/api.pem",
        "key_path": "/etc/swerver/api.key"
      },
      {
        "hostnames": ["admin.example.com"],
        "cert_path": "/etc/swerver/admin.pem",
        "key_path": "/etc/swerver/admin.key"
      }
    ]
  }
}
```

### Mutual TLS (mTLS)

Require and verify client certificates by pointing `tls.client_ca_path` at the CA bundle that signs your clients. `tls.client_cert_required` controls whether a client certificate is mandatory (`true`, the default) or merely verified when presented (`false`).

```json
{
  "tls": {
    "cert_path": "/etc/swerver/server.pem",
    "key_path": "/etc/swerver/server.key",
    "client_ca_path": "/etc/swerver/client-ca.pem",
    "client_cert_required": true
  }
}
```

## HTTP/2

Over TLS, HTTP/2 is negotiated automatically via ALPN, no extra config. A TLS listener serves HTTP/2 to clients that ask for `h2` and HTTP/1.1 to everyone else. Tune the protocol under `http2`:

| Key | Default | Description |
| --- | --- | --- |
| `max_streams` | `128` | Concurrent streams per connection. |
| `max_header_list_size` | `8192` | Maximum decoded header list size (bytes). |
| `initial_window_size` | `1048576` | Initial flow-control window (bytes). Larger than the RFC default to cut WINDOW_UPDATE round-trips under load. |
| `max_frame_size` | `16384` | Maximum frame size; must be `16384..16777215`. |
| `h2c_only` | `false` | See cleartext h2c below. |

### Cleartext h2c

For HTTP/2 without TLS (e.g. behind a TLS-terminating edge), set `h2c_only: true` on a listener. That port then requires the HTTP/2 connection preface (prior-knowledge h2c) and refuses connections that begin with anything else, rather than silently falling back to HTTP/1.1. This is most useful on a dedicated multi-listener port (below).

## HTTP/3 over QUIC

HTTP/3 runs over QUIC (UDP). Enable it under `quic` with its own cert/key:

```json
{
  "quic": {
    "enabled": true,
    "port": 8443,
    "cert_path": "/etc/swerver/cert.pem",
    "key_path": "/etc/swerver/key.pem",
    "max_idle_timeout_ms": 30000,
    "max_streams_bidi": 100,
    "max_streams_uni": 100
  }
}
```

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Turn HTTP/3 on. Requires `cert_path` and `key_path`. |
| `port` | `443` | UDP port for QUIC. |
| `cert_path` / `key_path` | `""` | PEM certificate and key (required when enabled). |
| `max_idle_timeout_ms` | `30000` | Idle connection timeout. Must be non-zero. |
| `max_streams_bidi` | `100` | Concurrent client-initiated bidirectional streams. |
| `max_streams_uni` | `100` | Concurrent unidirectional streams. |

When QUIC is enabled, swerver advertises HTTP/3 to HTTP/1.1 and HTTP/2 clients via an `Alt-Svc` header so they can upgrade on a later connection.

## Multi-listener model

A single process can bind **multiple ports, each with its own protocol**, via `server.listeners[]`. When `listeners` is empty (the default), the server binds the single `server.port` and infers its protocol from the `tls`/`http2`/`quic` sections. When `listeners` is present, those legacy fields are ignored for binding: each listed entry is bound on every worker via `SO_REUSEPORT`, and the per-connection protocol is resolved **at accept time from the local port**.

Each entry is:

| Field | Default | Description |
| --- | --- | --- |
| `address` | `"0.0.0.0"` | Bind address. |
| `port` | none | Bind port (required). |
| `use_tls` | `false` | Terminate TLS on this port (HTTP/1.1 + HTTP/2 via ALPN). |
| `h2c_only` | `false` | Require the h2c preface; refuse non-HTTP/2 connections. |
| `quic_enabled` | `false` | Also serve HTTP/3 over QUIC for this listener. |
| `quic_port` | `0` | UDP port for this listener's QUIC. |

The TLS certificates and QUIC tuning still come from the top-level `tls` and `quic` sections; a listener entry decides *which protocols* a port speaks, not the cert material.

```json
{
  "server": {
    "workers": 0,
    "listeners": [
      { "address": "0.0.0.0", "port": 8080 },
      { "address": "0.0.0.0", "port": 8082, "h2c_only": true },
      { "address": "0.0.0.0", "port": 8443, "use_tls": true, "quic_enabled": true, "quic_port": 8443 }
    ]
  },
  "tls": {
    "cert_path": "/etc/swerver/cert.pem",
    "key_path": "/etc/swerver/key.pem"
  },
  "quic": {
    "enabled": true,
    "cert_path": "/etc/swerver/cert.pem",
    "key_path": "/etc/swerver/key.pem"
  }
}
```

This binds:

- **8080**: plaintext HTTP/1.1.
- **8082**: cleartext HTTP/2 only (prior-knowledge h2c).
- **8443**: TLS HTTP/1.1 and HTTP/2 (chosen by ALPN), plus HTTP/3 over QUIC on UDP 8443.

!!! tip "Single-listener stays simple"
    Most deployments never set `listeners`. Leaving it empty keeps the classic single-port setup, where `server.port` plus the `tls`/`quic` sections fully describe the listener.
