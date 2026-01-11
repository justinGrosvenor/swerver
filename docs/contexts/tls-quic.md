# Context Pack: TLS and QUIC Adapters

Reference architecture: [design/2.0-architecture.md](../design/2.0-architecture.md).
Reference contracts: [design/1.4-contracts.md](../design/1.4-contracts.md).
Reference core runtime: [design/3.0-core-runtime.md](../design/3.0-core-runtime.md).

## Scope

This pack covers TLS provider integration and QUIC adapter boundaries used by HTTP/3.

## Hard Invariants

- TLS keys and secrets must not be logged. See [design/1.3-invariants.md](../design/1.3-invariants.md).
- Protocol errors must close connections with correct error codes. See [design/1.3-invariants.md](../design/1.3-invariants.md).
- Request size limits must be enforced at parse time, even with TLS. See [design/1.3-invariants.md](../design/1.3-invariants.md).

## Responsibilities

- Provide a stable interface for TLS handshakes, ALPN, and record processing.
- Allow optional TLS and QUIC dependencies via build-time feature flags.
- Map TLS and QUIC errors to canonical protocol error categories.

## Build Flags

- `-Denable-tls` enables the TLS provider integration.
- `-Denable-http3` enables HTTP/3 via QUIC and requires TLS/QUIC availability.

## Inputs and Outputs

See [design/1.4-contracts.md](../design/1.4-contracts.md) for TLS provider and QUIC adapter tables.

## Non-goals

- Writing a custom TLS or QUIC implementation.
- Managing certificate issuance or rotation workflows.
