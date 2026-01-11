# Context Pack: Protocol Stack

Reference architecture: [design/2.0-architecture.md](../design/2.0-architecture.md).
Reference contracts: [design/1.4-contracts.md](../design/1.4-contracts.md).
Reference core runtime: [design/3.0-core-runtime.md](../design/3.0-core-runtime.md).

## Scope

This pack covers HTTP/1.1 parsing, HTTP/2 framing and HPACK, and HTTP/3 integration via QUIC.

## Hard Invariants

- HTTP/1.1 parsing must reject invalid or ambiguous header framing. See [design/1.3-invariants.md](../design/1.3-invariants.md).
- HTTP/2 stream state transitions must follow RFC-defined state machine rules. See [design/1.3-invariants.md](../design/1.3-invariants.md).
- HTTP/3 flow control must prevent unbounded send queues. See [design/1.3-invariants.md](../design/1.3-invariants.md).

## Responsibilities

- Parse requests into zero-copy views and hand off to routing.
- Enforce protocol-specific limits and error codes.
- Provide a unified request/response API across protocols.
- Support protocol feature flags for build-time inclusion.
- Allow optional middleware (including x402 payment flow) to gate responses.

## Build Flags

- `-Denable-http2` enables the HTTP/2 stack.
- `-Denable-http3` enables the HTTP/3 stack (requires QUIC/TLS support).

## Inputs and Outputs

See [design/1.4-contracts.md](../design/1.4-contracts.md) for the HTTP/1.1, HTTP/2, and QUIC/HTTP/3 tables.

## Non-goals

- Implementing TLS record encryption or QUIC transport internals.
- Defining application-level business logic.
