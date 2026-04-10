# Design Docs Index

## Docs

- [1.0-intro.md](1.0-intro.md) - Scope, goals, architecture, invariants, and validation for the Zig webserver.
- [1.1-user-stories.md](1.1-user-stories.md) - Personas and user stories for server requirements.
- [1.2-requirements.md](1.2-requirements.md) - Functional requirements mapped to personas and stories.
- [1.3-invariants.md](1.3-invariants.md) - Runtime, protocol, and security invariants.
- [1.4-contracts.md](1.4-contracts.md) - Input/output contracts for core components.
- [2.0-architecture.md](2.0-architecture.md) - System diagrams, data flow, and subsystem boundaries.
- [3.0-core-runtime.md](3.0-core-runtime.md) - Core runtime primitives: connection lifecycle, buffers, backpressure, timeouts.
- [3.1-connection-lifecycle.md](3.1-connection-lifecycle.md) - Connection state, lifecycle, and shutdown semantics.
- [3.2-buffer-management.md](3.2-buffer-management.md) - Buffer pool design, ownership, and reuse rules.
- [3.3-backpressure-timeouts.md](3.3-backpressure-timeouts.md) - Backpressure thresholds and timeout enforcement.
- [3.4-event-loop-integration.md](3.4-event-loop-integration.md) - Event model and runtime scheduling loop.
- [3.5-allocator-memory-layout.md](3.5-allocator-memory-layout.md) - Allocator strategy, memory layout, and sizing rules.
- [3.6-worker-scheduling.md](3.6-worker-scheduling.md) - Worker model, scheduling, and affinity.
- [3.7-protocol-handoff.md](3.7-protocol-handoff.md) - Zero-copy handoff and protocol selection.
- [3.8-metrics-telemetry.md](3.8-metrics-telemetry.md) - Runtime metrics, counters, and telemetry events.
- [3.9-error-shutdown-policy.md](3.9-error-shutdown-policy.md) - Canonical error classes and shutdown behavior.
- [3.10-file-io-zero-copy.md](3.10-file-io-zero-copy.md) - File-backed responses and zero-copy strategies.
- [3.11-config-feature-flag-validation.md](3.11-config-feature-flag-validation.md) - Config validation and feature-flag rules.
- [4.0-x402-payments.md](4.0-x402-payments.md) - HTTP 402 payment flow and x402 integration.
- [5.0-reverse-proxy.md](5.0-reverse-proxy.md) - Reverse proxy architecture, forwarding flow, and upstream behavior.
- [6.0-middleware.md](6.0-middleware.md) - Middleware chain, context propagation, and built-in middleware behavior.
- [7.0-rfc-compliance-index.md](7.0-rfc-compliance-index.md) - RFC compliance tracking index for HTTP, proxy, and transport behavior.
- [8.0-h3-performance-plan.md](8.0-h3-performance-plan.md) - h3 fast-path engineering plan targeting HttpArena submission.

## Subdirectories

- None.

## Related Code Paths

- [src/](../../src/) - Server runtime and protocol implementations.
