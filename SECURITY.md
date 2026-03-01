# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in swerver, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **jgrosvenor415@gmail.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You should receive a response within 48 hours. Once the issue is confirmed, a fix will be developed and released as soon as possible.

## Scope

This policy covers the swerver codebase, including:

- HTTP/1.1 request parsing and response handling
- QUIC/HTTP3 protocol implementation
- Reverse proxy and load balancing
- TLS integration
- Middleware (access logging, metrics, x402 payments)

## Supported Versions

As swerver is pre-1.0, security fixes are applied to the latest version on the `main` branch only.
