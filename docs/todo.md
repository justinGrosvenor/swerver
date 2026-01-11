# Swerver Code Review Findings & TODO

This document captures findings from a thorough code review of the Swerver codebase conducted on 2026-01-10. Items are organized by priority and category.

---

## Critical Bugs

### 1. Memory Leak in x402 Payload Initialization

**File:** `src/main.zig:10-14`

```zig
if (cfg.x402.enabled and cfg.x402.payment_required_b64.len == 0) {
    const payload = try x402.demoPaymentRequiredB64(allocator, "http://localhost:8080/");
    defer allocator.free(payload);  // BUG: frees immediately after this scope
    cfg.x402.payment_required_b64 = payload;
}
```

**Problem:** The `defer` statement frees the allocated payload at the end of the `if` block, but `cfg` is passed to `server.run()` which will access freed memory.

**Fix:** Remove the `defer` and either:
- Free the payload in `Server.deinit()`, or
- Store the payload in the Server struct with ownership, or
- Use a static/comptime string for demo mode

**Severity:** Critical - Use-after-free leading to undefined behavior

---

### 2. Invalid Enum Cast in HTTP/2 Frame Parsing

**File:** `src/protocol/http2.zig:114`

```zig
const typ: FrameType = @enumFromInt(buf[offset + 3]);
```

**Problem:** If the byte value doesn't correspond to a valid `FrameType` enum variant (0x0-0x9), this will panic at runtime.

**Fix:** Validate the byte value before casting:
```zig
const type_byte = buf[offset + 3];
if (type_byte > 0x9) {
    // Return protocol error or skip unknown frame type per RFC 7540
}
const typ: FrameType = @enumFromInt(type_byte);
```

**Severity:** Critical - Panic on malformed input (denial of service)

---

### 3. Potential Integer Truncation in Timeout Calculation

**File:** `src/runtime/connection.zig:169`

```zig
return @intCast(limit - elapsed);
```

**Problem:** Both `limit` and `elapsed` derive from `u64` timestamps. While the subtraction result should fit in `u32` given the timeout values, there's no explicit bounds checking.

**Fix:** Add explicit bounds check or use `@min()`:
```zig
const remaining = limit - elapsed;
return if (remaining > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(remaining);
```

**Severity:** Medium - Could cause unexpected behavior on edge cases

---

## Security Vulnerabilities

### 4. No Request Rate Limiting

**Files:** `src/server.zig`, `src/runtime/connection.zig`

**Problem:** No mechanism exists to limit:
- Connections per IP address
- Requests per connection per time window
- Total request rate across all connections

A malicious actor can exhaust server resources through connection flooding or request flooding.

**Recommendation:**
- [ ] Add per-IP connection tracking with configurable limits
- [ ] Add request rate limiting per connection
- [ ] Add global request rate limiting with token bucket algorithm
- [ ] Add configurable limits in `ServerConfig`

**Severity:** High - Denial of service vulnerability

---

### 5. Slowloris Attack Vulnerability

**File:** `src/config.zig:59-60`

```zig
idle_ms: u32 = 60_000,
header_ms: u32 = 10_000,
```

**Problem:** The header timeout of 10 seconds allows slow header attacks where an attacker sends headers byte-by-byte to hold connections open. The current implementation only tracks time since last activity, not progress.

**Recommendation:**
- [ ] Add minimum bytes-per-second requirement during header phase
- [ ] Add maximum total time for header reception regardless of activity
- [ ] Consider shorter default header timeout (e.g., 5 seconds)

**Severity:** Medium - Resource exhaustion attack vector

---

### 6. No Host Header Validation

**File:** `src/protocol/http1.zig:269-270`

```zig
if (std.ascii.eqlIgnoreCase(name, "host")) {
    host_present = value.len != 0;
}
```

**Problem:** The Host header is only checked for presence, not validated against allowed hostnames. This enables:
- DNS rebinding attacks
- Virtual host confusion
- Cache poisoning in downstream proxies

**Recommendation:**
- [ ] Add `allowed_hosts: [][]const u8` to `ServerConfig`
- [ ] Validate Host header against allowed list
- [ ] Return 400 Bad Request for invalid hosts

**Severity:** Medium - Multiple attack vectors

---

### 7. x402 Payment Middleware is Non-Functional

**File:** `src/middleware/x402.zig:43-46`

```zig
pub fn evaluate(req: request.RequestView, policy: Policy) Decision {
    _ = req;  // Request is completely ignored!
    if (!policy.require_payment) return .allow;
    return .{ .reject = paymentRequired(policy.payment_required_b64) };
}
```

**Problem:** The payment evaluation function ignores the actual request entirely. It doesn't:
- Check for payment tokens/signatures
- Validate payment proofs
- Implement any actual payment verification

All requests are either always allowed or always blocked based solely on config.

**Recommendation:**
- [ ] Implement actual payment header parsing (`X-PAYMENT` or similar)
- [ ] Implement payment signature verification
- [ ] Add payment amount/asset validation
- [ ] Or clearly document this as a stub requiring implementation

**Severity:** High if payment protection is expected to work

---

## Platform Support Issues

### 8. Linux Backend Not Implemented

**File:** `src/runtime/io.zig:54-68`

```zig
pub fn pollWithTimeout(self: *IoRuntime, timeout_ms: u32) ![]const Event {
    return switch (self.backend_state) {
        .bsd_kqueue => |*kq| { ... },
        else => {
            if (timeout_ms > 0) {
                sleepMs(timeout_ms);
            }
            return &[_]Event{};  // No events ever returned!
        },
    };
}
```

**Problem:** On Linux (and Windows), the server compiles but does nothing useful. It just sleeps and returns no events, meaning:
- No connections are ever accepted
- No data is ever read or written
- The server is completely non-functional

**File:** `src/runtime/net.zig:172-176`

```zig
fn isSupportedPlatform() bool {
    return switch (builtin.os.tag) {
        .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
        else => false,  // Linux returns false!
    };
}
```

**Problem:** Socket operations explicitly reject Linux, meaning `listen()` and `accept()` fail immediately.

**Recommendation:**
- [ ] Implement `epoll` backend in `src/runtime/backend/epoll.zig`
- [ ] Update `pickBackend()` to return `.linux_epoll` for Linux
- [ ] Update `initBackend()` to initialize epoll state
- [ ] Update `net.zig` to support Linux socket structures
- [ ] Add Linux to `isSupportedPlatform()`

**Severity:** Critical - Server non-functional on Linux (major target platform)

---

### 9. Windows Backend Not Implemented

**File:** `src/runtime/io.zig:200-214`

Similar to Linux, Windows IOCP is declared but not implemented.

**Recommendation:**
- [ ] Implement `iocp` backend in `src/runtime/backend/iocp.zig`
- [ ] Update backend initialization for Windows
- [ ] Update `net.zig` for Windows socket APIs

**Severity:** High - Server non-functional on Windows

---

## Incomplete Features

### 10. HTTP/2 Parsed But Not Used

**Files:** `src/server.zig:32-34`, `src/server.zig:127-156`

```zig
// In init():
const http2_stack: ?http2.Stack = if (build_options.enable_http2) http2.Stack.init() else null;

// In handleRead() - only HTTP/1.1 is used:
const parse = http1.parse(buffer_handle.bytes[start..end], .{ ... });
```

**Problem:** The HTTP/2 stack is initialized but never consulted. All connections are handled as HTTP/1.1 regardless of:
- ALPN negotiation (not implemented)
- Connection preface detection
- Upgrade header handling

**Recommendation:**
- [ ] Detect HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
- [ ] Route connections to appropriate protocol handler
- [ ] Implement TLS ALPN for h2 negotiation
- [ ] Add HTTP/1.1 Upgrade header handling for h2c

**Severity:** High - Advertised feature doesn't work

---

### 11. HTTP/3 is Entirely Stubbed

**File:** `src/protocol/http3.zig`

```zig
// Entire file is 9 lines with no implementation
```

**Problem:** HTTP/3 requires QUIC transport which is not implemented.

**Recommendation:**
- [ ] Either remove HTTP/3 from documentation/build flags, or
- [ ] Implement QUIC transport layer
- [ ] Implement HTTP/3 framing on top of QUIC

**Severity:** Medium - Advertised feature not available

---

### 12. TLS Provider is Stubbed

**File:** `src/tls/provider.zig`

```zig
// Only 5 lines, no actual implementation
```

**Problem:** TLS is required for production HTTPS and for HTTP/2 (via ALPN).

**Recommendation:**
- [ ] Integrate with system TLS (Security.framework on macOS, OpenSSL on Linux)
- [ ] Or integrate with a Zig-native TLS library
- [ ] Implement certificate loading and management
- [ ] Implement ALPN for protocol negotiation

**Severity:** High - No HTTPS support

---

### 13. No HPACK Huffman Decoding

**File:** `src/protocol/http2.zig:463`

```zig
fn decodeString(self: *HpackDecoder, buf: []const u8, idx: *usize) ![]const u8 {
    // ...
    const huffman = (first & 0x80) != 0;
    if (huffman) return error.HuffmanUnsupported;  // Rejects Huffman-encoded strings
    // ...
}
```

**Problem:** Many HTTP/2 clients send Huffman-encoded header values by default. These are rejected, causing connection failures.

**Recommendation:**
- [ ] Implement Huffman decoding table from RFC 7541 Appendix B
- [ ] Add Huffman decode function
- [ ] Update `decodeString` to handle Huffman-encoded values

**Severity:** High - HTTP/2 interoperability issue

---

### 14. Router Has No Actual Routing

**File:** `src/router/router.zig`

```zig
pub fn handle(self: *Router, req: request.RequestView) response.Response {
    switch (x402.evaluate(req, self.policy)) {
        .allow => {},
        .reject => |resp| return resp,
    }
    return response.Response.ok();  // Always returns 200 OK with empty body
}
```

**Problem:** The router:
- Has no path matching
- Has no method dispatch
- Has no handler registration
- Cannot serve files or dynamic content

**Recommendation:**
- [ ] Add route registration API (`router.get("/path", handler)`)
- [ ] Implement path matching (exact, prefix, pattern)
- [ ] Add method-based dispatch
- [ ] Add middleware chain support
- [ ] Add static file serving handler

**Severity:** High - Server can't serve useful content

---

### 15. No Static File Serving

**Problem:** There's no way to serve files from the filesystem.

**Recommendation:**
- [ ] Add `StaticFileHandler` with configurable root directory
- [ ] Implement MIME type detection
- [ ] Add directory index support (index.html)
- [ ] Implement range requests for large files
- [ ] Add caching headers (ETag, Last-Modified)
- [ ] Consider sendfile/splice for zero-copy serving

**Severity:** High - Basic web server functionality missing

---

### 16. No Graceful Shutdown

**Files:** `src/main.zig`, `src/server.zig`

**Problem:** The server has no signal handling and cannot:
- Catch SIGTERM/SIGINT
- Stop accepting new connections
- Drain existing connections gracefully
- Exit cleanly

**Recommendation:**
- [ ] Add signal handler registration
- [ ] Add `Server.shutdown()` method
- [ ] Implement connection draining with timeout
- [ ] Add shutdown hook for cleanup

**Severity:** Medium - Ungraceful termination loses in-flight requests

---

### 17. No Configuration File Support

**File:** `src/main.zig`

**Problem:** All configuration is hardcoded. No way to:
- Load config from file (TOML, JSON, etc.)
- Override via environment variables
- Pass via command line flags (except `--run-for-ms`)

**Recommendation:**
- [ ] Add TOML or JSON config file parsing
- [ ] Add environment variable overrides
- [ ] Add comprehensive CLI argument parsing
- [ ] Add config validation with helpful error messages

**Severity:** Medium - Difficult to deploy/configure

---

### 18. No Logging or Metrics

**Problem:** The server has no observability:
- No request logging
- No error logging
- No metrics (request count, latency, error rate)
- No health check endpoint

**Recommendation:**
- [ ] Add structured logging with configurable levels
- [ ] Add access log in common format
- [ ] Add Prometheus-compatible metrics endpoint
- [ ] Add health check endpoint (`/health`, `/ready`)
- [ ] Add request ID tracking

**Severity:** Medium - Cannot debug or monitor in production

---

## Code Quality Issues

### 19. Silently Ignored Transition Errors

**File:** `src/server.zig:96`

```zig
_ = conn.transition(.active, now_ms) catch {};
```

**Problem:** Connection state transition errors are silently ignored. If a transition fails, the connection may be in an inconsistent state.

**Recommendation:**
- [ ] Log transition errors
- [ ] Close connection on invalid transition
- [ ] Or restructure to prevent invalid transitions

**Severity:** Low - May cause subtle bugs

---

### 20. Hardcoded HTTP/2 Limits

**File:** `src/protocol/http2.zig:204-212`

```zig
const MaxHeaders = 64;
const HeaderScratchBytes = 4096;
const HeaderBlockBytes = 8192;
const MaxDynamicEntries = 64;
const MaxDynamicBytes = 4096;
const MaxStreams = 128;
```

**Problem:** These limits should be configurable through `ServerConfig`, not hardcoded.

**Recommendation:**
- [ ] Add HTTP/2 specific config section
- [ ] Make limits configurable
- [ ] Document default values and constraints

**Severity:** Low - Inflexible for different workloads

---

### 21. Duplicate Header Struct Definitions

**Files:** `src/protocol/request.zig:1-4`, `src/response/response.zig:1-4`

Both files define identical `Header` structs.

**Recommendation:**
- [ ] Create shared `src/common/header.zig`
- [ ] Import from single location

**Severity:** Low - Code duplication

---

## Performance Concerns

### 22. Linear Stream Lookup in HTTP/2

**File:** `src/protocol/http2.zig:749-754`

```zig
fn findStream(self: *Stack, stream_id: u32) ?*Stream {
    for (self.streams[0..self.stream_count]) |*stream| {
        if (stream.id == stream_id) return stream;
    }
    return null;
}
```

**Problem:** O(n) lookup for every frame on a stream. With 128 max streams and many frames per request, this adds latency.

**Recommendation:**
- [ ] Use hash map for stream lookup
- [ ] Or use stream_id as direct index (client streams are odd, so `(stream_id - 1) / 2`)

**Severity:** Low - Performance optimization

---

### 23. Memory Copy in Chunked Transfer Decoding

**File:** `src/protocol/http1.zig:533`

```zig
if (dst != src) std.mem.copyForwards(u8, buf[dst..dst + size], buf[src..src + size]);
```

**Problem:** In-place chunked decoding requires memory moves which can be slow for large bodies.

**Recommendation:**
- [ ] Consider streaming decode without reassembly
- [ ] Or document the trade-off (simplicity vs. performance)

**Severity:** Low - Performance optimization for large chunked bodies

---

### 24. No Connection Keep-Alive Pooling

**Problem:** Closed connections are fully reset. For high-churn workloads, keeping connections "warm" in the pool could improve performance.

**Recommendation:**
- [ ] Consider connection recycling without full reset
- [ ] Benchmark to determine if this matters

**Severity:** Low - Micro-optimization

---

## Testing Gaps

### 25. Missing Test Categories

**File:** `src/tests.zig`

Current tests cover:
- Buffer pool operations
- Connection pool operations
- HTTP/1.1 parsing (various cases)
- HTTP/2 frame parsing

Missing tests:
- [ ] Integration tests (actual HTTP requests through the server)
- [ ] Timeout enforcement tests
- [ ] Backpressure behavior tests
- [ ] Concurrent connection tests
- [ ] Connection state machine transitions
- [ ] Error path coverage
- [ ] Malformed input fuzzing
- [ ] Edge cases for buffer boundaries
- [ ] Pipelining behavior

**Severity:** Medium - Reduced confidence in correctness

---

### 26. No Fuzz Testing

**Problem:** HTTP parsers are prime targets for fuzzing to find edge cases and crashes.

**Recommendation:**
- [ ] Add fuzz testing for HTTP/1.1 parser
- [ ] Add fuzz testing for HTTP/2 parser
- [ ] Add fuzz testing for HPACK decoder
- [ ] Integrate with Zig's built-in fuzzing or AFL

**Severity:** Medium - Security and reliability concern

---

## Documentation Gaps

### 27. Missing API Documentation

**Problem:** Public functions lack doc comments explaining:
- Purpose and behavior
- Parameters and return values
- Error conditions
- Thread safety (if applicable)

**Recommendation:**
- [ ] Add doc comments to all public functions
- [ ] Generate documentation with `zig build docs`

**Severity:** Low - Developer experience

---

### 28. Missing Deployment Guide

**Problem:** No documentation on how to:
- Build for production
- Configure for different workloads
- Deploy behind a reverse proxy
- Monitor and troubleshoot

**Recommendation:**
- [ ] Add `docs/deployment.md`
- [ ] Add example configurations
- [ ] Add troubleshooting guide

**Severity:** Low - Adoption barrier

---

## Summary Checklist

### P0 - Must Fix Before Any Use
- [x] Fix memory leak in `main.zig` x402 payload ✓ FIXED
- [x] Fix HTTP/2 frame type enum cast panic ✓ FIXED
- [ ] Implement Linux epoll backend

### P1 - Required for Production
- [ ] Add request rate limiting
- [ ] Implement actual routing with handlers
- [ ] Add TLS support
- [ ] Integrate HTTP/2 into request pipeline
- [ ] Add logging infrastructure
- [ ] Implement graceful shutdown
- [ ] Add static file serving

### P2 - Important Improvements
- [x] ~~Add Huffman decoding for HTTP/2~~ - Already implemented!
- [ ] Add Host header validation
- [ ] Add configuration file support
- [ ] Add metrics endpoint
- [ ] Implement Windows IOCP backend
- [ ] Add integration tests

### P3 - Nice to Have
- [x] Optimize HTTP/2 stream lookup ✓ FIXED
- [ ] Add fuzz testing
- [ ] Add API documentation
- [ ] Add deployment guide
- [x] Deduplicate Header structs ✓ FIXED

---

## Second Audit - Additional Findings

The following issues were discovered in a deeper code review focusing on existing implementation bugs.

---

### 29. File Descriptor Leak on Buffer Acquisition Failure

**File:** `src/server.zig:82-93`

```zig
fn handleAccept(self: *Server, listen_fd: std.posix.fd_t) void {
    const now_ms = self.io.nowMs();
    const conn = self.io.acquireConnection(now_ms) orelse return;
    errdefer self.io.releaseConnection(conn);
    const client_fd = net.accept(listen_fd) orelse return;  // FD leaked here!
    // ...
}
```

**Problem:** If `net.accept()` succeeds but subsequent operations fail (buffer acquisition, registration), the `client_fd` is never closed. The `errdefer` only releases the connection, not the file descriptor.

**Fix:** Add `errdefer std.posix.close(client_fd)` after the accept call.

**Severity:** High - File descriptor exhaustion under load

---

### 30. Silent Response Failure Leaves Client Hanging

**File:** `src/server.zig:195-196` (in `queueResponse`)

```zig
const buffer_handle = self.io.acquireBuffer() orelse return;
const len = response.encode(buffer_handle.bytes) catch return;
```

**Problem:** If buffer acquisition or encoding fails, the function returns silently without:
- Closing the connection
- Sending an error response
- Logging the failure

The client will hang waiting for a response that never comes.

**Fix:** On failure, transition connection to error state and close it.

**Severity:** High - Poor client experience, hard to debug

---

### 31. Partial Response on Data Frame Buffer Failure

**File:** `src/server.zig:298` (in HTTP/2 response path)

```zig
const data_buf = self.io.acquireBuffer() orelse return;
```

**Problem:** If buffer acquisition fails mid-response (after headers sent), the function returns without completing the response. The client receives partial data with no indication of failure.

**Fix:** Send RST_STREAM frame on failure, or pre-allocate all needed buffers.

**Severity:** Medium - Data corruption from client perspective

---

### 32. HTTP/2 Window Overflow Vulnerability

**File:** `src/protocol/http2.zig:847, 851`

```zig
self.conn_recv_window += @intCast(increment);
// ...
stream.recv_window += @intCast(increment);
```

**Problem:** WINDOW_UPDATE increments are added without checking for i32 overflow. An attacker could send many WINDOW_UPDATE frames to overflow the window, wrapping to negative, then bypassing flow control checks.

Per RFC 7540 Section 6.9: "A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets."

**Fix:** Check that window + increment <= 2^31-1, send FLOW_CONTROL_ERROR if exceeded.

**Severity:** High - Flow control bypass, potential memory exhaustion

---

### 33. HTTP/2 Stream Exhaustion (No Recycling)

**File:** `src/protocol/http2.zig:884-895`

```zig
fn getOrCreateStream(self: *Stack, stream_id: u32) ?*Stream {
    // ...
    if (self.stream_count >= self.streams.len) return null;  // No recycling!
    // ...
    self.stream_count += 1;
    // ...
}
```

**Problem:** Once 128 streams are created, no new streams can be created even if previous streams are closed. The `stream_count` only increases, never decreases.

A single connection making 128 requests will become unusable for further requests.

**Fix:** Recycle closed streams or implement stream ID tracking with cleanup.

**Severity:** High - Connection becomes unusable after 128 requests

---

### 34. HPACK Ring Buffer Overflow

**File:** `src/protocol/http2.zig:414-418`

```zig
const base = self.storage_tail;
@memcpy(self.storage[base .. base + name.len], name);
@memcpy(self.storage[base + name.len .. base + storage_len], value);
self.storage_tail = (self.storage_tail + storage_len) % self.storage.len;
```

**Problem:** If `base + storage_len > storage.len`, the `@memcpy` writes past the end of the storage buffer before the modulo wraps `storage_tail`. The `ensureStorage` function attempts to handle this but has edge cases.

**Fix:** Split the memcpy when wrapping around the ring buffer, or use a linear buffer with compaction.

**Severity:** High - Buffer overflow, potential memory corruption

---

### 35. Connection ID Truncation

**File:** `src/server.zig:73-75`

```zig
const conn_index: u32 = @intCast(ev.conn_id);  // conn_id is u64!
const conn = self.io.getConnection(conn_index) orelse continue;
```

**Problem:** `conn_id` is `u64` but cast to `u32` for indexing. If the connection ID exceeds `u32` max (after ~4 billion connections), this truncates and accesses the wrong connection.

While unlikely in practice, this could cause request/response misrouting after long uptime.

**Fix:** Use u64 consistently or reset connection IDs periodically.

**Severity:** Low - Only affects very long-running servers

---

### 36. HTTP/1.1 Header Value Not Trimmed at End

**File:** `src/protocol/http1.zig:246`

```zig
value = std.mem.trimStart(u8, value, " \t");
```

**Problem:** RFC 7230 Section 3.2.4 says optional whitespace (OWS) should be trimmed from both ends of header values. Only the start is trimmed here.

A header like `Content-Type: text/html   ` would retain trailing spaces.

**Fix:** Use `std.mem.trim()` instead of `trimStart()`.

**Severity:** Low - Minor protocol non-compliance

---

### 37. HTTP/1.1 Connection Header Multi-Value Handling

**File:** `src/protocol/http1.zig:334-339`

```zig
if (std.ascii.eqlIgnoreCase(name, "connection") and std.ascii.indexOfIgnoreCase(value, "close") != null) {
    keep_alive = false;
}
if (std.ascii.eqlIgnoreCase(name, "connection") and std.ascii.indexOfIgnoreCase(value, "keep-alive") != null) {
    if (std.mem.eql(u8, version, "HTTP/1.0")) keep_alive = true;
}
```

**Problem:** The Connection header can have multiple comma-separated tokens (e.g., `Connection: keep-alive, upgrade`). The current code uses substring search which could match partial tokens.

Example: `Connection: closeout` would incorrectly match "close".

**Fix:** Split on commas and match exact tokens.

**Severity:** Low - Edge case protocol handling

---

### 38. O(n) Timeout Scanning Every Poll Cycle

**File:** `src/runtime/io.zig:70-78, 136-144`

```zig
pub fn nextPollTimeoutMs(self: *IoRuntime, now_ms: u64) u32 {
    for (self.connections.entries) |*conn| {  // O(max_connections)
        // ...
    }
}

pub fn enforceTimeouts(self: *IoRuntime, now_ms: u64) void {
    for (self.connections.entries) |*conn| {  // O(max_connections) again
        // ...
    }
}
```

**Problem:** Both functions iterate all connection slots (2048 by default) on every poll cycle, even if most are unused. This is 2 * O(max_connections) per poll.

**Fix:** Maintain a linked list of active connections, or use a timer wheel.

**Severity:** Medium - CPU overhead scales with max_connections, not active connections

---

### 39. Kqueue Event Data Truncation

**File:** `src/runtime/io.zig:250-251`

```zig
.conn_id = @intCast(ev.udata),
.bytes = @intCast(ev.data),
```

**Problem:** `ev.data` is `isize` (platform-dependent, could be 64-bit). Casting to `usize` is fine, but `@intCast` will panic if the value is negative (which kqueue can return for errors).

**Fix:** Handle negative values explicitly or use `@bitCast`.

**Severity:** Medium - Panic on certain kqueue error conditions

---

### 40. HTTP/2 Flow Control Sign Mismatch

**File:** `src/protocol/http2.zig:822-826`

```zig
if (data.len > @as(usize, @intCast(self.conn_recv_window))) {
    return .{ .state = .err, .error_code = .flow_control_error, .event_count = 0 };
}
```

**Problem:** `conn_recv_window` is `i32`. If it goes negative (possible through bugs or attacks), `@intCast` to `usize` will panic.

**Fix:** Check `conn_recv_window <= 0` first, or use saturating arithmetic.

**Severity:** Medium - Panic on negative window (reachable via issue #32)

---

### 41. Chunked Encoding Size Parsing Accepts Leading Zeros

**File:** `src/protocol/http1.zig:570-574`

```zig
fn parseChunkSize(line: []const u8) !usize {
    const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
    const size_str = line[0..semi];
    if (size_str.len == 0) return error.InvalidChunk;
    return std.fmt.parseInt(usize, size_str, 16) catch return error.InvalidChunk;
}
```

**Problem:** `std.fmt.parseInt` accepts leading zeros. While not strictly a bug, some strict HTTP implementations reject chunk sizes with leading zeros (e.g., `0000a` instead of `a`).

**Severity:** Very Low - Strict compliance issue

---

### 42. Missing Validation for HTTP/2 SETTINGS Values

**File:** `src/protocol/http2.zig:871-882`

```zig
fn applySetting(self: *Stack, id: u16, value: u32) !void {
    switch (id) {
        0x1 => self.decoder.setMaxSize(value),
        0x4 => self.max_frame_size = value,  // No validation!
        // ...
    }
}
```

**Problem:** SETTINGS_MAX_FRAME_SIZE (0x4) must be between 16384 and 16777215 per RFC 7540. Values outside this range should trigger PROTOCOL_ERROR. Currently any value is accepted.

**Fix:** Validate: `if (value < 16384 or value > 16777215) return error.InvalidSetting;`

**Severity:** Medium - Protocol non-compliance, potential for oversized frames

---

### 43. HTTP/2 GOAWAY Not Handled

**File:** `src/protocol/http2.zig:720`

```zig
else => .{ .state = .complete, .error_code = .none, .event_count = 0 },
```

**Problem:** GOAWAY frames are silently ignored. When a server sends GOAWAY, the client should stop creating new streams and gracefully close. The current implementation ignores it entirely.

**Fix:** Handle GOAWAY by setting a flag to reject new streams and emit an event.

**Severity:** Medium - Poor connection management with HTTP/2 peers

---

### 44. HTTP/2 PRIORITY Frame Ignored

**File:** `src/protocol/http2.zig:720`

Same location - PRIORITY frames are parsed but ignored. While deprioritization is optional, completely ignoring priorities can cause suboptimal resource allocation.

**Severity:** Low - Performance optimization

---

### 45. No Bounds Check on Header Storage Index

**File:** `src/protocol/http1.zig:267`

```zig
_limits.headers_storage[header_count] = .{ .name = name, .value = value };
```

**Problem:** While there's a check at line 247 for `header_count >= max_header_count`, the actual bounds check is against `_limits.max_header_count`, not `_limits.headers_storage.len`. If these are misconfigured to differ, this could write out of bounds.

The check at line 36 validates `headers_storage.len < max_header_count` which catches one direction but not the other.

**Severity:** Low - Only if config is manually misconfigured

---

## Updated Summary Checklist

### P0 - Must Fix Before Any Use
- [x] Fix memory leak in `main.zig` x402 payload (#1) ✓ FIXED
- [x] Fix HTTP/2 frame type enum cast panic (#2) ✓ FIXED
- [ ] Implement Linux epoll backend (#8)
- [x] Fix HPACK ring buffer overflow (#34) ✓ FIXED

### P1 - Required for Production
- [x] Fix file descriptor leak on accept (#29) ✓ FIXED
- [x] Fix silent response failures (#30) ✓ FIXED
- [x] Fix HTTP/2 window overflow (#32) ✓ FIXED
- [x] Fix HTTP/2 stream exhaustion (#33) ✓ FIXED
- [ ] Add request rate limiting (#4)
- [ ] Implement actual routing with handlers (#14)
- [ ] Add TLS support (#12)
- [ ] Integrate HTTP/2 into request pipeline (#10)
- [ ] Add logging infrastructure (#18)
- [ ] Implement graceful shutdown (#16)

### P2 - Important Improvements
- [x] Fix O(n) timeout scanning (#38) ✓ FIXED - Now O(active) with active connection list
- [x] Fix kqueue event truncation (#39) ✓ FIXED
- [x] Fix HTTP/2 flow control sign issue (#40) ✓ FIXED
- [x] Validate HTTP/2 SETTINGS values (#42) ✓ FIXED
- [x] Handle GOAWAY frames (#43) ✓ FIXED
- [x] ~~Add Huffman decoding for HTTP/2 (#13)~~ - Already implemented!
- [ ] Add Host header validation (#6)
- [ ] Add configuration file support (#17)
- [ ] Add metrics endpoint (#18)
- [ ] Implement Windows IOCP backend (#9)
- [ ] Add integration tests (#25)

### P3 - Nice to Have
- [x] Fix header value trailing whitespace (#36) ✓ FIXED
- [x] Fix Connection header parsing (#37) ✓ FIXED
- [x] Optimize HTTP/2 stream lookup (#22) ✓ FIXED - Added last-accessed cache
- [x] Handle PRIORITY frames (#44) ✓ FIXED
- [ ] Add fuzz testing (#26)
- [ ] Add API documentation (#27)
- [ ] Add deployment guide (#28)
- [x] Deduplicate Header structs (#21) ✓ FIXED

### Additional Fixes (from code review)
- [x] Fix integer truncation in timeout calculation (#3) ✓ FIXED
- [x] Fix silently ignored transition errors (#19) ✓ FIXED
- [x] Fix connection ID truncation (#35) ✓ FIXED
- [x] Fix partial response on buffer failure (#31) ✓ FIXED
- [x] Fix header storage bounds check (#45) ✓ FIXED

---

## Summary of Completed Bug Fixes

**22 bugs fixed across 4 batches:**

| Issue | Description | File(s) |
|-------|-------------|---------|
| #1 | Memory leak in x402 payload | `main.zig` |
| #2 | HTTP/2 frame type enum panic | `http2.zig` |
| #3 | Integer truncation in timeout | `connection.zig` |
| #19 | Silently ignored transitions | `server.zig` |
| #21 | Duplicate Header structs | `response.zig` |
| #22 | Linear stream lookup O(n) | `http2.zig` |
| #29 | File descriptor leak on accept | `server.zig` |
| #30 | Silent response failure | `server.zig` |
| #31 | Partial response buffer failure | `server.zig` |
| #32 | HTTP/2 window overflow | `http2.zig` |
| #33 | HTTP/2 stream exhaustion | `http2.zig` |
| #34 | HPACK ring buffer overflow | `http2.zig` |
| #35 | Connection ID truncation | `server.zig` |
| #36 | Header value trailing whitespace | `http1.zig` |
| #37 | Connection header multi-value | `http1.zig` |
| #38 | O(n) timeout scanning | `connection.zig`, `io.zig` |
| #39 | Kqueue event data truncation | `io.zig` |
| #40 | HTTP/2 flow control sign | `http2.zig` |
| #42 | HTTP/2 SETTINGS validation | `http2.zig` |
| #43 | HTTP/2 GOAWAY handling | `http2.zig` |
| #44 | HTTP/2 PRIORITY frames | `http2.zig` |
| #45 | Header storage bounds check | `http1.zig` |

**Notes:**
- #13 (Huffman decoding) was already implemented - todo was outdated
- #41 (Chunked leading zeros) is not a bug - RFC 7230 allows leading zeros

---

*Last updated: 2026-01-10 (Bug fixes completed)*

---

## Feature Implementation: Reverse Proxy (5.0)

**Design Doc:** [5.0-reverse-proxy.md](design/5.0-reverse-proxy.md)

The reverse proxy is a major feature enabling swerver to act as a load balancer and gateway. Implementation should follow the design doc architecture.

### Implementation Phases

#### Phase 1: Core Infrastructure
- [ ] Create `src/proxy/` directory structure
- [ ] Implement `upstream.zig` - Upstream server definitions and configuration
- [ ] Implement `pool.zig` - Upstream connection pool management
- [ ] Implement `balancer.zig` - Load balancing algorithms (round_robin, least_conn, ip_hash, weighted)

#### Phase 2: Request Forwarding
- [ ] Implement `forward.zig` - Request/response forwarding logic
- [ ] Add hop-by-hop header removal (Connection, Keep-Alive, etc.)
- [ ] Add standard proxy headers (X-Forwarded-For, X-Real-IP, Via)
- [ ] Implement header manipulation rules (set/remove request/response headers)
- [ ] Support zero-copy body forwarding where possible

#### Phase 3: Proxy Handler Integration
- [ ] Implement `proxy.zig` - Main proxy handler
- [ ] Add `ProxyRoute` matching (path prefix, host-based routing)
- [ ] Integrate with router - add `router.proxy("/api/", upstream)` API
- [ ] Add proxy-specific timeouts (connect, send, read, total)

#### Phase 4: Health Checking
- [ ] Implement `health.zig` - Health check logic
- [ ] Add passive health checks (track failures per server)
- [ ] Add active health checks (periodic HTTP probes)
- [ ] Implement server availability state machine
- [ ] Add circuit breaker pattern (optional)

#### Phase 5: Advanced Features
- [ ] Implement `websocket.zig` - WebSocket upgrade proxying
- [ ] Add HTTP/2 upstream support (single multiplexed connection)
- [ ] Add retry logic for idempotent requests
- [ ] Add configurable retry on 502/503/504

#### Phase 6: Observability
- [ ] Add proxy-specific metrics (proxy_requests_total, upstream_connect_duration_ms, etc.)
- [ ] Add access log fields (upstream_addr, upstream_status, upstream_response_time)
- [ ] Add health status metrics per upstream

### Build Integration
- [ ] Add `-Denable-proxy` build flag
- [ ] Ensure proxy code excluded when flag disabled
- [ ] Add proxy configuration to `ServerConfig`

### Testing
- [ ] Unit tests for load balancing algorithms
- [ ] Unit tests for header manipulation
- [ ] Integration tests for request forwarding
- [ ] Integration tests for failover behavior
- [ ] Integration tests for WebSocket proxying
- [ ] Load tests measuring proxy overhead

### Key Files to Create
| File | Responsibility |
|------|----------------|
| `src/proxy/proxy.zig` | Main proxy handler |
| `src/proxy/upstream.zig` | Upstream definitions |
| `src/proxy/pool.zig` | Connection pool management |
| `src/proxy/balancer.zig` | Load balancing algorithms |
| `src/proxy/health.zig` | Health check logic |
| `src/proxy/forward.zig` | Request/response forwarding |
| `src/proxy/websocket.zig` | WebSocket tunnel handling |

### Invariants (from design doc)
1. Upstream connections must be returned to pool or closed; never leaked
2. Client must receive a response even if all upstreams fail
3. Hop-by-hop headers must never be forwarded
4. Health check failures must not block request handling
5. Connection pool must respect configured limits
6. Retry must not occur for non-idempotent methods unless explicitly configured
7. WebSocket upgrade must be atomic (no partial state)

---

## Recently Completed (2026-01-11)

### Spec Compliance Fixes
- [x] Per-stream metrics for HTTP/2 with stream_id labels in `/metrics`
- [x] onExit observability hooks with eBPF counter interface
- [x] Rate limiter backpressure integration (pause reads when bucket empty)
- [x] Connection-level `read_paused` with automatic resume timer

### Benchmark Endpoints
- [x] `/health` - minimal health check (empty 200)
- [x] `/echo` GET - returns `{"status":"ok"}`
- [x] `/echo` POST - echoes request body
- [x] `/blob` - 1MB response for throughput testing
- [x] `/plaintext` - TechEmpower plaintext test ("Hello, World!")
- [x] `/json` - TechEmpower JSON test (`{"message":"Hello, World!"}`)

### Backpressure Flow (implemented)
```
Rate limiter → middleware → router (RouteResult) → server
    ↓
conn.setRateLimitPause(now_ms, resume_after_ms)
    ↓
handleRead checks canRead() → skips read if paused
    ↓
checkRateLimitResume() clears pause when timer expires
```

---

*Last updated: 2026-01-11 (Reverse proxy todo added, spec compliance fixes documented)*
