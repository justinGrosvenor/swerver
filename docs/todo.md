# Swerver Code Audit Findings & TODO (Round 4)

Previous audits: Round 1 (23 fixed), Round 2 (20 fixed), Round 3 (8 fixed).
This round focuses on error paths, resource leaks, edge cases, and logic bugs.

---

## Critical

### 1. HPACK ensureStorage() Infinite Loop (DoS)

**File:** `src/protocol/http2.zig:476-511`

**Problem:** `ensureStorage()` has a `while(true)` loop (line 494) that calls `evictOldest()`. When `entry_count` reaches 0, `evictOldest()` becomes a no-op but the loop continues forever. This happens when a single header entry requires more space than the entire storage buffer (4096 bytes). A malicious client can send one HPACK entry > 4KB to hang the server.

**Fix:** Break the loop when `entry_count == 0` and `needed > storage.len - storage_used`, or add `if (self.entry_count == 0) return;` guard after `evictOldest()` in the loop.

**Severity:** Critical - CPU hang / infinite loop DoS

---

### 2. HTTP/2 CONTINUATION Loses END_STREAM Flag from HEADERS

**File:** `src/protocol/http2.zig:856-877, 880-908`

**Problem:** When a HEADERS frame has END_STREAM=1 but not END_HEADERS, `handleHeaders()` computes `end_stream` at line 859 but never stores it on the Stream struct. When the completing CONTINUATION arrives, `handleContinuation()` hardcodes `.end_stream = false` at line 903. The stream remains `.open` instead of transitioning to `.half_closed_remote`.

**Fix:** Add `end_stream_pending: bool` field to Stream struct. Set it in `handleHeaders()` when `header_block_in_progress` is true. Use it in `handleContinuation()` when the header block completes.

**Severity:** Critical - HTTP/2 protocol violation; request body handling incorrect

---

## High

### 3. HTTP/2 Stream Pool Exhaustion (No Reuse of Closed Streams)

**File:** `src/protocol/http2.zig:1055-1086`

**Problem:** `getOrCreateStream()` increments `stream_count` when creating new streams. Closed streams are only reused when `findStream()` finds them by ID, not when creating new streams. Once `stream_count` reaches `MaxStreams` (128), new streams are rejected with null even if many slots hold closed streams.

**Fix:** In `getOrCreateStream()`, when `stream_count >= streams.len`, scan for a closed stream to reuse instead of returning null.

**Severity:** High - HTTP/2 connections become unusable after 128 total streams

---

## Low

### 4. HPACK Decoder Circular Buffer Index Underflow

**File:** `src/protocol/http2.zig:544`

**Problem:** `(self.entry_head + self.entry_count - dynamic_index) % self.entries.len` — if `entry_head + entry_count < dynamic_index`, the subtraction wraps to a huge value. The modulo then gives wrong index. Checked by `dynamic_index > self.entry_count` guard at line 541, so this is defense-in-depth only.

**Fix:** Already guarded; add assertion for safety.

**Severity:** Low - Defense-in-depth

---

## Verified False Positives (Not Fixing)

- Thread-safety of BufferPool/ConnectionPool: Server is single-threaded event-loop; no races possible
- Static ack_ranges_buf: Single-threaded; safe
- QUIC frame offset underflow: varint.decode returns error before offset exceeds buf.len
- HTTP/2 flow control cast: Check for <= 0 happens before @intCast to usize
