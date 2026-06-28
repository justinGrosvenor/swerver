//! Per-worker park registry for WASM async host calls (design 10.0, Phase 3b).
//!
//! When a filter stages a host_call and parks, its instance is pinned
//! (filter.invokeOutcome leaves it `.parked`) and an entry is recorded here,
//! tying the pinned instance to the HTTP connection that is waiting. When the
//! outbound call completes on the reactor, `complete(token, result)` resumes the
//! filter (re-enters on_resume) and yields the terminal Decision plus the
//! connection linkage the server needs to deliver it. Failures, wall-clock
//! deadlines, and client disconnects each release the pinned instance.
//!
//! This is the transport-agnostic core: it knows nothing about sockets. The
//! reactor transport (an async outbound client on the external-fd primitive) and
//! the server resume glue (mirroring pgResume: queue the response / re-dispatch,
//! restart connection I/O) drive it. Modeled on the PG park table
//! (db/pg/client.zig): fixed slots, generation-checked, tick-driven timeouts.
//!
//! Compiled only when build_options.enable_wasm is set.

const std = @import("std");
const filter = @import("filter.zig");
const middleware = @import("../middleware/middleware.zig");
const request = @import("../protocol/request.zig");

pub const Token = u32;
pub const INVALID_TOKEN: Token = std.math.maxInt(u32);

/// Which HTTP protocol the parked stream belongs to. Reuses the canonical
/// h1/h2/h3 enum so the resume path can route delivery (H1 queueResponse vs the
/// H2/H3 stream-correct sends wired in E2). H1 is the only protocol that parks
/// today; H2/H3 set the real value once E2 lands.
pub const Protocol = middleware.Context.Protocol;

/// Bounded backing storage for a park's OWNED request snapshot. Parks are rare,
/// so a per-slot copy is cheap, and owning it frees the resume path from
/// depending on the connection's read buffer (H1) or a reused frame buffer
/// (H2/H3) staying pinned. A request whose method/path/headers/body do not fit
/// these bounds fails the park (the caller fails closed), matching the
/// table-full behavior. method_raw + path + header name/value bytes + a small
/// body all share `buf`.
const SNAP_BUF_CAP = 4096;
const SNAP_MAX_HEADERS = 32;

const ReqSnapshot = struct {
    buf: [SNAP_BUF_CAP]u8 = undefined,
    headers: [SNAP_MAX_HEADERS]request.Header = undefined,
};

/// Copy `src` into the slot-owned `snap` storage and return a RequestView whose
/// slices point at that owned storage (stable while the slot is live). Returns
/// null when the request does not fit the bounded snapshot; the caller then
/// fails the park closed rather than borrowing the (soon-reused) source buffer.
fn buildSnapshot(snap: *ReqSnapshot, src: request.RequestView) ?request.RequestView {
    var off: usize = 0;

    var method_raw: []const u8 = "";
    if (src.method_raw.len > 0) {
        if (off + src.method_raw.len > snap.buf.len) return null;
        @memcpy(snap.buf[off..][0..src.method_raw.len], src.method_raw);
        method_raw = snap.buf[off..][0..src.method_raw.len];
        off += src.method_raw.len;
    }

    if (off + src.path.len > snap.buf.len) return null;
    @memcpy(snap.buf[off..][0..src.path.len], src.path);
    const path = snap.buf[off..][0..src.path.len];
    off += src.path.len;

    if (src.headers.len > snap.headers.len) return null;
    for (src.headers, 0..) |h, i| {
        if (off + h.name.len + h.value.len > snap.buf.len) return null;
        @memcpy(snap.buf[off..][0..h.name.len], h.name);
        const name = snap.buf[off..][0..h.name.len];
        off += h.name.len;
        @memcpy(snap.buf[off..][0..h.value.len], h.value);
        const value = snap.buf[off..][0..h.value.len];
        off += h.value.len;
        snap.headers[i] = .{ .name = name, .value = value };
    }
    const headers = snap.headers[0..src.headers.len];

    var body: request.RequestBody = .{ .slice = "" };
    const body_len = src.body.len();
    if (body_len > 0) {
        if (off + body_len > snap.buf.len) return null;
        // copyTo materializes slice/scattered bytes; length_only carries none
        // (returns null) -> fail the park closed.
        const copied = src.body.copyTo(snap.buf[off..][0..body_len]) orelse return null;
        body = .{ .slice = copied };
        off += copied.len;
    }

    return request.RequestView{
        .method = src.method,
        .method_raw = method_raw,
        .path = path,
        .headers = headers,
        .body = body,
    };
}

/// Terminal result of a parked filter, with the stream it belongs to. The server
/// uses (conn_index, conn_id, stream_id, protocol) to find the waiting stream
/// (re-checking the generation) and acts on `decision`.
pub const Completion = struct {
    conn_index: u32,
    conn_id: u64,
    /// Stream within the connection. H1 uses the sentinel 0 (one in-flight
    /// request per connection); H2/H3 carry the real stream id (E2).
    stream_id: u32,
    /// Protocol of the parked stream; `wasmResume` routes delivery by it.
    protocol: Protocol,
    decision: middleware.Decision,
    /// The parked request, for re-dispatch on resume-to-allow/modify. It is an
    /// OWNED snapshot in the park slot's storage (no longer a borrow of the
    /// connection read buffer), valid through the synchronous resume that
    /// consumes this Completion. Unused for a reject decision (served directly
    /// without re-running the handler).
    req: request.RequestView,
    /// Opaque resumed-path context carried from park time. E0 leaves it null;
    /// E1 populates it with the proxy's cache/otel/x402-settlement context so the
    /// resumed forward can run the post-`proxy.handle` processing.
    resume_ctx: ?*anyopaque,
};

/// Why a park ended without a host-call result (all fail closed).
pub const CancelReason = enum { host_call_failed, timed_out };

pub const Table = struct {
    /// Max concurrent parked filters per worker. Bounded like the PG park table;
    /// also bounded implicitly by the instance pool sizes (each park pins one).
    pub const CAP = 64;

    const Slot = struct {
        active: bool = false,
        instance: *filter.Instance = undefined,
        conn_index: u32 = 0,
        conn_id: u64 = 0,
        stream_id: u32 = 0,
        protocol: Protocol = .http1,
        deadline_ms: u64 = 0,
        resume_fuel: i64 = filter.DEFAULT_FUEL,
        resume_ctx: ?*anyopaque = null,
        /// Rebuilt view over `snap` (owned copy), not a borrow of the request's
        /// source buffer. Valid while the slot is active.
        req: request.RequestView = undefined,
        snap: ReqSnapshot = .{},
    };

    slots: [CAP]Slot = [1]Slot{.{}} ** CAP,

    /// Register a parked filter, keyed by (conn_index, conn_id, stream_id,
    /// protocol). The instance must already be pinned (`.parked`) by
    /// filter.invokeOutcome. Snapshots the request into the slot's owned storage
    /// so the resume path does not depend on the source buffer staying pinned.
    /// Returns a token, or null if the table is full or the request does not fit
    /// the bounded snapshot (the caller should filter.cancelPark the instance and
    /// fail closed). `resume_ctx` is the opaque resumed-path context (E1; null in
    /// E0).
    pub fn park(
        self: *Table,
        instance: *filter.Instance,
        req: request.RequestView,
        conn_index: u32,
        conn_id: u64,
        stream_id: u32,
        protocol: Protocol,
        deadline_ms: u64,
        resume_fuel: i64,
        resume_ctx: ?*anyopaque,
    ) ?Token {
        std.debug.assert(instance.state == .parked);
        for (&self.slots, 0..) |*s, i| {
            if (!s.active) {
                // Build the owned snapshot in-place first; bail (caller fails
                // closed) before claiming the slot if it does not fit.
                const owned = buildSnapshot(&s.snap, req) orelse return null;
                s.active = true;
                s.instance = instance;
                s.conn_index = conn_index;
                s.conn_id = conn_id;
                s.stream_id = stream_id;
                s.protocol = protocol;
                s.deadline_ms = deadline_ms;
                s.resume_fuel = resume_fuel;
                s.resume_ctx = resume_ctx;
                s.req = owned;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Is there a live park for this connection (generation-checked)? Mirrors
    /// PgClient.hasParkFor; used by handleParkSentinel to set `.wasm_parked`.
    pub fn hasParkFor(self: *Table, conn_index: u32, conn_id: u64) bool {
        for (&self.slots) |*s| {
            if (s.active and s.conn_index == conn_index and s.conn_id == conn_id) return true;
        }
        return false;
    }

    /// The host call for `token` completed: resume the filter with `result` and
    /// return the terminal Decision + connection linkage. Frees the slot and
    /// releases the instance. Null if the token is stale/free (double complete).
    pub fn complete(self: *Table, token: Token, result: []const u8) ?Completion {
        const s = self.live(token) orelse return null;
        const decision = filter.resumeCall(s.instance, result, s.resume_fuel);
        const out = self.completionFor(s, decision);
        s.active = false;
        return out;
    }

    /// End a park without a result (host-call failure or deadline): release the
    /// instance and return a fail-closed completion to serve if the connection
    /// is still live.
    pub fn cancel(self: *Table, token: Token, reason: CancelReason) ?Completion {
        _ = reason;
        const s = self.live(token) orelse return null;
        const decision = filter.cancelPark(s.instance);
        const out = self.completionFor(s, decision);
        s.active = false;
        return out;
    }

    /// The client connection closed while a filter was parked on it: release the
    /// pinned instance, drop the entry, and DON'T produce a completion (there is
    /// nobody to serve). Generation-checked. Returns true if one was found.
    pub fn cancelForConn(self: *Table, conn_index: u32, conn_id: u64) bool {
        var found = false;
        for (&self.slots) |*s| {
            if (s.active and s.conn_index == conn_index and s.conn_id == conn_id) {
                _ = filter.cancelPark(s.instance);
                s.active = false;
                found = true;
            }
        }
        return found;
    }

    /// A single multiplexed stream closed (RST_STREAM / QUIC stream reset) while
    /// a filter was parked on it: release that one pinned instance and drop the
    /// entry, leaving the connection's other parked streams intact. The per-stream
    /// counterpart to cancelForConn, used by H2/H3 (E2). Generation-checked.
    /// Returns true if a matching park was found.
    pub fn cancelForStream(self: *Table, conn_index: u32, conn_id: u64, stream_id: u32) bool {
        for (&self.slots) |*s| {
            if (s.active and s.conn_index == conn_index and s.conn_id == conn_id and s.stream_id == stream_id) {
                _ = filter.cancelPark(s.instance);
                s.active = false;
                return true;
            }
        }
        return false;
    }

    /// Fire wall-clock deadlines: for each park past `now_ms`, release the
    /// instance and emit a fail-closed completion into `out`. Returns the count
    /// written (capped at out.len). The reactor housekeeping tick calls this;
    /// it is the deadline backstop fuel cannot provide for an outstanding call.
    pub fn tick(self: *Table, now_ms: u64, out: []Completion) usize {
        var n: usize = 0;
        for (&self.slots) |*s| {
            if (n >= out.len) break;
            if (s.active and now_ms >= s.deadline_ms) {
                const decision = filter.cancelPark(s.instance);
                out[n] = self.completionFor(s, decision);
                n += 1;
                s.active = false;
            }
        }
        return n;
    }

    /// Count of currently parked filters (for metrics / tests).
    pub fn liveCount(self: *const Table) usize {
        var n: usize = 0;
        for (&self.slots) |*s| {
            if (s.active) n += 1;
        }
        return n;
    }

    fn live(self: *Table, token: Token) ?*Slot {
        if (token >= self.slots.len) return null;
        const s = &self.slots[token];
        return if (s.active) s else null;
    }

    /// Build a Completion from a (still-active) slot, carrying the stream key,
    /// protocol, owned request snapshot, and resumed-path context. The returned
    /// `req` slices point into the slot's snapshot storage, which stays valid
    /// through the synchronous resume that consumes the Completion (the slot is
    /// not reused until the next park, and the worker is single-threaded).
    fn completionFor(self: *Table, s: *Slot, decision: middleware.Decision) Completion {
        _ = self;
        return .{
            .conn_index = s.conn_index,
            .conn_id = s.conn_id,
            .stream_id = s.stream_id,
            .protocol = s.protocol,
            .decision = decision,
            .req = s.req,
            .resume_ctx = s.resume_ctx,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests (run with: zig build test -Denable-wasm=true)
// ---------------------------------------------------------------------------

const testing = std.testing;
const FILTER_WASM = @embedFile("testdata/filter_probe.wasm");

// Park a real filter instance (the /enrich fixture path stages a host_call and
// returns parked) and return the pool + token for the table-level tests.
fn parkOne(pool: *filter.Pool, table: *Table, conn_index: u32, conn_id: u64, deadline_ms: u64) !Token {
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    switch (filter.invokeOutcome(inst, &r, filter.DEFAULT_FUEL)) {
        .parked => {},
        .decision => return error.DidNotPark,
    }
    // H1 sentinels: stream_id 0, protocol .http1, no resumed-path context.
    return table.park(inst, r, conn_index, conn_id, 0, .http1, deadline_ms, filter.DEFAULT_FUEL, null) orelse error.TableFull;
}

test "host_call table: complete resumes the filter to a decision" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    var table = Table{};

    const token = try parkOne(&pool, &table, 7, 100, 5000);
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    // Result "ok" -> on_resume allows. Connection linkage preserved.
    const c = table.complete(token, "ok") orelse return error.NoCompletion;
    try testing.expect(c.decision == .allow);
    try testing.expectEqual(@as(u32, 7), c.conn_index);
    try testing.expectEqual(@as(u64, 100), c.conn_id);
    try testing.expectEqual(@as(usize, 0), table.liveCount());

    // Double-complete is a no-op (stale token).
    try testing.expect(table.complete(token, "ok") == null);
}

test "host_call table: result drives reject" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table{};
    const token = try parkOne(&pool, &table, 1, 1, 5000);
    const c = table.complete(token, "denied") orelse return error.NoCompletion;
    try testing.expect(c.decision == .reject);
    try testing.expectEqual(@as(u16, 403), c.decision.reject.status);
}

test "host_call table: cancel fails closed and releases the instance" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table{};
    const token = try parkOne(&pool, &table, 1, 1, 5000);
    const c = table.cancel(token, .host_call_failed) orelse return error.NoCompletion;
    try testing.expect(c.decision == .reject);
    try testing.expectEqual(@as(u16, 500), c.decision.reject.status);
    // Instance released: the single-instance pool can be acquired again.
    try testing.expect(pool.acquire() != null);
}

test "host_call table: tick fires deadlines, fail-closed" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    var table = Table{};
    _ = try parkOne(&pool, &table, 1, 1, 1000);
    _ = try parkOne(&pool, &table, 2, 2, 5000); // later deadline, survives

    var out: [8]Completion = undefined;
    const fired = table.tick(2000, &out); // past the first deadline only
    try testing.expectEqual(@as(usize, 1), fired);
    try testing.expectEqual(@as(u32, 1), out[0].conn_index);
    try testing.expect(out[0].decision == .reject);
    try testing.expectEqual(@as(usize, 1), table.liveCount());
}

test "host_call table: cancelForConn releases without a completion" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table{};
    _ = try parkOne(&pool, &table, 9, 42, 5000);

    // Wrong generation: no-op.
    try testing.expect(table.cancelForConn(9, 999) == false);
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    // Matching conn+generation: released, no completion to serve.
    try testing.expect(table.cancelForConn(9, 42) == true);
    try testing.expectEqual(@as(usize, 0), table.liveCount());
    try testing.expect(pool.acquire() != null);
}

test "host_call table: full table returns null token" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = Table.CAP + 2 });
    defer pool.deinit();
    var table = Table{};
    var i: u32 = 0;
    while (i < Table.CAP) : (i += 1) {
        _ = try parkOne(&pool, &table, i, i, 5000);
    }
    // Table full: one more park returns null (caller fails closed).
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst, &r, filter.DEFAULT_FUEL) == .parked);
    try testing.expect(table.park(inst, r, 999, 999, 0, .http1, 5000, filter.DEFAULT_FUEL, null) == null);
    _ = filter.cancelPark(inst);
}

test "host_call table: completion carries stream_id + protocol sentinels for H1" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table{};
    const token = try parkOne(&pool, &table, 3, 4, 5000);
    const c = table.complete(token, "ok") orelse return error.NoCompletion;
    try testing.expectEqual(@as(u32, 0), c.stream_id);
    try testing.expect(c.protocol == .http1);
    try testing.expect(c.resume_ctx == null);
}

test "host_call table: cancelForStream releases only the matching stream" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    var table = Table{};

    // Two parks on the same conn but different stream ids (the H2/H3 shape).
    const inst_a = pool.acquire() orelse return error.AcquireFailed;
    const r1 = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst_a, &r1, filter.DEFAULT_FUEL) == .parked);
    _ = table.park(inst_a, r1, 1, 1, 7, .http2, 5000, filter.DEFAULT_FUEL, null) orelse return error.TableFull;

    const inst_b = pool.acquire() orelse return error.AcquireFailed;
    const r2 = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst_b, &r2, filter.DEFAULT_FUEL) == .parked);
    _ = table.park(inst_b, r2, 1, 1, 9, .http2, 5000, filter.DEFAULT_FUEL, null) orelse return error.TableFull;

    try testing.expectEqual(@as(usize, 2), table.liveCount());
    // Wrong stream: no-op.
    try testing.expect(table.cancelForStream(1, 1, 99) == false);
    try testing.expectEqual(@as(usize, 2), table.liveCount());
    // Matching stream: only that one is released.
    try testing.expect(table.cancelForStream(1, 1, 7) == true);
    try testing.expectEqual(@as(usize, 1), table.liveCount());
}

test "host_call table: owned snapshot survives mutation of the source buffer" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table{};

    // Back the request with MUTABLE storage, then scribble over it after parking
    // to simulate the read/frame buffer being reused while the stream is parked.
    var path_buf = "/enrich".*;
    var name_buf = "x-trace".*;
    var value_buf = "original-value".*;
    var headers = [_]request.Header{.{ .name = &name_buf, .value = &value_buf }};
    const r = request.RequestView{ .method = .GET, .path = &path_buf, .headers = &headers };

    const inst = pool.acquire() orelse return error.AcquireFailed;
    try testing.expect(filter.invokeOutcome(inst, &r, filter.DEFAULT_FUEL) == .parked);
    const token = table.park(inst, r, 2, 2, 0, .http1, 5000, filter.DEFAULT_FUEL, null) orelse return error.TableFull;

    // Buffer reuse: clobber the original bytes.
    @memset(&path_buf, 'X');
    @memset(&name_buf, 'X');
    @memset(&value_buf, 'X');

    const c = table.complete(token, "ok") orelse return error.NoCompletion;
    try testing.expect(c.decision == .allow);
    // The snapshot is independent of the (now-clobbered) source buffer.
    try testing.expectEqualStrings("/enrich", c.req.path);
    try testing.expectEqual(@as(usize, 1), c.req.headers.len);
    try testing.expectEqualStrings("x-trace", c.req.headers[0].name);
    try testing.expectEqualStrings("original-value", c.req.headers[0].value);
}

test "host_call table: oversized request fails the park closed" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table{};

    // A path longer than the snapshot buffer cannot be owned: park returns null
    // and the instance must be released by the caller (fail closed).
    var big: [SNAP_BUF_CAP + 16]u8 = undefined;
    @memset(&big, 'a');
    big[0] = '/';
    const r = request.RequestView{ .method = .GET, .path = &big, .headers = &.{} };
    const inst = pool.acquire() orelse return error.AcquireFailed;
    // The probe parks only on "/enrich"; force the parked state directly so we
    // exercise the snapshot bound rather than the guest's routing.
    const parked = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst, &parked, filter.DEFAULT_FUEL) == .parked);
    try testing.expect(table.park(inst, r, 1, 1, 0, .http1, 5000, filter.DEFAULT_FUEL, null) == null);
    try testing.expectEqual(@as(usize, 0), table.liveCount());
    _ = filter.cancelPark(inst);
}
