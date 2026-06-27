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

pub const Token = u32;
pub const INVALID_TOKEN: Token = std.math.maxInt(u32);

/// Terminal result of a parked filter, with the connection it belongs to. The
/// server uses (conn_index, conn_id) to find the waiting connection (re-checking
/// the generation) and acts on `decision`.
pub const Completion = struct {
    conn_index: u32,
    conn_id: u64,
    decision: middleware.Decision,
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
        deadline_ms: u64 = 0,
        resume_fuel: i64 = filter.DEFAULT_FUEL,
    };

    slots: [CAP]Slot = [1]Slot{.{}} ** CAP,

    /// Register a parked filter. The instance must already be pinned (`.parked`)
    /// by filter.invokeOutcome. Returns a token, or null if the table is full
    /// (the caller should filter.cancelPark the instance and fail closed).
    pub fn park(
        self: *Table,
        instance: *filter.Instance,
        conn_index: u32,
        conn_id: u64,
        deadline_ms: u64,
        resume_fuel: i64,
    ) ?Token {
        std.debug.assert(instance.state == .parked);
        for (&self.slots, 0..) |*s, i| {
            if (!s.active) {
                s.* = .{
                    .active = true,
                    .instance = instance,
                    .conn_index = conn_index,
                    .conn_id = conn_id,
                    .deadline_ms = deadline_ms,
                    .resume_fuel = resume_fuel,
                };
                return @intCast(i);
            }
        }
        return null;
    }

    /// The host call for `token` completed: resume the filter with `result` and
    /// return the terminal Decision + connection linkage. Frees the slot and
    /// releases the instance. Null if the token is stale/free (double complete).
    pub fn complete(self: *Table, token: Token, result: []const u8) ?Completion {
        const s = self.live(token) orelse return null;
        const decision = filter.resumeCall(s.instance, result, s.resume_fuel);
        const out = Completion{ .conn_index = s.conn_index, .conn_id = s.conn_id, .decision = decision };
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
        const out = Completion{ .conn_index = s.conn_index, .conn_id = s.conn_id, .decision = decision };
        s.active = false;
        return out;
    }

    /// The client connection closed while a filter was parked on it: release the
    /// pinned instance, drop the entry, and DON'T produce a completion (there is
    /// nobody to serve). Generation-checked. Returns true if one was found.
    pub fn cancelForConn(self: *Table, conn_index: u32, conn_id: u64) bool {
        for (&self.slots) |*s| {
            if (s.active and s.conn_index == conn_index and s.conn_id == conn_id) {
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
                out[n] = .{ .conn_index = s.conn_index, .conn_id = s.conn_id, .decision = decision };
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
};

// ---------------------------------------------------------------------------
// Tests (run with: zig build test -Denable-wasm=true)
// ---------------------------------------------------------------------------

const testing = std.testing;
const request = @import("../protocol/request.zig");
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
    return table.park(inst, conn_index, conn_id, deadline_ms, filter.DEFAULT_FUEL) orelse error.TableFull;
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
    try testing.expect(table.park(inst, 999, 999, 5000, filter.DEFAULT_FUEL) == null);
    _ = filter.cancelPark(inst);
}
