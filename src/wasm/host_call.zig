//! Per-worker park registry for WASM async host calls (design 10.0, Phase 3b).
//!
//! When a filter stages a host_call and parks, its instance is pinned
//! (filter.invokeOutcome leaves it `.parked`) and an entry is recorded here,
//! tying the pinned instance to the waiting (connection, stream) -- keyed by
//! (conn_index, conn_id, stream_id, protocol) so HTTP/1, HTTP/2, and HTTP/3 all
//! use one model (E0). The slot OWNS a snapshot of the request, so resume does
//! not depend on a pinned read buffer (H2/H3 frame buffers get reused). When the
//! outbound call completes on the reactor, `complete(token, result)` resumes the
//! filter (re-enters on_resume) and yields the terminal Decision plus the
//! (connection, stream) linkage the server needs to deliver it. Failures,
//! wall-clock deadlines, and client disconnects each release the pinned instance.
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

/// Upper bounds for a park's OWNED request snapshot. The snapshot is now
/// HEAP-allocated, sized exactly to the request (method_raw + path + header
/// name/value bytes + a small body, plus a sized Header array), so the common
/// case carries no fixed per-slot footprint and the old 4 KiB ceiling is gone: a
/// request with a big JWT + many cookies on a parked route now round-trips. These
/// bounds exist only to cap a HOSTILE giant request -- without them a single park
/// could be coerced into a multi-megabyte allocation. A request exceeding either
/// bound fails the park CLOSED (rather than truncating, which could drop an auth
/// header and change a verdict), matching the table-full behavior.
const SNAP_MAX_BYTES = 64 * 1024;
const SNAP_MAX_HEADERS = 128;

/// One heap-allocated, request-sized snapshot owned by a Slot: a byte buffer
/// holding method_raw + path + header name/value bytes + the small body, and a
/// sized Header array indexing into it. `view`'s slices point into `buf`/`headers`
/// and stay valid until the buffer is freed (slot reuse or Table.deinit).
const Owned = struct {
    buf: []u8,
    headers: []request.Header,
    view: request.RequestView,
};

/// Heap-allocate an owned copy of `src` sized to the request and return it with a
/// RequestView pointing into that owned storage. Returns null (caller fails the
/// park closed) when the request exceeds SNAP_MAX_BYTES / SNAP_MAX_HEADERS, when
/// the body cannot be materialized (length_only carries no bytes), or on OOM.
/// Leak-free: any partial allocation is freed before returning null.
fn buildSnapshot(allocator: std.mem.Allocator, src: request.RequestView) ?Owned {
    if (src.headers.len > SNAP_MAX_HEADERS) return null;

    // Size the buffer to exactly the bytes we copy, bounded against a hostile
    // request before allocating anything.
    var total: usize = src.method_raw.len + src.path.len;
    for (src.headers) |h| total += h.name.len + h.value.len;
    const body_len = src.body.len();
    total += body_len;
    if (total > SNAP_MAX_BYTES) return null;

    const buf = allocator.alloc(u8, total) catch return null;
    const headers = allocator.alloc(request.Header, src.headers.len) catch {
        allocator.free(buf);
        return null;
    };

    var off: usize = 0;

    var method_raw: []const u8 = "";
    if (src.method_raw.len > 0) {
        @memcpy(buf[off..][0..src.method_raw.len], src.method_raw);
        method_raw = buf[off..][0..src.method_raw.len];
        off += src.method_raw.len;
    }

    @memcpy(buf[off..][0..src.path.len], src.path);
    const path = buf[off..][0..src.path.len];
    off += src.path.len;

    for (src.headers, 0..) |h, i| {
        @memcpy(buf[off..][0..h.name.len], h.name);
        const name = buf[off..][0..h.name.len];
        off += h.name.len;
        @memcpy(buf[off..][0..h.value.len], h.value);
        const value = buf[off..][0..h.value.len];
        off += h.value.len;
        headers[i] = .{ .name = name, .value = value };
    }

    var body: request.RequestBody = .{ .slice = "" };
    if (body_len > 0) {
        // copyTo materializes slice/scattered bytes; length_only carries none
        // (returns null) -> fail the park closed.
        const copied = src.body.copyTo(buf[off..][0..body_len]) orelse {
            allocator.free(buf);
            allocator.free(headers);
            return null;
        };
        body = .{ .slice = copied };
        off += copied.len;
    }

    return Owned{
        .buf = buf,
        .headers = headers,
        .view = request.RequestView{
            .method = src.method,
            .method_raw = method_raw,
            .path = path,
            .headers = headers,
            .body = body,
        },
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

    // Token layout: the low INDEX_BITS are the slot index, the rest a per-slot
    // generation. The generation makes a token unique to ONE park. When a slot is
    // freed (connection close, deadline, cancel) and later reused by a different
    // request, the new park bumps the slot's generation, so a late or duplicate
    // completion -- or a stale in-flight transport token for the PREVIOUS occupant
    // (the ControlClient has no cancel-by-token, so a parked-then-disconnected
    // request's reply can still arrive) -- is rejected by live() instead of
    // resuming the new occupant with the wrong host-call result.
    const INDEX_BITS = 8; // CAP (64) fits in 8 bits
    const INDEX_MASK: Token = (1 << INDEX_BITS) - 1;
    // The index must fit in INDEX_BITS, else live()'s mask would alias slots and
    // the generation could be truncated. Pin it at comptime so raising CAP past
    // 256 is a compile error, not a silent token-aliasing bug.
    comptime {
        std.debug.assert(CAP <= INDEX_MASK + 1);
    }

    const Slot = struct {
        active: bool = false,
        /// Bumped each time the slot is claimed; packed into the token so a stale
        /// token for a prior occupant fails the live() check. Wraps (u24 space is
        /// ~16M parks per slot); a collision needs exactly that many reuses
        /// between a stale token and its check, which cannot occur in practice.
        generation: u24 = 0,
        instance: *filter.Instance = undefined,
        conn_index: u32 = 0,
        conn_id: u64 = 0,
        stream_id: u32 = 0,
        protocol: Protocol = .http1,
        deadline_ms: u64 = 0,
        resume_fuel: i64 = filter.DEFAULT_FUEL,
        resume_ctx: ?*anyopaque = null,
        /// View over the slot-OWNED heap snapshot (`snap_buf`/`snap_headers`), not
        /// a borrow of the request's source buffer. Valid while the slot is active
        /// AND through the synchronous resume that consumes the Completion (see the
        /// lifecycle note on `freeSnapshot`).
        req: request.RequestView = undefined,
        /// Heap-allocated, request-sized backing for `req`, owned by this slot.
        /// Null when the slot has never been used or its buffer was already
        /// reclaimed. DEFERRED-FREE lifecycle (load-bearing): complete/cancel/tick/
        /// cancelForConn/cancelForStream only mark the slot inactive; they MUST NOT
        /// free this buffer, because the Completion they return carries `req`
        /// slices into it and is consumed SYNCHRONOUSLY by dispatch.wasmResume
        /// afterward. The buffer is reclaimed when the slot is NEXT reused (park
        /// frees the prior occupant's buffer before allocating) and at Table.deinit
        /// (frees whatever remains). Freeing it earlier would dangle Completion.req.
        snap_buf: ?[]u8 = null,
        snap_headers: ?[]request.Header = null,

        /// Free the slot's owned snapshot (no-op if already reclaimed). Called at
        /// slot reuse (park) and Table.deinit -- NEVER from the park-end paths
        /// while a Completion may still alias the buffer.
        fn freeSnapshot(s: *Slot, allocator: std.mem.Allocator) void {
            if (s.snap_buf) |b| allocator.free(b);
            if (s.snap_headers) |h| allocator.free(h);
            s.snap_buf = null;
            s.snap_headers = null;
        }
    };

    /// Allocator for the per-park owned snapshots (set at server init via init()).
    /// The default (`Table{}`) leaves it undefined; park/deinit require init().
    allocator: std.mem.Allocator = undefined,

    slots: [CAP]Slot = [1]Slot{.{}} ** CAP,

    /// Build a Table bound to `allocator` (used to heap-allocate each park's owned
    /// request snapshot). Server passes its worker allocator here at init.
    pub fn init(allocator: std.mem.Allocator) Table {
        return .{ .allocator = allocator };
    }

    /// Reclaim every owned snapshot still held by a slot (live parks plus the
    /// deferred-free buffer of the last occupant of any reused slot). The worker
    /// is single-threaded and torn down with no park mid-resume, so no Completion
    /// is aliasing a buffer at this point.
    pub fn deinit(self: *Table) void {
        for (&self.slots) |*s| s.freeSnapshot(self.allocator);
    }

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
        // Runtime fail-closed guard (NOT a debug assert, which compiles out in
        // ReleaseFast): registering a non-parked instance would corrupt a live or
        // idle instance on resume. Caller treats null as table-full -> cancelPark
        // + 503. (Mirrors the same guard in filter.resumeCall.)
        if (instance.state != .parked) return null;
        // LOAD-BEARING for the deferred-free lifecycle: park reuses the LOWEST-index
        // free slot, and tick() emits its completions in ascending slot order while
        // wasmTick consumes them in that same order. Together this guarantees a tail
        // re-park during a batched-completion resume can only reclaim an
        // already-consumed lower-index buffer, never a still-pending higher-index
        // completion's buffer. Do NOT change this to a free-list / LIFO policy
        // without also changing tick()'s emission/consumption order, or the
        // tick-batch path can use-after-free.
        for (&self.slots, 0..) |*s, i| {
            if (!s.active) {
                // Reclaim the prior occupant's deferred-free buffer (its Completion
                // was consumed synchronously long ago), then heap-allocate this
                // park's owned snapshot. Bail (caller fails closed) before claiming
                // the slot if the request exceeds the bounds or cannot be owned;
                // snap_buf is left null so there is no leak.
                s.freeSnapshot(self.allocator);
                const owned = buildSnapshot(self.allocator, req) orelse return null;
                s.snap_buf = owned.buf;
                s.snap_headers = owned.headers;
                s.generation +%= 1; // unique to this park; stale tokens fail live()
                s.active = true;
                s.instance = instance;
                s.conn_index = conn_index;
                s.conn_id = conn_id;
                s.stream_id = stream_id;
                s.protocol = protocol;
                s.deadline_ms = deadline_ms;
                s.resume_fuel = resume_fuel;
                s.resume_ctx = resume_ctx;
                s.req = owned.view;
                return (@as(Token, s.generation) << INDEX_BITS) | @as(Token, @intCast(i));
            }
        }
        return null;
    }

    /// Is there a live park for this connection (matched by conn id, not the
    /// token generation)? Mirrors PgClient.hasParkFor; used by handleParkSentinel
    /// to set `.wasm_parked`.
    pub fn hasParkFor(self: *Table, conn_index: u32, conn_id: u64) bool {
        for (&self.slots) |*s| {
            if (s.active and s.conn_index == conn_index and s.conn_id == conn_id) return true;
        }
        return false;
    }

    /// Is there a live park for this specific stream (matched by conn id +
    /// stream id, not the token generation)? The
    /// per-stream counterpart to hasParkFor, used by the H2/H3 dispatch (E2) to
    /// confirm a park-sentinel response really registered a park on the stream
    /// before suspending it.
    pub fn hasParkForStream(self: *Table, conn_index: u32, conn_id: u64, stream_id: u32) bool {
        for (&self.slots) |*s| {
            if (s.active and s.conn_index == conn_index and s.conn_id == conn_id and s.stream_id == stream_id) return true;
        }
        return false;
    }

    /// The host call for `token` completed: resume the filter with `result` and
    /// return the terminal Decision + connection linkage. Marks the slot inactive
    /// (releasing the instance) but DEFERS freeing the owned snapshot: the returned
    /// Completion's `req` still aliases it for the synchronous resume; the buffer is
    /// reclaimed at the next park of this slot (or Table.deinit). Null if the token
    /// is stale/free (double complete).
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
    /// nobody to serve). Matched by conn id (all streams on the conn). Returns
    /// true if at least one was found. NOTE: this does NOT cancel any in-flight
    /// transport token for the freed slot(s); a late reply is rejected later by
    /// live()'s generation check (a slot reused by a new park has a new
    /// generation), so the new occupant is never resumed with a stale result.
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
    /// counterpart to cancelForConn, used by H2/H3 (E2). Matched by stream id.
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
        const idx = token & INDEX_MASK;
        if (idx >= self.slots.len) return null;
        const s = &self.slots[idx];
        const gen: u24 = @truncate(token >> INDEX_BITS);
        // Reject a stale token: the slot is free, or was reused by a later park
        // (different generation). This is what stops request A's late host-call
        // reply from resuming request B after B reused A's freed slot.
        if (!s.active or s.generation != gen) return null;
        return s;
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
    var table = Table.init(testing.allocator);
    defer table.deinit();

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
    var table = Table.init(testing.allocator);
    defer table.deinit();
    const token = try parkOne(&pool, &table, 1, 1, 5000);
    const c = table.complete(token, "denied") orelse return error.NoCompletion;
    try testing.expect(c.decision == .reject);
    try testing.expectEqual(@as(u16, 403), c.decision.reject.status);
}

test "host_call table: cancel fails closed and releases the instance" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();
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
    var table = Table.init(testing.allocator);
    defer table.deinit();
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
    var table = Table.init(testing.allocator);
    defer table.deinit();
    _ = try parkOne(&pool, &table, 9, 42, 5000);

    // Wrong generation: no-op.
    try testing.expect(table.cancelForConn(9, 999) == false);
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    // Matching conn+generation: released, no completion to serve.
    try testing.expect(table.cancelForConn(9, 42) == true);
    try testing.expectEqual(@as(usize, 0), table.liveCount());
    try testing.expect(pool.acquire() != null);
}

test "host_call table: a stale token does not resume a reused slot (generation)" {
    // Regression for the cross-request misattribution bug: request A parks, A's
    // connection closes (slot freed), request B reuses the SAME slot, then A's
    // late host-call reply arrives. complete(tokenA) must be rejected (stale
    // generation) and must NOT resume B with A's result.
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();

    const token_a = try parkOne(&pool, &table, 1, 100, 5000); // A: conn 1
    try testing.expect(table.cancelForConn(1, 100)); // A disconnects -> slot freed, token_a still outstanding
    try testing.expectEqual(@as(usize, 0), table.liveCount());

    const token_b = try parkOne(&pool, &table, 2, 200, 5000); // B reuses the freed slot
    try testing.expect(token_a != token_b); // same index, different generation

    // A's late reply lands on the reused slot index -> rejected as stale.
    try testing.expect(table.complete(token_a, "ok") == null);
    try testing.expectEqual(@as(usize, 1), table.liveCount()); // B still parked, untouched

    // B's own completion still works and carries B's connection.
    const c = table.complete(token_b, "ok") orelse return error.NoCompletion;
    try testing.expectEqual(@as(u32, 2), c.conn_index);
    try testing.expectEqual(@as(u64, 200), c.conn_id);
}

test "host_call table: full table returns null token" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = Table.CAP + 2 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();
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
    var table = Table.init(testing.allocator);
    defer table.deinit();
    const token = try parkOne(&pool, &table, 3, 4, 5000);
    const c = table.complete(token, "ok") orelse return error.NoCompletion;
    try testing.expectEqual(@as(u32, 0), c.stream_id);
    try testing.expect(c.protocol == .http1);
    try testing.expect(c.resume_ctx == null);
}

test "host_call table: resume_ctx is carried opaquely through park -> complete (E1)" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();

    // Stand-in for the proxy resumed-path context (E1): the dispatch loop stores
    // a WasmProxyResumeCtx on the connection and points resume_ctx at it; the
    // table must hand that exact pointer back in the Completion so proxyResume
    // can read the stashed cache/otel/settlement context. We use a local struct
    // (the table treats resume_ctx as ?*anyopaque) to assert the opaque carry
    // without coupling the table to connection.zig.
    const Ctx = struct { route_idx: usize, otel_start: i128, needs_settlement: bool };
    var ctx = Ctx{ .route_idx = 3, .otel_start = 123, .needs_settlement = true };

    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst, &r, filter.DEFAULT_FUEL) == .parked);
    const token = table.park(inst, r, 5, 6, 0, .http1, 5000, filter.DEFAULT_FUEL, @ptrCast(&ctx)) orelse return error.TableFull;

    const c = table.complete(token, "ok") orelse return error.NoCompletion;
    try testing.expect(c.decision == .allow);
    const got: *Ctx = @ptrCast(@alignCast(c.resume_ctx orelse return error.NoCtx));
    try testing.expectEqual(@as(usize, 3), got.route_idx);
    try testing.expectEqual(@as(i128, 123), got.otel_start);
    try testing.expect(got.needs_settlement);
}

test "host_call table: cancelForStream releases only the matching stream" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();

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
    var table = Table.init(testing.allocator);
    defer table.deinit();

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
    var table = Table.init(testing.allocator);
    defer table.deinit();

    // A path past the hostile-request byte bound cannot be owned: park returns
    // null and the instance must be released by the caller (fail closed).
    var big: [SNAP_MAX_BYTES + 16]u8 = undefined;
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

// --- D2 security probing: park-path fail-closed + exhaustion recovery --------

test "D2-4 park path: a trap inside on_resume fails the completion closed (500)" {
    // The async resume path (Table.complete -> filter.resumeCall) must fail
    // CLOSED when the resumed guest traps: the parked request never slips through
    // as .allow, and the instance is released (no pinned leak).
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();
    const token = try parkOne(&pool, &table, 1, 1, 5000);
    // The fixture's on_resume traps on a "trap" result.
    const c = table.complete(token, "trap") orelse return error.NoCompletion;
    try testing.expect(c.decision != .allow);
    try testing.expect(c.decision == .reject);
    try testing.expectEqual(@as(u16, 500), c.decision.reject.status);
    try testing.expectEqual(@as(usize, 0), table.liveCount());
    // Released, reusable (the single-instance pool can be acquired again).
    try testing.expect(pool.acquire() != null);
}

test "D2-5 park table: full fails closed, then recovers after a slot frees" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = Table.CAP + 2 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();

    var tokens: [Table.CAP]Token = undefined;
    var i: u32 = 0;
    while (i < Table.CAP) : (i += 1) tokens[i] = try parkOne(&pool, &table, i, i, 5000);
    try testing.expectEqual(@as(usize, Table.CAP), table.liveCount());

    // Table full: a fresh park returns null; the caller fails closed (cancelPark).
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst, &r, filter.DEFAULT_FUEL) == .parked);
    try testing.expect(table.park(inst, r, 999, 999, 0, .http1, 5000, filter.DEFAULT_FUEL, null) == null);
    _ = filter.cancelPark(inst);
    try testing.expectEqual(@as(usize, Table.CAP), table.liveCount());

    // Free one slot -> a later park succeeds (recovery; no leak of the freed slot).
    try testing.expect(table.cancel(tokens[0], .timed_out) != null);
    try testing.expectEqual(@as(usize, Table.CAP - 1), table.liveCount());
    const inst2 = pool.acquire() orelse return error.AcquireFailed;
    try testing.expect(filter.invokeOutcome(inst2, &r, filter.DEFAULT_FUEL) == .parked);
    const tok = table.park(inst2, r, 1000, 1000, 0, .http1, 5000, filter.DEFAULT_FUEL, null);
    try testing.expect(tok != null);
    try testing.expectEqual(@as(usize, Table.CAP), table.liveCount());
}

// --- G1: heap-allocated owned snapshot --------------------------------------

// Park while snapshotting an ARBITRARY request `snap_req` (which may differ from
// the routing request). The probe parks only on "/enrich", so we force the parked
// state with a plain "/enrich" invoke, then snapshot `snap_req` -- letting a test
// exercise the snapshot allocation independent of the guest's routing.
fn parkReq(pool: *filter.Pool, table: *Table, snap_req: request.RequestView, conn_index: u32, conn_id: u64, deadline_ms: u64) !Token {
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const route = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst, &route, filter.DEFAULT_FUEL) == .parked);
    return table.park(inst, snap_req, conn_index, conn_id, 0, .http1, deadline_ms, filter.DEFAULT_FUEL, null) orelse error.TableFull;
}

test "host_call table: a request with >4 KiB of headers now parks (heap snapshot)" {
    // Regression for the old 4 KiB embedded-snapshot ceiling: a big JWT plus many
    // cookies (8 KiB of header bytes here) used to fail the park CLOSED. With the
    // heap-allocated owned snapshot it round-trips, and the completion carries the
    // FULL request, byte-for-byte.
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();

    var jwt: [8192]u8 = undefined;
    @memset(&jwt, 'J');
    const headers = [_]request.Header{
        .{ .name = "authorization", .value = &jwt }, // ~8 KiB, well past the old 4 KiB cap
        .{ .name = "cookie", .value = "session=abc; theme=dark" },
    };
    const r = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &headers };

    const token = try parkReq(&pool, &table, r, 1, 1, 5000);
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    const c = table.complete(token, "ok") orelse return error.NoCompletion;
    try testing.expect(c.decision == .allow);
    try testing.expectEqualStrings("/enrich", c.req.path);
    try testing.expectEqual(@as(usize, 2), c.req.headers.len);
    try testing.expectEqualStrings("authorization", c.req.headers[0].name);
    try testing.expectEqual(@as(usize, 8192), c.req.headers[0].value.len);
    try testing.expect(std.mem.allEqual(u8, c.req.headers[0].value, 'J'));
    try testing.expectEqualStrings("cookie", c.req.headers[1].name);
    try testing.expectEqualStrings("session=abc; theme=dark", c.req.headers[1].value);
}

test "host_call table: header count past the bound fails the park closed" {
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit();

    // One header over SNAP_MAX_HEADERS -> fail closed (no truncation that could
    // drop an auth header). The caller releases the instance.
    var hdrs: [SNAP_MAX_HEADERS + 1]request.Header = undefined;
    for (&hdrs) |*h| h.* = .{ .name = "x", .value = "y" };
    const r = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &hdrs };

    const inst = pool.acquire() orelse return error.AcquireFailed;
    const route = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
    try testing.expect(filter.invokeOutcome(inst, &route, filter.DEFAULT_FUEL) == .parked);
    try testing.expect(table.park(inst, r, 1, 1, 0, .http1, 5000, filter.DEFAULT_FUEL, null) == null);
    try testing.expectEqual(@as(usize, 0), table.liveCount());
    _ = filter.cancelPark(inst);
}

test "host_call table: no snapshot leak across every park-end path" {
    // testing.allocator FAILS the test on any leak, so exercising each path that
    // ends a park (complete, cancel, tick deadline, cancelForConn) and then
    // table.deinit -- plus a slot REUSE that frees the prior occupant's deferred
    // buffer -- proves the deferred-free lifecycle reclaims every heap snapshot.
    var pool = try filter.Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    var table = Table.init(testing.allocator);
    defer table.deinit(); // backstop: frees any buffer still held (e.g. deferred)

    // A non-trivial request so the snapshot is a real allocation, not empty.
    const headers = [_]request.Header{.{ .name = "authorization", .value = "Bearer xyz" }};
    const r = request.RequestView{ .method = .GET, .path = "/enrich/path", .headers = &headers };

    // park + complete
    {
        const t = try parkReq(&pool, &table, r, 1, 1, 5000);
        _ = table.complete(t, "ok") orelse return error.NoCompletion;
    }
    // park + cancel
    {
        const t = try parkReq(&pool, &table, r, 2, 2, 5000);
        _ = table.cancel(t, .host_call_failed) orelse return error.NoCompletion;
    }
    // park + tick(deadline)
    {
        _ = try parkReq(&pool, &table, r, 3, 3, 1000);
        var out: [4]Completion = undefined;
        try testing.expectEqual(@as(usize, 1), table.tick(2000, &out));
    }
    // park + cancelForConn (no completion produced)
    {
        _ = try parkReq(&pool, &table, r, 4, 4, 5000);
        try testing.expect(table.cancelForConn(4, 4));
    }
    // park then reuse the same slot: the prior occupant's deferred buffer is
    // freed by the next park, and the new one is freed at deinit.
    {
        const t = try parkReq(&pool, &table, r, 5, 5, 5000);
        _ = table.complete(t, "ok") orelse return error.NoCompletion; // slot inactive, buffer deferred
        const t2 = try parkReq(&pool, &table, r, 6, 6, 5000); // reuses slot -> frees prior buffer
        _ = table.complete(t2, "ok") orelse return error.NoCompletion;
    }
    try testing.expectEqual(@as(usize, 0), table.liveCount());
}
