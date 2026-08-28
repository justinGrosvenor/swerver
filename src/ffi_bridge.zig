//! FFI request bridge: hands a matched request from the reactor thread to a
//! host callback (e.g. a Bun JS handler) and takes the response back, mirroring
//! the x402 cross-thread pattern. The reactor parks the connection and invokes
//! a thread-safe host callback; the host later calls `respond()` from its own
//! thread, which copies the response into the slot, enqueues the slot on a
//! lock-free SPSC ring, and wakes the loop. The reactor drains the ring and
//! resumes the parked connection ON ITS OWN THREAD (resume mutates non-atomic
//! reactor state, so it must never run on the host thread).
//!
//! One bridge per process (embedded servers are single-instance). All slot
//! allocation and freeing happen on the reactor thread; the host thread only
//! writes an already-allocated slot and pushes its index onto the ring.

const std = @import("std");
const io_mod = @import("runtime/io.zig");

pub const MAX_ROUTES = 64;
pub const MAX_SLOTS = 256;
// Ring capacity: a power of two so index wrap is a mask, not a prime modulo.
// Must exceed MAX_SLOTS (producers do no fullness check; capacity is RING_CAP-1
// usable, and at most MAX_SLOTS requests are ever outstanding).
const RING_CAP = 512;
const RING_MASK = RING_CAP - 1;
const PATH_CAP = 4096;
const METHOD_CAP = 16;
const CTYPE_CAP = 256;
const REQ_BODY_CAP = 32 * 1024;
const RESP_BODY_CAP = 128 * 1024;

/// C callback the reactor invokes when a request is parked. Must be
/// thread-safe (Bun's JSCallback with threadsafe:true is). It should return
/// promptly (schedule the JS handler) — it runs on the reactor thread.
pub const RequestCallback = *const fn (req_id: u64) callconv(.c) void;

const Route = struct {
    pattern: [PATH_CAP]u8 = undefined,
    pattern_len: u16 = 0,
    route_id: u32 = 0,
};

const Slot = struct {
    in_use: bool = false, // reactor-owned
    awaiting: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    nonce: u32 = 0,
    conn_index: u32 = 0,
    conn_id: u64 = 0,
    route_id: u32 = 0,

    method: [METHOD_CAP]u8 = undefined,
    method_len: u8 = 0,
    path: [PATH_CAP]u8 = undefined,
    path_len: u16 = 0,
    req_body: []u8 = &.{},
    req_body_len: u32 = 0,

    status: u16 = 0,
    ctype: [CTYPE_CAP]u8 = undefined,
    ctype_len: u16 = 0,
    resp_body: []u8 = &.{},
    resp_body_len: u32 = 0,
};

pub const ParkResult = enum { parked, no_slot, no_callback, too_large };

pub const Bridge = struct {
    ready: bool = false,
    callback: ?RequestCallback = null,
    io: ?*io_mod.IoRuntime = null,

    routes: [MAX_ROUTES]Route = undefined,
    route_count: u16 = 0,

    slots: []Slot = &.{},
    // Reactor-only free stack of slot indices.
    free: []u32 = &.{},
    free_top: usize = 0,

    // SPSC completion ring (host -> reactor): host pushes (tail) a slot index
    // in respond(), reactor pops (head) in popCompletion().
    ring: [RING_CAP]u32 = undefined,
    // SPSC request ring (reactor -> host): reactor pushes (tail) a req_id in
    // park(), host pops (head) in pollRequest(). The host drains this ring; the
    // callback is only a coalesced wake (Bun's thread-safe callback is unsafe
    // to invoke per-request under load), armed at most once per drain cycle.
    preq: [RING_CAP]u64 = undefined,
    // Each index and the coalesced-wake flag gets its own cache line: a
    // producer index written by one thread must not share a line with a
    // consumer index (or another producer index) written by the other, or the
    // line ping-pongs between cores on every request (SPSC false sharing).
    // align(64) starts each on a line; declared consecutively so the padding of
    // one covers the next. Mirrors SpscFdQueue in io_uring_native.zig.
    ring_head: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
    ring_tail: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
    preq_head: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
    preq_tail: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
    notify: std.atomic.Value(bool) align(64) = std.atomic.Value(bool).init(false),

    pub fn init(self: *Bridge, allocator: std.mem.Allocator) !void {
        if (self.ready) return;
        self.slots = try allocator.alloc(Slot, MAX_SLOTS);
        errdefer allocator.free(self.slots);
        self.free = try allocator.alloc(u32, MAX_SLOTS);
        errdefer allocator.free(self.free);
        for (self.slots, 0..) |*s, i| {
            s.* = .{};
            s.req_body = try allocator.alloc(u8, REQ_BODY_CAP);
            s.resp_body = try allocator.alloc(u8, RESP_BODY_CAP);
            self.free[i] = @intCast(i);
        }
        self.free_top = MAX_SLOTS;
        self.route_count = 0;
        self.ready = true;
    }

    pub fn deinit(self: *Bridge, allocator: std.mem.Allocator) void {
        if (!self.ready) return;
        for (self.slots) |*s| {
            allocator.free(s.req_body);
            allocator.free(s.resp_body);
        }
        allocator.free(self.slots);
        allocator.free(self.free);
        self.* = .{};
    }

    /// Clear routes/callback/io and the rings for a fresh embed cycle without
    /// freeing slot buffers. Called between cycles when no thread is running.
    pub fn resetRoutes(self: *Bridge) void {
        self.route_count = 0;
        self.callback = null;
        self.io = null;
        self.ring_head.store(0, .monotonic);
        self.ring_tail.store(0, .monotonic);
        self.preq_head.store(0, .monotonic);
        self.preq_tail.store(0, .monotonic);
        self.notify.store(false, .monotonic);
        self.free_top = MAX_SLOTS;
        for (self.slots, 0..) |*s, i| {
            s.in_use = false;
            s.awaiting.store(false, .monotonic);
            self.free[i] = @intCast(i);
        }
    }

    pub fn setCallback(self: *Bridge, cb: ?RequestCallback) void {
        self.callback = cb;
    }

    pub fn setIo(self: *Bridge, io: *io_mod.IoRuntime) void {
        self.io = io;
    }

    pub fn addRoute(self: *Bridge, pattern: []const u8, route_id: u32) bool {
        if (self.route_count >= MAX_ROUTES or pattern.len == 0 or pattern.len > PATH_CAP) return false;
        var r = &self.routes[self.route_count];
        @memcpy(r.pattern[0..pattern.len], pattern);
        r.pattern_len = @intCast(pattern.len);
        r.route_id = route_id;
        self.route_count += 1;
        return true;
    }

    /// Longest-prefix match of the request path against the registered FFI
    /// route patterns. Returns the route id, or null if no FFI route claims it.
    pub fn match(self: *const Bridge, path: []const u8) ?u32 {
        var best: ?u32 = null;
        var best_len: u16 = 0;
        var i: u16 = 0;
        while (i < self.route_count) : (i += 1) {
            const r = &self.routes[i];
            const pat = r.pattern[0..r.pattern_len];
            if (std.mem.startsWith(u8, path, pat) and r.pattern_len >= best_len) {
                best = r.route_id;
                best_len = r.pattern_len;
            }
        }
        return best;
    }

    // ── Reactor thread: park ────────────────────────────────────────────────
    pub fn park(
        self: *Bridge,
        conn_index: u32,
        conn_id: u64,
        route_id: u32,
        method: []const u8,
        path: []const u8,
        body: []const u8,
    ) ParkResult {
        if (method.len > METHOD_CAP or path.len > PATH_CAP or body.len > REQ_BODY_CAP) return .too_large;
        if (self.free_top == 0) return .no_slot;

        self.free_top -= 1;
        const idx = self.free[self.free_top];
        var s = &self.slots[idx];
        s.in_use = true;
        s.nonce +%= 1;
        s.conn_index = conn_index;
        s.conn_id = conn_id;
        s.route_id = route_id;
        @memcpy(s.method[0..method.len], method);
        s.method_len = @intCast(method.len);
        @memcpy(s.path[0..path.len], path);
        s.path_len = @intCast(path.len);
        @memcpy(s.req_body[0..body.len], body);
        s.req_body_len = @intCast(body.len);
        s.status = 0;
        s.resp_body_len = 0;
        // .monotonic: the slot payload is published by the preq_tail release
        // store below, which the host acquires — this flag needs no ordering.
        s.awaiting.store(true, .monotonic);

        const req_id = (@as(u64, s.nonce) << 32) | idx;

        // Publish onto the request ring (reactor is the sole producer). The
        // release store publishes the slot bytes written above.
        const tail = self.preq_tail.load(.monotonic);
        self.preq[tail] = req_id;
        self.preq_tail.store((tail + 1) & RING_MASK, .release);

        // Coalesced wake: invoke the host callback only on the false->true edge
        // of `notify`. Double-checked: a relaxed load elides the locked RMW on
        // the common batched path (host lagging, notify already true), so only
        // the actual transition pays the cmpxchg.
        if (self.callback != null and self.notify.load(.monotonic) == false) {
            if (self.notify.cmpxchgStrong(false, true, .acq_rel, .monotonic) == null) {
                self.callback.?(req_id);
            }
        }
        return .parked;
    }

    /// Host thread: pop the next parked req_id, or 0 if the ring is empty.
    pub fn pollRequest(self: *Bridge) u64 {
        const head = self.preq_head.load(.monotonic);
        const tail = self.preq_tail.load(.acquire);
        if (head == tail) return 0;
        const req_id = self.preq[head];
        self.preq_head.store((head + 1) & RING_MASK, .monotonic);
        return req_id;
    }

    /// Host thread: re-arm the coalesced wake after draining. Call when
    /// pollRequest returns 0; then poll once more to catch a request enqueued
    /// during the drain.
    pub fn notifyDone(self: *Bridge) void {
        self.notify.store(false, .release);
    }

    // ── Host thread: read request, write response ───────────────────────────
    fn resolve(self: *Bridge, req_id: u64) ?*Slot {
        const idx: u32 = @truncate(req_id);
        if (idx >= MAX_SLOTS) return null;
        const s = &self.slots[idx];
        const nonce: u32 = @truncate(req_id >> 32);
        if (s.nonce != nonce) return null;
        return s;
    }

    /// Fill `out` with [method_ptr, method_len, path_ptr, path_len, body_ptr,
    /// body_len] for the parked request. Returns 0 on success, -1 if req_id is
    /// stale/invalid. Pointers are valid until respond() is called.
    pub fn requestInfo(self: *Bridge, req_id: u64, out: *[6]usize) c_int {
        const s = self.resolve(req_id) orelse return -1;
        out[0] = @intFromPtr(&s.method);
        out[1] = s.method_len;
        out[2] = @intFromPtr(&s.path);
        out[3] = s.path_len;
        out[4] = @intFromPtr(s.req_body.ptr);
        out[5] = s.req_body_len;
        return 0;
    }

    /// Host-thread: record the response and hand the slot back to the reactor.
    /// Returns 0 on success, -1 if req_id is stale or already responded, -2 if
    /// the body/content-type exceeds the slot capacity.
    pub fn respond(
        self: *Bridge,
        req_id: u64,
        status: u16,
        ctype: []const u8,
        body: []const u8,
    ) c_int {
        const s = self.resolve(req_id) orelse return -1;
        if (ctype.len > CTYPE_CAP or body.len > RESP_BODY_CAP) return -2;
        // Exactly-once: only the first respond for this park wins.
        if (s.awaiting.cmpxchgStrong(true, false, .acq_rel, .monotonic) != null) return -1;

        s.status = status;
        @memcpy(s.ctype[0..ctype.len], ctype);
        s.ctype_len = @intCast(ctype.len);
        @memcpy(s.resp_body[0..body.len], body);
        s.resp_body_len = @intCast(body.len);

        // Publish onto the ring (release pairs with the reactor's acquire load).
        const tail = self.ring_tail.load(.monotonic);
        const next = (tail + 1) & RING_MASK;
        self.ring[tail] = @truncate(req_id);
        self.ring_tail.store(next, .release);

        if (self.io) |io| io.wake();
        return 0;
    }

    // ── Reactor thread: drain completions ───────────────────────────────────
    pub const Completion = struct {
        slot: u32,
        conn_index: u32,
        conn_id: u64,
        status: u16,
        ctype: []const u8,
        body: []const u8,
    };

    /// Pop one completed slot, or null if the ring is empty. Reactor-only.
    pub fn popCompletion(self: *Bridge) ?Completion {
        const head = self.ring_head.load(.monotonic);
        const tail = self.ring_tail.load(.acquire);
        if (head == tail) return null;
        const idx = self.ring[head];
        self.ring_head.store((head + 1) & RING_MASK, .monotonic);
        const s = &self.slots[idx];
        return .{
            .slot = idx,
            .conn_index = s.conn_index,
            .conn_id = s.conn_id,
            .status = s.status,
            .ctype = s.ctype[0..s.ctype_len],
            .body = s.resp_body[0..s.resp_body_len],
        };
    }

    /// Return a slot to the free pool after the reactor has resumed it.
    pub fn freeSlot(self: *Bridge, idx: u32) void {
        var s = &self.slots[idx];
        s.in_use = false;
        self.free[self.free_top] = idx;
        self.free_top += 1;
    }
};

/// Process-global bridge instance (one embedded server per process).
pub var instance: Bridge = .{};

test "bridge: route match longest prefix" {
    var b = Bridge{};
    try b.init(std.testing.allocator);
    defer b.deinit(std.testing.allocator);
    _ = b.addRoute("/api/", 1);
    _ = b.addRoute("/api/users/", 2);
    try std.testing.expectEqual(@as(?u32, 2), b.match("/api/users/7"));
    try std.testing.expectEqual(@as(?u32, 1), b.match("/api/orders"));
    try std.testing.expectEqual(@as(?u32, null), b.match("/static/x"));
}

test "bridge: cross-thread ring indices sit on separate cache lines" {
    const line = 64;
    // Each producer/consumer index and the wake flag must start on its own
    // cache line so a store by one thread does not invalidate an index the
    // other thread reads/writes (SPSC false sharing).
    inline for (.{ "ring_head", "ring_tail", "preq_head", "preq_tail", "notify" }) |field| {
        try std.testing.expectEqual(@as(usize, 0), @offsetOf(Bridge, field) % line);
    }
    // And no two of them land on the same line.
    try std.testing.expect(@offsetOf(Bridge, "ring_tail") != @offsetOf(Bridge, "preq_tail"));
    try std.testing.expect(@offsetOf(Bridge, "preq_tail") != @offsetOf(Bridge, "notify"));
}

test "bridge: coalesced wake fires once per drain cycle" {
    const S = struct {
        var count: u32 = 0;
        fn cb(_: u64) callconv(.c) void {
            count += 1;
        }
    };
    S.count = 0;
    var b = Bridge{};
    try b.init(std.testing.allocator);
    defer b.deinit(std.testing.allocator);
    b.setCallback(S.cb);

    // Three parks with no drain in between: the callback fires only once
    // (false->true edge), and all three req_ids are queued.
    _ = b.park(0, 1, 0, "GET", "/a", "");
    _ = b.park(0, 2, 0, "GET", "/b", "");
    _ = b.park(0, 3, 0, "GET", "/c", "");
    try std.testing.expectEqual(@as(u32, 1), S.count);
    try std.testing.expect(b.pollRequest() != 0);
    try std.testing.expect(b.pollRequest() != 0);
    try std.testing.expect(b.pollRequest() != 0);
    try std.testing.expectEqual(@as(u64, 0), b.pollRequest());
    // After draining and re-arming, the next park wakes again.
    b.notifyDone();
    _ = b.park(0, 4, 0, "GET", "/d", "");
    try std.testing.expectEqual(@as(u32, 2), S.count);
}

test "bridge: park/poll/respond/drain round-trip" {
    var b = Bridge{};
    try b.init(std.testing.allocator);
    defer b.deinit(std.testing.allocator);

    try std.testing.expectEqual(ParkResult.parked, b.park(3, 99, 0, "POST", "/api/x", "hello"));
    const req_id = b.pollRequest();
    try std.testing.expect(req_id != 0);

    var info: [6]usize = undefined;
    try std.testing.expectEqual(@as(c_int, 0), b.requestInfo(req_id, &info));
    try std.testing.expectEqual(@as(usize, 5), info[5]); // body len

    try std.testing.expectEqual(@as(c_int, 0), b.respond(req_id, 200, "application/json", "{\"ok\":true}"));
    // Double respond rejected.
    try std.testing.expectEqual(@as(c_int, -1), b.respond(req_id, 200, "", ""));

    const c = b.popCompletion() orelse return error.NoCompletion;
    try std.testing.expectEqual(@as(u32, 3), c.conn_index);
    try std.testing.expectEqual(@as(u64, 99), c.conn_id);
    try std.testing.expectEqual(@as(u16, 200), c.status);
    try std.testing.expectEqualStrings("{\"ok\":true}", c.body);
    b.freeSlot(c.slot);
    try std.testing.expectEqual(@as(?Bridge.Completion, null), b.popCompletion());
}
