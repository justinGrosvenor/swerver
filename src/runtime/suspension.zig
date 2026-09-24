//! Bounded, reactor-owned handler continuations. No worker threads or per-wait
//! kernel objects. Timers and explicit completion use the same slot lifecycle.
const std = @import("std");
const response = @import("../response/response.zig");
const clock = @import("clock.zig");
const middleware = @import("../middleware/middleware.zig");

pub const STASH_CAPACITY = 256;
pub const Token = struct { index: u32, generation: u64 };
pub const Identity = struct {
    conn_index: u32,
    conn_id: u64,
    stream_id: u64 = 0,
    protocol: middleware.Context.Protocol = .http1,
};
pub const Event = enum { ready, timeout };
pub const CancelReason = enum { disconnected, reset, abandoned, shutdown, reload, cancelled };
pub const Error = error{ Unavailable, Full, AlreadyParked, InvalidDelay, ClockUnavailable, OutOfMemory, SnapshotTooLarge };
pub const Continuation = *const fn (*ResumeContext) response.Response;
pub const CancelFn = *const fn (*CancelContext) void;
pub const Options = struct { on_cancel: ?CancelFn = null };

pub fn assertPlainData(comptime T: type) void {
    switch (@typeInfo(T)) {
        .int, .float, .bool, .void, .@"enum" => {},
        .array => |a| assertPlainData(a.child),
        .optional => |o| assertPlainData(o.child),
        .@"struct" => |s| inline for (s.fields) |f| assertPlainData(f.type),
        .@"union" => |u| inline for (u.fields) |f| assertPlainData(f.type),
        else => @compileError("suspension stash must contain only plain values; copy request bytes into fixed arrays"),
    }
    if (@sizeOf(T) > STASH_CAPACITY or @alignOf(T) > 16)
        @compileError("suspension stash exceeds 256 bytes or 16-byte alignment");
}

pub const CancelContext = struct {
    app_state: ?*anyopaque = null,
    reason: CancelReason,
    bytes: *align(16) [STASH_CAPACITY]u8,

    pub fn stash(self: *CancelContext, comptime T: type) *T {
        comptime assertPlainData(T);
        return @ptrCast(@alignCast(self.bytes));
    }
};

/// Request-independent scratch. Never contains borrowed request buffers.
pub const ResumeContext = struct {
    app_state: ?*anyopaque = null,
    event: Event,
    response_buf: []u8,
    suspension: Handle,
    bytes: *align(16) [STASH_CAPACITY]u8,

    pub fn stash(self: *ResumeContext, comptime T: type) *T {
        comptime assertPlainData(T);
        return @ptrCast(@alignCast(self.bytes));
    }

    pub fn state(self: *ResumeContext, comptime T: type) *T {
        return @ptrCast(@alignCast(self.app_state.?));
    }

    pub fn text(_: *ResumeContext, status: u16, body: []const u8) response.Response {
        return .{ .status = status, .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }}, .body = .{ .bytes = body } };
    }
};

/// Router-owned metadata, retained across chains and released after encoding.
pub const Attachment = struct {
    ctx: *anyopaque,
    retain: *const fn (*anyopaque) void,
    release: *const fn (*anyopaque) void,
};

pub const Pending = struct {
    token: Token,
    response: response.Response = response.Response.parked,
};

/// All methods must run on the owning reactor thread. A saved handle is valid
/// only for complete(), and only while its Server lives. sleep()/wait() may
/// only be called during the handler or continuation that received this handle.
/// Tokens do not retain request scratch or sockets.
pub const Handle = struct {
    did_park: bool = false,
    app_state: ?*anyopaque = null,
    table: ?*Table = null,
    identity: Identity = .{ .conn_index = 0, .conn_id = 0 },
    prepare_ctx: ?*anyopaque = null,
    prepare: ?*const fn (*anyopaque) Error!Attachment = null,
    attachment: ?Attachment = null,

    pub fn sleep(self: *Handle, ms: u64, comptime T: type, value: T, next: Continuation) Error!response.Response {
        return (try self.park(ms, .ready, T, value, next, .{})).response;
    }

    /// Park until complete(token) or the timeout. on_cancel releases application
    /// resources when the request disappears; it cannot produce a response.
    pub fn wait(self: *Handle, timeout_ms: u64, comptime T: type, value: T, next: Continuation, options: Options) Error!Pending {
        return self.park(timeout_ms, .timeout, T, value, next, options);
    }

    fn park(self: *Handle, ms: u64, event: Event, comptime T: type, value: T, next: Continuation, options: Options) Error!Pending {
        comptime assertPlainData(T);
        const table = self.table orelse return error.Unavailable;
        const now = clock.Instant.now() orelse return error.ClockUnavailable;
        const duration = std.math.mul(u64, ms, std.time.ns_per_ms) catch return error.InvalidDelay;
        const deadline = std.math.add(u64, now.ns, duration) catch return error.InvalidDelay;
        // Reserve before copying metadata so Full never allocates a snapshot.
        const token = try table.reserve(self.identity, deadline, event, std.mem.asBytes(&value), next, options);
        errdefer table.discard(token);
        const a = if (self.attachment) |attachment| blk: {
            attachment.retain(attachment.ctx);
            break :blk attachment;
        } else if (self.prepare) |prepare| try prepare(self.prepare_ctx.?) else null;
        table.slots[token.index].attachment = a;
        table.slots[token.index].app_state = self.app_state;
        self.did_park = true;
        return .{ .token = token };
    }

    /// Queue completion; never invokes a continuation inline. Late/duplicate
    /// tokens (including a deadline that already elapsed) return false.
    pub fn complete(self: Handle, token: Token) bool {
        const table = self.table orelse return false;
        const now = clock.Instant.now() orelse return false;
        return table.complete(token, now.ns);
    }
};

const ConnectionKey = struct { index: u32, id: u64 };

const NONE = std.math.maxInt(u32);
const Slot = struct {
    generation: u64 = 0,
    active: bool = false,
    identity: Identity = undefined,
    deadline_ns: u64 = 0,
    heap_pos: u32 = NONE,
    next_free: u32 = NONE,
    conn_prev: u32 = NONE,
    conn_next: u32 = NONE,
    app_state: ?*anyopaque = null,
    event: Event = .ready,
    completed: bool = false,
    continuation: Continuation = undefined,
    on_cancel: ?CancelFn = null,
    bytes: [STASH_CAPACITY]u8 align(16) = undefined,
    attachment: ?Attachment = null,
};

pub const Outcome = struct {
    app_state: ?*anyopaque,
    identity: Identity,
    event: Event,
    continuation: Continuation,
    bytes: [STASH_CAPACITY]u8 align(16),
    attachment: ?Attachment,
    on_cancel: ?CancelFn,

    pub fn release(self: *Outcome) void {
        if (self.attachment) |a| a.release(a.ctx);
        self.attachment = null;
    }

    pub fn cancelled(self: *Outcome, reason: CancelReason) void {
        if (self.on_cancel) |f| {
            var ctx = CancelContext{ .reason = reason, .bytes = &self.bytes, .app_state = self.app_state };
            f(&ctx);
        }
        self.release();
    }
};

/// Lazily allocated slab + indexed min heap. O(log n) insert/expiry/cancel,
/// O(1) request lookup, fixed maximum live waits. The common idle path is a
/// single count check, with no allocation and no connection-layout growth.
pub const Table = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    slots: []Slot = &.{},
    heap: []u32 = &.{},
    by_request: std.AutoHashMapUnmanaged(Identity, u32) = .empty,
    connections: std.AutoHashMapUnmanaged(ConnectionKey, u32) = .empty,
    count: usize = 0,
    free_head: u32 = NONE,
    closing: bool = false,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) Table {
        return .{ .allocator = allocator, .capacity = capacity };
    }

    pub fn deinit(self: *Table) void {
        self.closing = true;
        self.cancelAll(.shutdown);
        self.by_request.deinit(self.allocator);
        self.connections.deinit(self.allocator);
        self.allocator.free(self.heap);
        self.allocator.free(self.slots);
        self.heap = &.{};
        self.slots = &.{};
    }

    fn allocate(self: *Table) Error!void {
        if (self.slots.len != 0) return;
        if (self.capacity == 0 or self.capacity >= NONE) return error.Full;
        const slots = try self.allocator.alloc(Slot, self.capacity);
        errdefer self.allocator.free(slots);
        const heap = try self.allocator.alloc(u32, self.capacity);
        errdefer self.allocator.free(heap);
        try self.by_request.ensureTotalCapacity(self.allocator, @intCast(self.capacity));
        try self.connections.ensureTotalCapacity(self.allocator, @intCast(self.capacity));
        for (slots, 0..) |*s, i| s.* = .{ .next_free = if (i + 1 == slots.len) NONE else @intCast(i + 1) };
        self.slots = slots;
        self.heap = heap;
        self.free_head = 0;
    }

    pub fn reserve(self: *Table, id: Identity, deadline_ns: u64, event: Event, bytes: []const u8, next: Continuation, options: Options) Error!Token {
        if (self.closing) return error.Unavailable;
        if (self.has(id)) return error.AlreadyParked;
        if (self.count == self.capacity) return error.Full;
        try self.allocate();
        std.debug.assert(bytes.len <= STASH_CAPACITY);
        const index = self.free_head;
        const s = &self.slots[index];
        self.free_head = s.next_free;
        s.generation +%= 1;
        if (s.generation == 0) s.generation = 1;
        s.active = true;
        s.identity = id;
        s.deadline_ns = deadline_ns;
        s.event = event;
        s.completed = false;
        s.continuation = next;
        s.on_cancel = options.on_cancel;
        s.attachment = null;
        s.app_state = null;
        @memset(&s.bytes, 0);
        @memcpy(s.bytes[0..bytes.len], bytes);
        self.by_request.putAssumeCapacity(id, index);
        const key = ConnectionKey{ .index = id.conn_index, .id = id.conn_id };
        s.conn_prev = NONE;
        s.conn_next = self.connections.get(key) orelse NONE;
        if (s.conn_next != NONE) self.slots[s.conn_next].conn_prev = index;
        self.connections.putAssumeCapacity(key, index);
        s.heap_pos = @intCast(self.count);
        self.heap[self.count] = index;
        self.count += 1;
        self.up(s.heap_pos);
        return .{ .index = index, .generation = s.generation };
    }

    pub fn has(self: *const Table, id: Identity) bool {
        return self.count != 0 and self.by_request.contains(id);
    }

    fn live(self: *Table, token: Token) ?*Slot {
        if (token.index >= self.slots.len) return null;
        const s = &self.slots[token.index];
        return if (s.active and s.generation == token.generation) s else null;
    }

    pub fn complete(self: *Table, token: Token, now_ns: u64) bool {
        const s = self.live(token) orelse return false;
        if (s.completed or now_ns >= s.deadline_ns) return false;
        s.completed = true;
        s.event = .ready;
        s.deadline_ns = now_ns;
        self.up(s.heap_pos);
        return true;
    }

    pub fn pollTimeout(self: *const Table, now_ns: u64, maximum_ms: u32) u32 {
        if (self.count == 0) return maximum_ms;
        const deadline = self.slots[self.heap[0]].deadline_ns;
        if (deadline <= now_ns) return 0;
        // Round UP: a sub-millisecond remainder must not fire early or spin.
        const ns = deadline - now_ns;
        const ms = ns / std.time.ns_per_ms + @intFromBool(ns % std.time.ns_per_ms != 0);
        return @intCast(@min(ms, maximum_ms));
    }

    pub fn pop(self: *Table, now_ns: u64) ?Outcome {
        if (self.count == 0) return null;
        const index = self.heap[0];
        if (self.slots[index].deadline_ns > now_ns) return null;
        return self.remove(index);
    }

    fn remove(self: *Table, index: u32) Outcome {
        const s = &self.slots[index];
        const out = Outcome{ .app_state = s.app_state, .identity = s.identity, .event = s.event, .continuation = s.continuation, .bytes = s.bytes, .attachment = s.attachment, .on_cancel = s.on_cancel };
        _ = self.by_request.remove(s.identity);
        const key = ConnectionKey{ .index = s.identity.conn_index, .id = s.identity.conn_id };
        if (s.conn_prev != NONE) {
            self.slots[s.conn_prev].conn_next = s.conn_next;
        } else if (s.conn_next != NONE) {
            self.connections.putAssumeCapacity(key, s.conn_next);
        } else {
            _ = self.connections.remove(key);
        }
        if (s.conn_next != NONE) self.slots[s.conn_next].conn_prev = s.conn_prev;
        self.count -= 1;
        const pos = s.heap_pos;
        if (pos < self.count) {
            const replacement = self.heap[self.count];
            self.heap[pos] = replacement;
            self.slots[replacement].heap_pos = pos;
            self.up(pos);
            self.down(self.slots[replacement].heap_pos);
        }
        s.active = false;
        s.attachment = null;
        s.next_free = self.free_head;
        self.free_head = index;
        return out;
    }

    fn discard(self: *Table, token: Token) void {
        if (self.live(token) != null) {
            var out = self.remove(token.index);
            out.release();
        }
    }

    pub fn cancel(self: *Table, token: Token, reason: CancelReason) bool {
        if (self.live(token) == null) return false;
        const was_closing = self.closing;
        self.closing = true;
        defer self.closing = was_closing;
        var out = self.remove(token.index);
        out.cancelled(reason);
        return true;
    }

    pub fn cancelRequest(self: *Table, id: Identity, reason: CancelReason) void {
        const index = self.by_request.get(id) orelse return;
        const was_closing = self.closing;
        self.closing = true;
        defer self.closing = was_closing;
        var out = self.remove(index);
        out.cancelled(reason);
    }

    pub fn cancelConnection(self: *Table, conn_index: u32, conn_id: u64, reason: CancelReason) void {
        const was_closing = self.closing;
        self.closing = true;
        defer self.closing = was_closing;
        const key = ConnectionKey{ .index = conn_index, .id = conn_id };
        while (self.connections.get(key)) |index| {
            var out = self.remove(index);
            out.cancelled(reason);
        }
    }

    pub fn cancelAll(self: *Table, reason: CancelReason) void {
        const was_closing = self.closing;
        self.closing = true;
        defer self.closing = was_closing;
        while (self.count > 0) {
            var out = self.remove(self.heap[0]);
            out.cancelled(reason);
        }
    }

    fn less(self: *Table, a: usize, b: usize) bool {
        return self.slots[self.heap[a]].deadline_ns < self.slots[self.heap[b]].deadline_ns;
    }
    fn swap(self: *Table, a: usize, b: usize) void {
        std.mem.swap(u32, &self.heap[a], &self.heap[b]);
        self.slots[self.heap[a]].heap_pos = @intCast(a);
        self.slots[self.heap[b]].heap_pos = @intCast(b);
    }
    fn up(self: *Table, start: usize) void {
        var i = start;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (!self.less(i, parent)) break;
            self.swap(i, parent);
            i = parent;
        }
    }
    fn down(self: *Table, start: usize) void {
        var i = start;
        while (i * 2 + 1 < self.count) {
            var child = i * 2 + 1;
            if (child + 1 < self.count and self.less(child + 1, child)) child += 1;
            if (!self.less(child, i)) break;
            self.swap(i, child);
            i = child;
        }
    }
};

fn testContinuation(_: *ResumeContext) response.Response {
    return response.Response.ok();
}

test "suspension: lazy allocation, bounded capacity, stale and duplicate completion" {
    const t = std.testing;
    var table = Table.init(t.allocator, 1);
    defer table.deinit();
    try t.expectEqual(@as(usize, 0), table.slots.len);
    try t.expectEqual(@as(u32, 10), table.pollTimeout(0, 10));
    const id = Identity{ .conn_index = 7, .conn_id = 19 };
    const token = try table.reserve(id, 100, .timeout, "first", testContinuation, .{});
    try t.expectError(error.AlreadyParked, table.reserve(id, 100, .ready, "", testContinuation, .{}));
    try t.expectError(error.Full, table.reserve(.{ .conn_index = 8, .conn_id = 20 }, 100, .ready, "", testContinuation, .{}));
    try t.expect(table.complete(token, 50));
    try t.expect(!table.complete(token, 51));
    var out = table.pop(50).?;
    defer out.release();
    try t.expectEqual(Event.ready, out.event);
    try t.expectEqualStrings("first", out.bytes[0..5]);
    const next = try table.reserve(id, 200, .timeout, "second", testContinuation, .{});
    try t.expectEqual(token.index, next.index);
    try t.expect(!table.complete(token, 60));
    try t.expect(!table.cancel(token, .cancelled));
    try t.expect(!table.complete(next, 200));
    var expired = table.pop(200).?;
    defer expired.release();
    try t.expectEqual(Event.timeout, expired.event);
    try t.expectEqualStrings("second", expired.bytes[0..6]);
}

test "suspension: timers never expire early and poll rounds up" {
    const t = std.testing;
    var table = Table.init(t.allocator, 2);
    defer table.deinit();
    _ = try table.reserve(.{ .conn_index = 1, .conn_id = 1 }, 10_500_001, .ready, "", testContinuation, .{});
    try t.expectEqual(@as(u32, 1), table.pollTimeout(10_000_000, 10));
    try t.expect(table.pop(10_500_000) == null);
    var out = table.pop(10_500_001).?;
    defer out.release();
    try t.expectEqual(Event.ready, out.event);
}

test "suspension: 32000 shuffled deadlines with cancellation preserve heap order" {
    const t = std.testing;
    const count = 32000;
    var table = Table.init(t.allocator, count);
    defer table.deinit();
    const tokens = try t.allocator.alloc(Token, count);
    defer t.allocator.free(tokens);
    for (tokens, 0..) |*token, i| {
        // Odd multiplier coprime to 32000 visits every deadline once.
        token.* = try table.reserve(.{ .conn_index = @intCast(i), .conn_id = 1 }, (i * 7919) % count + 1, .ready, "", testContinuation, .{});
    }
    for (tokens, 0..) |token, i| if (i % 3 == 0) {
        try t.expect(table.cancel(token, .cancelled));
    };
    var previous: u64 = 0;
    var seen: usize = 0;
    while (table.count > 0) {
        const deadline = table.slots[table.heap[0]].deadline_ns;
        try t.expect(deadline > previous);
        previous = deadline;
        var out = table.pop(deadline).?;
        out.release();
        seen += 1;
    }
    try t.expectEqual(@as(usize, count - (count + 2) / 3), seen);
}

test "suspension: stream cancellation and shutdown call cleanup exactly once" {
    const t = std.testing;
    const Probe = struct {
        var cancels: usize = 0;
        fn cancel(ctx: *CancelContext) void {
            cancels += ctx.stash(u32).*;
        }
    };
    Probe.cancels = 0;
    var table = Table.init(t.allocator, 4);
    defer table.deinit();
    const one: u32 = 1;
    const a = Identity{ .conn_index = 3, .conn_id = 20, .stream_id = 1, .protocol = .http2 };
    const b = Identity{ .conn_index = 3, .conn_id = 20, .stream_id = 3, .protocol = .http2 };
    const c = Identity{ .conn_index = 3, .conn_id = 21, .stream_id = 1, .protocol = .http2 };
    _ = try table.reserve(a, 100, .ready, std.mem.asBytes(&one), testContinuation, .{ .on_cancel = Probe.cancel });
    _ = try table.reserve(b, 100, .ready, std.mem.asBytes(&one), testContinuation, .{ .on_cancel = Probe.cancel });
    _ = try table.reserve(c, 100, .ready, std.mem.asBytes(&one), testContinuation, .{ .on_cancel = Probe.cancel });
    table.cancelRequest(a, .reset);
    table.cancelRequest(a, .reset);
    try t.expect(table.has(b) and table.has(c));
    table.cancelConnection(3, 20, .disconnected);
    try t.expect(!table.has(b) and table.has(c));
    try t.expectEqual(@as(usize, 2), Probe.cancels);
    table.cancelAll(.shutdown);
    try t.expectEqual(@as(usize, 3), Probe.cancels);
    try t.expectEqual(@as(usize, 0), table.count);
}

test "suspension: public sleep and wait own plain stashes and validate deadlines" {
    const t = std.testing;
    var table = Table.init(t.allocator, 2);
    defer table.deinit();
    var handle = Handle{ .table = &table, .identity = .{ .conn_index = 0, .conn_id = 1 } };
    try t.expectError(error.InvalidDelay, handle.sleep(std.math.maxInt(u64), u32, 42, testContinuation));
    var value: u32 = 42;
    try t.expect((try handle.sleep(0, u32, value, testContinuation)).isParked());
    value = 0;
    var out = table.pop(std.math.maxInt(u64)).?;
    defer out.release();
    var ctx = ResumeContext{ .event = out.event, .response_buf = &.{}, .bytes = &out.bytes, .suspension = handle };
    try t.expectEqual(@as(u32, 42), ctx.stash(u32).*);
    const pending = try handle.wait(1000, u32, 9, testContinuation, .{});
    try t.expect(pending.response.isParked());
    try t.expect(handle.complete(pending.token));
    try t.expect(!handle.complete(pending.token));
}

test "suspension: cancellation cannot repark and allocation failure leaks no slots" {
    const Probe = struct {
        table: *Table,
        blocked: bool = false,
        fn cancel(ctx: *CancelContext) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.app_state.?));
            _ = self.table.reserve(.{ .conn_index = 0, .conn_id = 1 }, 20, .ready, "", testContinuation, .{}) catch |err| {
                self.blocked = err == error.Unavailable;
                return;
            };
        }
        fn allocate(allocator: std.mem.Allocator) !void {
            var table = Table.init(allocator, 2);
            defer table.deinit();
            _ = try table.reserve(.{ .conn_index = 0, .conn_id = 1 }, 20, .ready, "", testContinuation, .{});
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Probe.allocate, .{});
    var table = Table.init(std.testing.allocator, 1);
    defer table.deinit();
    var probe = Probe{ .table = &table };
    const token = try table.reserve(.{ .conn_index = 0, .conn_id = 1 }, 20, .ready, "", testContinuation, .{ .on_cancel = Probe.cancel });
    table.slots[token.index].app_state = &probe;
    try std.testing.expect(table.cancel(token, .reset));
    try std.testing.expect(probe.blocked);
    try std.testing.expectEqual(@as(usize, 0), table.count);
}
