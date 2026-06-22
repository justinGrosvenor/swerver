//! Nether sandbox client (design 11.0) — per-worker driver for Tier-2
//! microVM sandboxes over Nether's unix control socket.
//!
//! Structurally the PostgreSQL client (db/pg/client.zig): a per-worker slot
//! pool, a bounded park table, external-FD reactor dispatch, and the
//! park-and-resume contract. The protocol is simpler — write `command\n`,
//! read a `<output>0x1e<exit>\n` framed reply.
//!
//! SPIKE SCOPE (phase 0): the line-exec transport over a unix control
//! socket, and the client-side exec/park/scan/resume logic with a DB-free
//! test. Still to wire (phase 0/1, needs a live nether + box): the reactor
//! onEvent route in dispatch.zig, the `ctx.sandbox` handle on the router,
//! subprocess spawn + nether.conf generation, and the resume hook install.
//! The transport is deliberately behind `connectSlot`/`flush`/`readInto`
//! so it can become the in-process embeddable core later (design 11.0
//! transport seam) without touching exec/scan/deliver.

const std = @import("std");
const builtin = @import("builtin");
const io_mod = @import("../runtime/io.zig");
const clock = @import("../runtime/clock.zig");
const response_mod = @import("../response/response.zig");
const api = @import("handler_api.zig");

pub const MAX_SLOTS = 16;
pub const DEFAULT_POOL_SIZE = 4;
pub const MAX_PARKED = 64;
const NO_PARK: u16 = std.math.maxInt(u16);

const RECV_BUF_SIZE = 64 * 1024; // guest output can be large
const SEND_BUF_SIZE = 8 * 1024;
const DEFAULT_EXEC_TIMEOUT_MS: u64 = 30_000;
const BACKOFF_INITIAL_MS: u64 = 500;
const BACKOFF_MAX_MS: u64 = 15_000;

pub const SlotState = enum { closed, connecting, ready, busy, failed };

pub const Slot = struct {
    state: SlotState = .closed,
    fd: std.posix.fd_t = -1,
    recv_buf: [RECV_BUF_SIZE]u8 = undefined,
    recv_len: usize = 0,
    send_buf: [SEND_BUF_SIZE]u8 = undefined,
    send_len: usize = 0,
    send_off: usize = 0,
    /// Park-table index of the in-flight exec (`.busy`); NO_PARK when the
    /// requester vanished (the op still drains, outcome discarded).
    park: u16 = NO_PARK,
    deadline_ms: u64 = 0,
    retry_at_ms: u64 = 0,
    backoff_ms: u64 = 0,
};

/// One parked HTTP request awaiting an exec. The continuation, stash, and
/// generation check live here — the Connection carries only the
/// `.sandbox_parked` state byte.
const ParkedRequest = struct {
    active: bool = false,
    conn_index: u32 = 0,
    conn_id: u64 = 0,
    continuation: api.Continuation = undefined,
    stash: [api.STASH_CAPACITY]u8 align(16) = undefined,
    deadline_ms: u64 = 0,
    pending_error: ?api.SandboxError = null,
};

/// Everything the resume layer needs to run a continuation. Borrowed fields
/// (the result output) are valid only inside the resume callback.
pub const Outcome = struct {
    conn_index: u32,
    conn_id: u64,
    continuation: api.Continuation,
    stash: *[api.STASH_CAPACITY]u8,
    result: api.SandboxError!api.SandboxResult,
};

/// Installed by the server: runs the continuation against the
/// (generation-checked) HTTP connection and enqueues its response.
pub const ResumeFn = *const fn (ctx: *anyopaque, outcome: *const Outcome) void;

pub const Options = struct {
    /// Control-socket path (per sandbox). The spike connects to a
    /// pre-existing socket; subprocess spawn + per-slot paths is phase 1.
    socket_path: []const u8,
    pool_size: u8 = DEFAULT_POOL_SIZE,
    exec_timeout_ms: u64 = DEFAULT_EXEC_TIMEOUT_MS,
};

pub const NetherClient = struct {
    opts: Options,
    slots: [MAX_SLOTS]Slot = [1]Slot{.{}} ** MAX_SLOTS,
    parked: [MAX_PARKED]ParkedRequest = [1]ParkedRequest{.{}} ** MAX_PARKED,
    conn_parks: []u16,
    allocator: std.mem.Allocator,
    resume_ctx: ?*anyopaque = null,
    resume_fn: ?ResumeFn = null,

    pub const InitError = error{ InvalidPoolSize, OutOfMemory };

    pub fn init(allocator: std.mem.Allocator, max_connections: usize, opts: Options) InitError!NetherClient {
        if (opts.pool_size == 0 or opts.pool_size > MAX_SLOTS) return error.InvalidPoolSize;
        const conn_parks = try allocator.alloc(u16, max_connections);
        @memset(conn_parks, NO_PARK);
        return .{ .opts = opts, .conn_parks = conn_parks, .allocator = allocator };
    }

    pub fn deinit(self: *NetherClient, io_rt: *io_mod.IoRuntime) void {
        for (&self.slots) |*slot| {
            if (slot.fd >= 0) {
                io_rt.unregisterExternalFd(slot.fd) catch {};
                clock.closeFd(slot.fd);
                slot.fd = -1;
            }
            slot.state = .closed;
        }
        self.allocator.free(self.conn_parks);
    }

    pub fn installResume(self: *NetherClient, ctx: *anyopaque, f: ResumeFn) void {
        self.resume_ctx = ctx;
        self.resume_fn = f;
    }

    pub fn anyReady(self: *const NetherClient) bool {
        for (self.slots[0..self.opts.pool_size]) |*s| if (s.state == .ready) return true;
        return false;
    }

    pub fn hasParkFor(self: *const NetherClient, conn_index: u32, conn_id: u64) bool {
        if (conn_index >= self.conn_parks.len) return false;
        const pi = self.conn_parks[conn_index];
        if (pi == NO_PARK) return false;
        const e = &self.parked[pi];
        return e.active and e.conn_id == conn_id;
    }

    /// Issue one exec on a ready slot and park the request. The continuation
    /// never runs synchronously inside this call (a flush failure surfaces
    /// as NotConnected to the still-running handler).
    pub fn exec(
        self: *NetherClient,
        io_rt: *io_mod.IoRuntime,
        conn_index: u32,
        conn_id: u64,
        command: []const u8,
        stash_bytes: []const u8,
        continuation: api.Continuation,
    ) api.QueryError!response_mod.Response {
        std.debug.assert(stash_bytes.len <= api.STASH_CAPACITY);
        if (conn_index >= self.conn_parks.len) return error.NotConnected;
        if (self.conn_parks[conn_index] != NO_PARK) return error.AlreadyParked;

        var idx: ?u32 = null;
        for (0..self.opts.pool_size) |i| {
            if (self.slots[i].state == .ready) {
                idx = @intCast(i);
                break;
            }
        }
        const sidx = idx orelse return error.NotConnected;
        const slot = &self.slots[sidx];

        // command + newline must fit the send buffer.
        if (command.len + 1 > slot.send_buf.len) return error.RequestTooLarge;

        const park_idx: u16 = blk: {
            for (&self.parked, 0..) |*p, i| if (!p.active) break :blk @intCast(i);
            return error.ParkTableFull;
        };

        @memcpy(slot.send_buf[0..command.len], command);
        slot.send_buf[command.len] = '\n';
        slot.send_len = command.len + 1;
        slot.send_off = 0;
        slot.recv_len = 0;

        const now_ms = io_rt.nowMs();
        const entry = &self.parked[park_idx];
        entry.* = .{
            .active = true,
            .conn_index = conn_index,
            .conn_id = conn_id,
            .continuation = continuation,
            .deadline_ms = now_ms + self.opts.exec_timeout_ms,
        };
        @memcpy(entry.stash[0..stash_bytes.len], stash_bytes);
        if (stash_bytes.len < entry.stash.len) @memset(entry.stash[stash_bytes.len..], 0);

        slot.state = .busy;
        slot.park = NO_PARK; // attach only after the flush succeeds
        if (!self.flush(io_rt, sidx, now_ms)) {
            entry.active = false;
            return error.NotConnected;
        }
        slot.park = park_idx;
        slot.deadline_ms = entry.deadline_ms;
        self.conn_parks[conn_index] = park_idx;
        return response_mod.Response.parked;
    }

    /// The HTTP connection died/recycled while parked: drop the park and
    /// detach the in-flight op (it still drains; outcome discarded).
    pub fn cancelForConn(self: *NetherClient, conn_index: u32, conn_id: u64) void {
        if (conn_index >= self.conn_parks.len) return;
        const pi = self.conn_parks[conn_index];
        if (pi == NO_PARK) return;
        const e = &self.parked[pi];
        if (!e.active or e.conn_id != conn_id) return;
        e.active = false;
        e.pending_error = null;
        self.conn_parks[conn_index] = NO_PARK;
        for (&self.slots) |*s| if (s.state == .busy and s.park == pi) {
            s.park = NO_PARK;
        };
    }

    /// Single reactor entry point for external-FD events tagged to this
    /// client. (Wiring in dispatch.zig is phase 0/1.)
    pub fn onEvent(self: *NetherClient, io_rt: *io_mod.IoRuntime, slot_idx: u32, kind: io_mod.EventKind) void {
        if (slot_idx >= self.opts.pool_size) return;
        const slot = &self.slots[slot_idx];
        if (slot.fd < 0) return;
        const now_ms = io_rt.nowMs();
        switch (kind) {
            .err => self.failSlot(io_rt, slot_idx, now_ms, "socket error"),
            .write => if (slot.state == .busy) {
                _ = self.flush(io_rt, slot_idx, now_ms);
            },
            .read => if (slot.state == .busy) self.pumpRead(io_rt, slot_idx, now_ms),
            .accept, .datagram => {},
        }
    }

    /// Read available bytes into the slot and scan for a complete reply.
    fn pumpRead(self: *NetherClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        while (slot.state == .busy) {
            if (slot.recv_len == slot.recv_buf.len) {
                if (slot.park != NO_PARK and self.parked[slot.park].active) {
                    self.parked[slot.park].pending_error = error.ResultTooLarge;
                    self.deliverPending(slot.park);
                    slot.park = NO_PARK;
                }
                return self.failSlot(io_rt, idx, now_ms, "reply exceeded recv buffer");
            }
            const raw = std.posix.system.read(slot.fd, slot.recv_buf[slot.recv_len..].ptr, slot.recv_buf.len - slot.recv_len);
            if (raw == 0) return self.failSlot(io_rt, idx, now_ms, "sandbox closed connection");
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => return,
                    .INTR => continue,
                    else => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                }
            }
            slot.recv_len += @intCast(raw);
            if (self.scanSlot(idx)) return; // delivered + slot back to ready
        }
    }

    /// Parse a complete reply from the slot recv buffer; deliver it and
    /// return the slot to ready. Returns true when a reply was delivered.
    /// Pure over the slot buffer — the DB-free tests drive this directly.
    fn scanSlot(self: *NetherClient, idx: u32) bool {
        const slot = &self.slots[idx];
        const parsed = api.parseReply(slot.recv_buf[0..slot.recv_len]) catch {
            // malformed framing: fail the op (and the slot, by the caller).
            if (slot.park != NO_PARK and self.parked[slot.park].active) {
                self.parked[slot.park].pending_error = error.Malformed;
                self.deliverPending(slot.park);
            }
            slot.park = NO_PARK;
            slot.recv_len = 0;
            return true;
        };
        const p = parsed orelse return false; // need more bytes
        const park = slot.park;
        slot.park = NO_PARK;
        if (park != NO_PARK) {
            self.deliverOutcome(park, p.result);
        }
        if (builtin.mode == .Debug) @memset(slot.recv_buf[0..p.consumed], 0xAA);
        slot.recv_len = 0;
        slot.state = .ready;
        return true;
    }

    fn deliverPending(self: *NetherClient, park_idx: u16) void {
        const err = self.parked[park_idx].pending_error orelse return;
        self.deliverOutcome(park_idx, err);
    }

    fn deliverOutcome(self: *NetherClient, park_idx: u16, result: api.SandboxError!api.SandboxResult) void {
        const entry = &self.parked[park_idx];
        if (!entry.active) return;
        if (entry.conn_index < self.conn_parks.len and self.conn_parks[entry.conn_index] == park_idx) {
            self.conn_parks[entry.conn_index] = NO_PARK;
        }
        if (self.resume_fn) |rf| {
            const outcome = Outcome{
                .conn_index = entry.conn_index,
                .conn_id = entry.conn_id,
                .continuation = entry.continuation,
                .stash = &entry.stash,
                .result = result,
            };
            rf(self.resume_ctx.?, &outcome);
        } else {
            std.log.debug("sandbox: dropping outcome (no resume hook)", .{});
        }
        entry.active = false;
        entry.pending_error = null;
    }

    /// Housekeeping: exec deadlines and reconnect backoff. Failure outcomes
    /// are delivered here, never inside exec()/failSlot(), so a continuation
    /// never runs beneath the issuing handler's stack frame.
    pub fn tick(self: *NetherClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        for (0..self.opts.pool_size) |i| {
            const idx: u32 = @intCast(i);
            const slot = &self.slots[i];
            switch (slot.state) {
                .closed => self.connectSlot(io_rt, idx, now_ms),
                .failed => if (now_ms >= slot.retry_at_ms) self.connectSlot(io_rt, idx, now_ms),
                .busy => if (slot.park != NO_PARK and self.parked[slot.park].active and
                    now_ms >= self.parked[slot.park].deadline_ms)
                {
                    self.parked[slot.park].pending_error = error.Timeout;
                    const pk = slot.park;
                    slot.park = NO_PARK;
                    self.deliverPending(pk);
                    self.failSlot(io_rt, idx, now_ms, "exec timeout");
                },
                else => {},
            }
        }
        // Deliver any staged ConnectionLost from failSlot.
        for (&self.parked, 0..) |*e, pi| {
            if (e.active and e.pending_error != null) {
                const err = e.pending_error.?;
                e.pending_error = null;
                self.deliverOutcome(@intCast(pi), err);
            }
        }
    }

    /// Connect to the control socket. Spike: a single shared socket_path.
    /// Phase 1 generates a per-slot nether.conf and spawns nether.
    fn connectSlot(self: *NetherClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        const fd = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0) catch {
            return scheduleRetry(slot, now_ms);
        };
        var addr = std.posix.sockaddr.un{ .family = std.posix.AF.UNIX, .path = undefined };
        if (self.opts.socket_path.len >= addr.path.len) {
            clock.closeFd(fd);
            return scheduleRetry(slot, now_ms);
        }
        @memcpy(addr.path[0..self.opts.socket_path.len], self.opts.socket_path);
        addr.path[self.opts.socket_path.len] = 0;
        std.posix.connect(fd, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.un)) catch {
            clock.closeFd(fd);
            return scheduleRetry(slot, now_ms);
        };
        io_rt.registerExternalFd(idx, fd) catch {
            clock.closeFd(fd);
            return scheduleRetry(slot, now_ms);
        };
        slot.fd = fd;
        slot.state = .ready;
        slot.backoff_ms = 0;
    }

    /// Write the slot's pending send buffer. Returns false on a hard failure
    /// (failSlot already ran).
    fn flush(self: *NetherClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) bool {
        const slot = &self.slots[idx];
        while (slot.send_off < slot.send_len) {
            const raw = std.c.write(slot.fd, slot.send_buf[slot.send_off..].ptr, slot.send_len - slot.send_off);
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => {
                        io_rt.armExternalWritable(idx, slot.fd) catch {
                            self.failSlot(io_rt, idx, now_ms, "arm writable failed");
                            return false;
                        };
                        return true; // will resume on .write
                    },
                    .INTR => continue,
                    else => {
                        self.failSlot(io_rt, idx, now_ms, "socket write failed");
                        return false;
                    },
                }
            }
            slot.send_off += @intCast(raw);
        }
        return true;
    }

    fn failSlot(self: *NetherClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64, reason: []const u8) void {
        const slot = &self.slots[idx];
        if (slot.state == .busy and slot.park != NO_PARK and
            self.parked[slot.park].active and self.parked[slot.park].pending_error == null)
        {
            // Staged, delivered at tick — never synchronously here.
            self.parked[slot.park].pending_error = error.ConnectionLost;
        }
        slot.park = NO_PARK;
        if (slot.fd >= 0) {
            io_rt.unregisterExternalFd(slot.fd) catch {};
            clock.closeFd(slot.fd);
            slot.fd = -1;
        }
        scheduleRetry(slot, now_ms);
        std.log.warn("sandbox: slot {d}: {s}; reconnecting in {d} ms", .{ idx, reason, slot.backoff_ms });
    }
};

fn scheduleRetry(slot: *Slot, now_ms: u64) void {
    slot.backoff_ms = if (slot.backoff_ms == 0) BACKOFF_INITIAL_MS else @min(slot.backoff_ms * 2, BACKOFF_MAX_MS);
    slot.retry_at_ms = now_ms + slot.backoff_ms;
    slot.state = .failed;
}

// ── tests (DB-free: drive recv_buf + a stub resume hook) ─────────────

const testing = std.testing;

fn testClient() NetherClient {
    return .{
        .opts = .{ .socket_path = "/tmp/test.sock", .pool_size = 2 },
        .conn_parks = undefined, // set per test
        .allocator = testing.allocator,
    };
}

test "scanSlot delivers a complete reply to the continuation" {
    const Hook = struct {
        var ran = false;
        var output_buf: [64]u8 = undefined;
        var output_len: usize = 0;
        var exit_code: i32 = -999;
        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            ran = true;
            if (outcome.result) |r| {
                @memcpy(output_buf[0..r.output.len], r.output);
                output_len = r.output.len;
                exit_code = r.exit_code;
            } else |_| {}
        }
    };
    Hook.ran = false;

    var parks = [_]u16{NO_PARK} ** 4;
    var client = testClient();
    client.conn_parks = parks[0..];
    var dummy: u8 = 0;
    client.installResume(@ptrCast(&dummy), Hook.onResume);

    // Simulate a busy slot 0 with park 0 and a framed reply in recv_buf.
    client.slots[0].state = .busy;
    client.slots[0].park = 0;
    client.parked[0] = .{ .active = true, .conn_index = 1, .conn_id = 42, .continuation = undefined };
    client.conn_parks[1] = 0;
    const reply = "Linux 6.12 aarch64\x1e0\n";
    @memcpy(client.slots[0].recv_buf[0..reply.len], reply);
    client.slots[0].recv_len = reply.len;

    try testing.expect(client.scanSlot(0));
    try testing.expect(Hook.ran);
    try testing.expectEqualStrings("Linux 6.12 aarch64", Hook.output_buf[0..Hook.output_len]);
    try testing.expectEqual(@as(i32, 0), Hook.exit_code);
    try testing.expectEqual(SlotState.ready, client.slots[0].state);
    try testing.expectEqual(NO_PARK, client.conn_parks[1]);
}

test "scanSlot waits for more bytes on a partial reply" {
    var parks = [_]u16{NO_PARK} ** 4;
    var client = testClient();
    client.conn_parks = parks[0..];
    client.slots[0].state = .busy;
    client.slots[0].park = 0;
    client.parked[0] = .{ .active = true, .conn_index = 0, .conn_id = 1, .continuation = undefined };
    const partial = "output but no trailer yet";
    @memcpy(client.slots[0].recv_buf[0..partial.len], partial);
    client.slots[0].recv_len = partial.len;
    try testing.expect(!client.scanSlot(0)); // not delivered
    try testing.expectEqual(SlotState.busy, client.slots[0].state);
}

test "cancelForConn detaches a parked op (generation-checked)" {
    var parks = [_]u16{NO_PARK} ** 4;
    var client = testClient();
    client.conn_parks = parks[0..];
    client.slots[0].state = .busy;
    client.slots[0].park = 0;
    client.parked[0] = .{ .active = true, .conn_index = 2, .conn_id = 9, .continuation = undefined };
    client.conn_parks[2] = 0;

    client.cancelForConn(2, 8); // wrong generation: no-op
    try testing.expect(client.parked[0].active);
    client.cancelForConn(2, 9); // right generation: detach
    try testing.expect(!client.parked[0].active);
    try testing.expectEqual(NO_PARK, client.conn_parks[2]);
    try testing.expectEqual(NO_PARK, client.slots[0].park);
}
