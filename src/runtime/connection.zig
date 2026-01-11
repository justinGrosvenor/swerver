const std = @import("std");
const config = @import("../config.zig");
const buffer_pool = @import("buffer_pool.zig");
const request = @import("../protocol/request.zig");
const http2 = @import("../protocol/http2.zig");

pub const State = enum {
    accept,
    handshake,
    active,
    draining,
    closed,
    err,
};

pub const TimeoutPhase = enum {
    idle,
    header,
    body,
    write,
};

pub const Protocol = enum {
    http1,
    http2,
};

pub const TransitionError = error{InvalidTransition};

pub const Connection = struct {
    index: u32,
    id: u64,
    state: State,
    fd: ?std.posix.fd_t,
    state_enter_ms: u64,
    last_active_ms: u64,
    read_offset: usize,
    read_buffered_bytes: usize,
    write_buffered_bytes: usize,
    write_queue: [write_queue_capacity]WriteEntry,
    write_head: u8,
    write_tail: u8,
    write_count: u8,
    close_after_write: bool,
    sent_continue: bool,
    protocol: Protocol,
    http2_stack: ?*http2.Stack,
    headers: [HeaderCapacity]request.Header,
    header_count: usize,
    read_paused: bool,
    write_paused: bool,
    timeout_phase: TimeoutPhase,
    read_buffer: ?buffer_pool.BufferHandle,
    // Position in active list for O(1) removal
    active_list_pos: u32,

    pub fn init(index: u32) Connection {
        return .{
            .index = index,
            .id = 0,
            .state = .closed,
            .fd = null,
            .state_enter_ms = 0,
            .last_active_ms = 0,
            .read_offset = 0,
            .read_buffered_bytes = 0,
            .write_buffered_bytes = 0,
            .write_queue = undefined,
            .write_head = 0,
            .write_tail = 0,
            .write_count = 0,
            .close_after_write = false,
            .sent_continue = false,
            .protocol = .http1,
            .http2_stack = null,
            .headers = undefined,
            .header_count = 0,
            .read_paused = false,
            .write_paused = false,
            .timeout_phase = .idle,
            .read_buffer = null,
            .active_list_pos = 0,
        };
    }

    pub fn reset(self: *Connection, id: u64, now_ms: u64) void {
        self.id = id;
        self.state = .accept;
        self.fd = null;
        self.state_enter_ms = now_ms;
        self.last_active_ms = now_ms;
        self.read_offset = 0;
        self.read_buffered_bytes = 0;
        self.write_buffered_bytes = 0;
        self.write_head = 0;
        self.write_tail = 0;
        self.write_count = 0;
        self.close_after_write = false;
        self.sent_continue = false;
        self.protocol = .http1;
        self.http2_stack = null;
        self.header_count = 0;
        self.read_paused = false;
        self.write_paused = false;
        self.timeout_phase = .idle;
        self.read_buffer = null;
        // active_list_pos is set by ConnectionPool.acquire
    }

    pub fn transition(self: *Connection, next: State, now_ms: u64) TransitionError!void {
        if (!isValidTransition(self.state, next)) return error.InvalidTransition;
        self.state = next;
        self.state_enter_ms = now_ms;
    }

    pub fn markActive(self: *Connection, now_ms: u64) void {
        self.last_active_ms = now_ms;
    }

    pub fn setTimeoutPhase(self: *Connection, phase: TimeoutPhase) void {
        self.timeout_phase = phase;
    }

    pub fn isTimedOut(self: *Connection, now_ms: u64, phase: TimeoutPhase, timeouts: config.Timeouts) bool {
        if (now_ms <= self.last_active_ms) return false;
        const elapsed = now_ms - self.last_active_ms;
        return switch (phase) {
            .idle => elapsed > timeouts.idle_ms,
            .header => elapsed > timeouts.header_ms,
            .body => elapsed > timeouts.body_ms,
            .write => elapsed > timeouts.write_ms,
        };
    }

    pub fn canRead(self: *Connection, backpressure: config.Backpressure) bool {
        self.updateReadBackpressure(backpressure);
        return !self.read_paused;
    }

    pub fn canWrite(self: *Connection, backpressure: config.Backpressure) bool {
        self.updateWriteBackpressure(backpressure);
        return !self.write_paused;
    }

    pub fn onReadBuffered(self: *Connection, bytes: usize, backpressure: config.Backpressure) void {
        self.read_buffered_bytes += bytes;
        self.updateReadBackpressure(backpressure);
    }

    pub fn onReadConsumed(self: *Connection, bytes: usize, backpressure: config.Backpressure) void {
        if (bytes >= self.read_buffered_bytes) {
            self.read_buffered_bytes = 0;
            self.read_offset = 0;
        } else {
            self.read_buffered_bytes -= bytes;
            self.read_offset += bytes;
        }
        self.updateReadBackpressure(backpressure);
    }

    pub fn onWriteBuffered(self: *Connection, bytes: usize, backpressure: config.Backpressure) void {
        self.write_buffered_bytes += bytes;
        self.updateWriteBackpressure(backpressure);
    }

    pub fn onWriteCompleted(self: *Connection, bytes: usize, backpressure: config.Backpressure) void {
        if (bytes >= self.write_buffered_bytes) {
            self.write_buffered_bytes = 0;
        } else {
            self.write_buffered_bytes -= bytes;
        }
        self.updateWriteBackpressure(backpressure);
    }

    pub fn remainingTimeoutMs(self: *Connection, now_ms: u64, timeouts: config.Timeouts) u32 {
        const limit: u64 = switch (self.timeout_phase) {
            .idle => timeouts.idle_ms,
            .header => timeouts.header_ms,
            .body => timeouts.body_ms,
            .write => timeouts.write_ms,
        };
        if (now_ms <= self.last_active_ms) return @intCast(@min(limit, std.math.maxInt(u32)));
        const elapsed = now_ms - self.last_active_ms;
        if (elapsed >= limit) return 0;
        const remaining = limit - elapsed;
        // Defensive bounds check - remaining should fit in u32 since limit was u32
        return @intCast(@min(remaining, std.math.maxInt(u32)));
    }

    pub fn enqueueWrite(self: *Connection, handle: buffer_pool.BufferHandle, len: usize) bool {
        if (self.write_count == write_queue_capacity) return false;
        self.write_queue[self.write_tail] = .{
            .handle = handle,
            .len = len,
            .offset = 0,
        };
        self.write_tail = nextIndex(self.write_tail);
        self.write_count += 1;
        return true;
    }

    pub fn canEnqueueWrite(self: *Connection) bool {
        return self.write_count < write_queue_capacity;
    }

    pub fn peekWrite(self: *Connection) ?*WriteEntry {
        if (self.write_count == 0) return null;
        return &self.write_queue[self.write_head];
    }

    pub fn popWrite(self: *Connection) void {
        if (self.write_count == 0) return;
        self.write_head = nextIndex(self.write_head);
        self.write_count -= 1;
    }

    fn updateReadBackpressure(self: *Connection, backpressure: config.Backpressure) void {
        if (self.read_paused) {
            if (self.read_buffered_bytes <= backpressure.read_low_water) self.read_paused = false;
        } else {
            if (self.read_buffered_bytes >= backpressure.read_high_water) self.read_paused = true;
        }
    }

    fn updateWriteBackpressure(self: *Connection, backpressure: config.Backpressure) void {
        if (self.write_paused) {
            if (self.write_buffered_bytes <= backpressure.write_low_water) self.write_paused = false;
        } else {
            if (self.write_buffered_bytes >= backpressure.write_high_water) self.write_paused = true;
        }
    }
};

pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    entries: []Connection,
    free_stack: []u32,
    free_len: usize,
    next_id: u64,
    // Active connection tracking for O(active) iteration
    active_list: []u32,
    active_count: usize,

    pub fn init(allocator: std.mem.Allocator, max_connections: usize) !ConnectionPool {
        const entries = try allocator.alloc(Connection, max_connections);
        const free_stack = try allocator.alloc(u32, max_connections);
        const active_list = try allocator.alloc(u32, max_connections);
        for (0..max_connections) |i| {
            const index: u32 = @intCast(i);
            entries[i] = Connection.init(index);
            free_stack[i] = @intCast(max_connections - 1 - i);
        }

        return .{
            .allocator = allocator,
            .entries = entries,
            .free_stack = free_stack,
            .free_len = max_connections,
            .next_id = 1,
            .active_list = active_list,
            .active_count = 0,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.free_stack);
        self.allocator.free(self.active_list);
    }

    pub fn acquire(self: *ConnectionPool, now_ms: u64) ?*Connection {
        if (self.free_len == 0) return null;
        self.free_len -= 1;
        const index = self.free_stack[self.free_len];
        const conn = &self.entries[index];
        conn.reset(self.next_id, now_ms);
        self.next_id += 1;
        // Add to active list
        conn.active_list_pos = @intCast(self.active_count);
        self.active_list[self.active_count] = conn.index;
        self.active_count += 1;
        return conn;
    }

    pub fn release(self: *ConnectionPool, conn: *Connection) void {
        // Remove from active list using swap-remove for O(1)
        if (self.active_count > 0) {
            const pos = conn.active_list_pos;
            const last_pos = self.active_count - 1;
            if (pos < last_pos) {
                // Swap with last element
                const last_index = self.active_list[last_pos];
                self.active_list[pos] = last_index;
                self.entries[last_index].active_list_pos = pos;
            }
            self.active_count -= 1;
        }
        conn.state = .closed;
        conn.fd = null;
        conn.read_offset = 0;
        conn.close_after_write = false;
        conn.sent_continue = false;
        conn.protocol = .http1;
        conn.http2_stack = null;
        conn.read_buffer = null;
        conn.write_head = 0;
        conn.write_tail = 0;
        conn.write_count = 0;
        conn.header_count = 0;
        std.debug.assert(conn.index < self.entries.len);
        std.debug.assert(self.free_len < self.free_stack.len);
        self.free_stack[self.free_len] = conn.index;
        self.free_len += 1;
    }

    /// Returns slice of active connection indices for O(active) iteration
    pub fn activeConnections(self: *ConnectionPool) []const u32 {
        return self.active_list[0..self.active_count];
    }
};

fn isValidTransition(from: State, to: State) bool {
    return switch (from) {
        .accept => to == .handshake or to == .active or to == .err or to == .closed,
        .handshake => to == .active or to == .err or to == .closed,
        .active => to == .draining or to == .err or to == .closed,
        .draining => to == .closed or to == .err,
        .err => to == .closed,
        .closed => to == .accept,
    };
}

const write_queue_capacity: u8 = 8;
pub const HeaderCapacity: usize = 128;

const WriteEntry = struct {
    handle: buffer_pool.BufferHandle,
    len: usize,
    offset: usize,
};

fn nextIndex(index: u8) u8 {
    return (index + 1) % write_queue_capacity;
}
