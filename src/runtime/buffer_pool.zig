const std = @import("std");
const config = @import("../config.zig");

pub const BufferHandle = struct {
    index: u32,
    bytes: []u8,
};

pub const BufferPool = struct {
    allocator: std.mem.Allocator,
    buffer_size: usize,
    buffer_count: usize,
    storage: []u8,
    free_stack: []u32,
    free_len: usize,
    /// Bitmap tracking acquired (true) vs free (false) state for double-release detection
    acquired: []bool,

    pub fn init(allocator: std.mem.Allocator, cfg: config.BufferPoolConfig) !BufferPool {
        const total_bytes = cfg.buffer_size * cfg.buffer_count;
        const storage = try allocator.alloc(u8, total_bytes);
        const free_stack = try allocator.alloc(u32, cfg.buffer_count);
        const acquired = try allocator.alloc(bool, cfg.buffer_count);
        @memset(acquired, false);
        for (0..cfg.buffer_count) |i| {
            free_stack[i] = @intCast(cfg.buffer_count - 1 - i);
        }

        return .{
            .allocator = allocator,
            .buffer_size = cfg.buffer_size,
            .buffer_count = cfg.buffer_count,
            .storage = storage,
            .free_stack = free_stack,
            .free_len = cfg.buffer_count,
            .acquired = acquired,
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.free_stack);
        self.allocator.free(self.acquired);
    }

    pub fn acquire(self: *BufferPool) ?BufferHandle {
        if (self.free_len == 0) return null;
        self.free_len -= 1;
        const index = self.free_stack[self.free_len];
        self.acquired[index] = true;
        return .{ .index = index, .bytes = self.bufferSlice(index) };
    }

    pub fn release(self: *BufferPool, handle: BufferHandle) void {
        if (handle.index >= self.buffer_count) {
            std.log.err("BufferPool: release of invalid buffer index {}", .{handle.index});
            return;
        }
        if (!self.acquired[handle.index]) {
            std.log.err("BufferPool: double-release of buffer index {}", .{handle.index});
            return;
        }
        self.acquired[handle.index] = false;
        if (self.free_len >= self.free_stack.len) {
            std.log.err("BufferPool: free stack overflow on release of index {}", .{handle.index});
            return;
        }
        self.free_stack[self.free_len] = handle.index;
        self.free_len += 1;
    }

    fn bufferSlice(self: *BufferPool, index: u32) []u8 {
        const start = @as(usize, index) * self.buffer_size;
        return self.storage[start .. start + self.buffer_size];
    }
};

test "BufferPool.init allocates N buffers of the configured size" {
    const cfg = config.BufferPoolConfig{ .buffer_size = 256, .buffer_count = 8 };
    var pool = try BufferPool.init(std.testing.allocator, cfg);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 256), pool.buffer_size);
    try std.testing.expectEqual(@as(usize, 8), pool.buffer_count);
    try std.testing.expectEqual(@as(usize, 8), pool.free_len);

    const h = pool.acquire().?;
    try std.testing.expectEqual(@as(usize, 256), h.bytes.len);
    // Buffer is writable across its whole length.
    @memset(h.bytes, 0xAB);
    try std.testing.expectEqual(@as(u8, 0xAB), h.bytes[h.bytes.len - 1]);
    pool.release(h);
}

test "BufferPool.acquire exhausts after buffer_count handles then returns null" {
    const cfg = config.BufferPoolConfig{ .buffer_size = 64, .buffer_count = 3 };
    var pool = try BufferPool.init(std.testing.allocator, cfg);
    defer pool.deinit();

    var handles: [3]BufferHandle = undefined;
    for (0..3) |i| {
        handles[i] = pool.acquire().?;
    }
    // Pool is now empty.
    try std.testing.expectEqual(@as(usize, 0), pool.free_len);
    try std.testing.expect(pool.acquire() == null);

    // Clean up so deinit does not leak.
    for (handles) |h| pool.release(h);
}

test "BufferPool.release makes a buffer available for a subsequent acquire" {
    const cfg = config.BufferPoolConfig{ .buffer_size = 64, .buffer_count = 1 };
    var pool = try BufferPool.init(std.testing.allocator, cfg);
    defer pool.deinit();

    const first = pool.acquire().?;
    try std.testing.expect(pool.acquire() == null); // exhausted

    pool.release(first);
    const second = pool.acquire().?; // now succeeds again
    try std.testing.expectEqual(@as(u32, 0), second.index);
    pool.release(second);
}

test "BufferPool.acquire hands out distinct, non-aliasing buffers" {
    const cfg = config.BufferPoolConfig{ .buffer_size = 32, .buffer_count = 4 };
    var pool = try BufferPool.init(std.testing.allocator, cfg);
    defer pool.deinit();

    var handles: [4]BufferHandle = undefined;
    for (0..4) |i| handles[i] = pool.acquire().?;

    // Distinct indices.
    for (0..4) |i| {
        for (i + 1..4) |j| {
            try std.testing.expect(handles[i].index != handles[j].index);
        }
    }

    // Distinct, non-overlapping memory: stamp each buffer with its own byte
    // and confirm no write bled into another buffer.
    for (handles, 0..) |h, i| @memset(h.bytes, @intCast(i + 1));
    for (handles, 0..) |h, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i + 1)), h.bytes[0]);
        try std.testing.expectEqual(@as(u8, @intCast(i + 1)), h.bytes[h.bytes.len - 1]);
    }

    for (handles) |h| pool.release(h);
}

test "BufferPool reuses released buffers in LIFO order" {
    const cfg = config.BufferPoolConfig{ .buffer_size = 16, .buffer_count = 3 };
    var pool = try BufferPool.init(std.testing.allocator, cfg);
    defer pool.deinit();

    const a = pool.acquire().?;
    const b = pool.acquire().?;
    const c = pool.acquire().?;
    try std.testing.expectEqual(@as(usize, 0), pool.free_len);

    // Release in a known order, then re-acquire: the free stack is LIFO,
    // so the most recently released handle is handed back first.
    pool.release(b);
    pool.release(a);
    const next = pool.acquire().?;
    try std.testing.expectEqual(a.index, next.index);

    pool.release(c);
    pool.release(next);
    // After returning everything the pool is full again.
    try std.testing.expectEqual(@as(usize, 3), pool.free_len);
}
