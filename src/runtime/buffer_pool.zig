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
        std.debug.assert(handle.index < self.buffer_count);
        // Detect double-release: buffer must be in acquired state
        if (!self.acquired[handle.index]) {
            std.log.err("BufferPool: double-release of buffer index {}", .{handle.index});
            return;
        }
        self.acquired[handle.index] = false;
        std.debug.assert(self.free_len < self.free_stack.len);
        self.free_stack[self.free_len] = handle.index;
        self.free_len += 1;
    }

    fn bufferSlice(self: *BufferPool, index: u32) []u8 {
        const start = @as(usize, index) * self.buffer_size;
        return self.storage[start .. start + self.buffer_size];
    }
};
