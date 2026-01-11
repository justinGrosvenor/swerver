const std = @import("std");
const swerver = @import("swerver");
const config = swerver.config;
const buffer_pool = swerver.runtime.buffer_pool;
const connection = swerver.runtime.connection;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("swerver microbench\n", .{});

    try benchBufferPool(allocator);
    try benchConnectionPool(allocator);
}

fn benchBufferPool(allocator: std.mem.Allocator) !void {
    const iterations: usize = 1_000_000;
    const cfg = config.BufferPoolConfig{ .buffer_size = 1024, .buffer_count = 1024 };
    var pool = try buffer_pool.BufferPool.init(allocator, cfg);
    defer pool.deinit();

    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const handle = pool.acquire() orelse continue;
        pool.release(handle);
    }
    const elapsed_ns = timer.read();
    const per_op = elapsed_ns / iterations;
    std.debug.print("buffer_pool acquire/release: {d} ns/op\n", .{per_op});
}

fn benchConnectionPool(allocator: std.mem.Allocator) !void {
    const iterations: usize = 1_000_000;
    var pool = try connection.ConnectionPool.init(allocator, 1024);
    defer pool.deinit();

    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const conn = pool.acquire(0) orelse continue;
        pool.release(conn);
    }
    const elapsed_ns = timer.read();
    const per_op = elapsed_ns / iterations;
    std.debug.print("connection_pool acquire/release: {d} ns/op\n", .{per_op});
}
