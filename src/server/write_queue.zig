//! # Write queue + buffer-op helpers
//!
//! Small, mostly-static helpers that live together because they
//! all touch the connection's write queue bookkeeping or the
//! buffer pool ops interface:
//!
//!   - `submitConnAsyncWritev` / `advanceAsyncWriteQueue` —
//!     async writev submission and CQE advance for the native
//!     io_uring backend. `submitConnAsyncWritev` is currently
//!     dead code (no callers) but is kept because its partner
//!     `advanceAsyncWriteQueue` is still invoked from the
//!     dispatch loop's write CQE arm.
//!   - `acquireBufferOpaque` / `releaseBufferOpaque` — the type-
//!     erased trampolines that the middleware buffer_ops interface
//!     plugs into. Every cold-path request dispatcher (h1 cold
//!     path, h2 cold path, h3 cold path, proxy path) wires these
//!     into the per-request middleware.Context.
//!   - `drainWriteQueue` — a test-only helper that concatenates
//!     every enqueued buffer into a flat slice, used by the
//!     response-correctness tests in `server.zig`.
//!
//! These are the "Extract 8" polish from the server.zig
//! decomposition handoff — they could have moved any time after
//! Extract 1 since they're self-contained.

const std = @import("std");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const runtime = @import("../runtime/io.zig");
const connection = @import("../runtime/connection.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");

/// Build an iovec batch from the connection's write queue and
/// submit it as an async `IORING_OP_WRITEV` SQE on the native
/// io_uring backend. Returns `true` if the SQE was accepted (the
/// caller should `return` and wait for the CQE) or `false` if
/// the submission failed and the caller should fall back to a
/// sync writev.
///
/// On success the iovec array is parked on `conn.async_send_iov`
/// so its address stays stable until the kernel has copied the
/// bytes out; `conn.send_in_flight` is set to lock out further
/// submissions until the `.write` CQE fires.
pub fn submitConnAsyncWritev(server: *Server, conn: *connection.Connection, fd: std.posix.fd_t) bool {
    var iov_count: u16 = 0;
    var total_bytes: usize = 0;
    var scan_head = conn.write_head;
    var scan_remaining = conn.write_count;
    const cap = connection.async_send_iov_capacity;
    while (scan_remaining > 0 and iov_count < cap) : (iov_count += 1) {
        const e = &conn.write_queue[scan_head];
        const s = e.handle.bytes[e.offset..e.len];
        conn.async_send_iov[iov_count] = .{ .base = s.ptr, .len = s.len };
        total_bytes += s.len;
        scan_head = if (scan_head + 1 >= conn.write_queue.len) 0 else scan_head + 1;
        scan_remaining -= 1;
    }
    if (iov_count == 0) return false;
    const iov_slice = conn.async_send_iov[0..iov_count];
    server.io.submitAsyncWritev(conn.index, fd, iov_slice) catch return false;
    conn.send_in_flight = true;
    conn.async_send_iov_count = iov_count;
    conn.async_send_total_bytes = total_bytes;
    return true;
}

/// Advance the connection's write queue after an async writev
/// CQE reports `bytes_written`. Pops any fully-sent entries,
/// releases their buffers, and updates `entry.offset` on a
/// partially-sent entry. Called from the event dispatcher when a
/// `.write` event arrives for a connection with `send_in_flight`.
pub fn advanceAsyncWriteQueue(server: *Server, conn: *connection.Connection, bytes_written: usize) void {
    // Imported lazily to avoid a dispatch → write_queue → http1 →
    // write_queue cycle at file-load time.
    const http1_mod = @import("http1.zig");
    var remaining = bytes_written;
    while (remaining > 0) {
        const entry = conn.peekWrite() orelse break;
        const left_in_entry = entry.len - entry.offset;
        if (remaining >= left_in_entry) {
            remaining -= left_in_entry;
            server.io.onWriteCompleted(conn, left_in_entry);
            server.io.releaseBuffer(entry.handle);
            conn.popWrite();
            if (conn.hasPendingBody()) {
                http1_mod.streamBodyChunks(server, conn, conn.pending_body);
            }
        } else {
            entry.offset += remaining;
            server.io.onWriteCompleted(conn, remaining);
            remaining = 0;
        }
    }
    conn.send_in_flight = false;
    conn.async_send_iov_count = 0;
    conn.async_send_total_bytes = 0;
    conn.markActive(server.io.nowMs());
}

/// Middleware `buffer_ops.acquire` trampoline. `ctx` is an erased
/// `*runtime.IoRuntime`; the call returns a fresh buffer handle
/// from the Server's pool or null if exhausted.
pub fn acquireBufferOpaque(ctx: *anyopaque) ?buffer_pool.BufferHandle {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    return io.acquireBuffer();
}

/// Middleware `buffer_ops.release` trampoline — the counterpart
/// to `acquireBufferOpaque`.
pub fn releaseBufferOpaque(ctx: *anyopaque, handle: buffer_pool.BufferHandle) void {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    io.releaseBuffer(handle);
}

/// Test-only helper: drain every enqueued write buffer into a
/// single contiguous slice. Used by the response-bytes correctness
/// tests in `server.zig` to verify the on-wire output of
/// `queueResponse` and friends without round-tripping through an
/// actual socket.
pub fn drainWriteQueue(io: *runtime.IoRuntime, conn: *connection.Connection, allocator: std.mem.Allocator) ![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        try list.appendSlice(allocator, entry.handle.bytes[entry.offset..entry.len]);
        io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    return list.toOwnedSlice(allocator);
}
