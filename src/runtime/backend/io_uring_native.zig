const std = @import("std");
const builtin = @import("builtin");

const is_linux = builtin.os.tag == .linux;
const linux = if (is_linux) std.os.linux else undefined;
const IoUring = if (is_linux) linux.IoUring else void;
const BufferGroup = if (is_linux) linux.IoUring.BufferGroup else void;

/// Native io_uring backend — completion model with multishot accept,
/// multishot recv over a provided buffer group, and SINGLE_ISSUER +
/// DEFER_TASKRUN for lockless single-worker-per-ring operation.
///
/// Unlike `io_uring_poll`, this backend delivers read data inline with
/// the event: the kernel fills a buffer from the provided ring, and
/// the CQE carries a buffer ID the caller translates to a slice. The
/// caller MUST release the buffer back to the ring once the data has
/// been consumed (or copied out).
///
/// Writes are submitted as `send` SQEs and confirmed via later `.write`
/// completion events. For simplicity on the initial implementation we
/// fall back to a direct syscall when the ring has no SQ space.

// ─── io_uring setup flags (kernel 6.0+ / 6.1+) ──────────────────────
// SINGLE_ISSUER: tells the kernel that only one thread submits SQEs to
// this ring (each worker owns its own ring). Enables a lockless fast
// path in the kernel. Available since Linux 6.0.
// DEFER_TASKRUN: deferred task run. Instead of interrupting task work
// immediately on every I/O completion, defer CQE delivery to the next
// io_uring_enter (with IORING_ENTER_GETEVENTS). Batches completions
// and avoids IPI storms. Available since Linux 6.1.
// Both flags are critical for multi-worker scaling — without them we
// suffer ~1ms extra latency from lock contention and interrupt storms.
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;

// ─── Buffer group sizing ─────────────────────────────────────────────
// Each ring owns a buffer group of `RECV_BUF_COUNT` buffers each of
// `RECV_BUF_SIZE` bytes, totaling `RECV_SLAB_BYTES` per ring. The
// kernel picks a free buffer when data arrives and points our CQE at
// it. We return the buffer to the ring once the data is consumed.
//
// Sizing rationale: each buffer must be large enough for a typical
// HTTP request (headers + small body). 16KB fits all but the most
// extreme header bloat. With 2048 buffers per ring we can absorb
// bursts of 2048 concurrent packets before any connection stalls.
pub const RECV_BUF_SIZE: u32 = 16 * 1024;
pub const RECV_BUF_COUNT: u16 = 2048;
pub const RECV_SLAB_BYTES: usize = @as(usize, RECV_BUF_SIZE) * @as(usize, RECV_BUF_COUNT);

const RECV_BUF_GROUP_ID: u16 = 0;

// ─── User-data encoding ──────────────────────────────────────────────
// Every SQE carries a u64 `user_data` the kernel echoes back in its
// CQE. We encode (op, generation, fd/conn_id) into this field so that
// completion dispatch can identify what finished and whether the
// target is still alive (generation counter detects stale CQEs from
// closed-then-reused fds).
pub const Op = enum(u4) {
    accept = 0,
    recv = 1,
    send = 2,
    close = 3,
};

pub fn packUserData(op: Op, gen: u28, conn_id: u32) u64 {
    return (@as(u64, @intFromEnum(op)) << 60) |
        (@as(u64, gen) << 32) |
        @as(u64, conn_id);
}

pub fn unpackOp(ud: u64) Op {
    return @enumFromInt(@as(u4, @truncate(ud >> 60)));
}

pub fn unpackGen(ud: u64) u28 {
    return @truncate(ud >> 32);
}

pub fn unpackConnId(ud: u64) u32 {
    return @truncate(ud);
}

// ─── Event type ──────────────────────────────────────────────────────
// We deliberately mirror the event shape used by the poll backend so
// the io.zig translation layer can normalize across backends. The
// `data` and `kernel_buffer_id` fields are native-specific: the data
// was filled by the kernel and lives in our BufferGroup slab until we
// release that buffer.
pub const IoUringNativeEvent = struct {
    kind: Kind,
    conn_id: u32,
    // For .read events: the data already delivered by the kernel.
    // Points into the BufferGroup slab — valid until the caller
    // releases the buffer.
    data: ?[]const u8 = null,
    // For .read events: the buffer ID to return to the kernel once
    // the caller has consumed the data. Caller must eventually call
    // IoUringNativeBackend.releaseRecvBuffer(buffer_id).
    kernel_buffer_id: ?u16 = null,
    // For .accept events: the new client fd.
    accepted_fd: ?i32 = null,

    pub const Kind = enum { accept, read, write, err };
};

pub const IoUringNativeBackend = struct {
    ring: IoUring,
    buf_group: BufferGroup,
    allocator: std.mem.Allocator,
    /// Output events produced by poll()
    events: []IoUringNativeEvent,
    /// Registered listener fd (for multishot accept re-arming)
    listener_fd: ?i32 = null,
    /// Per-connection generation counter — incremented when a conn_id
    /// is reused, so stale CQEs from the previous lifetime get ignored.
    generations: []u28,

    pub fn init(
        allocator: std.mem.Allocator,
        max_events: usize,
    ) !IoUringNativeBackend {
        if (!is_linux) return error.Unsupported;

        // Try the fast flags first; fall back to plain init if the
        // kernel is too old. The fast path is critical for multi-worker
        // performance — it eliminates ring-level lock contention and
        // interrupt storms that otherwise cost ~1ms per request.
        const entries: u16 = @intCast(std.math.ceilPowerOfTwoAssert(u32, @intCast(@min(max_events * 2, 4096))));
        var ring = IoUring.init(
            entries,
            IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
        ) catch |err| blk: {
            std.log.warn("io_uring_native: SINGLE_ISSUER|DEFER_TASKRUN failed ({}); retrying without", .{err});
            break :blk try IoUring.init(entries, 0);
        };
        errdefer ring.deinit();

        // Set up the provided buffer group for recv_multishot.
        var buf_group = try BufferGroup.init(
            &ring,
            allocator,
            RECV_BUF_GROUP_ID,
            RECV_BUF_SIZE,
            RECV_BUF_COUNT,
        );
        errdefer buf_group.deinit(allocator);

        const events = try allocator.alloc(IoUringNativeEvent, max_events);
        errdefer allocator.free(events);

        const generations = try allocator.alloc(u28, max_events);
        @memset(generations, 0);
        errdefer allocator.free(generations);

        return .{
            .ring = ring,
            .buf_group = buf_group,
            .allocator = allocator,
            .events = events,
            .generations = generations,
        };
    }

    pub fn deinit(self: *IoUringNativeBackend, allocator: std.mem.Allocator) void {
        self.buf_group.deinit(allocator);
        self.ring.deinit();
        allocator.free(self.events);
        allocator.free(self.generations);
    }

    /// Register the TCP listener fd and arm multishot accept. The
    /// accept SQE stays alive for the lifetime of the listener — each
    /// incoming connection produces a CQE without any re-submission.
    pub fn registerListener(self: *IoUringNativeBackend, fd: i32) !void {
        if (!is_linux) return error.Unsupported;
        self.listener_fd = fd;
        try self.armMultishotAccept(fd);
    }

    fn armMultishotAccept(self: *IoUringNativeBackend, fd: i32) !void {
        const sqe = try self.ring.get_sqe();
        sqe.prep_accept(fd, null, null, 0);
        // IORING_ACCEPT_MULTISHOT: rearm automatically after each accept
        sqe.ioprio |= 1; // IORING_ACCEPT_MULTISHOT (flag value = 1)
        sqe.user_data = packUserData(.accept, 0, 0);
    }

    /// Arm a multishot recv on a freshly-accepted connection. Data
    /// arrives via the buffer group and is delivered inline with each
    /// completion event. The multishot SQE stays armed until the
    /// connection closes.
    pub fn registerConnection(self: *IoUringNativeBackend, conn_id: u32, fd: i32) !void {
        if (!is_linux) return error.Unsupported;
        if (conn_id >= self.generations.len) return error.ConnIdOutOfRange;
        const gen = self.generations[conn_id];
        _ = try self.buf_group.recv_multishot(
            packUserData(.recv, gen, conn_id),
            fd,
            0,
        );
    }

    /// Submit a send operation for a response. The completion arrives
    /// as a .write event once the kernel has transmitted the data.
    /// `data` must remain valid until the CQE is reaped.
    pub fn submitSend(self: *IoUringNativeBackend, conn_id: u32, fd: i32, data: []const u8) !void {
        if (!is_linux) return error.Unsupported;
        if (conn_id >= self.generations.len) return error.ConnIdOutOfRange;
        const gen = self.generations[conn_id];
        const sqe = try self.ring.get_sqe();
        sqe.prep_send(fd, data, 0);
        sqe.user_data = packUserData(.send, gen, conn_id);
    }

    /// Increment the generation counter for a connection slot being
    /// reused. Stale CQEs from the previous incarnation will be
    /// dropped in `poll()`.
    pub fn bumpGeneration(self: *IoUringNativeBackend, conn_id: u32) void {
        if (conn_id >= self.generations.len) return;
        self.generations[conn_id] +%= 1;
    }

    /// Release a recv buffer back to the kernel's buffer ring.
    /// Called by the server after it has finished consuming the data
    /// (copied out or fully processed) for a given .read event.
    pub fn releaseRecvBuffer(self: *IoUringNativeBackend, buffer_id: u16) void {
        // The BufferGroup.put API wants a CQE (it reads the buffer_id
        // and flags from it). We reconstruct a minimal CQE shape.
        const fake_cqe = linux.io_uring_cqe{
            .user_data = 0,
            .res = 0,
            .flags = (@as(u32, buffer_id) << linux.IORING_CQE_BUFFER_SHIFT) | linux.IORING_CQE_F_BUFFER,
        };
        self.buf_group.put(fake_cqe) catch {};
    }

    /// Blocks until at least one CQE is available (or returns
    /// immediately when `timeout_ms == 0`). Reaps all available CQEs
    /// and translates them into IoUringNativeEvent entries.
    pub fn poll(self: *IoUringNativeBackend, timeout_ms: u32) ![]IoUringNativeEvent {
        if (!is_linux) return error.Unsupported;

        // Submit any pending SQEs and (if waiting) block on the first
        // completion. With DEFER_TASKRUN, GETEVENTS must be set on
        // every enter call for deferred completions to run.
        const wait_nr: u32 = if (timeout_ms > 0) 1 else 0;
        _ = self.ring.submit_and_wait(wait_nr) catch |err| switch (err) {
            error.SignalInterrupt => return self.events[0..0],
            else => return err,
        };

        var count: usize = 0;
        while (count < self.events.len) {
            const cqe = self.ring.copy_cqe() catch |err| switch (err) {
                error.SignalInterrupt => break,
                else => return err,
            };
            if (cqe.user_data == 0 and cqe.res == 0 and cqe.flags == 0) break;

            const ud = cqe.user_data;
            const op = unpackOp(ud);
            const gen = unpackGen(ud);
            const conn_id = unpackConnId(ud);

            // Drop stale CQEs from reused conn_id slots.
            if (op == .recv or op == .send) {
                if (conn_id >= self.generations.len or self.generations[conn_id] != gen) {
                    if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                        self.buf_group.put(cqe) catch {};
                    }
                    continue;
                }
            }

            switch (op) {
                .accept => {
                    if (cqe.res < 0) {
                        // accept failed; try to re-arm once
                        if (self.listener_fd) |fd| {
                            self.armMultishotAccept(fd) catch {};
                        }
                        continue;
                    }
                    self.events[count] = .{
                        .kind = .accept,
                        .conn_id = 0,
                        .accepted_fd = cqe.res,
                    };
                    count += 1;
                    // Multishot accept re-arms itself unless F_MORE is unset.
                    if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                        if (self.listener_fd) |fd| {
                            self.armMultishotAccept(fd) catch {};
                        }
                    }
                },
                .recv => {
                    if (cqe.res <= 0) {
                        self.events[count] = .{
                            .kind = .err,
                            .conn_id = conn_id,
                        };
                        count += 1;
                        continue;
                    }
                    const data = self.buf_group.get(cqe) catch {
                        // Buffer lookup failed — return error event and
                        // don't try to reuse the (possibly-invalid) id.
                        self.events[count] = .{
                            .kind = .err,
                            .conn_id = conn_id,
                        };
                        count += 1;
                        continue;
                    };
                    const buffer_id = cqe.buffer_id() catch 0;
                    self.events[count] = .{
                        .kind = .read,
                        .conn_id = conn_id,
                        .data = data,
                        .kernel_buffer_id = buffer_id,
                    };
                    count += 1;
                    // Multishot recv re-arms itself unless F_MORE is unset.
                    // If it dropped out (ENOBUFS, EINVAL, etc.), the server
                    // will observe the next .err event; we rely on the
                    // connection-close path to re-arm via registerConnection.
                },
                .send => {
                    self.events[count] = .{
                        .kind = .write,
                        .conn_id = conn_id,
                    };
                    count += 1;
                },
                .close => {
                    // no event — close completions are informational
                },
            }
        }

        return self.events[0..count];
    }
};

/// Runtime probe: attempt to set up an io_uring with the fast flags.
/// Returns true if the kernel supports SINGLE_ISSUER + DEFER_TASKRUN.
/// False on older kernels or when io_uring is disabled entirely.
pub fn probe() bool {
    if (!is_linux) return false;
    var ring = IoUring.init(
        2,
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
    ) catch return false;
    ring.deinit();
    return true;
}
