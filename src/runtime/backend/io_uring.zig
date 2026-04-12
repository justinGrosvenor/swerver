const std = @import("std");
const builtin = @import("builtin");

const is_linux = builtin.os.tag == .linux;
const linux = if (is_linux) std.os.linux else undefined;

/// Phase 3a: Readiness-emulation io_uring backend.
///
/// Uses IORING_OP_POLL_ADD to emulate epoll-style readiness notifications.
/// This is a drop-in replacement for the epoll backend — same event model,
/// same dispatch in server.zig. The advantage is reduced syscall overhead:
/// io_uring batches SQE submissions and CQE reaping in single syscalls.
///
/// Phase 3b (future): Replace POLL_ADD with native IORING_OP_ACCEPT,
/// IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED for true async I/O.

// io_uring constants (from linux/io_uring.h)
const IORING_SETUP_SQPOLL = 1 << 1;
const IORING_SETUP_SINGLE_ISSUER = 1 << 12; // kernel 6.0+: lockless SQE submission
const IORING_SETUP_DEFER_TASKRUN = 1 << 13; // kernel 6.1+: batch CQE delivery
const IORING_OP_POLL_ADD: u8 = 6;
const IORING_OP_POLL_REMOVE: u8 = 7;
const IORING_OP_NOP: u8 = 0;

// Poll event masks matching EPOLL constants
const POLLIN: u32 = 0x001;
const POLLOUT: u32 = 0x004;
const POLLERR: u32 = 0x008;
const POLLHUP: u32 = 0x010;

/// Unified event type matching the epoll backend's output format.
pub const IoUringEvent = extern struct {
    events: u32,
    data: extern union { ptr: usize, fd: i32, u32_val: u32, u64: u64 } align(1),
};

/// io_uring CQE for reading completions
const IoUringCqe = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

/// io_uring SQE for submitting operations
const IoUringSqe = extern struct {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off_or_addr2: u64,
    addr_or_splice: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    addr3: u64,
    __pad: u64,
};

pub const IoUringBackend = struct {
    /// io_uring file descriptor
    ring_fd: i32,
    /// SQ ring mapped memory
    sq_ring: []u8,
    /// CQ ring mapped memory
    cq_ring: []u8,
    /// SQE array mapped memory (must be unmapped on deinit)
    sqe_ring: []u8,
    /// SQE array
    sqes: [*]IoUringSqe,
    /// CQE array
    cqes: [*]IoUringCqe,
    /// Ring parameters
    sq_entries: u32,
    cq_entries: u32,
    sq_mask: u32,
    cq_mask: u32,
    /// Pointers into mmaped ring for head/tail
    sq_head: *volatile u32,
    sq_tail: *volatile u32,
    sq_array: [*]u32,
    cq_head: *volatile u32,
    cq_tail: *volatile u32,
    /// Output events buffer
    events: []IoUringEvent,
    /// Track registered FDs for re-arming (POLL_ADD is one-shot)
    /// Layout: [0]=listener, [1]=UDP, [2..]=connections (indexed by conn_id + 2)
    registered_fds: []RegisteredFd,
    /// Pending SQEs queued for submission on the next poll.
    /// Re-arm SQEs from the previous cycle are submitted together
    /// with the wait call, saving one io_uring_enter syscall per cycle.
    pending_submits: u32 = 0,

    const RegisteredFd = struct {
        fd: i32 = -1,
        conn_id: u64 = 0,
        poll_mask: u32 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, max_events: usize) !IoUringBackend {
        if (!is_linux) return error.Unsupported;

        const events = try allocator.alloc(IoUringEvent, max_events);
        errdefer allocator.free(events);

        // +3: slot 0 = listener, slot 1 = UDP, slots 2..max_events+2 = connections
        // io.zig passes conn_id+1 as the conn_id, and we add +2 for the slot
        const registered_fds = try allocator.alloc(RegisteredFd, max_events + 3);
        errdefer allocator.free(registered_fds);
        @memset(registered_fds, RegisteredFd{});

        // Setup io_uring with desired queue depth.
        // SINGLE_ISSUER: lockless SQE submission (each worker has its own ring).
        // DEFER_TASKRUN: batch CQE delivery to io_uring_enter instead of
        // interrupting immediately. Critical for multi-worker scalability —
        // without these, 64 workers generate lock contention and interrupt
        // storms that add ~1ms latency per request.
        const entries: u32 = @intCast(@min(max_events * 2, 4096));
        var params: IoUringParams = std.mem.zeroes(IoUringParams);
        params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;

        var ring_fd = io_uring_setup(entries, &params);
        if (ring_fd < 0) {
            // Fallback: older kernels may not support these flags.
            // Retry without them for compatibility.
            params = std.mem.zeroes(IoUringParams);
            ring_fd = io_uring_setup(entries, &params);
        }
        if (ring_fd < 0) return error.IoUringSetupFailed;
        errdefer _ = linux.close(@intCast(ring_fd));

        // Map SQ ring
        const sq_ring_sz = params.sq_off.array + params.sq_entries * @sizeOf(u32);
        const sq_ring = mapRing(ring_fd, IORING_OFF_SQ_RING, sq_ring_sz) orelse return error.MmapFailed;
        errdefer unmapRing(sq_ring);

        // Map CQ ring
        const cq_ring_sz = params.cq_off.cqes + params.cq_entries * @sizeOf(IoUringCqe);
        const cq_ring = mapRing(ring_fd, IORING_OFF_CQ_RING, cq_ring_sz) orelse return error.MmapFailed;
        errdefer unmapRing(cq_ring);

        // Map SQEs
        const sqe_sz = params.sq_entries * @sizeOf(IoUringSqe);
        const sqe_ring = mapRing(ring_fd, IORING_OFF_SQES, sqe_sz) orelse return error.MmapFailed;
        errdefer unmapRing(sqe_ring);

        return .{
            .ring_fd = ring_fd,
            .sq_ring = sq_ring,
            .cq_ring = cq_ring,
            .sqe_ring = sqe_ring,
            .sqes = @ptrCast(@alignCast(sqe_ring.ptr)),
            .cqes = @ptrCast(@alignCast(cq_ring[params.cq_off.cqes..].ptr)),
            .sq_entries = params.sq_entries,
            .cq_entries = params.cq_entries,
            .sq_mask = params.sq_entries - 1,
            .cq_mask = params.cq_entries - 1,
            .sq_head = @ptrCast(@alignCast(&sq_ring[params.sq_off.head])),
            .sq_tail = @ptrCast(@alignCast(&sq_ring[params.sq_off.tail])),
            .sq_array = @ptrCast(@alignCast(sq_ring[params.sq_off.array..].ptr)),
            .cq_head = @ptrCast(@alignCast(&cq_ring[params.cq_off.head])),
            .cq_tail = @ptrCast(@alignCast(&cq_ring[params.cq_off.tail])),
            .events = events,
            .registered_fds = registered_fds,
        };
    }

    pub fn deinit(self: *IoUringBackend, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        allocator.free(self.registered_fds);
        if (is_linux) {
            unmapRing(self.sqe_ring);
            unmapRing(self.sq_ring);
            unmapRing(self.cq_ring);
            _ = linux.close(@intCast(self.ring_fd));
        }
    }

    pub fn poll(self: *IoUringBackend, timeout_ms: u32) ![]IoUringEvent {
        if (!is_linux) return error.Unsupported;

        // Single io_uring_enter: submit pending re-arm SQEs from the
        // previous cycle AND wait for new events. This merges what was
        // previously two syscalls (submit + wait) into one.
        const min_complete: u32 = if (timeout_ms > 0) 1 else 0;
        // GETEVENTS must always be set with DEFER_TASKRUN to process
        // deferred completions, even for non-blocking peeks.
        const flags: u32 = IORING_ENTER_GETEVENTS;
        const to_submit = self.pending_submits;
        self.pending_submits = 0;

        const rc = io_uring_enter(self.ring_fd, to_submit, min_complete, flags, null);
        if (rc < 0) {
            return self.events[0..0];
        }

        // Reap CQEs and queue re-arms for next cycle
        var count: usize = 0;

        var head = @atomicLoad(u32, self.cq_head, .acquire);
        const tail = @atomicLoad(u32, self.cq_tail, .acquire);

        while (head != tail and count < self.events.len) {
            const cqe = &self.cqes[head & self.cq_mask];
            const conn_id = cqe.user_data;
            const res = cqe.res;

            if (res < 0) {
                self.events[count] = .{
                    .events = POLLERR,
                    .data = .{ .u64 = conn_id },
                };
            } else {
                self.events[count] = .{
                    .events = @intCast(res),
                    .data = .{ .u64 = conn_id },
                };
            }
            count += 1;
            head +%= 1;
        }

        // Advance CQ head before queuing re-arms
        @atomicStore(u32, self.cq_head, head, .release);

        // Queue re-arm SQEs — they'll be submitted on the NEXT poll()
        // call, merged with the wait. This eliminates the separate
        // io_uring_enter for re-arming that was costing 1 syscall/cycle.
        var submitted: u32 = 0;
        // Re-read the events we just collected to get conn_ids for re-arm
        for (self.events[0..count]) |ev| {
            if (self.queuePollAdd(ev.data.u64)) {
                submitted += 1;
            }
        }
        self.pending_submits = submitted;

        return self.events[0..count];
    }

    pub fn registerListener(self: *IoUringBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        self.registered_fds[0] = .{ .fd = fd, .conn_id = 0, .poll_mask = POLLIN };
        self.submitPollAdd(fd, 0, POLLIN);
    }

    pub fn registerUdpSocket(self: *IoUringBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        const udp_id = std.math.maxInt(u64) - 1;
        self.registered_fds[1] = .{ .fd = fd, .conn_id = udp_id, .poll_mask = POLLIN };
        self.submitPollAdd(fd, udp_id, POLLIN);
    }

    pub fn registerConnection(self: *IoUringBackend, conn_id: u64, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        // Offset by 2 to skip listener (slot 0) and UDP (slot 1)
        const slot = conn_id + 2;
        if (slot >= self.registered_fds.len) return error.TooManyConnections;
        self.registered_fds[slot] = .{
            .fd = fd,
            .conn_id = conn_id,
            .poll_mask = POLLIN | POLLOUT,
        };
        self.submitPollAdd(fd, conn_id, POLLIN | POLLOUT);
    }

    pub fn unregister(self: *IoUringBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return;
        // Find the registration and get its conn_id for POLL_REMOVE
        var conn_id_to_remove: ?u64 = null;
        for (self.registered_fds) |*reg| {
            if (reg.fd == fd) {
                conn_id_to_remove = reg.conn_id;
                reg.fd = -1;
                break;
            }
        }
        // Submit POLL_REMOVE to cancel any outstanding poll on this fd.
        // This prevents stale CQEs from arriving after the fd is closed/reused.
        if (conn_id_to_remove) |cid| {
            if (self.sqRingHasSpace()) {
                const tail = @atomicLoad(u32, self.sq_tail, .acquire);
                const idx = tail & self.sq_mask;

                var sqe = &self.sqes[idx];
                sqe.* = std.mem.zeroes(IoUringSqe);
                sqe.opcode = IORING_OP_POLL_REMOVE;
                sqe.fd = -1;
                sqe.addr_or_splice = cid; // user_data of the poll to cancel
                sqe.user_data = cid;

                self.sq_array[idx] = idx;
                @atomicStore(u32, self.sq_tail, tail +% 1, .release);
                _ = io_uring_enter(self.ring_fd, 1, 0, 0, null);
            }
        }
    }

    fn submitPollAdd(self: *IoUringBackend, fd: std.posix.fd_t, user_data: u64, poll_mask: u32) void {
        if (!self.sqRingHasSpace()) {
            // SQ ring full — flush pending submissions first
            _ = io_uring_enter(self.ring_fd, self.pendingSqCount(), 0, 0, null);
            // If still full after flush, drop this submission (will be retried on next event)
            if (!self.sqRingHasSpace()) return;
        }

        const tail = @atomicLoad(u32, self.sq_tail, .acquire);
        const idx = tail & self.sq_mask;

        var sqe = &self.sqes[idx];
        sqe.* = std.mem.zeroes(IoUringSqe);
        sqe.opcode = IORING_OP_POLL_ADD;
        sqe.fd = fd;
        sqe.op_flags = poll_mask;
        sqe.user_data = user_data;

        self.sq_array[idx] = idx;
        @atomicStore(u32, self.sq_tail, tail +% 1, .release);

        // Submit immediately
        _ = io_uring_enter(self.ring_fd, 1, 0, 0, null);
    }

    /// Queue a POLL_ADD SQE without submitting (for batched submission).
    /// Returns true if successfully queued, false if SQ ring is full.
    fn queuePollAdd(self: *IoUringBackend, conn_id: u64) bool {
        // Find the registered fd for this conn_id
        for (self.registered_fds) |reg| {
            if (reg.conn_id == conn_id and reg.fd >= 0) {
                if (!self.sqRingHasSpace()) return false;

                const tail = @atomicLoad(u32, self.sq_tail, .acquire);
                const idx = tail & self.sq_mask;

                var sqe = &self.sqes[idx];
                sqe.* = std.mem.zeroes(IoUringSqe);
                sqe.opcode = IORING_OP_POLL_ADD;
                sqe.fd = reg.fd;
                sqe.op_flags = reg.poll_mask;
                sqe.user_data = conn_id;

                self.sq_array[idx] = idx;
                @atomicStore(u32, self.sq_tail, tail +% 1, .release);
                return true;
            }
        }
        return false;
    }

    /// Check if the SQ ring has space for at least one more SQE
    fn sqRingHasSpace(self: *IoUringBackend) bool {
        const head = @atomicLoad(u32, self.sq_head, .acquire);
        const tail = @atomicLoad(u32, self.sq_tail, .acquire);
        return (tail -% head) < self.sq_entries;
    }

    /// Count pending (unsubmitted) SQEs
    fn pendingSqCount(self: *IoUringBackend) u32 {
        const head = @atomicLoad(u32, self.sq_head, .acquire);
        const tail = @atomicLoad(u32, self.sq_tail, .acquire);
        return tail -% head;
    }
};

// io_uring setup params structure
const IoUringParams = extern struct {
    sq_entries: u32 = 0,
    cq_entries: u32 = 0,
    flags: u32 = 0,
    sq_thread_cpu: u32 = 0,
    sq_thread_idle: u32 = 0,
    features: u32 = 0,
    wq_fd: u32 = 0,
    resv: [3]u32 = .{ 0, 0, 0 },
    sq_off: SqRingOffsets = .{},
    cq_off: CqRingOffsets = .{},
};

const SqRingOffsets = extern struct {
    head: u32 = 0,
    tail: u32 = 0,
    ring_mask: u32 = 0,
    ring_entries: u32 = 0,
    flags: u32 = 0,
    dropped: u32 = 0,
    array: u32 = 0,
    resv1: u32 = 0,
    user_addr: u64 = 0,
};

const CqRingOffsets = extern struct {
    head: u32 = 0,
    tail: u32 = 0,
    ring_mask: u32 = 0,
    ring_entries: u32 = 0,
    overflow: u32 = 0,
    cqes: u32 = 0,
    flags: u32 = 0,
    resv1: u32 = 0,
    user_addr: u64 = 0,
};

// Mmap offsets for io_uring
const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_CQ_RING: u64 = 0x8000000;
const IORING_OFF_SQES: u64 = 0x10000000;

// io_uring_enter flags
const IORING_ENTER_GETEVENTS: u32 = 1;

// Syscall wrappers
fn io_uring_setup(entries: u32, params: *IoUringParams) i32 {
    if (!is_linux) return -1;
    const rc: isize = @bitCast(linux.io_uring_setup(entries, @ptrCast(params)));
    if (rc < 0) return -1;
    return @intCast(rc);
}

fn io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32, sig: ?*anyopaque) i32 {
    if (!is_linux) return -1;
    _ = sig;
    const rc: isize = @bitCast(linux.io_uring_enter(fd, to_submit, min_complete, flags, null));
    if (rc < 0) return -1;
    return @intCast(rc);
}

fn mapRing(ring_fd: i32, offset: u64, size: u32) ?[]u8 {
    if (!is_linux) return null;
    const prot = mmapProtReadWrite();
    const flags: std.posix.MAP = .{ .TYPE = .SHARED, .POPULATE = true };
    const mapping = std.posix.mmap(null, @as(usize, size), prot, flags, ring_fd, offset) catch return null;
    return mapping;
}

fn unmapRing(ring: []u8) void {
    if (!is_linux) return;
    const aligned: []align(std.heap.page_size_min) const u8 = @alignCast(ring);
    std.posix.munmap(aligned);
}

fn mmapProtReadWrite() MmapProt {
    const prot_type_info = @typeInfo(MmapProt);
    switch (prot_type_info) {
        .int => return @as(MmapProt, 0x1 | 0x2),
        .@"struct" => |info| {
            if (info.backing_integer) |Backing| {
                return @bitCast(@as(Backing, 0x1 | 0x2));
            }

            var prot: MmapProt = .{};
            var set_any = false;
            if (@hasField(MmapProt, "READ")) {
                @field(prot, "READ") = true;
                set_any = true;
            }
            if (@hasField(MmapProt, "read")) {
                @field(prot, "read") = true;
                set_any = true;
            }
            if (@hasField(MmapProt, "WRITE")) {
                @field(prot, "WRITE") = true;
                set_any = true;
            }
            if (@hasField(MmapProt, "write")) {
                @field(prot, "write") = true;
                set_any = true;
            }
            if (!set_any) {
                @compileError("Unsupported mmap PROT layout");
            }
            return prot;
        },
        else => @compileError("Unsupported mmap PROT type"),
    }
}

const MmapProt = blk: {
    const mmap_type_info = @typeInfo(@TypeOf(std.posix.mmap));
    const fn_info = if (@hasField(std.builtin.Type, "Fn"))
        mmap_type_info.Fn
    else
        mmap_type_info.@"fn";
    break :blk fn_info.params[2].type.?;
};

// Probe whether the kernel supports io_uring
pub fn probeIoUring() bool {
    if (!is_linux) return false;
    var params = std.mem.zeroes(IoUringParams);
    const fd = io_uring_setup(1, &params);
    if (fd < 0) return false;
    _ = linux.close(@intCast(fd));
    return true;
}

test "io_uring probe" {
    // Just verify the probe function compiles and runs without crash.
    // On non-Linux, it returns false. On Linux, it depends on kernel version.
    const supported = probeIoUring();
    if (!is_linux) {
        try std.testing.expect(!supported);
    }
    // On Linux, supported may be true or false depending on kernel
}
