const std = @import("std");
const builtin = @import("builtin");

const is_linux = builtin.os.tag == .linux;
const linux = if (is_linux) std.os.linux else undefined;

/// Readiness-emulation io_uring backend.
///
/// Uses IORING_OP_POLL_ADD to emulate epoll-style readiness notifications.
/// This is a drop-in replacement for the epoll backend — same event model,
/// same dispatch in server.zig. The advantage is reduced syscall overhead:
/// io_uring batches SQE submissions and CQE reaping in single syscalls.
///
/// A possible future step is to replace POLL_ADD with native
/// IORING_OP_ACCEPT, IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED for
/// true async I/O.

// io_uring constants (from linux/io_uring.h)
const IORING_SETUP_SQPOLL = 1 << 1;
const IORING_SETUP_SINGLE_ISSUER = 1 << 12; // kernel 6.0+: lockless SQE submission
const IORING_SETUP_DEFER_TASKRUN = 1 << 13; // kernel 6.1+: batch CQE delivery
const IORING_OP_POLL_ADD: u8 = 6;
const IORING_OP_POLL_REMOVE: u8 = 7;
const IORING_OP_NOP: u8 = 0;
const IORING_OP_TIMEOUT: u8 = 11;

/// struct __kernel_timespec (backing an IORING_OP_TIMEOUT SQE).
const KernelTimespec = extern struct {
    sec: i64,
    nsec: i64,
};

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

/// Bit 62 tags user_data values that belong to external
/// (non-Connection-pool) fds — PostgreSQL client sockets.
/// MUST stay equal to io.zig's EXTERNAL_ID_BIT (io.zig pins the
/// equality in a test; this module can't import io.zig without a cycle).
pub const EXTERNAL_ID_BIT: u64 = 1 << 62;

/// Hard cap on concurrently registered external fds. PgClient needs at
/// most 4 per worker; 16 leaves room for the proxy-streaming consumer
/// (design 5.0) without growing the table.
pub const MAX_EXTERNAL_FDS = 16;

/// Max TCP listeners a single ring tracks (multi-listener model). Slots
/// [0..MAX_LISTENERS) are reserved for listeners, slot MAX_LISTENERS for the
/// UDP socket, and connections start at MAX_LISTENERS+1.
///
/// Listener user_data: slot 0 uses 0 (the legacy listener token); extra
/// listeners use DISTINCT tokens LISTENER_ID_BASE+1, +2, … so each one-shot
/// POLL_ADD re-arms independently via queuePollAdd's conn_id→fd lookup.
/// io.zig translates 0 AND the LISTENER_ID_BASE range to `.accept`.
/// These constants MUST stay equal to io.zig's LISTENER_ID_BASE /
/// LISTENER_ID_COUNT (no import — would create a cycle, like EXTERNAL_ID_BIT).
pub const MAX_LISTENERS = 8;
const LISTENER_ID_BASE: u64 = std.math.maxInt(u64) - 16;

/// user_data of the one-shot IORING_OP_TIMEOUT bounding a blocking poll()
/// wait (below the listener token range, never a conn id). Without it,
/// io_uring_enter(min_complete=1) on an idle ring sleeps until the next
/// I/O CQE - which can be never - starving the reactor's deadline and
/// housekeeping checks. Its CQE is swallowed in the reap loop (never
/// surfaced as an event, never re-armed as a poll).
const TICK_TOKEN: u64 = LISTENER_ID_BASE - 1;

/// True only for well-formed external tokens: bit 62 set, every other
/// high bit clear, slot in the low 32 bits (mirror of io.zig's
/// isExternalId — same UDP_SOCKET_ID trap applies).
pub fn isExternalToken(user_data: u64) bool {
    return (user_data >> 32) == (EXTERNAL_ID_BIT >> 32);
}

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

pub const IoUringPollBackend = struct {
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
    /// True while a TICK_TOKEN timeout SQE is in flight.
    tick_armed: bool = false,
    /// Backing timespec for the in-flight tick SQE. A struct field (not a
    /// stack local) so the address the SQE carries stays valid until the
    /// kernel consumes it at submit.
    tick_ts: KernelTimespec = .{ .sec = 0, .nsec = 0 },
    /// Track registered FDs for re-arming (POLL_ADD is one-shot)
    /// Layout: [0..MAX_LISTENERS)=listeners, [MAX_LISTENERS]=UDP,
    /// [MAX_LISTENERS+1..]=connections (indexed by conn_id + MAX_LISTENERS + 1).
    /// Slot 0 uses conn_id=0; additional slots use LISTENER_ID_BASE+slot as
    /// their token. Both ranges translate to .accept in io.zig.
    registered_fds: []RegisteredFd,
    /// Number of listener slots in use ([0..listener_count) of registered_fds).
    /// Re-arming a listener CQE (conn_id=0) re-arms every active listener slot
    /// since a single CQE can't tell us which listener fired.
    listener_count: usize = 0,
    /// External (non-Connection-pool) fds, keyed by external slot — the
    /// low 32 bits of the EXTERNAL_ID_BIT-tagged token. Tagged tokens
    /// can't index `registered_fds` (its slots are conn_id + 2), so
    /// external fds live in their own small table and every CQE/re-arm
    /// path branches on the tag bit before any conn_id arithmetic.
    external_fds: [MAX_EXTERNAL_FDS]ExternalFd = [_]ExternalFd{.{}} ** MAX_EXTERNAL_FDS,
    /// Pending SQEs queued for submission on the next poll.
    pending_submits: u32 = 0,
    /// Whether DEFER_TASKRUN is active (requires GETEVENTS on every enter).
    defer_taskrun: bool = false,

    const RegisteredFd = struct {
        fd: i32 = -1,
        conn_id: u64 = 0,
        poll_mask: u32 = 0,
    };

    const ExternalFd = struct {
        fd: i32 = -1,
        active: bool = false,
        /// A one-shot POLLOUT poll is in flight (armExternalWritable).
        /// Tracked so unregister knows to cancel it alongside the
        /// perpetual POLLIN poll.
        want_write: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator, max_events: usize, multi_worker: bool) !IoUringPollBackend {
        if (!is_linux) return error.Unsupported;

        const events = try allocator.alloc(IoUringEvent, max_events);
        errdefer allocator.free(events);

        // slots [0..MAX_LISTENERS) = listeners, slot MAX_LISTENERS = UDP,
        // slots MAX_LISTENERS+1.. = connections. io.zig passes conn_id+1, and
        // we add MAX_LISTENERS+1 for the slot, so reserve that many extra.
        const registered_fds = try allocator.alloc(RegisteredFd, max_events + MAX_LISTENERS + 2);
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
        if (multi_worker) {
            // Only enable in multi-worker (forked) mode where the
            // flags eliminate lock contention across 64+ rings.
            // Single-process mode doesn't benefit and some kernels
            // (e.g., linuxkit) have issues with DEFER_TASKRUN in
            // single-process io_uring.
            params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
        }

        var ring_fd = io_uring_setup(entries, &params);
        if (ring_fd < 0 and params.flags != 0) {
            // Fallback: retry without flags for compatibility.
            params = std.mem.zeroes(IoUringParams);
            ring_fd = io_uring_setup(entries, &params);
        }
        if (ring_fd < 0) return error.IoUringSetupFailed;
        const has_defer_taskrun = (params.flags & IORING_SETUP_DEFER_TASKRUN) != 0;
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
            .defer_taskrun = has_defer_taskrun,
        };
    }

    pub fn deinit(self: *IoUringPollBackend, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        allocator.free(self.registered_fds);
        if (is_linux) {
            unmapRing(self.sqe_ring);
            unmapRing(self.sq_ring);
            unmapRing(self.cq_ring);
            _ = linux.close(@intCast(self.ring_fd));
        }
    }

    pub fn poll(self: *IoUringPollBackend, timeout_ms: u32) ![]IoUringEvent {
        if (!is_linux) return error.Unsupported;

        // Single io_uring_enter: submit pending re-arm SQEs from the
        // previous cycle AND wait for new events. This merges what was
        // previously two syscalls (submit + wait) into one.
        var min_complete: u32 = if (timeout_ms > 0) 1 else 0;
        var to_submit = self.pending_submits;
        self.pending_submits = 0;
        if (min_complete == 1 and !self.tick_armed) {
            // Bound the blocking wait (see TICK_TOKEN). Armed lazily and only
            // when this poll would actually sleep, so a loaded ring re-arms at
            // most once per timeout_ms, not once per poll.
            if (self.sqRingHasSpace()) {
                self.tick_ts = .{
                    .sec = @intCast(timeout_ms / 1000),
                    .nsec = @intCast((timeout_ms % 1000) * std.time.ns_per_ms),
                };
                const tail = @atomicLoad(u32, self.sq_tail, .acquire);
                const idx = tail & self.sq_mask;
                var sqe = &self.sqes[idx];
                sqe.* = std.mem.zeroes(IoUringSqe);
                sqe.opcode = IORING_OP_TIMEOUT;
                sqe.fd = -1;
                sqe.addr_or_splice = @intFromPtr(&self.tick_ts);
                sqe.len = 1;
                sqe.user_data = TICK_TOKEN;
                self.sq_array[idx] = idx;
                @atomicStore(u32, self.sq_tail, tail +% 1, .release);
                to_submit += 1;
                self.tick_armed = true;
            } else {
                // SQ full: skip blocking this round rather than sleep unbounded.
                min_complete = 0;
            }
        }
        // GETEVENTS is required with DEFER_TASKRUN to process deferred
        // completions. Without DEFER_TASKRUN, only set it when waiting.
        const flags: u32 = if (self.defer_taskrun or min_complete > 0)
            IORING_ENTER_GETEVENTS
        else
            0;

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

            // Bounded-wait tick fired; the next blocking poll re-arms it.
            // Swallow the CQE - waking with zero events is exactly the
            // deadline/housekeeping pass the reactor loop wants.
            if (conn_id == TICK_TOKEN) {
                self.tick_armed = false;
                head +%= 1;
                continue;
            }

            // External-fd CQEs: drop after unregister so a cancelled or
            // still-in-flight poll (POLL_REMOVE completions reuse the
            // token as their own user_data, and -ENOENT misses land here
            // too) can't surface a stale event for a slot that may have
            // been re-registered with a new fd.
            if (isExternalToken(conn_id)) {
                const slot = conn_id & 0xFFFF_FFFF;
                if (slot >= MAX_EXTERNAL_FDS or !self.external_fds[@intCast(slot)].active) {
                    head +%= 1;
                    continue;
                }
            }

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
            if (isExternalToken(ev.data.u64)) {
                if (self.queueExternalRearm(ev)) {
                    submitted += 1;
                }
                continue;
            }
            if (self.queuePollAdd(ev.data.u64)) {
                submitted += 1;
            }
        }
        self.pending_submits = submitted;

        return self.events[0..count];
    }

    pub fn registerListener(self: *IoUringPollBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        // Append into the next free listener slot. Slot 0 keeps token 0 (legacy
        // listener); extra listeners get distinct LISTENER_ID_BASE+slot tokens
        // so each re-arms independently. Both translate to .accept in io.zig.
        if (self.listener_count >= MAX_LISTENERS) return error.TooManyConnections;
        const slot = self.listener_count;
        const token: u64 = if (slot == 0) 0 else LISTENER_ID_BASE + slot;
        self.registered_fds[slot] = .{ .fd = fd, .conn_id = token, .poll_mask = POLLIN };
        self.listener_count += 1;
        self.submitPollAdd(fd, token, POLLIN);
    }

    pub fn registerUdpSocket(self: *IoUringPollBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        const udp_id = std.math.maxInt(u64) - 1;
        self.registered_fds[MAX_LISTENERS] = .{ .fd = fd, .conn_id = udp_id, .poll_mask = POLLIN };
        self.submitPollAdd(fd, udp_id, POLLIN);
    }

    pub fn registerConnection(self: *IoUringPollBackend, conn_id: u64, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        // Offset past the listener slots (0..MAX_LISTENERS) and the UDP slot.
        const slot = conn_id + MAX_LISTENERS + 1;
        if (slot >= self.registered_fds.len) return error.TooManyConnections;
        self.registered_fds[slot] = .{
            .fd = fd,
            .conn_id = conn_id,
            .poll_mask = POLLIN | POLLOUT,
        };
        self.submitPollAdd(fd, conn_id, POLLIN | POLLOUT);
    }

    pub fn unregister(self: *IoUringPollBackend, fd: std.posix.fd_t) !void {
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
            self.submitPollRemove(cid);
        }
    }

    /// Register an external fd for POLLIN readiness. The poll is
    /// one-shot like every POLL_ADD on this ring, but the re-arm path
    /// in `poll()` keeps it perpetually armed while the slot stays
    /// registered — consumers drain to EAGAIN and rely on the next
    /// readability producing another event.
    pub fn registerExternalFd(self: *IoUringPollBackend, slot: u32, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        if (slot >= MAX_EXTERNAL_FDS) return error.TooManyConnections;
        self.external_fds[slot] = .{ .fd = fd, .active = true };
        self.submitPollAdd(fd, EXTERNAL_ID_BIT | @as(u64, slot), POLLIN);
    }

    /// One-shot POLLOUT wake for an external fd (connect-in-progress
    /// or a partial write that hit EAGAIN). Runs as a second concurrent
    /// POLL_ADD with the same tagged token; the CQE's poll mask is what
    /// distinguishes it from the POLLIN poll. Never re-armed by the
    /// backend — consumers re-arm on demand.
    pub fn armExternalWritable(self: *IoUringPollBackend, slot: u32, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        if (slot >= MAX_EXTERNAL_FDS) return error.TooManyConnections;
        self.external_fds[slot].want_write = true;
        self.submitPollAdd(fd, EXTERNAL_ID_BIT | @as(u64, slot), POLLOUT);
    }

    /// Remove an external fd: cancel the in-flight POLLIN poll (and the
    /// one-shot POLLOUT poll if armed) and deactivate the slot so any
    /// already-reaped or still-in-flight CQE for it is dropped in
    /// `poll()` instead of surfacing after unregistration.
    pub fn unregisterExternalFd(self: *IoUringPollBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return;
        for (&self.external_fds, 0..) |*ext, slot| {
            if (!ext.active or ext.fd != fd) continue;
            const token = EXTERNAL_ID_BIT | @as(u64, slot);
            // POLL_REMOVE cancels ONE matching request per submission —
            // submit a second when a one-shot POLLOUT poll is also in
            // flight. An extra remove completes with -ENOENT; its CQE
            // (and the cancelled polls') is dropped by the
            // inactive-slot filter in poll().
            self.submitPollRemove(token);
            if (ext.want_write) self.submitPollRemove(token);
            ext.* = .{};
        }
    }

    fn submitPollAdd(self: *IoUringPollBackend, fd: std.posix.fd_t, user_data: u64, poll_mask: u32) void {
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

    /// Queue and immediately submit a POLL_REMOVE cancelling the poll
    /// whose user_data matches `target`. The remove's own completion
    /// reuses `target` as its user_data so the CQE routes through the
    /// same drop/ignore paths as the poll it cancelled.
    fn submitPollRemove(self: *IoUringPollBackend, target: u64) void {
        if (!self.sqRingHasSpace()) return;
        const tail = @atomicLoad(u32, self.sq_tail, .acquire);
        const idx = tail & self.sq_mask;

        var sqe = &self.sqes[idx];
        sqe.* = std.mem.zeroes(IoUringSqe);
        sqe.opcode = IORING_OP_POLL_REMOVE;
        sqe.fd = -1;
        sqe.addr_or_splice = target; // user_data of the poll to cancel
        sqe.user_data = target;

        self.sq_array[idx] = idx;
        @atomicStore(u32, self.sq_tail, tail +% 1, .release);
        _ = io_uring_enter(self.ring_fd, 1, 0, 0, null);
    }

    /// Queue a POLL_ADD SQE without submitting (for batched submission).
    /// Returns true if successfully queued, false if SQ ring is full.
    fn queuePollAdd(self: *IoUringPollBackend, conn_id: u64) bool {
        // Find the registered fd for this conn_id
        for (self.registered_fds) |reg| {
            if (reg.conn_id == conn_id and reg.fd >= 0) {
                return self.queueRawPollAdd(reg.fd, conn_id, reg.poll_mask);
            }
        }
        return false;
    }

    /// Re-arm decision for an external-fd CQE. The POLLIN poll is
    /// perpetual: re-armed after every read wake while the slot stays
    /// registered. The one-shot POLLOUT poll is consumed here
    /// (want_write cleared) and never re-armed. Error wakes don't
    /// re-arm — the consumer fails the slot and unregisters.
    fn queueExternalRearm(self: *IoUringPollBackend, ev: IoUringEvent) bool {
        const slot = ev.data.u64 & 0xFFFF_FFFF;
        if (slot >= MAX_EXTERNAL_FDS) return false;
        const ext = &self.external_fds[@intCast(slot)];
        if (!ext.active) return false;
        if (ev.events & POLLOUT != 0) ext.want_write = false;
        if (ev.events & (POLLERR | POLLHUP) != 0) return false;
        if (ev.events & POLLIN == 0) return false;
        return self.queueRawPollAdd(ext.fd, ev.data.u64, POLLIN);
    }

    /// Queue a POLL_ADD SQE for batched submission on the next poll().
    /// Returns false (dropped) when the SQ ring is full.
    fn queueRawPollAdd(self: *IoUringPollBackend, fd: i32, user_data: u64, poll_mask: u32) bool {
        if (!self.sqRingHasSpace()) return false;

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
        return true;
    }

    /// Check if the SQ ring has space for at least one more SQE
    fn sqRingHasSpace(self: *IoUringPollBackend) bool {
        const head = @atomicLoad(u32, self.sq_head, .acquire);
        const tail = @atomicLoad(u32, self.sq_tail, .acquire);
        return (tail -% head) < self.sq_entries;
    }

    /// Count pending (unsubmitted) SQEs
    fn pendingSqCount(self: *IoUringPollBackend) u32 {
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
