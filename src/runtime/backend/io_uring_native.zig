const std = @import("std");
const builtin = @import("builtin");
const clock = @import("../clock.zig");

const is_linux = builtin.os.tag == .linux;
const linux = if (is_linux) std.os.linux else undefined;
const IoUring = if (is_linux) linux.IoUring else void;
const page_size_min = std.heap.page_size_min;

/// Native io_uring backend — completion model with multishot accept,
/// multishot recv over a non-incremental provided-buffer ring, and
/// SINGLE_ISSUER + DEFER_TASKRUN for lockless single-worker-per-ring
/// operation.
///
/// Unlike `io_uring_poll`, this backend delivers read data inline with
/// the event: the kernel fills a buffer from the provided ring, and
/// the CQE carries a buffer ID the caller translates to a slice. The
/// caller MUST release the buffer back to the ring once the data has
/// been consumed (or copied out).
///
/// We deliberately set up the provided-buffer ring with `.inc = false`
/// (non-incremental) rather than going through stdlib's `BufferGroup`
/// (which hardcodes `.inc = true`). Non-incremental gives us clean
/// one-CQE-one-buffer semantics: every recv CQE fully consumes its
/// buffer, so `releaseRecvBuffer` can re-add it without any head/tail
/// bookkeeping. Incremental would require tracking partial consumption
/// across CQEs and composing awkwardly with the server's copy-out +
/// release-immediately flow.
///
/// Not used with TLS or QUIC: those configurations stay on the poll
/// emulation backend, because (a) the TLS BIO reads through plain
/// `recv()` and would see EAGAIN forever after multishot recv drains
/// the socket into our slab, and (b) UDP recvmsg isn't wired into the
/// native ring yet. The picker in `io.zig` enforces this.

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

/// Reserved space for the peer sockaddr at the head of each UDP
/// provided buffer (after the `io_uring_recvmsg_out` header). 28 bytes
/// is enough for `sockaddr_in6` (the largest we care about); smaller
/// is preferable because the kernel rounds the payload offset up by
/// this amount on every datagram.
const UDP_NAMELEN: u32 = 28;

// ─── Acceptor thread sizing ─────────────────────────────────────────
// The acceptor runs on its own thread with its own io_uring ring,
// drains accept CQEs from the kernel as fast as possible, and pushes
// the new fds into a single-producer / single-consumer queue that the
// reactor consumes at the top of each event loop iteration.
// The key insight is that the accept path and the recv/send path don't
// compete for the same io_uring ring,
// so the kernel can satisfy accepts at line rate
// without being throttled by the reactor's task-work queue under
// DEFER_TASKRUN.
//
// `ACCEPT_QUEUE_CAPACITY` must be a power of two so the SPSC ring
// can use a bitmask for index wrap. 4096 slots gives ~64 KB of state
// per worker process and absorbs accept bursts up to that depth.
// `ACCEPTOR_RING_ENTRIES` is the io_uring submission queue depth on
// the acceptor's ring — accept SQEs are submitted once (multishot)
// and never refilled, so it can be small.
const ACCEPT_QUEUE_CAPACITY: usize = 4096;
const ACCEPT_QUEUE_MASK: usize = ACCEPT_QUEUE_CAPACITY - 1;
const ACCEPTOR_RING_ENTRIES: u16 = 16;
const ACCEPTOR_CQE_BATCH: usize = 256;

/// Lock-free single-producer / single-consumer ring buffer of file
/// descriptors. The acceptor thread is the sole producer; the reactor
/// thread is the sole consumer. No locking — ordering is enforced by
/// release-acquire semantics on the head/tail counters.
const SpscFdQueue = struct {
    slots: [ACCEPT_QUEUE_CAPACITY]i32 = [_]i32{-1} ** ACCEPT_QUEUE_CAPACITY,
    head: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
    tail: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),

    fn push(self: *SpscFdQueue, fd: i32) bool {
        const tail = self.tail.load(.monotonic);
        const head = self.head.load(.acquire);
        if (tail -% head >= ACCEPT_QUEUE_CAPACITY) return false;
        self.slots[tail & ACCEPT_QUEUE_MASK] = fd;
        self.tail.store(tail +% 1, .release);
        return true;
    }

    fn pop(self: *SpscFdQueue) ?i32 {
        const head = self.head.load(.monotonic);
        const tail = self.tail.load(.acquire);
        if (head == tail) return null;
        const fd = self.slots[head & ACCEPT_QUEUE_MASK];
        self.head.store(head +% 1, .release);
        return fd;
    }
};

/// Dedicated acceptor thread state. Heap-allocated so the spawned
/// thread can hold a stable pointer through its entire lifetime.
///
/// The acceptor owns its own io_uring ring (separate from the reactor
/// ring), arms a multishot accept on the listener fd, and pushes each
/// accepted client fd into the SPSC queue shared with the reactor.
/// After every push it bumps an eventfd that the reactor's main ring
/// is poll-watching, which wakes the reactor exactly once per batch
/// of accepts (the eventfd counter coalesces redundant signals).
///
/// Why this separation:
/// With SINGLE_ISSUER + DEFER_TASKRUN set on the reactor's ring,
/// multishot accept on that same ring gets rate-limited by the
/// kernel's deferred-taskrun queue: new accept CQEs aren't
/// dispatched until the next io_uring_enter, and on a busy reactor
/// that lags behind the actual SYN backlog. Running accept on a
/// separate ring whose only job is to sit in io_uring_enter waiting
/// for accept CQEs lets the kernel satisfy accepts at line rate
/// independently of how busy the reactor is.
const Acceptor = if (!is_linux) void else struct {
    queue: SpscFdQueue = .{},
    /// eventfd we write to from the acceptor thread. The reactor's
    /// main ring polls this fd; each readiness event triggers a drain
    /// of the SPSC queue. EFD_SEMAPHORE is NOT set: a single read()
    /// drains the entire counter, which is exactly the coalescing
    /// behavior we want.
    eventfd_fd: i32 = -1,
    listener_fd: i32 = -1,
    /// Acceptor's own io_uring ring (independent of the reactor's).
    /// Plain init flags — DEFER_TASKRUN would defeat the whole point
    /// of running accept on its own thread (we *want* the kernel to
    /// dispatch accept CQEs the moment they're ready, not at the next
    /// io_uring_enter).
    ring: IoUring = undefined,
    thread: ?std.Thread = null,
    shutdown: std.atomic.Value(bool) align(64) = std.atomic.Value(bool).init(false),
    /// Counted backpressure. Incremented when the SPSC queue is full
    /// and the acceptor must drop the new fd (closes it cleanly so
    /// the client gets a TCP RST). Logged at deinit for visibility.
    overflow_drops: std.atomic.Value(u64) align(64) = std.atomic.Value(u64).init(0),

    fn create(allocator: std.mem.Allocator, listener_fd: i32) !*Acceptor {
        const self = try allocator.create(Acceptor);
        errdefer allocator.destroy(self);
        self.* = .{
            .queue = .{},
            .eventfd_fd = -1,
            .listener_fd = listener_fd,
            .ring = undefined,
            .thread = null,
            .shutdown = std.atomic.Value(bool).init(false),
            .overflow_drops = std.atomic.Value(u64).init(0),
        };

        // eventfd via raw syscall — std.posix.eventfd was removed
        // in newer 0.16-dev releases, and we only need the simple
        // case (init=0, NONBLOCK + CLOEXEC). The kernel returns the
        // new fd as a positive integer or -errno.
        const efd_rc = linux.eventfd(0, linux.EFD.NONBLOCK | linux.EFD.CLOEXEC);
        const efd_errno = std.posix.errno(efd_rc);
        if (efd_errno != .SUCCESS) {
            std.log.err("io_uring_native acceptor: eventfd failed: errno={}", .{@intFromEnum(efd_errno)});
            return error.EventfdFailed;
        }
        const efd: i32 = @intCast(efd_rc);
        errdefer clock.closeFd(efd);
        self.eventfd_fd = efd;

        self.ring = IoUring.init(ACCEPTOR_RING_ENTRIES, 0) catch |err| {
            std.log.err("io_uring_native acceptor: IoUring.init failed: {}", .{err});
            return err;
        };
        errdefer self.ring.deinit();

        // Arm multishot accept on the acceptor's ring. The kernel will
        // produce one CQE per incoming connection until F_MORE clears
        // (kernel error / oom). user_data tag is irrelevant — this is
        // the only op type on this ring.
        _ = self.ring.accept_multishot(
            1,
            listener_fd,
            null,
            null,
            std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
        ) catch |err| {
            std.log.err("io_uring_native acceptor: accept_multishot prep failed: {}", .{err});
            return err;
        };
        _ = self.ring.submit() catch |err| {
            std.log.err("io_uring_native acceptor: initial submit failed: {}", .{err});
            return err;
        };

        return self;
    }

    fn start(self: *Acceptor) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn run(self: *Acceptor) void {
        var rearm_pending: bool = false;
        while (!self.shutdown.load(.acquire)) {
            // Block until at least one accept CQE arrives. On shutdown
            // the parent calls eventfd_write on a dummy fd to wake us;
            // we recheck the flag at the top of the loop.
            const submit_count: u32 = if (rearm_pending) 1 else 0;
            _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => {
                    std.log.warn("io_uring_native acceptor: submit_and_wait failed: {}", .{err});
                    return;
                },
            };
            _ = submit_count;
            rearm_pending = false;

            var batch: [ACCEPTOR_CQE_BATCH]linux.io_uring_cqe = undefined;
            const n = self.ring.copy_cqes(&batch, 0) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => {
                    std.log.warn("io_uring_native acceptor: copy_cqes failed: {}", .{err});
                    return;
                },
            };

            var any_pushed: bool = false;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const cqe = batch[i];

                // Multishot accept terminated (kernel ENOMEM, etc.).
                // Re-arm so we don't lose the listener.
                if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                    rearm_pending = true;
                    _ = self.ring.accept_multishot(
                        1,
                        self.listener_fd,
                        null,
                        null,
                        std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
                    ) catch {};
                }

                if (cqe.res < 0) continue;
                const fd: i32 = cqe.res;

                // Hand off to the reactor via the SPSC queue. If the
                // queue is full the reactor is too far behind us to
                // catch up — close the fresh fd to release the SYN
                // backlog slot and bump the drop counter.
                if (!self.queue.push(fd)) {
                    _ = self.overflow_drops.fetchAdd(1, .monotonic);
                    clock.closeFd(fd);
                    continue;
                }
                any_pushed = true;
            }

            if (any_pushed) {
                // Wake the reactor exactly once per batch. We always
                // write 1; the reactor's read() drains the eventfd
                // counter to zero in a single call so even bursts
                // collapse to one wakeup.
                const one: u64 = 1;
                _ = linux.write(self.eventfd_fd, @ptrCast(&one), @sizeOf(u64));
            }
        }
    }

    fn signalShutdown(self: *Acceptor) void {
        self.shutdown.store(true, .release);
        // Bump the eventfd to give the reactor one last poke, and
        // wake the acceptor thread (which is blocked in
        // submit_and_wait on its own ring) by closing the listener
        // — the parent process tearing down will do that, and the
        // kernel delivers a final -EBADF CQE which unblocks the wait.
        const one: u64 = 1;
        _ = linux.write(self.eventfd_fd, @ptrCast(&one), @sizeOf(u64));
    }

    fn destroy(self: *Acceptor, allocator: std.mem.Allocator) void {
        const drops = self.overflow_drops.load(.monotonic);
        if (drops > 0) {
            std.log.warn("io_uring_native acceptor: dropped {d} accepts due to SPSC backpressure", .{drops});
        }
        if (self.thread) |t| {
            self.signalShutdown();
            t.join();
        }
        if (self.eventfd_fd >= 0) clock.closeFd(self.eventfd_fd);
        self.ring.deinit();
        allocator.destroy(self);
    }
};

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
    /// Multishot recvmsg on the singleton UDP socket (QUIC). The CQE
    /// points at a provided buffer whose first bytes are a
    /// `struct io_uring_recvmsg_out` followed by the reserved name
    /// area (msghdr.namelen), cmsg area (msghdr.controllen, zero for
    /// us), and the packet payload. We reuse the same buffer group
    /// as TCP recv — a UDP flood and a TCP flood share the pool.
    recvmsg = 4,
    /// POLL_ADD readiness wake for write backpressure. The CQE is
    /// emitted when a connection's socket becomes writable again
    /// after a sync writev hit EAGAIN. `cqe.res` carries the poll
    /// mask, not a byte count — we emit a .write event with
    /// `bytes_written = 0` so the server's dispatcher re-enters
    /// handleWrite and retries the writev.
    poll_writable = 5,
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
// was filled by the kernel into one of our provided buffers and lives
// in the slab until we release that buffer back to the ring.
pub const IoUringNativeEvent = struct {
    kind: Kind,
    conn_id: u32,
    // For .read and .datagram events: the data already delivered by
    // the kernel. Points into the backend's provided-buffer slab —
    // valid until the caller releases the buffer via
    // releaseRecvBuffer.
    data: ?[]const u8 = null,
    // For .read and .datagram events: the buffer ID to return to the
    // kernel once the caller has consumed the data. Caller must
    // eventually call IoUringNativeBackend.releaseRecvBuffer(buffer_id).
    kernel_buffer_id: ?u16 = null,
    // For .accept events: the new client fd.
    accepted_fd: ?i32 = null,
    // For .write events: the actual bytes written by the kernel
    // (cqe.res). The server advances the connection's write queue
    // by this amount; a short write means the kernel couldn't fit
    // the full iovec and we'll resubmit the remainder.
    bytes_written: usize = 0,
    // For .datagram events: the peer address the packet came from.
    // The bytes at `datagram_peer[0..datagram_peer_len]` are the raw
    // `struct sockaddr_in` or `sockaddr_in6` the kernel wrote into
    // the buffer's reserved name area.
    datagram_peer: [28]u8 = undefined,
    datagram_peer_len: u8 = 0,

    pub const Kind = enum { accept, read, write, err, datagram };
};

/// Non-Linux stub. Every method returns `error.Unsupported` so the
/// type checks on every platform but fails cleanly at runtime if the
/// backend picker somehow selects it on a non-Linux build.
const StubBackend = struct {
    pub fn init(_: std.mem.Allocator, _: usize) !StubBackend {
        return error.Unsupported;
    }
    pub fn deinit(_: *StubBackend, _: std.mem.Allocator) void {}
    pub fn registerListener(_: *StubBackend, _: i32) !void {
        return error.Unsupported;
    }
    pub fn registerUdpSocket(_: *StubBackend, _: i32) !void {
        return error.Unsupported;
    }
    pub fn registerConnection(_: *StubBackend, _: u32, _: i32) !void {
        return error.Unsupported;
    }
    pub fn submitSend(_: *StubBackend, _: u32, _: i32, _: []const u8) !void {
        return error.Unsupported;
    }
    pub fn submitWritev(_: *StubBackend, _: u32, _: i32, _: []const std.posix.iovec_const) !void {
        return error.Unsupported;
    }
    pub fn armWritable(_: *StubBackend, _: u32, _: i32) !void {
        return error.Unsupported;
    }
    pub fn rearmRecv(_: *StubBackend, _: u32, _: i32) void {}
    pub fn bumpGeneration(_: *StubBackend, _: u32) void {}
    pub fn releaseRecvBuffer(_: *StubBackend, _: u16) void {}
    pub fn poll(_: *StubBackend, _: u32) ![]IoUringNativeEvent {
        return &[_]IoUringNativeEvent{};
    }
};

pub const IoUringNativeBackend = if (!is_linux) StubBackend else struct {
    /// Heap-allocated so its address is stable across struct copies.
    /// This MUST be a pointer, not a value: any code that caches a
    /// `*IoUring` (like our own recv_multishot path, which takes
    /// `&self.ring.*` to pass the ring's address to `get_sqe`) would
    /// otherwise see a dangling pointer the moment this struct is
    /// copied out of `init()` into the caller's slot.
    ring: *IoUring,
    /// Our own provided-buffer ring (not stdlib's `BufferGroup`).
    /// We bypass `BufferGroup` because it hardcodes
    /// `REGISTER_PBUF_RING` with `.inc = true` (incremental buffer
    /// consumption, kernel 6.12+). Incremental mode means the kernel
    /// can deliver multiple CQEs that all point at the *same* buffer
    /// (`F_BUF_MORE` set) and only the final CQE releases it — a
    /// protocol that does not compose with our event-based release
    /// path where the server copies data out and releases the buffer
    /// immediately. Non-incremental gives us the clean
    /// one-CQE-one-buffer semantics the rest of the backend assumes.
    br: *align(page_size_min) linux.io_uring_buf_ring,
    /// Backing slab for the buffer ring: RECV_BUF_COUNT buffers of
    /// RECV_BUF_SIZE bytes each.
    buffers: []u8,
    allocator: std.mem.Allocator,
    /// Output events produced by poll()
    events: []IoUringNativeEvent,
    /// Registered listener fd (for multishot accept re-arming)
    listener_fd: ?i32 = null,
    /// Registered UDP socket fd (for multishot recvmsg re-arming,
    /// used by QUIC). Null when QUIC isn't enabled on this process.
    udp_fd: ?i32 = null,
    /// Template msghdr for multishot recvmsg. Kernel reads namelen /
    /// controllen from here to reserve space at the start of each
    /// provided buffer. MUST remain valid for the lifetime of the
    /// multishot op — stored here so the pointer stays stable.
    udp_msghdr: linux.msghdr = undefined,
    /// Dummy single iovec backing the msghdr.iov pointer. Zig's
    /// `linux.msghdr.iov` is `[*]iovec` and cannot be null; in the
    /// multishot path `iovlen` is 0 so the kernel never dereferences
    /// the base pointer.
    udp_iov: [1]std.posix.iovec = undefined,
    /// Per-connection generation counter — incremented when a conn_id
    /// is reused, so stale CQEs from the previous lifetime get ignored.
    generations: []u28,
    /// Per-connection "multishot recv is live" flag. Set by armRecv,
    /// cleared when the kernel delivers a terminal CQE (F_MORE not
    /// set on a non-stale completion). Used to skip redundant rearms
    /// from the server's generic per-event rearm path when the
    /// multishot is still producing CQEs.
    recv_armed: []bool,

    // ─── Acceptor thread state ──────────────────────────────────────
    // Heap-allocated so the acceptor thread can hold a stable pointer
    // to it for its entire lifetime, regardless of how the parent
    // backend struct gets moved/copied during init().
    acceptor: ?*Acceptor = null,

    pub fn init(
        allocator: std.mem.Allocator,
        max_events: usize,
    ) !IoUringNativeBackend {

        // Try the fast flags first; fall back to plain init if the
        // kernel is too old. The fast path is critical for multi-worker
        // performance — it eliminates ring-level lock contention and
        // interrupt storms that otherwise cost ~1ms per request.
        const entries: u16 = @intCast(std.math.ceilPowerOfTwoAssert(u32, @intCast(@min(max_events * 2, 4096))));
        const ring = try allocator.create(IoUring);
        errdefer allocator.destroy(ring);
        ring.* = IoUring.init(
            entries,
            IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
        ) catch |err| blk: {
            std.log.warn("io_uring_native: SINGLE_ISSUER|DEFER_TASKRUN failed ({}); retrying without", .{err});
            break :blk try IoUring.init(entries, 0);
        };
        errdefer ring.deinit();

        // Set up a provided-buffer ring with .inc = false (non-
        // incremental). Each CQE fully consumes the buffer it points
        // at; the server copies the bytes out and calls
        // releaseRecvBuffer to return the buffer id to the kernel.
        const br = try linux.IoUring.setup_buf_ring(
            ring.fd,
            RECV_BUF_COUNT,
            RECV_BUF_GROUP_ID,
            .{ .inc = false },
        );
        errdefer linux.IoUring.free_buf_ring(ring.fd, br, RECV_BUF_COUNT, RECV_BUF_GROUP_ID);
        linux.IoUring.buf_ring_init(br);

        const buffers = try allocator.alloc(u8, @as(usize, RECV_BUF_SIZE) * @as(usize, RECV_BUF_COUNT));
        errdefer allocator.free(buffers);

        // Seed the buffer ring with all RECV_BUF_COUNT buffers.
        const mask = linux.IoUring.buf_ring_mask(RECV_BUF_COUNT);
        var i: u16 = 0;
        while (i < RECV_BUF_COUNT) : (i += 1) {
            const pos = @as(usize, RECV_BUF_SIZE) * @as(usize, i);
            const buf = buffers[pos .. pos + RECV_BUF_SIZE];
            linux.IoUring.buf_ring_add(br, buf, i, mask, i);
        }
        linux.IoUring.buf_ring_advance(br, RECV_BUF_COUNT);

        const events = try allocator.alloc(IoUringNativeEvent, max_events);
        errdefer allocator.free(events);

        const generations = try allocator.alloc(u28, max_events);
        @memset(generations, 0);
        errdefer allocator.free(generations);

        const recv_armed = try allocator.alloc(bool, max_events);
        @memset(recv_armed, false);
        errdefer allocator.free(recv_armed);

        return .{
            .ring = ring,
            .br = br,
            .buffers = buffers,
            .allocator = allocator,
            .events = events,
            .generations = generations,
            .recv_armed = recv_armed,
            .udp_fd = null,
            .udp_msghdr = undefined,
            .udp_iov = undefined,
            .acceptor = null,
        };
    }

    pub fn deinit(self: *IoUringNativeBackend, allocator: std.mem.Allocator) void {
        // Stop and free the acceptor first: it owns the listener fd
        // and an independent io_uring ring. Doing this before the
        // reactor ring's free_buf_ring/deinit makes sure no acceptor
        // CQE arrives during teardown to push into a destroyed queue.
        if (self.acceptor) |acc| {
            acc.destroy(allocator);
            self.acceptor = null;
        }
        linux.IoUring.free_buf_ring(self.ring.fd, self.br, RECV_BUF_COUNT, RECV_BUF_GROUP_ID);
        allocator.free(self.buffers);
        self.ring.deinit();
        allocator.destroy(self.ring);
        allocator.free(self.events);
        allocator.free(self.generations);
        allocator.free(self.recv_armed);
    }

    /// Compute the slice that buffer `id` points at in our slab.
    fn bufferSlice(self: *IoUringNativeBackend, id: u16) []u8 {
        const pos = @as(usize, RECV_BUF_SIZE) * @as(usize, id);
        return self.buffers[pos .. pos + RECV_BUF_SIZE];
    }

    /// Register the TCP listener fd. Two modes:
    /// - Default: reactor arms POLL_ADD on the listener directly and
    ///   calls `accept4()` in a userspace loop on each readiness
    ///   event. Same accept model as the `io_uring_poll` backend.
    ///   Best overall on mixed workloads because the reactor's CQE
    ///   batch window stays wide and there's no cross-thread wakeup
    ///   latency between accept and the first recv.
    /// - `SWERVER_THREADED_ACCEPT=1`: a dedicated acceptor thread
    ///   runs multishot accept on its own io_uring ring and hands
    ///   fds to the reactor through a lock-free SPSC queue + an
    ///   eventfd. Reserved for very accept-heavy benchmarks that
    ///   want to fully saturate a single core with accept4 syscalls.
    pub fn registerListener(self: *IoUringNativeBackend, fd: i32) !void {
        self.listener_fd = fd;
        if (envThreadedAccept()) {
            const acc = try Acceptor.create(self.allocator, fd);
            errdefer acc.destroy(self.allocator);
            try acc.start();
            self.acceptor = acc;
            try self.armAcceptorWakeup(acc.eventfd_fd);
            return;
        }
        try self.armListenerPoll(fd);
    }

    fn envThreadedAccept() bool {
        const raw = std.c.getenv("SWERVER_THREADED_ACCEPT") orelse return false;
        const v = std.mem.span(raw);
        return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true");
    }

    fn armListenerPoll(self: *IoUringNativeBackend, fd: i32) !void {
        _ = try self.ring.poll_add(
            packUserData(.accept, 0, 0),
            @intCast(fd),
            linux.POLL.IN,
        );
    }

    fn armAcceptorWakeup(self: *IoUringNativeBackend, eventfd: i32) !void {
        _ = try self.ring.poll_add(
            packUserData(.accept, 0, 0),
            @intCast(eventfd),
            linux.POLL.IN,
        );
    }

    /// Register the UDP socket for QUIC and arm multishot recvmsg.
    /// Every inbound datagram produces a CQE whose buffer starts with
    /// a `struct io_uring_recvmsg_out` header followed by the
    /// `UDP_NAMELEN`-byte reserved name area and then the payload.
    pub fn registerUdpSocket(self: *IoUringNativeBackend, fd: i32) !void {
        self.udp_fd = fd;
        // The iov slot is never dereferenced by the kernel in the
        // multishot path (iovlen=0) but Zig's msghdr struct declares
        // iov as `[*]iovec` which can't be null — so we keep a
        // dummy-but-addressable iovec to satisfy the type.
        self.udp_iov[0] = .{ .base = undefined, .len = 0 };
        self.udp_msghdr = .{
            .name = null,
            .namelen = UDP_NAMELEN,
            .iov = @ptrCast(&self.udp_iov),
            .iovlen = 0,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        try self.armMultishotRecvmsg();
    }

    fn armMultishotRecvmsg(self: *IoUringNativeBackend) !void {
        const fd = self.udp_fd orelse return;
        const sqe = try self.ring.get_sqe();
        sqe.prep_recvmsg_multishot(fd, &self.udp_msghdr, 0);
        sqe.flags |= linux.IOSQE_BUFFER_SELECT;
        sqe.buf_index = RECV_BUF_GROUP_ID;
        // conn_id field is unused for the singleton UDP socket.
        sqe.user_data = packUserData(.recvmsg, 0, 0);
    }


    /// Arm a multishot recv on a freshly-accepted connection. Data
    /// arrives via the provided buffer ring and is delivered inline
    /// with each completion event. The multishot SQE stays armed for
    /// the lifetime of the connection: as long as the kernel sets
    /// IORING_CQE_F_MORE on each CQE, we do no further submissions
    /// and amortize the recv-setup cost across every request on the
    /// connection. This is the core amortization that makes the
    /// native backend win on keepalive workloads.
    ///
    /// Stale-CQE safety: when a connection slot is reused, the per-
    /// slot generation counter gets bumped in `bumpGeneration` (called
    /// from `IoRuntime.releaseConnection`). Any CQE still in the
    /// kernel's completion queue from the previous incarnation carries
    /// the old generation and gets filtered out in `poll()` below
    /// before the provided buffer is handed back to the server.
    pub fn registerConnection(self: *IoUringNativeBackend, conn_id: u32, fd: i32) !void {
        if (conn_id >= self.generations.len) return error.ConnIdOutOfRange;
        try self.armRecv(conn_id, fd);
    }

    fn armRecv(self: *IoUringNativeBackend, conn_id: u32, fd: i32) !void {
        const gen = self.generations[conn_id];
        const sqe = try self.ring.get_sqe();
        sqe.prep_rw(.RECV, fd, 0, 0, 0);
        sqe.rw_flags = 0;
        sqe.flags |= linux.IOSQE_BUFFER_SELECT;
        sqe.buf_index = RECV_BUF_GROUP_ID;
        sqe.user_data = packUserData(.recv, gen, conn_id);
        self.recv_armed[conn_id] = true;
    }

    /// Re-arm a single-shot recv after a .read event has been
    /// processed by the server. Called by the dispatcher for each
    /// still-alive non-close-mode connection. Close-mode connections
    /// skip the rearm so the kernel can reclaim the fd when
    /// `closeConnection` runs.
    ///
    /// Multishot recv is a correctness footgun in this server because
    /// pipelined data and EOF CQEs can arrive for a connection that
    /// has already been written+closed by an earlier event in the
    /// same poll() batch; single-shot sidesteps the issue by only
    /// having one SQE in flight per connection at a time.
    pub fn rearmRecv(self: *IoUringNativeBackend, conn_id: u32, fd: i32) void {
        if (conn_id >= self.recv_armed.len) return;
        self.armRecv(conn_id, fd) catch {};
    }

    /// Arm a POLL_ADD for POLLOUT on a connection's socket. The
    /// server calls this when a sync `writev(2)` hits EAGAIN mid
    /// response — the socket send buffer filled up and we need the
    /// kernel to tell us when there's room for more. When the CQE
    /// fires, `poll()` emits a .write event for this conn_id so
    /// the server's dispatcher resumes `handleWrite`.
    ///
    /// This is the native analogue of the `io_uring_poll` backend's
    /// POLLOUT re-arm. It's only used for large responses whose
    /// first writev couldn't drain the whole iovec in one shot —
    /// the hot path (small responses, keepalive fast writes) never
    /// hits EAGAIN and so never submits this SQE.
    pub fn armWritable(self: *IoUringNativeBackend, conn_id: u32, fd: i32) !void {
        if (conn_id >= self.generations.len) return error.ConnIdOutOfRange;
        const gen = self.generations[conn_id];
        _ = try self.ring.poll_add(
            packUserData(.poll_writable, gen, conn_id),
            @intCast(fd),
            linux.POLL.OUT,
        );
    }

    /// Submit a send operation for a response. The completion arrives
    /// as a .write event once the kernel has transmitted the data.
    /// `data` must remain valid until the CQE is reaped.
    pub fn submitSend(self: *IoUringNativeBackend, conn_id: u32, fd: i32, data: []const u8) !void {
        if (conn_id >= self.generations.len) return error.ConnIdOutOfRange;
        const gen = self.generations[conn_id];
        const sqe = try self.ring.get_sqe();
        sqe.prep_send(fd, data, 0);
        sqe.user_data = packUserData(.send, gen, conn_id);
    }

    /// Submit a scattered writev for a response. The iovec array MUST
    /// remain valid until the CQE is reaped — the caller typically
    /// parks it on the Connection struct (`conn.async_send_iov`) so
    /// its address stays stable across the kernel's processing window.
    ///
    /// Completion arrives as a .send op CQE; `poll()` translates it to
    /// a .write event whose `data.len` carries `cqe.res` (the actual
    /// bytes written, which may be less than the total requested on a
    /// short write / EAGAIN).
    pub fn submitWritev(
        self: *IoUringNativeBackend,
        conn_id: u32,
        fd: i32,
        iov: []const std.posix.iovec_const,
    ) !void {
        if (conn_id >= self.generations.len) return error.ConnIdOutOfRange;
        const gen = self.generations[conn_id];
        const sqe = try self.ring.get_sqe();
        sqe.prep_writev(fd, iov, 0);
        sqe.user_data = packUserData(.send, gen, conn_id);
    }

    /// Increment the generation counter for a connection slot being
    /// reused. Stale CQEs from the previous incarnation will be
    /// dropped in `poll()`.
    pub fn bumpGeneration(self: *IoUringNativeBackend, conn_id: u32) void {
        if (conn_id >= self.generations.len) return;
        self.generations[conn_id] +%= 1;
        // Slot is being recycled. Any prior multishot recv belongs to
        // the old incarnation; mark it inactive so the next
        // registerConnection arms a fresh one.
        self.recv_armed[conn_id] = false;
    }

    /// Release a recv buffer back to the kernel's provided-buffer
    /// ring. Called by the server after it has copied the data out
    /// of the kernel-owned slab (or fully processed it).
    ///
    /// Non-incremental semantics: each buffer id maps 1:1 to a CQE,
    /// so re-adding the buffer at its original offset makes it
    /// available for the next recv without any head/tail bookkeeping.
    pub fn releaseRecvBuffer(self: *IoUringNativeBackend, buffer_id: u16) void {
        const mask = linux.IoUring.buf_ring_mask(RECV_BUF_COUNT);
        linux.IoUring.buf_ring_add(self.br, self.bufferSlice(buffer_id), buffer_id, mask, 0);
        linux.IoUring.buf_ring_advance(self.br, 1);
    }

    /// Scratch buffer for copying CQEs out of the completion ring.
    /// Reused across poll() calls to avoid per-tick allocation.
    var cqe_batch: [256]linux.io_uring_cqe = undefined;

    /// Blocks until at least one CQE is available (or returns
    /// immediately when `timeout_ms == 0`). Reaps all available CQEs
    /// and translates them into IoUringNativeEvent entries.
    pub fn poll(self: *IoUringNativeBackend, timeout_ms: u32) ![]IoUringNativeEvent {
        var count: usize = 0;

        // ── Step 1: drain the acceptor SPSC queue first ──────────────
        // The acceptor thread is the producer; we are the only
        // consumer. Drain unconditionally on every poll() — under
        // load the reactor's own CQE stream keeps this loop spinning,
        // so new fds get picked up within a single iteration. The
        // eventfd POLL_ADD is only the cold-wake path for when the
        // reactor is idle with nothing else in flight.
        if (self.acceptor) |acc| {
            // Drain the eventfd counter so the next POLL_ADD wakeup
            // fires only on the *next* batch — not on the residue
            // from a previous one. Single read() consumes the entire
            // counter regardless of how many writes the acceptor did.
            var counter: u64 = 0;
            _ = linux.read(acc.eventfd_fd, @ptrCast(&counter), @sizeOf(u64));
            while (count < self.events.len) {
                const fd = acc.queue.pop() orelse break;
                self.events[count] = .{
                    .kind = .accept,
                    .conn_id = 0,
                    .accepted_fd = fd,
                };
                count += 1;
            }
        }

        // ── Step 2: submit pending SQEs and reap CQEs ────────────────
        // Only block if we don't already have accept events from the
        // SPSC drain above. If we do, return immediately so the
        // server can register all of them right away — the next
        // poll() will catch up on any CQEs.
        const wait_nr: u32 = if (count > 0 or timeout_ms == 0) 0 else 1;
        _ = self.ring.submit_and_wait(wait_nr) catch |err| switch (err) {
            error.SignalInterrupt => return self.events[0..count],
            else => return err,
        };
        const ready = self.ring.copy_cqes(&cqe_batch, 0) catch |err| switch (err) {
            error.SignalInterrupt => return self.events[0..count],
            else => return err,
        };

        var i: u32 = 0;
        while (i < ready and count < self.events.len) : (i += 1) {
            const cqe = cqe_batch[i];
            const ud = cqe.user_data;
            const op = unpackOp(ud);
            const gen = unpackGen(ud);
            const conn_id = unpackConnId(ud);

            // Drop stale CQEs from reused conn_id slots.
            if (op == .recv or op == .send or op == .poll_writable) {
                if (conn_id >= self.generations.len or self.generations[conn_id] != gen) {
                    // If the stale CQE carried a buffer, release it so
                    // the kernel doesn't leak provided-buffer slots.
                    if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                        if (cqe.buffer_id()) |bid| {
                            self.releaseRecvBuffer(bid);
                        } else |_| {}
                    }
                    continue;
                }
            }

            switch (op) {
                .accept => {
                    if (self.acceptor) |acc| {
                        // Threaded-acceptor path: the eventfd
                        // POLL_ADD fired because a batch of fds
                        // arrived. The SPSC drain already ran at the
                        // top of poll(); re-arm the wakeup so the
                        // next cold-idle wait can fire and pick up
                        // any stragglers the earlier drain missed.
                        while (count < self.events.len) {
                            const fd = acc.queue.pop() orelse break;
                            self.events[count] = .{
                                .kind = .accept,
                                .conn_id = 0,
                                .accepted_fd = fd,
                            };
                            count += 1;
                        }
                        self.armAcceptorWakeup(acc.eventfd_fd) catch {};
                    } else {
                        // Inline-accept path: POLL_ADD readiness on
                        // the listener itself. The res is a poll
                        // mask; re-arm regardless and emit one
                        // .accept event so the server's handleAccept
                        // drains accept4 in userspace until EAGAIN.
                        if (self.listener_fd) |lfd| {
                            self.armListenerPoll(lfd) catch {};
                        }
                        self.events[count] = .{
                            .kind = .accept,
                            .conn_id = 0,
                            .accepted_fd = null,
                        };
                        count += 1;
                    }
                },
                .recv => {
                    // Single-shot recv: each CQE consumes its SQE.
                    self.recv_armed[conn_id] = false;

                    if (cqe.res <= 0) {
                        // EOF / error. A real CQE may still carry a
                        // buffer id (e.g., a zero-length notification)
                        // — release it if so.
                        if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                            if (cqe.buffer_id()) |bid| {
                                self.releaseRecvBuffer(bid);
                            } else |_| {}
                        }
                        self.events[count] = .{
                            .kind = .err,
                            .conn_id = conn_id,
                        };
                        count += 1;
                        continue;
                    }
                    const buffer_id = cqe.buffer_id() catch {
                        // CQE claimed no buffer — treat as error.
                        self.events[count] = .{
                            .kind = .err,
                            .conn_id = conn_id,
                        };
                        count += 1;
                        continue;
                    };
                    const used: usize = @intCast(cqe.res);
                    const data = self.bufferSlice(buffer_id)[0..used];
                    self.events[count] = .{
                        .kind = .read,
                        .conn_id = conn_id,
                        .data = data,
                        .kernel_buffer_id = buffer_id,
                    };
                    count += 1;
                },
                .send => {
                    // cqe.res < 0 → socket error; cqe.res >= 0 is the
                    // actual number of bytes the kernel wrote. The
                    // caller uses it to advance the write queue.
                    if (cqe.res < 0) {
                        self.events[count] = .{
                            .kind = .err,
                            .conn_id = conn_id,
                        };
                        count += 1;
                        continue;
                    }
                    self.events[count] = .{
                        .kind = .write,
                        .conn_id = conn_id,
                        .bytes_written = @intCast(cqe.res),
                    };
                    count += 1;
                },
                .poll_writable => {
                    // POLL_ADD POLLOUT readiness wake. cqe.res is the
                    // returned poll mask or a negative errno. Either
                    // way we emit a zero-byte .write event so the
                    // dispatcher re-enters handleWrite. bytes_written
                    // is 0 because no bytes actually moved — the
                    // socket just became writable again and the
                    // retry happens in the server.
                    if (cqe.res < 0) {
                        self.events[count] = .{
                            .kind = .err,
                            .conn_id = conn_id,
                        };
                        count += 1;
                        continue;
                    }
                    self.events[count] = .{
                        .kind = .write,
                        .conn_id = conn_id,
                        .bytes_written = 0,
                    };
                    count += 1;
                },
                .recvmsg => {
                    // Multishot recvmsg on the UDP socket (QUIC).
                    // The CQE's provided buffer starts with a
                    // `struct io_uring_recvmsg_out` header, then the
                    // reserved name area (UDP_NAMELEN bytes), then
                    // the packet payload.
                    if (cqe.res < 0) {
                        // A fatal error or a non-fatal EAGAIN — try
                        // to re-arm once. If re-arm itself fails we
                        // fall back to the next poll cycle picking
                        // this up via the UDP fd eventually going
                        // silent; there's no dedicated error event.
                        if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                            if (cqe.buffer_id()) |bid| {
                                self.releaseRecvBuffer(bid);
                            } else |_| {}
                        }
                        if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                            self.armMultishotRecvmsg() catch {};
                        }
                        continue;
                    }
                    const buffer_id = cqe.buffer_id() catch {
                        if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                            self.armMultishotRecvmsg() catch {};
                        }
                        continue;
                    };
                    const total: usize = @intCast(cqe.res);
                    const slab = self.bufferSlice(buffer_id);
                    if (total < @sizeOf(linux.io_uring_recvmsg_out)) {
                        // Malformed CQE — release and re-arm.
                        self.releaseRecvBuffer(buffer_id);
                        if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                            self.armMultishotRecvmsg() catch {};
                        }
                        continue;
                    }
                    const out: *const linux.io_uring_recvmsg_out = @ptrCast(@alignCast(slab.ptr));
                    const name_off: usize = @sizeOf(linux.io_uring_recvmsg_out);
                    const cmsg_off: usize = name_off + UDP_NAMELEN;
                    const payload_off: usize = cmsg_off + self.udp_msghdr.controllen;
                    // Guard against truncation: o.payloadlen may
                    // exceed what fits in the buffer if the peer
                    // sent an oversized datagram. Clamp to what we
                    // actually received.
                    const max_payload = if (payload_off >= total) 0 else total - payload_off;
                    const payload_len = @min(@as(usize, out.payloadlen), max_payload);
                    const namelen = @min(@as(usize, out.namelen), UDP_NAMELEN);
                    var ev: IoUringNativeEvent = .{
                        .kind = .datagram,
                        .conn_id = 0,
                        .data = slab[payload_off .. payload_off + payload_len],
                        .kernel_buffer_id = buffer_id,
                    };
                    @memcpy(ev.datagram_peer[0..namelen], slab[name_off .. name_off + namelen]);
                    ev.datagram_peer_len = @intCast(namelen);
                    self.events[count] = ev;
                    count += 1;
                    // Multishot recvmsg stays armed until F_MORE is
                    // unset. Re-arm if the kernel dropped it (e.g.
                    // ENOBUFS / EINVAL).
                    if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                        self.armMultishotRecvmsg() catch {};
                    }
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
