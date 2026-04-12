const std = @import("std");
const builtin = @import("builtin");

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

        return .{
            .ring = ring,
            .br = br,
            .buffers = buffers,
            .allocator = allocator,
            .events = events,
            .generations = generations,
            .udp_fd = null,
            .udp_msghdr = undefined,
            .udp_iov = undefined,
        };
    }

    pub fn deinit(self: *IoUringNativeBackend, allocator: std.mem.Allocator) void {
        linux.IoUring.free_buf_ring(self.ring.fd, self.br, RECV_BUF_COUNT, RECV_BUF_GROUP_ID);
        allocator.free(self.buffers);
        self.ring.deinit();
        allocator.destroy(self.ring);
        allocator.free(self.events);
        allocator.free(self.generations);
    }

    /// Compute the slice that buffer `id` points at in our slab.
    fn bufferSlice(self: *IoUringNativeBackend, id: u16) []u8 {
        const pos = @as(usize, RECV_BUF_SIZE) * @as(usize, id);
        return self.buffers[pos .. pos + RECV_BUF_SIZE];
    }

    /// Register the TCP listener fd and arm multishot accept. The
    /// accept SQE stays alive for the lifetime of the listener — each
    /// incoming connection produces a CQE without any re-submission.
    pub fn registerListener(self: *IoUringNativeBackend, fd: i32) !void {
        self.listener_fd = fd;
        try self.armMultishotAccept(fd);
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

    fn armMultishotAccept(self: *IoUringNativeBackend, fd: i32) !void {
        // Use stdlib's accept_multishot helper, which calls
        // prep_multishot_accept (correct opcode + IORING_ACCEPT_MULTISHOT flag).
        //
        // Pass SOCK_NONBLOCK | SOCK_CLOEXEC as the accept flags so the
        // kernel hands us back non-blocking, close-on-exec fds without
        // forcing a follow-up fcntl() round trip per accept. That
        // extra syscall was the single biggest overhead vs epoll's
        // accept4(SOCK_NONBLOCK) fast path — and the reason the
        // earlier Connection: close benchmark came in 4x slower
        // than the epoll backend for new-connection-per-request
        // workloads.
        _ = try self.ring.accept_multishot(
            packUserData(.accept, 0, 0),
            @intCast(fd),
            null,
            null,
            linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
        );
    }

    /// Arm a multishot recv on a freshly-accepted connection. Data
    /// arrives via the provided buffer ring and is delivered inline
    /// with each completion event. The multishot SQE stays armed
    /// until the connection closes or errors.
    pub fn registerConnection(self: *IoUringNativeBackend, conn_id: u32, fd: i32) !void {
        if (conn_id >= self.generations.len) return error.ConnIdOutOfRange;
        const gen = self.generations[conn_id];
        const sqe = try self.ring.get_sqe();
        // Equivalent of `prep_recv` + IOSQE_BUFFER_SELECT + multishot
        // (what BufferGroup.recv_multishot does, but without the
        // hardcoded incremental-consumption buffer group).
        sqe.prep_rw(.RECV, fd, 0, 0, 0);
        sqe.rw_flags = 0;
        sqe.flags |= linux.IOSQE_BUFFER_SELECT;
        sqe.buf_index = RECV_BUF_GROUP_ID;
        sqe.ioprio |= linux.IORING_RECV_MULTISHOT;
        sqe.user_data = packUserData(.recv, gen, conn_id);
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
        // submit_and_wait: flushes pending SQEs to the kernel AND
        // (if wait_nr > 0) blocks until at least one CQE is available.
        // copy_cqes alone would not submit pending SQEs — it only
        // drains the CQ ring — so we'd miss the initial multishot
        // accept arm on the first poll cycle.
        const wait_nr: u32 = if (timeout_ms > 0) 1 else 0;
        _ = self.ring.submit_and_wait(wait_nr) catch |err| switch (err) {
            error.SignalInterrupt => return self.events[0..0],
            else => return err,
        };
        const ready = self.ring.copy_cqes(&cqe_batch, 0) catch |err| switch (err) {
            error.SignalInterrupt => return self.events[0..0],
            else => return err,
        };

        var count: usize = 0;
        var i: u32 = 0;
        while (i < ready and count < self.events.len) : (i += 1) {
            const cqe = cqe_batch[i];
            const ud = cqe.user_data;
            const op = unpackOp(ud);
            const gen = unpackGen(ud);
            const conn_id = unpackConnId(ud);

            // Drop stale CQEs from reused conn_id slots.
            if (op == .recv or op == .send) {
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
                        // EOF / error. A real CQE may still carry a
                        // buffer id (e.g., a zero-length "wake up and
                        // close" notification) — release it if so.
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
                    // Multishot recv re-arms itself unless F_MORE is
                    // unset. If it dropped out (ENOBUFS, EINVAL, etc.),
                    // the caller will re-arm via registerConnection on
                    // the next successful accept for this slot.
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
