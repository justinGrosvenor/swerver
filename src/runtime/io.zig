const std = @import("std");
const config = @import("../config.zig");
const buffer_pool = @import("buffer_pool.zig");
const connection = @import("connection.zig");
const clock = @import("clock.zig");
const kqueue_backend = @import("backend/kqueue.zig");
const epoll_backend = @import("backend/epoll.zig");
const io_uring_poll_backend = @import("backend/io_uring_poll.zig");
const io_uring_native_backend = @import("backend/io_uring_native.zig");

pub const IoRuntime = struct {
    allocator: std.mem.Allocator,
    cfg: config.ServerConfig,
    backend: Backend,
    backend_state: BackendState,
    connections: connection.ConnectionPool,
    buffers: buffer_pool.BufferPool,
    /// Dedicated pool for large request body accumulation (uploads).
    /// Larger buffers (1MB default), fewer slots. Keeps uploads from
    /// exhausting the hot-path pool used by request/response buffers.
    body_buffers: buffer_pool.BufferPool,
    events: []Event,
    timer: clock.Timer,

    pub fn init(allocator: std.mem.Allocator, cfg: config.ServerConfig) !IoRuntime {
        const backend = pickBackend(cfg);
        var connections = try connection.ConnectionPool.init(allocator, cfg.max_connections);
        errdefer connections.deinit();
        var buffers = try buffer_pool.BufferPool.init(allocator, cfg.buffer_pool);
        errdefer buffers.deinit();
        var body_buffers = try buffer_pool.BufferPool.init(allocator, .{
            .buffer_size = cfg.buffer_pool.body_buffer_size,
            .buffer_count = cfg.buffer_pool.body_buffer_count,
        });
        errdefer body_buffers.deinit();
        const events = try allocator.alloc(Event, cfg.max_connections);
        errdefer allocator.free(events);
        var backend_state = try initBackend(allocator, backend, cfg.max_connections, cfg.workers != 1);
        errdefer deinitBackend(&backend_state, allocator);
        const timer = try clock.Timer.start();
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .backend = backend,
            .backend_state = backend_state,
            .connections = connections,
            .buffers = buffers,
            .body_buffers = body_buffers,
            .events = events,
            .timer = timer,
        };
    }

    pub fn deinit(self: *IoRuntime) void {
        self.connections.deinit();
        self.buffers.deinit();
        self.body_buffers.deinit();
        deinitBackend(&self.backend_state, self.allocator);
        self.allocator.free(self.events);
    }

    pub fn start(self: *IoRuntime) !void {
        return switch (self.backend_state) {
            .unknown => error.UnsupportedBackend,
            else => {},
        };
    }

    /// Return the capability set for this runtime's backend.
    /// The server uses this to choose between portable readiness
    /// paths and backend-specific fast paths.
    pub fn capabilities(self: *const IoRuntime) Capabilities {
        return switch (self.backend_state) {
            .bsd_kqueue => .{},
            .linux_epoll => .{},
            .linux_io_uring_poll => .{},
            .linux_io_uring_native => .{
                .delivers_read_data = true,
                .multishot_accept = true,
                .zero_copy_buffers = true,
                // Plain-TCP writes are now async via IORING_OP_WRITEV.
                // TLS writes stay sync through `tlsFlushWbio` because
                // the ciphertext drain re-encrypts per call and would
                // need a deeper buffer-backed carry to go async.
                .async_writes = true,
            },
            .windows_iocp, .unknown => .{},
        };
    }

    pub fn poll(self: *IoRuntime) ![]const Event {
        return self.pollWithTimeout(0);
    }

    pub fn pollWithTimeout(self: *IoRuntime, timeout_ms: u32) ![]const Event {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| {
                const kev = try kq.poll(timeout_ms);
                const count = translateKqueueEvents(kev, self.events);
                return self.events[0..count];
            },
            .linux_epoll => |*ep| {
                const epev = try ep.poll(timeout_ms);
                const count = translateEpollEvents(epev, self.events);
                return self.events[0..count];
            },
            .linux_io_uring_poll => |*ur| {
                const urev = try ur.poll(timeout_ms);
                const count = translateIoUringEvents(urev, self.events);
                return self.events[0..count];
            },
            .linux_io_uring_native => |*ur| {
                const nev = try ur.poll(timeout_ms);
                const count = translateIoUringNativeEvents(ur, nev, self.events);
                return self.events[0..count];
            },
            else => {
                if (timeout_ms > 0) {
                    sleepMs(timeout_ms);
                }
                return &[_]Event{};
            },
        };
    }

    pub fn nextPollTimeoutMs(self: *IoRuntime, now_ms: u64) u32 {
        var min_timeout: u32 = 10;
        var has_timeout_pending = false;
        // Iterate only active connections - O(active) instead of O(max)
        for (self.connections.activeConnections()) |index| {
            const conn = &self.connections.entries[index];
            // Skip connections in error/draining state - they're being cleaned up
            if (conn.state == .err or conn.state == .draining or conn.state == .closed) {
                continue;
            }
            const remaining = conn.remainingTimeoutMs(now_ms, self.cfg.timeouts);
            if (remaining == 0) {
                // Connection needs timeout enforcement, but don't busy-poll
                // Just mark that we need a quick check
                has_timeout_pending = true;
                continue;
            }
            if (remaining < min_timeout) min_timeout = remaining;
        }
        // If we have pending timeouts, use a short but non-zero timeout
        // to avoid busy-waiting while still being responsive
        if (has_timeout_pending and min_timeout > 1) {
            min_timeout = 1;
        }
        return min_timeout;
    }

    pub fn nowMs(self: *IoRuntime) u64 {
        return self.timer.read() / @as(u64, std.time.ns_per_ms);
    }

    pub fn acquireConnection(self: *IoRuntime, now_ms: u64) ?*connection.Connection {
        return self.connections.acquire(now_ms);
    }

    pub fn releaseConnection(self: *IoRuntime, conn: *connection.Connection) void {
        // Bump the native backend's per-slot generation counter BEFORE
        // releasing the slot. Any in-flight multishot recv CQEs from
        // this connection's previous incarnation will now carry a
        // stale generation and be dropped in poll(). Without this,
        // stale CQEs leak into the next connection to reuse the slot
        // — which under connection churn silently hands the new
        // connection's handler a read event for the old socket and
        // stalls it waiting for real data that never arrives.
        self.onConnectionReleased(conn.index);
        self.connections.release(conn);
    }

    pub fn getConnection(self: *IoRuntime, index: u32) ?*connection.Connection {
        if (index >= self.connections.entries.len) return null;
        return &self.connections.entries[index];
    }

    pub fn acquireBuffer(self: *IoRuntime) ?buffer_pool.BufferHandle {
        return self.buffers.acquire();
    }

    pub fn releaseBuffer(self: *IoRuntime, handle: buffer_pool.BufferHandle) void {
        self.buffers.release(handle);
    }

    /// Acquire a large buffer from the body pool (for request body
    /// accumulation). Body buffers are separate from the hot-path pool
    /// so large uploads don't exhaust request/response buffers.
    pub fn acquireBodyBuffer(self: *IoRuntime) ?buffer_pool.BufferHandle {
        return self.body_buffers.acquire();
    }

    pub fn releaseBodyBuffer(self: *IoRuntime, handle: buffer_pool.BufferHandle) void {
        self.body_buffers.release(handle);
    }

    pub fn bodyBufferSize(self: *IoRuntime) usize {
        return self.body_buffers.buffer_size;
    }

    pub fn canRead(self: *IoRuntime, conn: *connection.Connection) bool {
        return conn.canRead(self.cfg.backpressure, self.nowMs());
    }

    pub fn canWrite(self: *IoRuntime, conn: *connection.Connection) bool {
        return conn.canWrite(self.cfg.backpressure);
    }

    pub fn onReadBuffered(self: *IoRuntime, conn: *connection.Connection, bytes: usize) void {
        conn.onReadBuffered(bytes, self.cfg.backpressure);
    }

    pub fn onReadConsumed(self: *IoRuntime, conn: *connection.Connection, bytes: usize) void {
        conn.onReadConsumed(bytes, self.cfg.backpressure);
    }

    pub fn onWriteBuffered(self: *IoRuntime, conn: *connection.Connection, bytes: usize) void {
        conn.onWriteBuffered(bytes, self.cfg.backpressure);
    }

    pub fn onWriteCompleted(self: *IoRuntime, conn: *connection.Connection, bytes: usize) void {
        conn.onWriteCompleted(bytes, self.cfg.backpressure);
    }

    pub fn setTimeoutPhase(self: *IoRuntime, conn: *connection.Connection, phase: connection.TimeoutPhase) void {
        _ = self;
        conn.setTimeoutPhase(phase);
    }

    /// Enforce timeouts and return indices of connections that should be closed.
    /// The caller is responsible for closing these connections.
    pub fn enforceTimeouts(self: *IoRuntime, now_ms: u64) TimeoutResult {
        var result = TimeoutResult{};
        // Iterate only active connections - O(active) instead of O(max)
        for (self.connections.activeConnections()) |index| {
            const conn = &self.connections.entries[index];
            // Collect already-errored connections for cleanup
            if (conn.state == .err) {
                if (result.count < result.to_close.len) {
                    result.to_close[result.count] = index;
                    result.count += 1;
                }
                continue;
            }
            if (!conn.isTimedOut(now_ms, conn.timeout_phase, self.cfg.timeouts)) continue;
            const next_state: connection.State = switch (conn.timeout_phase) {
                .idle => .err, // idle timeout means client is inactive — close directly
                .header, .body, .write => .err,
            };
            _ = conn.transition(next_state, now_ms) catch |err| {
                std.log.debug("Timeout transition conn={} to {s} failed: {}", .{ index, @tagName(next_state), err });
            };
            // Mark for closure if transitioned to error
            if (next_state == .err) {
                if (result.count < result.to_close.len) {
                    result.to_close[result.count] = index;
                    result.count += 1;
                }
            }
        }
        return result;
    }

    pub const TimeoutResult = struct {
        to_close: [64]u32 = undefined,
        count: usize = 0,
    };

    pub fn registerListener(self: *IoRuntime, fd: std.posix.fd_t) !void {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.registerListener(fd),
            .linux_epoll => |*ep| ep.registerListener(fd),
            .linux_io_uring_poll => |*ur| ur.registerListener(fd),
            .linux_io_uring_native => |*ur| ur.registerListener(@intCast(fd)),
            else => error.UnsupportedBackend,
        };
    }

    pub fn registerUdpSocket(self: *IoRuntime, fd: std.posix.fd_t) !void {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.registerUdpSocket(fd),
            .linux_epoll => |*ep| ep.registerUdpSocket(fd),
            .linux_io_uring_poll => |*ur| ur.registerUdpSocket(fd),
            // Native backend arms a multishot IORING_OP_RECVMSG SQE
            // on the UDP socket; every packet arrives as a .datagram
            // event with inline data and a sockaddr slice.
            .linux_io_uring_native => |*ur| ur.registerUdpSocket(@intCast(fd)),
            else => error.UnsupportedBackend,
        };
    }

    /// Register a connection with the event loop.
    /// Note: conn_id is offset by 1 internally to avoid collision with listener (udata=0)
    pub fn registerConnection(self: *IoRuntime, conn_id: u64, fd: std.posix.fd_t) !void {
        // Offset by 1 to avoid collision with listener socket (udata=0)
        const offset_id = conn_id + 1;
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.registerConnection(offset_id, fd),
            .linux_epoll => |*ep| ep.registerConnection(offset_id, fd),
            .linux_io_uring_poll => |*ur| ur.registerConnection(offset_id, fd),
            // Native backend uses the raw conn_id (no offset) because
            // its user_data encoding already distinguishes ops and
            // treats conn_id == 0 as valid (accept events use op = .accept).
            .linux_io_uring_native => |*ur| ur.registerConnection(@intCast(conn_id), @intCast(fd)),
            else => error.UnsupportedBackend,
        };
    }

    pub fn unregister(self: *IoRuntime, fd: std.posix.fd_t) !void {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.unregister(fd),
            .linux_epoll => |*ep| ep.unregister(fd),
            .linux_io_uring_poll => |*ur| ur.unregister(fd),
            // Native backend: multishot recv will drop when the fd
            // closes. The connection slot's generation is bumped in
            // releaseConnection() so any in-flight CQEs are dropped.
            .linux_io_uring_native => {},
            else => error.UnsupportedBackend,
        };
    }

    /// Called when a connection slot is being recycled. The native
    /// backend uses this to bump the generation counter so stale CQEs
    /// from the previous incarnation get dropped.
    pub fn onConnectionReleased(self: *IoRuntime, conn_id: u32) void {
        switch (self.backend_state) {
            .linux_io_uring_native => |*ur| ur.bumpGeneration(conn_id),
            else => {},
        }
    }

    /// Submit an async writev for plaintext TCP responses. Only valid
    /// when `capabilities().async_writes` is true. The iovec slice
    /// MUST live until the CQE is reaped — callers typically park it
    /// on the Connection struct so its address stays stable.
    pub fn submitAsyncWritev(
        self: *IoRuntime,
        conn_id: u32,
        fd: std.posix.fd_t,
        iov: []const std.posix.iovec_const,
    ) !void {
        return switch (self.backend_state) {
            .linux_io_uring_native => |*ur| ur.submitWritev(conn_id, @intCast(fd), iov),
            else => error.UnsupportedBackend,
        };
    }
};

pub const Backend = enum {
    linux_io_uring_native,
    linux_io_uring_poll,
    linux_epoll,
    bsd_kqueue,
    windows_iocp,
    unknown,
};

/// Optional reference to a kernel-managed buffer that must be released
/// after the event has been fully processed. Used by completion-model
/// backends (io_uring native with buffer groups) to deliver zero-copy
/// reads. Readiness backends (epoll, kqueue, io_uring poll) leave this
/// null and the server does its own read().
pub const KernelBufferRef = struct {
    ctx: *anyopaque,
    release_fn: *const fn (ctx: *anyopaque, buffer_id: u16) void,
    buffer_id: u16,

    pub fn release(self: KernelBufferRef) void {
        self.release_fn(self.ctx, self.buffer_id);
    }
};

pub const Event = struct {
    kind: EventKind,
    conn_id: u64,
    bytes: usize,
    handle: ?std.posix.fd_t,
    /// Optional inline data payload. Set by completion-model backends
    /// that deliver reads via kernel-filled buffers. Readiness backends
    /// leave this null — the server calls connRead() to fetch the data.
    data: ?[]const u8 = null,
    /// Optional kernel buffer token. When non-null, the server MUST
    /// call `.release()` on this once it has copied or fully consumed
    /// the event's data (the kernel owns the memory until then).
    kernel_buffer: ?KernelBufferRef = null,
    /// For `.datagram` events on completion-model backends: raw bytes
    /// of the peer's sockaddr_in / sockaddr_in6 (length in
    /// `datagram_peer_len`). The server reinterprets these into its
    /// own `SockAddrStorage` union in `handleDatagram`.
    datagram_peer: [28]u8 = undefined,
    datagram_peer_len: u8 = 0,
};

pub const EventKind = enum {
    accept,
    read,
    write,
    err,
    datagram,
};

/// Capability flags describing what a backend can do. The server
/// branches on these when choosing between specialized fast paths
/// (e.g., native-io_uring direct-from-kernel reads) and the common
/// portable paths (readiness + explicit read).
pub const Capabilities = struct {
    /// True if the backend delivers read data inline with the event.
    /// The server should use event.data instead of calling connRead().
    delivers_read_data: bool = false,
    /// True if the backend keeps the accept op armed after each event
    /// (no manual re-arm needed).
    multishot_accept: bool = false,
    /// True if the backend uses kernel-managed buffer groups for reads
    /// (zero-copy path, requires event.kernel_buffer to be released).
    zero_copy_buffers: bool = false,
    /// True if writes are submitted asynchronously and completion is
    /// signaled via a later .write event (vs sync writev in handleWrite).
    async_writes: bool = false,
};

/// Magic identifier for UDP socket events to distinguish from TCP listener (0) and connections
pub const UDP_SOCKET_ID: u64 = std.math.maxInt(u64) - 1;

fn pickBackend(_: config.ServerConfig) Backend {
    // Diagnostic override: SWERVER_BACKEND=epoll|poll|native forces
    // the backend regardless of auto-detection. Intended for A/B
    // benchmarking and debugging — production should leave it unset
    // so the picker's capability-based auto-detection chooses the
    // best available backend for the current OS + kernel + config.
    if (std.c.getenv("SWERVER_BACKEND")) |forced_ptr| {
        const forced = std.mem.span(forced_ptr);
        if (std.mem.eql(u8, forced, "epoll")) return .linux_epoll;
        if (std.mem.eql(u8, forced, "poll")) return .linux_io_uring_poll;
        if (std.mem.eql(u8, forced, "kqueue")) return .bsd_kqueue;
        // "native" or anything else → fall through to auto-pick.
    }
    return switch (@import("builtin").os.tag) {
        .linux => blk: {
            // Prefer the native io_uring backend (multishot accept +
            // recv over a provided buffer ring). Requires kernel 6.1+
            // for SINGLE_ISSUER | DEFER_TASKRUN.
            //
            // Native backend handles TCP (multishot accept + recv),
            // TLS (memory BIOs fed from `seedReadBuffer`), and UDP
            // (multishot recvmsg for QUIC). Pick it whenever the
            // kernel supports SINGLE_ISSUER | DEFER_TASKRUN.
            if (io_uring_native_backend.probe()) {
                break :blk .linux_io_uring_native;
            }
            // Older kernels that still support io_uring fall back to
            // the POLL_ADD emulation backend.
            if (io_uring_poll_backend.probeIoUring()) break :blk .linux_io_uring_poll;
            break :blk .linux_epoll;
        },
        .macos, .freebsd, .netbsd, .openbsd, .dragonfly => .bsd_kqueue,
        .windows => .windows_iocp,
        else => .unknown,
    };
}

pub const BackendState = union(Backend) {
    linux_io_uring_native: io_uring_native_backend.IoUringNativeBackend,
    linux_io_uring_poll: io_uring_poll_backend.IoUringPollBackend,
    linux_epoll: epoll_backend.EpollBackend,
    bsd_kqueue: kqueue_backend.KqueueBackend,
    windows_iocp: void,
    unknown: void,
};

fn initBackend(allocator: std.mem.Allocator, backend: Backend, max_events: usize, multi_worker: bool) !BackendState {
    return switch (backend) {
        .bsd_kqueue => .{ .bsd_kqueue = try kqueue_backend.KqueueBackend.init(allocator, max_events) },
        .linux_epoll => .{ .linux_epoll = try epoll_backend.EpollBackend.init(allocator, max_events) },
        .linux_io_uring_poll => .{ .linux_io_uring_poll = try io_uring_poll_backend.IoUringPollBackend.init(allocator, max_events, multi_worker) },
        .linux_io_uring_native => .{ .linux_io_uring_native = try io_uring_native_backend.IoUringNativeBackend.init(allocator, max_events) },
        .windows_iocp => .{ .windows_iocp = {} },
        .unknown => .{ .unknown = {} },
    };
}

fn deinitBackend(state: *BackendState, allocator: std.mem.Allocator) void {
    switch (state.*) {
        .bsd_kqueue => |*kq| kq.deinit(allocator),
        .linux_epoll => |*ep| ep.deinit(allocator),
        .linux_io_uring_poll => |*ur| ur.deinit(allocator),
        .linux_io_uring_native => |*ur| ur.deinit(allocator),
        else => {},
    }
}

fn translateKqueueEvents(events: []const kqueue_backend.Kevent, out: []Event) usize {
    var count: usize = 0;
    for (events) |ev| {
        if (count >= out.len) break;
        if ((ev.flags & kqueue_backend.EV_ERROR) != 0) {
            // Determine conn_id: listener=0, UDP=special, connections are offset by 1
            const conn_id: u64 = if (ev.udata == 0)
                0 // Listener error
            else if (ev.udata == std.math.maxInt(usize) - 1)
                UDP_SOCKET_ID // UDP error
            else
                @intCast(ev.udata - 1); // Connection error (subtract offset)
            out[count] = .{
                .kind = .err,
                .conn_id = conn_id,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
            continue;
        }
        // Handle negative ev.data (error condition) - treat as error event
        if (ev.data < 0) {
            const conn_id: u64 = if (ev.udata == 0)
                0
            else if (ev.udata == std.math.maxInt(usize) - 1)
                UDP_SOCKET_ID
            else
                @intCast(ev.udata - 1);
            out[count] = .{
                .kind = .err,
                .conn_id = conn_id,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
            continue;
        }
        const bytes: usize = @intCast(ev.data);
        if (ev.filter == kqueue_backend.EVFILT_READ) {
            if (ev.udata == 0) {
                // TCP listener socket
                out[count] = .{
                    .kind = .accept,
                    .conn_id = 0,
                    .bytes = 0,
                    .handle = @intCast(ev.ident),
                };
            } else if (ev.udata == std.math.maxInt(usize) - 1) {
                // UDP socket - datagram ready
                out[count] = .{
                    .kind = .datagram,
                    .conn_id = UDP_SOCKET_ID,
                    .bytes = bytes,
                    .handle = @intCast(ev.ident),
                };
            } else {
                // Connection read event - subtract 1 to reverse the offset
                out[count] = .{
                    .kind = .read,
                    .conn_id = @intCast(ev.udata - 1),
                    .bytes = bytes,
                    .handle = null,
                };
            }
            count += 1;
            continue;
        }
        if (ev.filter == kqueue_backend.EVFILT_WRITE) {
            // Write events are always for connections - subtract 1 to reverse offset
            out[count] = .{
                .kind = .write,
                .conn_id = @intCast(ev.udata - 1),
                .bytes = bytes,
                .handle = null,
            };
            count += 1;
            continue;
        }
    }
    return count;
}

fn translateEpollEvents(events: []const epoll_backend.EpollEvent, out: []Event) usize {
    var count: usize = 0;
    for (events) |ev| {
        if (count >= out.len) break;
        const raw_id = ev.data.u64;

        // Check for error conditions
        if ((ev.events & epoll_backend.EPOLLERR) != 0 or (ev.events & epoll_backend.EPOLLHUP) != 0) {
            // Determine conn_id: listener=0, UDP=special, connections are offset by 1
            const conn_id: u64 = if (raw_id == 0)
                0 // Listener error
            else if (raw_id == UDP_SOCKET_ID)
                UDP_SOCKET_ID // UDP error
            else
                raw_id - 1; // Connection error (subtract offset)
            out[count] = .{
                .kind = .err,
                .conn_id = conn_id,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
            continue;
        }

        // Handle read events (including accept on listener where raw_id == 0)
        if ((ev.events & epoll_backend.EPOLLIN) != 0) {
            if (raw_id == 0) {
                // TCP listener socket
                // For epoll, we stored raw_id=0 for listener, but we need the fd
                // The server will use its stored listener_fd
                out[count] = .{
                    .kind = .accept,
                    .conn_id = 0,
                    .bytes = 0,
                    .handle = null, // Server uses its listener_fd
                };
            } else if (raw_id == UDP_SOCKET_ID) {
                // UDP socket - datagram ready
                out[count] = .{
                    .kind = .datagram,
                    .conn_id = UDP_SOCKET_ID,
                    .bytes = 0, // epoll doesn't provide bytes available
                    .handle = null, // Server uses its udp_fd
                };
            } else {
                // Connection read event - subtract 1 to reverse the offset
                out[count] = .{
                    .kind = .read,
                    .conn_id = raw_id - 1,
                    .bytes = 0, // epoll doesn't provide bytes available
                    .handle = null,
                };
            }
            count += 1;
            // Don't continue - check for write too (edge-triggered)
        }

        // Handle write events
        if ((ev.events & epoll_backend.EPOLLOUT) != 0 and raw_id != 0) {
            if (count >= out.len) break;
            // Write events are always for connections - subtract 1 to reverse offset
            out[count] = .{
                .kind = .write,
                .conn_id = raw_id - 1,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
        }
    }
    return count;
}

fn translateIoUringEvents(events: []const io_uring_poll_backend.IoUringEvent, out: []Event) usize {
    var count: usize = 0;
    for (events) |ev| {
        if (count >= out.len) break;
        const raw_id = ev.data.u64;

        // Check for error conditions
        if ((ev.events & 0x008) != 0 or (ev.events & 0x010) != 0) { // POLLERR | POLLHUP
            const conn_id: u64 = if (raw_id == 0)
                0
            else if (raw_id == UDP_SOCKET_ID)
                UDP_SOCKET_ID
            else
                raw_id - 1;
            out[count] = .{
                .kind = .err,
                .conn_id = conn_id,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
            continue;
        }

        // Handle read events (POLLIN)
        if ((ev.events & 0x001) != 0) {
            if (raw_id == 0) {
                out[count] = .{
                    .kind = .accept,
                    .conn_id = 0,
                    .bytes = 0,
                    .handle = null,
                };
            } else if (raw_id == UDP_SOCKET_ID) {
                out[count] = .{
                    .kind = .datagram,
                    .conn_id = UDP_SOCKET_ID,
                    .bytes = 0,
                    .handle = null,
                };
            } else {
                out[count] = .{
                    .kind = .read,
                    .conn_id = raw_id - 1,
                    .bytes = 0,
                    .handle = null,
                };
            }
            count += 1;
        }

        // Handle write events (POLLOUT)
        if ((ev.events & 0x004) != 0 and raw_id != 0) {
            if (count >= out.len) break;
            out[count] = .{
                .kind = .write,
                .conn_id = raw_id - 1,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
        }
    }
    return count;
}

/// Release callback for KernelBufferRef from the native io_uring backend.
/// The `ctx` argument is a type-erased pointer to the IoUringNativeBackend.
fn releaseNativeRecvBuffer(ctx: *anyopaque, buffer_id: u16) void {
    const backend: *io_uring_native_backend.IoUringNativeBackend = @ptrCast(@alignCast(ctx));
    backend.releaseRecvBuffer(buffer_id);
}

fn translateIoUringNativeEvents(
    backend: *io_uring_native_backend.IoUringNativeBackend,
    events: []const io_uring_native_backend.IoUringNativeEvent,
    out: []Event,
) usize {
    var count: usize = 0;
    for (events) |ev| {
        if (count >= out.len) break;
        switch (ev.kind) {
            .accept => {
                out[count] = .{
                    .kind = .accept,
                    .conn_id = 0,
                    .bytes = 0,
                    // The multishot accept CQE hands us the new client fd
                    // directly — stash it in .handle so handleAccept can
                    // skip the accept() syscall.
                    .handle = ev.accepted_fd,
                };
                count += 1;
            },
            .read => {
                // The kernel has already filled a buffer for us. Pass
                // the slice inline and the buffer_id token so the
                // server can return the buffer when it's done.
                const kref: ?KernelBufferRef = if (ev.kernel_buffer_id) |bid| .{
                    .ctx = @ptrCast(backend),
                    .release_fn = releaseNativeRecvBuffer,
                    .buffer_id = bid,
                } else null;
                out[count] = .{
                    .kind = .read,
                    .conn_id = ev.conn_id,
                    .bytes = if (ev.data) |d| d.len else 0,
                    .handle = null,
                    .data = ev.data,
                    .kernel_buffer = kref,
                };
                count += 1;
            },
            .write => {
                // Native async writev: `bytes_written` is `cqe.res`,
                // i.e. the actual bytes the kernel sent (may be less
                // than the submitted iovec total on a short write).
                // The server uses it to advance the write queue.
                out[count] = .{
                    .kind = .write,
                    .conn_id = ev.conn_id,
                    .bytes = ev.bytes_written,
                    .handle = null,
                };
                count += 1;
            },
            .err => {
                out[count] = .{
                    .kind = .err,
                    .conn_id = ev.conn_id,
                    .bytes = 0,
                    .handle = null,
                };
                count += 1;
            },
            .datagram => {
                // Kernel already filled a provided buffer with the
                // io_uring_recvmsg_out header + peer sockaddr + QUIC
                // packet payload. The native backend's translate step
                // parsed the header and set `data` to the payload
                // slice; we pass that through plus the raw sockaddr
                // bytes so handleDatagram can feed the QUIC stack
                // without any recvfrom call.
                const kref: ?KernelBufferRef = if (ev.kernel_buffer_id) |bid| .{
                    .ctx = @ptrCast(backend),
                    .release_fn = releaseNativeRecvBuffer,
                    .buffer_id = bid,
                } else null;
                var e: Event = .{
                    .kind = .datagram,
                    .conn_id = UDP_SOCKET_ID,
                    .bytes = if (ev.data) |d| d.len else 0,
                    .handle = null,
                    .data = ev.data,
                    .kernel_buffer = kref,
                };
                e.datagram_peer_len = ev.datagram_peer_len;
                @memcpy(e.datagram_peer[0..ev.datagram_peer_len], ev.datagram_peer[0..ev.datagram_peer_len]);
                out[count] = e;
                count += 1;
            },
        }
    }
    return count;
}

fn sleepMs(timeout_ms: u32) void {
    const ts = std.posix.timespec{
        .sec = @intCast(timeout_ms / 1000),
        .nsec = @intCast((timeout_ms % 1000) * std.time.ns_per_ms),
    };
    while (true) {
        const rc = std.posix.system.nanosleep(&ts, null);
        if (rc == 0) return;
        switch (std.posix.errno(rc)) {
            .INTR => continue,
            else => return,
        }
    }
}
