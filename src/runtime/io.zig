const std = @import("std");
const config = @import("../config.zig");
const buffer_pool = @import("buffer_pool.zig");
const connection = @import("connection.zig");
const kqueue_backend = @import("backend/kqueue.zig");
const epoll_backend = @import("backend/epoll.zig");

pub const IoRuntime = struct {
    allocator: std.mem.Allocator,
    cfg: config.ServerConfig,
    backend: Backend,
    backend_state: BackendState,
    connections: connection.ConnectionPool,
    buffers: buffer_pool.BufferPool,
    events: []Event,
    timer: std.time.Timer,

    pub fn init(allocator: std.mem.Allocator, cfg: config.ServerConfig) !IoRuntime {
        const backend = pickBackend();
        const connections = try connection.ConnectionPool.init(allocator, cfg.max_connections);
        const buffers = try buffer_pool.BufferPool.init(allocator, cfg.buffer_pool);
        const events = try allocator.alloc(Event, cfg.max_connections);
        const backend_state = try initBackend(allocator, backend, cfg.max_connections);
        const timer = try std.time.Timer.start();
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .backend = backend,
            .backend_state = backend_state,
            .connections = connections,
            .buffers = buffers,
            .events = events,
            .timer = timer,
        };
    }

    pub fn deinit(self: *IoRuntime) void {
        self.connections.deinit();
        self.buffers.deinit();
        deinitBackend(&self.backend_state, self.allocator);
        self.allocator.free(self.events);
    }

    pub fn start(self: *IoRuntime) !void {
        return switch (self.backend_state) {
            .unknown => error.UnsupportedBackend,
            else => {},
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
        // Iterate only active connections - O(active) instead of O(max)
        for (self.connections.activeConnections()) |index| {
            const conn = &self.connections.entries[index];
            const remaining = conn.remainingTimeoutMs(now_ms, self.cfg.timeouts);
            if (remaining == 0) return 0;
            if (remaining < min_timeout) min_timeout = remaining;
        }
        return min_timeout;
    }

    pub fn nowMs(self: *IoRuntime) u64 {
        return self.timer.read() / std.time.ns_per_ms;
    }

    pub fn acquireConnection(self: *IoRuntime, now_ms: u64) ?*connection.Connection {
        return self.connections.acquire(now_ms);
    }

    pub fn releaseConnection(self: *IoRuntime, conn: *connection.Connection) void {
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

    pub fn canRead(self: *IoRuntime, conn: *connection.Connection) bool {
        return conn.canRead(self.cfg.backpressure);
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

    pub fn enforceTimeouts(self: *IoRuntime, now_ms: u64) void {
        // Iterate only active connections - O(active) instead of O(max)
        for (self.connections.activeConnections()) |index| {
            const conn = &self.connections.entries[index];
            if (conn.state == .err) continue;
            if (!conn.isTimedOut(now_ms, conn.timeout_phase, self.cfg.timeouts)) continue;
            const next_state: connection.State = switch (conn.timeout_phase) {
                .idle => .draining,
                .header, .body, .write => .err,
            };
            _ = conn.transition(next_state, now_ms) catch {};
        }
    }

    pub fn registerListener(self: *IoRuntime, fd: std.posix.fd_t) !void {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.registerListener(fd),
            .linux_epoll => |*ep| ep.registerListener(fd),
            else => error.UnsupportedBackend,
        };
    }

    pub fn registerUdpSocket(self: *IoRuntime, fd: std.posix.fd_t) !void {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.registerUdpSocket(fd),
            .linux_epoll => |*ep| ep.registerUdpSocket(fd),
            else => error.UnsupportedBackend,
        };
    }

    pub fn registerConnection(self: *IoRuntime, conn_id: u64, fd: std.posix.fd_t) !void {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.registerConnection(conn_id, fd),
            .linux_epoll => |*ep| ep.registerConnection(conn_id, fd),
            else => error.UnsupportedBackend,
        };
    }

    pub fn unregister(self: *IoRuntime, fd: std.posix.fd_t) !void {
        return switch (self.backend_state) {
            .bsd_kqueue => |*kq| kq.unregister(fd),
            .linux_epoll => |*ep| ep.unregister(fd),
            else => error.UnsupportedBackend,
        };
    }
};

pub const Backend = enum {
    linux_io_uring,
    linux_epoll,
    bsd_kqueue,
    windows_iocp,
    unknown,
};

pub const Event = struct {
    kind: EventKind,
    conn_id: u64,
    bytes: usize,
    handle: ?std.posix.fd_t,
};

pub const EventKind = enum {
    accept,
    read,
    write,
    err,
    datagram,
};

/// Magic identifier for UDP socket events to distinguish from TCP listener (0) and connections
pub const UDP_SOCKET_ID: u64 = std.math.maxInt(u64) - 1;

fn pickBackend() Backend {
    return switch (@import("builtin").os.tag) {
        .linux => .linux_epoll,
        .macos, .freebsd, .netbsd, .openbsd, .dragonfly => .bsd_kqueue,
        .windows => .windows_iocp,
        else => .unknown,
    };
}

pub const BackendState = union(Backend) {
    linux_io_uring: void,
    linux_epoll: epoll_backend.EpollBackend,
    bsd_kqueue: kqueue_backend.KqueueBackend,
    windows_iocp: void,
    unknown: void,
};

fn initBackend(allocator: std.mem.Allocator, backend: Backend, max_events: usize) !BackendState {
    return switch (backend) {
        .bsd_kqueue => .{ .bsd_kqueue = try kqueue_backend.KqueueBackend.init(allocator, max_events) },
        .linux_epoll => .{ .linux_epoll = try epoll_backend.EpollBackend.init(allocator, max_events) },
        .linux_io_uring => .{ .linux_io_uring = {} },
        .windows_iocp => .{ .windows_iocp = {} },
        .unknown => .{ .unknown = {} },
    };
}

fn deinitBackend(state: *BackendState, allocator: std.mem.Allocator) void {
    switch (state.*) {
        .bsd_kqueue => |*kq| kq.deinit(allocator),
        .linux_epoll => |*ep| ep.deinit(allocator),
        else => {},
    }
}

fn translateKqueueEvents(events: []const kqueue_backend.Kevent, out: []Event) usize {
    var count: usize = 0;
    for (events) |ev| {
        if (count >= out.len) break;
        if ((ev.flags & kqueue_backend.EV_ERROR) != 0) {
            out[count] = .{
                .kind = .err,
                .conn_id = @intCast(ev.udata),
                .bytes = 0,
                .handle = null,
            };
            count += 1;
            continue;
        }
        // Handle negative ev.data (error condition) - treat as error event
        if (ev.data < 0) {
            out[count] = .{
                .kind = .err,
                .conn_id = @intCast(ev.udata),
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
                // Connection read event
                out[count] = .{
                    .kind = .read,
                    .conn_id = @intCast(ev.udata),
                    .bytes = bytes,
                    .handle = null,
                };
            }
            count += 1;
            continue;
        }
        if (ev.filter == kqueue_backend.EVFILT_WRITE) {
            out[count] = .{
                .kind = .write,
                .conn_id = @intCast(ev.udata),
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
        const conn_id = ev.data.u64;

        // Check for error conditions
        if ((ev.events & epoll_backend.EPOLLERR) != 0 or (ev.events & epoll_backend.EPOLLHUP) != 0) {
            out[count] = .{
                .kind = .err,
                .conn_id = conn_id,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
            continue;
        }

        // Handle read events (including accept on listener where conn_id == 0)
        if ((ev.events & epoll_backend.EPOLLIN) != 0) {
            if (conn_id == 0) {
                // TCP listener socket
                // For epoll, we stored conn_id=0 for listener, but we need the fd
                // The server will use its stored listener_fd
                out[count] = .{
                    .kind = .accept,
                    .conn_id = 0,
                    .bytes = 0,
                    .handle = null, // Server uses its listener_fd
                };
            } else if (conn_id == UDP_SOCKET_ID) {
                // UDP socket - datagram ready
                out[count] = .{
                    .kind = .datagram,
                    .conn_id = UDP_SOCKET_ID,
                    .bytes = 0, // epoll doesn't provide bytes available
                    .handle = null, // Server uses its udp_fd
                };
            } else {
                // Connection read event
                out[count] = .{
                    .kind = .read,
                    .conn_id = conn_id,
                    .bytes = 0, // epoll doesn't provide bytes available
                    .handle = null,
                };
            }
            count += 1;
            // Don't continue - check for write too (edge-triggered)
        }

        // Handle write events
        if ((ev.events & epoll_backend.EPOLLOUT) != 0 and conn_id != 0) {
            if (count >= out.len) break;
            out[count] = .{
                .kind = .write,
                .conn_id = conn_id,
                .bytes = 0,
                .handle = null,
            };
            count += 1;
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
