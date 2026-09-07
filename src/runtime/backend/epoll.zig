const std = @import("std");
const builtin = @import("builtin");

const is_linux = builtin.os.tag == .linux;
const linux = std.os.linux;

// Use Linux epoll_event type on Linux, stub on other platforms
pub const EpollEvent = if (is_linux) linux.epoll_event else extern struct {
    events: u32,
    data: extern union { ptr: usize, fd: i32, u32_val: u32, u64: u64 } align(1),
};

// Epoll constants
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLET: u32 = 0x80000000;

// data.u64 marker for the cross-thread wake pipe. Distinct from the listener
// (0), the UDP socket (maxInt - 1), and any connection id (conn_id + 1).
pub const WAKE_ID: u64 = std.math.maxInt(u64);

pub const EpollBackend = struct {
    epfd: i32,
    events: []EpollEvent,
    // Self-pipe for cross-thread wake (registerWake). Any thread writes a byte
    // to wake_w to nudge the loop; the read end is registered with WAKE_ID.
    wake_r: i32 = -1,
    wake_w: i32 = -1,

    pub fn init(allocator: std.mem.Allocator, max_events: usize) !EpollBackend {
        if (!is_linux) return error.Unsupported;

        const events = try allocator.alloc(EpollEvent, max_events);
        errdefer allocator.free(events);

        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        const epfd = unwrapSyscallI32(rc) catch return error.EpollCreateFailed;

        return .{
            .epfd = epfd,
            .events = events,
        };
    }

    pub fn deinit(self: *EpollBackend, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        if (is_linux) {
            if (self.wake_r >= 0) _ = linux.close(@intCast(self.wake_r));
            if (self.wake_w >= 0) _ = linux.close(@intCast(self.wake_w));
            _ = linux.close(@intCast(self.epfd));
        }
    }

    /// Cross-thread wake: a self-pipe whose read end is registered with the
    /// epoll set under WAKE_ID. Embedders (libswerver/FFI) call wake() from the
    /// host thread to nudge the reactor when a completion is enqueued. Idempotent.
    pub fn registerWake(self: *EpollBackend) !void {
        if (!is_linux) return error.Unsupported;
        if (self.wake_r >= 0) return; // already set up
        var fds: [2]c_int = undefined;
        if (std.c.pipe(&fds) != 0) return error.PipeFailed;
        const nonblock: c_int = 1 << @bitOffsetOf(std.posix.O, "NONBLOCK");
        for (fds) |fd| {
            _ = std.c.fcntl(fd, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));
            const fl = std.c.fcntl(fd, std.posix.F.GETFL);
            _ = std.c.fcntl(fd, std.posix.F.SETFL, fl | nonblock);
        }
        self.wake_r = fds[0];
        self.wake_w = fds[1];
        var ev = EpollEvent{ .events = EPOLLIN, .data = .{ .u64 = WAKE_ID } };
        const rc = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, self.wake_r, &ev);
        _ = unwrapSyscall(rc) catch return error.EpollCtlFailed;
    }

    /// Signal the loop from any thread. No-op if registerWake was not called.
    pub fn wake(self: *const EpollBackend) void {
        if (self.wake_w < 0) return;
        const byte = [_]u8{1};
        _ = std.c.write(self.wake_w, &byte, 1);
    }

    /// Drain the wake pipe after handling a wake event.
    pub fn drainWake(self: *const EpollBackend) void {
        if (self.wake_r < 0) return;
        var buf: [64]u8 = undefined;
        // Nonblocking read: EAGAIN (n < 0) or EOF (n == 0) ends the drain.
        while (std.c.read(self.wake_r, &buf, buf.len) > 0) {}
    }

    pub fn poll(self: *EpollBackend, timeout_ms: u32) ![]EpollEvent {
        if (!is_linux) return error.Unsupported;

        const timeout: i32 = if (timeout_ms > std.math.maxInt(i32))
            std.math.maxInt(i32)
        else
            @intCast(timeout_ms);

        const rc = linux.epoll_wait(self.epfd, self.events.ptr, @intCast(self.events.len), timeout);
        const count = unwrapSyscall(rc) catch |err| {
            if (err == error.INTR) return self.events[0..0];
            return error.EpollWaitFailed;
        };

        return self.events[0..count];
    }

    pub fn registerListener(self: *EpollBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        var ev = EpollEvent{
            .events = EPOLLIN,
            .data = .{ .u64 = 0 }, // conn_id 0 indicates listener
        };
        const rc = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, fd, &ev);
        _ = unwrapSyscall(rc) catch return error.EpollCtlFailed;
    }

    /// Register a UDP socket for read events.
    /// Uses a special data value to distinguish from TCP listener.
    pub fn registerUdpSocket(self: *EpollBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        var ev = EpollEvent{
            .events = EPOLLIN,
            // Use max u64 - 1 as magic value for UDP socket to distinguish from TCP listener (0)
            .data = .{ .u64 = std.math.maxInt(u64) - 1 },
        };
        const rc = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, fd, &ev);
        _ = unwrapSyscall(rc) catch return error.EpollCtlFailed;
    }

    pub fn registerConnection(self: *EpollBackend, conn_id: u64, fd: std.posix.fd_t) !void {
        if (!is_linux) return error.Unsupported;
        var ev = EpollEvent{
            .events = EPOLLIN | EPOLLOUT | EPOLLET,
            .data = .{ .u64 = conn_id },
        };
        const rc = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, fd, &ev);
        _ = unwrapSyscall(rc) catch return error.EpollCtlFailed;
    }

    pub fn unregister(self: *EpollBackend, fd: std.posix.fd_t) !void {
        if (!is_linux) return;
        // For EPOLL_CTL_DEL, the event parameter is ignored since Linux 2.6.9
        _ = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_DEL, fd, null);
    }
};

// Helper to convert Linux syscall return to i32 result
fn unwrapSyscallI32(rc: usize) error{SyscallFailed}!i32 {
    if (is_linux) {
        const signed: isize = @bitCast(rc);
        if (signed < 0) return error.SyscallFailed;
        return @intCast(signed);
    }
    return 0;
}

// Helper to convert Linux syscall return to usize result
fn unwrapSyscall(rc: usize) error{ INTR, SyscallFailed }!usize {
    if (is_linux) {
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            const errno: u16 = @intCast(-signed);
            if (errno == 4) return error.INTR; // EINTR = 4
            return error.SyscallFailed;
        }
        return rc;
    }
    return 0;
}
