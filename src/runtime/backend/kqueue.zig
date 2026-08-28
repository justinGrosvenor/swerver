const std = @import("std");
const builtin = @import("builtin");
const clock = @import("../clock.zig");

// BSD/Darwin kqueue constants for a minimal backend implementation.
pub const EV_ADD: u16 = 0x0001;
pub const EV_DELETE: u16 = 0x0002;
pub const EV_ENABLE: u16 = 0x0004;
pub const EV_ONESHOT: u16 = 0x0010;
pub const EV_ERROR: u16 = 0x4000;
pub const EVFILT_READ: i16 = -1;
pub const EVFILT_WRITE: i16 = -2;

/// udata token for the cross-thread wake pipe. Distinct from the listener (0)
/// and UDP (maxInt-1) magic values and from any connection id, so dispatch can
/// recognize a wake event. See registerWake().
pub const WAKE_TOKEN: usize = std.math.maxInt(usize) - 2;

const is_supported = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

// Use std.posix.Kevent on BSD, stub type on other platforms
pub const Kevent = if (is_supported) std.posix.Kevent else extern struct {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: usize,
};

pub const KqueueBackend = struct {
    kq: std.posix.fd_t,
    events: []Kevent,
    // Self-pipe for cross-thread wake. -1 until registerWake() is called. The
    // write end is signalled (a single byte) by another thread to make a
    // blocked poll() return promptly; the read end is drained on wake.
    wake_r: std.posix.fd_t = -1,
    wake_w: std.posix.fd_t = -1,

    pub fn init(allocator: std.mem.Allocator, max_events: usize) !KqueueBackend {
        if (!is_supported) return error.Unsupported;
        const kq = std.posix.system.kqueue();
        if (kq < 0) return error.KqueueFailed;
        _ = std.c.fcntl(kq, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));
        const events = try allocator.alloc(Kevent, max_events);
        return .{
            .kq = kq,
            .events = events,
        };
    }

    pub fn deinit(self: *KqueueBackend, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        if (self.wake_r >= 0) clock.closeFd(self.wake_r);
        if (self.wake_w >= 0) clock.closeFd(self.wake_w);
        clock.closeFd(self.kq);
    }

    /// Create the wake self-pipe and register its read end. Idempotent-safe to
    /// call once during setup. After this, wake() (from any thread) makes a
    /// blocked poll() return a Kevent tagged WAKE_TOKEN.
    pub fn registerWake(self: *KqueueBackend) !void {
        if (!is_supported) return error.Unsupported;
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
        try self.registerEvent(self.wake_r, EVFILT_READ, WAKE_TOKEN);
    }

    /// Signal the loop. Safe to call from any thread. A full pipe means a wake
    /// is already pending, which is exactly the desired coalescing, so EAGAIN
    /// is ignored along with any other error (a lost wake is never worse than
    /// no wake mechanism at all).
    pub fn wake(self: *const KqueueBackend) void {
        if (self.wake_w < 0) return;
        const byte = [_]u8{1};
        _ = std.c.write(self.wake_w, &byte, 1);
    }

    /// Drain the wake pipe after a WAKE_TOKEN event so it is level-clear for the
    /// next poll. Reads until EAGAIN.
    pub fn drainWake(self: *const KqueueBackend) void {
        if (self.wake_r < 0) return;
        var buf: [64]u8 = undefined;
        // Nonblocking read: EAGAIN (n < 0) or EOF (n == 0) ends the drain.
        while (std.c.read(self.wake_r, &buf, buf.len) > 0) {}
    }

    pub fn poll(self: *KqueueBackend, timeout_ms: u32) ![]Kevent {
        if (!is_supported) return error.Unsupported;
        const ts = std.posix.timespec{
            .sec = @intCast(timeout_ms / 1000),
            .nsec = @intCast((timeout_ms % 1000) * std.time.ns_per_ms),
        };
        const count = try std.Io.Kqueue.kevent(self.kq, &[_]Kevent{}, self.events, &ts);
        return self.events[0..count];
    }

    pub fn registerListener(self: *KqueueBackend, fd: std.posix.fd_t) !void {
        if (!is_supported) return error.Unsupported;
        try self.registerEvent(fd, EVFILT_READ, 0);
    }

    /// Register a UDP socket for read events.
    /// Uses a special udata value to distinguish from TCP listener.
    pub fn registerUdpSocket(self: *KqueueBackend, fd: std.posix.fd_t) !void {
        if (!is_supported) return error.Unsupported;
        // Use max u64 - 1 as magic value for UDP socket to distinguish from TCP listener (0)
        try self.registerEvent(fd, EVFILT_READ, std.math.maxInt(usize) - 1);
    }

    pub fn registerConnection(self: *KqueueBackend, conn_id: u64, fd: std.posix.fd_t) !void {
        if (!is_supported) return error.Unsupported;
        const token: usize = @intCast(conn_id);
        try self.registerEvent(fd, EVFILT_READ, token);
    }

    pub fn armWritable(self: *KqueueBackend, conn_id: u64, fd: std.posix.fd_t) !void {
        if (!is_supported) return error.Unsupported;
        const token: usize = @intCast(conn_id);
        try self.registerOneshotEvent(fd, EVFILT_WRITE, token);
    }

    pub fn unregister(self: *KqueueBackend, fd: std.posix.fd_t) !void {
        if (!is_supported) return error.Unsupported;
        self.unregisterEvent(fd, EVFILT_READ);
        self.unregisterEvent(fd, EVFILT_WRITE);
    }

    fn registerEvent(self: *KqueueBackend, fd: std.posix.fd_t, filter: i16, udata: usize) !void {
        const ev = Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = EV_ADD | EV_ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = udata,
        };
        var out: [0]Kevent = .{};
        _ = try std.Io.Kqueue.kevent(self.kq, &[_]Kevent{ev}, out[0..], null);
    }

    fn registerOneshotEvent(self: *KqueueBackend, fd: std.posix.fd_t, filter: i16, udata: usize) !void {
        const ev = Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = EV_ADD | EV_ENABLE | EV_ONESHOT,
            .fflags = 0,
            .data = 0,
            .udata = udata,
        };
        var out: [0]Kevent = .{};
        _ = try std.Io.Kqueue.kevent(self.kq, &[_]Kevent{ev}, out[0..], null);
    }

    fn unregisterEvent(self: *KqueueBackend, fd: std.posix.fd_t, filter: i16) void {
        const ev = Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = EV_DELETE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        var out: [0]Kevent = .{};
        _ = std.Io.Kqueue.kevent(self.kq, &[_]Kevent{ev}, out[0..], null) catch {};
    }
};

test "kqueue cross-thread wake unblocks a blocked poll" {
    if (!is_supported) return; // kqueue only exists on BSD/Darwin
    var backend = try KqueueBackend.init(std.testing.allocator, 8);
    defer backend.deinit(std.testing.allocator);
    try backend.registerWake();

    // Another thread wakes the loop. The self-pipe is level-triggered, so the
    // wake is delivered whether it lands before or after poll() blocks. If
    // wake() did nothing, poll() below would block the full 2s and then return
    // 0 events, failing the assertions.
    const Waker = struct {
        fn run(b: *KqueueBackend) void {
            b.wake();
        }
    };
    var thread = try std.Thread.spawn(.{}, Waker.run, .{&backend});
    defer thread.join();

    const events = try backend.poll(2000);
    try std.testing.expect(events.len >= 1);
    var saw_wake = false;
    for (events) |e| {
        if (e.udata == WAKE_TOKEN) saw_wake = true;
    }
    try std.testing.expect(saw_wake);

    // After draining, a short poll with no pending wake returns nothing: the
    // self-pipe is level-triggered, so the drain must clear it.
    backend.drainWake();
    const none = try backend.poll(10);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "kqueue wake is a no-op before registerWake" {
    if (!is_supported) return;
    var backend = try KqueueBackend.init(std.testing.allocator, 4);
    defer backend.deinit(std.testing.allocator);
    backend.wake(); // must not crash with no pipe set up
    const none = try backend.poll(1);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}
