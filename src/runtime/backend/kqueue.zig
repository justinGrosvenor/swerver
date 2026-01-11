const std = @import("std");
const builtin = @import("builtin");

// BSD/Darwin kqueue constants for a minimal backend implementation.
pub const EV_ADD: u16 = 0x0001;
pub const EV_DELETE: u16 = 0x0002;
pub const EV_ENABLE: u16 = 0x0004;
pub const EV_ERROR: u16 = 0x4000;
pub const EVFILT_READ: i16 = -1;
pub const EVFILT_WRITE: i16 = -2;

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

    pub fn init(allocator: std.mem.Allocator, max_events: usize) !KqueueBackend {
        if (!is_supported) return error.Unsupported;
        const kq = std.posix.system.kqueue();
        if (kq < 0) return error.KqueueFailed;
        const events = try allocator.alloc(Kevent, max_events);
        return .{
            .kq = kq,
            .events = events,
        };
    }

    pub fn deinit(self: *KqueueBackend, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        std.posix.close(self.kq);
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
        try self.registerEvent(fd, EVFILT_WRITE, token);
    }

    pub fn unregister(self: *KqueueBackend, fd: std.posix.fd_t) !void {
        if (!is_supported) return error.Unsupported;
        try self.unregisterEvent(fd, EVFILT_READ);
        try self.unregisterEvent(fd, EVFILT_WRITE);
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

    fn unregisterEvent(self: *KqueueBackend, fd: std.posix.fd_t, filter: i16) !void {
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
