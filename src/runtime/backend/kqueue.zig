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

pub const KqueueBackend = struct {
    kq: std.posix.fd_t,
    events: []std.posix.Kevent,

    pub fn init(allocator: std.mem.Allocator, max_events: usize) !KqueueBackend {
        if (!is_supported) return error.Unsupported;
        const kq = std.posix.system.kqueue();
        if (kq < 0) return error.KqueueFailed;
        const events = try allocator.alloc(std.posix.Kevent, max_events);
        return .{
            .kq = kq,
            .events = events,
        };
    }

    pub fn deinit(self: *KqueueBackend, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        std.posix.close(self.kq);
    }

    pub fn poll(self: *KqueueBackend, timeout_ms: u32) ![]std.posix.Kevent {
        const ts = std.posix.timespec{
            .sec = @intCast(timeout_ms / 1000),
            .nsec = @intCast((timeout_ms % 1000) * std.time.ns_per_ms),
        };
        const count = try std.Io.Kqueue.kevent(self.kq, &[_]std.posix.Kevent{}, self.events, &ts);
        return self.events[0..count];
    }

    pub fn registerListener(self: *KqueueBackend, fd: std.posix.fd_t) !void {
        try self.registerEvent(fd, EVFILT_READ, 0);
    }

    pub fn registerConnection(self: *KqueueBackend, conn_id: u64, fd: std.posix.fd_t) !void {
        const token: usize = @intCast(conn_id);
        try self.registerEvent(fd, EVFILT_READ, token);
        try self.registerEvent(fd, EVFILT_WRITE, token);
    }

    pub fn unregister(self: *KqueueBackend, fd: std.posix.fd_t) !void {
        try self.unregisterEvent(fd, EVFILT_READ);
        try self.unregisterEvent(fd, EVFILT_WRITE);
    }

    fn registerEvent(self: *KqueueBackend, fd: std.posix.fd_t, filter: i16, udata: usize) !void {
        const ev = std.posix.Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = EV_ADD | EV_ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = udata,
        };
        var out: [0]std.posix.Kevent = .{};
        _ = try std.Io.Kqueue.kevent(self.kq, &[_]std.posix.Kevent{ev}, out[0..], null);
    }

    fn unregisterEvent(self: *KqueueBackend, fd: std.posix.fd_t, filter: i16) !void {
        const ev = std.posix.Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = EV_DELETE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        var out: [0]std.posix.Kevent = .{};
        _ = std.Io.Kqueue.kevent(self.kq, &[_]std.posix.Kevent{ev}, out[0..], null) catch {};
    }
};
