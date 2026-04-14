const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const native_os = builtin.os.tag;

/// Monotonic timestamp for measuring elapsed time.
/// Drop-in replacement for the removed std.time.Instant.
pub const Instant = struct {
    ns: u64,

    /// Get the current monotonic time.
    pub fn now() ?Instant {
        var ts: posix.timespec = undefined;
        const rc = posix.system.clock_gettime(clock_id, &ts);
        if (posix.errno(rc) != .SUCCESS) return null;
        const ns: u64 = @intCast(ts.sec * std.time.ns_per_s + ts.nsec);
        return .{ .ns = ns };
    }

    /// Nanoseconds elapsed since an earlier instant.
    pub fn since(self: Instant, earlier: Instant) u64 {
        if (self.ns >= earlier.ns) return self.ns - earlier.ns;
        return 0;
    }

    const clock_id: posix.clockid_t = switch (native_os) {
        .macos, .ios, .tvos, .watchos, .visionos => posix.CLOCK.UPTIME_RAW,
        else => posix.CLOCK.MONOTONIC,
    };
};

/// Simple elapsed-time timer. Drop-in replacement for the removed std.time.Timer.
pub const Timer = struct {
    start_ns: u64,

    pub fn start() !Timer {
        const instant = Instant.now() orelse return error.Unsupported;
        return .{ .start_ns = instant.ns };
    }

    /// Returns elapsed nanoseconds since start.
    pub fn read(self: *Timer) u64 {
        const now_inst = Instant.now() orelse return 0;
        if (now_inst.ns >= self.start_ns) return now_inst.ns - self.start_ns;
        return 0;
    }
};

/// Close a file descriptor (replacement for the removed std.posix.close).
pub fn closeFd(fd: posix.fd_t) void {
    _ = posix.system.close(fd);
}

/// Get the current wall-clock time as a posix timespec.
/// Replacement for the removed std.posix.clock_gettime(.REALTIME).
pub fn realtimeTimespec() ?posix.timespec {
    var ts: posix.timespec = undefined;
    if (posix.errno(posix.system.clock_gettime(posix.CLOCK.REALTIME, &ts)) != .SUCCESS) return null;
    return ts;
}

/// Get the current wall-clock time as nanoseconds since the Unix epoch.
/// Replacement for the removed std.time.nanoTimestamp(). Returns null if
/// the underlying clock_gettime call fails.
pub fn realtimeNanos() ?i128 {
    const ts = realtimeTimespec() orelse return null;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

/// Get the current monotonic time as a posix timespec.
/// Replacement for the removed std.posix.clock_gettime(.MONOTONIC).
pub fn monotonicTimespec() ?posix.timespec {
    var ts: posix.timespec = undefined;
    if (posix.errno(posix.system.clock_gettime(Instant.clock_id, &ts)) != .SUCCESS) return null;
    return ts;
}
