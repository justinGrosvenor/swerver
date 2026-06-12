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

test "Instant.now is non-decreasing across two reads" {
    const first = Instant.now() orelse return error.ClockUnsupported;
    const second = Instant.now() orelse return error.ClockUnsupported;
    // A monotonic clock must never go backwards between two sequential reads.
    try std.testing.expect(second.ns >= first.ns);
}

test "Instant.since returns non-negative elapsed and zero for reversed args" {
    const earlier = Instant.now() orelse return error.ClockUnsupported;
    const later = Instant.now() orelse return error.ClockUnsupported;
    // Forward direction: elapsed equals the raw nanosecond delta and is >= 0.
    try std.testing.expectEqual(later.ns - earlier.ns, later.since(earlier));
    // Reversed direction is saturated to 0 rather than underflowing.
    try std.testing.expectEqual(@as(u64, 0), earlier.since(later));
    // since() against itself is exactly 0.
    try std.testing.expectEqual(@as(u64, 0), later.since(later));
}

test "Timer.read returns a sane non-negative elapsed" {
    var timer = try Timer.start();
    const elapsed = timer.read();
    // read() can never be negative (u64) and for a fresh timer should be a
    // small, bounded value — well under a second of pure CPU time here.
    try std.testing.expect(elapsed < std.time.ns_per_s);
    // A second read is monotonic with respect to the first.
    const elapsed2 = timer.read();
    try std.testing.expect(elapsed2 >= elapsed);
}

test "realtimeTimespec and realtimeNanos agree and are positive" {
    const ts = realtimeTimespec() orelse return error.ClockUnsupported;
    // Wall-clock seconds since the Unix epoch are well past 2020.
    try std.testing.expect(ts.sec > 1_577_836_800); // 2020-01-01T00:00:00Z
    try std.testing.expect(ts.nsec >= 0 and ts.nsec < std.time.ns_per_s);

    const nanos = realtimeNanos() orelse return error.ClockUnsupported;
    // realtimeNanos is the same conversion applied to a timespec, so it must
    // be a positive count consistent with the seconds field we just read.
    try std.testing.expect(nanos > 0);
    const nanos_secs = @divFloor(nanos, std.time.ns_per_s);
    // Two independent reads can straddle a second boundary; allow a 2s window.
    try std.testing.expect(nanos_secs >= ts.sec - 2 and nanos_secs <= ts.sec + 2);
}

test "monotonicTimespec converts to the same scale as Instant.now" {
    const ts = monotonicTimespec() orelse return error.ClockUnsupported;
    try std.testing.expect(ts.nsec >= 0 and ts.nsec < std.time.ns_per_s);
    const ts_ns: u64 = @intCast(ts.sec * std.time.ns_per_s + ts.nsec);
    const inst = Instant.now() orelse return error.ClockUnsupported;
    // Both read the same underlying monotonic clock, so consecutive reads are
    // ordered and within a small (<1s) window of each other.
    try std.testing.expect(inst.ns >= ts_ns);
    try std.testing.expect(inst.ns - ts_ns < std.time.ns_per_s);
}
