const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");

/// Health + Readiness Middleware
///
/// Provides liveness and readiness probes:
/// - GET /.healthz - Liveness probe (always 200 if server is running)
/// - GET /.ready   - Readiness probe (200 if fully initialized, 503 otherwise)
///
/// Responses have no body, Content-Length: 0, and are cached per connection.

/// Readiness state - tracks whether the server is ready to accept traffic
/// Uses atomic bitfield for thread-safe access
pub const ReadinessState = struct {
    const LISTENERS_READY: u8 = 0x01;
    const BUFFERS_READY: u8 = 0x02;
    const TLS_READY: u8 = 0x04;
    const QUIC_READY: u8 = 0x08;
    const ALL_READY: u8 = LISTENERS_READY | BUFFERS_READY | TLS_READY | QUIC_READY;

    /// Check if all subsystems are ready
    pub fn isReady() bool {
        const state = @atomicLoad(u8, &readiness_flags, .acquire);
        return (state & ALL_READY) == ALL_READY;
    }

    /// Mark listeners as ready
    pub fn setListenersReady() void {
        _ = @atomicRmw(u8, &readiness_flags, .Or, LISTENERS_READY, .release);
    }

    /// Mark buffers as ready
    pub fn setBuffersReady() void {
        _ = @atomicRmw(u8, &readiness_flags, .Or, BUFFERS_READY, .release);
    }

    /// Mark TLS as ready
    pub fn setTlsReady() void {
        _ = @atomicRmw(u8, &readiness_flags, .Or, TLS_READY, .release);
    }

    /// Mark QUIC as ready
    pub fn setQuicReady() void {
        _ = @atomicRmw(u8, &readiness_flags, .Or, QUIC_READY, .release);
    }

    /// Mark all as ready
    pub fn markAllReady() void {
        @atomicStore(u8, &readiness_flags, ALL_READY, .release);
    }

    /// Reset all (for testing)
    pub fn reset() void {
        // TLS and QUIC default to ready (not all deployments use them)
        @atomicStore(u8, &readiness_flags, TLS_READY | QUIC_READY, .release);
    }
};

/// Atomic readiness flags (TLS and QUIC default ready)
var readiness_flags: u8 = ReadinessState.TLS_READY | ReadinessState.QUIC_READY;

/// Mark server as fully ready
pub fn markReady() void {
    ReadinessState.markAllReady();
}

/// Check if server is ready
pub fn isReady() bool {
    return ReadinessState.isReady();
}

/// Pre-allocated health response (no body, Content-Length: 0)
const health_ok_response = response.Response{
    .status = 200,
    .headers = &[_]response.Header{
        .{ .name = "Content-Length", .value = "0" },
        .{ .name = "Cache-Control", .value = "no-cache" },
    },
    .body = "",
};

/// Pre-allocated readiness OK response
const ready_ok_response = response.Response{
    .status = 200,
    .headers = &[_]response.Header{
        .{ .name = "Content-Length", .value = "0" },
        .{ .name = "Cache-Control", .value = "no-cache" },
    },
    .body = "",
};

/// Pre-allocated not ready response
const not_ready_response = response.Response{
    .status = 503,
    .headers = &[_]response.Header{
        .{ .name = "Content-Length", .value = "0" },
        .{ .name = "Cache-Control", .value = "no-cache" },
        .{ .name = "Retry-After", .value = "5" },
    },
    .body = "",
};

/// Health check middleware function
pub fn evaluate(ctx: *middleware.Context, req: request.RequestView) middleware.Decision {
    _ = ctx;

    // Only handle GET requests
    if (req.method != .GET) return .allow;

    const path = req.path orelse return .allow;

    // Liveness probe
    if (std.mem.eql(u8, path, "/.healthz")) {
        return .{ .reject = health_ok_response };
    }

    // Readiness probe
    if (std.mem.eql(u8, path, "/.ready")) {
        if (ReadinessState.isReady()) {
            return .{ .reject = ready_ok_response };
        } else {
            return .{ .reject = not_ready_response };
        }
    }

    return .allow;
}

/// Configuration for health middleware
pub const Config = struct {
    /// Path for liveness probe
    liveness_path: []const u8 = "/.healthz",
    /// Path for readiness probe
    readiness_path: []const u8 = "/.ready",
    /// Enable caching of probe responses per connection
    cache_per_connection: bool = true,
};

// Tests
test "liveness probe returns 200" {
    var ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/.healthz",
        .headers = &.{},
    };

    const decision = evaluate(&ctx, req);
    switch (decision) {
        .reject => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
        },
        else => try std.testing.expect(false),
    }
}

test "readiness probe returns 503 when not ready" {
    // Reset state (listeners and buffers not ready)
    ReadinessState.reset();

    var ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/.ready",
        .headers = &.{},
    };

    const decision = evaluate(&ctx, req);
    switch (decision) {
        .reject => |resp| {
            try std.testing.expectEqual(@as(u16, 503), resp.status);
        },
        else => try std.testing.expect(false),
    }
}

test "readiness probe returns 200 when ready" {
    ReadinessState.markAllReady();

    var ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/.ready",
        .headers = &.{},
    };

    const decision = evaluate(&ctx, req);
    switch (decision) {
        .reject => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
        },
        else => try std.testing.expect(false),
    }
}

test "non-health paths pass through" {
    var ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/users",
        .headers = &.{},
    };

    const decision = evaluate(&ctx, req);
    try std.testing.expect(decision == .allow);
}
