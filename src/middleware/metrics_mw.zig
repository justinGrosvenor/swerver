const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");

/// Metrics Exporter Middleware
///
/// Collects and exposes Prometheus-compatible metrics at /metrics.
/// Uses fixed-size ring buffers for zero heap allocations.

/// Maximum number of metric records to keep
const MAX_METRICS = 256;

/// Metric types
pub const MetricType = enum {
    counter,
    gauge,
    histogram,
};

/// Single metric record
pub const MetricRecord = struct {
    /// Metric name
    name: [64]u8 = undefined,
    name_len: u8 = 0,
    /// Metric type
    metric_type: MetricType = .counter,
    /// Value
    value: u64 = 0,
    /// Labels (protocol, method, status, etc.)
    protocol: middleware.Context.Protocol = .http1,
    method: request.Method = .GET,
    status: u16 = 0,
    /// Timestamp
    timestamp_ns: i128 = 0,

    pub fn getName(self: *const MetricRecord) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *MetricRecord, name: []const u8) void {
        const len = @min(name.len, 64);
        @memcpy(self.name[0..len], name[0..len]);
        self.name_len = @intCast(len);
    }
};

/// Thread-safe metrics storage using atomic operations
pub const MetricsStore = struct {
    // Counters
    requests_total: u64 = 0,
    responses_total: u64 = 0,
    errors_total: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,

    // Per-status counters (index = status / 100 - 1, so 1xx=0, 2xx=1, etc.)
    status_1xx: u64 = 0,
    status_2xx: u64 = 0,
    status_3xx: u64 = 0,
    status_4xx: u64 = 0,
    status_5xx: u64 = 0,

    // Per-protocol counters
    http1_requests: u64 = 0,
    http2_requests: u64 = 0,
    http3_requests: u64 = 0,

    // Gauges
    active_connections: u64 = 0,
    active_streams: u64 = 0,
    queue_depth: u64 = 0,

    // Latency histogram buckets (in microseconds)
    // Buckets: <1ms, <5ms, <10ms, <50ms, <100ms, <500ms, <1s, <5s, +Inf
    latency_bucket_1ms: u64 = 0,
    latency_bucket_5ms: u64 = 0,
    latency_bucket_10ms: u64 = 0,
    latency_bucket_50ms: u64 = 0,
    latency_bucket_100ms: u64 = 0,
    latency_bucket_500ms: u64 = 0,
    latency_bucket_1s: u64 = 0,
    latency_bucket_5s: u64 = 0,
    latency_bucket_inf: u64 = 0,
    latency_sum_us: u64 = 0,
    latency_count: u64 = 0,

    /// Record a request
    pub fn recordRequest(self: *MetricsStore, protocol: middleware.Context.Protocol) void {
        _ = @atomicRmw(u64, &self.requests_total, .Add, 1, .monotonic);
        switch (protocol) {
            .http1 => _ = @atomicRmw(u64, &self.http1_requests, .Add, 1, .monotonic),
            .http2 => _ = @atomicRmw(u64, &self.http2_requests, .Add, 1, .monotonic),
            .http3 => _ = @atomicRmw(u64, &self.http3_requests, .Add, 1, .monotonic),
        }
    }

    /// Record a response
    pub fn recordResponse(self: *MetricsStore, status: u16, latency_us: u64) void {
        _ = @atomicRmw(u64, &self.responses_total, .Add, 1, .monotonic);

        // Status bucket
        const bucket = status / 100;
        switch (bucket) {
            1 => _ = @atomicRmw(u64, &self.status_1xx, .Add, 1, .monotonic),
            2 => _ = @atomicRmw(u64, &self.status_2xx, .Add, 1, .monotonic),
            3 => _ = @atomicRmw(u64, &self.status_3xx, .Add, 1, .monotonic),
            4 => _ = @atomicRmw(u64, &self.status_4xx, .Add, 1, .monotonic),
            5 => _ = @atomicRmw(u64, &self.status_5xx, .Add, 1, .monotonic),
            else => {},
        }

        // Latency histogram
        if (latency_us < 1_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_1ms, .Add, 1, .monotonic);
        } else if (latency_us < 5_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_5ms, .Add, 1, .monotonic);
        } else if (latency_us < 10_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_10ms, .Add, 1, .monotonic);
        } else if (latency_us < 50_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_50ms, .Add, 1, .monotonic);
        } else if (latency_us < 100_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_100ms, .Add, 1, .monotonic);
        } else if (latency_us < 500_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_500ms, .Add, 1, .monotonic);
        } else if (latency_us < 1_000_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_1s, .Add, 1, .monotonic);
        } else if (latency_us < 5_000_000) {
            _ = @atomicRmw(u64, &self.latency_bucket_5s, .Add, 1, .monotonic);
        } else {
            _ = @atomicRmw(u64, &self.latency_bucket_inf, .Add, 1, .monotonic);
        }

        _ = @atomicRmw(u64, &self.latency_sum_us, .Add, latency_us, .monotonic);
        _ = @atomicRmw(u64, &self.latency_count, .Add, 1, .monotonic);
    }

    /// Record an error
    pub fn recordError(self: *MetricsStore) void {
        _ = @atomicRmw(u64, &self.errors_total, .Add, 1, .monotonic);
    }

    /// Record bytes transferred
    pub fn recordBytes(self: *MetricsStore, sent: u64, received: u64) void {
        _ = @atomicRmw(u64, &self.bytes_sent, .Add, sent, .monotonic);
        _ = @atomicRmw(u64, &self.bytes_received, .Add, received, .monotonic);
    }

    /// Update connection count
    pub fn setActiveConnections(self: *MetricsStore, count: u64) void {
        @atomicStore(u64, &self.active_connections, count, .monotonic);
    }

    /// Format metrics as Prometheus text
    pub fn format(self: *const MetricsStore, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        // Requests
        try writer.print("# HELP swerver_requests_total Total number of requests\n", .{});
        try writer.print("# TYPE swerver_requests_total counter\n", .{});
        try writer.print("swerver_requests_total {d}\n", .{@atomicLoad(u64, &self.requests_total, .monotonic)});

        try writer.print("swerver_requests_total{{protocol=\"http/1.1\"}} {d}\n", .{@atomicLoad(u64, &self.http1_requests, .monotonic)});
        try writer.print("swerver_requests_total{{protocol=\"http/2\"}} {d}\n", .{@atomicLoad(u64, &self.http2_requests, .monotonic)});
        try writer.print("swerver_requests_total{{protocol=\"http/3\"}} {d}\n", .{@atomicLoad(u64, &self.http3_requests, .monotonic)});

        // Responses by status
        try writer.print("# HELP swerver_responses_total Total number of responses\n", .{});
        try writer.print("# TYPE swerver_responses_total counter\n", .{});
        try writer.print("swerver_responses_total {d}\n", .{@atomicLoad(u64, &self.responses_total, .monotonic)});
        try writer.print("swerver_responses_total{{status=\"1xx\"}} {d}\n", .{@atomicLoad(u64, &self.status_1xx, .monotonic)});
        try writer.print("swerver_responses_total{{status=\"2xx\"}} {d}\n", .{@atomicLoad(u64, &self.status_2xx, .monotonic)});
        try writer.print("swerver_responses_total{{status=\"3xx\"}} {d}\n", .{@atomicLoad(u64, &self.status_3xx, .monotonic)});
        try writer.print("swerver_responses_total{{status=\"4xx\"}} {d}\n", .{@atomicLoad(u64, &self.status_4xx, .monotonic)});
        try writer.print("swerver_responses_total{{status=\"5xx\"}} {d}\n", .{@atomicLoad(u64, &self.status_5xx, .monotonic)});

        // Errors
        try writer.print("# HELP swerver_errors_total Total number of errors\n", .{});
        try writer.print("# TYPE swerver_errors_total counter\n", .{});
        try writer.print("swerver_errors_total {d}\n", .{@atomicLoad(u64, &self.errors_total, .monotonic)});

        // Bytes
        try writer.print("# HELP swerver_bytes_sent_total Total bytes sent\n", .{});
        try writer.print("# TYPE swerver_bytes_sent_total counter\n", .{});
        try writer.print("swerver_bytes_sent_total {d}\n", .{@atomicLoad(u64, &self.bytes_sent, .monotonic)});

        try writer.print("# HELP swerver_bytes_received_total Total bytes received\n", .{});
        try writer.print("# TYPE swerver_bytes_received_total counter\n", .{});
        try writer.print("swerver_bytes_received_total {d}\n", .{@atomicLoad(u64, &self.bytes_received, .monotonic)});

        // Active connections
        try writer.print("# HELP swerver_active_connections Current active connections\n", .{});
        try writer.print("# TYPE swerver_active_connections gauge\n", .{});
        try writer.print("swerver_active_connections {d}\n", .{@atomicLoad(u64, &self.active_connections, .monotonic)});

        // Latency histogram
        try writer.print("# HELP swerver_request_duration_seconds Request latency histogram\n", .{});
        try writer.print("# TYPE swerver_request_duration_seconds histogram\n", .{});

        var cumulative: u64 = 0;
        cumulative += @atomicLoad(u64, &self.latency_bucket_1ms, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"0.001\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_5ms, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"0.005\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_10ms, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"0.01\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_50ms, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"0.05\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_100ms, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"0.1\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_500ms, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"0.5\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_1s, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"1\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_5s, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"5\"}} {d}\n", .{cumulative});

        cumulative += @atomicLoad(u64, &self.latency_bucket_inf, .monotonic);
        try writer.print("swerver_request_duration_seconds_bucket{{le=\"+Inf\"}} {d}\n", .{cumulative});

        const sum_us = @atomicLoad(u64, &self.latency_sum_us, .monotonic);
        const sum_s: f64 = @as(f64, @floatFromInt(sum_us)) / 1_000_000.0;
        try writer.print("swerver_request_duration_seconds_sum {d:.6}\n", .{sum_s});
        try writer.print("swerver_request_duration_seconds_count {d}\n", .{@atomicLoad(u64, &self.latency_count, .monotonic)});

        return fbs.getWritten();
    }
};

/// Global metrics store
var store: MetricsStore = .{};

/// Thread-local format buffer (avoids stack pointer escape)
threadlocal var metrics_buf: [16384]u8 = undefined;

/// Get the global metrics store
pub fn getStore() *MetricsStore {
    return &store;
}

/// Metrics endpoint middleware
pub fn evaluate(ctx: *middleware.Context, req: request.RequestView) middleware.Decision {
    _ = ctx;

    // Only handle GET /metrics
    if (req.method != .GET) return .allow;

    const path = req.path orelse return .allow;
    if (!std.mem.eql(u8, path, "/metrics")) return .allow;

    // Format metrics - use thread-local buffer (safe across function return)
    const body = store.format(&metrics_buf) catch {
        return .{ .reject = response.Response{
            .status = 500,
            .headers = &.{},
            .body = "Failed to format metrics",
        } };
    };

    // Create response with metrics body (threadlocal buffer is safe)
    return .{ .reject = response.Response{
        .status = 200,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain; version=0.0.4; charset=utf-8" },
        },
        .body = body,
    } };
}

/// Post-response hook to record metrics
pub fn postResponse(ctx: *middleware.Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) void {
    _ = req;

    store.recordRequest(ctx.protocol);
    store.recordResponse(resp.status, elapsed_ns / 1000); // Convert to microseconds

    if (resp.status >= 500) {
        store.recordError();
    }

    store.recordBytes(resp.body.len, 0);
}

// Tests
test "metrics store record request" {
    var s = MetricsStore{};
    s.recordRequest(.http1);
    s.recordRequest(.http2);
    s.recordRequest(.http1);

    try std.testing.expectEqual(@as(u64, 3), s.requests_total);
    try std.testing.expectEqual(@as(u64, 2), s.http1_requests);
    try std.testing.expectEqual(@as(u64, 1), s.http2_requests);
}

test "metrics store record response" {
    var s = MetricsStore{};
    s.recordResponse(200, 500); // 500us
    s.recordResponse(404, 1500); // 1.5ms
    s.recordResponse(500, 100_000); // 100ms

    try std.testing.expectEqual(@as(u64, 3), s.responses_total);
    try std.testing.expectEqual(@as(u64, 1), s.status_2xx);
    try std.testing.expectEqual(@as(u64, 1), s.status_4xx);
    try std.testing.expectEqual(@as(u64, 1), s.status_5xx);
}

test "metrics format prometheus" {
    var s = MetricsStore{};
    s.recordRequest(.http1);
    s.recordResponse(200, 1000);

    var buf: [8192]u8 = undefined;
    const output = try s.format(&buf);

    try std.testing.expect(std.mem.indexOf(u8, output, "swerver_requests_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "swerver_responses_total 1") != null);
}
