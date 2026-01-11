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

/// Per-stream metrics for HTTP/2 and HTTP/3
pub const StreamMetrics = struct {
    stream_id: u64,
    requests: u64 = 0,
    responses: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    latency_sum_us: u64 = 0,
    latency_count: u64 = 0,
    active: bool = false,
};

/// Maximum tracked streams for per-stream metrics
const MAX_TRACKED_STREAMS = 256;

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

    // Per-stream metrics (for HTTP/2 and HTTP/3)
    stream_metrics: [MAX_TRACKED_STREAMS]StreamMetrics = [_]StreamMetrics{.{ .stream_id = 0 }} ** MAX_TRACKED_STREAMS,
    stream_metrics_count: u64 = 0,

    // Gauges
    active_connections: u64 = 0,
    active_streams: u64 = 0,
    queue_depth: u64 = 0,

    // QUIC-specific metrics
    quic_connections_attempted: u64 = 0,
    quic_connections_established: u64 = 0,
    quic_connections_active: u64 = 0,
    quic_connections_failed: u64 = 0,
    quic_connections_timeout: u64 = 0,
    quic_packets_sent: u64 = 0,
    quic_packets_received: u64 = 0,
    quic_packets_lost: u64 = 0,
    quic_handshake_latency_sum_ms: u64 = 0,
    quic_handshake_count: u64 = 0,
    quic_rtt_sum_us: u64 = 0,
    quic_rtt_count: u64 = 0,
    quic_min_rtt_us: u64 = std.math.maxInt(u64),

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

    // QUIC metrics methods

    /// Record QUIC connection attempt
    pub fn recordQuicConnectionAttempt(self: *MetricsStore) void {
        _ = @atomicRmw(u64, &self.quic_connections_attempted, .Add, 1, .monotonic);
        _ = @atomicRmw(u64, &self.quic_connections_active, .Add, 1, .monotonic);
    }

    /// Record QUIC handshake complete
    pub fn recordQuicHandshakeComplete(self: *MetricsStore, latency_ms: u64) void {
        _ = @atomicRmw(u64, &self.quic_connections_established, .Add, 1, .monotonic);
        _ = @atomicRmw(u64, &self.quic_handshake_latency_sum_ms, .Add, latency_ms, .monotonic);
        _ = @atomicRmw(u64, &self.quic_handshake_count, .Add, 1, .monotonic);
    }

    /// Record QUIC connection close
    pub fn recordQuicConnectionClose(self: *MetricsStore, is_error: bool, is_timeout: bool) void {
        _ = @atomicRmw(u64, &self.quic_connections_active, .Sub, 1, .monotonic);
        if (is_timeout) {
            _ = @atomicRmw(u64, &self.quic_connections_timeout, .Add, 1, .monotonic);
        } else if (is_error) {
            _ = @atomicRmw(u64, &self.quic_connections_failed, .Add, 1, .monotonic);
        }
    }

    /// Record QUIC packets
    pub fn recordQuicPackets(self: *MetricsStore, sent: u64, received: u64, lost: u64) void {
        _ = @atomicRmw(u64, &self.quic_packets_sent, .Add, sent, .monotonic);
        _ = @atomicRmw(u64, &self.quic_packets_received, .Add, received, .monotonic);
        _ = @atomicRmw(u64, &self.quic_packets_lost, .Add, lost, .monotonic);
    }

    /// Record QUIC RTT sample
    pub fn recordQuicRtt(self: *MetricsStore, rtt_us: u64) void {
        _ = @atomicRmw(u64, &self.quic_rtt_sum_us, .Add, rtt_us, .monotonic);
        _ = @atomicRmw(u64, &self.quic_rtt_count, .Add, 1, .monotonic);
        // Update min RTT (atomic compare-exchange)
        var current = @atomicLoad(u64, &self.quic_min_rtt_us, .monotonic);
        while (rtt_us < current) {
            const result = @cmpxchgWeak(u64, &self.quic_min_rtt_us, current, rtt_us, .monotonic, .monotonic);
            if (result) |r| {
                current = r;
            } else {
                break;
            }
        }
    }

    /// Get average QUIC handshake latency
    pub fn avgQuicHandshakeLatencyMs(self: *const MetricsStore) u64 {
        const count = @atomicLoad(u64, &self.quic_handshake_count, .monotonic);
        if (count == 0) return 0;
        return @atomicLoad(u64, &self.quic_handshake_latency_sum_ms, .monotonic) / count;
    }

    /// Get average QUIC RTT in microseconds
    pub fn avgQuicRttUs(self: *const MetricsStore) u64 {
        const count = @atomicLoad(u64, &self.quic_rtt_count, .monotonic);
        if (count == 0) return 0;
        return @atomicLoad(u64, &self.quic_rtt_sum_us, .monotonic) / count;
    }

    /// Get QUIC packet loss rate (0.0 - 1.0)
    pub fn quicPacketLossRate(self: *const MetricsStore) f64 {
        const sent = @atomicLoad(u64, &self.quic_packets_sent, .monotonic);
        if (sent == 0) return 0.0;
        const lost = @atomicLoad(u64, &self.quic_packets_lost, .monotonic);
        return @as(f64, @floatFromInt(lost)) / @as(f64, @floatFromInt(sent));
    }

    // Per-stream metrics methods (for HTTP/2 and HTTP/3)

    /// Get or create stream metrics entry (returns index, or null if full)
    fn getOrCreateStreamEntry(self: *MetricsStore, stream_id: u64) ?*StreamMetrics {
        // Look for existing entry
        for (&self.stream_metrics) |*entry| {
            if (entry.active and entry.stream_id == stream_id) {
                return entry;
            }
        }

        // Find empty slot
        for (&self.stream_metrics) |*entry| {
            if (!entry.active) {
                entry.* = .{ .stream_id = stream_id, .active = true };
                _ = @atomicRmw(u64, &self.stream_metrics_count, .Add, 1, .monotonic);
                return entry;
            }
        }

        // Full - LRU eviction (reuse first slot)
        self.stream_metrics[0] = .{ .stream_id = stream_id, .active = true };
        return &self.stream_metrics[0];
    }

    /// Record request for a specific stream
    pub fn recordStreamRequest(self: *MetricsStore, stream_id: u64, protocol: middleware.Context.Protocol) void {
        // Only track for HTTP/2 and HTTP/3
        if (protocol == .http1) return;

        if (self.getOrCreateStreamEntry(stream_id)) |entry| {
            entry.requests += 1;
        }
    }

    /// Record response for a specific stream
    pub fn recordStreamResponse(self: *MetricsStore, stream_id: u64, protocol: middleware.Context.Protocol, latency_us: u64, bytes_sent: u64) void {
        if (protocol == .http1) return;

        if (self.getOrCreateStreamEntry(stream_id)) |entry| {
            entry.responses += 1;
            entry.bytes_sent += bytes_sent;
            entry.latency_sum_us += latency_us;
            entry.latency_count += 1;
        }
    }

    /// Record bytes received on a stream
    pub fn recordStreamBytesReceived(self: *MetricsStore, stream_id: u64, protocol: middleware.Context.Protocol, bytes: u64) void {
        if (protocol == .http1) return;

        if (self.getOrCreateStreamEntry(stream_id)) |entry| {
            entry.bytes_received += bytes;
        }
    }

    /// Mark stream as closed (deactivate entry)
    pub fn closeStream(self: *MetricsStore, stream_id: u64) void {
        for (&self.stream_metrics) |*entry| {
            if (entry.active and entry.stream_id == stream_id) {
                entry.active = false;
                _ = @atomicRmw(u64, &self.stream_metrics_count, .Sub, 1, .monotonic);
                return;
            }
        }
    }

    /// Get count of active streams being tracked
    pub fn activeStreamCount(self: *const MetricsStore) u64 {
        return @atomicLoad(u64, &self.stream_metrics_count, .monotonic);
    }

    /// Format metrics as Prometheus text
    pub fn format(self: *const MetricsStore, buf: []u8) ![]const u8 {
        var cumulative: u64 = 0;
        cumulative += @atomicLoad(u64, &self.latency_bucket_1ms, .monotonic);
        const bucket_1ms = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_5ms, .monotonic);
        const bucket_5ms = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_10ms, .monotonic);
        const bucket_10ms = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_50ms, .monotonic);
        const bucket_50ms = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_100ms, .monotonic);
        const bucket_100ms = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_500ms, .monotonic);
        const bucket_500ms = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_1s, .monotonic);
        const bucket_1s = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_5s, .monotonic);
        const bucket_5s = cumulative;
        cumulative += @atomicLoad(u64, &self.latency_bucket_inf, .monotonic);
        const bucket_inf = cumulative;

        const sum_us = @atomicLoad(u64, &self.latency_sum_us, .monotonic);
        const sum_s: f64 = @as(f64, @floatFromInt(sum_us)) / 1_000_000.0;

        // Part 1: HTTP metrics
        const part1 = std.fmt.bufPrint(buf,
            \\# HELP swerver_requests_total Total number of requests
            \\# TYPE swerver_requests_total counter
            \\swerver_requests_total {d}
            \\swerver_requests_total{{protocol="http/1.1"}} {d}
            \\swerver_requests_total{{protocol="http/2"}} {d}
            \\swerver_requests_total{{protocol="http/3"}} {d}
            \\# HELP swerver_responses_total Total number of responses
            \\# TYPE swerver_responses_total counter
            \\swerver_responses_total {d}
            \\swerver_responses_total{{status="1xx"}} {d}
            \\swerver_responses_total{{status="2xx"}} {d}
            \\swerver_responses_total{{status="3xx"}} {d}
            \\swerver_responses_total{{status="4xx"}} {d}
            \\swerver_responses_total{{status="5xx"}} {d}
            \\# HELP swerver_errors_total Total number of errors
            \\# TYPE swerver_errors_total counter
            \\swerver_errors_total {d}
            \\# HELP swerver_bytes_sent_total Total bytes sent
            \\# TYPE swerver_bytes_sent_total counter
            \\swerver_bytes_sent_total {d}
            \\# HELP swerver_bytes_received_total Total bytes received
            \\# TYPE swerver_bytes_received_total counter
            \\swerver_bytes_received_total {d}
            \\# HELP swerver_active_connections Current active connections
            \\# TYPE swerver_active_connections gauge
            \\swerver_active_connections {d}
            \\# HELP swerver_request_duration_seconds Request latency histogram
            \\# TYPE swerver_request_duration_seconds histogram
            \\swerver_request_duration_seconds_bucket{{le="0.001"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="0.005"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="0.01"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="0.05"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="0.1"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="0.5"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="1"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="5"}} {d}
            \\swerver_request_duration_seconds_bucket{{le="+Inf"}} {d}
            \\swerver_request_duration_seconds_sum {d:.6}
            \\swerver_request_duration_seconds_count {d}
            \\
        , .{
            @atomicLoad(u64, &self.requests_total, .monotonic),
            @atomicLoad(u64, &self.http1_requests, .monotonic),
            @atomicLoad(u64, &self.http2_requests, .monotonic),
            @atomicLoad(u64, &self.http3_requests, .monotonic),
            @atomicLoad(u64, &self.responses_total, .monotonic),
            @atomicLoad(u64, &self.status_1xx, .monotonic),
            @atomicLoad(u64, &self.status_2xx, .monotonic),
            @atomicLoad(u64, &self.status_3xx, .monotonic),
            @atomicLoad(u64, &self.status_4xx, .monotonic),
            @atomicLoad(u64, &self.status_5xx, .monotonic),
            @atomicLoad(u64, &self.errors_total, .monotonic),
            @atomicLoad(u64, &self.bytes_sent, .monotonic),
            @atomicLoad(u64, &self.bytes_received, .monotonic),
            @atomicLoad(u64, &self.active_connections, .monotonic),
            bucket_1ms,
            bucket_5ms,
            bucket_10ms,
            bucket_50ms,
            bucket_100ms,
            bucket_500ms,
            bucket_1s,
            bucket_5s,
            bucket_inf,
            sum_s,
            @atomicLoad(u64, &self.latency_count, .monotonic),
        }) catch return error.BufferTooSmall;

        const offset1 = part1.len;

        // Part 2: QUIC metrics
        const handshake_sum_ms = @atomicLoad(u64, &self.quic_handshake_latency_sum_ms, .monotonic);
        const handshake_sum_s: f64 = @as(f64, @floatFromInt(handshake_sum_ms)) / 1000.0;
        const rtt_sum_us = @atomicLoad(u64, &self.quic_rtt_sum_us, .monotonic);
        const rtt_sum_s: f64 = @as(f64, @floatFromInt(rtt_sum_us)) / 1_000_000.0;
        const min_rtt = @atomicLoad(u64, &self.quic_min_rtt_us, .monotonic);
        const min_rtt_s: f64 = if (min_rtt < std.math.maxInt(u64))
            @as(f64, @floatFromInt(min_rtt)) / 1_000_000.0
        else
            0.0;

        const part2 = std.fmt.bufPrint(buf[offset1..],
            \\# HELP swerver_quic_connections_total Total QUIC connections
            \\# TYPE swerver_quic_connections_total counter
            \\swerver_quic_connections_total{{state="attempted"}} {d}
            \\swerver_quic_connections_total{{state="established"}} {d}
            \\swerver_quic_connections_total{{state="failed"}} {d}
            \\swerver_quic_connections_total{{state="timeout"}} {d}
            \\# HELP swerver_quic_connections_active Current active QUIC connections
            \\# TYPE swerver_quic_connections_active gauge
            \\swerver_quic_connections_active {d}
            \\# HELP swerver_quic_packets_total Total QUIC packets
            \\# TYPE swerver_quic_packets_total counter
            \\swerver_quic_packets_total{{direction="sent"}} {d}
            \\swerver_quic_packets_total{{direction="received"}} {d}
            \\swerver_quic_packets_total{{direction="lost"}} {d}
            \\# HELP swerver_quic_packet_loss_rate QUIC packet loss rate (0.0-1.0)
            \\# TYPE swerver_quic_packet_loss_rate gauge
            \\swerver_quic_packet_loss_rate {d:.6}
            \\# HELP swerver_quic_handshake_duration_seconds QUIC handshake duration
            \\# TYPE swerver_quic_handshake_duration_seconds summary
            \\swerver_quic_handshake_duration_seconds_sum {d:.6}
            \\swerver_quic_handshake_duration_seconds_count {d}
            \\# HELP swerver_quic_rtt_seconds QUIC round-trip time
            \\# TYPE swerver_quic_rtt_seconds summary
            \\swerver_quic_rtt_seconds_sum {d:.6}
            \\swerver_quic_rtt_seconds_count {d}
            \\# HELP swerver_quic_min_rtt_seconds Minimum observed QUIC RTT
            \\# TYPE swerver_quic_min_rtt_seconds gauge
            \\swerver_quic_min_rtt_seconds {d:.6}
            \\
        , .{
            @atomicLoad(u64, &self.quic_connections_attempted, .monotonic),
            @atomicLoad(u64, &self.quic_connections_established, .monotonic),
            @atomicLoad(u64, &self.quic_connections_failed, .monotonic),
            @atomicLoad(u64, &self.quic_connections_timeout, .monotonic),
            @atomicLoad(u64, &self.quic_connections_active, .monotonic),
            @atomicLoad(u64, &self.quic_packets_sent, .monotonic),
            @atomicLoad(u64, &self.quic_packets_received, .monotonic),
            @atomicLoad(u64, &self.quic_packets_lost, .monotonic),
            self.quicPacketLossRate(),
            handshake_sum_s,
            @atomicLoad(u64, &self.quic_handshake_count, .monotonic),
            rtt_sum_s,
            @atomicLoad(u64, &self.quic_rtt_count, .monotonic),
            min_rtt_s,
        }) catch return error.BufferTooSmall;

        var offset2 = offset1 + part2.len;

        // Part 3: Per-stream metrics (for HTTP/2 and HTTP/3)
        // Format active streams with labels
        var has_streams = false;
        for (self.stream_metrics) |entry| {
            if (entry.active) {
                has_streams = true;
                break;
            }
        }

        if (has_streams) {
            // Write stream metrics header
            const header = "# HELP swerver_stream_requests_total Requests per stream\n# TYPE swerver_stream_requests_total counter\n";
            if (offset2 + header.len <= buf.len) {
                @memcpy(buf[offset2 .. offset2 + header.len], header);
                offset2 += header.len;
            }

            // Write per-stream entries
            for (self.stream_metrics) |entry| {
                if (entry.active) {
                    const line = std.fmt.bufPrint(buf[offset2..],
                        \\swerver_stream_requests_total{{stream_id="{d}"}} {d}
                        \\swerver_stream_responses_total{{stream_id="{d}"}} {d}
                        \\swerver_stream_bytes_sent_total{{stream_id="{d}"}} {d}
                        \\swerver_stream_bytes_received_total{{stream_id="{d}"}} {d}
                        \\
                    , .{
                        entry.stream_id,
                        entry.requests,
                        entry.stream_id,
                        entry.responses,
                        entry.stream_id,
                        entry.bytes_sent,
                        entry.stream_id,
                        entry.bytes_received,
                    }) catch break;
                    offset2 += line.len;
                }
            }
        }

        return buf[0..offset2];
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

    const latency_us = elapsed_ns / 1000;

    store.recordRequest(ctx.protocol);
    store.recordResponse(resp.status, latency_us);

    if (resp.status >= 500) {
        store.recordError();
    }

    store.recordBytes(resp.body.len, 0);

    // Record per-stream metrics for HTTP/2 and HTTP/3
    if (ctx.stream_id != 0) {
        store.recordStreamRequest(ctx.stream_id, ctx.protocol);
        store.recordStreamResponse(ctx.stream_id, ctx.protocol, latency_us, resp.body.len);
    }
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

test "quic metrics tracking" {
    var s = MetricsStore{};

    // Record QUIC connection
    s.recordQuicConnectionAttempt();
    try std.testing.expectEqual(@as(u64, 1), s.quic_connections_attempted);
    try std.testing.expectEqual(@as(u64, 1), s.quic_connections_active);

    // Record handshake complete
    s.recordQuicHandshakeComplete(50); // 50ms
    try std.testing.expectEqual(@as(u64, 1), s.quic_connections_established);
    try std.testing.expectEqual(@as(u64, 50), s.avgQuicHandshakeLatencyMs());

    // Record packets
    s.recordQuicPackets(10, 8, 2);
    try std.testing.expectEqual(@as(u64, 10), s.quic_packets_sent);
    try std.testing.expectEqual(@as(u64, 8), s.quic_packets_received);
    try std.testing.expectEqual(@as(u64, 2), s.quic_packets_lost);

    // Packet loss rate should be 20%
    try std.testing.expect(s.quicPacketLossRate() == 0.2);

    // Record RTT
    s.recordQuicRtt(100_000); // 100ms in microseconds
    s.recordQuicRtt(50_000); // 50ms
    try std.testing.expectEqual(@as(u64, 50_000), s.quic_min_rtt_us);
    try std.testing.expectEqual(@as(u64, 75_000), s.avgQuicRttUs()); // Average of 100ms and 50ms

    // Record connection close
    s.recordQuicConnectionClose(false, false);
    try std.testing.expectEqual(@as(u64, 0), s.quic_connections_active);
}

test "quic metrics prometheus format" {
    var s = MetricsStore{};
    s.recordQuicConnectionAttempt();
    s.recordQuicHandshakeComplete(100);
    s.recordQuicPackets(5, 5, 1);
    s.recordQuicRtt(50_000); // 50ms

    var buf: [16384]u8 = undefined;
    const output = try s.format(&buf);

    // Check QUIC metrics are in output
    try std.testing.expect(std.mem.indexOf(u8, output, "swerver_quic_connections_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "swerver_quic_packets_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "swerver_quic_handshake_duration_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "swerver_quic_rtt_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "swerver_quic_packet_loss_rate") != null);
}
