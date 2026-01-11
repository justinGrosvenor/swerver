const std = @import("std");

/// QUIC Metrics Collection
///
/// Provides statistics about QUIC connections, performance, and errors.
/// Thread-safe for reading; writes should be synchronized by caller.

/// Per-connection metrics
pub const ConnectionMetrics = struct {
    /// Instant when connection was created
    created_at: ?std.time.Instant,
    /// Instant when handshake completed (null if not complete)
    handshake_completed_at: ?std.time.Instant = null,
    /// Current RTT estimate (microseconds)
    rtt_us: u64 = 0,
    /// Minimum RTT observed (microseconds)
    min_rtt_us: u64 = std.math.maxInt(u64),
    /// RTT variance (microseconds)
    rtt_var_us: u64 = 0,
    /// Bytes sent
    bytes_sent: u64 = 0,
    /// Bytes received
    bytes_received: u64 = 0,
    /// Packets sent
    packets_sent: u64 = 0,
    /// Packets received
    packets_received: u64 = 0,
    /// Packets lost (detected by loss recovery)
    packets_lost: u64 = 0,
    /// Packets retransmitted
    packets_retransmitted: u64 = 0,
    /// Current congestion window
    cwnd: u64 = 0,
    /// Bytes in flight
    bytes_in_flight: u64 = 0,
    /// Number of congestion events
    congestion_events: u64 = 0,

    pub fn init() ConnectionMetrics {
        return .{
            .created_at = std.time.Instant.now() catch null,
        };
    }

    /// Mark handshake as complete
    pub fn handshakeComplete(self: *ConnectionMetrics) void {
        self.handshake_completed_at = std.time.Instant.now() catch null;
    }

    /// Get handshake duration in milliseconds (0 if not complete)
    pub fn handshakeLatencyMs(self: *const ConnectionMetrics) u64 {
        const completed = self.handshake_completed_at orelse return 0;
        const created = self.created_at orelse return 0;
        const elapsed_ns = completed.since(created);
        return elapsed_ns / std.time.ns_per_ms;
    }

    /// Get packet loss rate (0.0 - 1.0)
    pub fn packetLossRate(self: *const ConnectionMetrics) f64 {
        if (self.packets_sent == 0) return 0.0;
        return @as(f64, @floatFromInt(self.packets_lost)) / @as(f64, @floatFromInt(self.packets_sent));
    }

    /// Record RTT sample
    pub fn updateRtt(self: *ConnectionMetrics, rtt_us: u64) void {
        // Update min RTT
        self.min_rtt_us = @min(self.min_rtt_us, rtt_us);

        // Exponential moving average for smoothed RTT
        if (self.rtt_us == 0) {
            self.rtt_us = rtt_us;
            self.rtt_var_us = rtt_us / 2;
        } else {
            // RFC 9002 RTT estimation
            const rtt_sample = @as(i64, @intCast(rtt_us));
            const smoothed = @as(i64, @intCast(self.rtt_us));
            const abs_diff: u64 = @intCast(@abs(rtt_sample - smoothed));

            self.rtt_var_us = (3 * self.rtt_var_us + abs_diff) / 4;
            self.rtt_us = (7 * self.rtt_us + rtt_us) / 8;
        }
    }

    /// Record packet sent
    pub fn recordPacketSent(self: *ConnectionMetrics, size: usize) void {
        self.packets_sent += 1;
        self.bytes_sent += size;
    }

    /// Record packet received
    pub fn recordPacketReceived(self: *ConnectionMetrics, size: usize) void {
        self.packets_received += 1;
        self.bytes_received += size;
    }

    /// Record packet loss
    pub fn recordPacketLost(self: *ConnectionMetrics) void {
        self.packets_lost += 1;
    }

    /// Record congestion event
    pub fn recordCongestionEvent(self: *ConnectionMetrics) void {
        self.congestion_events += 1;
    }
};

/// Aggregate server-wide QUIC metrics
pub const ServerMetrics = struct {
    /// Total connections attempted
    connections_attempted: u64 = 0,
    /// Total connections established (handshake complete)
    connections_established: u64 = 0,
    /// Current active connections
    connections_active: u64 = 0,
    /// Connections closed normally
    connections_closed: u64 = 0,
    /// Connections closed due to error
    connections_failed: u64 = 0,
    /// Connections closed due to timeout
    connections_timeout: u64 = 0,
    /// Total bytes sent
    total_bytes_sent: u64 = 0,
    /// Total bytes received
    total_bytes_received: u64 = 0,
    /// Total packets sent
    total_packets_sent: u64 = 0,
    /// Total packets received
    total_packets_received: u64 = 0,
    /// Total packets lost
    total_packets_lost: u64 = 0,
    /// Version negotiation packets sent
    version_negotiation_sent: u64 = 0,
    /// Retry packets sent
    retry_sent: u64 = 0,
    /// Stateless reset packets sent
    stateless_reset_sent: u64 = 0,
    /// Sum of handshake latencies (for averaging)
    handshake_latency_sum_ms: u64 = 0,
    /// Count of completed handshakes (for averaging)
    handshake_count: u64 = 0,

    /// Record a new connection attempt
    pub fn recordConnectionAttempt(self: *ServerMetrics) void {
        _ = @atomicRmw(u64, &self.connections_attempted, .Add, 1, .monotonic);
        _ = @atomicRmw(u64, &self.connections_active, .Add, 1, .monotonic);
    }

    /// Record a successful handshake
    pub fn recordHandshakeComplete(self: *ServerMetrics, latency_ms: u64) void {
        _ = @atomicRmw(u64, &self.connections_established, .Add, 1, .monotonic);
        _ = @atomicRmw(u64, &self.handshake_latency_sum_ms, .Add, latency_ms, .monotonic);
        _ = @atomicRmw(u64, &self.handshake_count, .Add, 1, .monotonic);
    }

    /// Record connection close
    pub fn recordConnectionClose(self: *ServerMetrics, is_error: bool, is_timeout: bool) void {
        _ = @atomicRmw(u64, &self.connections_active, .Sub, 1, .monotonic);
        if (is_timeout) {
            _ = @atomicRmw(u64, &self.connections_timeout, .Add, 1, .monotonic);
        } else if (is_error) {
            _ = @atomicRmw(u64, &self.connections_failed, .Add, 1, .monotonic);
        } else {
            _ = @atomicRmw(u64, &self.connections_closed, .Add, 1, .monotonic);
        }
    }

    /// Record bytes transferred
    pub fn recordBytesTransferred(self: *ServerMetrics, sent: u64, received: u64) void {
        _ = @atomicRmw(u64, &self.total_bytes_sent, .Add, sent, .monotonic);
        _ = @atomicRmw(u64, &self.total_bytes_received, .Add, received, .monotonic);
    }

    /// Record packets
    pub fn recordPackets(self: *ServerMetrics, sent: u64, received: u64, lost: u64) void {
        _ = @atomicRmw(u64, &self.total_packets_sent, .Add, sent, .monotonic);
        _ = @atomicRmw(u64, &self.total_packets_received, .Add, received, .monotonic);
        _ = @atomicRmw(u64, &self.total_packets_lost, .Add, lost, .monotonic);
    }

    /// Get average handshake latency in milliseconds
    pub fn avgHandshakeLatencyMs(self: *const ServerMetrics) u64 {
        const count = @atomicLoad(u64, &self.handshake_count, .monotonic);
        if (count == 0) return 0;
        return @atomicLoad(u64, &self.handshake_latency_sum_ms, .monotonic) / count;
    }

    /// Get overall packet loss rate
    pub fn packetLossRate(self: *const ServerMetrics) f64 {
        const sent = @atomicLoad(u64, &self.total_packets_sent, .monotonic);
        if (sent == 0) return 0.0;
        const lost = @atomicLoad(u64, &self.total_packets_lost, .monotonic);
        return @as(f64, @floatFromInt(lost)) / @as(f64, @floatFromInt(sent));
    }

    /// Format metrics as JSON
    pub fn toJson(self: *const ServerMetrics, buf: []u8) ![]const u8 {
        return std.fmt.bufPrint(buf,
            \\{{"connections":{{"attempted":{d},"established":{d},"active":{d},"closed":{d},"failed":{d},"timeout":{d}}},"bytes":{{"sent":{d},"received":{d}}},"packets":{{"sent":{d},"received":{d},"lost":{d}}},"handshake":{{"avg_latency_ms":{d},"count":{d}}}}}
        , .{
            @atomicLoad(u64, &self.connections_attempted, .monotonic),
            @atomicLoad(u64, &self.connections_established, .monotonic),
            @atomicLoad(u64, &self.connections_active, .monotonic),
            @atomicLoad(u64, &self.connections_closed, .monotonic),
            @atomicLoad(u64, &self.connections_failed, .monotonic),
            @atomicLoad(u64, &self.connections_timeout, .monotonic),
            @atomicLoad(u64, &self.total_bytes_sent, .monotonic),
            @atomicLoad(u64, &self.total_bytes_received, .monotonic),
            @atomicLoad(u64, &self.total_packets_sent, .monotonic),
            @atomicLoad(u64, &self.total_packets_received, .monotonic),
            @atomicLoad(u64, &self.total_packets_lost, .monotonic),
            self.avgHandshakeLatencyMs(),
            @atomicLoad(u64, &self.handshake_count, .monotonic),
        }) catch error.BufferTooSmall;
    }
};

// Tests
test "connection metrics initialization" {
    const m = ConnectionMetrics.init();
    try std.testing.expect(m.created_at != null);
    try std.testing.expect(m.handshake_completed_at == null);
    try std.testing.expectEqual(@as(u64, 0), m.packets_sent);
}

test "connection metrics RTT update" {
    var metrics = ConnectionMetrics.init();

    // First sample sets initial value
    metrics.updateRtt(100_000); // 100ms
    try std.testing.expectEqual(@as(u64, 100_000), metrics.rtt_us);
    try std.testing.expectEqual(@as(u64, 100_000), metrics.min_rtt_us);

    // Lower sample updates min
    metrics.updateRtt(50_000); // 50ms
    try std.testing.expectEqual(@as(u64, 50_000), metrics.min_rtt_us);

    // Smoothed RTT should be updated
    try std.testing.expect(metrics.rtt_us < 100_000);
}

test "connection metrics packet tracking" {
    var metrics = ConnectionMetrics.init();

    metrics.recordPacketSent(1200);
    metrics.recordPacketSent(1200);
    metrics.recordPacketReceived(500);
    metrics.recordPacketLost();

    try std.testing.expectEqual(@as(u64, 2), metrics.packets_sent);
    try std.testing.expectEqual(@as(u64, 2400), metrics.bytes_sent);
    try std.testing.expectEqual(@as(u64, 1), metrics.packets_received);
    try std.testing.expectEqual(@as(u64, 500), metrics.bytes_received);
    try std.testing.expectEqual(@as(u64, 1), metrics.packets_lost);

    // Loss rate should be 50%
    try std.testing.expect(metrics.packetLossRate() == 0.5);
}

test "server metrics atomic operations" {
    var metrics = ServerMetrics{};

    metrics.recordConnectionAttempt();
    try std.testing.expectEqual(@as(u64, 1), metrics.connections_attempted);
    try std.testing.expectEqual(@as(u64, 1), metrics.connections_active);

    metrics.recordHandshakeComplete(50);
    try std.testing.expectEqual(@as(u64, 1), metrics.connections_established);
    try std.testing.expectEqual(@as(u64, 50), metrics.avgHandshakeLatencyMs());

    metrics.recordConnectionClose(false, false);
    try std.testing.expectEqual(@as(u64, 0), metrics.connections_active);
    try std.testing.expectEqual(@as(u64, 1), metrics.connections_closed);
}

test "server metrics JSON output" {
    var metrics = ServerMetrics{};
    metrics.recordConnectionAttempt();
    metrics.recordHandshakeComplete(100);

    var buf: [1024]u8 = undefined;
    const json = try metrics.toJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"attempted\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"established\":1") != null);
}
