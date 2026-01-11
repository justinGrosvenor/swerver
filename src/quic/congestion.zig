const std = @import("std");

/// QUIC Congestion Control per RFC 9002.
///
/// Implements NewReno congestion control:
/// - Slow start
/// - Congestion avoidance
/// - Loss recovery

pub const Error = error{
    InvalidState,
};

/// Constants for congestion control
pub const Constants = struct {
    /// Initial congestion window (in bytes) - 10 * max_datagram_size or 14720
    pub const initial_window: usize = 14720;
    /// Minimum congestion window (2 * max_datagram_size)
    pub const minimum_window: usize = 2400;
    /// Maximum datagram size
    pub const max_datagram_size: usize = 1200;
    /// Loss reduction factor (divide by 2)
    pub const loss_reduction_factor: usize = 2;
};

/// Congestion controller state
pub const CongestionState = enum {
    /// Exponential growth phase
    slow_start,
    /// Linear growth phase
    congestion_avoidance,
    /// Recovering from loss
    recovery,
};

/// NewReno Congestion Controller
pub const CongestionController = struct {
    /// Current congestion window (bytes)
    congestion_window: usize = Constants.initial_window,
    /// Bytes in flight
    bytes_in_flight: usize = 0,
    /// Slow start threshold
    ssthresh: usize = std.math.maxInt(usize),
    /// Current state
    state: CongestionState = .slow_start,
    /// Bytes acknowledged since last window increase (for congestion avoidance)
    bytes_acked: usize = 0,
    /// Recovery start time (packet number that triggered recovery)
    recovery_start_pn: ?u64 = null,
    /// ECN-CE counter
    ecn_ce_count: u64 = 0,

    pub fn init() CongestionController {
        return .{};
    }

    /// Check if we can send more data
    pub fn canSend(self: *const CongestionController, bytes: usize) bool {
        return self.bytes_in_flight + bytes <= self.congestion_window;
    }

    /// Get available window (bytes we can send)
    pub fn availableWindow(self: *const CongestionController) usize {
        if (self.bytes_in_flight >= self.congestion_window) {
            return 0;
        }
        return self.congestion_window - self.bytes_in_flight;
    }

    /// Called when a packet is sent
    pub fn onPacketSent(self: *CongestionController, bytes: usize) void {
        self.bytes_in_flight += bytes;
    }

    /// Called when a packet is acknowledged
    pub fn onPacketAcked(self: *CongestionController, bytes: usize, packet_number: u64) void {
        self.bytes_in_flight -|= bytes;

        // Don't increase window during recovery for packets sent before recovery
        if (self.recovery_start_pn) |recovery_pn| {
            if (packet_number < recovery_pn) {
                return;
            }
            // Exiting recovery
            self.recovery_start_pn = null;
            self.state = .congestion_avoidance;
        }

        // Increase congestion window
        switch (self.state) {
            .slow_start => {
                // Increase by bytes acked
                self.congestion_window += bytes;
                if (self.congestion_window >= self.ssthresh) {
                    self.state = .congestion_avoidance;
                }
            },
            .congestion_avoidance => {
                // Increase by ~1 MSS per RTT (bytes_acked / cwnd * MSS)
                self.bytes_acked += bytes;
                if (self.bytes_acked >= self.congestion_window) {
                    self.congestion_window += Constants.max_datagram_size;
                    self.bytes_acked = 0;
                }
            },
            .recovery => {
                // Don't increase during recovery
            },
        }
    }

    /// Called when congestion is detected (packet loss or ECN-CE)
    pub fn onCongestionEvent(self: *CongestionController, sent_pn: u64) void {
        // Don't react to loss of packets sent before recovery started
        if (self.recovery_start_pn) |recovery_pn| {
            if (sent_pn < recovery_pn) {
                return;
            }
        }

        // Enter recovery
        self.recovery_start_pn = sent_pn;
        self.state = .recovery;

        // Reduce congestion window
        self.ssthresh = self.congestion_window / Constants.loss_reduction_factor;
        self.congestion_window = @max(self.ssthresh, Constants.minimum_window);
        self.bytes_acked = 0;
    }

    /// Called when a packet is lost
    pub fn onPacketLost(self: *CongestionController, bytes: usize, packet_number: u64) void {
        self.bytes_in_flight -|= bytes;
        self.onCongestionEvent(packet_number);
    }

    /// Called on persistent congestion (2 * PTO without ACK)
    pub fn onPersistentCongestion(self: *CongestionController) void {
        self.congestion_window = Constants.minimum_window;
        self.ssthresh = Constants.minimum_window;
        self.state = .slow_start;
        self.recovery_start_pn = null;
    }

    /// Called when ECN-CE is received
    pub fn onEcnCeReceived(self: *CongestionController, ce_count: u64, sent_pn: u64) void {
        if (ce_count > self.ecn_ce_count) {
            self.ecn_ce_count = ce_count;
            self.onCongestionEvent(sent_pn);
        }
    }

    /// Reset for a new path
    pub fn onPathChange(self: *CongestionController) void {
        self.congestion_window = Constants.initial_window;
        self.ssthresh = std.math.maxInt(usize);
        self.bytes_in_flight = 0;
        self.bytes_acked = 0;
        self.state = .slow_start;
        self.recovery_start_pn = null;
    }

    /// Get current congestion window
    pub fn getCongestionWindow(self: *const CongestionController) usize {
        return self.congestion_window;
    }

    /// Check if in slow start
    pub fn isSlowStart(self: *const CongestionController) bool {
        return self.state == .slow_start;
    }

    /// Check if in recovery
    pub fn isRecovering(self: *const CongestionController) bool {
        return self.state == .recovery;
    }
};

/// Pacing controller for smooth packet transmission
pub const Pacer = struct {
    /// Tokens available for sending (in bytes)
    tokens: usize = 0,
    /// Last time tokens were added
    last_update: u64 = 0,
    /// Pacing rate (bytes per nanosecond)
    rate: u64 = 0,
    /// Maximum burst size
    max_burst: usize = Constants.initial_window,

    pub fn init() Pacer {
        return .{};
    }

    /// Update pacing rate based on congestion window and RTT
    pub fn updateRate(self: *Pacer, congestion_window: usize, smoothed_rtt: u64) void {
        if (smoothed_rtt == 0) {
            self.rate = 0;
            return;
        }
        // rate = cwnd / rtt (with 25% headroom: cwnd * 1.25 / rtt)
        // Compute as: (cwnd * 5 * ns_per_s) / (4 * rtt) to avoid division by zero
        // when rtt < ns_per_s
        const numerator: u128 = @as(u128, congestion_window) * 5 * std.time.ns_per_s;
        const denominator: u128 = @as(u128, 4) * smoothed_rtt;
        self.rate = @intCast(@min(numerator / denominator, std.math.maxInt(u64)));
    }

    /// Add tokens based on elapsed time
    pub fn addTokens(self: *Pacer, now: u64) void {
        if (self.last_update == 0) {
            self.last_update = now;
            self.tokens = self.max_burst;
            return;
        }

        const elapsed = now - self.last_update;
        self.last_update = now;

        if (self.rate > 0) {
            const new_tokens = (elapsed * self.rate) / std.time.ns_per_s;
            self.tokens = @min(self.tokens + @as(usize, @intCast(new_tokens)), self.max_burst);
        }
    }

    /// Check if we can send bytes
    pub fn canSend(self: *const Pacer, bytes: usize) bool {
        return self.tokens >= bytes;
    }

    /// Consume tokens when sending
    pub fn onPacketSent(self: *Pacer, bytes: usize) void {
        self.tokens -|= bytes;
    }

    /// Get time until we can send (in nanoseconds)
    pub fn timeUntilSend(self: *const Pacer, bytes: usize) u64 {
        if (self.tokens >= bytes or self.rate == 0) {
            return 0;
        }
        const needed = bytes - self.tokens;
        return (needed * std.time.ns_per_s) / @as(usize, @intCast(@max(1, self.rate)));
    }
};

// Tests
test "congestion controller initialization" {
    var cc = CongestionController.init();

    try std.testing.expectEqual(Constants.initial_window, cc.congestion_window);
    try std.testing.expectEqual(CongestionState.slow_start, cc.state);
    try std.testing.expect(cc.canSend(1200));
}

test "slow start growth" {
    var cc = CongestionController.init();

    // Send a packet
    cc.onPacketSent(1200);
    try std.testing.expectEqual(@as(usize, 1200), cc.bytes_in_flight);

    // ACK the packet - window should grow
    cc.onPacketAcked(1200, 0);
    try std.testing.expectEqual(@as(usize, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(Constants.initial_window + 1200, cc.congestion_window);
}

test "congestion avoidance" {
    var cc = CongestionController.init();

    // Force into congestion avoidance
    cc.ssthresh = Constants.initial_window;
    cc.state = .congestion_avoidance;

    const initial_cwnd = cc.congestion_window;

    // ACK one full window's worth
    var acked: usize = 0;
    while (acked < initial_cwnd) {
        cc.onPacketAcked(1200, 0);
        acked += 1200;
    }

    // Should have increased by one MSS
    try std.testing.expectEqual(initial_cwnd + Constants.max_datagram_size, cc.congestion_window);
}

test "loss reduces window" {
    var cc = CongestionController.init();

    // Send some packets
    cc.onPacketSent(1200);
    cc.onPacketSent(1200);

    const cwnd_before = cc.congestion_window;

    // Lose a packet
    cc.onPacketLost(1200, 0);

    // Window should be halved (but not below minimum)
    try std.testing.expect(cc.congestion_window < cwnd_before);
    try std.testing.expect(cc.congestion_window >= Constants.minimum_window);
    try std.testing.expectEqual(CongestionState.recovery, cc.state);
}

test "recovery exit" {
    var cc = CongestionController.init();

    // Enter recovery
    cc.onPacketLost(1200, 5);
    try std.testing.expectEqual(CongestionState.recovery, cc.state);

    // ACK a packet sent after recovery started
    cc.onPacketAcked(1200, 10);

    // Should exit recovery
    try std.testing.expectEqual(CongestionState.congestion_avoidance, cc.state);
}

test "persistent congestion" {
    var cc = CongestionController.init();

    // Grow window
    cc.onPacketAcked(1200, 0);
    cc.onPacketAcked(1200, 1);

    // Persistent congestion resets to minimum
    cc.onPersistentCongestion();

    try std.testing.expectEqual(Constants.minimum_window, cc.congestion_window);
    try std.testing.expectEqual(CongestionState.slow_start, cc.state);
}

test "available window calculation" {
    var cc = CongestionController.init();

    try std.testing.expectEqual(Constants.initial_window, cc.availableWindow());

    cc.onPacketSent(5000);
    try std.testing.expectEqual(Constants.initial_window - 5000, cc.availableWindow());

    // Fill window
    cc.onPacketSent(Constants.initial_window - 5000);
    try std.testing.expectEqual(@as(usize, 0), cc.availableWindow());
    try std.testing.expect(!cc.canSend(1));
}
