const std = @import("std");
const types = @import("types.zig");

/// QUIC Loss Detection and Recovery per RFC 9002.
///
/// Handles:
/// - RTT estimation
/// - Packet tracking and acknowledgment
/// - Loss detection (time-based and packet-based)
/// - PTO (Probe Timeout) calculation

pub const Error = error{
    InvalidPacketNumber,
    OutOfMemory,
};

/// Constants from RFC 9002
pub const Constants = struct {
    /// Initial RTT estimate (333ms)
    pub const initial_rtt_ms: u64 = 333;
    /// Maximum ACK delay (25ms)
    pub const max_ack_delay_ms: u64 = 25;
    /// Time threshold for loss detection (9/8)
    pub const time_threshold_numerator: u64 = 9;
    pub const time_threshold_denominator: u64 = 8;
    /// Packet threshold for loss detection
    pub const packet_threshold: u64 = 3;
    /// Granularity of timers (1ms)
    pub const granularity_ms: u64 = 1;
    /// PTO multiplier for max ACK delay
    pub const pto_multiplier: u64 = 2;
};

/// RTT estimator
pub const RttEstimator = struct {
    /// Latest RTT sample
    latest_rtt: u64 = 0,
    /// Smoothed RTT (EWMA)
    smoothed_rtt: u64 = 0,
    /// RTT variance
    rttvar: u64 = 0,
    /// Minimum RTT observed
    min_rtt: u64 = std.math.maxInt(u64),
    /// Max ACK delay from peer's transport parameters
    max_ack_delay: u64 = Constants.max_ack_delay_ms * std.time.ns_per_ms,
    /// First sample received?
    first_sample: bool = true,

    pub fn init() RttEstimator {
        return .{
            .smoothed_rtt = Constants.initial_rtt_ms * std.time.ns_per_ms,
            .rttvar = Constants.initial_rtt_ms * std.time.ns_per_ms / 2,
        };
    }

    /// Update RTT estimate with a new sample
    pub fn update(self: *RttEstimator, rtt_sample: u64, ack_delay: u64, is_handshake: bool) void {
        self.latest_rtt = rtt_sample;

        // Update min_rtt
        if (rtt_sample < self.min_rtt) {
            self.min_rtt = rtt_sample;
        }

        // Adjust for ACK delay (only for application data)
        var adjusted_rtt = rtt_sample;
        if (!is_handshake and ack_delay < self.max_ack_delay) {
            if (rtt_sample > self.min_rtt + ack_delay) {
                adjusted_rtt = rtt_sample - ack_delay;
            }
        }

        if (self.first_sample) {
            self.smoothed_rtt = adjusted_rtt;
            self.rttvar = adjusted_rtt / 2;
            self.first_sample = false;
        } else {
            // EWMA update
            const rttvar_sample = if (self.smoothed_rtt > adjusted_rtt)
                self.smoothed_rtt - adjusted_rtt
            else
                adjusted_rtt - self.smoothed_rtt;

            self.rttvar = (3 * self.rttvar + rttvar_sample) / 4;
            self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted_rtt) / 8;
        }
    }

    /// Get PTO (Probe Timeout) duration
    pub fn getPto(self: *const RttEstimator) u64 {
        return self.smoothed_rtt + @max(4 * self.rttvar, Constants.granularity_ms * std.time.ns_per_ms) + self.max_ack_delay;
    }

    /// Get loss delay threshold
    pub fn getLossDelay(self: *const RttEstimator) u64 {
        const threshold = @max(self.latest_rtt, self.smoothed_rtt);
        return (threshold * Constants.time_threshold_numerator) / Constants.time_threshold_denominator;
    }
};

/// Sent packet metadata for tracking
pub const SentPacket = struct {
    /// Packet number
    packet_number: u64,
    /// Time sent (nanoseconds, monotonic)
    time_sent: u64,
    /// Size in bytes (for congestion control)
    size: usize,
    /// Is this an ACK-eliciting packet?
    ack_eliciting: bool,
    /// Is this an in-flight packet?
    in_flight: bool,
    /// Packet number space
    space: types.PacketNumberSpace,
    /// Has this been declared lost?
    lost: bool = false,
};

/// Loss detection state for one packet number space
pub const PnSpaceLossState = struct {
    /// Largest ACKed packet number
    largest_acked: ?u64 = null,
    /// Time largest ACKed was sent
    largest_acked_sent_time: ?u64 = null,
    /// Time of last ACK-eliciting packet sent
    time_of_last_ack_eliciting: ?u64 = null,
    /// Loss time (earliest time a packet should be declared lost)
    loss_time: ?u64 = null,
};

/// Recovery manager
pub const Recovery = struct {
    allocator: std.mem.Allocator,
    /// RTT estimator
    rtt: RttEstimator = RttEstimator.init(),
    /// Sent packets awaiting acknowledgment
    sent_packets: std.ArrayList(SentPacket) = .empty,
    /// Loss state per packet number space
    initial_state: PnSpaceLossState = .{},
    handshake_state: PnSpaceLossState = .{},
    application_state: PnSpaceLossState = .{},
    /// PTO count (for exponential backoff)
    pto_count: u32 = 0,
    /// Bytes in flight
    bytes_in_flight: usize = 0,
    /// Packets lost callback
    lost_packets: std.ArrayList(SentPacket) = .empty,

    pub fn init(allocator: std.mem.Allocator) Recovery {
        return Recovery{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Recovery) void {
        self.sent_packets.deinit(self.allocator);
        self.lost_packets.deinit(self.allocator);
    }

    pub fn getState(self: *Recovery, space: types.PacketNumberSpace) *PnSpaceLossState {
        return switch (space) {
            .initial => &self.initial_state,
            .handshake => &self.handshake_state,
            .application => &self.application_state,
        };
    }

    /// Record a sent packet
    pub fn onPacketSent(
        self: *Recovery,
        packet_number: u64,
        space: types.PacketNumberSpace,
        size: usize,
        ack_eliciting: bool,
        now: u64,
    ) Error!void {
        const pkt = SentPacket{
            .packet_number = packet_number,
            .time_sent = now,
            .size = size,
            .ack_eliciting = ack_eliciting,
            .in_flight = ack_eliciting or size > 0,
            .space = space,
        };

        self.sent_packets.append(self.allocator, pkt) catch return Error.OutOfMemory;

        if (pkt.in_flight) {
            self.bytes_in_flight += size;
        }

        if (ack_eliciting) {
            const state = self.getState(space);
            state.time_of_last_ack_eliciting = now;
        }
    }

    /// Process an ACK frame
    pub fn onAckReceived(
        self: *Recovery,
        space: types.PacketNumberSpace,
        largest_acked: u64,
        ack_delay_ns: u64,
        now: u64,
    ) void {
        const state = self.getState(space);

        // Update largest acked
        if (state.largest_acked == null or largest_acked > state.largest_acked.?) {
            state.largest_acked = largest_acked;

            // Find the sent time for RTT calculation
            for (self.sent_packets.items) |pkt| {
                if (pkt.packet_number == largest_acked and pkt.space == space) {
                    state.largest_acked_sent_time = pkt.time_sent;

                    // Update RTT
                    const rtt_sample = now - pkt.time_sent;
                    self.rtt.update(rtt_sample, ack_delay_ns, space != .application);
                    break;
                }
            }
        }

        // Mark packets as acknowledged and detect newly acked
        self.markAcked(space, largest_acked);

        // Detect lost packets
        self.detectLost(space, now);

        // Reset PTO count on successful ACK
        self.pto_count = 0;
    }

    fn markAcked(self: *Recovery, space: types.PacketNumberSpace, largest_acked: u64) void {
        self.markAckedRange(space, 0, largest_acked);
    }

    /// Mark only packets within [smallest, largest] range as acknowledged
    pub fn markAckedRange(self: *Recovery, space: types.PacketNumberSpace, smallest: u64, largest: u64) void {
        var i: usize = 0;
        while (i < self.sent_packets.items.len) {
            const pkt = &self.sent_packets.items[i];
            if (pkt.space == space and pkt.packet_number >= smallest and pkt.packet_number <= largest and !pkt.lost) {
                if (pkt.in_flight) {
                    self.bytes_in_flight -|= pkt.size;
                }
                _ = self.sent_packets.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Detect lost packets using time and packet thresholds
    pub fn detectLost(self: *Recovery, space: types.PacketNumberSpace, now: u64) void {
        const state = self.getState(space);
        const largest_acked = state.largest_acked orelse return;

        state.loss_time = null;
        const loss_delay = self.rtt.getLossDelay();

        for (self.sent_packets.items) |*pkt| {
            if (pkt.space != space or pkt.lost) continue;

            // Time-based loss
            if (now >= pkt.time_sent + loss_delay) {
                pkt.lost = true;
                if (pkt.in_flight) {
                    self.bytes_in_flight -|= pkt.size;
                }
                self.lost_packets.append(self.allocator, pkt.*) catch {};
                continue;
            }

            // Packet-based loss
            if (pkt.packet_number + Constants.packet_threshold <= largest_acked) {
                pkt.lost = true;
                if (pkt.in_flight) {
                    self.bytes_in_flight -|= pkt.size;
                }
                self.lost_packets.append(self.allocator, pkt.*) catch {};
                continue;
            }

            // Update loss time for timer
            const loss_time = pkt.time_sent + loss_delay;
            if (state.loss_time == null or loss_time < state.loss_time.?) {
                state.loss_time = loss_time;
            }
        }

        // Remove lost packets from sent list
        var i: usize = 0;
        while (i < self.sent_packets.items.len) {
            if (self.sent_packets.items[i].lost) {
                _ = self.sent_packets.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Get lost packets slice (caller must process before next detectLost call)
    /// Returns a slice that is valid until the next call to detectLost or drainLostPackets
    pub fn getLostPackets(self: *const Recovery) []const SentPacket {
        return self.lost_packets.items;
    }

    /// Clear the lost packets list after processing
    pub fn clearLostPackets(self: *Recovery) void {
        self.lost_packets.clearRetainingCapacity();
    }

    /// Get the next timeout
    pub fn getTimeout(self: *Recovery) ?u64 {
        // Check loss times
        var earliest: ?u64 = null;

        for ([_]*PnSpaceLossState{ &self.initial_state, &self.handshake_state, &self.application_state }) |state| {
            if (state.loss_time) |lt| {
                if (earliest == null or lt < earliest.?) {
                    earliest = lt;
                }
            }
        }

        if (earliest != null) {
            return earliest;
        }

        // No loss time, use PTO
        if (self.bytes_in_flight == 0 and self.application_state.time_of_last_ack_eliciting == null) {
            return null; // No timeout needed
        }

        // Calculate PTO
        const pto = self.rtt.getPto() * (@as(u64, 1) << @intCast(self.pto_count));

        // Find latest time of ACK-eliciting packet
        var latest_time: u64 = 0;
        for ([_]*PnSpaceLossState{ &self.initial_state, &self.handshake_state, &self.application_state }) |state| {
            if (state.time_of_last_ack_eliciting) |t| {
                if (t > latest_time) {
                    latest_time = t;
                }
            }
        }

        if (latest_time > 0) {
            return latest_time + pto;
        }

        return null;
    }

    /// Handle PTO timeout
    pub fn onPtoTimeout(self: *Recovery) void {
        self.pto_count += 1;
    }

    /// Check if handshake is confirmed (Initial and Handshake spaces can be discarded)
    pub fn discardSpace(self: *Recovery, space: types.PacketNumberSpace) void {
        // Remove all sent packets from this space
        var i: usize = 0;
        while (i < self.sent_packets.items.len) {
            const pkt = &self.sent_packets.items[i];
            if (pkt.space == space) {
                if (pkt.in_flight) {
                    self.bytes_in_flight -|= pkt.size;
                }
                _ = self.sent_packets.orderedRemove(i);
            } else {
                i += 1;
            }
        }

        // Reset state
        const state = self.getState(space);
        state.* = .{};
    }
};

// Tests
test "RTT estimator initialization" {
    const rtt = RttEstimator.init();

    try std.testing.expectEqual(Constants.initial_rtt_ms * std.time.ns_per_ms, rtt.smoothed_rtt);
    try std.testing.expect(rtt.first_sample);
}

test "RTT estimator update" {
    var rtt = RttEstimator.init();

    // First sample
    const sample1: u64 = 100 * std.time.ns_per_ms;
    rtt.update(sample1, 0, true);

    try std.testing.expect(!rtt.first_sample);
    try std.testing.expectEqual(sample1, rtt.smoothed_rtt);
    try std.testing.expectEqual(sample1 / 2, rtt.rttvar);
    try std.testing.expectEqual(sample1, rtt.min_rtt);

    // Second sample (lower)
    const sample2: u64 = 80 * std.time.ns_per_ms;
    rtt.update(sample2, 0, true);

    try std.testing.expectEqual(sample2, rtt.min_rtt);
    // smoothed_rtt should decrease
    try std.testing.expect(rtt.smoothed_rtt < sample1);
}

test "recovery packet tracking" {
    const allocator = std.testing.allocator;
    var recovery = Recovery.init(allocator);
    defer recovery.deinit();

    const now: u64 = 1_000_000_000; // 1 second

    // Send some packets
    try recovery.onPacketSent(0, .initial, 1200, true, now);
    try recovery.onPacketSent(1, .initial, 1200, true, now + 10_000_000);

    try std.testing.expectEqual(@as(usize, 2), recovery.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 2400), recovery.bytes_in_flight);
}

test "recovery ACK processing" {
    const allocator = std.testing.allocator;
    var recovery = Recovery.init(allocator);
    defer recovery.deinit();

    const t0: u64 = 1_000_000_000;
    const t1: u64 = t0 + 100_000_000; // 100ms later

    // Send packets
    try recovery.onPacketSent(0, .initial, 1200, true, t0);
    try recovery.onPacketSent(1, .initial, 1200, true, t0 + 10_000_000);

    // Receive ACK for packet 1
    recovery.onAckReceived(.initial, 1, 0, t1);

    // Both should be acknowledged (ACK implies all packets up to largest)
    try std.testing.expectEqual(@as(usize, 0), recovery.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
}

test "loss detection time-based" {
    const allocator = std.testing.allocator;
    var recovery = Recovery.init(allocator);
    defer recovery.deinit();

    const t0: u64 = 1_000_000_000; // 1 second
    const rtt: u64 = 100 * std.time.ns_per_ms; // 100ms RTT

    // Send packets
    try recovery.onPacketSent(0, .application, 1200, true, t0);
    try recovery.onPacketSent(1, .application, 1200, true, t0 + 10_000_000);
    try recovery.onPacketSent(2, .application, 1200, true, t0 + 20_000_000);

    // Update RTT with a sample
    recovery.rtt.update(rtt, 0, false);

    // Set largest_acked to enable loss detection
    recovery.application_state.largest_acked = 2;

    // Get loss delay (should be ~112.5ms based on 100ms RTT * 9/8)
    const loss_delay = recovery.rtt.getLossDelay();

    // Detect losses after enough time has passed
    recovery.detectLost(.application, t0 + loss_delay + 1);

    // Packet 0 should be lost (oldest, enough time elapsed since it was sent)
    try std.testing.expectEqual(@as(usize, 1), recovery.lost_packets.items.len);
    try std.testing.expectEqual(@as(u64, 0), recovery.lost_packets.items[0].packet_number);
}

test "PTO calculation" {
    var recovery = Recovery.init(std.testing.allocator);
    defer recovery.deinit();

    // Initial PTO
    const pto = recovery.rtt.getPto();

    // Should be roughly initial_rtt + 4*rttvar + max_ack_delay
    const expected = Constants.initial_rtt_ms * std.time.ns_per_ms +
        4 * (Constants.initial_rtt_ms * std.time.ns_per_ms / 2) +
        Constants.max_ack_delay_ms * std.time.ns_per_ms;

    try std.testing.expectEqual(expected, pto);

    // PTO should increase after timeout
    recovery.onPtoTimeout();
    try std.testing.expectEqual(@as(u32, 1), recovery.pto_count);
}
