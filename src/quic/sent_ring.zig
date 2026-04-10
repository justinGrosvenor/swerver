const std = @import("std");
const types = @import("types.zig");

/// Zero-allocation ring buffer for tracking sent QUIC packets.
///
/// Sized to 512 entries (16 KiB per connection), which gives ~8×
/// headroom over the typical congestion-window size of 64 packets.
///
/// All scans (markAckedRange, detectLost, findSentTime) iterate the
/// bitmap at the WORD level — an empty 64-bit word skips 64 slots in
/// one comparison. Within a word, only set bits are visited via @ctz.
/// For a typical ring with ~10-20 in-flight packets out of 512 slots,
/// this makes scans O(popcount ≈ 10) instead of O(512).

pub const RING_SIZE: usize = 512;
const WORDS: usize = RING_SIZE / 64;

pub const SentPacket = struct {
    packet_number: u64,
    time_sent: u64, // monotonic nanoseconds
    size: u16, // bytes on the wire (max UDP datagram ~1500)
    space: types.PacketNumberSpace,
    ack_eliciting: bool,
    in_flight: bool,
};

pub const LostPacket = struct {
    packet_number: u64,
    size: u16,
    space: types.PacketNumberSpace,
};

pub const SentRing = struct {
    entries: [RING_SIZE]SentPacket = undefined,
    /// Bit per slot: 1 = occupied, 0 = free.
    occupied: [WORDS]u64 = [_]u64{0} ** WORDS,
    /// Next write position (wraps at RING_SIZE).
    tail: usize = 0,
    /// Number of occupied slots.
    count: usize = 0,
    /// Total bytes in flight (for congestion control).
    bytes_in_flight: usize = 0,

    // ---- Bit helpers ----

    fn isOccupied(self: *const SentRing, idx: usize) bool {
        return (self.occupied[idx / 64] & (@as(u64, 1) << @intCast(idx % 64))) != 0;
    }

    fn setOccupied(self: *SentRing, idx: usize) void {
        self.occupied[idx / 64] |= @as(u64, 1) << @intCast(idx % 64);
    }

    fn clearOccupied(self: *SentRing, idx: usize) void {
        self.occupied[idx / 64] &= ~(@as(u64, 1) << @intCast(idx % 64));
    }

    // ---- Public API ----

    /// Record a sent packet. O(1). If the ring is full, the entry at
    /// `tail` is silently overwritten (evicted).
    pub fn push(self: *SentRing, pkt: SentPacket) void {
        if (self.isOccupied(self.tail)) {
            self.evict(self.tail);
        }
        self.entries[self.tail] = pkt;
        self.setOccupied(self.tail);
        self.count += 1;
        if (pkt.in_flight) self.bytes_in_flight += pkt.size;
        self.tail = (self.tail + 1) % RING_SIZE;
    }

    /// Mark all packets in [smallest, largest] for the given space as
    /// acknowledged and remove them from the ring. Returns the sent
    /// time of `largest` if found (for RTT calculation), or null.
    ///
    /// O(popcount of occupied bitmap) — skips empty 64-bit words.
    pub fn markAckedRange(
        self: *SentRing,
        space: types.PacketNumberSpace,
        smallest: u64,
        largest: u64,
    ) ?u64 {
        var largest_sent_time: ?u64 = null;
        for (&self.occupied, 0..) |*word, word_idx| {
            var bits = word.*;
            if (bits == 0) continue;
            while (bits != 0) {
                const bit_idx: u6 = @intCast(@ctz(bits));
                const idx = word_idx * 64 + bit_idx;
                const pkt = &self.entries[idx];
                if (pkt.space == space and
                    pkt.packet_number >= smallest and
                    pkt.packet_number <= largest)
                {
                    if (pkt.packet_number == largest) {
                        largest_sent_time = pkt.time_sent;
                    }
                    if (pkt.in_flight) self.bytes_in_flight -|= pkt.size;
                    self.count -|= 1;
                    word.* &= ~(@as(u64, 1) << bit_idx);
                    // Update bits for this iteration too
                    bits &= bits - 1;
                    continue;
                }
                bits &= bits - 1;
            }
        }
        return largest_sent_time;
    }

    /// Detect lost packets using RFC 9002 time-threshold and packet-
    /// threshold algorithms. Returns the number of packets declared
    /// lost (written into `out`).
    ///
    /// O(popcount of occupied bitmap).
    pub fn detectLost(
        self: *SentRing,
        space: types.PacketNumberSpace,
        largest_acked: u64,
        loss_delay_ns: u64,
        now: u64,
        out: []LostPacket,
        loss_time: *?u64,
    ) usize {
        var n: usize = 0;
        loss_time.* = null;

        for (&self.occupied, 0..) |*word, word_idx| {
            var bits = word.*;
            if (bits == 0) continue;
            while (bits != 0) {
                const bit_idx: u6 = @intCast(@ctz(bits));
                const idx = word_idx * 64 + bit_idx;
                const pkt = &self.entries[idx];

                if (pkt.space != space) {
                    bits &= bits - 1;
                    continue;
                }

                // Time-based loss
                if (now >= pkt.time_sent + loss_delay_ns) {
                    if (n < out.len) {
                        out[n] = .{ .packet_number = pkt.packet_number, .size = pkt.size, .space = pkt.space };
                        n += 1;
                    }
                    if (pkt.in_flight) self.bytes_in_flight -|= pkt.size;
                    self.count -|= 1;
                    word.* &= ~(@as(u64, 1) << bit_idx);
                    bits &= bits - 1;
                    continue;
                }

                // Packet-threshold loss
                if (pkt.packet_number + 3 <= largest_acked) {
                    if (n < out.len) {
                        out[n] = .{ .packet_number = pkt.packet_number, .size = pkt.size, .space = pkt.space };
                        n += 1;
                    }
                    if (pkt.in_flight) self.bytes_in_flight -|= pkt.size;
                    self.count -|= 1;
                    word.* &= ~(@as(u64, 1) << bit_idx);
                    bits &= bits - 1;
                    continue;
                }

                // Update loss_time for the timer
                const lt = pkt.time_sent + loss_delay_ns;
                if (loss_time.* == null or lt < loss_time.*.?) {
                    loss_time.* = lt;
                }
                bits &= bits - 1;
            }
        }
        return n;
    }

    /// Find the sent time of a specific packet number in a space.
    /// O(popcount of occupied bitmap).
    pub fn findSentTime(self: *const SentRing, space: types.PacketNumberSpace, pn: u64) ?u64 {
        for (0..WORDS) |word_idx| {
            var bits = self.occupied[word_idx];
            if (bits == 0) continue;
            while (bits != 0) {
                const bit_idx: u6 = @intCast(@ctz(bits));
                const idx = word_idx * 64 + bit_idx;
                const pkt = &self.entries[idx];
                if (pkt.space == space and pkt.packet_number == pn) {
                    return pkt.time_sent;
                }
                bits &= bits - 1;
            }
        }
        return null;
    }

    // ---- Internal ----

    fn evict(self: *SentRing, idx: usize) void {
        if (self.entries[idx].in_flight) {
            self.bytes_in_flight -|= self.entries[idx].size;
        }
        self.clearOccupied(idx);
        self.count -|= 1;
    }
};

// ---- Tests ----

test "SentRing: push and find" {
    var ring: SentRing = .{};
    ring.push(.{
        .packet_number = 42,
        .time_sent = 1000,
        .size = 1200,
        .space = .application,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try std.testing.expectEqual(@as(usize, 1), ring.count);
    try std.testing.expectEqual(@as(usize, 1200), ring.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 1000), ring.findSentTime(.application, 42));
    try std.testing.expectEqual(@as(?u64, null), ring.findSentTime(.application, 43));
}

test "SentRing: markAckedRange removes packets" {
    var ring: SentRing = .{};
    for (0..10) |i| {
        ring.push(.{
            .packet_number = i,
            .time_sent = 1000 + i * 100,
            .size = 100,
            .space = .application,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    try std.testing.expectEqual(@as(usize, 10), ring.count);
    try std.testing.expectEqual(@as(usize, 1000), ring.bytes_in_flight);

    // ACK [3, 7]
    const sent_time = ring.markAckedRange(.application, 3, 7);
    try std.testing.expectEqual(@as(?u64, 1700), sent_time); // pn=7 sent at 1700
    try std.testing.expectEqual(@as(usize, 5), ring.count); // 0,1,2,8,9 remain
    try std.testing.expectEqual(@as(usize, 500), ring.bytes_in_flight);
}

test "SentRing: detectLost with packet threshold" {
    var ring: SentRing = .{};
    for (0..10) |i| {
        ring.push(.{
            .packet_number = i,
            .time_sent = 1000 + i * 100,
            .size = 100,
            .space = .application,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    // ACK pn=9 — packets 0..6 are 3+ behind largest_acked(9)
    _ = ring.markAckedRange(.application, 9, 9);
    try std.testing.expectEqual(@as(usize, 9), ring.count);

    var lost: [16]LostPacket = undefined;
    var loss_time: ?u64 = null;
    const n = ring.detectLost(
        .application,
        9, // largest_acked
        1_000_000_000, // large loss_delay so time-based doesn't fire
        2000, // now
        &lost,
        &loss_time,
    );
    // Packets 0..6 are lost (pn + 3 <= 9)
    try std.testing.expectEqual(@as(usize, 7), n);
    // Packets 7, 8 remain (not yet 3 behind)
    try std.testing.expectEqual(@as(usize, 2), ring.count);
}

test "SentRing: overflow evicts oldest" {
    var ring: SentRing = .{};
    for (0..RING_SIZE) |i| {
        ring.push(.{
            .packet_number = i,
            .time_sent = 1000 + i,
            .size = 10,
            .space = .application,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    try std.testing.expectEqual(@as(usize, RING_SIZE), ring.count);

    ring.push(.{
        .packet_number = RING_SIZE,
        .time_sent = 9999,
        .size = 10,
        .space = .application,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try std.testing.expectEqual(@as(usize, RING_SIZE), ring.count);
    try std.testing.expectEqual(@as(?u64, null), ring.findSentTime(.application, 0));
    try std.testing.expectEqual(@as(?u64, 9999), ring.findSentTime(.application, RING_SIZE));
}
