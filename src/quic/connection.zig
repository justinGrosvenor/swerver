const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const varint = @import("varint.zig");
pub const metrics = @import("metrics.zig");
const tls = @import("../tls/provider.zig");
const stream = @import("stream.zig");
const recovery_mod = @import("recovery.zig");
const sent_ring = @import("sent_ring.zig");
const congestion_mod = @import("congestion.zig");
const http3 = @import("../protocol/http3.zig");
const clock = @import("../runtime/clock.zig");

/// QUIC Connection State Machine per RFC 9000.
///
/// Manages:
/// - Connection lifecycle (states, handshake)
/// - Packet number spaces
/// - Connection-level flow control
/// - Transport parameters

pub const Error = error{
    InvalidState,
    ConnectionClosed,
    FlowControlError,
    StreamLimitExceeded,
    ProtocolViolation,
    HandshakeFailed,
    InvalidPacket,
    CryptoError,
    OutOfMemory,
    TlsError,
};

/// Connection states per RFC 9000 Section 10
pub const State = enum {
    /// Initial state, waiting for or sending Initial packets
    initial,
    /// Handshake in progress
    handshaking,
    /// Connection established, can send application data
    connected,
    /// Initiated connection close, waiting for peer acknowledgment
    closing,
    /// Received connection close, waiting for timeout
    draining,
    /// Connection fully closed
    closed,
};

/// Packet number space tracking
pub const PacketNumberSpace = struct {
    /// Next packet number to send
    next_pn: u64 = 0,
    /// Largest acknowledged packet number (-1 means none acked yet)
    largest_acked: ?u64 = null,
    /// Largest received packet number
    largest_received: ?u64 = null,
    /// Smallest received packet number (set on the first onPacketReceived
    /// call). Used together with largest_received to compute the
    /// First ACK Range field for outgoing ACK frames — we ack
    /// [smallest_received, largest_received] as one contiguous range.
    /// This is correct as long as we never drop a packet in the middle
    /// of the range; missing-packet handling is a follow-up that needs
    /// real ack range tracking.
    smallest_received: ?u64 = null,
    /// Sliding-window receive bitmap for dedupe + ack-range building.
    /// Bit i (set) means we received packet number `bitmap_base + i` and
    /// have already processed it. Lets us drop duplicate retransmits
    /// without reprocessing them through the application layer.
    bitmap: u64 = 0,
    bitmap_base: u64 = 0,
    /// Timestamp when largest packet was received (microseconds since epoch)
    largest_received_time: ?u64 = null,
    /// ACK ranges to send (simple: just track largest for now)
    ack_needed: bool = false,
    /// Crypto keys for this space
    keys: ?crypto.Keys = null,

    /// Get the next packet number and increment
    pub fn allocatePacketNumber(self: *PacketNumberSpace) u64 {
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }

    /// Record that a packet was received
    pub fn onPacketReceived(self: *PacketNumberSpace, pn: u64) void {
        self.onPacketReceivedAt(pn, getCurrentTimeMicros());
    }

    /// Record that a packet was received at a specific time
    pub fn onPacketReceivedAt(self: *PacketNumberSpace, pn: u64, time_us: u64) void {
        if (self.largest_received) |largest| {
            if (pn > largest) {
                self.largest_received = pn;
                self.largest_received_time = time_us;
            }
        } else {
            self.largest_received = pn;
            self.largest_received_time = time_us;
        }
        // Track the smallest pn we've seen so we can build accurate ACK
        // ranges when packet numbers don't start from 0 (e.g., 1-RTT pns
        // that arrived before handshake completion were silently dropped).
        if (self.smallest_received) |smallest| {
            if (pn < smallest) self.smallest_received = pn;
        } else {
            self.smallest_received = pn;
        }
        self.markReceivedInBitmap(pn);
        self.ack_needed = true;
    }

    /// Mark a packet as received in the dedupe bitmap. The bitmap is a
    /// 64-bit sliding window: bit i represents (bitmap_base + i). When a
    /// packet arrives with pn beyond the window, slide the window forward.
    fn markReceivedInBitmap(self: *PacketNumberSpace, pn: u64) void {
        // First-ever packet: anchor the window at this pn
        if (self.bitmap == 0 and self.bitmap_base == 0 and self.largest_received == pn) {
            self.bitmap_base = pn;
        }
        if (pn < self.bitmap_base) return; // can't track packets older than the window
        const offset_in_window = pn - self.bitmap_base;
        if (offset_in_window >= 64) {
            // Slide window so the new pn is the highest bit (63)
            const slide = offset_in_window - 63;
            if (slide >= 64) {
                self.bitmap = 0;
            } else {
                self.bitmap >>= @intCast(slide);
            }
            self.bitmap_base += slide;
        }
        const new_offset = pn - self.bitmap_base;
        self.bitmap |= @as(u64, 1) << @intCast(new_offset);
    }

    /// Has this packet number already been processed (i.e., is its bit
    /// set in the receive bitmap, or is it older than the window)?
    /// Lets the receive path skip re-processing duplicate retransmits.
    pub fn isDuplicate(self: *const PacketNumberSpace, pn: u64) bool {
        if (pn < self.bitmap_base) return true; // outside the window — assume seen
        const offset_in_window = pn - self.bitmap_base;
        if (offset_in_window >= 64) return false; // too new, not seen
        return (self.bitmap & (@as(u64, 1) << @intCast(offset_in_window))) != 0;
    }

    /// Compute the First ACK Range field for an outgoing ACK frame:
    /// the number of contiguous packets immediately preceding
    /// largest_received that are also marked received in the bitmap.
    /// Single-range form — use `collectAckRanges` to also fill in
    /// additional ranges for multi-range ACK frames on lossy paths.
    pub fn firstAckRange(self: *const PacketNumberSpace) u64 {
        const result = self.collectAckRanges(&[_]frame.AckRange{});
        return result.first_range;
    }

    /// Result of `collectAckRanges`: the First ACK Range value plus
    /// the number of (gap, length) pairs written into the caller-
    /// provided buffer.
    pub const AckRangesResult = struct {
        first_range: u64,
        additional_count: usize,
    };

    /// Walk the receive bitmap backward from `largest_received` and
    /// collect ACK range metadata suitable for a multi-range ACK
    /// frame (RFC 9000 §19.3.1). Returns the First ACK Range value
    /// and writes up to `out.len` additional (gap, length) pairs in
    /// descending packet-number order.
    ///
    /// Each additional entry in `out` encodes the next acknowledged
    /// run of packets after a gap:
    ///   - `gap` = number of contiguous unacknowledged packets
    ///     preceding the packet one lower than the smallest in the
    ///     preceding range, encoded as length-1.
    ///   - `length` = (count of packets in this range) - 1.
    ///
    /// Runs out gracefully on empty bitmap, out-of-window
    /// `largest_received`, or an `out` buffer of length zero (in
    /// which case it just computes and returns `first_range`, which
    /// is what `firstAckRange` does internally).
    pub fn collectAckRanges(self: *const PacketNumberSpace, out: []frame.AckRange) AckRangesResult {
        const empty = AckRangesResult{ .first_range = 0, .additional_count = 0 };

        const largest = self.largest_received orelse return empty;
        if (largest < self.bitmap_base) return empty;
        const largest_offset_u = largest - self.bitmap_base;
        if (largest_offset_u >= 64) return empty;

        var i: i32 = @intCast(largest_offset_u);

        // First range: count contiguous set bits immediately preceding
        // the largest_received bit (same semantics as the old
        // firstAckRange — length-1 encoding, i.e. "number of packets
        // before largest that are also acked").
        i -= 1;
        var first_range: u64 = 0;
        while (i >= 0) : (i -= 1) {
            const bit = self.bitmap & (@as(u64, 1) << @intCast(i));
            if (bit == 0) break;
            first_range += 1;
        }

        // Early exit if the caller doesn't want additional ranges.
        if (out.len == 0) return .{ .first_range = first_range, .additional_count = 0 };

        // Smallest packet in the first range (absolute).
        // largest - first_range is the smallest packet included.
        var prev_smallest_abs: u64 = largest - first_range;

        var additional_count: usize = 0;
        while (i >= 0 and additional_count < out.len) {
            // Skip the gap (contiguous clear bits) until we either hit
            // a set bit (start of next range) or run out of window.
            while (i >= 0) : (i -= 1) {
                const bit = self.bitmap & (@as(u64, 1) << @intCast(i));
                if (bit != 0) break;
            }
            if (i < 0) break;

            // `i` now points at the largest set bit of the next range.
            const next_largest_offset: u64 = @intCast(i);
            const next_largest_abs: u64 = self.bitmap_base + next_largest_offset;

            // Count the remaining set bits in this range. Skip the
            // largest bit itself (already accounted for) and count
            // backward — length-1 encoding, matching first_range.
            var next_length: u64 = 0;
            i -= 1;
            while (i >= 0) : (i -= 1) {
                const bit = self.bitmap & (@as(u64, 1) << @intCast(i));
                if (bit == 0) break;
                next_length += 1;
            }

            // Gap = (prev range smallest) - (this range largest) - 2.
            // By construction there's at least one unacknowledged packet
            // between the two ranges (we just walked over at least one
            // clear bit), so prev.smallest >= next.largest + 2 and the
            // subtraction can't underflow.
            const gap = prev_smallest_abs - next_largest_abs - 2;

            out[additional_count] = .{
                .gap = gap,
                .length = next_length,
            };
            additional_count += 1;

            // Smallest packet in this range becomes the "prev" for the
            // next iteration.
            prev_smallest_abs = next_largest_abs - next_length;
        }

        return .{ .first_range = first_range, .additional_count = additional_count };
    }

    /// Record that an ACK was received
    pub fn onAckReceived(self: *PacketNumberSpace, largest_acked: u64) void {
        if (self.largest_acked) |current| {
            if (largest_acked > current) {
                self.largest_acked = largest_acked;
            }
        } else {
            self.largest_acked = largest_acked;
        }
    }

    /// Calculate ACK delay from when largest packet was received to now
    /// Returns delay in microseconds
    pub fn calculateAckDelay(self: *const PacketNumberSpace) u64 {
        const recv_time = self.largest_received_time orelse return 0;
        const now = getCurrentTimeMicros();
        if (now > recv_time) {
            return now - recv_time;
        }
        return 0;
    }
};

// Starting instant for relative time calculation
var start_instant: ?clock.Instant = null;

/// Get current time in microseconds (relative to first call)
fn getCurrentTimeMicros() u64 {
    const now_inst = clock.Instant.now() orelse return 0;

    if (start_instant == null) {
        start_instant = now_inst;
        return 0;
    }

    // Return nanoseconds since start, converted to microseconds
    const ns = now_inst.since(start_instant.?);
    return ns / 1000;
}

/// Transport parameter identifiers (RFC 9000 §18.2)
pub const TpId = struct {
    pub const original_destination_connection_id: u64 = 0x00;
    pub const max_idle_timeout: u64 = 0x01;
    pub const stateless_reset_token: u64 = 0x02;
    pub const max_udp_payload_size: u64 = 0x03;
    pub const initial_max_data: u64 = 0x04;
    pub const initial_max_stream_data_bidi_local: u64 = 0x05;
    pub const initial_max_stream_data_bidi_remote: u64 = 0x06;
    pub const initial_max_stream_data_uni: u64 = 0x07;
    pub const initial_max_streams_bidi: u64 = 0x08;
    pub const initial_max_streams_uni: u64 = 0x09;
    pub const ack_delay_exponent: u64 = 0x0a;
    pub const max_ack_delay: u64 = 0x0b;
    pub const disable_active_migration: u64 = 0x0c;
    pub const preferred_address: u64 = 0x0d;
    pub const active_connection_id_limit: u64 = 0x0e;
    pub const initial_source_connection_id: u64 = 0x0f;
    pub const retry_source_connection_id: u64 = 0x10;
};

/// Transport parameters negotiated with peer
pub const TransportParams = struct {
    max_idle_timeout: u64 = 0,
    max_udp_payload_size: u64 = types.TransportParamDefaults.max_udp_payload_size,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u8 = types.TransportParamDefaults.ack_delay_exponent,
    max_ack_delay: u64 = types.TransportParamDefaults.max_ack_delay,
    active_connection_id_limit: u64 = types.TransportParamDefaults.active_connection_id_limit,
    disable_active_migration: bool = false,
    /// Server-only: DCID from client's first Initial packet (RFC 9000 §7.3)
    original_destination_connection_id: ?types.ConnectionId = null,
    /// SCID we put in our long-header packets (both peers send this)
    initial_source_connection_id: ?types.ConnectionId = null,

    /// Encode this set into the QUIC transport parameters TLV format
    /// (RFC 9000 §18). Returns the number of bytes written.
    /// Each parameter is: varint(id) varint(len) value-bytes.
    /// For varint-typed parameters, value-bytes is itself varint-encoded.
    pub fn encode(self: *const TransportParams, out: []u8) !usize {
        var off: usize = 0;

        // Helper: emit a varint-valued parameter (id, value).
        const emitVarint = struct {
            fn call(buf: []u8, cur: *usize, id: u64, value: u64) !void {
                const var_len = varint.encodedLength(value);
                cur.* += try varint.encode(buf[cur.*..], id);
                cur.* += try varint.encode(buf[cur.*..], var_len);
                cur.* += try varint.encode(buf[cur.*..], value);
            }
        }.call;

        // Helper: emit an opaque-valued parameter (id, bytes).
        const emitBytes = struct {
            fn call(buf: []u8, cur: *usize, id: u64, value: []const u8) !void {
                cur.* += try varint.encode(buf[cur.*..], id);
                cur.* += try varint.encode(buf[cur.*..], value.len);
                if (buf.len < cur.* + value.len) return error.BufferTooSmall;
                @memcpy(buf[cur.* .. cur.* + value.len], value);
                cur.* += value.len;
            }
        }.call;

        // Helper: emit a zero-length flag parameter.
        const emitFlag = struct {
            fn call(buf: []u8, cur: *usize, id: u64) !void {
                cur.* += try varint.encode(buf[cur.*..], id);
                cur.* += try varint.encode(buf[cur.*..], 0);
            }
        }.call;

        if (self.original_destination_connection_id) |cid| {
            try emitBytes(out, &off, TpId.original_destination_connection_id, cid.slice());
        }
        if (self.max_idle_timeout != 0) {
            try emitVarint(out, &off, TpId.max_idle_timeout, self.max_idle_timeout);
        }
        try emitVarint(out, &off, TpId.max_udp_payload_size, self.max_udp_payload_size);
        try emitVarint(out, &off, TpId.initial_max_data, self.initial_max_data);
        try emitVarint(out, &off, TpId.initial_max_stream_data_bidi_local, self.initial_max_stream_data_bidi_local);
        try emitVarint(out, &off, TpId.initial_max_stream_data_bidi_remote, self.initial_max_stream_data_bidi_remote);
        try emitVarint(out, &off, TpId.initial_max_stream_data_uni, self.initial_max_stream_data_uni);
        try emitVarint(out, &off, TpId.initial_max_streams_bidi, self.initial_max_streams_bidi);
        try emitVarint(out, &off, TpId.initial_max_streams_uni, self.initial_max_streams_uni);
        try emitVarint(out, &off, TpId.ack_delay_exponent, self.ack_delay_exponent);
        try emitVarint(out, &off, TpId.max_ack_delay, self.max_ack_delay);
        if (self.disable_active_migration) {
            try emitFlag(out, &off, TpId.disable_active_migration);
        }
        try emitVarint(out, &off, TpId.active_connection_id_limit, self.active_connection_id_limit);
        if (self.initial_source_connection_id) |cid| {
            try emitBytes(out, &off, TpId.initial_source_connection_id, cid.slice());
        }

        return off;
    }

    /// Parse a peer's transport parameters TLV blob into this struct.
    /// Unknown parameters are silently ignored (forward compatibility).
    pub fn decode(self: *TransportParams, blob: []const u8) !void {
        var off: usize = 0;
        while (off < blob.len) {
            const id_dec = try varint.decode(blob[off..]);
            off += id_dec.len;
            const len_dec = try varint.decode(blob[off..]);
            off += len_dec.len;
            const value_len: usize = @intCast(len_dec.value);
            if (off + value_len > blob.len) return error.InvalidTransportParam;
            const value = blob[off .. off + value_len];
            off += value_len;

            switch (id_dec.value) {
                TpId.original_destination_connection_id => {
                    self.original_destination_connection_id = types.ConnectionId.init(value);
                },
                TpId.max_idle_timeout => {
                    self.max_idle_timeout = (try varint.decode(value)).value;
                },
                TpId.max_udp_payload_size => {
                    self.max_udp_payload_size = (try varint.decode(value)).value;
                },
                TpId.initial_max_data => {
                    self.initial_max_data = (try varint.decode(value)).value;
                },
                TpId.initial_max_stream_data_bidi_local => {
                    self.initial_max_stream_data_bidi_local = (try varint.decode(value)).value;
                },
                TpId.initial_max_stream_data_bidi_remote => {
                    self.initial_max_stream_data_bidi_remote = (try varint.decode(value)).value;
                },
                TpId.initial_max_stream_data_uni => {
                    self.initial_max_stream_data_uni = (try varint.decode(value)).value;
                },
                TpId.initial_max_streams_bidi => {
                    self.initial_max_streams_bidi = (try varint.decode(value)).value;
                },
                TpId.initial_max_streams_uni => {
                    self.initial_max_streams_uni = (try varint.decode(value)).value;
                },
                TpId.ack_delay_exponent => {
                    const v = (try varint.decode(value)).value;
                    self.ack_delay_exponent = @intCast(@min(v, 20));
                },
                TpId.max_ack_delay => {
                    self.max_ack_delay = (try varint.decode(value)).value;
                },
                TpId.disable_active_migration => {
                    self.disable_active_migration = true;
                },
                TpId.active_connection_id_limit => {
                    self.active_connection_id_limit = (try varint.decode(value)).value;
                },
                TpId.initial_source_connection_id => {
                    self.initial_source_connection_id = types.ConnectionId.init(value);
                },
                else => {}, // ignore unknown
            }
        }
    }
};

/// Flow control state
pub const FlowControl = struct {
    /// Maximum data we can send (peer's limit)
    max_data_send: u64 = 0,
    /// Data we've sent so far
    data_sent: u64 = 0,
    /// Maximum data peer can send (our limit)
    max_data_recv: u64 = 0,
    /// Data we've received so far
    data_received: u64 = 0,
    /// Need to send MAX_DATA update
    send_max_data: bool = false,

    /// Check if we can send data
    pub fn canSend(self: *const FlowControl, len: u64) bool {
        return self.data_sent + len <= self.max_data_send;
    }

    /// Record that we sent data
    pub fn onDataSent(self: *FlowControl, len: u64) void {
        self.data_sent += len;
    }

    /// Record that we received data
    pub fn onDataReceived(self: *FlowControl, len: u64) Error!void {
        self.data_received += len;
        if (self.data_received > self.max_data_recv) {
            return Error.FlowControlError;
        }
        // Check if we should send MAX_DATA (when 50% consumed)
        if (self.data_received > self.max_data_recv / 2) {
            self.send_max_data = true;
        }
    }

    /// Update our receive limit
    pub fn updateMaxRecv(self: *FlowControl, new_max: u64) void {
        if (new_max > self.max_data_recv) {
            self.max_data_recv = new_max;
            self.send_max_data = false;
        }
    }

    /// Update peer's send limit (from MAX_DATA frame)
    pub fn updateMaxSend(self: *FlowControl, new_max: u64) void {
        if (new_max > self.max_data_send) {
            self.max_data_send = new_max;
        }
    }
};

/// Peer connection ID with associated metadata
pub const PeerConnectionId = struct {
    cid: types.ConnectionId,
    sequence_number: u64,
    stateless_reset_token: ?[16]u8 = null,
    retired: bool = false,
};

/// Per-encryption-level CRYPTO stream reassembly. CRYPTO frames in QUIC
/// have absolute offsets and may arrive out of order. OpenSSL's TLS
/// state machine requires the handshake bytes in offset order, so we
/// buffer (offset, data) pairs and only release a contiguous prefix
/// starting at `next_contiguous_offset`.
///
/// 16 KB per level is sized for a TLS 1.3 server cert flight; clients
/// rarely need more than a few KB at the Initial / Handshake levels.
pub const CryptoReassembly = struct {
    pub const capacity: usize = 16 * 1024;

    data: [capacity]u8 = undefined,
    /// Bitmap: 1 bit per byte, indicating whether that byte has been received.
    received: [capacity / 8]u8 = [_]u8{0} ** (capacity / 8),
    /// The smallest offset that has not yet been delivered to TLS.
    next_contiguous_offset: u64 = 0,
    /// Highest offset+1 we've ever seen (helps bound the contiguous-scan).
    high_water_offset: u64 = 0,

    /// Record bytes received at `offset`. Returns error.OutOfBounds if
    /// the data extends past the buffer capacity (which would indicate
    /// either a malicious peer or a TLS handshake larger than expected).
    pub fn write(self: *CryptoReassembly, offset: u64, src: []const u8) error{OutOfBounds}!void {
        if (src.len == 0) return;
        const end = offset + src.len;
        if (end > capacity) return error.OutOfBounds;
        @memcpy(self.data[@intCast(offset)..@intCast(end)], src);
        // Mark each byte as received in the bitmap.
        var i: u64 = 0;
        while (i < src.len) : (i += 1) {
            const bit_off = offset + i;
            self.received[@intCast(bit_off / 8)] |= @as(u8, 1) << @intCast(bit_off & 7);
        }
        if (end > self.high_water_offset) self.high_water_offset = end;
    }

    /// Drain the longest contiguous prefix of newly-received bytes starting
    /// at next_contiguous_offset and advance the cursor past it. Returns
    /// an empty slice if there's nothing new to deliver.
    pub fn drainContiguous(self: *CryptoReassembly) []const u8 {
        const start = self.next_contiguous_offset;
        var end = start;
        while (end < self.high_water_offset) {
            const byte_idx: usize = @intCast(end / 8);
            const bit_idx: u3 = @intCast(end & 7);
            if ((self.received[byte_idx] & (@as(u8, 1) << bit_idx)) == 0) break;
            end += 1;
        }
        if (end == start) return &.{};
        const slice = self.data[@intCast(start)..@intCast(end)];
        self.next_contiguous_offset = end;
        return slice;
    }
};

/// QUIC Connection
pub const Connection = struct {
    allocator: std.mem.Allocator,
    /// Current connection state
    state: State = .initial,
    /// Is this a server-side connection?
    is_server: bool,
    /// Original destination connection ID (for Initial packet validation)
    original_dcid: types.ConnectionId,
    /// Our connection ID
    our_cid: types.ConnectionId,
    /// Peer's connection ID
    peer_cid: types.ConnectionId,
    /// QUIC version in use
    version: u32 = @intFromEnum(types.Version.quic_v1),
    /// Cryptographic context
    crypto_ctx: crypto.CryptoContext,
    /// Packet number spaces
    initial_space: PacketNumberSpace = .{},
    handshake_space: PacketNumberSpace = .{},
    application_space: PacketNumberSpace = .{},
    /// Our transport parameters
    local_params: TransportParams = .{},
    /// Peer's transport parameters
    peer_params: TransportParams = .{},
    /// Connection-level flow control
    flow_control: FlowControl = .{},
    /// Crypto data buffer (for assembling CRYPTO frames)
    crypto_buffer: std.ArrayList(u8) = .empty,
    /// Pending crypto data offset
    crypto_offset: u64 = 0,
    /// Close error code (if closing/draining)
    close_error: ?types.TransportError = null,
    /// Close reason phrase
    close_reason: ?[]const u8 = null,
    /// Timer for idle timeout (in nanoseconds)
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// Last activity instant
    last_activity: ?clock.Instant = null,
    /// Connection metrics
    conn_metrics: metrics.ConnectionMetrics = .{ .created_at = null },
    /// Loss recovery manager (RFC 9002)
    recovery: recovery_mod.Recovery,
    /// Zero-allocation ring buffer for tracking sent packets. Wired
    /// into the send path via `recordPacketSent`; the ACK-receive
    /// path in `processAckFrame` feeds it to update RTT and detect
    /// losses.
    sent_ring: sent_ring.SentRing = .{},
    /// Congestion controller (NewReno)
    congestion: congestion_mod.CongestionController = congestion_mod.CongestionController.init(),
    /// TLS session for handshake and key derivation. In QUIC mode (the
    /// only mode used here) this is bound to a tls.QuicState callback
    /// adapter; outgoing CRYPTO bytes live in per-encryption-level queues
    /// inside that QuicState, not in a single buffer here.
    tls_session: ?tls.Session = null,
    /// Per-encryption-level CRYPTO stream reassembly. CRYPTO frames may
    /// arrive out of offset order; we hold them here until we have a
    /// contiguous prefix to feed into TLS.
    crypto_reasm_initial: CryptoReassembly = .{},
    crypto_reasm_handshake: CryptoReassembly = .{},
    crypto_reasm_application: CryptoReassembly = .{},
    /// MAX_STREAMS tracking. We track how many peer-initiated bidi
    /// streams have been opened and emit MAX_STREAMS when > 50% of
    /// the granted limit is consumed (doubles the limit each time).
    max_streams_bidi_granted: u64 = 0,
    peer_bidi_streams_opened: u64 = 0,
    send_max_streams_bidi: bool = false,

    /// Key phase tracking (RFC 9001 §6). We track the current key
    /// phase bit so we can detect key updates from the peer. When a
    /// packet arrives with a different key_phase, we attempt to
    /// decrypt with the next set of keys. On success, we rotate.
    current_key_phase: bool = false,

    /// Server: have we already sent HANDSHAKE_DONE to the client?
    /// HANDSHAKE_DONE is sent exactly once after the server's handshake
    /// completes (RFC 9000 §19.20) and signals to the client that it
    /// can discard its Handshake-level keys.
    handshake_done_sent: bool = false,
    /// Stream manager for this connection
    stream_manager: ?stream.StreamManager = null,
    /// HTTP/3 protocol stack
    http3_stack: ?http3.Stack = null,
    /// Whether 0-RTT early data was received on this connection
    early_data_received: bool = false,
    /// Pending PATH_RESPONSE data to send
    pending_path_response: ?[8]u8 = null,
    /// Pending PATH_CHALLENGE data we're waiting to validate
    pending_path_challenge: ?[8]u8 = null,
    /// Peer's connection IDs (for connection ID rotation)
    peer_cids: [8]?PeerConnectionId = .{null} ** 8,
    /// Number of valid peer connection IDs
    peer_cid_count: usize = 0,
    /// Next sequence number for our connection IDs
    our_cid_seq: u64 = 0,
    /// Timestamp when draining started (microseconds)
    draining_started_us: ?u64 = null,
    /// Draining duration (3 × PTO, in microseconds)
    draining_duration_us: u64 = 3 * 1000 * 1000, // Default 3 seconds

    pub fn init(allocator: std.mem.Allocator, is_server: bool, dcid: types.ConnectionId) Connection {
        var conn = Connection{
            .allocator = allocator,
            .is_server = is_server,
            .original_dcid = dcid,
            .our_cid = types.ConnectionId{},
            .peer_cid = dcid,
            .crypto_ctx = crypto.CryptoContext.init(),
            .last_activity = clock.Instant.now(),
            .conn_metrics = metrics.ConnectionMetrics.init(),
            .recovery = recovery_mod.Recovery.init(allocator),
        };

        // Generate our connection ID (8 bytes) using random seeded from clock + DCID
        const now = clock.Instant.now();
        const seed_ns: u64 = if (now) |i| i.ns else 0;
        var rng = std.Random.DefaultPrng.init(seed_ns ^ std.hash.Wyhash.hash(0, dcid.slice()));
        rng.random().bytes(conn.our_cid.bytes[0..8]);
        conn.our_cid.len = 8;

        // Derive initial keys from DCID
        conn.crypto_ctx.deriveInitialKeys(dcid.slice(), conn.version);

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        self.recovery.deinit();
        self.crypto_buffer.deinit(self.allocator);
        if (self.tls_session) |*session| {
            session.deinit();
        }
        if (self.stream_manager) |*mgr| {
            mgr.deinit();
        }
        if (self.http3_stack) |*stack| {
            stack.deinit();
        }
    }

    /// Initialize the stream manager for this connection.
    pub fn initStreamManager(self: *Connection) void {
        if (self.stream_manager == null) {
            var mgr = stream.StreamManager.init(self.allocator, self.is_server);
            // Set initial limits from local transport parameters
            mgr.setLimits(
                self.local_params.initial_max_streams_bidi,
                self.peer_params.initial_max_streams_bidi,
                self.local_params.initial_max_streams_uni,
                self.peer_params.initial_max_streams_uni,
            );
            mgr.initial_max_stream_data = self.local_params.initial_max_stream_data_bidi_remote;
            self.stream_manager = mgr;
        }

        // Initialize HTTP/3 stack
        if (self.http3_stack == null) {
            self.http3_stack = http3.Stack.init(self.allocator, self.is_server);
        }
    }

    /// Process stream data through the HTTP/3 stack.
    ///
    /// Returns the full `IngestResult` so callers can observe
    /// `consumed` and `need_more`. Before PR A the caller only needed
    /// `events` and the other fields were silently dropped — one of
    /// the root causes of the h3 request-stream buffering bugs tracked
    /// in `docs/design/8.0-h3-performance-plan.md`.
    pub fn processHttp3Stream(self: *Connection, stream_id: u64, data: []const u8, end_stream: bool) Error!http3.IngestResult {
        if (self.http3_stack) |*stack| {
            return stack.ingest(stream_id, data, end_stream) catch return Error.ProtocolViolation;
        }
        return Error.InvalidState;
    }

    /// Reclaim a Stream's receive buffer after the application has
    /// finished dispatching its `RequestReadyEvent`. Called by
    /// `Server.handleDatagram` once the synchronous handler returns
    /// and the `RequestReadyEvent.body` slice (which points into
    /// `recv_buffer.items`) is no longer referenced. Keeps the
    /// stream's memory footprint bounded without invalidating any
    /// live slice during the handler's run.
    pub fn clearH3RequestStream(self: *Connection, stream_id: u64) void {
        if (self.stream_manager) |*mgr| {
            if (mgr.getStream(stream_id)) |s| {
                s.consumeRead(s.recv_buffer.items.len);
            }
        }
    }

    /// Initialize HTTP/3 control streams.
    /// Creates control stream and queues SETTINGS frame.
    /// HTTP/3 stream-type bytes (RFC 9114 §6.2 / RFC 9204 §4.2)
    const H3_STREAM_TYPE_CONTROL: u8 = 0x00;
    const H3_STREAM_TYPE_PUSH: u8 = 0x01;
    const H3_STREAM_TYPE_QPACK_ENCODER: u8 = 0x02;
    const H3_STREAM_TYPE_QPACK_DECODER: u8 = 0x03;

    /// Per-spec stream IDs for the server's three required unidirectional
    /// streams. Server-initiated unidirectional stream IDs are of the form
    /// 4n+3 (RFC 9000 §2.1): 3, 7, 11, 15, ...
    pub const H3_SERVER_CONTROL_STREAM_ID: u64 = 3;
    pub const H3_SERVER_QPACK_ENCODER_STREAM_ID: u64 = 7;
    pub const H3_SERVER_QPACK_DECODER_STREAM_ID: u64 = 11;

    fn initHttp3ControlStreams(self: *Connection) void {
        if (!self.is_server) return; // client side initialization is a follow-up

        // Open all three required server uni streams. The QPACK encoder
        // and decoder streams (0x02 / 0x03) must exist per RFC 9204 §4.2;
        // even if we never use the dynamic table, the type byte must be
        // delivered or the peer treats the connection as malformed.
        const stream_ids = [_]u64{
            H3_SERVER_CONTROL_STREAM_ID,
            H3_SERVER_QPACK_ENCODER_STREAM_ID,
            H3_SERVER_QPACK_DECODER_STREAM_ID,
        };
        const stream_types = [_]u8{
            H3_STREAM_TYPE_CONTROL,
            H3_STREAM_TYPE_QPACK_ENCODER,
            H3_STREAM_TYPE_QPACK_DECODER,
        };

        if (self.stream_manager) |*mgr| {
            for (stream_ids) |sid| {
                const s = mgr.getOrCreateStream(sid) catch continue;
                s.send_max_offset = 65536;
            }
        }

        if (self.http3_stack) |*stack| {
            stack.our_control_stream = H3_SERVER_CONTROL_STREAM_ID;

            // Control stream: type byte + SETTINGS frame.
            var ctrl_buf: [256]u8 = undefined;
            ctrl_buf[0] = H3_STREAM_TYPE_CONTROL;
            const settings_len = stack.buildSettings(ctrl_buf[1..]) catch return;
            const ctrl_total = 1 + settings_len;

            if (self.stream_manager) |*mgr| {
                if (mgr.getStream(H3_SERVER_CONTROL_STREAM_ID)) |s| {
                    s.send(ctrl_buf[0..ctrl_total], false) catch {};
                }
            }
        }

        // QPACK encoder and decoder streams: just the type byte. They'll
        // remain otherwise empty until we add dynamic-table support.
        if (self.stream_manager) |*mgr| {
            for (stream_ids[1..], stream_types[1..]) |sid, st| {
                if (mgr.getStream(sid)) |s| {
                    var byte = [_]u8{st};
                    s.send(byte[0..], false) catch {};
                }
            }
        }
    }

    /// One pending uni-stream's bytes-on-the-wire. Used by the packet
    /// builder to drain server-side control / QPACK encoder / QPACK
    /// decoder streams into STREAM frames.
    pub const PendingUniStream = struct { stream_id: u64, data: []const u8 };

    /// Get pending bytes for one of the server's three uni streams (control,
    /// QPACK encoder, QPACK decoder), in the order they should appear on
    /// the wire. Returns null when none have pending data. Caller copies
    /// the bytes into a STREAM frame and then calls clearPendingUniStream.
    pub fn nextPendingUniStream(self: *Connection) ?PendingUniStream {
        const stream_ids = [_]u64{
            H3_SERVER_CONTROL_STREAM_ID,
            H3_SERVER_QPACK_ENCODER_STREAM_ID,
            H3_SERVER_QPACK_DECODER_STREAM_ID,
        };
        if (self.stream_manager) |*mgr| {
            for (stream_ids) |sid| {
                if (mgr.getStream(sid)) |s| {
                    if (s.send_buffer.items.len > 0) {
                        return .{ .stream_id = sid, .data = s.send_buffer.items };
                    }
                }
            }
        }
        return null;
    }

    /// Mark a uni stream's pending bytes as sent. Call after copying the
    /// bytes into a STREAM frame.
    pub fn clearPendingUniStream(self: *Connection, stream_id: u64) void {
        if (self.stream_manager) |*mgr| {
            if (mgr.getStream(stream_id)) |s| {
                s.send_buffer.clearRetainingCapacity();
            }
        }
    }

    /// Encode an HTTP/3 response for a stream.
    pub fn encodeHttp3Response(
        self: *Connection,
        buf: []u8,
        status: u16,
        headers: []const http3.Header,
        body: ?[]const u8,
    ) Error!usize {
        if (self.http3_stack) |*stack| {
            return stack.encodeResponse(buf, status, headers, body) catch Error.ProtocolViolation;
        }
        return Error.InvalidState;
    }

    /// Get or create a stream by ID.
    pub fn getOrCreateStream(self: *Connection, stream_id: u64) Error!*stream.Stream {
        if (self.stream_manager) |*mgr| {
            return mgr.getOrCreateStream(stream_id) catch |err| switch (err) {
                stream.Error.OutOfMemory => Error.OutOfMemory,
                stream.Error.StreamLimitExceeded => Error.StreamLimitExceeded,
                else => Error.ProtocolViolation,
            };
        }
        return Error.InvalidState;
    }

    /// Get an existing stream by ID.
    pub fn getStream(self: *Connection, stream_id: u64) ?*stream.Stream {
        if (self.stream_manager) |*mgr| {
            return mgr.getStream(stream_id);
        }
        return null;
    }

    /// Map a quic-stack PacketNumberSpace to the tls.QuicLevel used by the
    /// callback adapter. (They're separate enum types deliberately —
    /// PacketNumberSpace is RFC 9000 §12.3, QuicLevel is the OpenSSL
    /// protection-level enum from the SSL_set_quic_tls_cbs API.)
    fn levelFromSpace(space: types.PacketNumberSpace) tls.QuicLevel {
        return switch (space) {
            .initial => .initial,
            .handshake => .handshake,
            .application => .application,
        };
    }

    /// Populate local_params with sane server defaults derived from this
    /// connection's CIDs. Called during initTls before transport params are
    /// installed on the SSL session.
    fn populateDefaultLocalParams(self: *Connection) void {
        // Connection-level flow control: 16 MiB receive window
        self.local_params.initial_max_data = 16 * 1024 * 1024;
        // Stream-level flow control: 256 KiB per stream
        self.local_params.initial_max_stream_data_bidi_local = 256 * 1024;
        self.local_params.initial_max_stream_data_bidi_remote = 256 * 1024;
        self.local_params.initial_max_stream_data_uni = 256 * 1024;
        // Stream limits. Start with 1024 bidi streams; MAX_STREAMS
        // frames grow the limit dynamically when > 50% is consumed.
        self.local_params.initial_max_streams_bidi = 1024;
        self.local_params.initial_max_streams_uni = 100;
        self.max_streams_bidi_granted = 1024;
        // Idle timeout 30s
        self.local_params.max_idle_timeout = 30_000;
        // ACK delay exponent (default 3 = 8μs units, RFC 9000 §18.2)
        self.local_params.ack_delay_exponent = 3;
        // Max ACK delay 25ms
        self.local_params.max_ack_delay = 25;
        // Active CID limit
        self.local_params.active_connection_id_limit = 4;
        // CID-related identifiers (server only)
        if (self.is_server) {
            self.local_params.original_destination_connection_id = self.original_dcid;
        }
        self.local_params.initial_source_connection_id = self.our_cid;
        // Initialize the connection-level recv flow control window from local_params
        self.flow_control.max_data_recv = self.local_params.initial_max_data;
    }

    /// Initialize TLS session for this connection.
    /// Must be called after init() to enable TLS 1.3 handshake.
    /// Populates local QUIC transport parameters and installs them on the
    /// SSL session via SSL_set_quic_tls_transport_params.
    pub fn initTls(self: *Connection, provider: *tls.Provider) Error!void {
        self.tls_session = provider.createQuicSession(self.is_server) catch return Error.TlsError;
        self.populateDefaultLocalParams();
        // Encode local transport params and hand to OpenSSL.
        var tp_buf: [512]u8 = undefined;
        const tp_len = self.local_params.encode(&tp_buf) catch return Error.TlsError;
        if (self.tls_session) |*session| {
            session.setQuicTransportParams(tp_buf[0..tp_len]) catch return Error.TlsError;
        }
    }

    /// Feed incoming CRYPTO frame data to TLS at the given encryption level.
    /// Caller derives the level from the packet header (Initial/Handshake/1-RTT).
    pub fn feedCryptoData(self: *Connection, space: types.PacketNumberSpace, data: []const u8) Error!void {
        if (self.tls_session) |*session| {
            session.feedQuicCryptoData(levelFromSpace(space), data) catch return Error.TlsError;
        }
    }

    /// Do we have any HTTP/3 stream data waiting to be flushed in a 1-RTT
    /// packet? Currently this checks the server's three required uni
    /// streams (control / QPACK encoder / QPACK decoder), which carry the
    /// SETTINGS frame and stream-type bytes that the peer needs before it
    /// will accept any response data. Request-response stream data still
    /// goes via the older buildStreamPacket path in server.zig.
    pub fn has1RttPayloadPending(self: *Connection) bool {
        if (self.nextPendingUniStream()) |_| return true;
        return false;
    }

    /// Get the per-level reassembly buffer.
    fn cryptoReassembly(self: *Connection, space: types.PacketNumberSpace) *CryptoReassembly {
        return switch (space) {
            .initial => &self.crypto_reasm_initial,
            .handshake => &self.crypto_reasm_handshake,
            .application => &self.crypto_reasm_application,
        };
    }

    /// Ingest a single CRYPTO frame at (offset, data) and feed any newly-
    /// contiguous prefix into TLS. Called by handler.processCryptoFrames
    /// for each parsed CRYPTO frame.
    pub fn ingestCryptoFrame(self: *Connection, space: types.PacketNumberSpace, offset: u64, data: []const u8) Error!void {
        const reasm = self.cryptoReassembly(space);
        reasm.write(offset, data) catch return Error.ProtocolViolation;
        const ready = reasm.drainContiguous();
        if (ready.len > 0) {
            try self.feedCryptoData(space, ready);
        }
    }

    /// Advance the TLS handshake. After OpenSSL processes any newly-fed
    /// CRYPTO data, drain any newly-installed traffic secrets and convert
    /// them into QUIC packet protection keys (key/iv/hp via HKDF-Expand-Label
    /// per RFC 9001 §5.1). Returns true once the handshake completes.
    pub fn advanceTlsHandshake(self: *Connection) Error!bool {
        const session = if (self.tls_session) |*s| s else return Error.TlsError;

        const result = session.doHandshake();

        // Drain any newly-installed (direction, level) secrets and turn them
        // into AEAD/HP keys at the matching crypto_ctx slot. yield_secret
        // fires up to 4 times during the handshake (handshake/app × read/write).
        var pending: [8]tls.quic_session.QuicState.SecretReady = undefined;
        const n = session.takePendingQuicSecrets(&pending);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const ready = pending[i];
            const secret_slice = session.getQuicSecret(ready.dir, ready.level) orelse continue;
            // Currently locked to TLS_AES_128_GCM_SHA256 → 32-byte secrets.
            // SHA-384 / 48-byte secrets are a follow-up; see crypto.deriveKeysFromSecret.
            if (secret_slice.len != 32) return Error.CryptoError;
            var secret_buf: [32]u8 = undefined;
            @memcpy(&secret_buf, secret_slice[0..32]);
            const keys = crypto.deriveKeysFromSecret(&secret_buf);
            const target_set = switch (ready.level) {
                .initial => &self.crypto_ctx.initial,
                .early_data => &self.crypto_ctx.early_data,
                .handshake => &self.crypto_ctx.handshake,
                .application => &self.crypto_ctx.application,
            };
            // direction=read means we decrypt (peer's traffic): client keys
            // for a server, server keys for a client. direction=write is the
            // opposite.
            const peer_keys_field = if (self.is_server) ready.dir == .read else ready.dir == .write;
            if (peer_keys_field) {
                target_set.client = keys;
            } else {
                target_set.server = keys;
            }
        }

        // If the peer's QUIC transport parameters arrived, parse them and
        // populate peer_params. The got_transport_params callback fired
        // during SSL_do_handshake will have buffered them in QuicState.
        if (session.peerQuicTransportParams()) |blob| {
            // Only parse once: if our peer_params is still all-default-zero,
            // try to populate it. (We could track a "parsed" bool more
            // explicitly; for now, idempotent parsing is fine since the
            // blob doesn't change after the first ServerHello / ClientHello.)
            if (self.peer_params.initial_max_data == 0) {
                self.peer_params.decode(blob) catch return Error.ProtocolViolation;
                // Hook the negotiated send window into flow control.
                self.flow_control.max_data_send = self.peer_params.initial_max_data;
            }
        }

        return switch (result) {
            .complete => true,
            .in_progress => false,
            .failed => Error.HandshakeFailed,
        };
    }

    /// Get pending outgoing CRYPTO data at a given encryption level. The
    /// returned slice is a borrow into the QuicState's per-level outbound
    /// queue and remains valid until consumePendingCryptoData is called.
    pub fn getPendingCryptoData(self: *Connection, space: types.PacketNumberSpace) []const u8 {
        if (self.tls_session) |*session| {
            return session.pendingQuicOutgoing(levelFromSpace(space));
        }
        return &.{};
    }

    /// Mark `n` bytes from the head of the outgoing CRYPTO queue at `space`
    /// as sent. Call this after copying the bytes into a CRYPTO frame and
    /// queueing the packet for transmission.
    pub fn consumePendingCryptoData(self: *Connection, space: types.PacketNumberSpace, n: usize) void {
        if (self.tls_session) |*session| {
            session.consumeQuicOutgoing(levelFromSpace(space), n);
        }
    }

    /// Get the packet number space for a given type
    pub fn getPacketSpace(self: *Connection, space: types.PacketNumberSpace) *PacketNumberSpace {
        return switch (space) {
            .initial => &self.initial_space,
            .handshake => &self.handshake_space,
            .application => &self.application_space,
        };
    }

    // NOTE: `Connection.processPacket` and its helper chain
    // (`processLongHeaderPacket`, `processShortHeaderPacket`,
    // `handleInitialPacket`, `handleHandshakePacket`,
    // `handleRetryPacket`) lived here pre-`3359d34` as an
    // unreachable parallel packet-processing path. All production
    // packet handling goes through `quic/handler.zig::Handler::
    // processPacket`. The dead copies were deleted wholesale in
    // this file to avoid any future reader following them — if you
    // want to trace packet handling, start from `Handler::processPacket`.

    /// Transition to connected state
    pub fn onHandshakeComplete(self: *Connection) void {
        self.state = .connected;

        // Record handshake completion in metrics
        self.conn_metrics.handshakeComplete();

        // Apply peer's transport parameters to flow control
        self.flow_control.max_data_send = self.peer_params.initial_max_data;
        self.flow_control.max_data_recv = self.local_params.initial_max_data;

        // Initialize stream manager now that transport params are set
        self.initStreamManager();

        // Initialize HTTP/3 control streams
        self.initHttp3ControlStreams();

        // Discard Initial and Handshake keys per RFC 9001 §4.9.
        // Null both the space-level keys AND the crypto_ctx keyset so
        // the send/receive paths can no longer decrypt or produce
        // packets at these encryption levels.
        self.initial_space.keys = null;
        self.handshake_space.keys = null;
        self.crypto_ctx.initial = .{ .client = null, .server = null };
        self.crypto_ctx.handshake = .{ .client = null, .server = null };
    }

    /// Initiate connection close
    pub fn close(self: *Connection, error_code: types.TransportError, reason: ?[]const u8) void {
        if (self.state == .closed or self.state == .draining) {
            return;
        }

        self.close_error = error_code;
        self.close_reason = reason;
        self.state = .closing;
    }

    /// Build a CONNECTION_CLOSE frame for the current close state
    /// Returns bytes written to buffer
    pub fn buildConnectionCloseFrame(self: *const Connection, buf: []u8) !usize {
        const error_code = if (self.close_error) |err|
            @intFromEnum(err)
        else
            @intFromEnum(types.TransportError.no_error);

        const reason = self.close_reason orelse "";

        return frame.writeConnectionClose(buf, error_code, null, reason);
    }

    /// Build a CONNECTION_CLOSE frame for a specific error
    /// Useful when closing due to a specific protocol error
    pub fn buildConnectionCloseForError(buf: []u8, error_code: types.TransportError, triggering_frame: ?u64, reason: []const u8) !usize {
        return frame.writeConnectionClose(buf, @intFromEnum(error_code), triggering_frame, reason);
    }

    /// Check if connection needs to send CONNECTION_CLOSE
    pub fn needsConnectionClose(self: *const Connection) bool {
        return self.state == .closing;
    }

    /// Enter draining state (received CONNECTION_CLOSE from peer)
    /// RFC 9000: After sending CONNECTION_CLOSE, endpoint enters draining period
    /// and should remain in that state for 3 × PTO before fully closing
    pub fn drain(self: *Connection) void {
        if (self.state == .closed or self.state == .draining) return;
        self.state = .draining;
        self.draining_started_us = getCurrentTimeMicros();

        // Calculate draining duration based on PTO
        // PTO = smoothed_rtt + max(4 * rttvar, granularity) + max_ack_delay
        // Default to 3 seconds if no RTT data
        const rtt_us = self.conn_metrics.rtt_us;
        const rtt_var = self.conn_metrics.rtt_var_us;
        const max_ack_delay = self.peer_params.max_ack_delay * 1000; // Convert ms to us
        if (rtt_us > 0) {
            const pto = rtt_us + @max(4 * rtt_var, 1000) + max_ack_delay;
            self.draining_duration_us = 3 * pto;
        }
    }

    /// Check if draining period has completed
    pub fn isDrainingComplete(self: *const Connection) bool {
        if (self.state != .draining) return false;

        const started = self.draining_started_us orelse return true;
        const now = getCurrentTimeMicros();
        return now >= started + self.draining_duration_us;
    }

    /// Complete connection close (call when draining complete or forced close)
    pub fn onClosed(self: *Connection) void {
        self.state = .closed;
    }

    /// Check and transition from draining to closed if draining period expired
    pub fn checkDrainingComplete(self: *Connection) bool {
        if (self.isDrainingComplete()) {
            self.onClosed();
            return true;
        }
        return false;
    }

    /// Check if connection is still alive (not closed or draining)
    pub fn isAlive(self: *const Connection) bool {
        return self.state != .closed and self.state != .draining;
    }

    /// Check if connection is in a terminal state (closed)
    pub fn isClosed(self: *const Connection) bool {
        return self.state == .closed;
    }

    /// Check if connection is draining
    pub fn isDraining(self: *const Connection) bool {
        return self.state == .draining;
    }

    /// Check if connection can send application data
    pub fn canSendAppData(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Check if idle timeout has expired
    pub fn isIdleTimedOut(self: *const Connection) bool {
        const last = self.last_activity orelse return false;
        const now_inst = clock.Instant.now() orelse return false;
        const elapsed = now_inst.since(last);
        return elapsed > self.idle_timeout_ns;
    }

    /// Process a received ACK frame, marking packets as acknowledged.
    /// ACK frame format:
    /// - First range: [largest_ack - first_ack_range, largest_ack]
    /// - Additional ranges: gap indicates unacked packets before next range
    pub fn processAckFrame(self: *Connection, ack: frame.AckFrame, space: types.PacketNumberSpace) void {
        const pn_space = self.getPacketSpace(space);
        pn_space.onAckReceived(ack.largest_acked);

        // Process first ACK range: [largest - first_range, largest]
        var current_largest = ack.largest_acked;
        var current_smallest = ack.largest_acked -| ack.first_ack_range;

        // Mark packets in first range as acknowledged
        self.markPacketsAcked(space, current_smallest, current_largest);

        // Process additional ACK ranges
        for (ack.ranges) |range| {
            // Gap of 'gap' unacknowledged packets before next range
            // Next range starts at: current_smallest - gap - 2
            if (current_smallest < range.gap + 2) break; // Underflow protection
            current_largest = current_smallest - range.gap - 2;
            current_smallest = current_largest -| range.length;

            self.markPacketsAcked(space, current_smallest, current_largest);
        }
    }

    /// Mark a range of packets as acknowledged, feeding into the
    /// sent-packet ring buffer for RTT estimation and loss detection.
    fn markPacketsAcked(self: *Connection, space: types.PacketNumberSpace, smallest: u64, largest: u64) void {
        const now_ns: u64 = if (clock.Instant.now()) |inst| inst.ns else 0;

        // Mark the range as ACKed in the ring buffer. Returns the sent
        // time of `largest` (for RTT) and the total bytes of in-flight
        // packets removed (for congestion window growth).
        const ack_result = self.sent_ring.markAckedRange(space, smallest, largest);
        if (ack_result.largest_sent_time) |sent_time| {
            // Update RTT estimator (RFC 9002 §5)
            if (now_ns > sent_time) {
                const ack_delay_ns = self.application_space.calculateAckDelay() * 1000;
                self.recovery.rtt.update(
                    now_ns - sent_time,
                    ack_delay_ns,
                    space != .application,
                );
            }
        }

        // Run loss detection on the remaining unacked packets in the
        // ring (RFC 9002 §6). The ring's detectLost outputs up to 16
        // lost-packet descriptors into a stack-local array — no heap.
        const state = self.recovery.getState(space);
        if (state.largest_acked == null or largest > state.largest_acked.?) {
            state.largest_acked = largest;
        }
        var lost_buf: [16]sent_ring.LostPacket = undefined;
        var loss_time: ?u64 = null;
        const lost_count = self.sent_ring.detectLost(
            space,
            state.largest_acked orelse largest,
            self.recovery.rtt.getLossDelay(),
            now_ns,
            &lost_buf,
            &loss_time,
        );
        state.loss_time = loss_time;

        // Feed lost packets into the congestion controller.
        for (lost_buf[0..lost_count]) |lost_pkt| {
            self.congestion.onPacketLost(lost_pkt.size, lost_pkt.packet_number);
        }

        // Feed ACK into congestion window growth using the exact byte
        // count from the ring rather than a `count * 1200` estimate.
        self.congestion.onPacketAcked(ack_result.total_bytes, largest);

        // Update metrics
        const acked_count = largest - smallest + 1;
        self.conn_metrics.packets_acked += acked_count;
        self.conn_metrics.rtt_us = self.recovery.rtt.smoothed_rtt / 1000;

        // Reset PTO count on successful ACK
        self.recovery.pto_count = 0;
    }

    /// Process a received MAX_DATA frame
    pub fn processMaxDataFrame(self: *Connection, max_data: u64) void {
        self.flow_control.updateMaxSend(max_data);
    }

    /// Process a received MAX_STREAM_DATA frame
    pub fn processMaxStreamDataFrame(self: *Connection, stream_id: u64, max_data: u64) void {
        if (self.stream_manager) |*mgr| {
            if (mgr.getStream(stream_id)) |strm| {
                strm.updateSendLimit(max_data);
            }
        }
    }

    /// Process a received CONNECTION_CLOSE frame
    pub fn processConnectionClose(self: *Connection, error_code: u64, reason: []const u8) void {
        _ = reason;
        self.close_error = @enumFromInt(error_code);
        self.drain();
    }

    // ---- FLOW CONTROL ----

    /// Check if connection needs to send MAX_DATA
    pub fn needsMaxData(self: *const Connection) bool {
        return self.flow_control.send_max_data;
    }

    /// Build a MAX_DATA frame
    /// Returns bytes written, or 0 if no update needed
    pub fn buildMaxDataFrame(self: *Connection, buf: []u8) !usize {
        if (!self.flow_control.send_max_data) {
            return 0;
        }

        // Increase our receive limit by the current max (double it)
        const new_max = self.flow_control.max_data_recv * 2;
        self.flow_control.updateMaxRecv(new_max);

        return frame.writeMaxData(buf, new_max);
    }

    /// Get a stream that needs MAX_STREAM_DATA to be sent
    /// Returns the stream ID, or null if none needed
    pub fn getStreamNeedingFlowControl(self: *Connection) ?u64 {
        if (self.stream_manager) |*mgr| {
            var it = mgr.streams.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.*.send_max_stream_data) {
                    return entry.key_ptr.*;
                }
            }
        }
        return null;
    }

    /// Build a MAX_STREAM_DATA frame for a stream
    /// Returns bytes written
    pub fn buildMaxStreamDataFrame(self: *Connection, buf: []u8, stream_id: u64) !usize {
        if (self.stream_manager) |*mgr| {
            if (mgr.getStream(stream_id)) |strm| {
                if (strm.send_max_stream_data) {
                    // Double the stream's receive limit
                    const new_max = strm.recv_max_offset * 2;
                    strm.updateRecvLimit(new_max);

                    return frame.writeMaxStreamData(buf, stream_id, new_max);
                }
            }
        }
        return 0;
    }

    /// Update flow control when stream data is received
    /// Call this after processing a STREAM frame
    pub fn onStreamDataReceived(self: *Connection, len: u64) Error!void {
        try self.flow_control.onDataReceived(len);
    }

    /// Check if we can send data of the given length (connection-level)
    pub fn canSendData(self: *const Connection, len: u64) bool {
        return self.flow_control.canSend(len);
    }

    /// Record that we sent data (connection-level)
    pub fn onDataSent(self: *Connection, len: u64) void {
        self.flow_control.onDataSent(len);
    }

    // ---- Sent-packet tracking (RFC 9002) ----

    /// Record a packet that was just sent on the wire. The packet
    /// builder (buildShortPacket / buildHandshakePacket) calls this
    /// after constructing and encrypting the packet. The ring buffer
    /// is zero-allocation — entries are fixed-size and overwrite the
    /// oldest slot on overflow.
    pub fn recordPacketSent(
        self: *Connection,
        pn: u64,
        space: types.PacketNumberSpace,
        size: usize,
        ack_eliciting: bool,
    ) void {
        const now = if (clock.Instant.now()) |inst| inst.ns else 0;
        self.sent_ring.push(.{
            .packet_number = pn,
            .time_sent = now,
            .size = @intCast(@min(size, std.math.maxInt(u16))),
            .space = space,
            .ack_eliciting = ack_eliciting,
            .in_flight = ack_eliciting or size > 0,
        });
    }

    // ---- MAX_STREAMS (RFC 9000 §19.11) ----

    /// Called when a new peer-initiated bidi stream is created (e.g.,
    /// a new h3 request stream). Bumps the counter and sets the
    /// send_max_streams_bidi flag when > 50% of the granted limit
    /// has been consumed.
    pub fn onPeerBidiStreamOpened(self: *Connection) void {
        self.peer_bidi_streams_opened += 1;
        if (self.peer_bidi_streams_opened > self.max_streams_bidi_granted / 2 and
            !self.send_max_streams_bidi)
        {
            self.send_max_streams_bidi = true;
        }
    }

    /// Check if we need to send MAX_STREAMS to the peer.
    pub fn needsMaxStreamsBidi(self: *const Connection) bool {
        return self.send_max_streams_bidi;
    }

    /// Build a MAX_STREAMS frame doubling the current grant.
    pub fn buildMaxStreamsBidiFrame(self: *Connection, buf: []u8) !usize {
        if (!self.send_max_streams_bidi) return 0;
        self.max_streams_bidi_granted *= 2;
        self.send_max_streams_bidi = false;
        // Update the stream manager's limit too
        if (self.stream_manager) |*mgr| {
            mgr.max_streams_bidi_remote = self.max_streams_bidi_granted;
        }
        return frame.writeMaxStreams(buf, self.max_streams_bidi_granted, true);
    }

    /// Check whether the congestion window allows sending a packet of
    /// `size` bytes. Uses the sent_ring's bytes_in_flight as the
    /// authoritative in-flight count. ACK-only packets are exempt
    /// from congestion control per RFC 9002 §7.
    pub fn canSendPacket(self: *const Connection, size: usize) bool {
        return self.sent_ring.bytes_in_flight + size <= self.congestion.congestion_window;
    }

    // ---- PATH_CHALLENGE / PATH_RESPONSE ----

    /// Queue a PATH_RESPONSE to be sent (in response to PATH_CHALLENGE)
    pub fn queuePathResponse(self: *Connection, data: [8]u8) void {
        self.pending_path_response = data;
    }

    /// Check if we have a pending PATH_RESPONSE to send
    pub fn hasPendingPathResponse(self: *const Connection) bool {
        return self.pending_path_response != null;
    }

    /// Get and clear pending PATH_RESPONSE data
    pub fn takePendingPathResponse(self: *Connection) ?[8]u8 {
        const data = self.pending_path_response;
        self.pending_path_response = null;
        return data;
    }

    /// Start a path validation by sending PATH_CHALLENGE
    pub fn startPathValidation(self: *Connection) [8]u8 {
        // Generate 8 random bytes for challenge
        var data: [8]u8 = undefined;
        const now = clock.Instant.now();
        const seed: u64 = if (now) |i| i.ns else 42;
        var prng = std.Random.DefaultPrng.init(seed);
        prng.random().bytes(&data);
        self.pending_path_challenge = data;
        return data;
    }

    /// Validate a received PATH_RESPONSE
    pub fn validatePathResponse(self: *Connection, data: [8]u8) void {
        if (self.pending_path_challenge) |expected| {
            if (std.mem.eql(u8, &data, &expected)) {
                // Path validated successfully
                self.pending_path_challenge = null;
                // Could update path state here for connection migration
            }
        }
    }

    /// Check if path validation is pending
    pub fn isPathValidationPending(self: *const Connection) bool {
        return self.pending_path_challenge != null;
    }

    // ---- NEW_CONNECTION_ID / RETIRE_CONNECTION_ID ----

    /// Add a new peer connection ID from NEW_CONNECTION_ID frame
    pub fn addPeerConnectionId(self: *Connection, new_cid_frame: frame.NewConnectionIdFrame) void {
        // Find an empty slot or replace retired one
        for (&self.peer_cids) |*slot| {
            if (slot.* == null or (slot.*.?.retired and slot.*.?.sequence_number < new_cid_frame.sequence_number)) {
                slot.* = PeerConnectionId{
                    .cid = new_cid_frame.connection_id,
                    .sequence_number = new_cid_frame.sequence_number,
                    .stateless_reset_token = new_cid_frame.stateless_reset_token,
                    .retired = false,
                };
                self.peer_cid_count = @min(self.peer_cid_count + 1, self.peer_cids.len);
                return;
            }
        }
        // All slots full - could trigger RETIRE_CONNECTION_ID for oldest
    }

    /// Retire a connection ID (from RETIRE_CONNECTION_ID frame)
    pub fn retireConnectionId(self: *Connection, sequence_number: u64) void {
        for (&self.peer_cids) |*slot| {
            if (slot.*) |*pcid| {
                if (pcid.sequence_number == sequence_number) {
                    pcid.retired = true;
                    return;
                }
            }
        }
    }

    /// Get the active peer connection ID to use
    pub fn getActivePeerCid(self: *const Connection) types.ConnectionId {
        // Return first non-retired peer CID, or fall back to peer_cid
        for (self.peer_cids) |slot| {
            if (slot) |pcid| {
                if (!pcid.retired) {
                    return pcid.cid;
                }
            }
        }
        return self.peer_cid;
    }

};

// Note: the file-local deriveKeysFromTlsSecret was a duplicate of
// crypto.deriveKeysFromSecret. Now that crypto.deriveKeysFromSecret is
// public, callers (advanceTlsHandshake) use it directly.

// Tests
test "connection initialization" {
    const allocator = std.testing.allocator;
    const dcid = types.ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    var conn = Connection.init(allocator, true, dcid);
    defer conn.deinit();

    try std.testing.expectEqual(State.initial, conn.state);
    try std.testing.expect(conn.is_server);
    try std.testing.expectEqual(@as(u8, 8), conn.our_cid.len);
    try std.testing.expect(conn.crypto_ctx.initial.client != null);
    try std.testing.expect(conn.crypto_ctx.initial.server != null);
}

test "connection state transitions" {
    const allocator = std.testing.allocator;
    const dcid = types.ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    var conn = Connection.init(allocator, true, dcid);
    defer conn.deinit();

    try std.testing.expectEqual(State.initial, conn.state);

    // Simulate handshake start
    conn.state = .handshaking;
    try std.testing.expectEqual(State.handshaking, conn.state);

    // Simulate handshake complete
    conn.onHandshakeComplete();
    try std.testing.expectEqual(State.connected, conn.state);
    try std.testing.expect(conn.canSendAppData());

    // Close connection
    conn.close(.no_error, null);
    try std.testing.expectEqual(State.closing, conn.state);
}

test "packet number space" {
    var space = PacketNumberSpace{};

    // Allocate packet numbers
    try std.testing.expectEqual(@as(u64, 0), space.allocatePacketNumber());
    try std.testing.expectEqual(@as(u64, 1), space.allocatePacketNumber());
    try std.testing.expectEqual(@as(u64, 2), space.allocatePacketNumber());

    // Receive packets
    space.onPacketReceived(10);
    try std.testing.expectEqual(@as(u64, 10), space.largest_received.?);
    try std.testing.expect(space.ack_needed);

    // Receive ACK
    space.onAckReceived(1);
    try std.testing.expectEqual(@as(u64, 1), space.largest_acked.?);
}

test "ack delay calculation" {
    var space = PacketNumberSpace{};

    // No packets received - delay should be 0
    try std.testing.expectEqual(@as(u64, 0), space.calculateAckDelay());

    // Receive a packet with a specific timestamp (1000us ago)
    const now = getCurrentTimeMicros();
    const past = if (now > 1000) now - 1000 else 0;
    space.onPacketReceivedAt(1, past);

    // Delay should be approximately 1000us (allow some tolerance for test execution time)
    const delay = space.calculateAckDelay();
    // Since getCurrentTimeMicros may return 0 on some platforms, only check if time is working
    if (now > 0 and past > 0) {
        try std.testing.expect(delay >= 1000);
        try std.testing.expect(delay < 100_000); // Less than 100ms (reasonable upper bound)
    }
}

test "flow control" {
    var fc = FlowControl{};

    // Initially can't send (no limit)
    try std.testing.expect(!fc.canSend(100));

    // Set limits
    fc.max_data_send = 1000;
    fc.max_data_recv = 1000;

    try std.testing.expect(fc.canSend(100));

    // Send some data
    fc.onDataSent(500);
    try std.testing.expect(fc.canSend(500));
    try std.testing.expect(!fc.canSend(501));

    // Receive some data (more than half triggers MAX_DATA update)
    try fc.onDataReceived(501);
    try std.testing.expect(fc.send_max_data); // Should trigger MAX_DATA

    // Try to receive too much
    try std.testing.expectError(Error.FlowControlError, fc.onDataReceived(500));
}

test "derive keys from TLS secret" {
    const secret = [_]u8{0x42} ** 32;
    const keys = crypto.deriveKeysFromSecret(&secret);

    try std.testing.expectEqual(@as(u8, 16), keys.key_len);
    try std.testing.expectEqual(@as(u8, 16), keys.hp_len);

    const secret2 = [_]u8{0x43} ** 32;
    const keys2 = crypto.deriveKeysFromSecret(&secret2);
    try std.testing.expect(!std.mem.eql(u8, keys.key[0..16], keys2.key[0..16]));
}

test "PacketNumberSpace: receive bitmap dedupe" {
    var space = PacketNumberSpace{};

    // First packet anchors the window
    space.onPacketReceived(0);
    try std.testing.expect(space.isDuplicate(0));
    try std.testing.expect(!space.isDuplicate(1));

    // Sequential packets
    space.onPacketReceived(1);
    space.onPacketReceived(2);
    try std.testing.expect(space.isDuplicate(0));
    try std.testing.expect(space.isDuplicate(1));
    try std.testing.expect(space.isDuplicate(2));
    try std.testing.expect(!space.isDuplicate(3));

    // Skipped packet (3 missing) is not a duplicate; 4 received
    space.onPacketReceived(4);
    try std.testing.expect(!space.isDuplicate(3));
    try std.testing.expect(space.isDuplicate(4));

    // Re-receiving 3 fills the gap
    space.onPacketReceived(3);
    try std.testing.expect(space.isDuplicate(3));
}

test "PacketNumberSpace: firstAckRange skips gaps" {
    var space = PacketNumberSpace{};

    // No packets → range 0
    try std.testing.expectEqual(@as(u64, 0), space.firstAckRange());

    // Single packet → range 0 (just the largest)
    space.onPacketReceived(0);
    try std.testing.expectEqual(@as(u64, 0), space.firstAckRange());

    // Contiguous run → range = (largest - smallest)
    space.onPacketReceived(1);
    space.onPacketReceived(2);
    space.onPacketReceived(3);
    try std.testing.expectEqual(@as(u64, 3), space.firstAckRange());

    // Gap at packet 4: 0,1,2,3, _, 5 — range from 5 is just 0 (5 alone)
    space.onPacketReceived(5);
    try std.testing.expectEqual(@as(u64, 0), space.firstAckRange());

    // Fill the gap: 0..5 all received → range from 5 is 5 (acks 0..5)
    space.onPacketReceived(4);
    try std.testing.expectEqual(@as(u64, 5), space.firstAckRange());
}

test "PacketNumberSpace: collectAckRanges with single range" {
    var space = PacketNumberSpace{};
    space.onPacketReceived(0);
    space.onPacketReceived(1);
    space.onPacketReceived(2);
    space.onPacketReceived(3);

    var buf: [8]frame.AckRange = undefined;
    const result = space.collectAckRanges(&buf);
    try std.testing.expectEqual(@as(u64, 3), result.first_range);
    try std.testing.expectEqual(@as(usize, 0), result.additional_count);
}

test "PacketNumberSpace: collectAckRanges with one gap" {
    var space = PacketNumberSpace{};
    // Received: 0,1,2,_,_,5,6,7  (gap at 3,4)
    space.onPacketReceived(0);
    space.onPacketReceived(1);
    space.onPacketReceived(2);
    space.onPacketReceived(5);
    space.onPacketReceived(6);
    space.onPacketReceived(7);

    var buf: [8]frame.AckRange = undefined;
    const result = space.collectAckRanges(&buf);
    // First range: {5, 6, 7} → largest=7, smallest=5, first_range = 7-5 = 2
    try std.testing.expectEqual(@as(u64, 2), result.first_range);
    try std.testing.expectEqual(@as(usize, 1), result.additional_count);
    // Next range: {0, 1, 2}. largest=2, length encoding = 2 (3 packets - 1).
    // Gap = prev.smallest (5) - next.largest (2) - 2 = 1.
    try std.testing.expectEqual(@as(u64, 1), buf[0].gap);
    try std.testing.expectEqual(@as(u64, 2), buf[0].length);
}

test "PacketNumberSpace: collectAckRanges with two gaps" {
    var space = PacketNumberSpace{};
    // Received: 0,_,2,_,4,_,_,7  (gaps at 1,3,5,6)
    space.onPacketReceived(0);
    space.onPacketReceived(2);
    space.onPacketReceived(4);
    space.onPacketReceived(7);

    var buf: [8]frame.AckRange = undefined;
    const result = space.collectAckRanges(&buf);
    // First range: {7} — just the largest. first_range = 0.
    try std.testing.expectEqual(@as(u64, 0), result.first_range);
    try std.testing.expectEqual(@as(usize, 3), result.additional_count);
    // Range 1: {4}. Gap = 7-4-2 = 1. Length = 0.
    try std.testing.expectEqual(@as(u64, 1), buf[0].gap);
    try std.testing.expectEqual(@as(u64, 0), buf[0].length);
    // Range 2: {2}. Gap = 4-2-2 = 0. Length = 0.
    try std.testing.expectEqual(@as(u64, 0), buf[1].gap);
    try std.testing.expectEqual(@as(u64, 0), buf[1].length);
    // Range 3: {0}. Gap = 2-0-2 = 0. Length = 0.
    try std.testing.expectEqual(@as(u64, 0), buf[2].gap);
    try std.testing.expectEqual(@as(u64, 0), buf[2].length);
}

test "PacketNumberSpace: collectAckRanges respects output buffer limit" {
    var space = PacketNumberSpace{};
    // Four disjoint ranges: {8}, {6}, {4}, {2}
    space.onPacketReceived(2);
    space.onPacketReceived(4);
    space.onPacketReceived(6);
    space.onPacketReceived(8);

    // Give the walker only 2 slots — it should fill them and stop.
    var buf: [2]frame.AckRange = undefined;
    const result = space.collectAckRanges(&buf);
    try std.testing.expectEqual(@as(u64, 0), result.first_range);
    try std.testing.expectEqual(@as(usize, 2), result.additional_count);
}

test "PacketNumberSpace: collectAckRanges with empty out delegates to firstAckRange" {
    var space = PacketNumberSpace{};
    space.onPacketReceived(0);
    space.onPacketReceived(1);
    space.onPacketReceived(2);

    const result = space.collectAckRanges(&[_]frame.AckRange{});
    try std.testing.expectEqual(@as(u64, 2), result.first_range);
    try std.testing.expectEqual(@as(usize, 0), result.additional_count);
    // firstAckRange should return the same value.
    try std.testing.expectEqual(result.first_range, space.firstAckRange());
}

test "PacketNumberSpace: bitmap window slides forward" {
    var space = PacketNumberSpace{};

    // Receive packet at the very start of the window
    space.onPacketReceived(0);
    try std.testing.expect(space.isDuplicate(0));

    // Receive a packet far beyond the 64-bit window
    space.onPacketReceived(100);
    try std.testing.expect(space.isDuplicate(100));
    // Old packets that fell out of the window are now considered duplicates
    // (assumed seen) — single-range ACK is correct as long as we never act
    // on this assumption beyond the ACK contents.
    try std.testing.expect(space.isDuplicate(0));
    // A new packet at 99 is still in the window and not seen yet
    try std.testing.expect(!space.isDuplicate(99));
    space.onPacketReceived(99);
    try std.testing.expect(space.isDuplicate(99));
}

test "TransportParams: encode round-trips through decode" {
    var src: TransportParams = .{
        .max_idle_timeout = 30000,
        .max_udp_payload_size = 1500,
        .initial_max_data = 1024 * 1024,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_stream_data_uni = 256 * 1024,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .ack_delay_exponent = 3,
        .max_ack_delay = 25,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = types.ConnectionId.init(&[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }),
    };

    var buf: [512]u8 = undefined;
    const written = try src.encode(&buf);
    try std.testing.expect(written > 0);

    var dst: TransportParams = .{};
    try dst.decode(buf[0..written]);

    try std.testing.expectEqual(src.max_idle_timeout, dst.max_idle_timeout);
    try std.testing.expectEqual(src.initial_max_data, dst.initial_max_data);
    try std.testing.expectEqual(src.initial_max_stream_data_bidi_local, dst.initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(src.initial_max_streams_bidi, dst.initial_max_streams_bidi);
    try std.testing.expectEqual(src.ack_delay_exponent, dst.ack_delay_exponent);
    try std.testing.expectEqual(src.max_ack_delay, dst.max_ack_delay);
    try std.testing.expectEqual(src.active_connection_id_limit, dst.active_connection_id_limit);
    const src_cid = src.initial_source_connection_id.?;
    const dst_cid = dst.initial_source_connection_id.?;
    try std.testing.expectEqualSlices(u8, src_cid.slice(), dst_cid.slice());
}

test "CryptoReassembly: in-order writes" {
    var r: CryptoReassembly = .{};
    try r.write(0, "hello");
    try std.testing.expectEqualStrings("hello", r.drainContiguous());
    try std.testing.expectEqual(@as(u64, 5), r.next_contiguous_offset);
    // Subsequent in-order data
    try r.write(5, " world");
    try std.testing.expectEqualStrings(" world", r.drainContiguous());
}

test "CryptoReassembly: out-of-order writes wait for in-order prefix" {
    var r: CryptoReassembly = .{};
    // Write the back half first
    try r.write(5, " world");
    // Nothing to drain — there's still a hole at offset 0..5
    try std.testing.expectEqualStrings("", r.drainContiguous());
    // Now write the front half
    try r.write(0, "hello");
    // Both halves should drain together
    try std.testing.expectEqualStrings("hello world", r.drainContiguous());
}

test "CryptoReassembly: rejects writes past capacity" {
    var r: CryptoReassembly = .{};
    var big: [CryptoReassembly.capacity + 1]u8 = undefined;
    @memset(&big, 'x');
    try std.testing.expectError(error.OutOfBounds, r.write(0, &big));
}
