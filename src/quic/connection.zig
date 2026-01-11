const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const varint = @import("varint.zig");
pub const metrics = @import("metrics.zig");

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
        if (self.largest_received) |largest| {
            if (pn > largest) {
                self.largest_received = pn;
            }
        } else {
            self.largest_received = pn;
        }
        self.ack_needed = true;
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
    last_activity: ?std.time.Instant = null,
    /// Connection metrics
    conn_metrics: metrics.ConnectionMetrics = .{ .created_at = null },

    pub fn init(allocator: std.mem.Allocator, is_server: bool, dcid: types.ConnectionId) Connection {
        var conn = Connection{
            .allocator = allocator,
            .is_server = is_server,
            .original_dcid = dcid,
            .our_cid = types.ConnectionId{},
            .peer_cid = dcid,
            .crypto_ctx = crypto.CryptoContext.init(),
            .last_activity = std.time.Instant.now() catch null,
            .conn_metrics = metrics.ConnectionMetrics.init(),
        };

        // Generate our connection ID (8 bytes) from hash of DCID
        // Note: In production, use cryptographically secure random bytes
        const hash = std.hash.Wyhash.hash(0, dcid.slice());
        const hash_bytes = std.mem.toBytes(hash);
        @memcpy(conn.our_cid.bytes[0..8], &hash_bytes);
        conn.our_cid.len = 8;

        // Derive initial keys from DCID
        conn.crypto_ctx.deriveInitialKeys(dcid.slice(), conn.version);

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        self.crypto_buffer.deinit(self.allocator);
    }

    /// Get the packet number space for a given type
    pub fn getPacketSpace(self: *Connection, space: types.PacketNumberSpace) *PacketNumberSpace {
        return switch (space) {
            .initial => &self.initial_space,
            .handshake => &self.handshake_space,
            .application => &self.application_space,
        };
    }

    /// Process an incoming packet
    pub fn processPacket(self: *Connection, data: []const u8) Error!void {
        self.last_activity = std.time.Instant.now() catch self.last_activity;

        // Parse header
        const result = packet.parseHeader(data, self.our_cid.len);
        if (result.state != .complete) {
            return Error.InvalidPacket;
        }

        const header = result.header orelse return Error.InvalidPacket;

        switch (header) {
            .long => |long| {
                try self.processLongHeaderPacket(long, data);
            },
            .short => |short| {
                try self.processShortHeaderPacket(short, data);
            },
        }
    }

    fn processLongHeaderPacket(self: *Connection, header: packet.LongHeader, data: []const u8) Error!void {
        _ = data;

        switch (header.packet_type) {
            .initial => {
                if (self.state != .initial and self.state != .handshaking) {
                    return Error.InvalidState;
                }
                // Process Initial packet
                try self.handleInitialPacket(header);
            },
            .handshake => {
                if (self.state != .handshaking and self.state != .connected) {
                    return Error.InvalidState;
                }
                try self.handleHandshakePacket(header);
            },
            .zero_rtt => {
                // 0-RTT not supported yet
                return Error.InvalidState;
            },
            .retry => {
                if (!self.is_server and self.state == .initial) {
                    try self.handleRetryPacket(header);
                }
            },
        }
    }

    fn processShortHeaderPacket(self: *Connection, header: packet.ShortHeader, data: []const u8) Error!void {
        _ = data;
        _ = header;

        if (self.state != .connected) {
            return Error.InvalidState;
        }

        // Process 1-RTT packet
        // TODO: Decrypt and process frames
    }

    fn handleInitialPacket(self: *Connection, header: packet.LongHeader) Error!void {
        // Update peer's connection ID if needed
        if (header.scid.len > 0) {
            self.peer_cid = header.scid;
        }

        // Process CRYPTO frames from Initial packet
        // The handshake data would be extracted here
        if (self.state == .initial) {
            self.state = .handshaking;
        }
    }

    fn handleHandshakePacket(self: *Connection, header: packet.LongHeader) Error!void {
        _ = self;
        _ = header;

        // Process Handshake CRYPTO frames
        // When complete, transition to connected
        // This would be done after TLS handshake completes
    }

    fn handleRetryPacket(self: *Connection, header: packet.LongHeader) Error!void {
        _ = self;
        _ = header;
        // Validate Retry token integrity
        // Update connection ID and token
        // Re-send Initial packet with token
    }

    /// Transition to connected state
    pub fn onHandshakeComplete(self: *Connection) void {
        self.state = .connected;

        // Record handshake completion in metrics
        self.conn_metrics.handshakeComplete();

        // Apply peer's transport parameters to flow control
        self.flow_control.max_data_send = self.peer_params.initial_max_data;
        self.flow_control.max_data_recv = self.local_params.initial_max_data;

        // Discard Initial and Handshake keys
        self.initial_space.keys = null;
        self.handshake_space.keys = null;
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

    /// Enter draining state (received CONNECTION_CLOSE from peer)
    pub fn drain(self: *Connection) void {
        if (self.state == .closed) return;
        self.state = .draining;
    }

    /// Complete connection close
    pub fn onClosed(self: *Connection) void {
        self.state = .closed;
    }

    /// Check if connection is still alive
    pub fn isAlive(self: *const Connection) bool {
        return self.state != .closed and self.state != .draining;
    }

    /// Check if connection can send application data
    pub fn canSendAppData(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Check if idle timeout has expired
    pub fn isIdleTimedOut(self: *const Connection) bool {
        const last = self.last_activity orelse return false;
        const now = std.time.Instant.now() catch return false;
        const elapsed = now.since(last);
        return elapsed > self.idle_timeout_ns;
    }

    /// Process a received ACK frame
    pub fn processAckFrame(self: *Connection, ack: frame.AckFrame, space: types.PacketNumberSpace) void {
        const pn_space = self.getPacketSpace(space);
        pn_space.onAckReceived(ack.largest_ack);
        // TODO: Process ACK ranges for loss detection
    }

    /// Process a received MAX_DATA frame
    pub fn processMaxDataFrame(self: *Connection, max_data: u64) void {
        self.flow_control.updateMaxSend(max_data);
    }

    /// Process a received MAX_STREAM_DATA frame
    pub fn processMaxStreamDataFrame(_: *Connection, stream_id: u64, max_data: u64) void {
        // TODO: Forward to stream manager
        _ = stream_id;
        _ = max_data;
    }

    /// Process a received CONNECTION_CLOSE frame
    pub fn processConnectionClose(self: *Connection, error_code: u64, reason: []const u8) void {
        _ = reason;
        self.close_error = @enumFromInt(error_code);
        self.drain();
    }

    /// Generate an ACK frame for a packet number space
    pub fn generateAckFrame(self: *Connection, space: types.PacketNumberSpace) ?frame.AckFrame {
        const pn_space = self.getPacketSpace(space);

        if (!pn_space.ack_needed) return null;

        const largest = pn_space.largest_received orelse return null;

        pn_space.ack_needed = false;

        return frame.AckFrame{
            .largest_ack = largest,
            .ack_delay = 0, // TODO: Calculate actual delay
            .first_ack_range = largest, // Simple: ACK only largest
            .ack_ranges = &[_]frame.AckRange{},
            .ecn = null,
        };
    }
};

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
