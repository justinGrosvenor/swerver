const std = @import("std");

/// QUIC protocol types and constants per RFC 9000.

// QUIC versions
pub const Version = enum(u32) {
    /// QUIC v1 (RFC 9000)
    quic_v1 = 0x00000001,
    /// QUIC v2 (RFC 9369)
    quic_v2 = 0x6b3343cf,
    /// Version negotiation
    negotiation = 0x00000000,

    pub fn isSupported(v: u32) bool {
        return v == @intFromEnum(Version.quic_v1) or v == @intFromEnum(Version.quic_v2);
    }
};

/// Long header packet types (first 2 bits of first byte after form bit)
pub const PacketType = enum(u2) {
    initial = 0b00,
    zero_rtt = 0b01,
    handshake = 0b10,
    retry = 0b11,
};

/// QUIC frame types per RFC 9000 Section 12.4
pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    // STREAM frames: 0x08-0x0f (lower 3 bits encode OFF/LEN/FIN flags)
    stream_base = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close_quic = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,

    pub fn isStream(frame_type: u64) bool {
        return frame_type >= 0x08 and frame_type <= 0x0f;
    }

    pub fn isAck(frame_type: u64) bool {
        return frame_type == 0x02 or frame_type == 0x03;
    }
};

/// STREAM frame flags (lower 3 bits of frame type)
pub const StreamFlags = struct {
    pub const OFF: u8 = 0x04; // Offset field present
    pub const LEN: u8 = 0x02; // Length field present
    pub const FIN: u8 = 0x01; // Final frame in stream
};

/// QUIC transport error codes per RFC 9000 Section 20
pub const TransportError = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    // Crypto errors: 0x0100-0x01ff (TLS alert + 0x100)
    _,

    pub fn fromTlsAlert(alert: u8) TransportError {
        return @enumFromInt(0x0100 + @as(u64, alert));
    }
};

/// Connection ID (max 20 bytes per RFC 9000)
pub const ConnectionId = struct {
    bytes: [20]u8 = undefined,
    len: u8 = 0,

    pub fn init(data: []const u8) ConnectionId {
        var cid = ConnectionId{};
        const copy_len = @min(data.len, 20);
        @memcpy(cid.bytes[0..copy_len], data[0..copy_len]);
        cid.len = @intCast(copy_len);
        return cid;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const ConnectionId, other: *const ConnectionId) bool {
        if (self.len != other.len) return false;
        return std.mem.eql(u8, self.slice(), other.slice());
    }

    pub fn hash(self: *const ConnectionId) u64 {
        return std.hash.Wyhash.hash(0, self.slice());
    }
};

/// Stream ID type (62-bit unsigned integer)
pub const StreamId = u64;

/// Stream ID helpers
pub const StreamIdHelpers = struct {
    /// Check if stream is client-initiated (bit 0 = 0)
    pub fn isClientInitiated(id: StreamId) bool {
        return (id & 0x01) == 0;
    }

    /// Check if stream is server-initiated (bit 0 = 1)
    pub fn isServerInitiated(id: StreamId) bool {
        return (id & 0x01) == 1;
    }

    /// Check if stream is bidirectional (bit 1 = 0)
    pub fn isBidirectional(id: StreamId) bool {
        return (id & 0x02) == 0;
    }

    /// Check if stream is unidirectional (bit 1 = 1)
    pub fn isUnidirectional(id: StreamId) bool {
        return (id & 0x02) == 2;
    }

    /// Get stream type from ID
    pub fn getType(id: StreamId) StreamType {
        return @enumFromInt(@as(u2, @truncate(id)));
    }
};

/// Stream type based on initiator and direction
pub const StreamType = enum(u2) {
    client_bidi = 0b00,
    server_bidi = 0b01,
    client_uni = 0b10,
    server_uni = 0b11,
};

/// Packet number space
pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

/// Encryption level (maps to packet number space)
pub const EncryptionLevel = enum {
    initial,
    early_data,
    handshake,
    application,

    pub fn toPacketNumberSpace(self: EncryptionLevel) PacketNumberSpace {
        return switch (self) {
            .initial, .early_data => .initial,
            .handshake => .handshake,
            .application => .application,
        };
    }
};

/// Transport parameter IDs per RFC 9000 Section 18.2
pub const TransportParamId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    // QUIC v2 adds: version_information = 0x11
    _,
};

/// Default transport parameter values per RFC 9000
pub const TransportParamDefaults = struct {
    pub const max_udp_payload_size: u64 = 65527;
    pub const ack_delay_exponent: u8 = 3;
    pub const max_ack_delay: u64 = 25; // milliseconds
    pub const active_connection_id_limit: u64 = 2;
    pub const initial_max_streams_bidi: u64 = 0;
    pub const initial_max_streams_uni: u64 = 0;
    pub const initial_max_data: u64 = 0;
    pub const initial_max_stream_data_bidi_local: u64 = 0;
    pub const initial_max_stream_data_bidi_remote: u64 = 0;
    pub const initial_max_stream_data_uni: u64 = 0;
};

/// Protocol constants
pub const Constants = struct {
    /// Maximum connection ID length
    pub const max_cid_len: u8 = 20;
    /// Minimum Initial packet size (for path MTU discovery)
    pub const min_initial_packet_size: usize = 1200;
    /// Maximum datagram size without path MTU discovery
    pub const max_datagram_size: usize = 1200;
    /// Initial packet number
    pub const initial_packet_number: u64 = 0;
    /// Maximum packet number (62-bit)
    pub const max_packet_number: u64 = (1 << 62) - 1;
    /// QUIC v1 Initial salt (RFC 9001 Section 5.2)
    pub const quic_v1_initial_salt = [_]u8{
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    };
    /// QUIC v2 Initial salt (RFC 9369)
    pub const quic_v2_initial_salt = [_]u8{
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    };
};

/// ALPN protocol identifier for HTTP/3
pub const HTTP3_ALPN = "h3";
pub const HTTP3_ALPN_29 = "h3-29"; // Draft version for compatibility
