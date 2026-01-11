const std = @import("std");
const types = @import("types.zig");
const varint = @import("varint.zig");

/// QUIC Packet Header Parsing per RFC 9000 Section 17.
///
/// Packet formats:
/// - Long Header: Used for Initial, 0-RTT, Handshake, and Retry packets
/// - Short Header: Used for 1-RTT packets after handshake completion

pub const ParseError = error{
    BufferTooSmall,
    InvalidHeader,
    InvalidVersion,
    InvalidConnectionId,
    UnsupportedVersion,
} || varint.Error;

pub const ParseState = enum {
    complete,
    partial,
    err,
};

/// Long header packet structure (Initial, Handshake, 0-RTT, Retry)
pub const LongHeader = struct {
    packet_type: types.PacketType,
    version: u32,
    dcid: types.ConnectionId,
    scid: types.ConnectionId,
    /// For Initial packets: token field
    token: []const u8,
    /// For Retry packets: retry token
    retry_token: []const u8,
    /// Offset where payload starts (after header)
    payload_offset: usize,
    /// Length of payload (from Length field, before packet number)
    payload_length: usize,
    /// Packet number offset within payload
    packet_number_offset: usize,
};

/// Short header packet structure (1-RTT)
pub const ShortHeader = struct {
    dcid: types.ConnectionId,
    /// Offset where packet number starts
    packet_number_offset: usize,
    /// Key phase bit
    key_phase: bool,
    /// Spin bit
    spin_bit: bool,
};

/// Unified header type
pub const Header = union(enum) {
    long: LongHeader,
    short: ShortHeader,

    pub fn isLong(self: Header) bool {
        return self == .long;
    }
};

/// Result of parsing a packet header
pub const ParseResult = struct {
    state: ParseState,
    header: ?Header,
    consumed: usize,
    error_detail: ?[]const u8,
};

/// Header form bit (first bit of first byte)
const HEADER_FORM_LONG: u8 = 0x80;
/// Fixed bit (second bit, must be 1 for valid packets)
const FIXED_BIT: u8 = 0x40;

/// Parse a packet header from the buffer.
/// For long headers, dcid_len is ignored.
/// For short headers, dcid_len specifies the expected DCID length.
pub fn parseHeader(buf: []const u8, dcid_len: u8) ParseResult {
    if (buf.len == 0) {
        return .{
            .state = .partial,
            .header = null,
            .consumed = 0,
            .error_detail = "empty buffer",
        };
    }

    const first_byte = buf[0];

    // Check fixed bit (must be 1 for all QUIC packets)
    if ((first_byte & FIXED_BIT) == 0) {
        return .{
            .state = .err,
            .header = null,
            .consumed = 0,
            .error_detail = "fixed bit not set",
        };
    }

    if ((first_byte & HEADER_FORM_LONG) != 0) {
        return parseLongHeader(buf);
    } else {
        return parseShortHeader(buf, dcid_len);
    }
}

fn parseLongHeader(buf: []const u8) ParseResult {
    // Minimum long header: 1 (first byte) + 4 (version) + 1 (DCID len) + 1 (SCID len) = 7
    if (buf.len < 7) {
        return .{
            .state = .partial,
            .header = null,
            .consumed = 0,
            .error_detail = "buffer too small for long header",
        };
    }

    const first_byte = buf[0];
    const packet_type: types.PacketType = @enumFromInt(@as(u2, @truncate((first_byte >> 4) & 0x03)));

    // Parse version (bytes 1-4, big-endian)
    const version = (@as(u32, buf[1]) << 24) |
        (@as(u32, buf[2]) << 16) |
        (@as(u32, buf[3]) << 8) |
        @as(u32, buf[4]);

    // DCID length (byte 5)
    const dcid_len = buf[5];
    if (dcid_len > types.Constants.max_cid_len) {
        return .{
            .state = .err,
            .header = null,
            .consumed = 0,
            .error_detail = "DCID too long",
        };
    }

    var offset: usize = 6;

    // Check buffer has DCID
    if (buf.len < offset + dcid_len) {
        return .{
            .state = .partial,
            .header = null,
            .consumed = 0,
            .error_detail = "buffer too small for DCID",
        };
    }

    var dcid = types.ConnectionId{};
    if (dcid_len > 0) {
        @memcpy(dcid.bytes[0..dcid_len], buf[offset .. offset + dcid_len]);
        dcid.len = dcid_len;
    }
    offset += dcid_len;

    // SCID length
    if (buf.len < offset + 1) {
        return .{
            .state = .partial,
            .header = null,
            .consumed = 0,
            .error_detail = "buffer too small for SCID length",
        };
    }
    const scid_len = buf[offset];
    offset += 1;

    if (scid_len > types.Constants.max_cid_len) {
        return .{
            .state = .err,
            .header = null,
            .consumed = 0,
            .error_detail = "SCID too long",
        };
    }

    // Check buffer has SCID
    if (buf.len < offset + scid_len) {
        return .{
            .state = .partial,
            .header = null,
            .consumed = 0,
            .error_detail = "buffer too small for SCID",
        };
    }

    var scid = types.ConnectionId{};
    if (scid_len > 0) {
        @memcpy(scid.bytes[0..scid_len], buf[offset .. offset + scid_len]);
        scid.len = scid_len;
    }
    offset += scid_len;

    // Handle version negotiation
    if (version == 0) {
        // Version Negotiation packet - rest is list of supported versions
        return .{
            .state = .complete,
            .header = .{
                .long = .{
                    .packet_type = packet_type,
                    .version = version,
                    .dcid = dcid,
                    .scid = scid,
                    .token = &[_]u8{},
                    .retry_token = &[_]u8{},
                    .payload_offset = offset,
                    .payload_length = buf.len - offset,
                    .packet_number_offset = 0,
                },
            },
            .consumed = buf.len,
            .error_detail = null,
        };
    }

    // Handle Retry packets (no length field, no packet number)
    if (packet_type == .retry) {
        // Retry packet: rest is Retry Token + 16-byte Retry Integrity Tag
        if (buf.len < offset + 16) {
            return .{
                .state = .partial,
                .header = null,
                .consumed = 0,
                .error_detail = "buffer too small for Retry packet",
            };
        }

        return .{
            .state = .complete,
            .header = .{
                .long = .{
                    .packet_type = packet_type,
                    .version = version,
                    .dcid = dcid,
                    .scid = scid,
                    .token = &[_]u8{},
                    .retry_token = buf[offset .. buf.len - 16],
                    .payload_offset = buf.len,
                    .payload_length = 0,
                    .packet_number_offset = 0,
                },
            },
            .consumed = buf.len,
            .error_detail = null,
        };
    }

    // Parse Token for Initial packets
    var token: []const u8 = &[_]u8{};
    if (packet_type == .initial) {
        const token_result = varint.decode(buf[offset..]) catch |err| {
            return .{
                .state = if (err == error.UnexpectedEnd) .partial else .err,
                .header = null,
                .consumed = 0,
                .error_detail = "failed to parse token length",
            };
        };
        offset += token_result.len;

        if (buf.len < offset + token_result.value) {
            return .{
                .state = .partial,
                .header = null,
                .consumed = 0,
                .error_detail = "buffer too small for token",
            };
        }

        token = buf[offset .. offset + token_result.value];
        offset += token_result.value;
    }

    // Parse Length field (varint)
    const length_result = varint.decode(buf[offset..]) catch |err| {
        return .{
            .state = if (err == error.UnexpectedEnd) .partial else .err,
            .header = null,
            .consumed = 0,
            .error_detail = "failed to parse length field",
        };
    };
    offset += length_result.len;

    const payload_length = length_result.value;

    // Check we have enough data for the full packet
    if (buf.len < offset + payload_length) {
        return .{
            .state = .partial,
            .header = null,
            .consumed = 0,
            .error_detail = "buffer too small for payload",
        };
    }

    return .{
        .state = .complete,
        .header = .{
            .long = .{
                .packet_type = packet_type,
                .version = version,
                .dcid = dcid,
                .scid = scid,
                .token = token,
                .retry_token = &[_]u8{},
                .payload_offset = offset,
                .payload_length = payload_length,
                .packet_number_offset = offset,
            },
        },
        .consumed = offset + payload_length,
        .error_detail = null,
    };
}

fn parseShortHeader(buf: []const u8, dcid_len: u8) ParseResult {
    // Minimum short header: 1 (first byte) + dcid_len + 1 (min packet number)
    const min_len = 1 + @as(usize, dcid_len) + 1;
    if (buf.len < min_len) {
        return .{
            .state = .partial,
            .header = null,
            .consumed = 0,
            .error_detail = "buffer too small for short header",
        };
    }

    const first_byte = buf[0];
    const key_phase = (first_byte & 0x04) != 0;
    const spin_bit = (first_byte & 0x20) != 0;

    var dcid = types.ConnectionId{};
    if (dcid_len > 0) {
        @memcpy(dcid.bytes[0..dcid_len], buf[1 .. 1 + dcid_len]);
        dcid.len = dcid_len;
    }

    return .{
        .state = .complete,
        .header = .{
            .short = .{
                .dcid = dcid,
                .packet_number_offset = 1 + dcid_len,
                .key_phase = key_phase,
                .spin_bit = spin_bit,
            },
        },
        .consumed = 1 + dcid_len, // Packet number and payload follow
        .error_detail = null,
    };
}

/// Check if a buffer starts with a QUIC long header
pub fn isLongHeader(buf: []const u8) bool {
    if (buf.len == 0) return false;
    return (buf[0] & HEADER_FORM_LONG) != 0;
}

/// Extract version from a long header packet without full parsing
pub fn peekVersion(buf: []const u8) ?u32 {
    if (buf.len < 5) return null;
    if ((buf[0] & HEADER_FORM_LONG) == 0) return null;
    return (@as(u32, buf[1]) << 24) |
        (@as(u32, buf[2]) << 16) |
        (@as(u32, buf[3]) << 8) |
        @as(u32, buf[4]);
}

/// Extract DCID from a packet for routing purposes
pub fn peekDcid(buf: []const u8, short_header_dcid_len: u8) ?types.ConnectionId {
    if (buf.len == 0) return null;

    if (isLongHeader(buf)) {
        if (buf.len < 6) return null;
        const dcid_len = buf[5];
        if (dcid_len > types.Constants.max_cid_len) return null;
        if (buf.len < 6 + dcid_len) return null;

        var dcid = types.ConnectionId{};
        if (dcid_len > 0) {
            @memcpy(dcid.bytes[0..dcid_len], buf[6 .. 6 + dcid_len]);
            dcid.len = dcid_len;
        }
        return dcid;
    } else {
        if (buf.len < 1 + short_header_dcid_len) return null;
        var dcid = types.ConnectionId{};
        if (short_header_dcid_len > 0) {
            @memcpy(dcid.bytes[0..short_header_dcid_len], buf[1 .. 1 + short_header_dcid_len]);
            dcid.len = short_header_dcid_len;
        }
        return dcid;
    }
}

// Tests
test "parse Initial packet header" {
    // Construct a minimal Initial packet header
    var buf: [100]u8 = undefined;
    var offset: usize = 0;

    // First byte: Long header (0x80) | Fixed (0x40) | Initial type (0x00) | Reserved (0x00)
    buf[offset] = 0xc0;
    offset += 1;

    // Version (QUIC v1)
    buf[offset] = 0x00;
    buf[offset + 1] = 0x00;
    buf[offset + 2] = 0x00;
    buf[offset + 3] = 0x01;
    offset += 4;

    // DCID length = 8
    buf[offset] = 0x08;
    offset += 1;

    // DCID bytes
    @memset(buf[offset .. offset + 8], 0xaa);
    offset += 8;

    // SCID length = 4
    buf[offset] = 0x04;
    offset += 1;

    // SCID bytes
    @memset(buf[offset .. offset + 4], 0xbb);
    offset += 4;

    // Token length = 0 (varint)
    buf[offset] = 0x00;
    offset += 1;

    // Length = 10 (varint)
    buf[offset] = 0x0a;
    offset += 1;

    // Payload (10 bytes)
    @memset(buf[offset .. offset + 10], 0x00);
    offset += 10;

    const result = parseHeader(buf[0..offset], 0);
    try std.testing.expectEqual(ParseState.complete, result.state);
    try std.testing.expect(result.header != null);

    const header = result.header.?.long;
    try std.testing.expectEqual(types.PacketType.initial, header.packet_type);
    try std.testing.expectEqual(@as(u32, 1), header.version);
    try std.testing.expectEqual(@as(u8, 8), header.dcid.len);
    try std.testing.expectEqual(@as(u8, 4), header.scid.len);
    try std.testing.expectEqual(@as(usize, 10), header.payload_length);
}

test "parse short header" {
    var buf: [20]u8 = undefined;

    // First byte: Short header (no 0x80) | Fixed (0x40) | Key phase (0x04)
    buf[0] = 0x44;

    // DCID (8 bytes)
    @memset(buf[1..9], 0xcc);

    const result = parseHeader(&buf, 8);
    try std.testing.expectEqual(ParseState.complete, result.state);
    try std.testing.expect(result.header != null);

    const header = result.header.?.short;
    try std.testing.expectEqual(@as(u8, 8), header.dcid.len);
    try std.testing.expect(header.key_phase);
    try std.testing.expectEqual(@as(usize, 9), header.packet_number_offset);
}

test "partial header" {
    // Truncated long header
    const buf = [_]u8{ 0xc0, 0x00, 0x00 };
    const result = parseHeader(&buf, 0);
    try std.testing.expectEqual(ParseState.partial, result.state);
}

test "invalid fixed bit" {
    // Fixed bit not set (invalid)
    const buf = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    const result = parseHeader(&buf, 0);
    try std.testing.expectEqual(ParseState.err, result.state);
}
