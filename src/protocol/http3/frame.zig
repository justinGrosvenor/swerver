const std = @import("std");

/// HTTP/3 Frame Types per RFC 9114.
///
/// HTTP/3 frames are sent on QUIC streams and have their own format
/// distinct from QUIC frames.

pub const Error = error{
    BufferTooSmall,
    InvalidFrame,
    UnexpectedEnd,
    ValueTooLarge,
    UnknownFrameType,
    InvalidEncoding,
};

/// HTTP/3 frame types per RFC 9114 Section 7.2
pub const FrameType = enum(u64) {
    /// DATA frame carries request/response body
    data = 0x00,
    /// HEADERS frame carries HTTP header fields
    headers = 0x01,
    /// CANCEL_PUSH cancels a server push
    cancel_push = 0x03,
    /// SETTINGS frame conveys configuration parameters
    settings = 0x04,
    /// PUSH_PROMISE initiates a server push
    push_promise = 0x05,
    /// GOAWAY initiates graceful shutdown
    goaway = 0x06,
    /// MAX_PUSH_ID limits push IDs
    max_push_id = 0x0d,

    // Reserved frame types (for grease)
    _,

    pub fn isKnown(t: u64) bool {
        return t == 0x00 or t == 0x01 or t == 0x03 or
            t == 0x04 or t == 0x05 or t == 0x06 or t == 0x0d;
    }
};

/// HTTP/3 SETTINGS identifiers per RFC 9114 Section 7.2.4.1
pub const SettingsId = enum(u64) {
    /// QPACK max table capacity
    qpack_max_table_capacity = 0x01,
    /// Max concurrent push streams (deprecated, must be 0)
    max_field_section_size = 0x06,
    /// QPACK blocked streams
    qpack_blocked_streams = 0x07,
    /// Enable CONNECT protocol
    enable_connect_protocol = 0x08,

    _,
};

/// Maximum variable-length integer value (2^62 - 1)
const MAX_VARINT: u64 = (1 << 62) - 1;

/// Decode a variable-length integer (same format as QUIC)
pub fn decodeVarint(buf: []const u8) Error!struct { value: u64, len: usize } {
    if (buf.len == 0) return error.UnexpectedEnd;

    const first_byte = buf[0];
    const prefix: u2 = @truncate(first_byte >> 6);

    return switch (prefix) {
        0b00 => .{
            .value = first_byte & 0x3f,
            .len = 1,
        },
        0b01 => {
            if (buf.len < 2) return error.UnexpectedEnd;
            const value = (@as(u64, first_byte & 0x3f) << 8) | @as(u64, buf[1]);
            return .{ .value = value, .len = 2 };
        },
        0b10 => {
            if (buf.len < 4) return error.UnexpectedEnd;
            const value = (@as(u64, first_byte & 0x3f) << 24) |
                (@as(u64, buf[1]) << 16) |
                (@as(u64, buf[2]) << 8) |
                @as(u64, buf[3]);
            return .{ .value = value, .len = 4 };
        },
        0b11 => {
            if (buf.len < 8) return error.UnexpectedEnd;
            const value = (@as(u64, first_byte & 0x3f) << 56) |
                (@as(u64, buf[1]) << 48) |
                (@as(u64, buf[2]) << 40) |
                (@as(u64, buf[3]) << 32) |
                (@as(u64, buf[4]) << 24) |
                (@as(u64, buf[5]) << 16) |
                (@as(u64, buf[6]) << 8) |
                @as(u64, buf[7]);
            return .{ .value = value, .len = 8 };
        },
    };
}

/// Encode a variable-length integer
pub fn encodeVarint(buf: []u8, value: u64) Error!usize {
    if (value > MAX_VARINT) return error.ValueTooLarge;

    const len = varintLength(value);
    if (buf.len < len) return error.BufferTooSmall;

    switch (len) {
        1 => {
            buf[0] = @intCast(value);
        },
        2 => {
            buf[0] = @intCast(0x40 | (value >> 8));
            buf[1] = @intCast(value & 0xff);
        },
        4 => {
            buf[0] = @intCast(0x80 | (value >> 24));
            buf[1] = @intCast((value >> 16) & 0xff);
            buf[2] = @intCast((value >> 8) & 0xff);
            buf[3] = @intCast(value & 0xff);
        },
        8 => {
            buf[0] = @intCast(0xc0 | (value >> 56));
            buf[1] = @intCast((value >> 48) & 0xff);
            buf[2] = @intCast((value >> 40) & 0xff);
            buf[3] = @intCast((value >> 32) & 0xff);
            buf[4] = @intCast((value >> 24) & 0xff);
            buf[5] = @intCast((value >> 16) & 0xff);
            buf[6] = @intCast((value >> 8) & 0xff);
            buf[7] = @intCast(value & 0xff);
        },
        else => unreachable,
    }

    return len;
}

/// Calculate encoded length of a variable-length integer
pub fn varintLength(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

/// Parsed HTTP/3 frame header
pub const FrameHeader = struct {
    frame_type: u64,
    length: u64,
    header_len: usize,
};

/// Parse an HTTP/3 frame header
pub fn parseFrameHeader(buf: []const u8) Error!FrameHeader {
    const type_result = try decodeVarint(buf);
    if (buf.len < type_result.len) return error.UnexpectedEnd;

    const len_result = try decodeVarint(buf[type_result.len..]);

    return FrameHeader{
        .frame_type = type_result.value,
        .length = len_result.value,
        .header_len = type_result.len + len_result.len,
    };
}

/// DATA frame (type 0x00)
pub const DataFrame = struct {
    data: []const u8,
};

/// HEADERS frame (type 0x01)
pub const HeadersFrame = struct {
    /// QPACK-encoded header field section
    encoded_headers: []const u8,
};

/// CANCEL_PUSH frame (type 0x03)
pub const CancelPushFrame = struct {
    push_id: u64,
};

/// SETTINGS parameter
pub const SettingsParam = struct {
    id: u64,
    value: u64,
};

/// Maximum number of SETTINGS parameters
pub const MAX_SETTINGS_PARAMS = 16;

/// SETTINGS frame (type 0x04)
pub const SettingsFrame = struct {
    params: [MAX_SETTINGS_PARAMS]SettingsParam = undefined,
    param_count: usize = 0,

    pub fn getParams(self: *const SettingsFrame) []const SettingsParam {
        return self.params[0..self.param_count];
    }
};

/// PUSH_PROMISE frame (type 0x05)
pub const PushPromiseFrame = struct {
    push_id: u64,
    encoded_headers: []const u8,
};

/// GOAWAY frame (type 0x06)
pub const GoawayFrame = struct {
    stream_id: u64,
};

/// MAX_PUSH_ID frame (type 0x0d)
pub const MaxPushIdFrame = struct {
    push_id: u64,
};

/// Unknown/reserved frame
pub const UnknownFrame = struct {
    frame_type: u64,
    payload: []const u8,
};

/// Parsed HTTP/3 frame
pub const Frame = union(enum) {
    data: DataFrame,
    headers: HeadersFrame,
    cancel_push: CancelPushFrame,
    settings: SettingsFrame,
    push_promise: PushPromiseFrame,
    goaway: GoawayFrame,
    max_push_id: MaxPushIdFrame,
    unknown: UnknownFrame,
};

/// Parse an HTTP/3 frame
pub fn parseFrame(buf: []const u8, allocator: std.mem.Allocator) Error!struct { frame: Frame, consumed: usize } {
    const header = try parseFrameHeader(buf);

    // Check for overflow before casting to usize (important on 32-bit systems)
    if (header.length > std.math.maxInt(usize) - header.header_len) {
        return error.ValueTooLarge;
    }
    const total_len = header.header_len + @as(usize, @intCast(header.length));
    if (buf.len < total_len) return error.UnexpectedEnd;

    const payload = buf[header.header_len..total_len];

    const frame: Frame = switch (header.frame_type) {
        0x00 => .{ .data = .{ .data = payload } },
        0x01 => .{ .headers = .{ .encoded_headers = payload } },
        0x03 => blk: {
            const push_id = try decodeVarint(payload);
            break :blk .{ .cancel_push = .{ .push_id = push_id.value } };
        },
        0x04 => blk: {
            _ = allocator;
            // Parse SETTINGS parameters (fixed-size buffer)
            var frame = SettingsFrame{};

            var offset: usize = 0;
            while (offset < payload.len) {
                const id_result = try decodeVarint(payload[offset..]);
                offset += id_result.len;

                const value_result = try decodeVarint(payload[offset..]);
                offset += value_result.len;

                if (frame.param_count >= MAX_SETTINGS_PARAMS) {
                    return error.BufferTooSmall;
                }

                frame.params[frame.param_count] = .{
                    .id = id_result.value,
                    .value = value_result.value,
                };
                frame.param_count += 1;
            }

            break :blk .{ .settings = frame };
        },
        0x05 => blk: {
            const push_id = try decodeVarint(payload);
            break :blk .{ .push_promise = .{
                .push_id = push_id.value,
                .encoded_headers = payload[push_id.len..],
            } };
        },
        0x06 => blk: {
            const stream_id = try decodeVarint(payload);
            break :blk .{ .goaway = .{ .stream_id = stream_id.value } };
        },
        0x0d => blk: {
            const push_id = try decodeVarint(payload);
            break :blk .{ .max_push_id = .{ .push_id = push_id.value } };
        },
        else => .{ .unknown = .{
            .frame_type = header.frame_type,
            .payload = payload,
        } },
    };

    return .{ .frame = frame, .consumed = total_len };
}

/// Write a DATA frame
pub fn writeDataFrame(buf: []u8, data: []const u8) Error!usize {
    var offset: usize = 0;

    // Frame type
    offset += try encodeVarint(buf[offset..], 0x00);

    // Length
    offset += try encodeVarint(buf[offset..], data.len);

    // Payload
    if (buf.len < offset + data.len) return error.BufferTooSmall;
    @memcpy(buf[offset .. offset + data.len], data);
    offset += data.len;

    return offset;
}

/// Write a HEADERS frame
pub fn writeHeadersFrame(buf: []u8, encoded_headers: []const u8) Error!usize {
    var offset: usize = 0;

    // Frame type
    offset += try encodeVarint(buf[offset..], 0x01);

    // Length
    offset += try encodeVarint(buf[offset..], encoded_headers.len);

    // Payload
    if (buf.len < offset + encoded_headers.len) return error.BufferTooSmall;
    @memcpy(buf[offset .. offset + encoded_headers.len], encoded_headers);
    offset += encoded_headers.len;

    return offset;
}

/// Write a SETTINGS frame
pub fn writeSettingsFrame(buf: []u8, params: []const SettingsParam) Error!usize {
    // First calculate payload size
    var payload_len: usize = 0;
    for (params) |param| {
        payload_len += varintLength(param.id);
        payload_len += varintLength(param.value);
    }

    var offset: usize = 0;

    // Frame type
    offset += try encodeVarint(buf[offset..], 0x04);

    // Length
    offset += try encodeVarint(buf[offset..], payload_len);

    // Parameters
    for (params) |param| {
        offset += try encodeVarint(buf[offset..], param.id);
        offset += try encodeVarint(buf[offset..], param.value);
    }

    return offset;
}

/// Write a GOAWAY frame
pub fn writeGoawayFrame(buf: []u8, stream_id: u64) Error!usize {
    var offset: usize = 0;

    // Frame type
    offset += try encodeVarint(buf[offset..], 0x06);

    // Length
    const payload_len = varintLength(stream_id);
    offset += try encodeVarint(buf[offset..], payload_len);

    // Stream ID
    offset += try encodeVarint(buf[offset..], stream_id);

    return offset;
}

// Tests
test "varint encode/decode round trip" {
    var buf: [8]u8 = undefined;

    // 1-byte
    {
        const len = try encodeVarint(&buf, 37);
        try std.testing.expectEqual(@as(usize, 1), len);
        const result = try decodeVarint(&buf);
        try std.testing.expectEqual(@as(u64, 37), result.value);
    }

    // 2-byte
    {
        const len = try encodeVarint(&buf, 15293);
        try std.testing.expectEqual(@as(usize, 2), len);
        const result = try decodeVarint(&buf);
        try std.testing.expectEqual(@as(u64, 15293), result.value);
    }

    // 4-byte
    {
        const len = try encodeVarint(&buf, 494878333);
        try std.testing.expectEqual(@as(usize, 4), len);
        const result = try decodeVarint(&buf);
        try std.testing.expectEqual(@as(u64, 494878333), result.value);
    }
}

test "parse frame header" {
    // DATA frame with 10 bytes payload
    var buf: [16]u8 = undefined;
    var len = try encodeVarint(&buf, 0x00); // type
    len += try encodeVarint(buf[len..], 10); // length

    const header = try parseFrameHeader(&buf);
    try std.testing.expectEqual(@as(u64, 0x00), header.frame_type);
    try std.testing.expectEqual(@as(u64, 10), header.length);
}

test "write and parse DATA frame" {
    var buf: [256]u8 = undefined;

    const data = "Hello, HTTP/3!";
    const written = try writeDataFrame(&buf, data);

    const result = try parseFrame(buf[0..written], std.testing.allocator);
    try std.testing.expectEqual(@as(usize, written), result.consumed);

    switch (result.frame) {
        .data => |frame| {
            try std.testing.expectEqualStrings(data, frame.data);
        },
        else => try std.testing.expect(false),
    }
}

test "write and parse SETTINGS frame" {
    var buf: [256]u8 = undefined;

    const params = [_]SettingsParam{
        .{ .id = @intFromEnum(SettingsId.qpack_max_table_capacity), .value = 4096 },
        .{ .id = @intFromEnum(SettingsId.max_field_section_size), .value = 16384 },
    };

    const written = try writeSettingsFrame(&buf, &params);

    const result = try parseFrame(buf[0..written], std.testing.allocator);
    try std.testing.expectEqual(@as(usize, written), result.consumed);

    switch (result.frame) {
        .settings => |frame| {
            const parsed_params = frame.getParams();
            try std.testing.expectEqual(@as(usize, 2), parsed_params.len);
            try std.testing.expectEqual(@as(u64, 0x01), parsed_params[0].id);
            try std.testing.expectEqual(@as(u64, 4096), parsed_params[0].value);
        },
        else => try std.testing.expect(false),
    }
}

test "write and parse GOAWAY frame" {
    var buf: [32]u8 = undefined;

    const written = try writeGoawayFrame(&buf, 100);

    const result = try parseFrame(buf[0..written], std.testing.allocator);
    try std.testing.expectEqual(@as(usize, written), result.consumed);

    switch (result.frame) {
        .goaway => |frame| {
            try std.testing.expectEqual(@as(u64, 100), frame.stream_id);
        },
        else => try std.testing.expect(false),
    }
}
