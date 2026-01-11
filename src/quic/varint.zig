const std = @import("std");

/// QUIC Variable-Length Integer Encoding per RFC 9000 Section 16.
/// Uses 1, 2, 4, or 8 bytes to encode values from 0 to 2^62-1.
///
/// Format:
/// - 1 byte:  0b00xxxxxx (6 bits, max 63)
/// - 2 bytes: 0b01xxxxxx xxxxxxxx (14 bits, max 16383)
/// - 4 bytes: 0b10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (30 bits, max 1073741823)
/// - 8 bytes: 0b11xxxxxx ... (62 bits, max 4611686018427387903)

pub const Error = error{
    BufferTooSmall,
    ValueTooLarge,
    InvalidEncoding,
    UnexpectedEnd,
};

/// Maximum value that can be encoded (2^62 - 1)
pub const MAX_VALUE: u64 = (1 << 62) - 1;

/// Decode a variable-length integer from the buffer.
/// Returns the decoded value and the number of bytes consumed.
pub fn decode(buf: []const u8) Error!struct { value: u64, len: usize } {
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

/// Encode a variable-length integer into the buffer.
/// Returns the number of bytes written.
pub fn encode(buf: []u8, value: u64) Error!usize {
    if (value > MAX_VALUE) return error.ValueTooLarge;

    const len = encodedLength(value);
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

/// Calculate the number of bytes needed to encode a value.
pub fn encodedLength(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

/// Decode multiple variable-length integers from a buffer.
/// Useful for parsing frame payloads that contain multiple varints.
pub fn decodeMultiple(buf: []const u8, comptime count: usize) Error!struct { values: [count]u64, total_len: usize } {
    var values: [count]u64 = undefined;
    var offset: usize = 0;

    for (0..count) |i| {
        if (offset >= buf.len) return error.UnexpectedEnd;
        const result = try decode(buf[offset..]);
        values[i] = result.value;
        offset += result.len;
    }

    return .{ .values = values, .total_len = offset };
}

// Unit tests
test "encode and decode round trip" {
    var buf: [8]u8 = undefined;

    // Test 1-byte encoding
    {
        const len = try encode(&buf, 37);
        try std.testing.expectEqual(@as(usize, 1), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 37), result.value);
        try std.testing.expectEqual(@as(usize, 1), result.len);
    }

    // Test 2-byte encoding
    {
        const len = try encode(&buf, 15293);
        try std.testing.expectEqual(@as(usize, 2), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 15293), result.value);
        try std.testing.expectEqual(@as(usize, 2), result.len);
    }

    // Test 4-byte encoding
    {
        const len = try encode(&buf, 494878333);
        try std.testing.expectEqual(@as(usize, 4), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 494878333), result.value);
        try std.testing.expectEqual(@as(usize, 4), result.len);
    }

    // Test 8-byte encoding
    {
        const len = try encode(&buf, 151288809941952652);
        try std.testing.expectEqual(@as(usize, 8), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 151288809941952652), result.value);
        try std.testing.expectEqual(@as(usize, 8), result.len);
    }
}

test "RFC 9000 test vectors" {
    // Test vectors from RFC 9000 Section 16
    {
        // 37 encoded as 0x25
        const buf = [_]u8{0x25};
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 37), result.value);
    }

    {
        // 15293 encoded as 0x7bbd
        const buf = [_]u8{ 0x7b, 0xbd };
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 15293), result.value);
    }

    {
        // 494878333 encoded as 0x9d7f3e7d
        const buf = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d };
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 494878333), result.value);
    }

    {
        // 151288809941952652 encoded as 0xc2197c5eff14e88c
        const buf = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 151288809941952652), result.value);
    }
}

test "boundary values" {
    var buf: [8]u8 = undefined;

    // 1-byte max (63)
    {
        const len = try encode(&buf, 63);
        try std.testing.expectEqual(@as(usize, 1), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 63), result.value);
    }

    // 2-byte min (64)
    {
        const len = try encode(&buf, 64);
        try std.testing.expectEqual(@as(usize, 2), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 64), result.value);
    }

    // 2-byte max (16383)
    {
        const len = try encode(&buf, 16383);
        try std.testing.expectEqual(@as(usize, 2), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 16383), result.value);
    }

    // 4-byte min (16384)
    {
        const len = try encode(&buf, 16384);
        try std.testing.expectEqual(@as(usize, 4), len);
        const result = try decode(&buf);
        try std.testing.expectEqual(@as(u64, 16384), result.value);
    }
}

test "error cases" {
    // Empty buffer
    {
        const result = decode(&[_]u8{});
        try std.testing.expectError(error.UnexpectedEnd, result);
    }

    // Truncated 2-byte encoding
    {
        const buf = [_]u8{0x40};
        const result = decode(&buf);
        try std.testing.expectError(error.UnexpectedEnd, result);
    }

    // Buffer too small for encode
    {
        var buf: [1]u8 = undefined;
        const result = encode(&buf, 1000);
        try std.testing.expectError(error.BufferTooSmall, result);
    }

    // Value too large
    {
        var buf: [8]u8 = undefined;
        const result = encode(&buf, MAX_VALUE + 1);
        try std.testing.expectError(error.ValueTooLarge, result);
    }
}
