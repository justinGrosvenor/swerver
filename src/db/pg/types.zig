//! Binary-format decoders for the common PostgreSQL type OIDs
//! (design 9.0 phase 1), plus text-format parse helpers for fallback.
//!
//! All decoders are pure functions over the raw column bytes of a
//! DataRow value (binary result format, network byte order). `numeric`
//! is deliberately text-passthrough in v1 (design open question 6):
//! request it as `::text` or decode the text representation with the
//! fallback helpers.

const std = @import("std");

// Type OIDs from pg_type.dat (stable across PostgreSQL versions).
pub const OID_BOOL: u32 = 16;
pub const OID_BYTEA: u32 = 17;
pub const OID_INT8: u32 = 20;
pub const OID_INT2: u32 = 21;
pub const OID_INT4: u32 = 23;
pub const OID_TEXT: u32 = 25;
pub const OID_FLOAT4: u32 = 700;
pub const OID_FLOAT8: u32 = 701;
pub const OID_VARCHAR: u32 = 1043;
pub const OID_TIMESTAMPTZ: u32 = 1184;
pub const OID_NUMERIC: u32 = 1700;
pub const OID_UUID: u32 = 2950;

pub const DecodeError = error{
    InvalidLength,
    InvalidValue,
};

/// Microseconds between the Unix epoch (1970-01-01) and the PostgreSQL
/// timestamp epoch (2000-01-01), both UTC.
pub const PG_EPOCH_UNIX_MICROS: i64 = 946_684_800_000_000;

/// bool (oid 16): single byte, 0 or 1.
pub fn decodeBool(data: []const u8) DecodeError!bool {
    if (data.len != 1) return error.InvalidLength;
    return switch (data[0]) {
        0 => false,
        1 => true,
        else => error.InvalidValue,
    };
}

/// int2 (oid 21): big-endian i16.
pub fn decodeInt2(data: []const u8) DecodeError!i16 {
    if (data.len != 2) return error.InvalidLength;
    return std.mem.readInt(i16, data[0..2], .big);
}

/// int4 (oid 23): big-endian i32.
pub fn decodeInt4(data: []const u8) DecodeError!i32 {
    if (data.len != 4) return error.InvalidLength;
    return std.mem.readInt(i32, data[0..4], .big);
}

/// int8 (oid 20): big-endian i64.
pub fn decodeInt8(data: []const u8) DecodeError!i64 {
    if (data.len != 8) return error.InvalidLength;
    return std.mem.readInt(i64, data[0..8], .big);
}

/// float4 (oid 700): big-endian IEEE 754 single.
pub fn decodeFloat4(data: []const u8) DecodeError!f32 {
    if (data.len != 4) return error.InvalidLength;
    return @bitCast(std.mem.readInt(u32, data[0..4], .big));
}

/// float8 (oid 701): big-endian IEEE 754 double.
pub fn decodeFloat8(data: []const u8) DecodeError!f64 {
    if (data.len != 8) return error.InvalidLength;
    return @bitCast(std.mem.readInt(u64, data[0..8], .big));
}

/// text (oid 25) / varchar (oid 1043): the binary format is the bytes
/// themselves — passthrough, borrowing the input.
pub fn decodeText(data: []const u8) []const u8 {
    return data;
}

/// bytea (oid 17): binary format is the raw bytes — passthrough.
pub fn decodeBytea(data: []const u8) []const u8 {
    return data;
}

/// timestamptz (oid 1184): big-endian i64 microseconds since
/// 2000-01-01 00:00:00 UTC, converted to Unix microseconds.
/// PostgreSQL's ±infinity sentinels (maxInt/minInt) are rejected as
/// `error.InvalidValue` — they have no Unix-micros representation.
pub fn decodeTimestamptz(data: []const u8) DecodeError!i64 {
    if (data.len != 8) return error.InvalidLength;
    const pg_micros = std.mem.readInt(i64, data[0..8], .big);
    return pgMicrosToUnixMicros(pg_micros);
}

/// Convert microseconds-since-2000-01-01 to microseconds-since-1970-01-01.
/// PostgreSQL encodes 'infinity' as maxInt(i64) and '-infinity' as
/// minInt(i64); both are rejected explicitly.
pub fn pgMicrosToUnixMicros(pg_micros: i64) DecodeError!i64 {
    if (pg_micros == std.math.maxInt(i64) or pg_micros == std.math.minInt(i64)) {
        return error.InvalidValue;
    }
    const sum = @addWithOverflow(pg_micros, PG_EPOCH_UNIX_MICROS);
    if (sum[1] != 0) return error.InvalidValue;
    return sum[0];
}

/// Length of a canonical UUID string (8-4-4-4-12).
pub const UUID_STRING_LEN = 36;

/// uuid (oid 2950): 16 raw bytes, formatted as canonical lowercase hex
/// into the caller's buffer (at least `UUID_STRING_LEN` bytes).
pub fn decodeUuid(data: []const u8, out: []u8) DecodeError![]u8 {
    if (data.len != 16) return error.InvalidLength;
    if (out.len < UUID_STRING_LEN) return error.InvalidLength;
    const hex = "0123456789abcdef";
    var pos: usize = 0;
    for (data, 0..) |byte, i| {
        // Dashes after bytes 4, 6, 8, and 10.
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            out[pos] = '-';
            pos += 1;
        }
        out[pos] = hex[byte >> 4];
        out[pos + 1] = hex[byte & 0x0f];
        pos += 2;
    }
    return out[0..UUID_STRING_LEN];
}

// ---------------------------------------------------------------------------
// Text-format fallback helpers (result format 0, or numeric-as-text)
// ---------------------------------------------------------------------------

/// Parse a text-format integer column (also covers numeric without a
/// fractional part).
pub fn parseTextInt(data: []const u8) DecodeError!i64 {
    return std.fmt.parseInt(i64, data, 10) catch error.InvalidValue;
}

/// Parse a text-format float or numeric column.
pub fn parseTextFloat(data: []const u8) DecodeError!f64 {
    return std.fmt.parseFloat(f64, data) catch error.InvalidValue;
}

// ---------------------------------------------------------------------------
// Tests (golden bytes)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "decode bool" {
    try testing.expectEqual(false, try decodeBool(&.{0}));
    try testing.expectEqual(true, try decodeBool(&.{1}));
    try testing.expectError(error.InvalidValue, decodeBool(&.{2}));
    try testing.expectError(error.InvalidLength, decodeBool(&.{ 0, 0 }));
    try testing.expectError(error.InvalidLength, decodeBool(&.{}));
}

test "decode int2" {
    try testing.expectEqual(@as(i16, 1), try decodeInt2("\x00\x01"));
    try testing.expectEqual(@as(i16, -1), try decodeInt2("\xff\xff"));
    try testing.expectEqual(@as(i16, -32768), try decodeInt2("\x80\x00"));
    try testing.expectError(error.InvalidLength, decodeInt2("\x00"));
}

test "decode int4" {
    try testing.expectEqual(@as(i32, 42), try decodeInt4("\x00\x00\x00\x2a"));
    try testing.expectEqual(@as(i32, -2147483648), try decodeInt4("\x80\x00\x00\x00"));
    try testing.expectError(error.InvalidLength, decodeInt4("\x00\x00\x2a"));
}

test "decode int8" {
    try testing.expectEqual(@as(i64, 1), try decodeInt8("\x00\x00\x00\x00\x00\x00\x00\x01"));
    try testing.expectEqual(
        @as(i64, std.math.maxInt(i64)),
        try decodeInt8("\x7f\xff\xff\xff\xff\xff\xff\xff"),
    );
    try testing.expectEqual(@as(i64, -1), try decodeInt8("\xff\xff\xff\xff\xff\xff\xff\xff"));
    try testing.expectError(error.InvalidLength, decodeInt8("\x00"));
}

test "decode float4" {
    // 1.5f32 = 0x3fc00000
    try testing.expectEqual(@as(f32, 1.5), try decodeFloat4("\x3f\xc0\x00\x00"));
    // -2.0f32 = 0xc0000000
    try testing.expectEqual(@as(f32, -2.0), try decodeFloat4("\xc0\x00\x00\x00"));
    try testing.expectError(error.InvalidLength, decodeFloat4("\x3f\xc0"));
}

test "decode float8" {
    // 1.5f64 = 0x3ff8000000000000
    try testing.expectEqual(@as(f64, 1.5), try decodeFloat8("\x3f\xf8\x00\x00\x00\x00\x00\x00"));
    // -0.0
    const neg_zero = try decodeFloat8("\x80\x00\x00\x00\x00\x00\x00\x00");
    try testing.expectEqual(@as(f64, 0.0), neg_zero);
    try testing.expect(std.math.signbit(neg_zero));
    try testing.expectError(error.InvalidLength, decodeFloat8("\x00"));
}

test "text and bytea passthrough" {
    try testing.expectEqualStrings("hello", decodeText("hello"));
    try testing.expectEqualSlices(u8, "\x00\x01\xff", decodeBytea("\x00\x01\xff"));
}

test "decode timestamptz epoch conversions" {
    // PG epoch itself: 2000-01-01 00:00:00 UTC.
    try testing.expectEqual(
        PG_EPOCH_UNIX_MICROS,
        try decodeTimestamptz("\x00\x00\x00\x00\x00\x00\x00\x00"),
    );
    // One microsecond after the PG epoch.
    try testing.expectEqual(
        PG_EPOCH_UNIX_MICROS + 1,
        try decodeTimestamptz("\x00\x00\x00\x00\x00\x00\x00\x01"),
    );
    // Unix epoch: 1970-01-01 is PG_EPOCH_UNIX_MICROS before the PG epoch.
    var buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &buf, -PG_EPOCH_UNIX_MICROS, .big);
    try testing.expectEqual(@as(i64, 0), try decodeTimestamptz(&buf));
    // Pre-1970: 1969-12-31 23:59:59 UTC.
    std.mem.writeInt(i64, &buf, -PG_EPOCH_UNIX_MICROS - 1_000_000, .big);
    try testing.expectEqual(@as(i64, -1_000_000), try decodeTimestamptz(&buf));
    // 2026-06-10 00:00:00 UTC = 1780704000 Unix seconds.
    std.mem.writeInt(i64, &buf, 1_780_704_000_000_000 - PG_EPOCH_UNIX_MICROS, .big);
    try testing.expectEqual(@as(i64, 1_780_704_000_000_000), try decodeTimestamptz(&buf));
    try testing.expectError(error.InvalidLength, decodeTimestamptz("\x00"));
}

test "decode timestamptz rejects infinity sentinels" {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &buf, std.math.maxInt(i64), .big); // +infinity
    try testing.expectError(error.InvalidValue, decodeTimestamptz(&buf));
    std.mem.writeInt(i64, &buf, std.math.minInt(i64), .big); // -infinity
    try testing.expectError(error.InvalidValue, decodeTimestamptz(&buf));
}

test "decode uuid" {
    const bytes = [16]u8{
        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
        0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
    };
    var out: [UUID_STRING_LEN]u8 = undefined;
    const s = try decodeUuid(&bytes, &out);
    try testing.expectEqualStrings("550e8400-e29b-41d4-a716-446655440000", s);

    var small: [10]u8 = undefined;
    try testing.expectError(error.InvalidLength, decodeUuid(&bytes, &small));
    try testing.expectError(error.InvalidLength, decodeUuid(bytes[0..8], &out));
}

test "text fallback parsers" {
    try testing.expectEqual(@as(i64, -123), try parseTextInt("-123"));
    try testing.expectEqual(@as(i64, 0), try parseTextInt("0"));
    try testing.expectError(error.InvalidValue, parseTextInt("12.5"));
    try testing.expectError(error.InvalidValue, parseTextInt(""));

    try testing.expectEqual(@as(f64, 12.5), try parseTextFloat("12.5"));
    // numeric-as-text passthrough decodes with the float helper.
    try testing.expectEqual(@as(f64, -0.25), try parseTextFloat("-0.25"));
    try testing.expectError(error.InvalidValue, parseTextFloat("abc"));
}
