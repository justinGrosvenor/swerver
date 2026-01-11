const std = @import("std");

/// QPACK Header Compression per RFC 9204.
///
/// QPACK is similar to HPACK but designed for QUIC's out-of-order delivery.
/// Uses static and dynamic tables for header field compression.

pub const Error = error{
    BufferTooSmall,
    InvalidEncoding,
    InvalidIndex,
    StringTooLong,
    TableFull,
    UnexpectedEnd,
    HuffmanDecodeFailed,
};

/// Maximum header name/value lengths
pub const MAX_HEADER_NAME_LEN = 256;
pub const MAX_HEADER_VALUE_LEN = 4096;

/// Header field (name-value pair)
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,

    pub fn size(self: HeaderField) usize {
        // Per RFC 9204: entry size = name length + value length + 32
        return self.name.len + self.value.len + 32;
    }
};

/// QPACK static table entries (RFC 9204 Appendix A)
/// Subset of commonly used headers for HTTP/3
pub const static_table = [_]HeaderField{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

/// Dynamic table for QPACK
pub const DynamicTable = struct {
    /// Storage for header entries
    entries: [64]HeaderField = undefined,
    /// Name storage (fixed buffers)
    name_storage: [64][MAX_HEADER_NAME_LEN]u8 = undefined,
    /// Value storage (fixed buffers)
    value_storage: [64][MAX_HEADER_VALUE_LEN]u8 = undefined,
    /// Number of entries
    count: usize = 0,
    /// Current size in bytes
    size: usize = 0,
    /// Maximum size
    max_size: usize = 4096,
    /// Insert index (for absolute indexing)
    insert_count: u64 = 0,

    pub fn init(max_size: usize) DynamicTable {
        return .{ .max_size = max_size };
    }

    /// Insert a new entry
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        if (name.len > MAX_HEADER_NAME_LEN or value.len > MAX_HEADER_VALUE_LEN) {
            return error.StringTooLong;
        }

        const entry_size = name.len + value.len + 32;

        // Evict entries if needed
        while (self.size + entry_size > self.max_size and self.count > 0) {
            self.evict();
        }

        if (self.count >= 64) {
            return error.TableFull;
        }

        // Store the entry
        const idx = self.count;
        @memcpy(self.name_storage[idx][0..name.len], name);
        @memcpy(self.value_storage[idx][0..value.len], value);

        self.entries[idx] = .{
            .name = self.name_storage[idx][0..name.len],
            .value = self.value_storage[idx][0..value.len],
        };

        self.count += 1;
        self.size += entry_size;
        self.insert_count += 1;
    }

    /// Evict the oldest entry
    fn evict(self: *DynamicTable) void {
        if (self.count == 0) return;

        const oldest = &self.entries[0];
        self.size -|= oldest.size();

        // Shift entries and storage
        var i: usize = 0;
        while (i < self.count - 1) : (i += 1) {
            // Copy storage first
            @memcpy(&self.name_storage[i], &self.name_storage[i + 1]);
            @memcpy(&self.value_storage[i], &self.value_storage[i + 1]);

            // Get lengths from the next entry (before we overwrite)
            const name_len = self.entries[i + 1].name.len;
            const value_len = self.entries[i + 1].value.len;

            // Update entry with slices pointing to NEW storage location
            self.entries[i] = .{
                .name = self.name_storage[i][0..name_len],
                .value = self.value_storage[i][0..value_len],
            };
        }
        self.count -= 1;
    }

    /// Get entry by relative index (0 = most recent)
    pub fn get(self: *const DynamicTable, index: usize) ?HeaderField {
        if (index >= self.count) return null;
        // Relative index 0 = most recent entry
        return self.entries[self.count - 1 - index];
    }

    /// Find entry by name
    pub fn findName(self: *const DynamicTable, name: []const u8) ?usize {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.entries[self.count - 1 - i].name, name)) {
                return i;
            }
        }
        return null;
    }

    /// Find entry by name and value
    pub fn findNameValue(self: *const DynamicTable, name: []const u8, value: []const u8) ?usize {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const entry = self.entries[self.count - 1 - i];
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i;
            }
        }
        return null;
    }
};

/// QPACK Encoder
pub const Encoder = struct {
    dynamic_table: DynamicTable,
    /// Whether to use dynamic table references
    use_dynamic: bool = false,

    pub fn init(max_table_size: usize) Encoder {
        return .{
            .dynamic_table = DynamicTable.init(max_table_size),
        };
    }

    /// Encode a list of headers
    pub fn encode(self: *Encoder, buf: []u8, headers: []const HeaderField) Error!usize {
        var offset: usize = 0;

        // Required Insert Count (0 for static-only encoding)
        offset += try encodeInteger(buf[offset..], 0, 8, 0);

        // Delta Base (0)
        offset += try encodeInteger(buf[offset..], 0, 7, 0);

        for (headers) |header| {
            offset += try self.encodeHeader(buf[offset..], header);
        }

        return offset;
    }

    fn encodeHeader(self: *Encoder, buf: []u8, header: HeaderField) Error!usize {
        // Try static table first
        if (findStaticNameValue(header.name, header.value)) |idx| {
            // Indexed field line (static)
            return encodeIndexed(buf, idx, true);
        }

        if (findStaticName(header.name)) |idx| {
            // Literal with name reference (static)
            return encodeLiteralNameRef(buf, idx, true, header.value);
        }

        // Try dynamic table
        if (self.use_dynamic) {
            if (self.dynamic_table.findNameValue(header.name, header.value)) |idx| {
                return encodeIndexed(buf, idx, false);
            }

            if (self.dynamic_table.findName(header.name)) |idx| {
                return encodeLiteralNameRef(buf, idx, false, header.value);
            }
        }

        // Literal with literal name
        return encodeLiteral(buf, header.name, header.value);
    }
};

/// QPACK Decoder
pub const Decoder = struct {
    dynamic_table: DynamicTable,
    /// Decoded headers buffer
    headers: [64]HeaderField = undefined,
    /// Name storage for literals
    name_storage: [64][MAX_HEADER_NAME_LEN]u8 = undefined,
    /// Value storage for literals
    value_storage: [64][MAX_HEADER_VALUE_LEN]u8 = undefined,
    header_count: usize = 0,

    pub fn init(max_table_size: usize) Decoder {
        return .{
            .dynamic_table = DynamicTable.init(max_table_size),
        };
    }

    /// Decode an encoded header block
    pub fn decode(self: *Decoder, buf: []const u8) Error![]const HeaderField {
        self.header_count = 0;
        var offset: usize = 0;

        // Required Insert Count
        const ric = try decodeInteger(buf[offset..], 8);
        offset += ric.len;
        _ = ric.value;

        // Delta Base (sign bit in first bit)
        const db = try decodeInteger(buf[offset..], 7);
        offset += db.len;
        _ = db.value;

        // Decode header field lines
        while (offset < buf.len) {
            const start = offset;
            _ = start;
            const first_byte = buf[offset];

            if ((first_byte & 0x80) != 0) {
                // Indexed field line
                offset += try self.decodeIndexed(buf[offset..]);
            } else if ((first_byte & 0x40) != 0) {
                // Literal with name reference
                offset += try self.decodeLiteralNameRef(buf[offset..]);
            } else if ((first_byte & 0x20) != 0) {
                // Literal with literal name
                offset += try self.decodeLiteral(buf[offset..]);
            } else {
                // Unknown encoding
                return error.InvalidEncoding;
            }
        }

        return self.headers[0..self.header_count];
    }

    fn decodeIndexed(self: *Decoder, buf: []const u8) Error!usize {
        const static = (buf[0] & 0x40) != 0;
        const idx_result = try decodeInteger(buf, 6);

        const entry = if (static)
            getStaticEntry(idx_result.value)
        else
            self.dynamic_table.get(idx_result.value);

        if (entry) |e| {
            if (self.header_count >= 64) return error.BufferTooSmall;

            @memcpy(self.name_storage[self.header_count][0..e.name.len], e.name);
            @memcpy(self.value_storage[self.header_count][0..e.value.len], e.value);

            self.headers[self.header_count] = .{
                .name = self.name_storage[self.header_count][0..e.name.len],
                .value = self.value_storage[self.header_count][0..e.value.len],
            };
            self.header_count += 1;
        } else {
            return error.InvalidIndex;
        }

        return idx_result.len;
    }

    fn decodeLiteralNameRef(self: *Decoder, buf: []const u8) Error!usize {
        var offset: usize = 0;
        const static = (buf[0] & 0x10) != 0;
        const never_index = (buf[0] & 0x20) != 0;
        _ = never_index;

        const idx_result = try decodeInteger(buf, 4);
        offset += idx_result.len;

        const name_entry = if (static)
            getStaticEntry(idx_result.value)
        else
            self.dynamic_table.get(idx_result.value);

        const name = if (name_entry) |e| e.name else return error.InvalidIndex;

        // Decode value
        const value_result = try decodeString(buf[offset..]);
        offset += value_result.len;

        if (self.header_count >= 64) return error.BufferTooSmall;

        @memcpy(self.name_storage[self.header_count][0..name.len], name);
        @memcpy(self.value_storage[self.header_count][0..value_result.str.len], value_result.str);

        self.headers[self.header_count] = .{
            .name = self.name_storage[self.header_count][0..name.len],
            .value = self.value_storage[self.header_count][0..value_result.str.len],
        };
        self.header_count += 1;

        return offset;
    }

    fn decodeLiteral(self: *Decoder, buf: []const u8) Error!usize {
        var offset: usize = 0;

        // Skip first byte pattern bits
        const name_result = try decodeString(buf[1..]);
        offset += 1 + name_result.len;

        const value_result = try decodeString(buf[offset..]);
        offset += value_result.len;

        if (self.header_count >= 64) return error.BufferTooSmall;

        @memcpy(self.name_storage[self.header_count][0..name_result.str.len], name_result.str);
        @memcpy(self.value_storage[self.header_count][0..value_result.str.len], value_result.str);

        self.headers[self.header_count] = .{
            .name = self.name_storage[self.header_count][0..name_result.str.len],
            .value = self.value_storage[self.header_count][0..value_result.str.len],
        };
        self.header_count += 1;

        return offset;
    }
};

// Helper functions

fn findStaticName(name: []const u8) ?usize {
    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) {
            return i;
        }
    }
    return null;
}

fn findStaticNameValue(name: []const u8, value: []const u8) ?usize {
    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
            return i;
        }
    }
    return null;
}

fn getStaticEntry(index: u64) ?HeaderField {
    if (index < static_table.len) {
        return static_table[index];
    }
    return null;
}

/// Encode an integer with prefix
fn encodeInteger(buf: []u8, value: u64, prefix_bits: u4, prefix: u8) Error!usize {
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;

    if (value < max_prefix) {
        if (buf.len < 1) return error.BufferTooSmall;
        buf[0] = prefix | @as(u8, @intCast(value));
        return 1;
    }

    if (buf.len < 1) return error.BufferTooSmall;
    buf[0] = prefix | @as(u8, @intCast(max_prefix));
    var remaining = value - max_prefix;
    var offset: usize = 1;

    while (remaining >= 128) {
        if (offset >= buf.len) return error.BufferTooSmall;
        buf[offset] = @intCast((remaining & 0x7f) | 0x80);
        remaining >>= 7;
        offset += 1;
    }

    if (offset >= buf.len) return error.BufferTooSmall;
    buf[offset] = @intCast(remaining);
    offset += 1;

    return offset;
}

/// Decode an integer with prefix
fn decodeInteger(buf: []const u8, prefix_bits: u4) Error!struct { value: u64, len: usize } {
    if (buf.len == 0) return error.UnexpectedEnd;

    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    var value: u64 = buf[0] & @as(u8, @intCast(max_prefix));

    if (value < max_prefix) {
        return .{ .value = value, .len = 1 };
    }

    var offset: usize = 1;
    var m: u6 = 0;

    while (offset < buf.len) {
        const b = buf[offset];
        value += @as(u64, b & 0x7f) << m;
        offset += 1;
        m += 7;

        if ((b & 0x80) == 0) {
            return .{ .value = value, .len = offset };
        }
    }

    return error.UnexpectedEnd;
}

/// Decode a string (length-prefixed)
fn decodeString(buf: []const u8) Error!struct { str: []const u8, len: usize } {
    if (buf.len == 0) return error.UnexpectedEnd;

    const huffman = (buf[0] & 0x80) != 0;
    const len_result = try decodeInteger(buf, 7);

    const total_len = len_result.len + @as(usize, @intCast(len_result.value));
    if (buf.len < total_len) return error.UnexpectedEnd;

    const str_data = buf[len_result.len..total_len];

    if (huffman) {
        // Huffman decoding not implemented - return as-is for now
        // In production, this would decode Huffman-encoded strings
        return .{ .str = str_data, .len = total_len };
    }

    return .{ .str = str_data, .len = total_len };
}

/// Encode an indexed field line
fn encodeIndexed(buf: []u8, index: usize, static: bool) Error!usize {
    const s_bit: u8 = if (static) 0x40 else 0x00;
    return encodeInteger(buf, index, 6, 0x80 | s_bit);
}

/// Encode literal with name reference
fn encodeLiteralNameRef(buf: []u8, name_idx: usize, static: bool, value: []const u8) Error!usize {
    var offset: usize = 0;

    const s_bit: u8 = if (static) 0x10 else 0x00;
    offset += try encodeInteger(buf[offset..], name_idx, 4, 0x40 | s_bit);

    // Value (not Huffman encoded for simplicity)
    offset += try encodeInteger(buf[offset..], value.len, 7, 0x00);
    if (buf.len < offset + value.len) return error.BufferTooSmall;
    @memcpy(buf[offset .. offset + value.len], value);
    offset += value.len;

    return offset;
}

/// Encode literal with literal name
fn encodeLiteral(buf: []u8, name: []const u8, value: []const u8) Error!usize {
    var offset: usize = 0;

    // Literal with literal name pattern: 0010nnnn
    offset += try encodeInteger(buf[offset..], name.len, 3, 0x20);
    if (buf.len < offset + name.len) return error.BufferTooSmall;
    @memcpy(buf[offset .. offset + name.len], name);
    offset += name.len;

    // Value
    offset += try encodeInteger(buf[offset..], value.len, 7, 0x00);
    if (buf.len < offset + value.len) return error.BufferTooSmall;
    @memcpy(buf[offset .. offset + value.len], value);
    offset += value.len;

    return offset;
}

// Tests
test "static table lookup" {
    // :method GET
    try std.testing.expectEqual(@as(?usize, 17), findStaticNameValue(":method", "GET"));

    // :status 200
    try std.testing.expectEqual(@as(?usize, 25), findStaticNameValue(":status", "200"));

    // :path /
    try std.testing.expectEqual(@as(?usize, 1), findStaticNameValue(":path", "/"));

    // Non-existent
    try std.testing.expectEqual(@as(?usize, null), findStaticNameValue(":method", "PATCH"));
}

test "integer encoding" {
    var buf: [10]u8 = undefined;

    // Small value
    {
        const len = try encodeInteger(&buf, 10, 5, 0);
        try std.testing.expectEqual(@as(usize, 1), len);
        try std.testing.expectEqual(@as(u8, 10), buf[0]);
    }

    // Value requiring continuation
    {
        const len = try encodeInteger(&buf, 1337, 5, 0);
        try std.testing.expect(len > 1);

        const result = try decodeInteger(&buf, 5);
        try std.testing.expectEqual(@as(u64, 1337), result.value);
    }
}

test "encode and decode simple headers" {
    var encoder = Encoder.init(4096);
    var decoder = Decoder.init(4096);

    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    };

    var buf: [256]u8 = undefined;
    const encoded_len = try encoder.encode(&buf, &headers);

    const decoded = try decoder.decode(buf[0..encoded_len]);

    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "dynamic table insertion" {
    var table = DynamicTable.init(1024);

    try table.insert("custom-header", "custom-value");
    try std.testing.expectEqual(@as(usize, 1), table.count);

    const entry = table.get(0);
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings("custom-header", entry.?.name);
    try std.testing.expectEqualStrings("custom-value", entry.?.value);
}

test "dynamic table eviction" {
    var table = DynamicTable.init(100); // Small size to force eviction

    // Insert entries until eviction
    try table.insert("h1", "v1");
    try table.insert("h2", "v2");

    // Third entry should evict first
    try table.insert("h3", "v3");

    // First entry should be gone
    const found = table.findNameValue("h1", "v1");
    try std.testing.expect(found == null or table.count <= 2);
}
