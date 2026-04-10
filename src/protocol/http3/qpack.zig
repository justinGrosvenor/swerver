const std = @import("std");
const huffman = @import("../huffman.zig");

/// QPACK Header Compression per RFC 9204.
///
/// QPACK is similar to HPACK but designed for QUIC's out-of-order delivery.
/// Uses static and dynamic tables for header field compression. Huffman
/// decoding shares the table from RFC 7541 Appendix B with HTTP/2 (HPACK).

pub const Error = error{
    BufferTooSmall,
    InvalidEncoding,
    InvalidIndex,
    IntegerOverflow,
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
    /// Last acknowledged insert count from decoder
    acked_insert_count: u64 = 0,

    pub fn init(max_table_size: usize) Encoder {
        return .{
            .dynamic_table = DynamicTable.init(max_table_size),
        };
    }

    /// Encode a list of headers
    pub fn encode(self: *Encoder, buf: []u8, headers: []const HeaderField) Error!usize {
        var offset: usize = 0;

        // Required Insert Count (use dynamic table insert count if enabled)
        const ric: u64 = if (self.use_dynamic) self.dynamic_table.insert_count else 0;
        offset += try encodeInteger(buf[offset..], ric, 8, 0);

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

    // ---- Encoder Stream Instructions (RFC 9204 Section 4.3) ----

    /// Build Set Dynamic Table Capacity instruction
    pub fn buildSetCapacity(_: *Encoder, buf: []u8, capacity: u64) Error!usize {
        // Format: 001xxxxx with 5-bit prefix
        return encodeInteger(buf, capacity, 5, 0x20);
    }

    /// Build Insert With Name Reference instruction (static table)
    pub fn buildInsertStaticNameRef(self: *Encoder, buf: []u8, static_idx: usize, value: []const u8) Error!usize {
        var offset: usize = 0;

        // Format: 1Tnnnnnn - T=1 for static
        offset += try encodeInteger(buf[offset..], static_idx, 6, 0xc0);

        // Value with H bit (not Huffman encoded)
        offset += try encodeInteger(buf[offset..], value.len, 7, 0x00);
        if (buf.len < offset + value.len) return error.BufferTooSmall;
        @memcpy(buf[offset .. offset + value.len], value);
        offset += value.len;

        // Also insert into our own table
        const static_entry = getStaticEntry(static_idx) orelse return error.InvalidIndex;
        try self.dynamic_table.insert(static_entry.name, value);

        return offset;
    }

    /// Build Insert Without Name Reference instruction
    pub fn buildInsertLiteral(self: *Encoder, buf: []u8, name: []const u8, value: []const u8) Error!usize {
        var offset: usize = 0;

        // Format: 01Hnnnnn - H=0 (not Huffman)
        offset += try encodeInteger(buf[offset..], name.len, 5, 0x40);
        if (buf.len < offset + name.len) return error.BufferTooSmall;
        @memcpy(buf[offset .. offset + name.len], name);
        offset += name.len;

        // Value
        offset += try encodeInteger(buf[offset..], value.len, 7, 0x00);
        if (buf.len < offset + value.len) return error.BufferTooSmall;
        @memcpy(buf[offset .. offset + value.len], value);
        offset += value.len;

        // Also insert into our own table
        try self.dynamic_table.insert(name, value);

        return offset;
    }

    /// Build Duplicate instruction
    pub fn buildDuplicate(self: *Encoder, buf: []u8, index: usize) Error!usize {
        // Format: 000xxxxx with 5-bit prefix
        const len = try encodeInteger(buf, index, 5, 0x00);

        // Also duplicate in our own table
        const entry = self.dynamic_table.get(index) orelse return error.InvalidIndex;
        try self.dynamic_table.insert(entry.name, entry.value);

        return len;
    }

    /// Process decoder stream instructions (acknowledgments from peer)
    pub fn processDecoderStream(self: *Encoder, data: []const u8) Error!usize {
        var offset: usize = 0;

        while (offset < data.len) {
            const first_byte = data[offset];

            if ((first_byte & 0x80) != 0) {
                // Section Acknowledgment: 1xxxxxxx
                const result = try decodeInteger(data[offset..], 7);
                offset += result.len;
                // Stream ID acknowledged - could track per-stream state if needed
            } else if ((first_byte & 0x40) != 0) {
                // Stream Cancellation: 01xxxxxx
                const result = try decodeInteger(data[offset..], 6);
                offset += result.len;
                // Stream cancelled - could clean up per-stream state
            } else {
                // Insert Count Increment: 00xxxxxx
                const result = try decodeInteger(data[offset..], 6);
                offset += result.len;
                self.acked_insert_count += result.value;
            }
        }

        return offset;
    }
};

/// QPACK Encoder Stream Instruction Types (RFC 9204 Section 4.3)
pub const EncoderInstruction = enum {
    /// Set Dynamic Table Capacity
    set_capacity,
    /// Insert With Name Reference (static or dynamic)
    insert_name_ref,
    /// Insert Without Name Reference (literal name)
    insert_literal,
    /// Duplicate existing entry
    duplicate,
};

/// QPACK Decoder Stream Instruction Types (RFC 9204 Section 4.4)
pub const DecoderInstruction = enum {
    /// Section Acknowledgment
    section_ack,
    /// Stream Cancellation
    stream_cancel,
    /// Insert Count Increment
    insert_count_increment,
};

/// Result of processing encoder stream instructions
pub const EncoderStreamResult = struct {
    /// Bytes consumed
    consumed: usize,
    /// Number of instructions processed
    instructions_processed: usize,
    /// New insert count (for decoder stream acknowledgment)
    insert_count: u64,
};

/// QPACK Decoder
pub const Decoder = struct {
    dynamic_table: DynamicTable,
    /// Upper bound on the dynamic table capacity as advertised in
    /// the local `SETTINGS_QPACK_MAX_TABLE_CAPACITY`. Peer is
    /// forbidden from issuing `Set Dynamic Table Capacity` with a
    /// value that exceeds this, and — when this is 0 — all insert
    /// and duplicate instructions are forbidden too (RFC 9204 §4.3
    /// / §2.1.3). Enforcement lives in `processEncoderStream`; any
    /// violation returns `error.InvalidEncoding`, which propagates
    /// up to an h3 connection error.
    max_allowed_capacity: usize,
    /// Decoded headers buffer
    headers: [64]HeaderField = undefined,
    /// Name storage for literals
    name_storage: [64][MAX_HEADER_NAME_LEN]u8 = undefined,
    /// Value storage for literals
    value_storage: [64][MAX_HEADER_VALUE_LEN]u8 = undefined,
    header_count: usize = 0,
    /// Known received count (for Insert Count Increment)
    known_received_count: u64 = 0,
    /// Temporary storage for encoder stream instruction strings
    enc_name_buf: [MAX_HEADER_NAME_LEN]u8 = undefined,
    enc_value_buf: [MAX_HEADER_VALUE_LEN]u8 = undefined,

    pub fn init(max_table_size: usize) Decoder {
        return .{
            .dynamic_table = DynamicTable.init(max_table_size),
            .max_allowed_capacity = max_table_size,
        };
    }

    /// Process encoder stream instructions (RFC 9204 Section 4.3)
    /// These instructions update the decoder's dynamic table.
    ///
    /// Enforces the `max_allowed_capacity` bound captured at init:
    /// - `Set Dynamic Table Capacity` values that exceed the bound
    ///   are rejected (RFC 9204 §4.3.1).
    /// - When the bound is 0, all insert and duplicate instructions
    ///   are rejected — a peer ignoring our advertised
    ///   `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` cannot sneak
    ///   entries into our dynamic table. `Set Dynamic Table Capacity
    ///   0` is still accepted as a no-op acknowledgment.
    ///
    /// Any violation returns `error.InvalidEncoding`, which
    /// `http3.Stack.processQpackEncoderStream` translates into an
    /// h3 connection error (H3_QPACK_ENCODER_STREAM_ERROR).
    pub fn processEncoderStream(self: *Decoder, data: []const u8) Error!EncoderStreamResult {
        var offset: usize = 0;
        var instructions: usize = 0;

        while (offset < data.len) {
            const first_byte = data[offset];

            if ((first_byte & 0x80) != 0) {
                // 1xxxxxxx - Insert With Name Reference
                if (self.max_allowed_capacity == 0) return error.InvalidEncoding;
                const consumed = try self.processInsertNameRef(data[offset..]);
                offset += consumed;
                instructions += 1;
            } else if ((first_byte & 0x40) != 0) {
                // 01xxxxxx - Insert Without Name Reference (literal name)
                if (self.max_allowed_capacity == 0) return error.InvalidEncoding;
                const consumed = try self.processInsertLiteral(data[offset..]);
                offset += consumed;
                instructions += 1;
            } else if ((first_byte & 0x20) != 0) {
                // 001xxxxx - Set Dynamic Table Capacity
                const result = try decodeInteger(data[offset..], 5);
                offset += result.len;
                const new_cap: usize = @intCast(result.value);
                if (new_cap > self.max_allowed_capacity) return error.InvalidEncoding;
                self.dynamic_table.max_size = new_cap;
                instructions += 1;
            } else {
                // 000xxxxx - Duplicate
                if (self.max_allowed_capacity == 0) return error.InvalidEncoding;
                const result = try decodeInteger(data[offset..], 5);
                offset += result.len;
                try self.processDuplicate(result.value);
                instructions += 1;
            }
        }

        return .{
            .consumed = offset,
            .instructions_processed = instructions,
            .insert_count = self.dynamic_table.insert_count,
        };
    }

    /// Process Insert With Name Reference instruction
    fn processInsertNameRef(self: *Decoder, buf: []const u8) Error!usize {
        var offset: usize = 0;
        const first_byte = buf[0];

        // Bit 6 indicates static (1) or dynamic (0) table
        const is_static = (first_byte & 0x40) != 0;
        const idx_result = try decodeInteger(buf, 6);
        offset += idx_result.len;

        // Get name from referenced entry
        const name_entry = if (is_static)
            getStaticEntry(idx_result.value)
        else
            self.dynamic_table.get(@intCast(idx_result.value));

        const name = if (name_entry) |e| e.name else return error.InvalidIndex;

        // Decode value
        const value_result = try decodeStringInto(buf[offset..], &self.enc_value_buf);
        offset += value_result.len;

        // Insert into dynamic table
        try self.dynamic_table.insert(name, self.enc_value_buf[0..value_result.str_len]);

        return offset;
    }

    /// Process Insert Without Name Reference instruction
    /// Format: 01Hnnnnn + name bytes + Hvvvvvvv + value bytes
    fn processInsertLiteral(self: *Decoder, buf: []const u8) Error!usize {
        var offset: usize = 0;

        // First byte: 01Hnnnnn - name length is 5-bit integer (H is Huffman flag, ignored for now)
        const name_len_result = try decodeInteger(buf, 5);
        offset += name_len_result.len;
        const name_len: usize = @intCast(name_len_result.value);

        // Read name bytes
        if (buf.len < offset + name_len) return error.UnexpectedEnd;
        if (name_len > self.enc_name_buf.len) return error.StringTooLong;
        @memcpy(self.enc_name_buf[0..name_len], buf[offset .. offset + name_len]);
        offset += name_len;

        // Decode value (7-bit length prefix)
        const value_result = try decodeStringInto(buf[offset..], &self.enc_value_buf);
        offset += value_result.len;

        // Insert into dynamic table
        try self.dynamic_table.insert(
            self.enc_name_buf[0..name_len],
            self.enc_value_buf[0..value_result.str_len],
        );

        return offset;
    }

    /// Process Duplicate instruction
    fn processDuplicate(self: *Decoder, index: u64) Error!void {
        const entry = self.dynamic_table.get(@intCast(index)) orelse return error.InvalidIndex;
        try self.dynamic_table.insert(entry.name, entry.value);
    }

    /// Build Insert Count Increment instruction for decoder stream
    pub fn buildInsertCountIncrement(self: *Decoder, buf: []u8) Error!usize {
        const increment = self.dynamic_table.insert_count - self.known_received_count;
        if (increment == 0) return 0;

        self.known_received_count = self.dynamic_table.insert_count;
        // Format: 00xxxxxx with 6-bit prefix
        return encodeInteger(buf, increment, 6, 0x00);
    }

    /// Build Section Acknowledgment instruction for decoder stream
    pub fn buildSectionAck(_: *Decoder, buf: []u8, stream_id: u64) Error!usize {
        // Format: 1xxxxxxx with 7-bit prefix
        return encodeInteger(buf, stream_id, 7, 0x80);
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

        if (self.header_count >= 64) return error.BufferTooSmall;
        if (name.len > MAX_HEADER_NAME_LEN) return error.StringTooLong;

        // Decode value directly into per-header storage so the slice we
        // hand back stays valid after this function returns. Handles both
        // Huffman-encoded and raw literals.
        const value_result = try decodeStringInto(buf[offset..], &self.value_storage[self.header_count]);
        offset += value_result.len;

        @memcpy(self.name_storage[self.header_count][0..name.len], name);

        self.headers[self.header_count] = .{
            .name = self.name_storage[self.header_count][0..name.len],
            .value = self.value_storage[self.header_count][0..value_result.str_len],
        };
        self.header_count += 1;

        return offset;
    }

    fn decodeLiteral(self: *Decoder, buf: []const u8) Error!usize {
        var offset: usize = 0;

        // First byte: 0010 H N N N — name length is a 3-bit prefix integer.
        // The H bit on the name is at position 0x08 (RFC 9204 §4.5.6).
        // For now we treat the name as a non-Huffman literal because the
        // tested clients (curl/ngtcp2) only Huffman-encode header values
        // when the encoder is in static-only mode like ours. We'll harden
        // this once we see a Huffman-encoded literal name in the wild.
        const name_int = try decodeInteger(buf, 3);
        offset += name_int.len;
        const name_len: usize = @intCast(name_int.value);

        if (buf.len < offset + name_len) return error.UnexpectedEnd;
        if (name_len > MAX_HEADER_NAME_LEN) return error.StringTooLong;
        const name_data = buf[offset .. offset + name_len];
        offset += name_len;

        if (self.header_count >= 64) return error.BufferTooSmall;

        // Decode value directly into per-header storage so the slice stays
        // valid; handles Huffman-encoded values.
        const value_result = try decodeStringInto(buf[offset..], &self.value_storage[self.header_count]);
        offset += value_result.len;

        @memcpy(self.name_storage[self.header_count][0..name_data.len], name_data);

        self.headers[self.header_count] = .{
            .name = self.name_storage[self.header_count][0..name_data.len],
            .value = self.value_storage[self.header_count][0..value_result.str_len],
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
    var m: u7 = 0;

    while (offset < buf.len) {
        const b = buf[offset];
        value += @as(u64, b & 0x7f) << @as(u6, @intCast(m));
        offset += 1;
        m += 7;
        if (m > 62) return error.IntegerOverflow; // max 9 continuation bytes for u64

        if ((b & 0x80) == 0) {
            return .{ .value = value, .len = offset };
        }
    }

    return error.UnexpectedEnd;
}

/// Decode a string (length-prefixed)
/// Decode a QPACK string literal into `dest`. Handles both raw and
/// Huffman-encoded forms (RFC 7541 §5.2 / RFC 9204 §4.1.2). Returns the
/// number of bytes consumed from `buf` and the number of decoded bytes
/// written to `dest`.
fn decodeStringInto(buf: []const u8, dest: []u8) Error!struct { str_len: usize, len: usize } {
    if (buf.len == 0) return error.UnexpectedEnd;

    const is_huffman = (buf[0] & 0x80) != 0;
    const len_result = try decodeInteger(buf, 7);
    const encoded_len: usize = @intCast(len_result.value);

    const total_len = len_result.len + encoded_len;
    if (buf.len < total_len) return error.UnexpectedEnd;

    const encoded_bytes = buf[len_result.len..total_len];

    if (is_huffman) {
        const decoded_len = huffman.decodeInto(encoded_bytes, dest) catch |err| switch (err) {
            error.InvalidHuffman => return error.HuffmanDecodeFailed,
            error.OutputTooSmall => return error.StringTooLong,
        };
        return .{ .str_len = decoded_len, .len = total_len };
    } else {
        if (encoded_len > dest.len) return error.StringTooLong;
        @memcpy(dest[0..encoded_len], encoded_bytes);
        return .{ .str_len = encoded_len, .len = total_len };
    }
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

test "encoder stream - set capacity instruction" {
    var decoder = Decoder.init(4096);

    // Build a Set Capacity instruction: 001xxxxx with capacity = 2048
    var buf: [16]u8 = undefined;
    var encoder = Encoder.init(4096);
    const len = try encoder.buildSetCapacity(&buf, 2048);

    // Process on decoder side
    const result = try decoder.processEncoderStream(buf[0..len]);
    try std.testing.expectEqual(@as(usize, len), result.consumed);
    try std.testing.expectEqual(@as(usize, 1), result.instructions_processed);
    try std.testing.expectEqual(@as(usize, 2048), decoder.dynamic_table.max_size);
}

test "encoder stream - insert literal instruction" {
    var encoder = Encoder.init(4096);
    var decoder = Decoder.init(4096);

    // Encoder builds an insert instruction
    var buf: [256]u8 = undefined;
    const len = try encoder.buildInsertLiteral(&buf, "x-custom", "test-value");

    // Process on decoder side
    const result = try decoder.processEncoderStream(buf[0..len]);
    try std.testing.expectEqual(@as(usize, 1), result.instructions_processed);

    // Decoder's dynamic table should now have the entry
    const entry = decoder.dynamic_table.get(0);
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings("x-custom", entry.?.name);
    try std.testing.expectEqualStrings("test-value", entry.?.value);
}

test "encoder stream - insert with static name ref" {
    var encoder = Encoder.init(4096);
    var decoder = Decoder.init(4096);

    // Insert using static table index 0 (:authority) with custom value
    var buf: [256]u8 = undefined;
    const len = try encoder.buildInsertStaticNameRef(&buf, 0, "example.com");

    // Process on decoder side
    const result = try decoder.processEncoderStream(buf[0..len]);
    try std.testing.expectEqual(@as(usize, 1), result.instructions_processed);

    // Decoder's dynamic table should have :authority = example.com
    const entry = decoder.dynamic_table.get(0);
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings(":authority", entry.?.name);
    try std.testing.expectEqualStrings("example.com", entry.?.value);
}

test "encoder stream - duplicate instruction" {
    var encoder = Encoder.init(4096);
    var decoder = Decoder.init(4096);

    // First, insert an entry
    var buf: [256]u8 = undefined;
    var offset: usize = 0;
    offset += try encoder.buildInsertLiteral(buf[offset..], "x-header", "value1");

    // Then duplicate it
    offset += try encoder.buildDuplicate(buf[offset..], 0);

    // Process both instructions on decoder side
    const result = try decoder.processEncoderStream(buf[0..offset]);
    try std.testing.expectEqual(@as(usize, 2), result.instructions_processed);
    try std.testing.expectEqual(@as(usize, 2), decoder.dynamic_table.count);

    // Both entries should have same name/value
    const entry0 = decoder.dynamic_table.get(0);
    const entry1 = decoder.dynamic_table.get(1);
    try std.testing.expectEqualStrings(entry0.?.name, entry1.?.name);
    try std.testing.expectEqualStrings(entry0.?.value, entry1.?.value);
}

test "decoder stream - insert count increment" {
    var decoder = Decoder.init(4096);
    var buf: [16]u8 = undefined;

    // Manually insert to advance insert_count
    try decoder.dynamic_table.insert("header", "value");

    // Build Insert Count Increment
    const len = try decoder.buildInsertCountIncrement(&buf);
    try std.testing.expect(len > 0);

    // First byte should have 00xxxxxx pattern
    try std.testing.expect((buf[0] & 0xc0) == 0x00);
}

test "decoder stream - section ack" {
    var decoder = Decoder.init(4096);
    var buf: [16]u8 = undefined;

    // Build Section Acknowledgment for stream 4
    const len = try decoder.buildSectionAck(&buf, 4);
    try std.testing.expect(len > 0);

    // First byte should have 1xxxxxxx pattern
    try std.testing.expect((buf[0] & 0x80) != 0);
}

test "encoder processes decoder stream" {
    var encoder = Encoder.init(4096);

    // Simulate Insert Count Increment of 5: 00000101
    const data = [_]u8{0x05};
    const consumed = try encoder.processDecoderStream(&data);

    try std.testing.expectEqual(@as(usize, 1), consumed);
    try std.testing.expectEqual(@as(u64, 5), encoder.acked_insert_count);
}
