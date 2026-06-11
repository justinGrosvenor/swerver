//! PostgreSQL wire protocol v3 message codec (design 9.0, phase 1).
//!
//! Pure functions over byte slices: frontend message writers serialize
//! into caller-provided buffers, backend message parsers return slices
//! borrowing from the input buffer. No allocation, no I/O — the reactor
//! integration (phase 2) owns sockets and buffers.
//!
//! Protocol reference: https://www.postgresql.org/docs/current/protocol-message-formats.html

const std = @import("std");

/// Protocol version 3.0 (major 3 << 16 | minor 0).
pub const PROTOCOL_VERSION: u32 = 196608;

pub const WriteError = error{BufferTooSmall};
pub const ParseError = error{Malformed};

// ---------------------------------------------------------------------------
// Frontend (client → server) message writers
// ---------------------------------------------------------------------------

/// Bounds-checked cursor over a caller-provided output buffer.
const Cursor = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeByte(self: *Cursor, b: u8) WriteError!void {
        if (self.buf.len - self.pos < 1) return error.BufferTooSmall;
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn writeInt16(self: *Cursor, v: u16) WriteError!void {
        if (self.buf.len - self.pos < 2) return error.BufferTooSmall;
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }

    fn writeInt32(self: *Cursor, v: u32) WriteError!void {
        if (self.buf.len - self.pos < 4) return error.BufferTooSmall;
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], v, .big);
        self.pos += 4;
    }

    fn writeBytes(self: *Cursor, bytes: []const u8) WriteError!void {
        if (self.buf.len - self.pos < bytes.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    /// NUL-terminated string. Embedded NULs are a protocol violation.
    fn writeCString(self: *Cursor, s: []const u8) WriteError!void {
        try self.writeBytes(s);
        try self.writeByte(0);
    }

    /// Reserve the message type byte + 4-byte length field. Returns the
    /// offset of the length field for `endMessage` to patch.
    fn beginMessage(self: *Cursor, typ: u8) WriteError!usize {
        try self.writeByte(typ);
        const len_off = self.pos;
        try self.writeInt32(0);
        return len_off;
    }

    /// Patch the length field (length covers itself but not the type byte).
    fn endMessage(self: *Cursor, len_off: usize) void {
        const len: u32 = @intCast(self.pos - len_off);
        std.mem.writeInt(u32, self.buf[len_off..][0..4], len, .big);
    }
};

/// StartupMessage: no type byte; protocol version + key/value parameter
/// pairs terminated by a single NUL. `database` defaults server-side to
/// the user name when omitted.
pub fn writeStartup(
    buf: []u8,
    user: []const u8,
    database: ?[]const u8,
    application_name: ?[]const u8,
) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = cur.pos;
    try cur.writeInt32(0);
    try cur.writeInt32(PROTOCOL_VERSION);
    try cur.writeCString("user");
    try cur.writeCString(user);
    if (database) |db| {
        try cur.writeCString("database");
        try cur.writeCString(db);
    }
    if (application_name) |app| {
        try cur.writeCString("application_name");
        try cur.writeCString(app);
    }
    try cur.writeByte(0);
    const len: u32 = @intCast(cur.pos - len_off);
    std.mem.writeInt(u32, buf[len_off..][0..4], len, .big);
    return buf[0..cur.pos];
}

/// PasswordMessage ('p'): cleartext password response.
pub fn writePassword(buf: []u8, password: []const u8) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('p');
    try cur.writeCString(password);
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// SASLInitialResponse ('p'): mechanism name + initial client response.
pub fn writeSaslInitialResponse(
    buf: []u8,
    mechanism: []const u8,
    initial_response: []const u8,
) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('p');
    try cur.writeCString(mechanism);
    try cur.writeInt32(@intCast(initial_response.len));
    try cur.writeBytes(initial_response);
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// SASLResponse ('p'): raw continuation data (client-final-message).
pub fn writeSaslResponse(buf: []u8, data: []const u8) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('p');
    try cur.writeBytes(data);
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// Parse ('P'): prepare a statement. `param_oids` may be empty to let the
/// server infer parameter types.
pub fn writeParse(
    buf: []u8,
    statement_name: []const u8,
    query: []const u8,
    param_oids: []const u32,
) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('P');
    try cur.writeCString(statement_name);
    try cur.writeCString(query);
    try cur.writeInt16(@intCast(param_oids.len));
    for (param_oids) |oid| try cur.writeInt32(oid);
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// Bind ('B'): bind text-format parameters (null = SQL NULL) to a prepared
/// statement and request binary format for all result columns
/// (one result-format code, value 1).
pub fn writeBind(
    buf: []u8,
    portal: []const u8,
    statement_name: []const u8,
    params: []const ?[]const u8,
) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('B');
    try cur.writeCString(portal);
    try cur.writeCString(statement_name);
    // Zero parameter-format codes: all parameters default to text format.
    try cur.writeInt16(0);
    try cur.writeInt16(@intCast(params.len));
    for (params) |param| {
        if (param) |value| {
            try cur.writeInt32(@intCast(value.len));
            try cur.writeBytes(value);
        } else {
            try cur.writeInt32(0xffff_ffff); // -1: SQL NULL
        }
    }
    // One result-format code applying to all columns: 1 = binary.
    try cur.writeInt16(1);
    try cur.writeInt16(1);
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// Describe ('D') for a portal: server replies RowDescription or NoData.
pub fn writeDescribePortal(buf: []u8, portal: []const u8) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('D');
    try cur.writeByte('P');
    try cur.writeCString(portal);
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// Execute ('E'): run a bound portal. `max_rows` 0 means no limit.
pub fn writeExecute(buf: []u8, portal: []const u8, max_rows: u32) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('E');
    try cur.writeCString(portal);
    try cur.writeInt32(max_rows);
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// Sync ('S'): close the implicit transaction; server replies ReadyForQuery.
pub fn writeSync(buf: []u8) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('S');
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

/// Terminate ('X'): graceful connection shutdown.
pub fn writeTerminate(buf: []u8) WriteError![]u8 {
    var cur = Cursor{ .buf = buf };
    const len_off = try cur.beginMessage('X');
    cur.endMessage(len_off);
    return buf[0..cur.pos];
}

// ---------------------------------------------------------------------------
// Backend (server → client) message reader
// ---------------------------------------------------------------------------

/// Backend message type bytes. Non-exhaustive: unknown types are surfaced
/// to the caller rather than rejected here.
pub const BackendType = enum(u8) {
    authentication = 'R',
    parameter_status = 'S',
    backend_key_data = 'K',
    ready_for_query = 'Z',
    row_description = 'T',
    data_row = 'D',
    command_complete = 'C',
    error_response = 'E',
    notice_response = 'N',
    parse_complete = '1',
    bind_complete = '2',
    close_complete = '3',
    empty_query_response = 'I',
    no_data = 'n',
    portal_suspended = 's',
    negotiate_protocol_version = 'v',
    copy_in_response = 'G',
    copy_out_response = 'H',
    notification_response = 'A',
    _,
};

/// One complete backend frame: type byte + payload (length field stripped).
/// The payload borrows from the receive buffer.
pub const Frame = struct {
    typ: u8,
    payload: []const u8,
};

/// Iterator over backend frames in a receive buffer. An incomplete
/// trailing frame stops iteration with `null`; `consumed()` then tells
/// the caller how many bytes were fully processed — the tail
/// `buf[consumed()..]` must be retained and re-presented with more data.
pub const FrameIter = struct {
    buf: []const u8,
    offset: usize = 0,

    pub fn init(buf: []const u8) FrameIter {
        return .{ .buf = buf };
    }

    /// Next complete frame, or null when more bytes are needed.
    pub fn next(self: *FrameIter) ParseError!?Frame {
        const rem = self.buf[self.offset..];
        if (rem.len < 5) return null;
        const len = std.mem.readInt(u32, rem[1..5], .big);
        // Length covers itself (4 bytes) at minimum.
        if (len < 4) return error.Malformed;
        const total = 1 + @as(usize, len);
        if (rem.len < total) return null;
        const frame = Frame{ .typ = rem[0], .payload = rem[5..total] };
        self.offset += total;
        return frame;
    }

    /// Bytes consumed by complete frames so far.
    pub fn consumed(self: *const FrameIter) usize {
        return self.offset;
    }
};

// ---------------------------------------------------------------------------
// Backend message parsers (all borrow from the input payload)
// ---------------------------------------------------------------------------

/// Authentication request variants ('R' payload).
pub const AuthRequest = union(enum) {
    ok,
    cleartext_password,
    md5_password: [4]u8,
    /// NUL-separated mechanism list (terminated by an empty string);
    /// query it with `saslMechanismsContain`.
    sasl: []const u8,
    /// SCRAM server-first-message.
    sasl_continue: []const u8,
    /// SCRAM server-final-message.
    sasl_final: []const u8,
    /// Any other authentication code (Kerberos, GSS, SSPI, ...).
    unsupported: u32,
};

/// Parse the payload of an Authentication ('R') message.
pub fn parseAuth(payload: []const u8) ParseError!AuthRequest {
    if (payload.len < 4) return error.Malformed;
    const code = std.mem.readInt(u32, payload[0..4], .big);
    const rest = payload[4..];
    return switch (code) {
        0 => .ok,
        3 => .cleartext_password,
        5 => blk: {
            if (rest.len != 4) return error.Malformed;
            break :blk .{ .md5_password = rest[0..4].* };
        },
        10 => blk: {
            // Mechanism list must end with an empty string (double NUL).
            if (rest.len < 2 or rest[rest.len - 1] != 0) return error.Malformed;
            break :blk .{ .sasl = rest };
        },
        11 => .{ .sasl_continue = rest },
        12 => .{ .sasl_final = rest },
        else => .{ .unsupported = code },
    };
}

/// True if a SASL mechanism list (NUL-separated) advertises `mech`.
pub fn saslMechanismsContain(list: []const u8, mech: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, 0);
    while (it.next()) |name| {
        if (name.len == 0) return false; // empty string terminates the list
        if (std.mem.eql(u8, name, mech)) return true;
    }
    return false;
}

/// Salient fields of an ErrorResponse / NoticeResponse.
pub const ErrorInfo = struct {
    /// e.g. "ERROR", "FATAL", "NOTICE".
    severity: []const u8 = "",
    /// Five-character SQLSTATE, e.g. "28P01".
    code: []const u8 = "",
    /// Primary human-readable message.
    message: []const u8 = "",
};

/// Parse ErrorResponse ('E') / NoticeResponse ('N'): a sequence of
/// (field-type byte, NUL-terminated value) pairs ending with a 0 byte.
/// Unrecognized fields are skipped.
pub fn parseErrorResponse(payload: []const u8) ParseError!ErrorInfo {
    var info = ErrorInfo{};
    var off: usize = 0;
    while (off < payload.len) {
        const field = payload[off];
        off += 1;
        if (field == 0) return info;
        const end = std.mem.indexOfScalarPos(u8, payload, off, 0) orelse return error.Malformed;
        const value = payload[off..end];
        off = end + 1;
        switch (field) {
            'S' => info.severity = value,
            'C' => info.code = value,
            'M' => info.message = value,
            else => {},
        }
    }
    return error.Malformed; // missing terminator
}

/// ParameterStatus ('S'): a server run-time parameter changed.
pub const ParameterStatus = struct {
    name: []const u8,
    value: []const u8,
};

pub fn parseParameterStatus(payload: []const u8) ParseError!ParameterStatus {
    const name_end = std.mem.indexOfScalar(u8, payload, 0) orelse return error.Malformed;
    const value_start = name_end + 1;
    const value_end = std.mem.indexOfScalarPos(u8, payload, value_start, 0) orelse return error.Malformed;
    return .{ .name = payload[0..name_end], .value = payload[value_start..value_end] };
}

/// BackendKeyData ('K'): cancellation key for this session.
pub const BackendKeyData = struct {
    pid: u32,
    secret: u32,
};

pub fn parseBackendKeyData(payload: []const u8) ParseError!BackendKeyData {
    if (payload.len != 8) return error.Malformed;
    return .{
        .pid = std.mem.readInt(u32, payload[0..4], .big),
        .secret = std.mem.readInt(u32, payload[4..8], .big),
    };
}

/// One column descriptor from RowDescription ('T').
pub const ColumnDesc = struct {
    name: []const u8,
    table_oid: u32,
    /// Attribute number within the table, 0 if not a simple column reference.
    column_attr: u16,
    type_oid: u32,
    /// Negative for variable-width types.
    type_size: i16,
    type_modifier: i32,
    /// 0 = text, 1 = binary.
    format: u16,
};

/// Iterator over the column descriptors of a RowDescription payload.
pub const RowDescriptionIter = struct {
    payload: []const u8,
    offset: usize,
    remaining: u16,
    column_count: u16,

    pub fn init(payload: []const u8) ParseError!RowDescriptionIter {
        if (payload.len < 2) return error.Malformed;
        const count = std.mem.readInt(u16, payload[0..2], .big);
        return .{ .payload = payload, .offset = 2, .remaining = count, .column_count = count };
    }

    pub fn next(self: *RowDescriptionIter) ParseError!?ColumnDesc {
        if (self.remaining == 0) return null;
        const name_end = std.mem.indexOfScalarPos(u8, self.payload, self.offset, 0) orelse
            return error.Malformed;
        const name = self.payload[self.offset..name_end];
        const fixed = name_end + 1;
        if (self.payload.len - fixed < 18) return error.Malformed;
        const f = self.payload[fixed..];
        self.offset = fixed + 18;
        self.remaining -= 1;
        return .{
            .name = name,
            .table_oid = std.mem.readInt(u32, f[0..4], .big),
            .column_attr = std.mem.readInt(u16, f[4..6], .big),
            .type_oid = std.mem.readInt(u32, f[6..10], .big),
            .type_size = std.mem.readInt(i16, f[10..12], .big),
            .type_modifier = std.mem.readInt(i32, f[12..16], .big),
            .format = std.mem.readInt(u16, f[16..18], .big),
        };
    }
};

/// One column value of a DataRow: null = SQL NULL, otherwise raw bytes
/// (binary or text per the requested result format) borrowing the payload.
pub const DataValue = ?[]const u8;

/// Iterator over the column values of a DataRow ('D') payload.
pub const DataRowIter = struct {
    payload: []const u8,
    offset: usize,
    remaining: u16,
    column_count: u16,

    pub fn init(payload: []const u8) ParseError!DataRowIter {
        if (payload.len < 2) return error.Malformed;
        const count = std.mem.readInt(u16, payload[0..2], .big);
        return .{ .payload = payload, .offset = 2, .remaining = count, .column_count = count };
    }

    pub fn next(self: *DataRowIter) ParseError!?DataValue {
        if (self.remaining == 0) return null;
        if (self.payload.len - self.offset < 4) return error.Malformed;
        const raw_len = std.mem.readInt(i32, self.payload[self.offset..][0..4], .big);
        self.offset += 4;
        self.remaining -= 1;
        if (raw_len == -1) return @as(DataValue, null);
        if (raw_len < 0) return error.Malformed;
        const len: usize = @intCast(raw_len);
        if (self.payload.len - self.offset < len) return error.Malformed;
        const value = self.payload[self.offset .. self.offset + len];
        self.offset += len;
        return @as(DataValue, value);
    }
};

/// CommandComplete ('C'): command tag plus rows-affected when the tag
/// carries one ("SELECT 5", "UPDATE 3", "INSERT 0 5", ...).
pub const CommandComplete = struct {
    tag: []const u8,
    rows: ?u64,
};

pub fn parseCommandComplete(payload: []const u8) ParseError!CommandComplete {
    const end = std.mem.indexOfScalar(u8, payload, 0) orelse return error.Malformed;
    const tag = payload[0..end];
    // Rows-affected is the final space-separated token when numeric.
    var rows: ?u64 = null;
    if (std.mem.lastIndexOfScalar(u8, tag, ' ')) |sp| {
        rows = std.fmt.parseInt(u64, tag[sp + 1 ..], 10) catch null;
    }
    return .{ .tag = tag, .rows = rows };
}

/// Transaction status reported by ReadyForQuery ('Z').
pub const TxnStatus = enum(u8) {
    idle = 'I',
    in_transaction = 'T',
    failed = 'E',
};

pub fn parseReadyForQuery(payload: []const u8) ParseError!TxnStatus {
    if (payload.len != 1) return error.Malformed;
    return switch (payload[0]) {
        'I' => .idle,
        'T' => .in_transaction,
        'E' => .failed,
        else => error.Malformed,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Append one backend frame (type + length + payload) to `buf` at `off`.
fn putFrame(buf: []u8, off: usize, typ: u8, payload: []const u8) usize {
    buf[off] = typ;
    std.mem.writeInt(u32, buf[off + 1 ..][0..4], @intCast(4 + payload.len), .big);
    @memcpy(buf[off + 5 .. off + 5 + payload.len], payload);
    return off + 5 + payload.len;
}

test "startup message golden bytes" {
    var buf: [128]u8 = undefined;
    const msg = try writeStartup(&buf, "alice", "appdb", "swerver");
    const expected = "\x00\x00\x00\x3c" ++ // length 60
        "\x00\x03\x00\x00" ++ // protocol 196608
        "user\x00alice\x00" ++
        "database\x00appdb\x00" ++
        "application_name\x00swerver\x00" ++
        "\x00";
    try testing.expectEqualSlices(u8, expected, msg);
}

test "startup message omits optional params" {
    var buf: [64]u8 = undefined;
    const msg = try writeStartup(&buf, "bob", null, null);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x12\x00\x03\x00\x00user\x00bob\x00\x00", msg);
}

test "startup message buffer too small" {
    var buf: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeStartup(&buf, "alice", "appdb", null));
}

test "password message round-trip" {
    var buf: [32]u8 = undefined;
    const msg = try writePassword(&buf, "hunter2");
    try testing.expectEqualSlices(u8, "p\x00\x00\x00\x0chunter2\x00", msg);
}

test "sasl initial response golden bytes" {
    var buf: [64]u8 = undefined;
    const msg = try writeSaslInitialResponse(&buf, "SCRAM-SHA-256", "n,,n=,r=abc");
    try testing.expectEqual(@as(u8, 'p'), msg[0]);
    const len = std.mem.readInt(u32, msg[1..5], .big);
    try testing.expectEqual(msg.len - 1, @as(usize, len));
    try testing.expectEqualSlices(u8, "SCRAM-SHA-256\x00", msg[5..19]);
    try testing.expectEqual(@as(u32, 11), std.mem.readInt(u32, msg[19..23], .big));
    try testing.expectEqualSlices(u8, "n,,n=,r=abc", msg[23..]);
}

test "sasl response is raw payload" {
    var buf: [32]u8 = undefined;
    const msg = try writeSaslResponse(&buf, "c=biws");
    try testing.expectEqualSlices(u8, "p\x00\x00\x00\x0ac=biws", msg);
}

test "parse message round-trip" {
    var buf: [64]u8 = undefined;
    const oids = [_]u32{ 23, 25 };
    const msg = try writeParse(&buf, "s1", "select $1, $2", &oids);
    try testing.expectEqual(@as(u8, 'P'), msg[0]);
    try testing.expectEqual(@as(usize, msg.len - 1), std.mem.readInt(u32, msg[1..5], .big));
    try testing.expectEqualSlices(u8, "s1\x00select $1, $2\x00", msg[5..22]);
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, msg[22..24], .big));
    try testing.expectEqual(@as(u32, 23), std.mem.readInt(u32, msg[24..28], .big));
    try testing.expectEqual(@as(u32, 25), std.mem.readInt(u32, msg[28..32], .big));
}

test "bind message with text params, null, and binary results" {
    var buf: [64]u8 = undefined;
    const params = [_]?[]const u8{ "42", null };
    const msg = try writeBind(&buf, "", "s1", &params);
    try testing.expectEqual(@as(u8, 'B'), msg[0]);
    var off: usize = 5;
    try testing.expectEqual(@as(u8, 0), msg[off]); // empty portal
    off += 1;
    try testing.expectEqualSlices(u8, "s1\x00", msg[off .. off + 3]);
    off += 3;
    // No param-format codes (all text).
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, msg[off..][0..2], .big));
    off += 2;
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, msg[off..][0..2], .big));
    off += 2;
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, msg[off..][0..4], .big));
    off += 4;
    try testing.expectEqualSlices(u8, "42", msg[off .. off + 2]);
    off += 2;
    try testing.expectEqual(@as(i32, -1), std.mem.readInt(i32, msg[off..][0..4], .big));
    off += 4;
    // One result-format code: binary.
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, msg[off..][0..2], .big));
    off += 2;
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, msg[off..][0..2], .big));
    off += 2;
    try testing.expectEqual(msg.len, off);
}

test "describe portal round-trip" {
    var buf: [32]u8 = undefined;
    const msg = try writeDescribePortal(&buf, "");
    try testing.expectEqualSlices(u8, "D\x00\x00\x00\x06P\x00", msg);
}

test "execute round-trip" {
    var buf: [32]u8 = undefined;
    const msg = try writeExecute(&buf, "", 0);
    try testing.expectEqualSlices(u8, "E\x00\x00\x00\x09\x00\x00\x00\x00\x00", msg);
}

test "sync and terminate golden bytes" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, "S\x00\x00\x00\x04", try writeSync(&buf));
    try testing.expectEqualSlices(u8, "X\x00\x00\x00\x04", try writeTerminate(&buf));
}

test "frontend writers report BufferTooSmall" {
    var buf: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeSync(&buf));
    try testing.expectError(error.BufferTooSmall, writePassword(&buf, "x"));
    try testing.expectError(error.BufferTooSmall, writeParse(&buf, "", "select 1", &.{}));
    try testing.expectError(error.BufferTooSmall, writeBind(&buf, "", "", &.{}));
}

test "frame iterator: multiple frames per buffer" {
    var buf: [64]u8 = undefined;
    var off = putFrame(&buf, 0, '1', "");
    off = putFrame(&buf, off, '2', "");
    off = putFrame(&buf, off, 'Z', "I");

    var iter = FrameIter.init(buf[0..off]);
    const f1 = (try iter.next()).?;
    try testing.expectEqual(@as(u8, '1'), f1.typ);
    try testing.expectEqual(@as(usize, 0), f1.payload.len);
    const f2 = (try iter.next()).?;
    try testing.expectEqual(@as(u8, '2'), f2.typ);
    const f3 = (try iter.next()).?;
    try testing.expectEqual(@as(u8, 'Z'), f3.typ);
    try testing.expectEqualSlices(u8, "I", f3.payload);
    try testing.expectEqual(@as(?Frame, null), try iter.next());
    try testing.expectEqual(off, iter.consumed());
}

test "frame iterator: incomplete trailing frame reports consumed bytes" {
    var buf: [64]u8 = undefined;
    var off = putFrame(&buf, 0, 'Z', "I");
    const first_len = off;
    off = putFrame(&buf, off, 'C', "SELECT 1");

    // Feed everything except the last 3 bytes.
    var iter = FrameIter.init(buf[0 .. off - 3]);
    const f1 = (try iter.next()).?;
    try testing.expectEqual(@as(u8, 'Z'), f1.typ);
    try testing.expectEqual(@as(?Frame, null), try iter.next());
    try testing.expectEqual(first_len, iter.consumed());

    // Re-present the tail plus the missing bytes: frame completes.
    var iter2 = FrameIter.init(buf[iter.consumed()..off]);
    const f2 = (try iter2.next()).?;
    try testing.expectEqual(@as(u8, 'C'), f2.typ);
    try testing.expectEqualSlices(u8, "SELECT 1", f2.payload);
}

test "frame iterator: split inside the 5-byte header" {
    var buf: [16]u8 = undefined;
    const off = putFrame(&buf, 0, 'n', "");
    var iter = FrameIter.init(buf[0..3]);
    try testing.expectEqual(@as(?Frame, null), try iter.next());
    try testing.expectEqual(@as(usize, 0), iter.consumed());
    var iter2 = FrameIter.init(buf[0..off]);
    try testing.expectEqual(@as(u8, 'n'), (try iter2.next()).?.typ);
}

test "frame iterator rejects length below 4" {
    const bad = [_]u8{ 'Z', 0, 0, 0, 3 };
    var iter = FrameIter.init(&bad);
    try testing.expectError(error.Malformed, iter.next());
}

test "parse authentication variants" {
    try testing.expectEqual(AuthRequest.ok, try parseAuth("\x00\x00\x00\x00"));
    try testing.expectEqual(AuthRequest.cleartext_password, try parseAuth("\x00\x00\x00\x03"));

    const md5 = try parseAuth("\x00\x00\x00\x05ABCD");
    try testing.expectEqualSlices(u8, "ABCD", &md5.md5_password);

    const sasl = try parseAuth("\x00\x00\x00\x0aSCRAM-SHA-256\x00\x00");
    try testing.expect(saslMechanismsContain(sasl.sasl, "SCRAM-SHA-256"));
    try testing.expect(!saslMechanismsContain(sasl.sasl, "SCRAM-SHA-256-PLUS"));

    const cont = try parseAuth("\x00\x00\x00\x0br=abc,s=x,i=1");
    try testing.expectEqualSlices(u8, "r=abc,s=x,i=1", cont.sasl_continue);

    const final = try parseAuth("\x00\x00\x00\x0cv=sig");
    try testing.expectEqualSlices(u8, "v=sig", final.sasl_final);

    const unsupported = try parseAuth("\x00\x00\x00\x07");
    try testing.expectEqual(@as(u32, 7), unsupported.unsupported);

    try testing.expectError(error.Malformed, parseAuth("\x00\x00"));
}

test "sasl mechanism list with multiple entries" {
    const list = "SCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00";
    try testing.expect(saslMechanismsContain(list, "SCRAM-SHA-256"));
    try testing.expect(saslMechanismsContain(list, "SCRAM-SHA-256-PLUS"));
    try testing.expect(!saslMechanismsContain(list, "PLAIN"));
}

test "error response parse" {
    const payload = "SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed for user \"alice\"\x00\x00";
    const info = try parseErrorResponse(payload);
    try testing.expectEqualStrings("FATAL", info.severity);
    try testing.expectEqualStrings("28P01", info.code);
    try testing.expectEqualStrings("password authentication failed for user \"alice\"", info.message);
}

test "error response missing terminator is malformed" {
    try testing.expectError(error.Malformed, parseErrorResponse("SERROR\x00C42601\x00"));
    try testing.expectError(error.Malformed, parseErrorResponse("S"));
}

test "parameter status parse" {
    const ps = try parseParameterStatus("server_version\x0016.3\x00");
    try testing.expectEqualStrings("server_version", ps.name);
    try testing.expectEqualStrings("16.3", ps.value);
    try testing.expectError(error.Malformed, parseParameterStatus("no_nul"));
}

test "backend key data parse" {
    const kd = try parseBackendKeyData("\x00\x00\x30\x39\xde\xad\xbe\xef");
    try testing.expectEqual(@as(u32, 12345), kd.pid);
    try testing.expectEqual(@as(u32, 0xdeadbeef), kd.secret);
    try testing.expectError(error.Malformed, parseBackendKeyData("short"));
}

test "row description parse" {
    // Two columns: id int4 (oid 23, table 1000, attr 1, size 4, binary),
    // name text (oid 25, variable size, text format).
    const payload = "\x00\x02" ++
        "id\x00" ++ "\x00\x00\x03\xe8" ++ "\x00\x01" ++ "\x00\x00\x00\x17" ++ "\x00\x04" ++ "\xff\xff\xff\xff" ++ "\x00\x01" ++
        "name\x00" ++ "\x00\x00\x03\xe8" ++ "\x00\x02" ++ "\x00\x00\x00\x19" ++ "\xff\xff" ++ "\xff\xff\xff\xff" ++ "\x00\x00";
    var iter = try RowDescriptionIter.init(payload);
    try testing.expectEqual(@as(u16, 2), iter.column_count);

    const c1 = (try iter.next()).?;
    try testing.expectEqualStrings("id", c1.name);
    try testing.expectEqual(@as(u32, 1000), c1.table_oid);
    try testing.expectEqual(@as(u16, 1), c1.column_attr);
    try testing.expectEqual(@as(u32, 23), c1.type_oid);
    try testing.expectEqual(@as(i16, 4), c1.type_size);
    try testing.expectEqual(@as(u16, 1), c1.format);

    const c2 = (try iter.next()).?;
    try testing.expectEqualStrings("name", c2.name);
    try testing.expectEqual(@as(u32, 25), c2.type_oid);
    try testing.expectEqual(@as(i16, -1), c2.type_size);
    try testing.expectEqual(@as(u16, 0), c2.format);

    try testing.expectEqual(@as(?ColumnDesc, null), try iter.next());
}

test "row description truncated is malformed" {
    const payload = "\x00\x01" ++ "id\x00" ++ "\x00\x00\x03\xe8";
    var iter = try RowDescriptionIter.init(payload);
    try testing.expectError(error.Malformed, iter.next());
}

test "data row with NULLs" {
    const payload = "\x00\x03" ++
        "\x00\x00\x00\x04" ++ "\x00\x00\x00\x2a" ++ // int4 42
        "\xff\xff\xff\xff" ++ // NULL
        "\x00\x00\x00\x00"; // empty (non-null) value
    var iter = try DataRowIter.init(payload);
    try testing.expectEqual(@as(u16, 3), iter.column_count);

    const v1 = (try iter.next()).?;
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x2a", v1.?);
    const v2 = (try iter.next()).?;
    try testing.expectEqual(@as(DataValue, null), v2);
    const v3 = (try iter.next()).?;
    try testing.expectEqual(@as(usize, 0), v3.?.len);
    try testing.expectEqual(@as(?DataValue, null), try iter.next());
}

test "data row truncated value is malformed" {
    const payload = "\x00\x01" ++ "\x00\x00\x00\x08" ++ "abc";
    var iter = try DataRowIter.init(payload);
    try testing.expectError(error.Malformed, iter.next());
}

test "command complete tag parsing" {
    const sel = try parseCommandComplete("SELECT 5\x00");
    try testing.expectEqualStrings("SELECT 5", sel.tag);
    try testing.expectEqual(@as(?u64, 5), sel.rows);

    const ins = try parseCommandComplete("INSERT 0 3\x00");
    try testing.expectEqual(@as(?u64, 3), ins.rows);

    const upd = try parseCommandComplete("UPDATE 12\x00");
    try testing.expectEqual(@as(?u64, 12), upd.rows);

    const begin = try parseCommandComplete("BEGIN\x00");
    try testing.expectEqualStrings("BEGIN", begin.tag);
    try testing.expectEqual(@as(?u64, null), begin.rows);

    try testing.expectError(error.Malformed, parseCommandComplete("SELECT 1"));
}

test "ready for query txn status" {
    try testing.expectEqual(TxnStatus.idle, try parseReadyForQuery("I"));
    try testing.expectEqual(TxnStatus.in_transaction, try parseReadyForQuery("T"));
    try testing.expectEqual(TxnStatus.failed, try parseReadyForQuery("E"));
    try testing.expectError(error.Malformed, parseReadyForQuery("X"));
    try testing.expectError(error.Malformed, parseReadyForQuery("II"));
}
