const std = @import("std");
const types = @import("types.zig");
const varint = @import("varint.zig");

/// QUIC Frame Parsing per RFC 9000 Section 12.
///
/// Frames are the basic unit of data exchange within QUIC packets.
/// Multiple frames can be packed into a single packet.

pub const ParseError = error{
    UnexpectedEnd,
    InvalidFrame,
    InvalidFrameType,
    InvalidStreamId,
    InvalidOffset,
    InvalidLength,
} || varint.Error;

/// Errors that can occur when writing frames
pub const WriteError = varint.Error;

/// PADDING frame (type 0x00)
pub const PaddingFrame = struct {
    /// Number of padding bytes (including the frame type byte)
    length: usize,
};

/// PING frame (type 0x01) - no payload
pub const PingFrame = struct {};

/// ACK frame (types 0x02, 0x03)
pub const AckFrame = struct {
    largest_acked: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ranges: []const AckRange,
    /// Only present for ACK_ECN (type 0x03)
    ecn: ?EcnCounts,
};

pub const AckRange = struct {
    gap: u64,
    length: u64,
};

pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

/// RESET_STREAM frame (type 0x04)
pub const ResetStreamFrame = struct {
    stream_id: types.StreamId,
    application_error_code: u64,
    final_size: u64,
};

/// STOP_SENDING frame (type 0x05)
pub const StopSendingFrame = struct {
    stream_id: types.StreamId,
    application_error_code: u64,
};

/// CRYPTO frame (type 0x06)
pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
};

/// NEW_TOKEN frame (type 0x07)
pub const NewTokenFrame = struct {
    token: []const u8,
};

/// STREAM frame (types 0x08-0x0f)
pub const StreamFrame = struct {
    stream_id: types.StreamId,
    offset: u64,
    data: []const u8,
    fin: bool,
};

/// MAX_DATA frame (type 0x10)
pub const MaxDataFrame = struct {
    maximum_data: u64,
};

/// MAX_STREAM_DATA frame (type 0x11)
pub const MaxStreamDataFrame = struct {
    stream_id: types.StreamId,
    maximum_stream_data: u64,
};

/// MAX_STREAMS frame (types 0x12, 0x13)
pub const MaxStreamsFrame = struct {
    maximum_streams: u64,
    bidirectional: bool,
};

/// DATA_BLOCKED frame (type 0x14)
pub const DataBlockedFrame = struct {
    maximum_data: u64,
};

/// STREAM_DATA_BLOCKED frame (type 0x15)
pub const StreamDataBlockedFrame = struct {
    stream_id: types.StreamId,
    maximum_stream_data: u64,
};

/// STREAMS_BLOCKED frame (types 0x16, 0x17)
pub const StreamsBlockedFrame = struct {
    maximum_streams: u64,
    bidirectional: bool,
};

/// NEW_CONNECTION_ID frame (type 0x18)
pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: types.ConnectionId,
    stateless_reset_token: [16]u8,
};

/// RETIRE_CONNECTION_ID frame (type 0x19)
pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,
};

/// PATH_CHALLENGE frame (type 0x1a)
pub const PathChallengeFrame = struct {
    data: [8]u8,
};

/// PATH_RESPONSE frame (type 0x1b)
pub const PathResponseFrame = struct {
    data: [8]u8,
};

/// CONNECTION_CLOSE frame (types 0x1c, 0x1d)
pub const ConnectionCloseFrame = struct {
    error_code: u64,
    frame_type: ?u64, // Only for QUIC-layer errors (0x1c)
    reason_phrase: []const u8,
    application_error: bool,
};

/// HANDSHAKE_DONE frame (type 0x1e) - no payload
pub const HandshakeDoneFrame = struct {};

/// Union of all frame types
pub const Frame = union(enum) {
    padding: PaddingFrame,
    ping: PingFrame,
    ack: AckFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    crypto: CryptoFrame,
    new_token: NewTokenFrame,
    stream: StreamFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams: MaxStreamsFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked: StreamsBlockedFrame,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: RetireConnectionIdFrame,
    path_challenge: PathChallengeFrame,
    path_response: PathResponseFrame,
    connection_close: ConnectionCloseFrame,
    handshake_done: HandshakeDoneFrame,
    unknown: u64, // Unrecognized frame type
};

/// Result of parsing a frame
pub const ParseResult = struct {
    frame: Frame,
    consumed: usize,
};

/// Parse a single frame from the buffer.
/// Returns the parsed frame and the number of bytes consumed.
pub fn parseFrame(buf: []const u8) ParseError!ParseResult {
    if (buf.len == 0) return error.UnexpectedEnd;

    // Decode frame type (varint)
    const type_result = try varint.decode(buf);
    const offset = type_result.len;
    const frame_type = type_result.value;

    // Handle PADDING specially - count consecutive padding bytes
    if (frame_type == 0x00) {
        var padding_len: usize = 1;
        while (offset + padding_len < buf.len and buf[offset + padding_len - 1] == 0x00) {
            padding_len += 1;
        }
        return .{
            .frame = .{ .padding = .{ .length = padding_len } },
            .consumed = padding_len,
        };
    }

    // Handle STREAM frames (0x08-0x0f)
    if (types.FrameType.isStream(frame_type)) {
        return parseStreamFrame(buf, offset, frame_type);
    }

    return switch (frame_type) {
        0x01 => .{ // PING
            .frame = .{ .ping = .{} },
            .consumed = offset,
        },
        0x02, 0x03 => try parseAckFrame(buf, offset, frame_type == 0x03), // ACK, ACK_ECN
        0x04 => try parseResetStreamFrame(buf, offset),
        0x05 => try parseStopSendingFrame(buf, offset),
        0x06 => try parseCryptoFrame(buf, offset),
        0x07 => try parseNewTokenFrame(buf, offset),
        0x10 => try parseMaxDataFrame(buf, offset),
        0x11 => try parseMaxStreamDataFrame(buf, offset),
        0x12 => try parseMaxStreamsFrame(buf, offset, true), // Bidi
        0x13 => try parseMaxStreamsFrame(buf, offset, false), // Uni
        0x14 => try parseDataBlockedFrame(buf, offset),
        0x15 => try parseStreamDataBlockedFrame(buf, offset),
        0x16 => try parseStreamsBlockedFrame(buf, offset, true), // Bidi
        0x17 => try parseStreamsBlockedFrame(buf, offset, false), // Uni
        0x18 => try parseNewConnectionIdFrame(buf, offset),
        0x19 => try parseRetireConnectionIdFrame(buf, offset),
        0x1a => try parsePathChallengeFrame(buf, offset),
        0x1b => try parsePathResponseFrame(buf, offset),
        0x1c => try parseConnectionCloseFrame(buf, offset, false),
        0x1d => try parseConnectionCloseFrame(buf, offset, true),
        0x1e => .{ // HANDSHAKE_DONE
            .frame = .{ .handshake_done = .{} },
            .consumed = offset,
        },
        else => .{
            .frame = .{ .unknown = frame_type },
            .consumed = offset,
        },
    };
}

fn parseStreamFrame(buf: []const u8, initial_offset: usize, frame_type: u64) ParseError!ParseResult {
    var offset = initial_offset;

    const has_offset = (frame_type & 0x04) != 0;
    const has_length = (frame_type & 0x02) != 0;
    const has_fin = (frame_type & 0x01) != 0;

    // Stream ID
    const stream_id_result = try varint.decode(buf[offset..]);
    offset += stream_id_result.len;
    const stream_id = stream_id_result.value;

    // Offset field (optional)
    var stream_offset: u64 = 0;
    if (has_offset) {
        const offset_result = try varint.decode(buf[offset..]);
        offset += offset_result.len;
        stream_offset = offset_result.value;
    }

    // Length field (optional)
    var data_len: usize = 0;
    if (has_length) {
        const len_result = try varint.decode(buf[offset..]);
        offset += len_result.len;
        data_len = len_result.value;
    } else {
        // Data extends to end of packet
        data_len = buf.len - offset;
    }

    if (buf.len < offset + data_len) return error.UnexpectedEnd;

    return .{
        .frame = .{
            .stream = .{
                .stream_id = stream_id,
                .offset = stream_offset,
                .data = buf[offset .. offset + data_len],
                .fin = has_fin,
            },
        },
        .consumed = offset + data_len,
    };
}

/// Static buffer for ACK ranges (reused per parse)
var ack_ranges_buf: [64]AckRange = undefined;

fn parseAckFrame(buf: []const u8, initial_offset: usize, has_ecn: bool) ParseError!ParseResult {
    var offset = initial_offset;

    const largest_acked = try varint.decode(buf[offset..]);
    offset += largest_acked.len;

    const ack_delay = try varint.decode(buf[offset..]);
    offset += ack_delay.len;

    const ack_range_count = try varint.decode(buf[offset..]);
    offset += ack_range_count.len;

    const first_ack_range = try varint.decode(buf[offset..]);
    offset += first_ack_range.len;

    // Parse additional ACK ranges
    const range_count = @min(ack_range_count.value, ack_ranges_buf.len);
    var i: usize = 0;
    while (i < range_count) : (i += 1) {
        const gap = try varint.decode(buf[offset..]);
        offset += gap.len;
        const range_len = try varint.decode(buf[offset..]);
        offset += range_len.len;
        ack_ranges_buf[i] = .{
            .gap = gap.value,
            .length = range_len.value,
        };
    }

    // Skip any remaining ranges that don't fit in buffer
    var j: u64 = range_count;
    while (j < ack_range_count.value) : (j += 1) {
        const gap = try varint.decode(buf[offset..]);
        offset += gap.len;
        const range_len = try varint.decode(buf[offset..]);
        offset += range_len.len;
    }

    var ecn: ?EcnCounts = null;
    if (has_ecn) {
        const ect0 = try varint.decode(buf[offset..]);
        offset += ect0.len;
        const ect1 = try varint.decode(buf[offset..]);
        offset += ect1.len;
        const ce = try varint.decode(buf[offset..]);
        offset += ce.len;
        ecn = .{
            .ect0 = ect0.value,
            .ect1 = ect1.value,
            .ce = ce.value,
        };
    }

    return .{
        .frame = .{
            .ack = .{
                .largest_acked = largest_acked.value,
                .ack_delay = ack_delay.value,
                .first_ack_range = first_ack_range.value,
                .ranges = ack_ranges_buf[0..range_count],
                .ecn = ecn,
            },
        },
        .consumed = offset,
    };
}

fn parseCryptoFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const crypto_offset = try varint.decode(buf[offset..]);
    offset += crypto_offset.len;

    const length = try varint.decode(buf[offset..]);
    offset += length.len;

    if (buf.len < offset + length.value) return error.UnexpectedEnd;

    return .{
        .frame = .{
            .crypto = .{
                .offset = crypto_offset.value,
                .data = buf[offset .. offset + length.value],
            },
        },
        .consumed = offset + length.value,
    };
}

fn parseResetStreamFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const stream_id = try varint.decode(buf[offset..]);
    offset += stream_id.len;

    const error_code = try varint.decode(buf[offset..]);
    offset += error_code.len;

    const final_size = try varint.decode(buf[offset..]);
    offset += final_size.len;

    return .{
        .frame = .{
            .reset_stream = .{
                .stream_id = stream_id.value,
                .application_error_code = error_code.value,
                .final_size = final_size.value,
            },
        },
        .consumed = offset,
    };
}

fn parseStopSendingFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const stream_id = try varint.decode(buf[offset..]);
    offset += stream_id.len;

    const error_code = try varint.decode(buf[offset..]);
    offset += error_code.len;

    return .{
        .frame = .{
            .stop_sending = .{
                .stream_id = stream_id.value,
                .application_error_code = error_code.value,
            },
        },
        .consumed = offset,
    };
}

fn parseNewTokenFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const length = try varint.decode(buf[offset..]);
    offset += length.len;

    if (buf.len < offset + length.value) return error.UnexpectedEnd;

    return .{
        .frame = .{
            .new_token = .{
                .token = buf[offset .. offset + length.value],
            },
        },
        .consumed = offset + length.value,
    };
}

fn parseMaxDataFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const max_data = try varint.decode(buf[offset..]);
    offset += max_data.len;

    return .{
        .frame = .{ .max_data = .{ .maximum_data = max_data.value } },
        .consumed = offset,
    };
}

fn parseMaxStreamDataFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const stream_id = try varint.decode(buf[offset..]);
    offset += stream_id.len;

    const max_data = try varint.decode(buf[offset..]);
    offset += max_data.len;

    return .{
        .frame = .{
            .max_stream_data = .{
                .stream_id = stream_id.value,
                .maximum_stream_data = max_data.value,
            },
        },
        .consumed = offset,
    };
}

fn parseMaxStreamsFrame(buf: []const u8, initial_offset: usize, bidi: bool) ParseError!ParseResult {
    var offset = initial_offset;

    const max_streams = try varint.decode(buf[offset..]);
    offset += max_streams.len;

    return .{
        .frame = .{
            .max_streams = .{
                .maximum_streams = max_streams.value,
                .bidirectional = bidi,
            },
        },
        .consumed = offset,
    };
}

fn parseDataBlockedFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const max_data = try varint.decode(buf[offset..]);
    offset += max_data.len;

    return .{
        .frame = .{ .data_blocked = .{ .maximum_data = max_data.value } },
        .consumed = offset,
    };
}

fn parseStreamDataBlockedFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const stream_id = try varint.decode(buf[offset..]);
    offset += stream_id.len;

    const max_data = try varint.decode(buf[offset..]);
    offset += max_data.len;

    return .{
        .frame = .{
            .stream_data_blocked = .{
                .stream_id = stream_id.value,
                .maximum_stream_data = max_data.value,
            },
        },
        .consumed = offset,
    };
}

fn parseStreamsBlockedFrame(buf: []const u8, initial_offset: usize, bidi: bool) ParseError!ParseResult {
    var offset = initial_offset;

    const max_streams = try varint.decode(buf[offset..]);
    offset += max_streams.len;

    return .{
        .frame = .{
            .streams_blocked = .{
                .maximum_streams = max_streams.value,
                .bidirectional = bidi,
            },
        },
        .consumed = offset,
    };
}

fn parseNewConnectionIdFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const seq = try varint.decode(buf[offset..]);
    offset += seq.len;

    const retire = try varint.decode(buf[offset..]);
    offset += retire.len;

    if (offset >= buf.len) return error.UnexpectedEnd;
    const cid_len = buf[offset];
    offset += 1;

    if (cid_len > types.Constants.max_cid_len) return error.InvalidFrame;
    if (buf.len < offset + cid_len + 16) return error.UnexpectedEnd;

    var cid = types.ConnectionId{};
    if (cid_len > 0) {
        @memcpy(cid.bytes[0..cid_len], buf[offset .. offset + cid_len]);
        cid.len = cid_len;
    }
    offset += cid_len;

    var reset_token: [16]u8 = undefined;
    @memcpy(&reset_token, buf[offset .. offset + 16]);
    offset += 16;

    return .{
        .frame = .{
            .new_connection_id = .{
                .sequence_number = seq.value,
                .retire_prior_to = retire.value,
                .connection_id = cid,
                .stateless_reset_token = reset_token,
            },
        },
        .consumed = offset,
    };
}

fn parseRetireConnectionIdFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    var offset = initial_offset;

    const seq = try varint.decode(buf[offset..]);
    offset += seq.len;

    return .{
        .frame = .{ .retire_connection_id = .{ .sequence_number = seq.value } },
        .consumed = offset,
    };
}

fn parsePathChallengeFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    if (buf.len < initial_offset + 8) return error.UnexpectedEnd;

    var data: [8]u8 = undefined;
    @memcpy(&data, buf[initial_offset .. initial_offset + 8]);

    return .{
        .frame = .{ .path_challenge = .{ .data = data } },
        .consumed = initial_offset + 8,
    };
}

fn parsePathResponseFrame(buf: []const u8, initial_offset: usize) ParseError!ParseResult {
    if (buf.len < initial_offset + 8) return error.UnexpectedEnd;

    var data: [8]u8 = undefined;
    @memcpy(&data, buf[initial_offset .. initial_offset + 8]);

    return .{
        .frame = .{ .path_response = .{ .data = data } },
        .consumed = initial_offset + 8,
    };
}

fn parseConnectionCloseFrame(buf: []const u8, initial_offset: usize, app_error: bool) ParseError!ParseResult {
    var offset = initial_offset;

    const error_code = try varint.decode(buf[offset..]);
    offset += error_code.len;

    var frame_type: ?u64 = null;
    if (!app_error) {
        const ft = try varint.decode(buf[offset..]);
        offset += ft.len;
        frame_type = ft.value;
    }

    const reason_len = try varint.decode(buf[offset..]);
    offset += reason_len.len;

    if (buf.len < offset + reason_len.value) return error.UnexpectedEnd;

    return .{
        .frame = .{
            .connection_close = .{
                .error_code = error_code.value,
                .frame_type = frame_type,
                .reason_phrase = buf[offset .. offset + reason_len.value],
                .application_error = app_error,
            },
        },
        .consumed = offset + reason_len.value,
    };
}

// === Frame Writing Functions ===

/// Write a CONNECTION_CLOSE frame for transport/QUIC layer errors (type 0x1c)
/// Returns bytes written
pub fn writeConnectionClose(buf: []u8, error_code: u64, frame_type: ?u64, reason: []const u8) WriteError!usize {
    var offset: usize = 0;

    // Frame type 0x1c
    offset += try varint.encode(buf[offset..], 0x1c);

    // Error code
    offset += try varint.encode(buf[offset..], error_code);

    // Frame type that triggered the error (or 0 if not applicable)
    offset += try varint.encode(buf[offset..], frame_type orelse 0);

    // Reason phrase length + data
    offset += try varint.encode(buf[offset..], reason.len);
    if (buf.len < offset + reason.len) return error.BufferTooSmall;
    @memcpy(buf[offset .. offset + reason.len], reason);
    offset += reason.len;

    return offset;
}

/// Write a CONNECTION_CLOSE frame for application layer errors (type 0x1d)
/// Returns bytes written
pub fn writeApplicationClose(buf: []u8, error_code: u64, reason: []const u8) WriteError!usize {
    var offset: usize = 0;

    // Frame type 0x1d
    offset += try varint.encode(buf[offset..], 0x1d);

    // Error code
    offset += try varint.encode(buf[offset..], error_code);

    // Reason phrase length + data
    offset += try varint.encode(buf[offset..], reason.len);
    if (buf.len < offset + reason.len) return error.BufferTooSmall;
    @memcpy(buf[offset .. offset + reason.len], reason);
    offset += reason.len;

    return offset;
}

/// Write a CRYPTO frame
/// Returns bytes written
pub fn writeCrypto(buf: []u8, offset_val: u64, data: []const u8) WriteError!usize {
    var off: usize = 0;

    // Frame type 0x06
    off += try varint.encode(buf[off..], 0x06);

    // Offset
    off += try varint.encode(buf[off..], offset_val);

    // Length
    off += try varint.encode(buf[off..], data.len);

    // Data
    if (buf.len < off + data.len) return error.BufferTooSmall;
    @memcpy(buf[off .. off + data.len], data);
    off += data.len;

    return off;
}

/// Write a STREAM frame
/// Returns bytes written
pub fn writeStream(buf: []u8, stream_id: u64, offset_val: u64, data: []const u8, fin: bool) WriteError!usize {
    var off: usize = 0;

    // Frame type: 0x08 base + flags (OFF=0x04, LEN=0x02, FIN=0x01)
    var frame_type: u8 = 0x08;
    if (offset_val > 0) frame_type |= 0x04; // OFF bit
    frame_type |= 0x02; // LEN bit (always include length for clarity)
    if (fin) frame_type |= 0x01;

    off += try varint.encode(buf[off..], frame_type);

    // Stream ID
    off += try varint.encode(buf[off..], stream_id);

    // Offset (only if OFF bit set)
    if (offset_val > 0) {
        off += try varint.encode(buf[off..], offset_val);
    }

    // Length
    off += try varint.encode(buf[off..], data.len);

    // Data
    if (buf.len < off + data.len) return error.BufferTooSmall;
    @memcpy(buf[off .. off + data.len], data);
    off += data.len;

    return off;
}

/// Write an ACK frame
/// Returns bytes written
pub fn writeAck(buf: []u8, largest_acked: u64, ack_delay: u64) WriteError!usize {
    var off: usize = 0;

    // Frame type 0x02 (simple ACK without ECN)
    off += try varint.encode(buf[off..], 0x02);

    // Largest Acknowledged
    off += try varint.encode(buf[off..], largest_acked);

    // ACK Delay
    off += try varint.encode(buf[off..], ack_delay);

    // ACK Range Count (0 for simple case)
    off += try varint.encode(buf[off..], 0);

    // First ACK Range (0 means only largest_acked is being acked)
    off += try varint.encode(buf[off..], 0);

    return off;
}

/// Write a PING frame
/// Returns bytes written
pub fn writePing(buf: []u8) WriteError!usize {
    if (buf.len < 1) return error.BufferTooSmall;
    buf[0] = 0x01;
    return 1;
}

/// Write a MAX_DATA frame
/// Returns bytes written
pub fn writeMaxData(buf: []u8, max_data: u64) WriteError!usize {
    var off: usize = 0;
    off += try varint.encode(buf[off..], 0x10); // Frame type
    off += try varint.encode(buf[off..], max_data);
    return off;
}

/// Write a MAX_STREAM_DATA frame
/// Returns bytes written
pub fn writeMaxStreamData(buf: []u8, stream_id: u64, max_data: u64) WriteError!usize {
    var off: usize = 0;
    off += try varint.encode(buf[off..], 0x11); // Frame type
    off += try varint.encode(buf[off..], stream_id);
    off += try varint.encode(buf[off..], max_data);
    return off;
}

/// Write a HANDSHAKE_DONE frame
/// Returns bytes written
pub fn writeHandshakeDone(buf: []u8) WriteError!usize {
    if (buf.len < 1) return error.BufferTooSmall;
    buf[0] = 0x1e;
    return 1;
}

// Tests
test "parse PING frame" {
    const buf = [_]u8{0x01};
    const result = try parseFrame(&buf);
    try std.testing.expect(result.frame == .ping);
    try std.testing.expectEqual(@as(usize, 1), result.consumed);
}

test "parse CRYPTO frame" {
    // Frame type (0x06) + offset (0) + length (5) + data
    const buf = [_]u8{ 0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    const result = try parseFrame(&buf);
    try std.testing.expect(result.frame == .crypto);
    const crypto = result.frame.crypto;
    try std.testing.expectEqual(@as(u64, 0), crypto.offset);
    try std.testing.expectEqualSlices(u8, "hello", crypto.data);
}

test "parse STREAM frame with all flags" {
    // Frame type 0x0f (OFF=1, LEN=1, FIN=1) + stream_id + offset + length + data
    const buf = [_]u8{ 0x0f, 0x04, 0x10, 0x03, 'a', 'b', 'c' };
    const result = try parseFrame(&buf);
    try std.testing.expect(result.frame == .stream);
    const stream = result.frame.stream;
    try std.testing.expectEqual(@as(u64, 4), stream.stream_id);
    try std.testing.expectEqual(@as(u64, 16), stream.offset);
    try std.testing.expectEqualSlices(u8, "abc", stream.data);
    try std.testing.expect(stream.fin);
}

test "parse MAX_DATA frame" {
    // Frame type (0x10) + maximum_data (1000000 = 0x40 0x0f 0x42 0x40)
    const buf = [_]u8{ 0x10, 0x80, 0x0f, 0x42, 0x40 };
    const result = try parseFrame(&buf);
    try std.testing.expect(result.frame == .max_data);
    try std.testing.expectEqual(@as(u64, 1000000), result.frame.max_data.maximum_data);
}

test "parse CONNECTION_CLOSE frame" {
    // Frame type (0x1c) + error_code (0) + frame_type (0) + reason_len (0)
    const buf = [_]u8{ 0x1c, 0x00, 0x00, 0x00 };
    const result = try parseFrame(&buf);
    try std.testing.expect(result.frame == .connection_close);
    const close = result.frame.connection_close;
    try std.testing.expectEqual(@as(u64, 0), close.error_code);
    try std.testing.expect(!close.application_error);
}

// === Write/Parse Round-Trip Tests ===

test "write and parse CONNECTION_CLOSE" {
    var buf: [256]u8 = undefined;
    const reason = "protocol violation";

    const written = try writeConnectionClose(&buf, 0x0a, 0x06, reason);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .connection_close);
    const close = result.frame.connection_close;
    try std.testing.expectEqual(@as(u64, 0x0a), close.error_code);
    try std.testing.expectEqual(@as(?u64, 0x06), close.frame_type);
    try std.testing.expectEqualStrings(reason, close.reason_phrase);
    try std.testing.expect(!close.application_error);
}

test "write and parse APPLICATION_CLOSE" {
    var buf: [256]u8 = undefined;
    const reason = "app error";

    const written = try writeApplicationClose(&buf, 0x100, reason);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .connection_close);
    const close = result.frame.connection_close;
    try std.testing.expectEqual(@as(u64, 0x100), close.error_code);
    try std.testing.expectEqualStrings(reason, close.reason_phrase);
    try std.testing.expect(close.application_error);
}

test "write and parse CRYPTO frame" {
    var buf: [256]u8 = undefined;
    const data = "crypto data";

    const written = try writeCrypto(&buf, 100, data);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .crypto);
    const crypto_frame = result.frame.crypto;
    try std.testing.expectEqual(@as(u64, 100), crypto_frame.offset);
    try std.testing.expectEqualStrings(data, crypto_frame.data);
}

test "write and parse STREAM frame" {
    var buf: [256]u8 = undefined;
    const data = "stream data";

    const written = try writeStream(&buf, 4, 50, data, true);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .stream);
    const stream_frame = result.frame.stream;
    try std.testing.expectEqual(@as(u64, 4), stream_frame.stream_id);
    try std.testing.expectEqual(@as(u64, 50), stream_frame.offset);
    try std.testing.expectEqualStrings(data, stream_frame.data);
    try std.testing.expect(stream_frame.fin);
}

test "write and parse ACK frame" {
    var buf: [256]u8 = undefined;

    const written = try writeAck(&buf, 100, 500);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .ack);
    const ack = result.frame.ack;
    try std.testing.expectEqual(@as(u64, 100), ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 500), ack.ack_delay);
}

test "write and parse PING frame" {
    var buf: [256]u8 = undefined;

    const written = try writePing(&buf);
    try std.testing.expectEqual(@as(usize, 1), written);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .ping);
}

test "write and parse MAX_DATA frame" {
    var buf: [256]u8 = undefined;

    const written = try writeMaxData(&buf, 1000000);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .max_data);
    try std.testing.expectEqual(@as(u64, 1000000), result.frame.max_data.maximum_data);
}

test "write and parse MAX_STREAM_DATA frame" {
    var buf: [256]u8 = undefined;

    const written = try writeMaxStreamData(&buf, 8, 500000);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .max_stream_data);
    try std.testing.expectEqual(@as(u64, 8), result.frame.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 500000), result.frame.max_stream_data.maximum_stream_data);
}

test "write and parse HANDSHAKE_DONE frame" {
    var buf: [256]u8 = undefined;

    const written = try writeHandshakeDone(&buf);
    try std.testing.expectEqual(@as(usize, 1), written);

    const result = try parseFrame(buf[0..written]);
    try std.testing.expect(result.frame == .handshake_done);
}
