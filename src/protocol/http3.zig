const std = @import("std");
pub const frame = @import("http3/frame.zig");
pub const qpack = @import("http3/qpack.zig");

/// HTTP/3 Protocol Stack
///
/// Processes HTTP/3 frames from QUIC streams and produces HTTP events.
/// Each QUIC connection should have one HTTP/3 Stack instance.

pub const Error = error{
    InvalidFrame,
    InvalidState,
    StreamError,
    QpackError,
    BufferTooSmall,
    ConnectionError,
    UnexpectedEnd,
};

/// HTTP/3 stream types (determined by stream ID)
pub const StreamType = enum {
    /// Bidirectional request stream (client-initiated)
    request,
    /// Control stream
    control,
    /// QPACK encoder stream
    qpack_encoder,
    /// QPACK decoder stream
    qpack_decoder,
    /// Push stream (server-initiated)
    push,
    /// Unknown unidirectional stream
    unknown,
};

/// HTTP/3 unidirectional stream type bytes per RFC 9114
pub const UniStreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    _,
};

/// Request state
pub const RequestState = enum {
    /// Waiting for HEADERS frame
    awaiting_headers,
    /// Headers received, may receive DATA
    headers_received,
    /// Request complete (end of stream)
    complete,
    /// Error state
    failed,
};

/// HTTP/3 event types
pub const Event = union(enum) {
    /// HEADERS frame received with decoded headers
    headers: HeadersEvent,
    /// DATA frame received
    data: DataEvent,
    /// End of stream
    end_stream: EndStreamEvent,
    /// SETTINGS received
    settings: SettingsEvent,
    /// GOAWAY received
    goaway: GoawayEvent,
    /// Error on stream
    stream_error: StreamErrorEvent,
};

pub const HeadersEvent = struct {
    stream_id: u64,
    /// Decoded header fields
    headers: []const Header,
    /// End of stream flag
    end_stream: bool,
};

pub const DataEvent = struct {
    stream_id: u64,
    data: []const u8,
    end_stream: bool,
};

pub const EndStreamEvent = struct {
    stream_id: u64,
};

pub const SettingsEvent = struct {
    qpack_max_table_capacity: u64,
    max_field_section_size: u64,
    qpack_blocked_streams: u64,
};

pub const GoawayEvent = struct {
    stream_id: u64,
};

pub const StreamErrorEvent = struct {
    stream_id: u64,
    error_code: u64,
};

/// Header field (reexport from qpack)
pub const Header = qpack.HeaderField;

/// Result of ingesting stream data
pub const IngestResult = struct {
    /// Bytes consumed from input
    consumed: usize,
    /// Events produced
    events: []Event,
    /// Need more data
    need_more: bool,
};

/// Per-stream state
const StreamState = struct {
    stream_type: StreamType,
    request_state: RequestState,
    /// Buffer for partial frames
    buffer: std.ArrayList(u8),
};

/// HTTP/3 Stack
pub const Stack = struct {
    allocator: std.mem.Allocator,
    /// QPACK decoder
    qpack_decoder: qpack.Decoder,
    /// QPACK encoder
    qpack_encoder: qpack.Encoder,
    /// Control stream ID (peer's)
    peer_control_stream: ?u64,
    /// Our control stream ID
    our_control_stream: ?u64,
    /// Peer's QPACK encoder stream
    peer_qpack_encoder: ?u64,
    /// Peer's QPACK decoder stream
    peer_qpack_decoder: ?u64,
    /// SETTINGS received from peer
    peer_settings_received: bool,
    /// Our SETTINGS
    settings: Settings,
    /// Stream states
    streams: std.AutoHashMap(u64, StreamState),
    /// Event buffer
    events: std.ArrayList(Event),
    /// Decoded headers buffer (copied from decoder to ensure lifetime)
    header_buf: [64]Header = undefined,
    /// Header name storage (for copied headers)
    header_name_storage: [64][256]u8 = undefined,
    /// Header value storage (for copied headers)
    header_value_storage: [64][4096]u8 = undefined,
    /// Number of headers currently stored
    header_count: usize = 0,
    /// Is server?
    is_server: bool,

    pub const Settings = struct {
        qpack_max_table_capacity: u64 = 4096,
        max_field_section_size: u64 = 16384,
        qpack_blocked_streams: u64 = 100,
    };

    pub fn init(allocator: std.mem.Allocator, is_server: bool) Stack {
        return .{
            .allocator = allocator,
            .qpack_decoder = qpack.Decoder.init(4096),
            .qpack_encoder = qpack.Encoder.init(4096),
            .peer_control_stream = null,
            .our_control_stream = null,
            .peer_qpack_encoder = null,
            .peer_qpack_decoder = null,
            .peer_settings_received = false,
            .settings = .{},
            .streams = std.AutoHashMap(u64, StreamState).init(allocator),
            .events = std.ArrayList(Event).init(allocator),
            .is_server = is_server,
        };
    }

    /// Copy headers from decoder's internal storage to Stack's owned storage
    /// Returns slice of copied headers (valid until next copyHeaders call or ingest)
    fn copyHeaders(self: *Stack, headers: []const Header) Error![]const Header {
        if (headers.len > 64) return error.BufferTooSmall;

        self.header_count = 0;
        for (headers) |hdr| {
            if (self.header_count >= 64) return error.BufferTooSmall;
            if (hdr.name.len > 256 or hdr.value.len > 4096) return error.BufferTooSmall;

            const idx = self.header_count;
            @memcpy(self.header_name_storage[idx][0..hdr.name.len], hdr.name);
            @memcpy(self.header_value_storage[idx][0..hdr.value.len], hdr.value);

            self.header_buf[idx] = .{
                .name = self.header_name_storage[idx][0..hdr.name.len],
                .value = self.header_value_storage[idx][0..hdr.value.len],
            };
            self.header_count += 1;
        }

        return self.header_buf[0..self.header_count];
    }

    pub fn deinit(self: *Stack) void {
        var it = self.streams.valueIterator();
        while (it.next()) |state| {
            state.buffer.deinit();
        }
        self.streams.deinit();
        self.events.deinit();
        // qpack encoder/decoder use fixed-size internal storage, no deinit needed
    }

    /// Determine stream type from stream ID
    pub fn getStreamType(self: *Stack, stream_id: u64) StreamType {
        // Client-initiated bidirectional: 0, 4, 8, ... (stream_id % 4 == 0)
        // Server-initiated bidirectional: 1, 5, 9, ... (stream_id % 4 == 1)
        // Client-initiated unidirectional: 2, 6, 10, ... (stream_id % 4 == 2)
        // Server-initiated unidirectional: 3, 7, 11, ... (stream_id % 4 == 3)

        const initiator = stream_id & 0x01;
        const direction = (stream_id >> 1) & 0x01;

        // Bidirectional streams are request streams
        if (direction == 0) {
            return .request;
        }

        // Unidirectional streams - check special stream IDs
        if (self.peer_control_stream) |ctrl| {
            if (stream_id == ctrl) return .control;
        }
        if (self.peer_qpack_encoder) |enc| {
            if (stream_id == enc) return .qpack_encoder;
        }
        if (self.peer_qpack_decoder) |dec| {
            if (stream_id == dec) return .qpack_decoder;
        }

        // Unknown unidirectional (need to read type byte)
        _ = initiator;
        return .unknown;
    }

    /// Process incoming stream data
    pub fn ingest(
        self: *Stack,
        stream_id: u64,
        data: []const u8,
        end_stream: bool,
    ) Error!IngestResult {
        self.events.clearRetainingCapacity();

        const stream_type = self.getStreamType(stream_id);

        switch (stream_type) {
            .request => {
                return self.processRequestStream(stream_id, data, end_stream);
            },
            .control => {
                return self.processControlStream(data);
            },
            .unknown => {
                // First byte is stream type
                if (data.len == 0) {
                    return .{ .consumed = 0, .events = &.{}, .need_more = true };
                }

                const uni_type = frame.decodeVarint(data) catch {
                    return error.InvalidFrame;
                };

                switch (@as(UniStreamType, @enumFromInt(uni_type.value))) {
                    .control => {
                        self.peer_control_stream = stream_id;
                        return self.processControlStream(data[uni_type.len..]);
                    },
                    .qpack_encoder => {
                        self.peer_qpack_encoder = stream_id;
                        // QPACK encoder instructions - for now skip
                        return .{ .consumed = data.len, .events = &.{}, .need_more = false };
                    },
                    .qpack_decoder => {
                        self.peer_qpack_decoder = stream_id;
                        // QPACK decoder instructions - for now skip
                        return .{ .consumed = data.len, .events = &.{}, .need_more = false };
                    },
                    .push => {
                        // Push streams (server to client only)
                        return .{ .consumed = data.len, .events = &.{}, .need_more = false };
                    },
                    _ => {
                        // Unknown stream type - skip
                        return .{ .consumed = data.len, .events = &.{}, .need_more = false };
                    },
                }
            },
            .qpack_encoder, .qpack_decoder => {
                // QPACK encoder/decoder instructions - consume but don't process
                // (dynamic table updates not implemented)
                return .{ .consumed = data.len, .events = &.{}, .need_more = false };
            },
            .push => {
                // Push streams (server to client only) - consume
                return .{ .consumed = data.len, .events = &.{}, .need_more = false };
            },
        }
    }

    fn processRequestStream(
        self: *Stack,
        stream_id: u64,
        data: []const u8,
        end_stream: bool,
    ) Error!IngestResult {
        var offset: usize = 0;

        while (offset < data.len) {
            const remaining = data[offset..];
            const parse_result = frame.parseFrame(remaining, self.allocator) catch |err| {
                switch (err) {
                    error.UnexpectedEnd => {
                        // Need more data
                        return .{
                            .consumed = offset,
                            .events = self.events.items,
                            .need_more = true,
                        };
                    },
                    else => return error.InvalidFrame,
                }
            };

            offset += parse_result.consumed;

            switch (parse_result.frame) {
                .headers => |hdr| {
                    // Decode QPACK headers
                    const decoded_headers = self.qpack_decoder.decode(hdr.encoded_headers) catch {
                        return error.QpackError;
                    };

                    // Copy headers to Stack's owned storage (decoder storage may be reused)
                    const owned_headers = try self.copyHeaders(decoded_headers);

                    self.events.append(.{
                        .headers = .{
                            .stream_id = stream_id,
                            .headers = owned_headers,
                            .end_stream = end_stream and offset >= data.len,
                        },
                    }) catch return error.BufferTooSmall;
                },
                .data => |d| {
                    self.events.append(.{
                        .data = .{
                            .stream_id = stream_id,
                            .data = d.data,
                            .end_stream = end_stream and offset >= data.len,
                        },
                    }) catch return error.BufferTooSmall;
                },
                else => {
                    // Ignore other frame types on request streams
                },
            }
        }

        if (end_stream) {
            self.events.append(.{
                .end_stream = .{ .stream_id = stream_id },
            }) catch return error.BufferTooSmall;
        }

        return .{
            .consumed = offset,
            .events = self.events.items,
            .need_more = false,
        };
    }

    fn processControlStream(self: *Stack, data: []const u8) Error!IngestResult {
        var offset: usize = 0;

        while (offset < data.len) {
            const remaining = data[offset..];
            const parse_result = frame.parseFrame(remaining, self.allocator) catch |err| {
                switch (err) {
                    error.UnexpectedEnd => {
                        return .{
                            .consumed = offset,
                            .events = self.events.items,
                            .need_more = true,
                        };
                    },
                    else => return error.InvalidFrame,
                }
            };

            offset += parse_result.consumed;

            switch (parse_result.frame) {
                .settings => |s| {
                    var event = SettingsEvent{
                        .qpack_max_table_capacity = 0,
                        .max_field_section_size = 16384,
                        .qpack_blocked_streams = 0,
                    };

                    for (s.getParams()) |param| {
                        switch (@as(frame.SettingsId, @enumFromInt(param.id))) {
                            .qpack_max_table_capacity => event.qpack_max_table_capacity = param.value,
                            .max_field_section_size => event.max_field_section_size = param.value,
                            .qpack_blocked_streams => event.qpack_blocked_streams = param.value,
                            else => {},
                        }
                    }

                    self.peer_settings_received = true;
                    self.events.append(.{ .settings = event }) catch return error.BufferTooSmall;
                },
                .goaway => |g| {
                    self.events.append(.{
                        .goaway = .{ .stream_id = g.stream_id },
                    }) catch return error.BufferTooSmall;
                },
                else => {
                    // Ignore unknown frames on control stream
                },
            }
        }

        return .{
            .consumed = offset,
            .events = self.events.items,
            .need_more = false,
        };
    }

    /// Encode an HTTP/3 response
    pub fn encodeResponse(
        self: *Stack,
        buf: []u8,
        status: u16,
        headers: []const Header,
        body: ?[]const u8,
    ) Error!usize {
        var offset: usize = 0;

        // Build header array with :status pseudo-header first
        var all_headers: [65]Header = undefined;
        var status_buf: [3]u8 = undefined;
        _ = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch {
            return error.BufferTooSmall;
        };

        all_headers[0] = .{ .name = ":status", .value = &status_buf };
        for (headers, 1..) |h, i| {
            all_headers[i] = h;
        }
        const header_count = headers.len + 1;

        // Encode headers with QPACK
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = self.qpack_encoder.encode(&qpack_buf, all_headers[0..header_count]) catch {
            return error.QpackError;
        };

        // Write HEADERS frame
        offset += frame.writeHeadersFrame(buf[offset..], qpack_buf[0..qpack_len]) catch {
            return error.BufferTooSmall;
        };

        // Write DATA frame if body present
        if (body) |b| {
            offset += frame.writeDataFrame(buf[offset..], b) catch {
                return error.BufferTooSmall;
            };
        }

        return offset;
    }

    /// Build initial SETTINGS frame for our control stream
    pub fn buildSettings(self: *Stack, buf: []u8) Error!usize {
        const params = [_]frame.SettingsParam{
            .{ .id = @intFromEnum(frame.SettingsId.qpack_max_table_capacity), .value = self.settings.qpack_max_table_capacity },
            .{ .id = @intFromEnum(frame.SettingsId.max_field_section_size), .value = self.settings.max_field_section_size },
            .{ .id = @intFromEnum(frame.SettingsId.qpack_blocked_streams), .value = self.settings.qpack_blocked_streams },
        };

        return frame.writeSettingsFrame(buf, &params) catch error.BufferTooSmall;
    }
};

// Tests
test "stack initialization" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    try std.testing.expect(stack.peer_control_stream == null);
    try std.testing.expect(!stack.peer_settings_received);
}

test "stream type detection" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Client-initiated bidirectional (request stream)
    try std.testing.expectEqual(StreamType.request, stack.getStreamType(0));
    try std.testing.expectEqual(StreamType.request, stack.getStreamType(4));

    // Server-initiated bidirectional (request stream)
    try std.testing.expectEqual(StreamType.request, stack.getStreamType(1));

    // Client-initiated unidirectional
    try std.testing.expectEqual(StreamType.unknown, stack.getStreamType(2));
}

test "encode response" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [4096]u8 = undefined;

    const headers = [_]Header{
        .{ .name = "content-type", .value = "text/plain" },
    };

    const len = try stack.encodeResponse(&buf, 200, &headers, "Hello");
    try std.testing.expect(len > 0);
}

test "build settings" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [256]u8 = undefined;
    const len = try stack.buildSettings(&buf);
    try std.testing.expect(len > 0);
}
