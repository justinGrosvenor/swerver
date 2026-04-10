const std = @import("std");
pub const frame = @import("http3/frame.zig");
pub const qpack = @import("http3/qpack.zig");
const clock = @import("../runtime/clock.zig");

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
    /// Accumulated request body
    body_buffer: std.ArrayList(u8),
    /// Headers received flag
    headers_received: bool = false,
    /// End of stream received flag
    end_stream_received: bool = false,
};

/// Maximum size of body data per DATA frame (16KB)
pub const MAX_DATA_FRAME_SIZE: usize = 16 * 1024;

/// Format current time as IMF-fixdate (RFC 9110 §5.6.7) for HTTP/3
fn formatImfDateHttp3(buf: *[29]u8) []const u8 {
    const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const ts = clock.realtimeTimespec() orelse return "Thu, 01 Jan 1970 00:00:00 GMT";
    const epoch_secs: u64 = @intCast(ts.sec);
    const secs_per_day: u64 = 86400;
    var days = epoch_secs / secs_per_day;
    const day_secs = epoch_secs % secs_per_day;
    const hour = day_secs / 3600;
    const minute = (day_secs % 3600) / 60;
    const second = day_secs % 60;
    const wday = days % 7;
    var year: u64 = 1970;
    while (true) {
        const days_in_year: u64 = if (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)) 366 else 365;
        if (days < days_in_year) break;
        days -= days_in_year;
        year += 1;
    }
    const leap = (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0));
    const month_days_arr = if (leap)
        [_]u64{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
    else
        [_]u64{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var month: usize = 0;
    while (month < 11) : (month += 1) {
        if (days < month_days_arr[month]) break;
        days -= month_days_arr[month];
    }
    const day = days + 1;
    _ = std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[wday], day, month_names[month], year, hour, minute, second,
    }) catch return "Thu, 01 Jan 1970 00:00:00 GMT";
    return buf[0..29];
}

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
    /// Accumulated request bodies by stream ID
    request_bodies: std.AutoHashMap(u64, std.ArrayList(u8)),
    /// Request body storage (fixed buffers for small bodies)
    body_storage: [16][8192]u8 = undefined,
    /// Which body storage slots are in use
    body_storage_used: [16]bool = .{false} ** 16,

    pub const Settings = struct {
        // Our QPACK encoder doesn't use the dynamic table yet (everything
        // is static-or-literal), so advertise 0 capacity / 0 blocked streams.
        // Until we wire up dynamic-table support, advertising non-zero
        // values would mislead the peer.
        qpack_max_table_capacity: u64 = 0,
        max_field_section_size: u64 = 16384,
        qpack_blocked_streams: u64 = 0,
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
            .events = .empty,
            .is_server = is_server,
            .request_bodies = std.AutoHashMap(u64, std.ArrayList(u8)).init(allocator),
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
            state.buffer.deinit(self.allocator);
            state.body_buffer.deinit(self.allocator);
        }
        self.streams.deinit();
        self.events.deinit(self.allocator);

        // Clean up request bodies
        var body_it = self.request_bodies.valueIterator();
        while (body_it.next()) |body| {
            body.deinit(self.allocator);
        }
        self.request_bodies.deinit();
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
                        // Process encoder stream instructions (updates our decoder's table)
                        return self.processQpackEncoderStream(data[uni_type.len..]);
                    },
                    .qpack_decoder => {
                        self.peer_qpack_decoder = stream_id;
                        // Process decoder stream instructions (acknowledgments to our encoder)
                        return self.processQpackDecoderStream(data[uni_type.len..]);
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
            .qpack_encoder => {
                return self.processQpackEncoderStream(data);
            },
            .qpack_decoder => {
                return self.processQpackDecoderStream(data);
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

                    self.events.append(self.allocator,.{
                        .headers = .{
                            .stream_id = stream_id,
                            .headers = owned_headers,
                            .end_stream = end_stream and offset >= data.len,
                        },
                    }) catch return error.BufferTooSmall;
                },
                .data => |d| {
                    // Accumulate body data
                    try self.accumulateBody(stream_id, d.data);

                    self.events.append(self.allocator, .{
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
            self.events.append(self.allocator,.{
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
                    self.events.append(self.allocator,.{ .settings = event }) catch return error.BufferTooSmall;
                },
                .goaway => |g| {
                    self.events.append(self.allocator,.{
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

    /// Process QPACK encoder stream (updates our decoder's dynamic table)
    fn processQpackEncoderStream(self: *Stack, data: []const u8) Error!IngestResult {
        if (data.len == 0) {
            return .{ .consumed = 0, .events = &.{}, .need_more = true };
        }

        const result = self.qpack_decoder.processEncoderStream(data) catch {
            return error.QpackError;
        };

        return .{
            .consumed = result.consumed,
            .events = &.{},
            .need_more = false,
        };
    }

    /// Process QPACK decoder stream (acknowledgments for our encoder)
    fn processQpackDecoderStream(self: *Stack, data: []const u8) Error!IngestResult {
        if (data.len == 0) {
            return .{ .consumed = 0, .events = &.{}, .need_more = true };
        }

        _ = self.qpack_encoder.processDecoderStream(data) catch {
            return error.QpackError;
        };

        return .{
            .consumed = data.len,
            .events = &.{},
            .need_more = false,
        };
    }

    /// Encode an HTTP/3 response
    /// For large bodies, this splits into multiple DATA frames (max 16KB each)
    pub fn encodeResponse(
        self: *Stack,
        buf: []u8,
        status: u16,
        headers: []const Header,
        body: ?[]const u8,
    ) Error!usize {
        var offset: usize = 0;

        // Build header array with :status pseudo-header first.
        // RFC 9114 §4.2: HTTP/3 field names MUST be lowercase. We
        // normalize here so application code can use canonical mixed
        // case ("Content-Type") without breaking interop.
        var all_headers: [66]Header = undefined;
        var status_buf: [3]u8 = undefined;
        _ = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch {
            return error.BufferTooSmall;
        };

        // Per-header lowercase name buffer (max 64 headers × 64 bytes/name).
        // 4 KB total — sized for typical response header sets.
        var name_storage: [64][64]u8 = undefined;
        var name_storage_idx: usize = 0;

        const lowercaseName = struct {
            fn call(
                store: *[64][64]u8,
                idx: *usize,
                name: []const u8,
            ) ![]const u8 {
                if (name.len == 0) return name;
                if (name[0] == ':') return name; // pseudo-headers stay literal
                // Already lowercase? Avoid copying.
                var all_lower = true;
                for (name) |c| {
                    if (c >= 'A' and c <= 'Z') {
                        all_lower = false;
                        break;
                    }
                }
                if (all_lower) return name;
                if (idx.* >= store.len) return error.BufferTooSmall;
                if (name.len > store[idx.*].len) return error.BufferTooSmall;
                for (name, 0..) |c, i| {
                    store[idx.*][i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
                }
                const slot = store[idx.*][0..name.len];
                idx.* += 1;
                return slot;
            }
        }.call;

        all_headers[0] = .{ .name = ":status", .value = &status_buf };
        // RFC 9110 §6.3: Suppress content-length for 1xx/204/304 (no message body)
        const suppress_body = (status >= 100 and status < 200) or status == 204 or status == 304;
        var header_count: usize = 1;
        for (headers) |h| {
            if (suppress_body and std.ascii.eqlIgnoreCase(h.name, "content-length")) continue;
            const lc_name = lowercaseName(&name_storage, &name_storage_idx, h.name) catch {
                return error.BufferTooSmall;
            };
            all_headers[header_count] = .{ .name = lc_name, .value = h.value };
            header_count += 1;
        }
        // RFC 9110 §6.6.1: Origin servers MUST send Date header (except 1xx)
        var date_buf: [29]u8 = undefined;
        if (status >= 200) {
            const date_str = formatImfDateHttp3(&date_buf);
            all_headers[header_count] = .{ .name = "date", .value = date_str };
            header_count += 1;
        }

        // Encode headers with QPACK
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = self.qpack_encoder.encode(&qpack_buf, all_headers[0..header_count]) catch {
            return error.QpackError;
        };

        // Write HEADERS frame
        offset += frame.writeHeadersFrame(buf[offset..], qpack_buf[0..qpack_len]) catch {
            return error.BufferTooSmall;
        };

        // RFC 9110 §6.3: 1xx/204/304 MUST NOT contain a message body
        if (suppress_body) return offset;

        // Write DATA frame(s) if body present - chunk large bodies
        if (body) |b| {
            var body_offset: usize = 0;
            while (body_offset < b.len) {
                const chunk_size = @min(b.len - body_offset, MAX_DATA_FRAME_SIZE);
                const chunk = b[body_offset .. body_offset + chunk_size];

                offset += frame.writeDataFrame(buf[offset..], chunk) catch {
                    return error.BufferTooSmall;
                };

                body_offset += chunk_size;
            }
        }

        return offset;
    }

    /// Response encoder for streaming large responses
    /// Returns chunks that can be sent incrementally
    pub const ResponseEncoder = struct {
        stack: *Stack,
        body: []const u8,
        body_offset: usize,
        headers_sent: bool,
        status: u16,
        headers: []const Header,

        pub fn init(stack: *Stack, status: u16, headers: []const Header, body: []const u8) ResponseEncoder {
            return .{
                .stack = stack,
                .body = body,
                .body_offset = 0,
                .headers_sent = false,
                .status = status,
                .headers = headers,
            };
        }

        /// Encode the next chunk into the buffer
        /// Returns bytes written, or 0 if done
        pub fn next(self: *ResponseEncoder, buf: []u8) Error!usize {
            var offset: usize = 0;

            // Send headers first
            if (!self.headers_sent) {
                var all_headers: [66]Header = undefined;
                var status_buf: [3]u8 = undefined;
                _ = std.fmt.bufPrint(&status_buf, "{d}", .{self.status}) catch {
                    return error.BufferTooSmall;
                };

                const suppress_body = (self.status >= 100 and self.status < 200) or self.status == 204 or self.status == 304;
                all_headers[0] = .{ .name = ":status", .value = &status_buf };
                var header_count: usize = 1;
                for (self.headers) |h| {
                    if (suppress_body and std.ascii.eqlIgnoreCase(h.name, "content-length")) continue;
                    all_headers[header_count] = h;
                    header_count += 1;
                }
                // RFC 9110 §6.6.1: Date header (except 1xx)
                var date_buf: [29]u8 = undefined;
                if (self.status >= 200) {
                    const date_str = formatImfDateHttp3(&date_buf);
                    all_headers[header_count] = .{ .name = "date", .value = date_str };
                    header_count += 1;
                }

                var qpack_buf: [4096]u8 = undefined;
                const qpack_len = self.stack.qpack_encoder.encode(&qpack_buf, all_headers[0..header_count]) catch {
                    return error.QpackError;
                };

                offset += frame.writeHeadersFrame(buf[offset..], qpack_buf[0..qpack_len]) catch {
                    return error.BufferTooSmall;
                };

                self.headers_sent = true;
                if (suppress_body) return offset;
            }

            // Send body chunk if there's more body
            if (self.body_offset < self.body.len) {
                const chunk_size = @min(self.body.len - self.body_offset, MAX_DATA_FRAME_SIZE);
                const chunk = self.body[self.body_offset .. self.body_offset + chunk_size];

                offset += frame.writeDataFrame(buf[offset..], chunk) catch {
                    return error.BufferTooSmall;
                };

                self.body_offset += chunk_size;
            }

            return offset;
        }

        /// Check if encoding is complete
        pub fn isDone(self: *const ResponseEncoder) bool {
            return self.headers_sent and self.body_offset >= self.body.len;
        }

        /// Get remaining body bytes
        pub fn remainingBytes(self: *const ResponseEncoder) usize {
            return self.body.len - self.body_offset;
        }
    };

    /// Build initial SETTINGS frame for our control stream
    pub fn buildSettings(self: *Stack, buf: []u8) Error!usize {
        const params = [_]frame.SettingsParam{
            .{ .id = @intFromEnum(frame.SettingsId.qpack_max_table_capacity), .value = self.settings.qpack_max_table_capacity },
            .{ .id = @intFromEnum(frame.SettingsId.max_field_section_size), .value = self.settings.max_field_section_size },
            .{ .id = @intFromEnum(frame.SettingsId.qpack_blocked_streams), .value = self.settings.qpack_blocked_streams },
        };

        return frame.writeSettingsFrame(buf, &params) catch error.BufferTooSmall;
    }

    /// Accumulate request body data for a stream
    pub fn accumulateBody(self: *Stack, stream_id: u64, data: []const u8) Error!void {
        if (data.len == 0) return;

        const entry = self.request_bodies.getPtr(stream_id);
        if (entry) |body_list| {
            // Append to existing body
            body_list.appendSlice(self.allocator, data) catch return error.BufferTooSmall;
        } else {
            // Create new body accumulator
            var body_list: std.ArrayList(u8) = .empty;
            body_list.appendSlice(self.allocator, data) catch return error.BufferTooSmall;
            self.request_bodies.put(stream_id, body_list) catch return error.BufferTooSmall;
        }
    }

    /// Get accumulated request body for a stream
    /// Returns null if no body data has been received
    pub fn getRequestBody(self: *Stack, stream_id: u64) ?[]const u8 {
        if (self.request_bodies.get(stream_id)) |body_list| {
            if (body_list.items.len > 0) {
                return body_list.items;
            }
        }
        return null;
    }

    /// Clear accumulated body for a stream (call after request is processed)
    pub fn clearRequestBody(self: *Stack, stream_id: u64) void {
        if (self.request_bodies.fetchRemove(stream_id)) |kv| {
            var body_list = kv.value;
            body_list.deinit(self.allocator);
        }
    }

    /// Get total accumulated body size for a stream
    pub fn getRequestBodySize(self: *Stack, stream_id: u64) usize {
        if (self.request_bodies.get(stream_id)) |body_list| {
            return body_list.items.len;
        }
        return 0;
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

test "request body accumulation" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    const stream_id: u64 = 0; // Client-initiated bidirectional

    // Initially no body
    try std.testing.expect(stack.getRequestBody(stream_id) == null);
    try std.testing.expectEqual(@as(usize, 0), stack.getRequestBodySize(stream_id));

    // Accumulate first chunk
    try stack.accumulateBody(stream_id, "Hello");
    try std.testing.expectEqual(@as(usize, 5), stack.getRequestBodySize(stream_id));
    try std.testing.expectEqualStrings("Hello", stack.getRequestBody(stream_id).?);

    // Accumulate second chunk
    try stack.accumulateBody(stream_id, " World");
    try std.testing.expectEqual(@as(usize, 11), stack.getRequestBodySize(stream_id));
    try std.testing.expectEqualStrings("Hello World", stack.getRequestBody(stream_id).?);

    // Clear body
    stack.clearRequestBody(stream_id);
    try std.testing.expect(stack.getRequestBody(stream_id) == null);
    try std.testing.expectEqual(@as(usize, 0), stack.getRequestBodySize(stream_id));
}

test "multiple stream body accumulation" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Two different streams
    const stream1: u64 = 0;
    const stream2: u64 = 4;

    try stack.accumulateBody(stream1, "Body1");
    try stack.accumulateBody(stream2, "Body2");

    try std.testing.expectEqualStrings("Body1", stack.getRequestBody(stream1).?);
    try std.testing.expectEqualStrings("Body2", stack.getRequestBody(stream2).?);

    // Clear only stream1
    stack.clearRequestBody(stream1);
    try std.testing.expect(stack.getRequestBody(stream1) == null);
    try std.testing.expectEqualStrings("Body2", stack.getRequestBody(stream2).?);
}

test "response body chunking - small body" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [4096]u8 = undefined;
    const headers = [_]Header{
        .{ .name = "content-type", .value = "text/plain" },
    };

    // Small body should produce single DATA frame
    const small_body = "Hello, World!";
    const len = try stack.encodeResponse(&buf, 200, &headers, small_body);
    try std.testing.expect(len > 0);

    // Parse and verify we get HEADERS + DATA
    var offset: usize = 0;

    // Parse HEADERS frame
    const headers_result = try frame.parseFrame(buf[offset..len], allocator);
    try std.testing.expect(headers_result.frame == .headers);
    offset += headers_result.consumed;

    // Parse single DATA frame
    const data_result = try frame.parseFrame(buf[offset..len], allocator);
    try std.testing.expect(data_result.frame == .data);
    try std.testing.expectEqualStrings(small_body, data_result.frame.data.data);
}

test "response body chunking - large body" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Create body larger than MAX_DATA_FRAME_SIZE
    var large_body: [MAX_DATA_FRAME_SIZE + 1000]u8 = undefined;
    for (&large_body, 0..) |*c, i| {
        c.* = @truncate(i % 256);
    }

    var buf: [65536]u8 = undefined;
    const headers = [_]Header{
        .{ .name = "content-type", .value = "application/octet-stream" },
    };

    const len = try stack.encodeResponse(&buf, 200, &headers, &large_body);
    try std.testing.expect(len > 0);

    // Parse and verify we get HEADERS + 2 DATA frames
    var offset: usize = 0;

    // Parse HEADERS frame
    const headers_result = try frame.parseFrame(buf[offset..len], allocator);
    try std.testing.expect(headers_result.frame == .headers);
    offset += headers_result.consumed;

    // Parse first DATA frame (should be MAX_DATA_FRAME_SIZE)
    const data1_result = try frame.parseFrame(buf[offset..len], allocator);
    try std.testing.expect(data1_result.frame == .data);
    try std.testing.expectEqual(MAX_DATA_FRAME_SIZE, data1_result.frame.data.data.len);
    offset += data1_result.consumed;

    // Parse second DATA frame (should be 1000 bytes)
    const data2_result = try frame.parseFrame(buf[offset..len], allocator);
    try std.testing.expect(data2_result.frame == .data);
    try std.testing.expectEqual(@as(usize, 1000), data2_result.frame.data.data.len);
}

test "response encoder streaming" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Create body larger than MAX_DATA_FRAME_SIZE
    var large_body: [MAX_DATA_FRAME_SIZE * 2 + 500]u8 = undefined;
    for (&large_body, 0..) |*c, i| {
        c.* = @truncate(i % 256);
    }

    const headers = [_]Header{
        .{ .name = "content-type", .value = "application/octet-stream" },
    };

    var encoder = Stack.ResponseEncoder.init(&stack, 200, &headers, &large_body);

    // Should not be done initially
    try std.testing.expect(!encoder.isDone());
    try std.testing.expectEqual(large_body.len, encoder.remainingBytes());

    var buf: [32768]u8 = undefined;
    var total_written: usize = 0;
    var chunks: usize = 0;

    // Encode chunks until done
    while (!encoder.isDone()) {
        const written = try encoder.next(&buf);
        total_written += written;
        chunks += 1;
    }

    // Should have produced 3 body chunks (plus headers in first call)
    try std.testing.expectEqual(@as(usize, 3), chunks);
    try std.testing.expect(encoder.isDone());
    try std.testing.expectEqual(@as(usize, 0), encoder.remainingBytes());
}
