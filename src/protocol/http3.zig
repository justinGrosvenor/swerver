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

/// HTTP/3 event types.
///
/// Request streams use the defer-until-FIN model: the Stack buffers
/// nothing and emits a single `request_ready` event once the stream's
/// FIN has been seen and the full HEADERS + optional DATA frames have
/// been parsed. There is no per-frame HeadersEvent / DataEvent — the
/// router is synchronous and wants complete requests.
pub const Event = union(enum) {
    /// Request complete — dispatch to the application handler.
    request_ready: RequestReadyEvent,
    /// SETTINGS received on the peer control stream.
    settings: SettingsEvent,
    /// GOAWAY received on the peer control stream.
    goaway: GoawayEvent,
    /// Stream-level error.
    stream_error: StreamErrorEvent,
};

/// Emitted exactly once per request, at FIN time, with the full
/// headers and body ready for dispatch.
///
/// Lifetime:
/// - `headers` slices point into the Stack's fixed-size owned storage
///   (`header_name_storage` / `header_value_storage`). They are valid
///   until the Stack's next `ingest()` call on this connection.
/// - `body` is a slice into the caller's input buffer passed to
///   `ingest()` (typically the decrypted QUIC STREAM frame payload).
///   It is valid for the duration of the synchronous handler
///   invocation that processes this event.
///
/// Both slices must be consumed / copied before the next `ingest()`
/// call on the same Stack.
pub const RequestReadyEvent = struct {
    stream_id: u64,
    headers: []const Header,
    body: []const u8,
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
    /// Event buffer. `clearRetainingCapacity` is called once per QUIC
    /// packet by `quic.handler::processPacket::clearEvents` so the
    /// backing storage amortizes to zero per-packet allocation after
    /// the first few packets.
    events: std.ArrayList(Event),
    /// Decoded headers buffer (copied from decoder to ensure lifetime
    /// across QPACK decoder reuse). Fixed-size, instance-owned, no
    /// heap allocation on the request path.
    header_buf: [64]Header = undefined,
    /// Header name storage (for copied headers)
    header_name_storage: [64][256]u8 = undefined,
    /// Header value storage (for copied headers)
    header_value_storage: [64][4096]u8 = undefined,
    /// Number of headers currently stored
    header_count: usize = 0,
    /// Is server?
    is_server: bool,
    /// Cached IMF-fixdate string for the Date response header,
    /// refreshed once per Unix epoch second. Mirrors h1's
    /// Server.getCachedDate pattern. Saves ~100 cycles per response
    /// on the cold h3 path. The hot path (PR PERF-3 pre-encoded
    /// cache) bakes the Date into its cached bytes and refreshes
    /// those independently.
    cached_date: [29]u8 = undefined,
    cached_date_epoch: u64 = 0,

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
            // Decoder capacity matches our advertised
            // SETTINGS_QPACK_MAX_TABLE_CAPACITY. Advertising 0 and
            // initializing at 4096 is a latent bug — a peer can
            // ignore SETTINGS and still get us to accept inserts
            // up to 4096 bytes. With max_allowed_capacity = 0 at
            // decoder init, `processEncoderStream` rejects any
            // insert/duplicate instruction and any `Set Capacity`
            // with a non-zero value.
            .qpack_decoder = qpack.Decoder.init(0),
            .qpack_encoder = qpack.Encoder.init(4096),
            .peer_control_stream = null,
            .our_control_stream = null,
            .peer_qpack_encoder = null,
            .peer_qpack_decoder = null,
            .peer_settings_received = false,
            .settings = .{},
            .events = .empty,
            .is_server = is_server,
        };
    }

    /// Copy decoded request headers into the Stack's fixed-size owned
    /// storage and return a slice of the copied headers.
    ///
    /// Headers are APPENDED at `header_count`, not overwritten — this
    /// lets multiple concurrent request streams in a single QUIC packet
    /// each hold stable slices at the same time. The counter is reset
    /// to 0 once per packet by the handler via `clearEvents`, after the
    /// previous packet's events have been fully dispatched. Finding #7
    /// in `docs/design/8.0-h3-performance-plan.md`.
    fn copyHeaders(self: *Stack, headers: []const Header) Error![]const Header {
        const start = self.header_count;
        for (headers) |hdr| {
            if (self.header_count >= self.header_buf.len) return error.BufferTooSmall;
            if (hdr.name.len > self.header_name_storage[0].len) return error.BufferTooSmall;
            if (hdr.value.len > self.header_value_storage[0].len) return error.BufferTooSmall;

            const idx = self.header_count;
            @memcpy(self.header_name_storage[idx][0..hdr.name.len], hdr.name);
            @memcpy(self.header_value_storage[idx][0..hdr.value.len], hdr.value);

            self.header_buf[idx] = .{
                .name = self.header_name_storage[idx][0..hdr.name.len],
                .value = self.header_value_storage[idx][0..hdr.value.len],
            };
            self.header_count += 1;
        }

        return self.header_buf[start..self.header_count];
    }

    /// Reset the per-packet header scratch counter. Called by the
    /// handler from `clearEvents` once per packet, simultaneously with
    /// `events.clearRetainingCapacity()`, so every `events[i].headers`
    /// slice stays stable for the full duration of the packet's
    /// dispatch loop.
    pub fn resetPerPacketScratch(self: *Stack) void {
        self.header_count = 0;
    }

    pub fn deinit(self: *Stack) void {
        self.events.deinit(self.allocator);
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
        // NOTE: events are cleared once per QUIC packet by the caller
        // (quic.handler::processPacket → clearEvents). Do NOT clear here:
        // a single packet may contain multiple STREAM frames (e.g.
        // h2load sends the request stream + 3 client uni streams in one
        // packet), and clearing on each ingest call would clobber the
        // events from the earlier frames before processPacket can return
        // them to the caller.

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
                        // RFC 9114 §6.2.1: "Only one control stream per peer
                        // is permitted; receipt of a second stream claiming
                        // to be a control stream MUST be treated as a
                        // connection error of type H3_STREAM_CREATION_ERROR."
                        if (self.peer_control_stream) |existing| {
                            if (existing != stream_id) return error.ConnectionError;
                        }
                        self.peer_control_stream = stream_id;
                        return self.processControlStream(data[uni_type.len..]);
                    },
                    .qpack_encoder => {
                        // RFC 9204 §4.2: "Only one encoder stream and one
                        // decoder stream of each type is permitted in each
                        // direction; receipt of a second instance of either
                        // stream type MUST be treated as a connection error
                        // of type H3_STREAM_CREATION_ERROR."
                        if (self.peer_qpack_encoder) |existing| {
                            if (existing != stream_id) return error.ConnectionError;
                        }
                        self.peer_qpack_encoder = stream_id;
                        // Process encoder stream instructions (updates our decoder's table)
                        return self.processQpackEncoderStream(data[uni_type.len..]);
                    },
                    .qpack_decoder => {
                        // RFC 9204 §4.2: see qpack_encoder comment above.
                        if (self.peer_qpack_decoder) |existing| {
                            if (existing != stream_id) return error.ConnectionError;
                        }
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

    /// Process a request stream using the defer-until-FIN model.
    ///
    /// Design notes:
    /// - If `end_stream == false`, nothing is buffered and nothing is
    ///   emitted. Partial request streams must be held by the caller
    ///   (PR B wires this up via `stream.Stream.read()`/`consumeRead()`
    ///   in the handler). For single-STREAM-frame requests — which is
    ///   the overwhelming majority of real-world h3 GET traffic —
    ///   the entire request arrives in one `ingest` call with
    ///   `end_stream` already true, and this path is the fast path.
    /// - On FIN: parse all h3 frames in one linear pass, QPACK-decode
    ///   the HEADERS into the Stack's fixed-size owned header storage,
    ///   capture the DATA frame payload (if any) as a direct slice
    ///   into the caller's input, and emit one `RequestReadyEvent`.
    /// - Multi-DATA-frame request bodies are rejected with
    ///   `error.ConnectionError`. The RFC allows them, but this path
    ///   focuses on zero-copy single-frame bodies; concatenation is
    ///   tracked as a follow-up.
    /// - Zero heap allocations on the hot path: no hashmap, no
    ///   ArrayList grow past capacity after warmup, no slab acquire.
    ///   The only allocations are the `self.events.append` calls,
    ///   which amortize to zero via `clearRetainingCapacity` called
    ///   once per QUIC packet by the handler.
    fn processRequestStream(
        self: *Stack,
        stream_id: u64,
        data: []const u8,
        end_stream: bool,
    ) Error!IngestResult {
        // Defer-until-FIN. Partial request streams wait.
        if (!end_stream) {
            return .{
                .consumed = 0,
                .events = self.events.items,
                .need_more = true,
            };
        }

        var owned_headers: []const Header = &.{};
        var body: []const u8 = "";
        var have_headers = false;
        var data_frame_count: usize = 0;

        var offset: usize = 0;
        while (offset < data.len) {
            const parse_result = frame.parseFrame(data[offset..], self.allocator) catch |err| {
                // On FIN we expect the stream's h3 frames to parse
                // completely. A short read here means the peer
                // terminated the stream mid-frame.
                switch (err) {
                    error.UnexpectedEnd => return error.InvalidFrame,
                    else => return error.InvalidFrame,
                }
            };
            offset += parse_result.consumed;

            switch (parse_result.frame) {
                .headers => |hdr| {
                    const decoded = self.qpack_decoder.decode(hdr.encoded_headers) catch {
                        return error.QpackError;
                    };
                    owned_headers = try self.copyHeaders(decoded);
                    have_headers = true;
                },
                .data => |d| {
                    data_frame_count += 1;
                    if (data_frame_count == 1) {
                        // Zero-copy body: slice into caller's input buffer.
                        body = d.data;
                    } else {
                        // Multi-DATA-frame request body: not supported
                        // in PR A. Returning ConnectionError closes the
                        // QUIC connection with H3_INTERNAL_ERROR via
                        // `quic.connection::processHttp3Stream`, which
                        // is strictly better than the pre-PR-A silent
                        // drop.
                        return error.ConnectionError;
                    }
                },
                else => {
                    // Ignore trailers, reserved/grease frame types, and
                    // cancel_push on the request stream. A stricter
                    // implementation would reject some of these per
                    // RFC 9114 §7.2, but leaving them as no-ops is
                    // compliant (frames the recipient does not
                    // understand MUST be discarded).
                },
            }
        }

        if (!have_headers) {
            // A request stream that ended without a HEADERS frame is
            // malformed.
            return error.InvalidFrame;
        }

        self.events.append(self.allocator, .{
            .request_ready = .{
                .stream_id = stream_id,
                .headers = owned_headers,
                .body = body,
            },
        }) catch return error.BufferTooSmall;

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
                    // RFC 9114 §7.2.4: "If an endpoint receives a second
                    // SETTINGS frame on the control stream, the endpoint
                    // MUST respond with a connection error of type
                    // H3_FRAME_UNEXPECTED."
                    if (self.peer_settings_received) return error.ConnectionError;

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
                .data, .headers, .push_promise => {
                    // RFC 9114 §7.2.1 / §7.2.2 / §7.2.5: DATA, HEADERS, and
                    // PUSH_PROMISE frames are not permitted on the control
                    // stream. Receipt MUST be treated as a connection error
                    // of type H3_FRAME_UNEXPECTED.
                    return error.ConnectionError;
                },
                .goaway => |g| {
                    // RFC 9114 §6.2.1: SETTINGS must be the first frame on
                    // the control stream; any other frame before it is
                    // H3_MISSING_SETTINGS.
                    if (!self.peer_settings_received) return error.ConnectionError;

                    self.events.append(self.allocator,.{
                        .goaway = .{ .stream_id = g.stream_id },
                    }) catch return error.BufferTooSmall;
                },
                .cancel_push, .max_push_id, .unknown => {
                    // RFC 9114 §6.2.1: SETTINGS must be the first frame on
                    // the control stream; any other frame that precedes it
                    // is H3_MISSING_SETTINGS. After SETTINGS, unknown /
                    // reserved frame types are allowed (for greasing, per
                    // §7.2.8) and silently ignored; cancel_push and
                    // max_push_id are valid control-stream frames that we
                    // currently do not forward to the server.
                    if (!self.peer_settings_received) return error.ConnectionError;
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
        // RFC 9110 §6.6.1: Origin servers MUST send Date header (except 1xx).
        // Served from the per-Stack cache; refreshed once per Unix
        // epoch second. Pre-PR PERF-3-followup this called
        // formatImfDateHttp3 on every response, costing ~100 cycles
        // per request for modular arithmetic over the Unix timestamp.
        if (status >= 200) {
            const date_str = self.getCachedDate();
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
                // RFC 9110 §6.6.1: Date header (except 1xx).
                // Uses the Stack's per-second cached date — same
                // path the main encodeResponse takes.
                if (self.status >= 200) {
                    const date_str = self.stack.getCachedDate();
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

    /// Return the cached IMF-fixdate string, refreshing once per
    /// Unix epoch second. Used by `encodeResponse` to stamp every
    /// 2xx/3xx/4xx/5xx response with a Date header without paying
    /// the modular-arithmetic cost on every request. Equivalent to
    /// `Server.getCachedDate` in h1/h2 but lives on the Stack so
    /// every QUIC connection carries its own tiny (37-byte) cache.
    pub fn getCachedDate(self: *Stack) []const u8 {
        const ts = clock.realtimeTimespec() orelse return "Thu, 01 Jan 1970 00:00:00 GMT";
        const epoch_secs: u64 = @intCast(ts.sec);
        if (epoch_secs != self.cached_date_epoch) {
            _ = formatImfDateHttp3(&self.cached_date);
            self.cached_date_epoch = epoch_secs;
        }
        return self.cached_date[0..29];
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

test "encode response: lowercases header field names (RFC 9114 §4.2)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [4096]u8 = undefined;

    // Application code returns mixed-case names — encoder must lowercase
    // them before QPACK encoding. Without this, ngtcp2/curl close the
    // connection with INTERNAL_ERROR after parsing the HEADERS frame.
    //
    // Note: well-known names like "content-type" hit the QPACK static
    // table and are encoded as an index, so they don't appear as literal
    // bytes in the output. We use a non-standard "X-Custom-Header" name
    // that goes through the literal-name encoding path so we can grep
    // for the actual ASCII bytes in the encoded HEADERS frame.
    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "X-Custom-Header", .value = "value" },
    };

    const len = try stack.encodeResponse(&buf, 200, &headers, "{}");
    try std.testing.expect(len > 0);

    const encoded = buf[0..len];
    try std.testing.expect(std.mem.indexOf(u8, encoded, "x-custom-header") != null);
    try std.testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, encoded, "X-Custom-Header"));
}

test "encode response: preserves :status pseudo-header literal" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [4096]u8 = undefined;
    const headers = [_]Header{};
    const len = try stack.encodeResponse(&buf, 200, &headers, null);
    try std.testing.expect(len > 0);
    // :status 200 maps to QPACK static table index 25 → encoded as 0xd9
    // (indexed field line, static, T=1, idx=25 fits in 6-bit prefix).
    // We don't assert exact bytes since the encoder may pick different
    // forms — but the response should not contain a literal ":status"
    // string because static-table indexing replaces it.
    const encoded = buf[0..len];
    try std.testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, encoded, ":status"));
}

test "build settings" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [256]u8 = undefined;
    const len = try stack.buildSettings(&buf);
    try std.testing.expect(len > 0);
}

// Build a valid control-stream prologue: [uni_type=0x00] [SETTINGS frame].
// The returned length includes both the 1-byte uni-stream type and the
// full SETTINGS frame encoding.
fn encodeControlStreamPrologue(buf: []u8) !usize {
    buf[0] = 0x00; // UniStreamType.control
    const params = [_]frame.SettingsParam{
        .{ .id = @intFromEnum(frame.SettingsId.qpack_max_table_capacity), .value = 0 },
        .{ .id = @intFromEnum(frame.SettingsId.max_field_section_size), .value = 16384 },
        .{ .id = @intFromEnum(frame.SettingsId.qpack_blocked_streams), .value = 0 },
    };
    const settings_len = try frame.writeSettingsFrame(buf[1..], &params);
    return 1 + settings_len;
}

test "ingest: duplicate peer control stream rejected (RFC 9114 §6.2.1)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [256]u8 = undefined;
    const total = try encodeControlStreamPrologue(&buf);

    // First control stream on client uni stream 2: accepted.
    _ = try stack.ingest(2, buf[0..total], false);
    try std.testing.expectEqual(@as(?u64, 2), stack.peer_control_stream);

    // Second "control stream" on a different uni stream ID must be
    // rejected as H3_STREAM_CREATION_ERROR.
    try std.testing.expectError(error.ConnectionError, stack.ingest(6, buf[0..total], false));
}

test "ingest: duplicate peer QPACK encoder stream rejected (RFC 9204 §4.2)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // QPACK encoder stream: just the type byte with no payload is enough
    // to claim the stream; processQpackEncoderStream returns need_more
    // when data is empty after the type byte.
    const encoder_type = [_]u8{0x02};

    _ = try stack.ingest(6, &encoder_type, false);
    try std.testing.expectEqual(@as(?u64, 6), stack.peer_qpack_encoder);

    try std.testing.expectError(error.ConnectionError, stack.ingest(10, &encoder_type, false));
}

test "ingest: duplicate peer QPACK decoder stream rejected (RFC 9204 §4.2)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    const decoder_type = [_]u8{0x03};

    _ = try stack.ingest(10, &decoder_type, false);
    try std.testing.expectEqual(@as(?u64, 10), stack.peer_qpack_decoder);

    try std.testing.expectError(error.ConnectionError, stack.ingest(14, &decoder_type, false));
}

test "control stream: first frame must be SETTINGS (RFC 9114 §6.2.1)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Build: [type=0x00] [GOAWAY frame] — no SETTINGS first.
    var buf: [64]u8 = undefined;
    buf[0] = 0x00;
    const goaway_len = try frame.writeGoawayFrame(buf[1..], 0);
    const total = 1 + goaway_len;

    try std.testing.expectError(error.ConnectionError, stack.ingest(2, buf[0..total], false));
}

test "control stream: repeated SETTINGS rejected (RFC 9114 §7.2.4)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Build: [type=0x00] [SETTINGS] [SETTINGS] — two SETTINGS frames.
    var buf: [512]u8 = undefined;
    buf[0] = 0x00;
    const params = [_]frame.SettingsParam{
        .{ .id = @intFromEnum(frame.SettingsId.qpack_max_table_capacity), .value = 0 },
    };
    const s1 = try frame.writeSettingsFrame(buf[1..], &params);
    const s2 = try frame.writeSettingsFrame(buf[1 + s1 ..], &params);
    const total = 1 + s1 + s2;

    try std.testing.expectError(error.ConnectionError, stack.ingest(2, buf[0..total], false));
}

test "control stream: DATA frame rejected (RFC 9114 §7.2.1)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Build: [type=0x00] [SETTINGS] [DATA] — DATA is forbidden on control.
    var buf: [512]u8 = undefined;
    const prologue_len = try encodeControlStreamPrologue(&buf);
    const data_len = try frame.writeDataFrame(buf[prologue_len..], "payload");
    const total = prologue_len + data_len;

    try std.testing.expectError(error.ConnectionError, stack.ingest(2, buf[0..total], false));
}

test "control stream: GOAWAY after SETTINGS accepted (RFC 9114 §7.2.6)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Build: [type=0x00] [SETTINGS] [GOAWAY] — valid control-stream sequence.
    var buf: [512]u8 = undefined;
    const prologue_len = try encodeControlStreamPrologue(&buf);
    const goaway_len = try frame.writeGoawayFrame(buf[prologue_len..], 8);
    const total = prologue_len + goaway_len;

    const result = try stack.ingest(2, buf[0..total], false);
    // Expect both a SETTINGS event and a GOAWAY event.
    var saw_settings = false;
    var saw_goaway = false;
    for (result.events) |ev| {
        switch (ev) {
            .settings => saw_settings = true,
            .goaway => |g| {
                saw_goaway = true;
                try std.testing.expectEqual(@as(u64, 8), g.stream_id);
            },
            else => {},
        }
    }
    try std.testing.expect(saw_settings);
    try std.testing.expect(saw_goaway);
}

test "qpack encoder stream: Insert rejected under zero capacity (RFC 9204 §4.3)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Build a valid Insert With Literal Name instruction using an
    // untethered Encoder (the Stack's decoder must reject it).
    var encoder = qpack.Encoder.init(4096);
    var payload: [256]u8 = undefined;
    const enc_len = try encoder.buildInsertLiteral(&payload, "x-custom", "value");

    // Claim the peer QPACK encoder stream (client uni id 6) with
    // the type byte, followed immediately by the Insert instruction.
    var buf: [260]u8 = undefined;
    buf[0] = 0x02; // UniStreamType.qpack_encoder
    @memcpy(buf[1 .. 1 + enc_len], payload[0..enc_len]);
    const total = 1 + enc_len;

    // The Stack advertises qpack_max_table_capacity = 0, so its
    // decoder is initialized with max_allowed_capacity = 0 and
    // processEncoderStream returns error.InvalidEncoding on any
    // Insert — which the Stack translates to error.QpackError.
    try std.testing.expectError(error.QpackError, stack.ingest(6, buf[0..total], false));
}

test "qpack encoder stream: Set Capacity 0 is an accepted no-op" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Build "Set Dynamic Table Capacity 0" — 001xxxxx with 5-bit
    // prefix value 0, which fits in the prefix → single byte 0x20.
    var buf: [4]u8 = undefined;
    buf[0] = 0x02; // UniStreamType.qpack_encoder
    buf[1] = 0x20; // Set Dynamic Table Capacity 0

    // Should succeed (no-op).
    _ = try stack.ingest(6, buf[0..2], false);
    try std.testing.expectEqual(@as(?u64, 6), stack.peer_qpack_encoder);
}

test "qpack encoder stream: Set Capacity > 0 rejected under zero advertised capacity" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    // Build "Set Dynamic Table Capacity 2048" via the Encoder helper.
    var encoder = qpack.Encoder.init(4096);
    var payload: [16]u8 = undefined;
    const enc_len = try encoder.buildSetCapacity(&payload, 2048);

    var buf: [32]u8 = undefined;
    buf[0] = 0x02; // UniStreamType.qpack_encoder
    @memcpy(buf[1 .. 1 + enc_len], payload[0..enc_len]);
    const total = 1 + enc_len;

    try std.testing.expectError(error.QpackError, stack.ingest(6, buf[0..total], false));
}

// Build a minimal h3 HEADERS frame for a request. Writes into `buf`
// and returns the bytes written. Generates static-table only pseudo
// headers so no dynamic table is required.
fn encodeRequestHeadersFrame(
    stack: *Stack,
    buf: []u8,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: []const u8,
) !usize {
    const headers_to_encode = [_]Header{
        .{ .name = ":method", .value = method },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
    };
    var qpack_buf: [1024]u8 = undefined;
    const qpack_len = try stack.qpack_encoder.encode(&qpack_buf, &headers_to_encode);
    return try frame.writeHeadersFrame(buf, qpack_buf[0..qpack_len]);
}

test "request stream: defer-until-FIN — partial ingest emits no events" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [512]u8 = undefined;
    const len = try encodeRequestHeadersFrame(&stack, &buf, "GET", "/", "https", "example.com");

    // end_stream=false should buffer nothing and emit no events.
    const result = try stack.ingest(0, buf[0..len], false);
    try std.testing.expect(result.need_more);
    try std.testing.expectEqual(@as(usize, 0), result.events.len);
}

test "request stream: single-STREAM-frame GET dispatches RequestReadyEvent" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [512]u8 = undefined;
    const len = try encodeRequestHeadersFrame(&stack, &buf, "GET", "/plaintext", "https", "example.com");

    const result = try stack.ingest(0, buf[0..len], true);
    try std.testing.expectEqual(@as(usize, 1), result.events.len);
    const ev = result.events[0];
    try std.testing.expect(ev == .request_ready);
    const req = ev.request_ready;
    try std.testing.expectEqual(@as(u64, 0), req.stream_id);
    try std.testing.expectEqual(@as(usize, 0), req.body.len);

    // Verify pseudo-headers made it through QPACK round-trip.
    var saw_method = false;
    var saw_path = false;
    for (req.headers) |h| {
        if (std.mem.eql(u8, h.name, ":method")) {
            saw_method = true;
            try std.testing.expectEqualStrings("GET", h.value);
        } else if (std.mem.eql(u8, h.name, ":path")) {
            saw_path = true;
            try std.testing.expectEqualStrings("/plaintext", h.value);
        }
    }
    try std.testing.expect(saw_method);
    try std.testing.expect(saw_path);
}

test "request stream: HEADERS + single DATA frame body is zero-copy slice" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [1024]u8 = undefined;
    const hdr_len = try encodeRequestHeadersFrame(&stack, &buf, "POST", "/echo", "https", "example.com");
    const body_payload = "hello world";
    const data_len = try frame.writeDataFrame(buf[hdr_len..], body_payload);
    const total = hdr_len + data_len;

    const result = try stack.ingest(0, buf[0..total], true);
    try std.testing.expectEqual(@as(usize, 1), result.events.len);
    const req = result.events[0].request_ready;
    try std.testing.expectEqualStrings(body_payload, req.body);

    // Zero-copy invariant: body.ptr must point INTO the input `buf`,
    // not into an internal Stack buffer.
    const body_ptr_addr = @intFromPtr(req.body.ptr);
    const buf_start = @intFromPtr(&buf[0]);
    const buf_end = buf_start + buf.len;
    try std.testing.expect(body_ptr_addr >= buf_start and body_ptr_addr < buf_end);
}

test "request stream: multi-DATA-frame body rejected (PR A limitation)" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [1024]u8 = undefined;
    const hdr_len = try encodeRequestHeadersFrame(&stack, &buf, "POST", "/echo", "https", "example.com");
    const data1_len = try frame.writeDataFrame(buf[hdr_len..], "part1");
    const data2_len = try frame.writeDataFrame(buf[hdr_len + data1_len ..], "part2");
    const total = hdr_len + data1_len + data2_len;

    try std.testing.expectError(error.ConnectionError, stack.ingest(0, buf[0..total], true));
}

test "request stream: FIN without HEADERS frame is malformed" {
    const allocator = std.testing.allocator;
    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [64]u8 = undefined;
    const data_len = try frame.writeDataFrame(&buf, "orphan body");
    try std.testing.expectError(error.InvalidFrame, stack.ingest(0, buf[0..data_len], true));
}

test "request stream: zero per-request heap alloc after warmup" {
    // Drive the Stack through many requests using a counting allocator
    // and assert that the steady-state request path doesn't call alloc.
    // The first request is allowed to grow the events ArrayList;
    // subsequent requests must reuse capacity via
    // clearRetainingCapacity (called by the handler between packets
    // in production; we mimic that here).
    var counting = CountingAllocator.init(std.testing.allocator);
    const allocator = counting.allocator();

    var stack = Stack.init(allocator, true);
    defer stack.deinit();

    var buf: [512]u8 = undefined;
    const len = try encodeRequestHeadersFrame(&stack, &buf, "GET", "/plaintext", "https", "example.com");

    // Warmup: first ingest grows events ArrayList. Allowed.
    _ = try stack.ingest(0, buf[0..len], true);
    stack.events.clearRetainingCapacity();
    stack.resetPerPacketScratch();

    const alloc_count_before = counting.alloc_count;

    // Steady state: 1000 requests must not add a single heap alloc.
    // Mimic the handler's per-packet reset: clear events and scratch
    // between requests, just like `Handler.processPacket` does via
    // `clearEvents` in production.
    var stream_id: u64 = 4;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        _ = try stack.ingest(stream_id, buf[0..len], true);
        stack.events.clearRetainingCapacity();
        stack.resetPerPacketScratch();
        stream_id += 4;
    }

    const alloc_count_after = counting.alloc_count;
    try std.testing.expectEqual(alloc_count_before, alloc_count_after);
}

/// Minimal allocator wrapper that counts allocations. Used by the
/// zero-alloc regression test above to lock in the invariant.
const CountingAllocator = struct {
    parent: std.mem.Allocator,
    alloc_count: usize = 0,

    fn init(parent: std.mem.Allocator) CountingAllocator {
        return .{ .parent = parent };
    }

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.alloc_count += 1;
        return self.parent.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.parent.rawResize(buf, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.parent.rawRemap(buf, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(buf, alignment, ret_addr);
    }
};

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
