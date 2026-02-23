const std = @import("std");
const request = @import("request.zig");
const response = @import("../response/response.zig");

pub const Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

pub const ErrorCode = enum {
    none,
    invalid_preface,
    frame_size_error,
    protocol_error,
    compression_error,
    header_list_too_large,
    stream_closed,
    flow_control_error,
    enhance_your_calm,
};

pub const ParseState = enum {
    complete,
    partial,
    err,
};

pub const FrameHeader = struct {
    length: u32,
    typ: FrameType,
    flags: u8,
    stream_id: u32,
};

pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,
};

pub const ParseResult = struct {
    state: ParseState,
    error_code: ErrorCode,
    consumed_bytes: usize,
    frame_count: usize,
};

pub const Limits = struct {
    max_frame_size: u32,
};

pub const Parser = struct {
    preface_remaining: usize,

    pub fn init() Parser {
        return .{ .preface_remaining = Preface.len };
    }

    pub fn parse(self: *Parser, buf: []const u8, frames: []Frame, limits: Limits) ParseResult {
        var offset: usize = 0;
        var out_count: usize = 0;
        if (self.preface_remaining > 0) {
            const want = self.preface_remaining;
            const avail = buf.len;
            const take = if (avail < want) avail else want;
            const preface_start = Preface.len - self.preface_remaining;
            if (!std.mem.eql(u8, buf[0..take], Preface[preface_start .. preface_start + take])) {
                return .{
                    .state = .err,
                    .error_code = .invalid_preface,
                    .consumed_bytes = 0,
                    .frame_count = 0,
                };
            }
            self.preface_remaining -= take;
            offset += take;
            if (self.preface_remaining > 0) {
                return .{
                    .state = .partial,
                    .error_code = .none,
                    .consumed_bytes = 0,
                    .frame_count = 0,
                };
            }
        }

        while (offset < buf.len and out_count < frames.len) {
            if (buf.len - offset < 9) {
                return .{
                    .state = .partial,
                    .error_code = .none,
                    .consumed_bytes = offset,
                    .frame_count = out_count,
                };
            }
            const len = (@as(u32, buf[offset]) << 16) |
                (@as(u32, buf[offset + 1]) << 8) |
                (@as(u32, buf[offset + 2]));
            if (len > limits.max_frame_size) {
                return .{
                    .state = .err,
                    .error_code = .frame_size_error,
                    .consumed_bytes = offset,
                    .frame_count = out_count,
                };
            }
            const type_byte = buf[offset + 3];
            // RFC 7540: Unknown frame types MUST be ignored
            if (type_byte > 0x9) {
                // Skip unknown frame type
                const payload_start = offset + 9;
                const payload_end = payload_start + len;
                if (payload_end > buf.len) {
                    return .{
                        .state = .partial,
                        .error_code = .none,
                        .consumed_bytes = offset,
                        .frame_count = out_count,
                    };
                }
                offset = payload_end;
                continue;
            }
            const typ: FrameType = @enumFromInt(type_byte);
            const flags = buf[offset + 4];
            const raw_stream_id = (@as(u32, buf[offset + 5]) << 24) |
                (@as(u32, buf[offset + 6]) << 16) |
                (@as(u32, buf[offset + 7]) << 8) |
                (@as(u32, buf[offset + 8]));
            // RFC 9113 §4.1: Reserved bit MUST be ignored by receiver
            const stream_id = raw_stream_id & 0x7fff_ffff;
            const payload_start = offset + 9;
            const payload_end = payload_start + len;
            if (payload_end > buf.len) {
                return .{
                    .state = .partial,
                    .error_code = .none,
                    .consumed_bytes = offset,
                    .frame_count = out_count,
                };
            }
            if (!validateFrame(typ, stream_id, flags, buf[payload_start..payload_end])) {
                return .{
                    .state = .err,
                    .error_code = .protocol_error,
                    .consumed_bytes = offset,
                    .frame_count = out_count,
                };
            }
            frames[out_count] = .{
                .header = .{
                    .length = len,
                    .typ = typ,
                    .flags = flags,
                    .stream_id = stream_id,
                },
                .payload = buf[payload_start..payload_end],
            };
            out_count += 1;
            offset = payload_end;
        }

        return .{
            .state = if (offset == buf.len) .complete else .partial,
            .error_code = .none,
            .consumed_bytes = offset,
            .frame_count = out_count,
        };
    }
};

pub const Event = union(enum) {
    headers: HeadersEvent,
    data: DataEvent,
    err: ErrorEvent,
    settings: SettingsEvent,
    ping: PingEvent,
    window_update_needed: WindowUpdateEvent,
};

pub const HeadersEvent = struct {
    stream_id: u32,
    request: request.RequestView,
    end_stream: bool,
};

pub const DataEvent = struct {
    stream_id: u32,
    data: []const u8,
    end_stream: bool,
};

pub const ErrorEvent = struct {
    stream_id: u32,
    code: ErrorCode,
};

pub const SettingsEvent = struct {
    ack: bool,
};

pub const PingEvent = struct {
    /// Opaque data from the PING frame (8 bytes) — must be echoed in ACK
    opaque_data: [8]u8,
};

pub const WindowUpdateEvent = struct {
    /// Stream ID (0 = connection level)
    stream_id: u32,
    /// Window increment to send
    increment: u32,
};

pub const IngestResult = struct {
    state: ParseState,
    error_code: ErrorCode,
    consumed_bytes: usize,
    event_count: usize,
};

const MaxHeaders = 64;
const HeaderScratchBytes = 4096;
const HeaderBlockBytes = 8192;
const MaxDynamicEntries = 64;
const MaxDynamicBytes = 4096;
/// Default values used when no config is provided.
/// These can be overridden via StackConfig / ServerConfig.http2.
pub const DefaultMaxStreams: usize = 128;
pub const DefaultMaxHeaderListSize: usize = 8192;
pub const DefaultInitialWindow: u32 = 65535;
pub const DefaultMaxFrameSize: u32 = 16384;
pub const DefaultMaxDynamicTableSize: usize = 4096;

/// Configuration for the HTTP/2 stack, mapping from ServerConfig.Http2Config.
pub const StackConfig = struct {
    max_streams: usize = DefaultMaxStreams,
    max_header_list_size: usize = DefaultMaxHeaderListSize,
    initial_window_size: u32 = DefaultInitialWindow,
    max_frame_size: u32 = DefaultMaxFrameSize,
    max_dynamic_table_size: usize = DefaultMaxDynamicTableSize,
};

// Internal alias so existing code using MaxStreams still works
const MaxStreams = DefaultMaxStreams;

const StreamState = enum {
    idle,
    open,
    half_closed_remote,
    closed,
};

const Stream = struct {
    id: u32,
    state: StreamState,
    recv_window: i32,
    header_block_len: usize,
    header_block_in_progress: bool,
    /// END_STREAM flag from HEADERS, deferred until header block completes via CONTINUATION
    end_stream_pending: bool,
    saw_headers: bool,
    saw_data: bool,

    fn reset(self: *Stream, id: u32, initial_window: i32) void {
        self.id = id;
        self.state = .idle;
        self.recv_window = initial_window;
        self.header_block_len = 0;
        self.header_block_in_progress = false;
        self.end_stream_pending = false;
        self.saw_headers = false;
        self.saw_data = false;
    }
};

const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

const DynamicEntry = struct {
    base: usize,
    name_len: usize,
    value_len: usize,
    size: usize,
};

pub const HpackDecoder = struct {
    entries: [MaxDynamicEntries]DynamicEntry,
    entry_head: usize,
    entry_count: usize,
    dynamic_size: usize,
    max_dynamic_size: usize,
    storage: [MaxDynamicBytes]u8,
    storage_head: usize,
    storage_tail: usize,
    storage_used: usize,
    scratch: [HeaderScratchBytes]u8,
    scratch_used: usize,

    pub fn init() HpackDecoder {
        return .{
            .entries = undefined,
            .entry_head = 0,
            .entry_count = 0,
            .dynamic_size = 0,
            .max_dynamic_size = MaxDynamicBytes,
            .storage = undefined,
            .storage_head = 0,
            .storage_tail = 0,
            .storage_used = 0,
            .scratch = undefined,
            .scratch_used = 0,
        };
    }

    fn resetScratch(self: *HpackDecoder) void {
        self.scratch_used = 0;
    }

    fn setMaxSize(self: *HpackDecoder, size: usize) void {
        self.max_dynamic_size = size;
        while (self.dynamic_size > self.max_dynamic_size) {
            self.evictOldest();
        }
    }

    pub fn decodeRequestBlock(self: *HpackDecoder, block: []const u8, out_headers: []request.Header, max_header_list_size: usize) !HeaderBlockResult {
        return self.decodeRequestBlockInternal(block, out_headers, max_header_list_size);
    }

    pub fn decodeResponseBlock(self: *HpackDecoder, block: []const u8, out_headers: []request.Header, max_header_list_size: usize) !ResponseBlockResult {
        return self.decodeResponseBlockInternal(block, out_headers, max_header_list_size);
    }

    fn decodeRequestBlockInternal(self: *HpackDecoder, block: []const u8, out_headers: []request.Header, max_header_list_size: usize) !HeaderBlockResult {
        self.resetScratch();
        var idx: usize = 0;
        var out_count: usize = 0;
        var total_size: usize = 0;
        var saw_regular = false;
        var method: []const u8 = "";
        var path: []const u8 = "";
        var authority: []const u8 = "";
        var scheme: []const u8 = "";

        while (idx < block.len) {
            const b = block[idx];
            if ((b & 0x80) != 0) {
                const index = try decodeInt(block, &idx, 7);
                const field = self.lookup(index) orelse return error.InvalidIndex;
                try appendHeader(.request, field.name, field.value, out_headers, &out_count, &total_size, max_header_list_size, &saw_regular, &method, &path, &authority, null, &scheme);
                continue;
            }
            if ((b & 0x40) != 0) {
                const name_index = try decodeInt(block, &idx, 6);
                const name = if (name_index == 0) try decodeString(self, block, &idx) else (self.lookup(name_index) orelse return error.InvalidIndex).name;
                const value = try decodeString(self, block, &idx);
                try appendHeader(.request, name, value, out_headers, &out_count, &total_size, max_header_list_size, &saw_regular, &method, &path, &authority, null, &scheme);
                self.addEntry(name, value);
                continue;
            }
            if ((b & 0x20) != 0) {
                const new_size = try decodeInt(block, &idx, 5);
                self.setMaxSize(new_size);
                continue;
            }
            const never_indexed = (b & 0x10) != 0;
            _ = never_indexed;
            const name_index = try decodeInt(block, &idx, 4);
            const name = if (name_index == 0) try decodeString(self, block, &idx) else (self.lookup(name_index) orelse return error.InvalidIndex).name;
            const value = try decodeString(self, block, &idx);
            try appendHeader(.request, name, value, out_headers, &out_count, &total_size, max_header_list_size, &saw_regular, &method, &path, &authority, null, &scheme);
        }

        if (method.len == 0) return error.MissingPseudo;
        const method_enum = request.Method.fromStringExtended(method) orelse return error.InvalidMethod;
        if (method_enum == .CONNECT) {
            if (authority.len == 0) return error.MissingPseudo;
            if (path.len == 0) path = authority;
        } else {
            // RFC 9113 §8.3.1: :scheme and :path MUST be present for non-CONNECT
            if (scheme.len == 0) return error.MissingPseudo;
            if (path.len == 0) return error.MissingPseudo;
        }

        return .{
            .headers = out_headers[0..out_count],
            .method = method_enum,
            .path = path,
            .authority = authority,
        };
    }

    fn decodeResponseBlockInternal(self: *HpackDecoder, block: []const u8, out_headers: []request.Header, max_header_list_size: usize) !ResponseBlockResult {
        self.resetScratch();
        var idx: usize = 0;
        var out_count: usize = 0;
        var total_size: usize = 0;
        var saw_regular = false;
        var status: []const u8 = "";

        while (idx < block.len) {
            const b = block[idx];
            if ((b & 0x80) != 0) {
                const index = try decodeInt(block, &idx, 7);
                const field = self.lookup(index) orelse return error.InvalidIndex;
                try appendHeader(.response, field.name, field.value, out_headers, &out_count, &total_size, max_header_list_size, &saw_regular, null, null, null, &status, null);
                continue;
            }
            if ((b & 0x40) != 0) {
                const name_index = try decodeInt(block, &idx, 6);
                const name = if (name_index == 0) try decodeString(self, block, &idx) else (self.lookup(name_index) orelse return error.InvalidIndex).name;
                const value = try decodeString(self, block, &idx);
                try appendHeader(.response, name, value, out_headers, &out_count, &total_size, max_header_list_size, &saw_regular, null, null, null, &status, null);
                self.addEntry(name, value);
                continue;
            }
            if ((b & 0x20) != 0) {
                const new_size = try decodeInt(block, &idx, 5);
                self.setMaxSize(new_size);
                continue;
            }
            const name_index = try decodeInt(block, &idx, 4);
            const name = if (name_index == 0) try decodeString(self, block, &idx) else (self.lookup(name_index) orelse return error.InvalidIndex).name;
            const value = try decodeString(self, block, &idx);
            try appendHeader(.response, name, value, out_headers, &out_count, &total_size, max_header_list_size, &saw_regular, null, null, null, &status, null);
        }

        if (status.len == 0) return error.MissingPseudo;
        return .{
            .headers = out_headers[0..out_count],
            .status = status,
        };
    }

    fn addEntry(self: *HpackDecoder, name: []const u8, value: []const u8) void {
        const size = 32 + name.len + value.len;
        if (size > self.max_dynamic_size) {
            self.clear();
            return;
        }
        while (self.dynamic_size + size > self.max_dynamic_size) {
            self.evictOldest();
        }
        const storage_len = name.len + value.len;
        if (storage_len > self.storage.len) {
            self.clear();
            return;
        }
        self.ensureStorage(storage_len);
        const base = self.storage_tail;
        // Defensive bounds check: ensure we have contiguous space
        if (base + storage_len > self.storage.len) {
            // Not enough contiguous space at end - this shouldn't happen if
            // ensureStorage worked correctly, but handle it defensively
            self.clear();
            return;
        }
        @memcpy(self.storage[base .. base + name.len], name);
        @memcpy(self.storage[base + name.len .. base + storage_len], value);
        self.storage_tail = (self.storage_tail + storage_len) % self.storage.len;
        self.storage_used += storage_len;

        const insert_index = (self.entry_head + self.entry_count) % self.entries.len;
        self.entries[insert_index] = .{
            .base = base,
            .name_len = name.len,
            .value_len = value.len,
            .size = size,
        };
        if (self.entry_count < self.entries.len) {
            self.entry_count += 1;
        } else {
            self.entry_head = (self.entry_head + 1) % self.entries.len;
        }
        self.dynamic_size += size;
    }

    fn ensureStorage(self: *HpackDecoder, needed: usize) void {
        // If the entry is larger than total storage, evict everything and bail out.
        // The caller must handle the case where storage is still insufficient.
        if (needed > self.storage.len) {
            while (self.entry_count > 0) self.evictOldest();
            self.storage_head = 0;
            self.storage_tail = 0;
            return;
        }
        while (self.storage.len - self.storage_used < needed) {
            if (self.entry_count == 0) break;
            self.evictOldest();
        }
        if (self.storage_used == 0) {
            self.storage_head = 0;
            self.storage_tail = 0;
        }
        if (self.storage_tail >= self.storage_head) {
            const end_space = self.storage.len - self.storage_tail;
            if (needed <= end_space) return;
            if (needed <= self.storage_head) {
                self.storage_tail = 0;
                return;
            }
        } else {
            if (needed <= self.storage_head - self.storage_tail) return;
        }
        while (self.entry_count > 0) {
            self.evictOldest();
            if (self.storage_used == 0) {
                self.storage_head = 0;
                self.storage_tail = 0;
            }
            if (self.storage_tail >= self.storage_head) {
                const end_space = self.storage.len - self.storage_tail;
                if (needed <= end_space) return;
                if (needed <= self.storage_head) {
                    self.storage_tail = 0;
                    return;
                }
            } else {
                if (needed <= self.storage_head - self.storage_tail) return;
            }
        }
    }

    fn evictOldest(self: *HpackDecoder) void {
        if (self.entry_count == 0) return;
        const entry = self.entries[self.entry_head];
        self.entry_head = (self.entry_head + 1) % self.entries.len;
        self.entry_count -= 1;
        self.dynamic_size -= entry.size;
        if (self.storage_used >= entry.name_len + entry.value_len) {
            self.storage_used -= entry.name_len + entry.value_len;
            self.storage_head = (self.storage_head + entry.name_len + entry.value_len) % self.storage.len;
        } else {
            self.storage_used = 0;
            self.storage_head = self.storage_tail;
        }
    }

    fn clear(self: *HpackDecoder) void {
        self.entry_head = 0;
        self.entry_count = 0;
        self.dynamic_size = 0;
        self.storage_head = 0;
        self.storage_tail = 0;
        self.storage_used = 0;
    }

    fn lookup(self: *HpackDecoder, index: usize) ?HeaderField {
        if (index == 0) return null;
        if (index <= StaticTable.len) {
            return StaticTable[index - 1];
        }
        const dynamic_index = index - StaticTable.len;
        if (dynamic_index == 0 or dynamic_index > self.entry_count) return null;
        const pos = (self.entry_head + self.entry_count - dynamic_index) % self.entries.len;
        const entry = self.entries[pos];
        const name = self.storage[entry.base .. entry.base + entry.name_len];
        const value = self.storage[entry.base + entry.name_len .. entry.base + entry.name_len + entry.value_len];
        return .{ .name = name, .value = value };
    }

    fn decodeString(self: *HpackDecoder, buf: []const u8, idx: *usize) ![]const u8 {
        if (idx.* >= buf.len) return error.Truncated;
        const first = buf[idx.*];
        const huffman = (first & 0x80) != 0;
        const len = try decodeInt(buf, idx, 7);
        if (idx.* + len > buf.len) return error.Truncated;
        if (huffman) {
            const decoded = try decodeHuffman(self, buf[idx.* .. idx.* + len]);
            idx.* += len;
            return decoded;
        }
        if (self.scratch_used + len > self.scratch.len) return error.HeaderListTooLarge;
        const start = self.scratch_used;
        @memcpy(self.scratch[start .. start + len], buf[idx.* .. idx.* + len]);
        self.scratch_used += len;
        idx.* += len;
        return self.scratch[start .. start + len];
    }
};

const HuffmanNode = struct {
    left: i16,
    right: i16,
    symbol: i16,
};

const MaxHuffmanNodes = 1024;
const HuffmanEosSymbol: usize = 256;

fn decodeHuffman(decoder: *HpackDecoder, input: []const u8) ![]const u8 {
    var nodes: [MaxHuffmanNodes]HuffmanNode = undefined;
    const root = buildHuffmanTree(&nodes);
    var node: usize = root;
    var pending_bits: u32 = 0;
    var pending_len: u8 = 0;
    const start = decoder.scratch_used;
    var out_len: usize = 0;

    for (input) |byte| {
        var bit_index: u4 = 0;
        while (bit_index < 8) : (bit_index += 1) {
            const shift: u3 = @intCast(7 - bit_index);
            const bit = (byte >> shift) & 1;
            pending_bits = (pending_bits << 1) | bit;
            if (pending_len < 32) {
                pending_len += 1;
            } else {
                return error.InvalidHuffman;
            }
            const next = if (bit == 0) nodes[node].left else nodes[node].right;
            if (next < 0) return error.InvalidHuffman;
            node = @intCast(next);
            if (nodes[node].symbol >= 0) {
                const symbol: usize = @intCast(nodes[node].symbol);
                if (symbol == HuffmanEosSymbol) return error.InvalidHuffman;
                if (decoder.scratch_used + out_len + 1 > decoder.scratch.len) return error.HeaderListTooLarge;
                decoder.scratch[start + out_len] = @intCast(symbol);
                out_len += 1;
                node = root;
                pending_bits = 0;
                pending_len = 0;
            }
        }
    }

    if (pending_len > 0) {
        const eos_len: u8 = HuffmanCodeLengths[HuffmanEosSymbol];
        const eos_code: u32 = HuffmanCodes[HuffmanEosSymbol] >> @as(u5, @intCast(32 - eos_len));
        if (pending_len > eos_len) return error.InvalidHuffman;
        const prefix = eos_code >> @as(u5, @intCast(eos_len - pending_len));
        if (pending_bits != prefix) return error.InvalidHuffman;
    }

    decoder.scratch_used += out_len;
    return decoder.scratch[start .. start + out_len];
}

fn buildHuffmanTree(nodes: *[MaxHuffmanNodes]HuffmanNode) usize {
    nodes[0] = .{ .left = -1, .right = -1, .symbol = -1 };
    var next_index: usize = 1;
    for (HuffmanCodes, 0..) |code, sym| {
        const len: u8 = HuffmanCodeLengths[sym];
        const value = code >> @as(u5, @intCast(32 - len));
        var node_index: usize = 0;
        var bit_index: i32 = @as(i32, @intCast(len)) - 1;
        while (bit_index >= 0) : (bit_index -= 1) {
            const bit = (value >> @as(u5, @intCast(bit_index))) & 1;
            const next_ptr = if (bit == 0) &nodes[node_index].left else &nodes[node_index].right;
            if (bit_index == 0) {
                if (next_index >= nodes.len) return 0;
                const new_index = next_index;
                next_index += 1;
                nodes[new_index] = .{ .left = -1, .right = -1, .symbol = @intCast(sym) };
                next_ptr.* = @intCast(new_index);
            } else {
                if (next_ptr.* < 0) {
                    if (next_index >= nodes.len) return 0;
                    const new_index = next_index;
                    next_index += 1;
                    nodes[new_index] = .{ .left = -1, .right = -1, .symbol = -1 };
                    next_ptr.* = @intCast(new_index);
                }
                node_index = @intCast(next_ptr.*);
            }
        }
    }
    return 0;
}

const HeaderBlockResult = struct {
    headers: []request.Header,
    method: request.Method,
    path: []const u8,
    authority: []const u8,
};

const ResponseBlockResult = struct {
    headers: []request.Header,
    status: []const u8,
};

pub const Stack = struct {
    parser: Parser,
    decoder: HpackDecoder,
    streams: [MaxStreams]Stream,
    stream_count: usize,
    last_stream_id: u32,
    conn_recv_window: i32,
    initial_stream_window: i32,
    max_frame_size: u32,
    max_header_list_size: usize,
    header_block: [HeaderBlockBytes]u8,
    headers_storage: [MaxHeaders]request.Header,
    goaway_received: bool,
    goaway_last_stream_id: u32,
    // Cache for last accessed stream to optimize repeated lookups
    cached_stream_id: u32,
    cached_stream_index: usize,
    /// Counter for SETTINGS frames received on this connection (DoS protection)
    settings_frame_count: u32,
    /// Stream ID expecting CONTINUATION frames (RFC 7540 Section 6.2).
    /// When set, only CONTINUATION frames for this stream are allowed.
    expecting_continuation: u32,

    pub fn init() Stack {
        return initWithConfig(.{});
    }

    pub fn initWithConfig(cfg: StackConfig) Stack {
        const initial_window: i32 = @intCast(@min(cfg.initial_window_size, 0x7FFFFFFF));
        var stack = Stack{
            .parser = Parser.init(),
            .decoder = HpackDecoder.init(),
            .streams = undefined,
            .stream_count = 0,
            .last_stream_id = 0,
            .conn_recv_window = initial_window,
            .initial_stream_window = initial_window,
            .max_frame_size = cfg.max_frame_size,
            .max_header_list_size = cfg.max_header_list_size,
            .header_block = undefined,
            .headers_storage = undefined,
            .goaway_received = false,
            .goaway_last_stream_id = 0,
            .cached_stream_id = 0,
            .cached_stream_index = 0,
            .settings_frame_count = 0,
            .expecting_continuation = 0,
        };
        for (&stack.streams, 0..) |*stream, i| {
            stream.reset(@intCast(i), initial_window);
            stream.state = .closed;
        }
        return stack;
    }

    pub fn ingest(self: *Stack, buf: []const u8, frames: []Frame, events: []Event) IngestResult {
        const parsed = self.parser.parse(buf, frames, .{ .max_frame_size = self.max_frame_size });
        if (parsed.state == .err) {
            return .{
                .state = .err,
                .error_code = parsed.error_code,
                .consumed_bytes = parsed.consumed_bytes,
                .event_count = 0,
            };
        }
        var event_count: usize = 0;
        var total_frame_bytes: usize = 0;
        for (frames[0..parsed.frame_count]) |frame| {
            total_frame_bytes += 9 + frame.header.length;
        }
        const base = parsed.consumed_bytes - total_frame_bytes;
        var consumed: usize = base;
        for (frames[0..parsed.frame_count]) |frame| {
            if (event_count >= events.len) break;
            const handle = self.handleFrame(frame, events[event_count..]);
            switch (handle.state) {
                .complete => {
                    consumed = frameConsumed(consumed, frame);
                    event_count += handle.event_count;
                },
                .partial => {
                    break;
                },
                .err => {
                    return .{
                        .state = .err,
                        .error_code = handle.error_code,
                        .consumed_bytes = consumed,
                        .event_count = event_count,
                    };
                },
            }
        }
        return .{
            .state = if (consumed == parsed.consumed_bytes) parsed.state else .partial,
            .error_code = .none,
            .consumed_bytes = consumed,
            .event_count = event_count,
        };
    }

    fn handleFrame(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        // RFC 9113 §5.4.2: After receiving GOAWAY, ignore frames on streams > last-stream-id
        if (self.goaway_received and frame.header.stream_id > self.goaway_last_stream_id and frame.header.stream_id != 0) {
            return .{ .state = .complete, .error_code = .none, .event_count = 0 };
        }
        // RFC 7540 Section 6.2: When a header block is in progress (HEADERS without
        // END_HEADERS), only CONTINUATION frames for that stream are allowed.
        if (self.expecting_continuation != 0) {
            if (frame.header.typ != .continuation or frame.header.stream_id != self.expecting_continuation) {
                return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
            }
        }
        return switch (frame.header.typ) {
            .settings => self.handleSettings(frame, events),
            .headers => self.handleHeaders(frame, events),
            .continuation => self.handleContinuation(frame, events),
            .data => self.handleData(frame, events),
            .window_update => self.handleWindowUpdate(frame, events),
            .rst_stream => self.handleRstStream(frame, events),
            .ping => self.handlePing(frame, events),
            .goaway => self.handleGoaway(frame, events),
            .priority => self.handlePriority(frame, events),
            // RFC 9113 §6.6: A server MUST NOT send PUSH_PROMISE; receiving one is a PROTOCOL_ERROR
            .push_promise => .{ .state = .err, .error_code = .protocol_error, .event_count = 0 },
        };
    }

    /// Maximum SETTINGS frames allowed per connection before triggering ENHANCE_YOUR_CALM
    const max_settings_frames: u32 = 100;

    fn handleSettings(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        // Rate-limit SETTINGS frames to prevent DoS via SETTINGS flood
        self.settings_frame_count += 1;
        if (self.settings_frame_count > max_settings_frames) {
            return .{ .state = .err, .error_code = .enhance_your_calm, .event_count = 0 };
        }
        const ack = (frame.header.flags & 0x1) != 0;
        if (ack and frame.payload.len != 0) {
            return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        }
        if (!ack and frame.payload.len % 6 != 0) {
            return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        }
        var idx: usize = 0;
        while (idx + 6 <= frame.payload.len) {
            const id = (@as(u16, frame.payload[idx]) << 8) | @as(u16, frame.payload[idx + 1]);
            const value = (@as(u32, frame.payload[idx + 2]) << 24) |
                (@as(u32, frame.payload[idx + 3]) << 16) |
                (@as(u32, frame.payload[idx + 4]) << 8) |
                (@as(u32, frame.payload[idx + 5]));
            self.applySetting(id, value) catch {
                return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
            };
            idx += 6;
        }
        if (events.len == 0) return .{ .state = .complete, .error_code = .none, .event_count = 0 };
        events[0] = .{ .settings = .{ .ack = ack } };
        return .{ .state = .complete, .error_code = .none, .event_count = 1 };
    }

    fn handleHeaders(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        if (frame.header.stream_id == 0) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        // RFC 7540 Section 5.3.1: validate priority self-dependency if PRIORITY flag set
        if ((frame.header.flags & 0x20) != 0) {
            const prio_offset: usize = if ((frame.header.flags & 0x8) != 0) 1 else 0; // skip pad length byte
            if (frame.payload.len >= prio_offset + 4) {
                const dep_raw = (@as(u32, frame.payload[prio_offset]) << 24) |
                    (@as(u32, frame.payload[prio_offset + 1]) << 16) |
                    (@as(u32, frame.payload[prio_offset + 2]) << 8) |
                    @as(u32, frame.payload[prio_offset + 3]);
                const stream_dependency = dep_raw & 0x7FFF_FFFF;
                if (stream_dependency == frame.header.stream_id) {
                    return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
                }
            }
        }
        const stream = self.getOrCreateStream(frame.header.stream_id) orelse return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        if (stream.state == .closed or stream.state == .half_closed_remote) {
            return .{ .state = .err, .error_code = .stream_closed, .event_count = 0 };
        }
        const header_block = parseHeadersPayload(frame.payload, frame.header.flags) catch {
            return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        };
        if (stream.header_block_len + header_block.len > self.header_block.len) {
            return .{ .state = .err, .error_code = .header_list_too_large, .event_count = 0 };
        }
        @memcpy(self.header_block[stream.header_block_len .. stream.header_block_len + header_block.len], header_block);
        stream.header_block_len += header_block.len;
        stream.header_block_in_progress = (frame.header.flags & 0x4) == 0;
        // Track connection-level CONTINUATION expectation (RFC 7540 Section 6.2)
        self.expecting_continuation = if (stream.header_block_in_progress) frame.header.stream_id else 0;
        const end_stream = (frame.header.flags & 0x1) != 0;
        // Persist END_STREAM for deferred use when CONTINUATION completes the header block
        stream.end_stream_pending = end_stream;
        if (!stream.header_block_in_progress) {
            const decoded = self.decodeHeaders(stream) catch |err| return mapHeaderError(err);
            if (events.len == 0) return .{ .state = .complete, .error_code = .none, .event_count = 0 };
            events[0] = .{ .headers = .{
                .stream_id = frame.header.stream_id,
                .request = .{
                    .method = decoded.method,
                    .path = decoded.path,
                    .headers = decoded.headers,
                    .body = "",
                },
                .end_stream = end_stream,
            } };
            if (end_stream) stream.state = .half_closed_remote else stream.state = .open;
            return .{ .state = .complete, .error_code = .none, .event_count = 1 };
        }
        if (stream.state == .idle) stream.state = .open;
        return .{ .state = .complete, .error_code = .none, .event_count = 0 };
    }

    fn handleContinuation(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        if (frame.header.stream_id == 0) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        const stream = self.findStream(frame.header.stream_id) orelse return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        if (!stream.header_block_in_progress) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        if (stream.header_block_len + frame.payload.len > self.header_block.len) {
            return .{ .state = .err, .error_code = .header_list_too_large, .event_count = 0 };
        }
        @memcpy(self.header_block[stream.header_block_len .. stream.header_block_len + frame.payload.len], frame.payload);
        stream.header_block_len += frame.payload.len;
        stream.header_block_in_progress = (frame.header.flags & 0x4) == 0;
        // Clear connection-level CONTINUATION expectation when header block completes
        self.expecting_continuation = if (stream.header_block_in_progress) frame.header.stream_id else 0;
        if (!stream.header_block_in_progress) {
            const decoded = self.decodeHeaders(stream) catch |err| return mapHeaderError(err);
            if (events.len == 0) return .{ .state = .complete, .error_code = .none, .event_count = 0 };
            events[0] = .{ .headers = .{
                .stream_id = frame.header.stream_id,
                .request = .{
                    .method = decoded.method,
                    .path = decoded.path,
                    .headers = decoded.headers,
                    .body = "",
                },
                .end_stream = stream.end_stream_pending,
            } };
            if (stream.end_stream_pending) stream.state = .half_closed_remote;
            stream.end_stream_pending = false;
            return .{ .state = .complete, .error_code = .none, .event_count = 1 };
        }
        return .{ .state = .complete, .error_code = .none, .event_count = 0 };
    }

    fn handleData(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        if (frame.header.stream_id == 0) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        const stream = self.findStream(frame.header.stream_id) orelse return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        if (stream.state == .half_closed_remote or stream.state == .closed) {
            return .{ .state = .err, .error_code = .stream_closed, .event_count = 0 };
        }
        const data = parseDataPayload(frame.payload, frame.header.flags) catch {
            return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        };
        // Validate flow control windows before cast — reject if window is non-positive
        // or if data exceeds remaining window capacity
        if (self.conn_recv_window <= 0) {
            return .{ .state = .err, .error_code = .flow_control_error, .event_count = 0 };
        }
        const conn_window: usize = @intCast(self.conn_recv_window);
        if (data.len > conn_window) {
            return .{ .state = .err, .error_code = .flow_control_error, .event_count = 0 };
        }
        if (stream.recv_window <= 0) {
            return .{ .state = .err, .error_code = .flow_control_error, .event_count = 0 };
        }
        const stream_window: usize = @intCast(stream.recv_window);
        if (data.len > stream_window) {
            return .{ .state = .err, .error_code = .flow_control_error, .event_count = 0 };
        }
        self.conn_recv_window -= @intCast(data.len);
        stream.recv_window -= @intCast(data.len);
        const end_stream = (frame.header.flags & 0x1) != 0;
        stream.saw_data = true;
        if (end_stream) stream.state = .half_closed_remote else stream.state = .open;
        if (events.len == 0) return .{ .state = .complete, .error_code = .none, .event_count = 0 };
        var event_count: usize = 0;
        events[event_count] = .{ .data = .{
            .stream_id = frame.header.stream_id,
            .data = data,
            .end_stream = end_stream,
        } };
        event_count += 1;
        // RFC 9113 §5.2.1: Send WINDOW_UPDATE when half the initial window is consumed
        const half_window = @divTrunc(self.initial_stream_window, 2);
        if (self.conn_recv_window < half_window and event_count < events.len) {
            const increment: u32 = @intCast(self.initial_stream_window - self.conn_recv_window);
            self.conn_recv_window = self.initial_stream_window;
            events[event_count] = .{ .window_update_needed = .{
                .stream_id = 0,
                .increment = increment,
            } };
            event_count += 1;
        }
        if (!end_stream and stream.recv_window < half_window and event_count < events.len) {
            const s_increment: u32 = @intCast(self.initial_stream_window - stream.recv_window);
            stream.recv_window = self.initial_stream_window;
            events[event_count] = .{ .window_update_needed = .{
                .stream_id = frame.header.stream_id,
                .increment = s_increment,
            } };
            event_count += 1;
        }
        return .{ .state = .complete, .error_code = .none, .event_count = event_count };
    }

    fn handleWindowUpdate(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        _ = events;
        if (frame.payload.len != 4) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        const increment = parseWindowIncrement(frame.payload) orelse return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        const max_window: i32 = 0x7FFF_FFFF; // 2^31-1 per RFC 7540
        if (frame.header.stream_id == 0) {
            // RFC 7540 Section 6.9.1: window must not exceed 2^31-1
            const new_window = @as(i64, self.conn_recv_window) + @as(i64, increment);
            if (new_window > max_window) {
                return .{ .state = .err, .error_code = .flow_control_error, .event_count = 0 };
            }
            self.conn_recv_window = @intCast(new_window);
            return .{ .state = .complete, .error_code = .none, .event_count = 0 };
        }
        const stream = self.findStream(frame.header.stream_id) orelse return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        // RFC 7540 Section 6.9.1: window must not exceed 2^31-1
        const new_stream_window = @as(i64, stream.recv_window) + @as(i64, increment);
        if (new_stream_window > max_window) {
            return .{ .state = .err, .error_code = .flow_control_error, .event_count = 0 };
        }
        stream.recv_window = @intCast(new_stream_window);
        return .{ .state = .complete, .error_code = .none, .event_count = 0 };
    }

    fn handleRstStream(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        _ = events;
        if (frame.payload.len != 4) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        const stream = self.findStream(frame.header.stream_id) orelse return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        stream.state = .closed;
        return .{ .state = .complete, .error_code = .none, .event_count = 0 };
    }

    fn handlePing(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        _ = self;
        if (frame.payload.len != 8) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        if (frame.header.stream_id != 0) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        const ack = (frame.header.flags & 0x1) != 0;
        if (ack) {
            // PING ACK received — no response needed
            return .{ .state = .complete, .error_code = .none, .event_count = 0 };
        }
        // RFC 9113 §6.7: MUST send PING ACK with identical opaque data
        if (events.len == 0) return .{ .state = .complete, .error_code = .none, .event_count = 0 };
        var opaque_data: [8]u8 = undefined;
        @memcpy(&opaque_data, frame.payload[0..8]);
        events[0] = .{ .ping = .{ .opaque_data = opaque_data } };
        return .{ .state = .complete, .error_code = .none, .event_count = 1 };
    }

    fn handlePriority(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        _ = self;
        _ = events;
        // RFC 7540 Section 6.3: PRIORITY frame is exactly 5 bytes
        if (frame.payload.len != 5) return .{ .state = .err, .error_code = .frame_size_error, .event_count = 0 };
        // PRIORITY must be on a non-zero stream
        if (frame.header.stream_id == 0) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        // Parse priority fields (we acknowledge but don't implement scheduling)
        // Exclusive flag (1 bit) + Stream Dependency (31 bits) + Weight (8 bits)
        const dependency_raw = (@as(u32, frame.payload[0]) << 24) |
            (@as(u32, frame.payload[1]) << 16) |
            (@as(u32, frame.payload[2]) << 8) |
            @as(u32, frame.payload[3]);
        const stream_dependency = dependency_raw & 0x7FFF_FFFF;
        // Validate: stream cannot depend on itself
        if (stream_dependency == frame.header.stream_id) {
            return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        }
        // Priority acknowledged - no scheduling implemented yet
        return .{ .state = .complete, .error_code = .none, .event_count = 0 };
    }

    fn handleGoaway(self: *Stack, frame: Frame, events: []Event) FrameHandle {
        _ = events;
        // GOAWAY must be on stream 0 and have at least 8 bytes (last-stream-id + error-code)
        if (frame.header.stream_id != 0) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        if (frame.payload.len < 8) return .{ .state = .err, .error_code = .protocol_error, .event_count = 0 };
        // Parse last-stream-id (first 4 bytes, ignoring reserved bit)
        const last_stream_id = ((@as(u32, frame.payload[0]) & 0x7F) << 24) |
            (@as(u32, frame.payload[1]) << 16) |
            (@as(u32, frame.payload[2]) << 8) |
            @as(u32, frame.payload[3]);
        // Mark that we received GOAWAY - no new streams should be created
        self.goaway_received = true;
        self.goaway_last_stream_id = last_stream_id;
        // Return complete - the connection should be gracefully closed
        // but we let existing streams finish
        return .{ .state = .complete, .error_code = .none, .event_count = 0 };
    }

    fn applySetting(self: *Stack, id: u16, value: u32) !void {
        switch (id) {
            // SETTINGS_HEADER_TABLE_SIZE (0x1)
            0x1 => self.decoder.setMaxSize(value),
            // SETTINGS_ENABLE_PUSH (0x2) - must be 0 or 1
            0x2 => {
                if (value > 1) return error.InvalidSetting;
            },
            // SETTINGS_MAX_CONCURRENT_STREAMS (0x3) - any value is valid
            0x3 => {},
            // SETTINGS_INITIAL_WINDOW_SIZE (0x4) - must be <= 2^31-1
            0x4 => {
                if (value > 0x7fff_ffff) return error.InvalidSetting;
                const new_window: i32 = @intCast(value);
                const delta: i64 = @as(i64, new_window) - @as(i64, self.initial_stream_window);
                // RFC 9113 §6.5.2: Adjust existing stream windows by the delta
                for (self.streams[0..self.stream_count]) |*stream| {
                    if (stream.state == .closed) continue;
                    const adjusted = @as(i64, stream.recv_window) + delta;
                    // RFC 9113 §6.5.2: flow-control error if window exceeds 2^31-1
                    if (adjusted > 0x7fff_ffff) return error.InvalidSetting;
                    stream.recv_window = @intCast(adjusted);
                }
                self.initial_stream_window = new_window;
            },
            // SETTINGS_MAX_FRAME_SIZE (0x5) - must be between 2^14 and 2^24-1
            0x5 => {
                if (value < 16384 or value > 16777215) return error.InvalidSetting;
                self.max_frame_size = value;
            },
            // SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
            0x6 => self.max_header_list_size = value,
            else => {},
        }
    }

    fn getOrCreateStream(self: *Stack, stream_id: u32) ?*Stream {
        if ((stream_id & 1) == 0) return null;
        if (stream_id <= self.last_stream_id) {
            return self.findStream(stream_id);
        }
        // Reject new streams after GOAWAY received
        if (self.goaway_received) return null;
        // Try to find a closed stream slot to reuse
        for (self.streams[0..self.stream_count], 0..) |*stream, idx| {
            if (stream.state == .closed) {
                self.last_stream_id = stream_id;
                stream.reset(stream_id, self.initial_stream_window);
                stream.state = .idle;
                // Update cache
                self.cached_stream_id = stream_id;
                self.cached_stream_index = idx;
                return stream;
            }
        }
        // No closed slots, try to allocate a new one
        if (self.stream_count >= self.streams.len) return null;
        self.last_stream_id = stream_id;
        const idx = self.stream_count;
        var stream = &self.streams[idx];
        stream.reset(stream_id, self.initial_stream_window);
        stream.state = .idle;
        self.stream_count += 1;
        // Update cache
        self.cached_stream_id = stream_id;
        self.cached_stream_index = idx;
        return stream;
    }

    fn findStream(self: *Stack, stream_id: u32) ?*Stream {
        // Check cache first for O(1) lookup on repeated access
        if (self.cached_stream_id == stream_id and self.cached_stream_index < self.stream_count) {
            const cached = &self.streams[self.cached_stream_index];
            if (cached.id == stream_id) return cached;
        }
        // Fall back to linear scan
        for (self.streams[0..self.stream_count], 0..) |*stream, idx| {
            if (stream.id == stream_id) {
                // Update cache
                self.cached_stream_id = stream_id;
                self.cached_stream_index = idx;
                return stream;
            }
        }
        return null;
    }

    /// Mark a stream as closed after sending a complete response (END_STREAM on our side).
    /// RFC 9113 §5.1: After both sides send END_STREAM, the stream is closed.
    pub fn closeStream(self: *Stack, stream_id: u32) void {
        if (self.findStream(stream_id)) |stream| {
            stream.state = .closed;
        }
    }

    fn decodeHeaders(self: *Stack, stream: *Stream) !HeaderBlockResult {
        if (stream.saw_headers and !stream.saw_data) return error.Protocol;
        stream.saw_headers = true;
        const result = try self.decoder.decodeRequestBlock(self.header_block[0..stream.header_block_len], self.headers_storage[0..], self.max_header_list_size);
        stream.header_block_len = 0;
        stream.header_block_in_progress = false;
        if (result.authority.len != 0) {
            var has_host = false;
            for (result.headers) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "host")) {
                    has_host = true;
                    break;
                }
            }
            if (!has_host) {
                if (result.headers.len < self.headers_storage.len) {
                    self.headers_storage[result.headers.len] = .{ .name = "host", .value = result.authority };
                    return .{
                        .headers = self.headers_storage[0 .. result.headers.len + 1],
                        .method = result.method,
                        .path = result.path,
                        .authority = result.authority,
                    };
                }
            }
        }
        return result;
    }
};

const FrameHandle = struct {
    state: ParseState,
    error_code: ErrorCode,
    event_count: usize,
};

fn mapHeaderError(err: anyerror) FrameHandle {
    return switch (err) {
        error.HeaderListTooLarge => .{ .state = .err, .error_code = .header_list_too_large, .event_count = 0 },
        error.InvalidHuffman, error.InvalidIndex, error.Truncated => .{ .state = .err, .error_code = .compression_error, .event_count = 0 },
        error.MissingPseudo, error.Protocol => .{ .state = .err, .error_code = .protocol_error, .event_count = 0 },
        else => .{ .state = .err, .error_code = .protocol_error, .event_count = 0 },
    };
}

fn frameConsumed(consumed: usize, frame: Frame) usize {
    return consumed + 9 + frame.header.length;
}

fn parseHeadersPayload(payload: []const u8, flags: u8) ![]const u8 {
    var idx: usize = 0;
    if ((flags & 0x8) != 0) {
        if (payload.len < 1) return error.Invalid;
        const pad_len = payload[0];
        idx = 1;
        if (payload.len < idx + pad_len) return error.Invalid;
        const end = payload.len - pad_len;
        if ((flags & 0x20) != 0) {
            if (end - idx < 5) return error.Invalid;
            idx += 5;
        }
        if (idx > end) return error.Invalid;
        return payload[idx..end];
    }
    if ((flags & 0x20) != 0) {
        if (payload.len < 5) return error.Invalid;
        idx = 5;
    }
    return payload[idx..];
}

fn parseDataPayload(payload: []const u8, flags: u8) ![]const u8 {
    var idx: usize = 0;
    if ((flags & 0x8) != 0) {
        if (payload.len < 1) return error.Invalid;
        const pad_len = payload[0];
        idx = 1;
        if (payload.len < idx + pad_len) return error.Invalid;
        return payload[idx .. payload.len - pad_len];
    }
    return payload[idx..];
}

fn parseWindowIncrement(payload: []const u8) ?u32 {
    const raw = (@as(u32, payload[0]) << 24) |
        (@as(u32, payload[1]) << 16) |
        (@as(u32, payload[2]) << 8) |
        (@as(u32, payload[3]));
    const increment = raw & 0x7fff_ffff;
    if (increment == 0) return null;
    return increment;
}

const HeaderMode = enum {
    request,
    response,
};

/// RFC 9113 §8.2: Connection-specific headers MUST NOT appear in HTTP/2
fn isConnectionSpecificHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "upgrade");
    // Note: transfer-encoding is allowed in HTTP/2 for request bodies
}

/// RFC 9113 §8.2: Header field names MUST be lowercase
fn hasUppercaseChar(name: []const u8) bool {
    for (name) |ch| {
        if (ch >= 'A' and ch <= 'Z') return true;
    }
    return false;
}

fn appendHeader(
    mode: HeaderMode,
    name: []const u8,
    value: []const u8,
    headers: []request.Header,
    header_count: *usize,
    total_size: *usize,
    max_header_list_size: usize,
    saw_regular: *bool,
    method: ?*[]const u8,
    path: ?*[]const u8,
    authority: ?*[]const u8,
    status: ?*[]const u8,
    scheme: ?*[]const u8,
) !void {
    const is_pseudo = name.len != 0 and name[0] == ':';
    if (is_pseudo and saw_regular.*) return error.Protocol;
    if (!is_pseudo) {
        saw_regular.* = true;
        // RFC 9113 §8.2: Header names MUST be lowercase
        if (hasUppercaseChar(name)) return error.Protocol;
        // RFC 9113 §8.2.2: Connection-specific headers MUST NOT appear
        if (isConnectionSpecificHeader(name)) return error.Protocol;
        // RFC 9113 §8.2.2: transfer-encoding MUST NOT appear in HTTP/2
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return error.Protocol;
        // RFC 9113 §8.4.2: TE header is only valid with value "trailers"
        if (std.ascii.eqlIgnoreCase(name, "te")) {
            if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "trailers")) return error.Protocol;
        }
    }
    if (is_pseudo) {
        switch (mode) {
            .request => {
                if (std.mem.eql(u8, name, ":method")) {
                    if (method == null) return error.Protocol;
                    if (method.?.*.len != 0) return error.Protocol;
                    method.?.* = value;
                    return;
                }
                if (std.mem.eql(u8, name, ":path")) {
                    if (path == null) return error.Protocol;
                    if (path.?.*.len != 0) return error.Protocol;
                    path.?.* = value;
                    return;
                }
                if (std.mem.eql(u8, name, ":authority")) {
                    if (authority == null) return error.Protocol;
                    if (authority.?.*.len != 0) return error.Protocol;
                    authority.?.* = value;
                    return;
                }
                if (std.mem.eql(u8, name, ":scheme")) {
                    // RFC 9113 §8.3.1: :scheme MUST be present, track it
                    if (scheme) |s| {
                        if (s.*.len != 0) return error.Protocol; // duplicate
                        s.* = value;
                    }
                    return;
                }
                return error.Protocol;
            },
            .response => {
                if (std.mem.eql(u8, name, ":status")) {
                    if (status == null) return error.Protocol;
                    if (status.?.*.len != 0) return error.Protocol;
                    status.?.* = value;
                    return;
                }
                return error.Protocol;
            },
        }
    }
    const entry_size = 32 + name.len + value.len;
    total_size.* += entry_size;
    if (total_size.* > max_header_list_size) return error.HeaderListTooLarge;
    if (header_count.* >= headers.len) return error.HeaderListTooLarge;
    headers[header_count.*] = .{ .name = name, .value = value };
    header_count.* += 1;
}

fn decodeInt(buf: []const u8, idx: *usize, prefix: u8) !usize {
    if (idx.* >= buf.len) return error.Truncated;
    const mask: u8 = (@as(u8, 1) << @as(u3, @intCast(prefix))) - 1;
    const first = buf[idx.*];
    idx.* += 1;
    var value: usize = first & mask;
    if (value < mask) return value;
    var m: u6 = 0;
    while (idx.* < buf.len) {
        const b = buf[idx.*];
        idx.* += 1;
        // Guard against overflow BEFORE the shift+add operation
        if (m >= 28) return error.InvalidInt;
        value += (@as(usize, b & 0x7f) << m);
        if ((b & 0x80) == 0) return value;
        m += 7;
    }
    return error.Truncated;
}

fn validateFrame(typ: FrameType, stream_id: u32, flags: u8, payload: []const u8) bool {
    if (!validateLength(typ, flags, payload)) return false;
    return switch (typ) {
        .data, .headers, .priority, .rst_stream, .push_promise, .continuation => stream_id != 0,
        .settings, .ping, .goaway => stream_id == 0,
        .window_update => true,
    };
}

fn validateLength(typ: FrameType, flags: u8, payload: []const u8) bool {
    return switch (typ) {
        .ping => payload.len == 8,
        .settings => if ((flags & 0x1) != 0) payload.len == 0 else payload.len % 6 == 0,
        .priority => payload.len == 5,
        .rst_stream => payload.len == 4,
        .window_update => if (payload.len != 4) false else parseWindowIncrement(payload) != null,
        .goaway => payload.len >= 8,
        else => true,
    };
}

const StaticTable = [_]HeaderField{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

pub const StaticTableLen = StaticTable.len;

const HuffmanCodes = [_]u32{
    0xffc00000,     0xffffb000,     0xfffffe20,     0xfffffe30,     0xfffffe40,     0xfffffe50,     0xfffffe60,     0xfffffe70,
    0xfffffe80,     0xffffea00,     0xfffffff0,     0xfffffe90,     0xfffffea0,     0xfffffff4,     0xfffffeb0,     0xfffffec0,
    0xfffffed0,     0xfffffee0,     0xfffffef0,     0xffffff00,     0xffffff10,     0xffffff20,     0xfffffff8,     0xffffff30,
    0xffffff40,     0xffffff50,     0xffffff60,     0xffffff70,     0xffffff80,     0xffffff90,     0xffffffa0,     0xffffffb0,
    0x50000000,     0xfe000000,     0xfe400000,     0xffa00000,     0xffc80000,     0x54000000,     0xf8000000,     0xff400000,
    0xfe800000,     0xfec00000,     0xf9000000,     0xff600000,     0xfa000000,     0x58000000,     0x5c000000,     0x60000000,
    0x00000000,     0x08000000,     0x10000000,     0x64000000,     0x68000000,     0x6c000000,     0x70000000,     0x74000000,
    0x78000000,     0x7c000000,     0xb8000000,     0xfb000000,     0xfff80000,     0x80000000,     0xffb00000,     0xff000000,
    0xffd00000,     0x84000000,     0xba000000,     0xbc000000,     0xbe000000,     0xc0000000,     0xc2000000,     0xc4000000,
    0xc6000000,     0xc8000000,     0xca000000,     0xcc000000,     0xce000000,     0xd0000000,     0xd2000000,     0xd4000000,
    0xd6000000,     0xd8000000,     0xda000000,     0xdc000000,     0xde000000,     0xe0000000,     0xe2000000,     0xe4000000,
    0xfc000000,     0xe6000000,     0xfd000000,     0xffd80000,     0xfffe0000,     0xffe00000,     0xfff00000,     0x88000000,
    0xfffa0000,     0x18000000,     0x8c000000,     0x20000000,     0x90000000,     0x28000000,     0x94000000,     0x98000000,
    0x9c000000,     0x30000000,     0xe8000000,     0xea000000,     0xa0000000,     0xa4000000,     0xa8000000,     0x38000000,
    0xac000000,     0xec000000,     0xb0000000,     0x40000000,     0x48000000,     0xb4000000,     0xee000000,     0xf0000000,
    0xf2000000,     0xf4000000,     0xf6000000,     0xfffc0000,     0xff800000,     0xfff40000,     0xffe80000,     0xffffffc0,
    0xfffe6000,     0xffff4800,     0xfffe7000,     0xfffe8000,     0xffff4c00,     0xffff5000,     0xffff5400,     0xffffb200,
    0xffff5800,     0xffffb400,     0xffffb600,     0xffffb800,     0xffffba00,     0xffffbc00,     0xffffeb00,     0xffffbe00,
    0xffffec00,     0xffffed00,     0xffff5c00,     0xffffc000,     0xffffee00,     0xffffc200,     0xffffc400,     0xffffc600,
    0xffffc800,     0xfffee000,     0xffff6000,     0xffffca00,     0xffff6400,     0xffffcc00,     0xffffce00,     0xffffef00,
    0xffff6800,     0xfffee800,     0xfffe9000,     0xffff6c00,     0xffff7000,     0xffffd000,     0xffffd200,     0xfffef000,
    0xffffd400,     0xffff7400,     0xffff7800,     0xfffff000,     0xfffef800,     0xffff7c00,     0xffffd600,     0xffffd800,
    0xffff0000,     0xffff0800,     0xffff8000,     0xffff1000,     0xffffda00,     0xffff8400,     0xffffdc00,     0xffffde00,
    0xfffea000,     0xffff8800,     0xffff8c00,     0xffff9000,     0xffffe000,     0xffff9400,     0xffff9800,     0xffffe200,
    0xfffff800,     0xfffff840,     0xfffeb000,     0xfffe2000,     0xffff9c00,     0xffffe400,     0xffffa000,     0xfffff600,
    0xfffff880,     0xfffff8c0,     0xfffff900,     0xfffffbc0,     0xfffffbe0,     0xfffff940,     0xfffff100,     0xfffff680,
    0xfffe4000,     0xffff1800,     0xfffff980,     0xfffffc00,     0xfffffc20,     0xfffff9c0,     0xfffffc40,     0xfffff200,
    0xffff2000,     0xffff2800,     0xfffffa00,     0xfffffa40,     0xffffffd0,     0xfffffc60,     0xfffffc80,     0xfffffca0,
    0xfffec000,     0xfffff300,     0xfffed000,     0xffff3000,     0xffffa400,     0xffff3800,     0xffff4000,     0xffffe600,
    0xffffa800,     0xffffac00,     0xfffff700,     0xfffff780,     0xfffff400,     0xfffff500,     0xfffffa80,     0xffffe800,
    0xfffffac0,     0xfffffcc0,     0xfffffb00,     0xfffffb40,     0xfffffce0,     0xfffffd00,     0xfffffd20,     0xfffffd40,
    0xfffffd60,     0xffffffe0,     0xfffffd80,     0xfffffda0,     0xfffffdc0,     0xfffffde0,     0xfffffe00,     0xfffffb80,
    0xfffffffc,
};

const HuffmanCodeLengths = [_]u8{
    13,     23,     28,     28,     28,     28,     28,     28,     28,     24,     30,     28,     28,     30,     28,     28,
    28,     28,     28,     28,     28,     28,     30,     28,     28,     28,     28,     28,     28,     28,     28,     28,
    6,     10,     10,     12,     13,     6,     8,     11,     10,     10,     8,     11,     8,     6,     6,     6,
    5,     5,     5,     6,     6,     6,     6,     6,     6,     6,     7,     8,     15,     6,     12,     10,
    13,     6,     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,
    7,     7,     7,     7,     7,     7,     7,     7,     8,     7,     8,     13,     19,     13,     14,     6,
    15,     5,     6,     5,     6,     5,     6,     6,     6,     5,     7,     7,     6,     6,     6,     5,
    6,     7,     6,     5,     5,     6,     7,     7,     7,     7,     7,     15,     11,     14,     13,     28,
    20,     22,     20,     20,     22,     22,     22,     23,     22,     23,     23,     23,     23,     23,     24,     23,
    24,     24,     22,     23,     24,     23,     23,     23,     23,     21,     22,     23,     22,     23,     23,     24,
    22,     21,     20,     22,     22,     23,     23,     21,     23,     22,     22,     24,     21,     22,     23,     23,
    21,     21,     22,     21,     23,     22,     23,     23,     20,     22,     22,     22,     23,     22,     22,     23,
    26,     26,     20,     19,     22,     23,     22,     25,     26,     26,     26,     27,     27,     26,     24,     25,
    19,     21,     26,     27,     27,     26,     27,     24,     21,     21,     26,     26,     28,     27,     27,     27,
    20,     24,     20,     21,     22,     21,     21,     23,     22,     22,     25,     25,     24,     24,     26,     23,
    26,     27,     26,     26,     27,     27,     27,     27,     27,     28,     27,     27,     27,     27,     27,     26,
    30,
};

pub fn writeFrame(buf: []u8, typ: FrameType, flags: u8, stream_id: u32, payload: []const u8) !usize {
    if (payload.len > 0x00ff_ffff) return error.FrameTooLarge;
    if (stream_id & 0x8000_0000 != 0) return error.InvalidStreamId;
    const needed = 9 + payload.len;
    if (buf.len < needed) return error.NoSpaceLeft;
    buf[0] = @intCast((payload.len >> 16) & 0xff);
    buf[1] = @intCast((payload.len >> 8) & 0xff);
    buf[2] = @intCast(payload.len & 0xff);
    buf[3] = @intFromEnum(typ);
    buf[4] = flags;
    buf[5] = @intCast((stream_id >> 24) & 0x7f);
    buf[6] = @intCast((stream_id >> 16) & 0xff);
    buf[7] = @intCast((stream_id >> 8) & 0xff);
    buf[8] = @intCast(stream_id & 0xff);
    @memcpy(buf[9 .. 9 + payload.len], payload);
    return needed;
}

pub fn writeFrameHeader(buf: []u8, typ: FrameType, flags: u8, stream_id: u32, payload_len: usize) !void {
    if (payload_len > 0x00ff_ffff) return error.FrameTooLarge;
    if (stream_id & 0x8000_0000 != 0) return error.InvalidStreamId;
    if (buf.len < 9) return error.NoSpaceLeft;
    buf[0] = @intCast((payload_len >> 16) & 0xff);
    buf[1] = @intCast((payload_len >> 8) & 0xff);
    buf[2] = @intCast(payload_len & 0xff);
    buf[3] = @intFromEnum(typ);
    buf[4] = flags;
    buf[5] = @intCast((stream_id >> 24) & 0x7f);
    buf[6] = @intCast((stream_id >> 16) & 0xff);
    buf[7] = @intCast((stream_id >> 8) & 0xff);
    buf[8] = @intCast(stream_id & 0xff);
}

pub fn encodeResponseHeaders(
    buf: []u8,
    status: u16,
    headers: []const response.Header,
    content_length: usize,
) !usize {
    var idx: usize = 0;
    const status_index = statusStaticIndex(status);
    if (status_index != 0) {
        idx += try encodeInt(buf[idx..], 7, status_index, 0x80);
    } else {
        idx += try encodeLiteralHeader(buf[idx..], ":status", statusString(status));
    }
    // RFC 9110 §15.2: 1xx responses have no content-length, no date
    if (status >= 100 and status < 200) {
        return idx;
    }
    // RFC 9110 §8.6: MUST NOT send content-length in 204 or 304 responses
    if (status != 204 and status != 304) {
        var length_buf: [20]u8 = undefined;
        const length_slice = try std.fmt.bufPrint(length_buf[0..], "{d}", .{content_length});
        idx += try encodeLiteralHeaderIndexed(buf[idx..], "content-length", length_slice);
    }
    // RFC 9110 §6.6.1: Origin servers MUST send Date header
    idx += try encodeLiteralHeaderIndexed(buf[idx..], "date", formatImfDateHttp2(&date_scratch_buf));
    for (headers) |header| {
        // Skip pseudo-headers (already handled)
        if (header.name.len > 0 and header.name[0] == ':') continue;
        // Skip content-length (already added above to avoid duplicates)
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        // Skip date (already added above)
        if (std.ascii.eqlIgnoreCase(header.name, "date")) continue;
        idx += try encodeLiteralHeader(buf[idx..], header.name, header.value);
    }
    return idx;
}

/// Thread-local scratch buffer for IMF-fixdate in HTTP/2 responses
threadlocal var date_scratch_buf: [29]u8 = undefined;

/// Format current time as IMF-fixdate (RFC 9110 §5.6.7) for HTTP/2
/// e.g., "Sun, 06 Nov 1994 08:49:37 GMT"
fn formatImfDateHttp2(buf: *[29]u8) []const u8 {
    const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    const ts = std.posix.clock_gettime(.REALTIME) catch return "Thu, 01 Jan 1970 00:00:00 GMT";
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
        const days_in_year: u64 = if (isLeapYear(year)) 366 else 365;
        if (days < days_in_year) break;
        days -= days_in_year;
        year += 1;
    }
    const leap = isLeapYear(year);
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

fn isLeapYear(year: u64) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

fn statusStaticIndex(status: u16) usize {
    return switch (status) {
        200 => 8,
        204 => 9,
        206 => 10,
        304 => 11,
        400 => 12,
        404 => 13,
        500 => 14,
        else => 0,
    };
}

/// Thread-local buffer for formatting arbitrary status codes as strings.
/// The static index covers 200, 204, 206, 304, 400, 404, 500 — this handles everything else.
threadlocal var status_fmt_buf: [3]u8 = undefined;

fn statusString(status: u16) []const u8 {
    return switch (status) {
        200 => "200",
        201 => "201",
        204 => "204",
        206 => "206",
        301 => "301",
        302 => "302",
        304 => "304",
        400 => "400",
        401 => "401",
        403 => "403",
        404 => "404",
        405 => "405",
        429 => "429",
        500 => "500",
        502 => "502",
        503 => "503",
        504 => "504",
        else => {
            // Dynamically format any 3-digit status code
            if (status >= 100 and status <= 999) {
                _ = std.fmt.bufPrint(&status_fmt_buf, "{d}", .{status}) catch return "500";
                return &status_fmt_buf;
            }
            return "500";
        },
    };
}

fn encodeLiteralHeaderIndexed(buf: []u8, name: []const u8, value: []const u8) !usize {
    const index = staticNameIndex(name);
    if (index == 0) return encodeLiteralHeader(buf, name, value);
    var idx: usize = 0;
    idx += try encodeInt(buf[idx..], 4, index, 0x00);
    idx += try encodeString(buf[idx..], value);
    return idx;
}

fn encodeLiteralHeader(buf: []u8, name: []const u8, value: []const u8) !usize {
    var idx: usize = 0;
    idx += try encodeInt(buf[idx..], 4, 0, 0x00);
    idx += try encodeString(buf[idx..], name);
    idx += try encodeString(buf[idx..], value);
    return idx;
}

fn encodeString(buf: []u8, value: []const u8) !usize {
    var idx: usize = 0;
    idx += try encodeInt(buf[idx..], 7, value.len, 0x00);
    if (idx + value.len > buf.len) return error.NoSpaceLeft;
    @memcpy(buf[idx .. idx + value.len], value);
    idx += value.len;
    return idx;
}

fn encodeInt(buf: []u8, prefix: u8, value: usize, prefix_bits: u8) !usize {
    const max_prefix: usize = (@as(usize, 1) << @intCast(prefix)) - 1;
    if (buf.len == 0) return error.NoSpaceLeft;
    if (value < max_prefix) {
        buf[0] = prefix_bits | @as(u8, @intCast(value));
        return 1;
    }
    buf[0] = prefix_bits | @as(u8, @intCast(max_prefix));
    var rem = value - max_prefix;
    var idx: usize = 1;
    while (true) {
        if (idx >= buf.len) return error.NoSpaceLeft;
        if (rem >= 128) {
            buf[idx] = @intCast((rem % 128) + 128);
            rem /= 128;
            idx += 1;
        } else {
            buf[idx] = @intCast(rem);
            idx += 1;
            break;
        }
    }
    return idx;
}

fn staticNameIndex(name: []const u8) usize {
    for (StaticTable, 0..) |entry, idx| {
        if (std.mem.eql(u8, entry.name, name) and entry.value.len == 0) {
            return idx + 1;
        }
    }
    return 0;
}

// ============================================================
// Server-side frame generation helpers
// ============================================================

/// Write the server SETTINGS frame (RFC 9113 §3.4: MUST be first frame sent)
pub fn writeServerSettings(buf: []u8, cfg: StackConfig) !usize {
    // Each setting is 6 bytes: 2-byte ID + 4-byte value
    var payload: [42]u8 = undefined; // Up to 7 settings
    var plen: usize = 0;

    // SETTINGS_HEADER_TABLE_SIZE (0x1)
    writeSetting(&payload, &plen, 0x1, @intCast(cfg.max_dynamic_table_size));
    // SETTINGS_ENABLE_PUSH (0x2) - server MUST NOT send push, advertise 0
    writeSetting(&payload, &plen, 0x2, 0);
    // SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
    writeSetting(&payload, &plen, 0x3, @intCast(cfg.max_streams));
    // SETTINGS_INITIAL_WINDOW_SIZE (0x4)
    writeSetting(&payload, &plen, 0x4, cfg.initial_window_size);
    // SETTINGS_MAX_FRAME_SIZE (0x5)
    writeSetting(&payload, &plen, 0x5, cfg.max_frame_size);
    // SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
    writeSetting(&payload, &plen, 0x6, @intCast(cfg.max_header_list_size));

    return writeFrame(buf, .settings, 0, 0, payload[0..plen]);
}

/// Write a SETTINGS ACK frame (RFC 9113 §6.5.3)
pub fn writeSettingsAck(buf: []u8) !usize {
    return writeFrame(buf, .settings, 0x1, 0, &.{});
}

/// Write a PING ACK frame (RFC 9113 §6.7)
pub fn writePingAck(buf: []u8, opaque_data: [8]u8) !usize {
    return writeFrame(buf, .ping, 0x1, 0, &opaque_data);
}

/// Write a WINDOW_UPDATE frame (RFC 9113 §6.9)
pub fn writeWindowUpdate(buf: []u8, stream_id: u32, increment: u32) !usize {
    var payload: [4]u8 = undefined;
    payload[0] = @intCast((increment >> 24) & 0x7f);
    payload[1] = @intCast((increment >> 16) & 0xff);
    payload[2] = @intCast((increment >> 8) & 0xff);
    payload[3] = @intCast(increment & 0xff);
    return writeFrame(buf, .window_update, 0, stream_id, &payload);
}

/// Write a RST_STREAM frame (RFC 9113 §6.4)
pub fn writeRstStream(buf: []u8, stream_id: u32, error_code: u32) !usize {
    var payload: [4]u8 = undefined;
    payload[0] = @intCast((error_code >> 24) & 0xff);
    payload[1] = @intCast((error_code >> 16) & 0xff);
    payload[2] = @intCast((error_code >> 8) & 0xff);
    payload[3] = @intCast(error_code & 0xff);
    return writeFrame(buf, .rst_stream, 0, stream_id, &payload);
}

/// Write a GOAWAY frame (RFC 9113 §5.4.1)
pub fn writeGoaway(buf: []u8, last_stream_id: u32, error_code: u32) !usize {
    var payload: [8]u8 = undefined;
    payload[0] = @intCast((last_stream_id >> 24) & 0x7f);
    payload[1] = @intCast((last_stream_id >> 16) & 0xff);
    payload[2] = @intCast((last_stream_id >> 8) & 0xff);
    payload[3] = @intCast(last_stream_id & 0xff);
    payload[4] = @intCast((error_code >> 24) & 0xff);
    payload[5] = @intCast((error_code >> 16) & 0xff);
    payload[6] = @intCast((error_code >> 8) & 0xff);
    payload[7] = @intCast(error_code & 0xff);
    return writeFrame(buf, .goaway, 0, 0, &payload);
}

fn writeSetting(payload: []u8, pos: *usize, id: u16, value: u32) void {
    payload[pos.*] = @intCast((id >> 8) & 0xff);
    payload[pos.* + 1] = @intCast(id & 0xff);
    payload[pos.* + 2] = @intCast((value >> 24) & 0xff);
    payload[pos.* + 3] = @intCast((value >> 16) & 0xff);
    payload[pos.* + 4] = @intCast((value >> 8) & 0xff);
    payload[pos.* + 5] = @intCast(value & 0xff);
    pos.* += 6;
}
