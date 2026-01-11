const std = @import("std");
const config = @import("config.zig");
const buffer_pool = @import("runtime/buffer_pool.zig");
const connection = @import("runtime/connection.zig");
const http1 = @import("protocol/http1.zig");
const http2 = @import("protocol/http2.zig");
const request = @import("protocol/request.zig");
const response = @import("response/response.zig");

// QUIC and HTTP/3 modules (excluding those that depend on TLS FFI)
const quic_types = @import("quic/types.zig");
const quic_varint = @import("quic/varint.zig");
const quic_packet = @import("quic/packet.zig");
const quic_frame = @import("quic/frame.zig");
const quic_crypto = @import("quic/crypto.zig");
const quic_stream = @import("quic/stream.zig");
const quic_recovery = @import("quic/recovery.zig");
const quic_congestion = @import("quic/congestion.zig");
const quic_metrics = @import("quic/metrics.zig");
const http3_frame = @import("protocol/http3/frame.zig");
const http3_qpack = @import("protocol/http3/qpack.zig");
const metrics_mw = @import("middleware/metrics_mw.zig");

// Force tests in these modules to be included
// Note: quic_connection, quic_handler, and http3 are excluded as they
// transitively import TLS FFI which requires OpenSSL linking
comptime {
    _ = quic_types;
    _ = quic_varint;
    _ = quic_packet;
    _ = quic_frame;
    _ = quic_crypto;
    _ = quic_stream;
    _ = quic_recovery;
    _ = quic_congestion;
    _ = quic_metrics;
    _ = http3_frame;
    _ = http3_qpack;
    _ = metrics_mw;
}

const Parsed = struct {
    buf: []u8,
    result: http1.ParseResult,

    fn deinit(self: *Parsed) void {
        std.testing.allocator.free(self.buf);
    }
};

fn parseRequest(input: []const u8, limits: http1.Limits) !Parsed {
    const buf = try std.testing.allocator.alloc(u8, input.len);
    @memcpy(buf, input);
    const result = http1.parse(buf, limits);
    return .{ .buf = buf, .result = result };
}

fn buildHeaderBlockAuthority(buffer: []u8, authority: []const u8) []u8 {
    var idx: usize = 0;
    buffer[idx] = 0x82; // :method GET
    idx += 1;
    buffer[idx] = 0x84; // :path /
    idx += 1;
    buffer[idx] = 0x01; // literal without indexing, indexed name :authority (index 1)
    idx += 1;
    buffer[idx] = @intCast(authority.len);
    idx += 1;
    @memcpy(buffer[idx .. idx + authority.len], authority);
    idx += authority.len;
    return buffer[0..idx];
}

fn hexToBytes(out: []u8, hex: []const u8) ![]u8 {
    var out_idx: usize = 0;
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        if (out_idx >= out.len) return error.OutOfMemory;
        const hi = std.fmt.charToDigit(hex[i], 16) catch return error.InvalidCharacter;
        const lo = std.fmt.charToDigit(hex[i + 1], 16) catch return error.InvalidCharacter;
        out[out_idx] = @intCast((hi << 4) | lo);
        out_idx += 1;
    }
    return out[0..out_idx];
}

test "buffer pool acquire and release" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cfg = config.BufferPoolConfig{ .buffer_size = 1024, .buffer_count = 4 };
    var pool = try buffer_pool.BufferPool.init(allocator, cfg);
    defer pool.deinit();

    var handles: [4]buffer_pool.BufferHandle = undefined;
    for (&handles, 0..) |*handle, i| {
        handle.* = pool.acquire() orelse return error.OutOfMemory;
        try std.testing.expectEqual(@as(usize, 1024), handle.bytes.len);
        try std.testing.expectEqual(@as(u32, @intCast(i)), handle.index);
    }
    try std.testing.expect(pool.acquire() == null);

    for (handles) |handle| {
        pool.release(handle);
    }
    try std.testing.expect(pool.acquire() != null);
}

test "connection pool acquire and release" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try connection.ConnectionPool.init(allocator, 2);
    defer pool.deinit();

    const first = pool.acquire(1000) orelse return error.OutOfMemory;
    const second = pool.acquire(1001) orelse return error.OutOfMemory;
    try std.testing.expect(pool.acquire(1002) == null);

    try std.testing.expect(first.id != 0);
    try std.testing.expect(second.id == first.id + 1);

    pool.release(first);
    const third = pool.acquire(1003) orelse return error.OutOfMemory;
    try std.testing.expect(third.index == first.index);
}

test "http1 parses origin-form and keeps host requirement" {
    const input = "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.complete, parsed.result.state);
    try std.testing.expectEqual(http1.ErrorCode.none, parsed.result.error_code);
    try std.testing.expectEqualStrings("/hello", parsed.result.view.path);
    try std.testing.expectEqual(@as(usize, input.len), parsed.result.consumed_bytes);
    try std.testing.expect(parsed.result.keep_alive);
    try std.testing.expect(!parsed.result.expect_continue);
    try std.testing.expectEqual(@as(usize, 1), parsed.result.view.headers.len);
}

test "http1 rejects missing host for HTTP/1.1 origin-form" {
    const input = "GET / HTTP/1.1\r\n\r\n";
    var headers: [4]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 4,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.err, parsed.result.state);
    try std.testing.expectEqual(http1.ErrorCode.missing_host, parsed.result.error_code);
}

test "http1 parses absolute-form without host header" {
    const input = "GET http://example.com/a/b HTTP/1.1\r\nUser-Agent: test\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.complete, parsed.result.state);
    try std.testing.expectEqualStrings("/a/b", parsed.result.view.path);
    try std.testing.expect(parsed.result.keep_alive);
}

test "http1 parses authority-form for CONNECT" {
    const input = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
    var headers: [4]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 4,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.complete, parsed.result.state);
    try std.testing.expectEqualStrings("example.com:443", parsed.result.view.path);
}

test "http1 accepts asterisk-form for OPTIONS only" {
    const ok_input = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers_ok: [4]request.Header = undefined;
    var parsed_ok = try parseRequest(ok_input, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 4,
        .headers_storage = headers_ok[0..],
    });
    defer parsed_ok.deinit();
    try std.testing.expectEqual(http1.ParseState.complete, parsed_ok.result.state);
    try std.testing.expectEqualStrings("*", parsed_ok.result.view.path);

    const bad_input = "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers_bad: [4]request.Header = undefined;
    var parsed_bad = try parseRequest(bad_input, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 4,
        .headers_storage = headers_bad[0..],
    });
    defer parsed_bad.deinit();
    try std.testing.expectEqual(http1.ParseState.err, parsed_bad.result.state);
    try std.testing.expectEqual(http1.ErrorCode.invalid_request_line, parsed_bad.result.error_code);
}

test "http1 expect 100-continue signals on partial body" {
    const input = "POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 1024,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.partial, parsed.result.state);
    try std.testing.expect(parsed.result.expect_continue);
}

test "http1 expect 100-continue invalid value rejects" {
    const input = "POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: bananas\r\nContent-Length: 4\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 1024,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.err, parsed.result.state);
    try std.testing.expectEqual(http1.ErrorCode.invalid_header_value, parsed.result.error_code);
}

test "http1 parses chunked with trailers" {
    const input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\nExpires: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 1024,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.complete, parsed.result.state);
    try std.testing.expectEqualStrings("Wiki", parsed.result.view.body);
}

test "http1 rejects invalid chunked trailers" {
    const input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nBadTrailer\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 1024,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.err, parsed.result.state);
    try std.testing.expectEqual(http1.ErrorCode.invalid_chunked_body, parsed.result.error_code);
}

test "http1 rejects chunked body too large" {
    const input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 3,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.err, parsed.result.state);
    try std.testing.expectEqual(http1.ErrorCode.body_too_large, parsed.result.error_code);
}

test "http1 enforces content-length limits" {
    const input = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 4,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.err, parsed.result.state);
    try std.testing.expectEqual(http1.ErrorCode.body_too_large, parsed.result.error_code);
}

test "http1 rejects unsupported transfer encoding" {
    const input = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var parsed = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 1024,
        .max_header_count = 8,
        .headers_storage = headers[0..],
    });
    defer parsed.deinit();

    try std.testing.expectEqual(http1.ParseState.err, parsed.result.state);
    try std.testing.expectEqual(http1.ErrorCode.unsupported_transfer_encoding, parsed.result.error_code);
}

test "http1 enforces header count and size limits" {
    const input = "GET / HTTP/1.1\r\nHost: example.com\r\nX-One: a\r\nX-Two: b\r\n\r\n";
    var headers_count: [1]request.Header = undefined;
    var parsed_count = try parseRequest(input, .{
        .max_header_bytes = 512,
        .max_body_bytes = 1024,
        .max_header_count = 1,
        .headers_storage = headers_count[0..],
    });
    defer parsed_count.deinit();
    try std.testing.expectEqual(http1.ParseState.err, parsed_count.result.state);
    try std.testing.expectEqual(http1.ErrorCode.header_too_large, parsed_count.result.error_code);

    const short_limit = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers_size: [4]request.Header = undefined;
    var parsed_size = try parseRequest(short_limit, .{
        .max_header_bytes = 10,
        .max_body_bytes = 1024,
        .max_header_count = 4,
        .headers_storage = headers_size[0..],
    });
    defer parsed_size.deinit();
    try std.testing.expectEqual(http1.ParseState.err, parsed_size.result.state);
    try std.testing.expectEqual(http1.ErrorCode.header_too_large, parsed_size.result.error_code);
}

test "http1 keep-alive for HTTP/1.0 only with explicit header" {
    const input_default = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    var headers_default: [4]request.Header = undefined;
    var parsed_default = try parseRequest(input_default, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 4,
        .headers_storage = headers_default[0..],
    });
    defer parsed_default.deinit();
    try std.testing.expect(!parsed_default.result.keep_alive);

    const input_keep = "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
    var headers_keep: [4]request.Header = undefined;
    var parsed_keep = try parseRequest(input_keep, .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = 4,
        .headers_storage = headers_keep[0..],
    });
    defer parsed_keep.deinit();
    try std.testing.expect(parsed_keep.result.keep_alive);
}

test "http2 parser accepts preface and settings" {
    var parser = http2.Parser.init();
    var frames: [4]http2.Frame = undefined;
    var buf: [http2.Preface.len + 9]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    _ = try http2.writeFrame(buf[http2.Preface.len..], .settings, 0, 0, &[_]u8{});

    const res = parser.parse(buf[0..], frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.complete, res.state);
    try std.testing.expectEqual(http2.ErrorCode.none, res.error_code);
    try std.testing.expectEqual(@as(usize, 1), res.frame_count);
    try std.testing.expectEqual(http2.FrameType.settings, frames[0].header.typ);
}

test "http2 parser handles partial preface" {
    var parser = http2.Parser.init();
    var frames: [2]http2.Frame = undefined;
    const part1 = http2.Preface[0..10];
    const res1 = parser.parse(part1, frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.partial, res1.state);
    try std.testing.expectEqual(@as(usize, 0), res1.consumed_bytes);

    const part2 = http2.Preface[10..];
    const res2 = parser.parse(part2, frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.complete, res2.state);
    try std.testing.expectEqual(@as(usize, part2.len), res2.consumed_bytes);
}

test "http2 parser rejects invalid preface" {
    var parser = http2.Parser.init();
    var frames: [1]http2.Frame = undefined;
    var buf: [http2.Preface.len]u8 = undefined;
    @memcpy(buf[0..], http2.Preface);
    buf[0] = 'X';
    const res = parser.parse(buf[0..], frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.invalid_preface, res.error_code);
}

test "http2 parser rejects oversized frame" {
    var parser = http2.Parser.init();
    var frames: [1]http2.Frame = undefined;
    var buf: [http2.Preface.len + 9]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    _ = try http2.writeFrame(buf[http2.Preface.len..], .settings, 0, 0, &[_]u8{});
    buf[http2.Preface.len] = 0x00;
    buf[http2.Preface.len + 1] = 0x40;
    buf[http2.Preface.len + 2] = 0x00;
    const res = parser.parse(buf[0..], frames[0..], .{ .max_frame_size = 0x3fff });
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.frame_size_error, res.error_code);
}

test "http2 parser rejects settings ack with payload" {
    var parser = http2.Parser.init();
    var frames: [1]http2.Frame = undefined;
    var buf: [http2.Preface.len + 15]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    _ = try http2.writeFrame(buf[http2.Preface.len..], .settings, 0x1, 0, &[_]u8{ 0, 1, 0, 0, 0, 1 });
    const res = parser.parse(buf[0..], frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, res.error_code);
}

test "http2 parser rejects headers on stream 0" {
    var parser = http2.Parser.init();
    var frames: [1]http2.Frame = undefined;
    var buf: [http2.Preface.len + 9]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    _ = try http2.writeFrame(buf[http2.Preface.len..], .headers, 0, 0, &[_]u8{});
    const res = parser.parse(buf[0..], frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, res.error_code);
}

test "http2 parser rejects ping with invalid length" {
    var parser = http2.Parser.init();
    var frames: [1]http2.Frame = undefined;
    var buf: [http2.Preface.len + 13]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    _ = try http2.writeFrame(buf[http2.Preface.len..], .ping, 0, 0, &[_]u8{ 1, 2, 3, 4 });
    const res = parser.parse(buf[0..], frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, res.error_code);
}

test "http2 parser rejects window update with zero increment" {
    var parser = http2.Parser.init();
    var frames: [1]http2.Frame = undefined;
    var buf: [http2.Preface.len + 13]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    _ = try http2.writeFrame(buf[http2.Preface.len..], .window_update, 0, 1, &[_]u8{ 0, 0, 0, 0 });
    const res = parser.parse(buf[0..], frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, res.error_code);
}

test "http2 parser returns partial for incomplete frame" {
    var parser = http2.Parser.init();
    var frames: [1]http2.Frame = undefined;
    var buf: [http2.Preface.len + 17]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    _ = try http2.writeFrame(buf[http2.Preface.len..], .ping, 0, 0, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const truncated = buf[0 .. buf.len - 3];
    const res = parser.parse(truncated, frames[0..], .{ .max_frame_size = 16384 });
    try std.testing.expectEqual(http2.ParseState.partial, res.state);
    try std.testing.expect(res.consumed_bytes < truncated.len);
}

test "http2 stack decodes headers event with hpack" {
    var stack = http2.Stack.init();
    var frames: [4]http2.Frame = undefined;
    var events: [4]http2.Event = undefined;
    var header_block: [64]u8 = undefined;
    const header_bytes = buildHeaderBlockAuthority(header_block[0..], "example.com");
    var buf: [http2.Preface.len + 9 + 64]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    const frame_len = try http2.writeFrame(buf[http2.Preface.len..], .headers, 0x5, 1, header_bytes);
    const frame_bytes = buf[http2.Preface.len .. http2.Preface.len + frame_len];
    const total = http2.Preface.len + frame_bytes.len;
    const res = stack.ingest(buf[0..total], frames[0..], events[0..]);
    try std.testing.expectEqual(http2.ParseState.complete, res.state);
    try std.testing.expectEqual(@as(usize, 1), res.event_count);
    switch (events[0]) {
        .headers => |ev| {
            try std.testing.expectEqual(@as(u32, 1), ev.stream_id);
            try std.testing.expectEqual(request.Method.GET, ev.request.method);
            try std.testing.expectEqualStrings("/", ev.request.path);
            try std.testing.expect(ev.end_stream);
        },
        else => return error.UnexpectedEvent,
    }
}

test "http2 stack handles continuation frames" {
    var stack = http2.Stack.init();
    var frames: [6]http2.Frame = undefined;
    var events: [2]http2.Event = undefined;
    var header_block: [64]u8 = undefined;
    const header_bytes = buildHeaderBlockAuthority(header_block[0..], "example.com");
    const split_at: usize = 3;
    var buf: [http2.Preface.len + 9 + 9 + 64]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    const headers_len = try http2.writeFrame(buf[http2.Preface.len..], .headers, 0x1, 1, header_bytes[0..split_at]);
    const continuation_len = try http2.writeFrame(buf[http2.Preface.len + headers_len ..], .continuation, 0x4, 1, header_bytes[split_at..]);
    const total = http2.Preface.len + headers_len + continuation_len;
    const res = stack.ingest(buf[0..total], frames[0..], events[0..]);
    try std.testing.expectEqual(http2.ParseState.complete, res.state);
    try std.testing.expectEqual(@as(usize, 1), res.event_count);
    switch (events[0]) {
        .headers => |ev| {
            try std.testing.expectEqual(request.Method.GET, ev.request.method);
            try std.testing.expectEqualStrings("/", ev.request.path);
        },
        else => return error.UnexpectedEvent,
    }
}

test "http2 stack rejects even stream id" {
    var stack = http2.Stack.init();
    var frames: [2]http2.Frame = undefined;
    var events: [2]http2.Event = undefined;
    var header_block: [32]u8 = undefined;
    const header_bytes = buildHeaderBlockAuthority(header_block[0..], "example.com");
    var buf: [http2.Preface.len + 9 + 32]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    const frame_len = try http2.writeFrame(buf[http2.Preface.len..], .headers, 0x5, 2, header_bytes);
    const total = http2.Preface.len + frame_len;
    const res = stack.ingest(buf[0..total], frames[0..], events[0..]);
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, res.error_code);
}

test "http2 stack enforces flow control on data frames" {
    var stack = http2.Stack.init();
    stack.conn_recv_window = 1;
    var frames: [4]http2.Frame = undefined;
    var events: [2]http2.Event = undefined;
    var header_block: [32]u8 = undefined;
    const header_bytes = buildHeaderBlockAuthority(header_block[0..], "example.com");
    var buf: [http2.Preface.len + 128]u8 = undefined;
    @memcpy(buf[0..http2.Preface.len], http2.Preface);
    const headers_len = try http2.writeFrame(buf[http2.Preface.len..], .headers, 0x4, 1, header_bytes);
    const data_payload = [_]u8{ 0x41, 0x42 };
    const data_len = try http2.writeFrame(buf[http2.Preface.len + headers_len ..], .data, 0x1, 1, data_payload[0..]);
    const total = http2.Preface.len + headers_len + data_len;
    const res = stack.ingest(buf[0..total], frames[0..], events[0..]);
    try std.testing.expectEqual(http2.ParseState.err, res.state);
    try std.testing.expectEqual(http2.ErrorCode.flow_control_error, res.error_code);
}

test "http2 hpack decodes huffman example" {
    var decoder = http2.HpackDecoder.init();
    var headers: [8]request.Header = undefined;
    var encoded_bytes: [32]u8 = undefined;
    const hex = "828684418cf1e3c2e5f23a6ba0ab90f4ff";
    const block = try hexToBytes(encoded_bytes[0..], hex);
    const result = try decoder.decodeRequestBlock(block, headers[0..], 4096);
    try std.testing.expectEqual(request.Method.GET, result.method);
    try std.testing.expectEqualStrings("/", result.path);
    try std.testing.expectEqualStrings("www.example.com", result.authority);
}

test "http2 response encoder roundtrip" {
    var decoder = http2.HpackDecoder.init();
    var headers: [8]request.Header = undefined;
    var buf: [128]u8 = undefined;
    const encoded_len = try http2.encodeResponseHeaders(buf[0..], 200, &[_]response.Header{}, 12);
    const decoded = try decoder.decodeResponseBlock(buf[0..encoded_len], headers[0..], 4096);
    try std.testing.expectEqualStrings("200", decoded.status);
    try std.testing.expectEqual(@as(usize, 1), decoded.headers.len);
    try std.testing.expectEqualStrings("content-length", decoded.headers[0].name);
    try std.testing.expectEqualStrings("12", decoded.headers[0].value);
}

test "http2 response encoder includes custom headers" {
    var decoder = http2.HpackDecoder.init();
    var headers: [8]request.Header = undefined;
    var buf: [256]u8 = undefined;
    const custom = [_]response.Header{
        .{ .name = "x-test", .value = "one" },
        .{ .name = "cache-control", .value = "no-cache" },
    };
    const encoded_len = try http2.encodeResponseHeaders(buf[0..], 200, custom[0..], 0);
    const decoded = try decoder.decodeResponseBlock(buf[0..encoded_len], headers[0..], 4096);
    try std.testing.expectEqualStrings("200", decoded.status);
    try std.testing.expectEqual(@as(usize, 3), decoded.headers.len);
    try std.testing.expectEqualStrings("content-length", decoded.headers[0].name);
    try std.testing.expectEqualStrings("0", decoded.headers[0].value);
    try std.testing.expectEqualStrings("x-test", decoded.headers[1].name);
    try std.testing.expectEqualStrings("one", decoded.headers[1].value);
    try std.testing.expectEqualStrings("cache-control", decoded.headers[2].name);
    try std.testing.expectEqualStrings("no-cache", decoded.headers[2].value);
}

test "http2 dynamic table resolves indexed header" {
    var decoder = http2.HpackDecoder.init();
    var headers: [8]request.Header = undefined;
    var buf: [64]u8 = undefined;
    var idx: usize = 0;
    buf[idx] = 0x88; // :status 200 (static index 8)
    idx += 1;
    buf[idx] = 0x40; // literal with incremental indexing, new name
    idx += 1;
    buf[idx] = 0x06; // name length
    idx += 1;
    @memcpy(buf[idx .. idx + 6], "x-test");
    idx += 6;
    buf[idx] = 0x03; // value length
    idx += 1;
    @memcpy(buf[idx .. idx + 3], "one");
    idx += 3;
    _ = try decoder.decodeResponseBlock(buf[0..idx], headers[0..], 4096);

    const dynamic_index: u8 = @intCast(http2.StaticTableLen + 1);
    buf[0] = 0x88;
    buf[1] = 0x80 | dynamic_index;
    const decoded = try decoder.decodeResponseBlock(buf[0..2], headers[0..], 4096);
    try std.testing.expectEqualStrings("200", decoded.status);
    try std.testing.expectEqual(@as(usize, 1), decoded.headers.len);
    try std.testing.expectEqualStrings("x-test", decoded.headers[0].name);
    try std.testing.expectEqualStrings("one", decoded.headers[0].value);
}

test "http2 response encoder preserves header order and duplicates" {
    var decoder = http2.HpackDecoder.init();
    var headers: [8]request.Header = undefined;
    var buf: [256]u8 = undefined;
    const custom = [_]response.Header{
        .{ .name = "set-cookie", .value = "a=1" },
        .{ .name = "x-order", .value = "first" },
        .{ .name = "set-cookie", .value = "b=2" },
    };
    const encoded_len = try http2.encodeResponseHeaders(buf[0..], 200, custom[0..], 0);
    const decoded = try decoder.decodeResponseBlock(buf[0..encoded_len], headers[0..], 4096);
    try std.testing.expectEqualStrings("200", decoded.status);
    try std.testing.expectEqual(@as(usize, 4), decoded.headers.len);
    try std.testing.expectEqualStrings("content-length", decoded.headers[0].name);
    try std.testing.expectEqualStrings("0", decoded.headers[0].value);
    try std.testing.expectEqualStrings("set-cookie", decoded.headers[1].name);
    try std.testing.expectEqualStrings("a=1", decoded.headers[1].value);
    try std.testing.expectEqualStrings("x-order", decoded.headers[2].name);
    try std.testing.expectEqualStrings("first", decoded.headers[2].value);
    try std.testing.expectEqualStrings("set-cookie", decoded.headers[3].name);
    try std.testing.expectEqualStrings("b=2", decoded.headers[3].value);
}

test "http2 response encoder ignores pseudo headers in custom list" {
    var decoder = http2.HpackDecoder.init();
    var headers: [8]request.Header = undefined;
    var buf: [256]u8 = undefined;
    const custom = [_]response.Header{
        .{ .name = ":status", .value = "418" },
        .{ .name = "x-ok", .value = "yes" },
    };
    const encoded_len = try http2.encodeResponseHeaders(buf[0..], 200, custom[0..], 0);
    const decoded = try decoder.decodeResponseBlock(buf[0..encoded_len], headers[0..], 4096);
    try std.testing.expectEqualStrings("200", decoded.status);
    try std.testing.expectEqual(@as(usize, 2), decoded.headers.len);
    try std.testing.expectEqualStrings("content-length", decoded.headers[0].name);
    try std.testing.expectEqualStrings("0", decoded.headers[0].value);
    try std.testing.expectEqualStrings("x-ok", decoded.headers[1].name);
    try std.testing.expectEqualStrings("yes", decoded.headers[1].value);
}
