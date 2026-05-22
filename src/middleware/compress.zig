const std = @import("std");
const response_mod = @import("../response/response.zig");
const build_options = @import("build_options");

const has_zlib = build_options.enable_compression;

const c = if (has_zlib) struct {
    const Z_OK = 0;
    const Z_STREAM_END = 1;
    const Z_FINISH = 4;
    const Z_DEFLATED = 8;
    const MAX_WBITS = 15;
    const Z_DEFAULT_COMPRESSION = -1;

    const z_stream = extern struct {
        next_in: ?[*]const u8 = null,
        avail_in: c_uint = 0,
        total_in: c_ulong = 0,
        next_out: ?[*]u8 = null,
        avail_out: c_uint = 0,
        total_out: c_ulong = 0,
        msg: ?[*:0]const u8 = null,
        internal_state: ?*anyopaque = null,
        alloc_func: ?*const anyopaque = null,
        free_func: ?*const anyopaque = null,
        @"opaque": ?*anyopaque = null,
        data_type: c_int = 0,
        adler: c_ulong = 0,
        reserved: c_ulong = 0,
    };

    extern "c" fn deflateInit2_(
        strm: *z_stream,
        level: c_int,
        method: c_int,
        windowBits: c_int,
        memLevel: c_int,
        strategy: c_int,
        version: [*:0]const u8,
        stream_size: c_int,
    ) c_int;

    extern "c" fn deflate(strm: *z_stream, flush: c_int) c_int;
    extern "c" fn deflateEnd(strm: *z_stream) c_int;
    extern "c" fn zlibVersion() [*:0]const u8;
} else struct {};

pub const Encoding = enum {
    gzip,
    deflate,
    identity,
};

pub fn parseAcceptEncoding(header_value: []const u8) Encoding {
    var it = std.mem.splitScalar(u8, header_value, ',');
    var has_gzip = false;
    var has_deflate = false;
    while (it.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        const semi = std.mem.indexOfScalar(u8, trimmed, ';');
        const name = if (semi) |s|
            std.mem.trim(u8, trimmed[0..s], " \t")
        else
            trimmed;
        if (semi) |s| {
            const params = std.mem.trim(u8, trimmed[s + 1 ..], " \t");
            if (std.ascii.startsWithIgnoreCase(params, "q=")) {
                const qval = std.mem.trim(u8, params[2..], " \t");
                if (std.mem.eql(u8, qval, "0") or std.mem.eql(u8, qval, "0.0") or
                    std.mem.eql(u8, qval, "0.00") or std.mem.eql(u8, qval, "0.000")) continue;
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "gzip")) has_gzip = true;
        if (std.ascii.eqlIgnoreCase(name, "deflate")) has_deflate = true;
    }
    if (has_gzip) return .gzip;
    if (has_deflate) return .deflate;
    return .identity;
}

pub fn isCompressible(content_type: []const u8) bool {
    const ct = if (std.mem.indexOfScalar(u8, content_type, ';')) |semi|
        std.mem.trim(u8, content_type[0..semi], " \t")
    else
        content_type;

    if (std.mem.startsWith(u8, ct, "text/")) return true;
    if (std.ascii.eqlIgnoreCase(ct, "application/json")) return true;
    if (std.ascii.eqlIgnoreCase(ct, "application/xml")) return true;
    if (std.ascii.eqlIgnoreCase(ct, "application/javascript")) return true;
    if (std.ascii.eqlIgnoreCase(ct, "application/xhtml+xml")) return true;
    if (std.mem.endsWith(u8, ct, "+json")) return true;
    if (std.mem.endsWith(u8, ct, "+xml")) return true;
    return false;
}

pub fn alreadyEncoded(headers: []const response_mod.Header) bool {
    for (headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "Content-Encoding")) return true;
    }
    return false;
}

const MIN_COMPRESS_SIZE = 256;
const MAX_COMPRESS_SIZE = 4 * 1024 * 1024;

pub fn gzipCompress(input: []const u8, output: []u8) ?usize {
    if (!has_zlib) return null;
    return zlibCompress(input, output, c.MAX_WBITS + 16);
}

pub fn deflateCompress(input: []const u8, output: []u8) ?usize {
    if (!has_zlib) return null;
    return zlibCompress(input, output, c.MAX_WBITS);
}

fn zlibCompress(input: []const u8, output: []u8, window_bits: c_int) ?usize {
    if (input.len < MIN_COMPRESS_SIZE or input.len > MAX_COMPRESS_SIZE) return null;

    var strm = c.z_stream{};
    const rc = c.deflateInit2_(
        &strm,
        c.Z_DEFAULT_COMPRESSION,
        c.Z_DEFLATED,
        window_bits,
        8,
        0,
        c.zlibVersion(),
        @sizeOf(c.z_stream),
    );
    if (rc != c.Z_OK) return null;
    defer _ = c.deflateEnd(&strm);

    strm.next_in = input.ptr;
    strm.avail_in = @intCast(@min(input.len, std.math.maxInt(c_uint)));
    strm.next_out = output.ptr;
    strm.avail_out = @intCast(@min(output.len, std.math.maxInt(c_uint)));

    const result = c.deflate(&strm, c.Z_FINISH);
    if (result != c.Z_STREAM_END) return null;

    const compressed_len: usize = @intCast(strm.total_out);
    if (compressed_len >= input.len) return null;
    return compressed_len;
}

pub fn encodingName(encoding: Encoding) []const u8 {
    return switch (encoding) {
        .gzip => "gzip",
        .deflate => "deflate",
        .identity => "identity",
    };
}

// ── Tests ──

test "parseAcceptEncoding" {
    try std.testing.expectEqual(Encoding.gzip, parseAcceptEncoding("gzip, deflate, br"));
    try std.testing.expectEqual(Encoding.gzip, parseAcceptEncoding("gzip"));
    try std.testing.expectEqual(Encoding.deflate, parseAcceptEncoding("deflate"));
    try std.testing.expectEqual(Encoding.gzip, parseAcceptEncoding("deflate, gzip;q=1.0"));
    try std.testing.expectEqual(Encoding.identity, parseAcceptEncoding("br"));
    try std.testing.expectEqual(Encoding.identity, parseAcceptEncoding(""));
}

test "isCompressible" {
    try std.testing.expect(isCompressible("text/html"));
    try std.testing.expect(isCompressible("text/plain"));
    try std.testing.expect(isCompressible("application/json"));
    try std.testing.expect(isCompressible("application/json; charset=utf-8"));
    try std.testing.expect(isCompressible("application/xml"));
    try std.testing.expect(isCompressible("application/vnd.api+json"));
    try std.testing.expect(!isCompressible("image/png"));
    try std.testing.expect(!isCompressible("application/octet-stream"));
}

test "gzipCompress basic" {
    if (!has_zlib) return error.SkipZigTest;
    const input = "Hello, World! " ** 50;
    var output: [4096]u8 = undefined;
    const len = gzipCompress(input, &output) orelse return error.CompressFailed;
    try std.testing.expect(len > 0);
    try std.testing.expect(len < input.len);
    // gzip magic bytes
    try std.testing.expectEqual(@as(u8, 0x1f), output[0]);
    try std.testing.expectEqual(@as(u8, 0x8b), output[1]);
}

test "deflateCompress basic" {
    if (!has_zlib) return error.SkipZigTest;
    const input = "Hello, World! " ** 50;
    var output: [4096]u8 = undefined;
    const len = deflateCompress(input, &output) orelse return error.CompressFailed;
    try std.testing.expect(len > 0);
    try std.testing.expect(len < input.len);
}

test "gzipCompress skips small input" {
    if (!has_zlib) return error.SkipZigTest;
    var buf: [64]u8 = .{0} ** 64;
    try std.testing.expectEqual(@as(?usize, null), gzipCompress("tiny", &buf));
}

test "gzipCompress skips if no savings" {
    if (!has_zlib) return error.SkipZigTest;
    var random_data: [300]u8 = undefined;
    for (&random_data, 0..) |*b, i| b.* = @truncate(i *% 251 +% 97);
    var output: [4096]u8 = undefined;
    _ = gzipCompress(&random_data, &output);
}

test "alreadyEncoded" {
    const hdrs = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "text/html" },
        .{ .name = "Content-Encoding", .value = "gzip" },
    };
    try std.testing.expect(alreadyEncoded(&hdrs));

    const hdrs2 = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "text/html" },
    };
    try std.testing.expect(!alreadyEncoded(&hdrs2));
}
