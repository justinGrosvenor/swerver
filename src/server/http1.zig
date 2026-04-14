//! # HTTP/1.1 response encoding + (future) dispatch path
//!
//! This module owns the h1-side of response building and — in a
//! later step — the connection-level h1 dispatch helpers
//! (`queueResponse`, body accumulation, file serving). For now it
//! hosts the pure wire-format primitives shared by every h1 write
//! path: status line emission, header encoding, the unified
//! `encodeResponseInner`, and the three facing encoders
//! (`encodeResponse`, `encodeResponseHeaders`, `encodeFileHeaders`)
//! used by `queueResponse`, `queueFileResponse`, and the pre-
//! encoded response cache.
//!
//! All functions here are `pub` so both `server.zig` (for the
//! current h1 dispatch path) and `server/preencoded.zig` (for
//! cache rebuilds) can reach them; once the full h1 block moves
//! here the encoding surface will go back to module-private.
//!
//! These functions are stateless: they take a target buffer and a
//! `Response` (or the pre-computed Date / Alt-Svc strings), write
//! the wire bytes, and return how many they consumed. No allocator,
//! no Server pointer.

const std = @import("std");

const response_mod = @import("../response/response.zig");

pub const connection_close_hdr = "Connection: close\r\n";
pub const date_prefix = "Date: ";
pub const alt_svc_prefix = "Alt-Svc: ";
pub const content_length_prefix = "Content-Length: ";
pub const crlf = "\r\n";

pub fn isValidHeaderBytes(s: []const u8) bool {
    for (s) |ch| {
        if (ch == '\r' or ch == '\n' or ch == 0) return false;
    }
    return true;
}

/// Comptime-generated status line lookup table for common HTTP status codes.
/// Maps status codes to pre-formatted "HTTP/1.1 NNN Reason\r\n" byte strings.
const StatusLine = struct {
    bytes: []const u8,

    fn comptimeFor(code: u16, reason: []const u8) StatusLine {
        return .{ .bytes = std.fmt.comptimePrint("HTTP/1.1 {d} {s}\r\n", .{ code, reason }) };
    }
};

const status_line_table: [512]?StatusLine = blk: {
    var table: [512]?StatusLine = .{null} ** 512;
    const entries = .{
        .{ 100, "Continue" },
        .{ 101, "Switching Protocols" },
        .{ 200, "OK" },
        .{ 201, "Created" },
        .{ 202, "Accepted" },
        .{ 204, "No Content" },
        .{ 206, "Partial Content" },
        .{ 301, "Moved Permanently" },
        .{ 302, "Found" },
        .{ 303, "See Other" },
        .{ 304, "Not Modified" },
        .{ 307, "Temporary Redirect" },
        .{ 308, "Permanent Redirect" },
        .{ 400, "Bad Request" },
        .{ 401, "Unauthorized" },
        .{ 402, "Payment Required" },
        .{ 403, "Forbidden" },
        .{ 404, "Not Found" },
        .{ 405, "Method Not Allowed" },
        .{ 408, "Request Timeout" },
        .{ 411, "Length Required" },
        .{ 413, "Content Too Large" },
        .{ 414, "URI Too Long" },
        .{ 415, "Unsupported Media Type" },
        .{ 417, "Expectation Failed" },
        .{ 429, "Too Many Requests" },
        .{ 500, "Internal Server Error" },
        .{ 501, "Not Implemented" },
        .{ 502, "Bad Gateway" },
        .{ 503, "Service Unavailable" },
        .{ 504, "Gateway Timeout" },
    };
    for (entries) |entry| {
        table[entry[0]] = StatusLine.comptimeFor(entry[0], entry[1]);
    }
    break :blk table;
};

/// Write pre-formatted status line via lookup table, falling back to bufPrint.
pub inline fn writeStatusLine(buf: []u8, status: u16) !usize {
    if (status < status_line_table.len) {
        if (status_line_table[status]) |sl| {
            if (sl.bytes.len > buf.len) return error.NoSpaceLeft;
            @memcpy(buf[0..sl.bytes.len], sl.bytes);
            return sl.bytes.len;
        }
    }
    // Fallback for unknown status codes
    const reason = reasonPhrase(status);
    const line = try std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\n", .{ status, reason });
    return line.len;
}

/// Fast header write: "Name: Value\r\n" via @memcpy (no format string parsing).
pub inline fn writeHeader(buf: []u8, name: []const u8, value: []const u8) !usize {
    const needed = name.len + 2 + value.len + 2; // ": " + "\r\n"
    if (needed > buf.len) return error.NoSpaceLeft;
    @memcpy(buf[0..name.len], name);
    var pos = name.len;
    buf[pos] = ':';
    buf[pos + 1] = ' ';
    pos += 2;
    @memcpy(buf[pos..][0..value.len], value);
    pos += value.len;
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    return pos + 2;
}

/// Fast usize-to-ASCII into buf, returns slice written.
pub inline fn writeUsize(buf: []u8, value: usize) !usize {
    if (value == 0) {
        if (buf.len < 1) return error.NoSpaceLeft;
        buf[0] = '0';
        return 1;
    }
    // Write digits in reverse, then flip
    var tmp: [20]u8 = undefined; // max u64 is 20 digits
    var len: usize = 0;
    var v = value;
    while (v > 0) {
        tmp[len] = @intCast((v % 10) + '0');
        len += 1;
        v /= 10;
    }
    if (len > buf.len) return error.NoSpaceLeft;
    // Reverse into output
    for (0..len) |i| {
        buf[i] = tmp[len - 1 - i];
    }
    return len;
}

/// Unified response encoder. When include_body is true, appends body bytes after headers.
pub fn encodeResponseInner(buf: []u8, status: u16, headers: []const response_mod.Header, body_len: usize, body_bytes: []const u8, alt_svc: ?[]const u8, connection_close: bool, date_str: []const u8, include_body: bool) !usize {
    var index: usize = 0;

    // Status line
    index += try writeStatusLine(buf[index..], status);

    // RFC 9110 §15.2: 1xx responses have no body, no Date, no Content-Length
    if (status >= 100 and status < 200) {
        if (index + 2 > buf.len) return error.NoSpaceLeft;
        buf[index] = '\r';
        buf[index + 1] = '\n';
        return index + 2;
    }

    // Response headers
    for (headers) |header| {
        if (!isValidHeaderBytes(header.name) or !isValidHeaderBytes(header.value)) continue;
        index += try writeHeader(buf[index..], header.name, header.value);
    }

    // Date header
    const date_total = date_prefix.len + date_str.len + crlf.len;
    if (index + date_total > buf.len) return error.NoSpaceLeft;
    @memcpy(buf[index..][0..date_prefix.len], date_prefix);
    index += date_prefix.len;
    @memcpy(buf[index..][0..date_str.len], date_str);
    index += date_str.len;
    buf[index] = '\r';
    buf[index + 1] = '\n';
    index += 2;

    // Alt-Svc header
    if (alt_svc) |svc| {
        if (svc.len > 0) {
            const svc_total = alt_svc_prefix.len + svc.len + crlf.len;
            if (index + svc_total > buf.len) return error.NoSpaceLeft;
            @memcpy(buf[index..][0..alt_svc_prefix.len], alt_svc_prefix);
            index += alt_svc_prefix.len;
            @memcpy(buf[index..][0..svc.len], svc);
            index += svc.len;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            index += 2;
        }
    }

    // Connection: close
    if (connection_close) {
        if (index + connection_close_hdr.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[index..][0..connection_close_hdr.len], connection_close_hdr);
        index += connection_close_hdr.len;
    }

    // RFC 9110 §8.6: MUST NOT send Content-Length in 204 or 304 responses
    if (status == 204 or status == 304) {
        if (index + 2 > buf.len) return error.NoSpaceLeft;
        buf[index] = '\r';
        buf[index + 1] = '\n';
        return index + 2;
    }

    // Content-Length + header terminator
    if (index + content_length_prefix.len > buf.len) return error.NoSpaceLeft;
    @memcpy(buf[index..][0..content_length_prefix.len], content_length_prefix);
    index += content_length_prefix.len;
    index += try writeUsize(buf[index..], body_len);
    // "\r\n\r\n" terminates headers
    if (index + 4 > buf.len) return error.NoSpaceLeft;
    buf[index] = '\r';
    buf[index + 1] = '\n';
    buf[index + 2] = '\r';
    buf[index + 3] = '\n';
    index += 4;

    // Body (for small, inline responses)
    if (include_body) {
        if (index + body_bytes.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[index..][0..body_bytes.len], body_bytes);
        index += body_bytes.len;
    }

    return index;
}

pub fn encodeResponse(buf: []u8, resp: response_mod.Response, alt_svc: ?[]const u8, connection_close: bool, date_str: []const u8) !usize {
    const body_bytes = resp.bodyBytes();
    return encodeResponseInner(buf, resp.status, resp.headers, body_bytes.len, body_bytes, alt_svc, connection_close, date_str, true);
}

pub fn encodeResponseHeaders(buf: []u8, resp: response_mod.Response, alt_svc: ?[]const u8, connection_close: bool, date_str: []const u8) !usize {
    const body_len = resp.bodyLen();
    return encodeResponseInner(buf, resp.status, resp.headers, body_len, "", alt_svc, connection_close, date_str, false);
}

/// Encode HTTP/1.1 response headers for file responses (doesn't add Content-Length)
pub fn encodeFileHeaders(buf: []u8, status: u16, headers: []const response_mod.Header, date_str: []const u8) !usize {
    var index: usize = 0;

    index += try writeStatusLine(buf[index..], status);

    for (headers) |header| {
        if (!isValidHeaderBytes(header.name) or !isValidHeaderBytes(header.value)) continue;
        index += try writeHeader(buf[index..], header.name, header.value);
    }

    // Date header
    const date_total = date_prefix.len + date_str.len + crlf.len;
    if (index + date_total > buf.len) return error.NoSpaceLeft;
    @memcpy(buf[index..][0..date_prefix.len], date_prefix);
    index += date_prefix.len;
    @memcpy(buf[index..][0..date_str.len], date_str);
    index += date_str.len;
    buf[index] = '\r';
    buf[index + 1] = '\n';
    index += 2;

    // End headers
    if (index + 2 > buf.len) return error.NoSpaceLeft;
    buf[index] = '\r';
    buf[index + 1] = '\n';
    return index + 2;
}

pub fn reasonPhrase(status: u16) []const u8 {
    return response_mod.statusPhrase(status);
}
