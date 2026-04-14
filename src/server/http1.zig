//! # HTTP/1.1 response + body + dispatch path
//!
//! Two distinct responsibilities sit in this module:
//!
//!   1. **Wire-format primitives** (top of the file) — the pure
//!      stateless encoders used by every h1 write path: status
//!      line emission, header encoding, the unified
//!      `encodeResponseInner`, and the three facing encoders
//!      (`encodeResponse`, `encodeResponseHeaders`,
//!      `encodeFileHeaders`). No allocator, no Server pointer.
//!      `server/preencoded.zig` uses these directly when rebuilding
//!      cache entries.
//!   2. **Connection-level dispatch** (bottom of the file) —
//!      `queueResponse` (the main h1 response enqueuer),
//!      `streamBodyChunks` (write-queue-bounded body chunking),
//!      `queueFileResponse` (static file sendfile setup), the
//!      body-accumulation state machine (`initBodyAccumulation`,
//!      `continueBodyAccumulation`, `dispatchWithAccumulatedBody`,
//!      `cleanupBodyAccumulation`, `abortBodyAccumulation`,
//!      `materializePendingBody`, `appendBodyData`, `bodyComplete`),
//!      and the router-dispatch helper (`dispatchToRouter`). These
//!      take `server: *Server` as their first parameter and touch
//!      Server fields (io, proxy, app_router, allocator) directly.
//!
//! The h1 *read* path still lives in `server.zig` (inside
//! `handleRead`) because it interleaves with h2 preface sniffing
//! and TLS routing. After Extract 7 the read side moves to
//! `server/dispatch.zig` and this module becomes the complete h1
//! surface.

const std = @import("std");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const connection = @import("../runtime/connection.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");
const response_mod = @import("../response/response.zig");
const request = @import("../protocol/request.zig");
const http1_proto = @import("../protocol/http1.zig");
const router = @import("../router/router.zig");
const middleware = @import("../middleware/middleware.zig");
const forward_mod = @import("../proxy/forward.zig");
const clock = @import("../runtime/clock.zig");
const preencoded = @import("preencoded.zig");

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

// ==================== Small response helpers ====================

pub fn continueResponse() response_mod.Response {
    return .{
        .status = 100,
        .headers = &[_]response_mod.Header{},
        .body = .none,
    };
}

pub fn errorResponseFor(code: http1_proto.ErrorCode) response_mod.Response {
    return switch (code) {
        .body_too_large => .{
            .status = 413,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Payload Too Large\n" },
        },
        .header_too_large => .{
            .status = 431,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Request Header Fields Too Large\n" },
        },
        .expectation_failed => .{
            .status = 417,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Expectation Failed\n" },
        },
        else => .{
            .status = 400,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Bad Request\n" },
        },
    };
}

// ==================== queueResponse ====================

pub fn queueResponse(server: *Server, conn: *connection.Connection, resp: response_mod.Response) !void {
    // Fast path: for common error statuses (404, 400, 405, 501)
    // with simple static bodies, serve pre-encoded bytes directly.
    // This skips encodeResponseHeaders, Date formatting, and the
    // Alt-Svc header entirely — just a memcpy into the write buf.
    // The error-handling benchmark is 80% error responses; this
    // turns them into the same speed as pre-encoded /health hits.
    //
    // Match criteria: non-close connection, body is .bytes or .none
    // (no managed/scattered body), and status in the error cache.
    // We don't check headers.len — the pre-encoded template
    // includes its own headers (Content-Type etc.).
    if (!conn.close_after_write) {
        const is_simple_body = switch (resp.body) {
            .bytes, .none => true,
            else => false,
        };
        if (is_simple_body) {
            if (preencoded.findPreencodedError(server, resp.status)) |entry| {
                if (preencoded.sendH1PreencodedBytes(server, conn, entry.bytes[0..entry.len])) return;
                // Pool exhausted — fall through to the normal encode path
                // which also acquires a buffer. If that also fails, the
                // connection is closed there (existing behavior).
            }
        }
    }

    const body_len = resp.bodyLen();
    const body_bytes = resp.bodyBytes();
    const managed_body = switch (resp.body) {
        .managed => |managed| managed,
        else => null,
    };
    const scattered_body = switch (resp.body) {
        .scattered => |sc| sc,
        else => null,
    };
    const date_str = server.getCachedDate();
    // RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body
    const suppress_body = conn.is_head_request;
    const buf = server.io.acquireBuffer() orelse {
        // Cannot acquire buffer to send response - close connection
        if (managed_body) |managed| server.io.releaseBuffer(managed.handle);
        if (scattered_body) |sc| {
            for (sc.handles[0..sc.count]) |h| server.io.releaseBuffer(h);
        }
        server.closeConnection(conn);
        return;
    };
    // Include Alt-Svc header to advertise HTTP/3 when QUIC is enabled
    const alt_svc: ?[]const u8 = if (server.alt_svc_len > 0)
        server.alt_svc_value[0..server.alt_svc_len]
    else
        null;

    if (managed_body) |managed| {
        if (body_len > managed.handle.bytes.len) {
            server.io.releaseBuffer(managed.handle);
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        }
        const managed_bytes = managed.handle.bytes[0..body_len];

        // Try to fit headers + body in a single buffer for one write() syscall
        const header_space = 512;
        if (!suppress_body and body_len > 0 and body_len <= buf.bytes.len - header_space) {
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
                server.io.releaseBuffer(managed.handle);
                server.io.releaseBuffer(buf);
                server.closeConnection(conn);
                return;
            };
            if (header_len + body_len <= buf.bytes.len) {
                // Copy body into header buffer — single write
                @memcpy(buf.bytes[header_len .. header_len + body_len], managed_bytes);
                server.io.releaseBuffer(managed.handle);
                if (!conn.enqueueWrite(buf, header_len + body_len)) {
                    server.io.releaseBuffer(buf);
                    server.closeConnection(conn);
                    return;
                }
                server.io.onWriteBuffered(conn, header_len + body_len);
                server.io.setTimeoutPhase(conn, .write);
                return;
            }
        }

        // Fallback: headers and body as separate writes
        const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
            server.io.releaseBuffer(managed.handle);
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        };
        if (!conn.enqueueWrite(buf, header_len)) {
            server.io.releaseBuffer(managed.handle);
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, header_len);

        if (body_len == 0 or suppress_body) {
            server.io.releaseBuffer(managed.handle);
            server.io.setTimeoutPhase(conn, .write);
            return;
        }
        if (!conn.enqueueWrite(managed.handle, body_len)) {
            server.io.releaseBuffer(managed.handle);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, body_len);
        server.io.setTimeoutPhase(conn, .write);
        return;
    }

    // Scattered body: enqueue pre-allocated pool buffers directly (zero-copy echo)
    if (scattered_body) |sc| {
        const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
            for (sc.handles[0..sc.count]) |h| server.io.releaseBuffer(h);
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        };
        if (!conn.enqueueWrite(buf, header_len)) {
            for (sc.handles[0..sc.count]) |h| server.io.releaseBuffer(h);
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, header_len);

        if (suppress_body or sc.count == 0) {
            for (sc.handles[0..sc.count]) |h| server.io.releaseBuffer(h);
            server.io.setTimeoutPhase(conn, .write);
            return;
        }

        // Enqueue each body buffer directly — no copy needed
        for (0..sc.count) |i| {
            const buf_len = if (i == sc.count - 1) sc.last_buf_len else sc.buffer_size;
            if (!conn.enqueueWrite(sc.handles[i], buf_len)) {
                // Can't enqueue — release remaining buffers and close
                for (i..sc.count) |j| server.io.releaseBuffer(sc.handles[j]);
                server.closeConnection(conn);
                return;
            }
            server.io.onWriteBuffered(conn, buf_len);
        }
        server.io.setTimeoutPhase(conn, .write);
        return;
    }

    if (suppress_body) {
        // HEAD: send headers with Content-Length but no body
        const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        };
        if (!conn.enqueueWrite(buf, header_len)) {
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, header_len);
        server.io.setTimeoutPhase(conn, .write);
        return;
    }

    // For large bodies that don't fit in a single buffer, write headers first then chunk body
    const header_space = 512; // Reserve space for headers
    if (body_len > buf.bytes.len - header_space) {
        // Write headers only first
        const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        };
        if (!conn.enqueueWrite(buf, header_len)) {
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, header_len);

        // Stream body in chunks - only enqueue what fits, store rest for later
        streamBodyChunks(server, conn, body_bytes);
        server.io.setTimeoutPhase(conn, .write);
        return;
    }

    // Small response - write everything in one buffer
    const written = encodeResponse(buf.bytes, resp, alt_svc, conn.close_after_write, date_str) catch {
        // Cannot encode response - close connection
        server.io.releaseBuffer(buf);
        server.closeConnection(conn);
        return;
    };
    if (!conn.enqueueWrite(buf, written)) {
        server.io.releaseBuffer(buf);
        server.closeConnection(conn);
        return;
    }
    server.io.onWriteBuffered(conn, written);
    server.io.setTimeoutPhase(conn, .write);
}

/// Stream body data in chunks, enqueueing up to available queue slots.
/// Remaining data is stored in conn.pending_body for later streaming.
///
/// LIFETIME CONTRACT: `body` (and thus `conn.pending_body`) must point to
/// memory that outlives the connection — typically compile-time string literals
/// from handler responses (e.g., `body = .{ .bytes = "Hello" }`). The slice is
/// never freed by the server; it is only read and copied into write buffers.
/// Managed bodies (.managed) are written inline in queueResponse and never
/// stored in pending_body.
pub fn streamBodyChunks(server: *Server, conn: *connection.Connection, body: []const u8) void {
    var remaining = body;

    // Enqueue chunks while we have queue space (leave 1 slot for new requests)
    while (remaining.len > 0 and conn.writeQueueAvailable() > 1) {
        const body_buf = server.io.acquireBuffer() orelse {
            // No buffers available - store remaining and wait
            conn.pending_body = remaining;
            return;
        };
        const chunk_len = @min(remaining.len, body_buf.bytes.len);
        @memcpy(body_buf.bytes[0..chunk_len], remaining[0..chunk_len]);
        if (!conn.enqueueWrite(body_buf, chunk_len)) {
            server.io.releaseBuffer(body_buf);
            conn.pending_body = remaining;
            return;
        }
        server.io.onWriteBuffered(conn, chunk_len);
        remaining = remaining[chunk_len..];
    }

    // Store any remaining data for continuation in handleWrite
    conn.pending_body = remaining;
}

// ==================== Static file path ====================

/// Queue a file response using sendfile for zero-copy transfer.
/// Sends HTTP headers first, then sets up the connection for sendfile.
pub fn queueFileResponse(server: *Server, conn: *connection.Connection, static_root: []const u8, file_path: []const u8, content_type: []const u8) !void {
    _ = static_root; // No longer used at request time — we use the cached dirfd.

    // Reject paths containing percent-encoded sequences to prevent URL-encoded
    // path traversal (e.g., %2e%2e bypassing the ".." check below)
    if (std.mem.indexOfScalar(u8, file_path, '%') != null) {
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    }
    // Prevent path traversal attacks — reject ".." components
    if (std.mem.indexOf(u8, file_path, "..") != null) {
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    }
    // Reject paths with null bytes
    if (std.mem.indexOfScalar(u8, file_path, 0) != null) {
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    }
    // Reject absolute paths — the root is the cached dirfd, not "/"
    if (file_path.len > 0 and file_path[0] == '/') {
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    }

    // Resolve against the cached static_root dirfd. This avoids realpath
    // on the hot path and pins the root directory against post-startup
    // renames. If static_root is unset or failed to open at init, serve 404.
    const root_fd = server.static_root_fd orelse {
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    };

    // Build null-terminated relative path.
    var path_buf: [4096]u8 = undefined;
    if (file_path.len >= path_buf.len) {
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    }
    @memcpy(path_buf[0..file_path.len], file_path);
    path_buf[file_path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);

    // Open with NOFOLLOW on the leaf. Intermediate-component symlinks
    // under static_root can still escape — operators should not place
    // arbitrary symlinks inside the static tree. Linux-only full
    // containment via openat2(RESOLVE_BENEATH) is a future enhancement.
    var o_flags: std.posix.O = .{};
    if (@hasField(std.posix.O, "NOFOLLOW")) o_flags.NOFOLLOW = true;
    const file_fd = std.posix.openatZ(root_fd, path_z, o_flags, 0) catch {
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    };

    // Get file size using lseek. Also rejects directories (can't seek on them).
    const end_pos = std.c.lseek(file_fd, 0, std.posix.SEEK.END);
    if (end_pos < 0) {
        clock.closeFd(file_fd);
        try queueResponse(server, conn, Server.notFoundResponse());
        return;
    }
    // Seek back to start for reading
    _ = std.c.lseek(file_fd, 0, std.posix.SEEK.SET);
    const file_size: u64 = @intCast(end_pos);

    // Build and send headers
    const buf = server.io.acquireBuffer() orelse {
        clock.closeFd(file_fd);
        server.closeConnection(conn);
        return;
    };

    var size_buf: [20]u8 = undefined;
    const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{file_size}) catch {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        server.closeConnection(conn);
        return;
    };

    const headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = content_type },
        .{ .name = "Content-Length", .value = size_str },
    };

    const header_len = encodeFileHeaders(buf.bytes, 200, &headers, server.getCachedDate()) catch {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        server.closeConnection(conn);
        return;
    };

    if (!conn.enqueueWrite(buf, header_len)) {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        server.closeConnection(conn);
        return;
    }
    server.io.onWriteBuffered(conn, header_len);

    // RFC 9110 §9.3.2: HEAD response sends headers with Content-Length but no body
    if (conn.is_head_request) {
        clock.closeFd(file_fd);
        server.io.setTimeoutPhase(conn, .write);
        return;
    }

    // Set up sendfile - file body will be sent after headers
    conn.pending_file_fd = file_fd;
    conn.pending_file_offset = 0;
    conn.pending_file_remaining = file_size;

    server.io.setTimeoutPhase(conn, .write);
}

pub fn bufferPendingFileWrites(server: *Server, conn: *connection.Connection) bool {
    var queued_any = false;

    while (conn.hasPendingFile() and conn.writeQueueAvailable() > 0) {
        const body_buf = server.io.acquireBuffer() orelse {
            if (!queued_any) {
                conn.cleanupPendingFile();
                server.closeConnection(conn);
            }
            return queued_any;
        };

        const max_read: usize = @intCast(@min(conn.pending_file_remaining, @as(u64, body_buf.bytes.len)));
        const read_result = std.c.pread(conn.pending_file_fd.?, body_buf.bytes.ptr, max_read, @intCast(conn.pending_file_offset));
        if (read_result < 0) {
            server.io.releaseBuffer(body_buf);
            switch (std.posix.errno(read_result)) {
                .INTR => continue,
                else => {
                    conn.cleanupPendingFile();
                    server.closeConnection(conn);
                    return queued_any;
                },
            }
        }
        const bytes_read: usize = @intCast(read_result);
        if (bytes_read == 0) {
            server.io.releaseBuffer(body_buf);
            conn.cleanupPendingFile();
            break;
        }
        if (!conn.enqueueWrite(body_buf, bytes_read)) {
            server.io.releaseBuffer(body_buf);
            return queued_any;
        }

        server.io.onWriteBuffered(conn, bytes_read);
        conn.pending_file_offset += bytes_read;
        conn.pending_file_remaining -= bytes_read;
        queued_any = true;

        if (conn.pending_file_remaining == 0) {
            conn.cleanupPendingFile();
            break;
        }
    }

    return queued_any;
}

// ==================== Body accumulation ====================

/// Initialize body accumulation for a request whose body exceeds the read buffer.
/// Allocates BodyAccumState, seeds it with any body bytes already in the read buffer,
/// and transitions the connection to body-accumulation mode.
pub fn initBodyAccumulation(
    server: *Server,
    conn: *connection.Connection,
    hparse: http1_proto.HeaderParseResult,
    buffer_handle: buffer_pool.BufferHandle,
) !void {
    conn.body_accum = .{
        .content_length = hparse.content_length,
        .is_chunked = hparse.is_chunked,
        .bytes_received = 0,
        .bytes_decoded = 0,
        .body_buffers = undefined,
        .buffer_count = 0,
        .current_buf_offset = 0,
        .chunk_decoder = http1_proto.ChunkDecoder.init(server.cfg.limits.max_body_bytes),
        .header_result = hparse,
        .original_read_buffer = null,
    };
    conn.header_count = hparse.view.headers.len;
    conn.is_head_request = (hparse.view.method == .HEAD);
    if (!hparse.keep_alive) conn.close_after_write = true;

    // Send 100-continue if client expects it
    if (hparse.expect_continue and !conn.sent_continue) {
        conn.sent_continue = true;
        try queueResponse(server, conn, continueResponse());
    }

    server.io.setTimeoutPhase(conn, .body);

    // Seed with any body bytes already in the read buffer after headers
    const start = conn.read_offset;
    const end = start + conn.read_buffered_bytes;
    const body_start = start + hparse.headers_consumed;
    if (body_start < end) {
        const body_bytes = buffer_handle.bytes[body_start..end];
        try appendBodyData(server, conn, body_bytes);
    }

    // Retain original read buffer (header slices point into it) and acquire a fresh one.
    // This prevents subsequent body reads from overwriting the header data.
    const accum = &(conn.body_accum orelse unreachable);
    accum.original_read_buffer = conn.read_buffer;
    conn.read_buffer = server.io.acquireBuffer() orelse {
        // No buffers available — abort body accumulation
        conn.read_buffer = accum.original_read_buffer;
        accum.original_read_buffer = null;
        return error.OutOfMemory;
    };
    conn.read_offset = 0;
    conn.read_buffered_bytes = 0;

    // Check if body is already complete
    if (bodyComplete(conn)) {
        try dispatchWithAccumulatedBody(server, conn);
    }
}

/// Continue accumulating body data from the read buffer into body buffers.
pub fn continueBodyAccumulation(server: *Server, conn: *connection.Connection) !void {
    const buffer_handle = conn.read_buffer orelse return;
    const start = conn.read_offset;
    const end = start + conn.read_buffered_bytes;
    if (end <= start) return;

    const data = buffer_handle.bytes[start..end];
    try appendBodyData(server, conn, data);
    server.io.onReadConsumed(conn, data.len);

    if (bodyComplete(conn)) {
        try dispatchWithAccumulatedBody(server, conn);
    }
}

/// Append raw body data into body accumulator buffers.
fn appendBodyData(server: *Server, conn: *connection.Connection, data: []u8) !void {
    const accum = &(conn.body_accum orelse return);
    var remaining = data;

    if (accum.is_chunked) {
        // Feed through chunk decoder
        while (remaining.len > 0 and !accum.chunk_decoder.isDone()) {
            // Ensure we have a destination buffer
            if (accum.buffer_count == 0 or accum.current_buf_offset >= server.io.bodyBufferSize()) {
                if (accum.buffer_count >= connection.BodyAccumState.MAX_BODY_BUFFERS) {
                    return error.BodyTooLarge;
                }
                const buf = server.io.acquireBodyBuffer() orelse return error.OutOfMemory;
                accum.body_buffers[accum.buffer_count] = buf;
                accum.buffer_count += 1;
                accum.current_buf_offset = 0;
            }
            const cur_buf = accum.body_buffers[accum.buffer_count - 1];
            const dst = cur_buf.bytes[accum.current_buf_offset..];
            const result = accum.chunk_decoder.feed(remaining, dst) catch |err| {
                return switch (err) {
                    error.BodyTooLarge => error.BodyTooLarge,
                    error.InvalidChunk => error.InvalidRequest,
                };
            };
            accum.current_buf_offset += result.decoded;
            accum.bytes_decoded += result.decoded;
            remaining = remaining[result.consumed..];
            accum.bytes_received += result.consumed;
        }
    } else {
        // Content-Length: raw copy
        while (remaining.len > 0) {
            const left = accum.content_length - accum.bytes_received;
            if (left == 0) break;
            const to_consume = @min(remaining.len, left);

            // Ensure we have a destination buffer
            if (accum.buffer_count == 0 or accum.current_buf_offset >= server.io.bodyBufferSize()) {
                if (accum.buffer_count >= connection.BodyAccumState.MAX_BODY_BUFFERS) {
                    return error.BodyTooLarge;
                }
                const buf = server.io.acquireBodyBuffer() orelse return error.OutOfMemory;
                accum.body_buffers[accum.buffer_count] = buf;
                accum.buffer_count += 1;
                accum.current_buf_offset = 0;
            }
            const cur_buf = accum.body_buffers[accum.buffer_count - 1];
            const dst = cur_buf.bytes[accum.current_buf_offset..];
            const copy_len = @min(to_consume, dst.len);
            @memcpy(dst[0..copy_len], remaining[0..copy_len]);
            accum.current_buf_offset += copy_len;
            accum.bytes_received += copy_len;
            accum.bytes_decoded += copy_len;
            remaining = remaining[copy_len..];
        }
    }
}

/// Check if body accumulation is complete.
fn bodyComplete(conn: *connection.Connection) bool {
    const accum = conn.body_accum orelse return false;
    if (accum.is_chunked) {
        return accum.chunk_decoder.isDone();
    }
    return accum.bytes_received >= accum.content_length;
}

/// Dispatch a request with accumulated body data to handler/proxy.
pub fn dispatchWithAccumulatedBody(server: *Server, conn: *connection.Connection) !void {
    const accum = &(conn.body_accum orelse return);
    const hparse = accum.header_result;
    const fd = conn.fd orelse return;

    // Build BodyView from accumulated buffers
    const body_view = forward_mod.BodyView{
        .buffers = .{
            .handles = accum.body_buffers[0..accum.buffer_count],
            .last_buf_len = accum.current_buf_offset,
            .total_len = accum.bytes_decoded,
            .buffer_size = server.io.bodyBufferSize(),
        },
    };

    // Check proxy routes first
    if (server.proxy) |proxy| {
        if (proxy.matchRoute(&hparse.view) != null) {
            var mw_ctx = middleware.Context{
                .protocol = .http1,
                .buffer_ops = .{
                    .ctx = &server.io,
                    .acquire = server_mod.acquireBufferOpaque,
                    .release = server_mod.releaseBufferOpaque,
                },
            };
            var ip_buf: [64]u8 = undefined;
            var client_ip_str: ?[]const u8 = null;
            if (conn.cached_peer_ip) |ip4| {
                const ip_len = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                if (ip_len.len > 0) client_ip_str = ip_buf[0..ip_len.len];
            }
            var proxy_result = proxy.handleWithBody(
                hparse.view,
                body_view,
                &mw_ctx,
                client_ip_str,
                false,
                server.io.nowMs(),
            );
            defer proxy_result.release();

            cleanupBodyAccumulation(server, conn);
            try queueResponse(server, conn, proxy_result.resp);
            // Materialize pending_body before proxy_result.release() frees the upstream buffer
            if (conn.pending_body.len > 0) {
                materializePendingBody(server, conn);
            }
            return;
        }
    }

    // Handler path: linearize body into contiguous allocation
    const total_len = accum.bytes_decoded;
    if (total_len > 0) {
        const buffer_count = accum.buffer_count;
        const last_buf_len = accum.current_buf_offset;
        const buffer_size = server.io.bodyBufferSize();

        const body_mem = server.allocator.alloc(u8, total_len) catch {
            abortBodyAccumulation(server, conn, 503);
            return;
        };

        // Copy from body buffers into contiguous memory
        var copied: usize = 0;
        for (0..buffer_count) |i| {
            const handle = accum.body_buffers[i];
            const buf_len = if (i == buffer_count - 1)
                last_buf_len
            else
                buffer_size;
            @memcpy(body_mem[copied .. copied + buf_len], handle.bytes[0..buf_len]);
            copied += buf_len;
        }

        // Build RequestView with body
        const req_view = request.RequestView{
            .method = hparse.view.method,
            .method_raw = hparse.view.method_raw,
            .path = hparse.view.path,
            .headers = hparse.view.headers,
            .body = body_mem[0..total_len],
        };

        if (!server.isAllowedHost(req_view)) {
            conn.close_after_write = true;
            cleanupBodyAccumulation(server, conn);
            queueResponse(server, conn, Server.badRequestResponse()) catch {};
            server.allocator.free(body_mem);
            return;
        }

        // Dispatch to router, but check result before queueing to detect echo responses
        // that can use scattered body buffers instead of re-copying.
        var mw_ctx = middleware.Context{
            .protocol = .http1,
            .buffer_ops = .{
                .ctx = &server.io,
                .acquire = server_mod.acquireBufferOpaque,
                .release = server_mod.releaseBufferOpaque,
            },
        };
        if (conn.cached_peer_ip) |ip4| {
            mw_ctx.client_ip = ip4;
        } else if (conn.cached_peer_ip6) |ip6| {
            mw_ctx.client_ip6 = ip6;
        }
        var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
        var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
        const arena_handle = server.io.acquireBuffer();
        var empty_arena: [0]u8 = undefined;
        const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
        var scratch = router.HandlerScratch{
            .response_buf = response_buf[0..],
            .response_headers = response_headers[0..],
            .arena_buf = arena_buf,
            .arena_handle = arena_handle,
            .buffer_ops = mw_ctx.buffer_ops,
        };
        const result = server.app_router.handle(req_view, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
        if (result.pause_reads_ms) |pause_ms| {
            conn.setRateLimitPause(server.io.nowMs(), pause_ms);
        }

        // Previously a zero-copy echo path transferred body buffers
        // to the write queue as a scattered response. Disabled now
        // that body buffers are from a separate pool with different
        // size — the transfer would require per-handle pool tagging.
        // The echo case still works via the normal copy path below.
        {
            // Non-echo response: cleanup body buffers and queue normally
            cleanupBodyAccumulation(server, conn);
            queueResponse(server, conn, result.resp) catch {};
            if (conn.pending_body.len > 0) {
                materializePendingBody(server, conn);
            }
            server.allocator.free(body_mem);
        }
    } else {
        cleanupBodyAccumulation(server, conn);
        dispatchToRouter(server, conn, hparse.view, fd);
    }
}

/// Dispatch a fully-formed request to the router (extracted for reuse).
pub fn dispatchToRouter(server: *Server, conn: *connection.Connection, req_view: request.RequestView, _: std.posix.fd_t) void {
    if (!server.isAllowedHost(req_view)) {
        conn.close_after_write = true;
        queueResponse(server, conn, Server.badRequestResponse()) catch {};
        return;
    }

    // Fast path: pre-encoded h1 response cache.
    if (preencoded.tryDispatchPreencodedH1(server, conn, req_view) == .dispatched) return;

    var mw_ctx = middleware.Context{
        .protocol = .http1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = server_mod.acquireBufferOpaque,
            .release = server_mod.releaseBufferOpaque,
        },
    };
    // Use cached client IP for rate limiting and logging
    if (conn.cached_peer_ip) |ip4| {
        mw_ctx.client_ip = ip4;
    } else if (conn.cached_peer_ip6) |ip6| {
        mw_ctx.client_ip6 = ip6;
    }
    var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const arena_handle = server.io.acquireBuffer();
    var empty_arena: [0]u8 = undefined;
    const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
    var scratch = router.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf,
        .arena_handle = arena_handle,
        .buffer_ops = mw_ctx.buffer_ops,
    };
    const result = server.app_router.handle(req_view, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    if (result.pause_reads_ms) |pause_ms| {
        conn.setRateLimitPause(server.io.nowMs(), pause_ms);
    }
    queueResponse(server, conn, result.resp) catch {};
}

/// Release all acquired body buffers and free BodyAccumState.
pub fn cleanupBodyAccumulation(server: *Server, conn: *connection.Connection) void {
    if (conn.body_accum) |*accum| {
        for (0..accum.buffer_count) |i| {
            server.io.releaseBodyBuffer(accum.body_buffers[i]);
        }
        // The original read buffer is from the hot-path pool
        if (accum.original_read_buffer) |buf| {
            server.io.releaseBuffer(buf);
        }
        conn.body_accum = null;
    }
}

/// Copy pending_body into pool buffers so the original allocation can be freed.
/// Called when a handler response references temporary body memory (e.g., echo with
/// accumulated body). Enqueues as many chunks as the write queue allows; any overflow
/// is stored back in pending_body pointing to the new pool buffer (safe lifetime).
pub fn materializePendingBody(server: *Server, conn: *connection.Connection) void {
    // Use streamBodyChunks which already copies into pool buffers and enqueues.
    // After this call, pending_body either points to a pool buffer or is empty.
    // The key insight: streamBodyChunks copies bytes into acquired pool buffers,
    // and if the write queue is full, stores 'remaining' as pending_body.
    // That 'remaining' is a subslice of the source — still pointing to body_mem.
    // We need to fully materialize everything NOW.
    var remaining = conn.pending_body;
    conn.pending_body = &[_]u8{};

    while (remaining.len > 0) {
        const body_buf = server.io.acquireBuffer() orelse {
            // Out of buffers — drop remaining data, close after current writes
            conn.close_after_write = true;
            return;
        };
        const chunk_len = @min(remaining.len, body_buf.bytes.len);
        @memcpy(body_buf.bytes[0..chunk_len], remaining[0..chunk_len]);
        if (!conn.enqueueWrite(body_buf, chunk_len)) {
            // Write queue full — this chunk is in a pool buffer but can't be enqueued.
            // Store the pool buffer slice as pending_body (safe lifetime — pool buffer).
            // The remaining un-copied source data is lost, but the chunk we just copied
            // will be streamed via handleWrite → streamBodyChunks later.
            server.io.releaseBuffer(body_buf);
            conn.close_after_write = true;
            return;
        }
        server.io.onWriteBuffered(conn, chunk_len);
        remaining = remaining[chunk_len..];
    }
}

/// Abort body accumulation with an error response, then close.
pub fn abortBodyAccumulation(server: *Server, conn: *connection.Connection, status: u16) void {
    cleanupBodyAccumulation(server, conn);
    conn.close_after_write = true;
    const resp: response_mod.Response = .{
        .status = status,
        .headers = &[_]response_mod.Header{},
        .body = .{ .bytes = if (status == 413) "Payload Too Large\n" else "Bad Request\n" },
    };
    queueResponse(server, conn, resp) catch {};
}
