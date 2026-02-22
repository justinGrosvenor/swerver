const std = @import("std");
const request = @import("../protocol/request.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");

pub const Header = request.Header;

pub const ManagedBody = struct {
    handle: buffer_pool.BufferHandle,
    len: usize,
};

pub const Body = union(enum) {
    none,
    bytes: []const u8,
    managed: ManagedBody,
};

/// Response body type
pub const BodyType = enum {
    /// Fixed-length body with known content
    fixed,
    /// Chunked transfer encoding (HTTP/1.1)
    chunked,
    /// No body (for 204, 304, etc.)
    none,
};

/// Response represents an HTTP response that can be either fixed or streaming.
pub const Response = struct {
    status: u16,
    headers: []const Header,
    body: Body = .none,
    body_type: BodyType = .fixed,

    pub fn ok() Response {
        return .{
            .status = 200,
            .headers = &[_]Header{},
            .body = .none,
        };
    }

    pub fn noContent() Response {
        return .{
            .status = 204,
            .headers = &[_]Header{},
            .body = .none,
            .body_type = .none,
        };
    }

    pub fn notModified() Response {
        return .{
            .status = 304,
            .headers = &[_]Header{},
            .body = .none,
            .body_type = .none,
        };
    }

    pub fn bodyLen(self: Response) usize {
        return switch (self.body) {
            .none => 0,
            .bytes => |bytes| bytes.len,
            .managed => |managed| managed.len,
        };
    }

    pub fn bodyBytes(self: Response) []const u8 {
        return switch (self.body) {
            .none => "",
            .bytes => |bytes| bytes,
            .managed => |managed| managed.handle.bytes[0..managed.len],
        };
    }
};

/// HTTP status code to reason phrase
pub fn statusPhrase(code: u16) []const u8 {
    return switch (code) {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => "Unknown",
    };
}

/// ResponseWriter for building responses with streaming support.
pub const ResponseWriter = struct {
    buf: []u8,
    pos: usize = 0,
    headers_sent: bool = false,
    chunked: bool = false,

    pub fn init(buf: []u8) ResponseWriter {
        return .{ .buf = buf };
    }

    /// Write HTTP/1.1 response status line
    pub fn writeStatus(self: *ResponseWriter, status: u16) !void {
        const result = std.fmt.bufPrint(
            self.buf[self.pos..],
            "HTTP/1.1 {d} {s}\r\n",
            .{ status, statusPhrase(status) },
        ) catch return error.BufferFull;
        self.pos += result.len;
    }

    /// Write a single header, rejecting values containing control characters
    /// to prevent header injection attacks.
    pub fn writeHeader(self: *ResponseWriter, name: []const u8, value: []const u8) !void {
        // Reject header names/values with CR, LF, or null bytes
        for (name) |ch| {
            if (ch == '\r' or ch == '\n' or ch == 0) return error.InvalidHeader;
        }
        for (value) |ch| {
            if (ch == '\r' or ch == '\n' or ch == 0) return error.InvalidHeader;
        }
        const result = std.fmt.bufPrint(
            self.buf[self.pos..],
            "{s}: {s}\r\n",
            .{ name, value },
        ) catch return error.BufferFull;
        self.pos += result.len;
    }

    /// Write Content-Length header
    pub fn writeContentLength(self: *ResponseWriter, len: usize) !void {
        const result = std.fmt.bufPrint(
            self.buf[self.pos..],
            "Content-Length: {d}\r\n",
            .{len},
        ) catch return error.BufferFull;
        self.pos += result.len;
    }

    /// Start chunked transfer encoding
    pub fn startChunked(self: *ResponseWriter) !void {
        try self.writeHeader("Transfer-Encoding", "chunked");
        self.chunked = true;
    }

    /// End headers section
    pub fn endHeaders(self: *ResponseWriter) !void {
        if (self.pos + 2 > self.buf.len) return error.BufferFull;
        self.buf[self.pos] = '\r';
        self.buf[self.pos + 1] = '\n';
        self.pos += 2;
        self.headers_sent = true;
    }

    /// Write body data (for fixed-length response)
    pub fn writeBody(self: *ResponseWriter, data: []const u8) !void {
        if (self.pos + data.len > self.buf.len) return error.BufferFull;
        @memcpy(self.buf[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }

    /// Write a chunk (for chunked transfer encoding)
    pub fn writeChunk(self: *ResponseWriter, data: []const u8) !void {
        if (data.len == 0) return;

        // Chunk format: <size in hex>\r\n<data>\r\n
        const size_result = std.fmt.bufPrint(
            self.buf[self.pos..],
            "{x}\r\n",
            .{data.len},
        ) catch return error.BufferFull;
        self.pos += size_result.len;

        if (self.pos + data.len + 2 > self.buf.len) return error.BufferFull;
        @memcpy(self.buf[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
        self.buf[self.pos] = '\r';
        self.buf[self.pos + 1] = '\n';
        self.pos += 2;
    }

    /// End chunked transfer (write terminating chunk)
    pub fn endChunked(self: *ResponseWriter) !void {
        if (self.pos + 5 > self.buf.len) return error.BufferFull;
        // Terminating chunk: "0\r\n\r\n"
        self.buf[self.pos] = '0';
        self.buf[self.pos + 1] = '\r';
        self.buf[self.pos + 2] = '\n';
        self.buf[self.pos + 3] = '\r';
        self.buf[self.pos + 4] = '\n';
        self.pos += 5;
    }

    /// Get the bytes written so far
    pub fn getWritten(self: *const ResponseWriter) []const u8 {
        return self.buf[0..self.pos];
    }

    /// Write a complete Response struct
    pub fn writeResponse(self: *ResponseWriter, resp: Response) !void {
        try self.writeStatus(resp.status);

        for (resp.headers) |hdr| {
            try self.writeHeader(hdr.name, hdr.value);
        }

        const body = resp.bodyBytes();
        switch (resp.body_type) {
            .fixed => {
                try self.writeContentLength(body.len);
                try self.endHeaders();
                if (body.len > 0) {
                    try self.writeBody(body);
                }
            },
            .chunked => {
                try self.startChunked();
                try self.endHeaders();
                if (body.len > 0) {
                    try self.writeChunk(body);
                }
                try self.endChunked();
            },
            .none => {
                try self.endHeaders();
            },
        }
    }

    /// Reset writer for reuse
    pub fn reset(self: *ResponseWriter) void {
        self.pos = 0;
        self.headers_sent = false;
        self.chunked = false;
    }
};

// Tests
test "response writer basic" {
    var buf: [1024]u8 = undefined;
    var writer = ResponseWriter.init(&buf);

    try writer.writeStatus(200);
    try writer.writeHeader("Content-Type", "text/plain");
    try writer.writeContentLength(5);
    try writer.endHeaders();
    try writer.writeBody("hello");

    const expected = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqualStrings(expected, writer.getWritten());
}

test "response writer chunked" {
    var buf: [1024]u8 = undefined;
    var writer = ResponseWriter.init(&buf);

    try writer.writeStatus(200);
    try writer.writeHeader("Content-Type", "text/plain");
    try writer.startChunked();
    try writer.endHeaders();
    try writer.writeChunk("Hello");
    try writer.writeChunk(" World");
    try writer.endChunked();

    const result = writer.getWritten();

    // Verify it contains chunked encoding
    try std.testing.expect(std.mem.indexOf(u8, result, "Transfer-Encoding: chunked") != null);
    // Verify it ends with terminating chunk
    try std.testing.expect(std.mem.endsWith(u8, result, "0\r\n\r\n"));
}

test "response writer complete response" {
    var buf: [1024]u8 = undefined;
    var writer = ResponseWriter.init(&buf);

    const resp = Response{
        .status = 404,
        .headers = &[_]Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "Not Found" },
    };

    try writer.writeResponse(resp);

    const result = writer.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "HTTP/1.1 404 Not Found") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Length: 9") != null);
    try std.testing.expect(std.mem.endsWith(u8, result, "Not Found"));
}
