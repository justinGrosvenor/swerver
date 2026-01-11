const std = @import("std");
const request = @import("request.zig");

pub const ParseState = enum {
    complete,
    partial,
    err,
};

pub const ParseResult = struct {
    state: ParseState,
    view: request.RequestView,
    error_code: ErrorCode,
    consumed_bytes: usize,
    keep_alive: bool,
    expect_continue: bool,
};

pub const ErrorCode = enum {
    none,
    invalid_method,
    invalid_header,
    invalid_request_line,
    invalid_version,
    missing_host,
    invalid_header_name,
    invalid_header_value,
    invalid_content_length,
    unsupported_transfer_encoding,
    invalid_chunked_body,
    body_too_large,
    header_too_large,
};

pub fn parse(_bytes: []u8, _limits: Limits) ParseResult {
    if (_limits.headers_storage.len < _limits.max_header_count) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .header_too_large,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    }
    const header_end = std.mem.indexOf(u8, _bytes, "\r\n\r\n") orelse {
        return .{
            .state = .partial,
            .view = emptyView(),
            .error_code = .none,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    };
    if (header_end + 4 > _limits.max_header_bytes) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .header_too_large,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    }
    const line_end = std.mem.indexOfPos(u8, _bytes, 0, "\r\n") orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    };
    const line = _bytes[0..line_end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    };
    const second_space = std.mem.indexOfScalarPos(u8, line, first_space + 1, ' ') orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    };
    const method = line[0..first_space];
    const request_target = line[first_space + 1 .. second_space];
    const version = line[second_space + 1 ..];
    var keep_alive = true;
    if (std.mem.eql(u8, version, "HTTP/1.1")) {
        keep_alive = true;
    } else if (std.mem.eql(u8, version, "HTTP/1.0")) {
        keep_alive = false;
    } else {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_version,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    }
    if (header_end + 4 > _bytes.len) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_header,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    }
    if (!isToken(method)) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_method,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    }
    if (request_target.len == 0) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    }
    var path: []const u8 = request_target;
    var host_in_target = false;
    if (request_target[0] == '/') {
        path = request_target;
    } else if (request_target[0] == '*') {
        if (!std.mem.eql(u8, method, "OPTIONS")) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_request_line,
                .consumed_bytes = 0,
                .keep_alive = keep_alive,
                .expect_continue = false,
            };
        }
        path = request_target;
    } else if (std.mem.indexOf(u8, request_target, "://")) |scheme_end| {
        const authority_start = scheme_end + 3;
        if (authority_start >= request_target.len) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_request_line,
                .consumed_bytes = 0,
                .keep_alive = keep_alive,
                .expect_continue = false,
            };
        }
        const path_start = std.mem.indexOfScalarPos(u8, request_target, authority_start, '/') orelse request_target.len;
        if (path_start == authority_start) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_request_line,
                .consumed_bytes = 0,
                .keep_alive = keep_alive,
                .expect_continue = false,
            };
        }
        host_in_target = true;
        if (path_start < request_target.len) {
            path = request_target[path_start..];
        } else {
            path = "/";
        }
    } else if (std.mem.eql(u8, method, "CONNECT")) {
        if (std.mem.indexOfScalar(u8, request_target, ':') == null) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_request_line,
                .consumed_bytes = 0,
                .keep_alive = keep_alive,
                .expect_continue = false,
            };
        }
        path = request_target;
        host_in_target = true;
    } else {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .consumed_bytes = 0,
            .keep_alive = keep_alive,
            .expect_continue = false,
        };
    }
    var header_count: usize = 0;
    var content_length: usize = 0;
    var has_content_length = false;
    var host_present = false;
    var is_chunked = false;
    var expect_continue = false;
    var pos = line_end + 2;
    while (pos < header_end) {
        const next = std.mem.indexOfPos(u8, _bytes, pos, "\r\n") orelse break;
        const header_line = _bytes[pos..next];
        if (header_line.len == 0) break;
        if (header_line[0] == ' ' or header_line[0] == '\t') {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_header_value,
                .consumed_bytes = 0,
                .keep_alive = true,
                .expect_continue = false,
            };
        }
        const colon = std.mem.indexOfScalar(u8, header_line, ':') orelse {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_header,
                .consumed_bytes = 0,
                .keep_alive = true,
                .expect_continue = false,
            };
        };
        const name = header_line[0..colon];
        var value: []const u8 = header_line[colon + 1 ..];
        // RFC 7230 Section 3.2.4: OWS should be trimmed from both ends
        value = std.mem.trim(u8, value, " \t");
        if (header_count >= _limits.max_header_count) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .header_too_large,
                .consumed_bytes = 0,
                .keep_alive = true,
                .expect_continue = false,
            };
        }
        if (!isToken(name)) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_header_name,
                .consumed_bytes = 0,
                .keep_alive = true,
                .expect_continue = false,
            };
        }
        _limits.headers_storage[header_count] = .{ .name = name, .value = value };
        header_count += 1;
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            host_present = value.len != 0;
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const parsed_len = std.fmt.parseInt(usize, value, 10) catch {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            };
            if (has_content_length and content_length != parsed_len) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
            content_length = parsed_len;
            has_content_length = true;
            if (content_length > _limits.max_body_bytes) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .body_too_large,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (std.ascii.indexOfIgnoreCase(value, "chunked") != null) {
                is_chunked = true;
            } else {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .unsupported_transfer_encoding,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "expect")) {
            if (std.ascii.indexOfIgnoreCase(value, "100-continue") != null) {
                expect_continue = true;
            } else {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_header_value,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (containsToken(value, "close")) {
                keep_alive = false;
            }
            if (containsToken(value, "keep-alive")) {
                if (std.mem.eql(u8, version, "HTTP/1.0")) keep_alive = true;
            }
        }
        pos = next + 2;
    }
    if (std.mem.eql(u8, version, "HTTP/1.1") and !host_present and !host_in_target) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .missing_host,
            .consumed_bytes = 0,
            .keep_alive = keep_alive,
            .expect_continue = false,
        };
    }
    if (is_chunked and has_content_length) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_header,
            .consumed_bytes = 0,
            .keep_alive = keep_alive,
            .expect_continue = false,
        };
    }
    const wants_body = is_chunked or (has_content_length and content_length > 0);
    if (!wants_body) expect_continue = false;
    const body_start = header_end + 4;
    if (is_chunked) {
        const scan = scanChunked(_bytes, body_start, _limits.max_body_bytes) catch |err| {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = switch (err) {
                    error.BodyTooLarge => .body_too_large,
                    else => .invalid_chunked_body,
                },
                .consumed_bytes = 0,
                .keep_alive = keep_alive,
                .expect_continue = false,
            };
        };
        if (scan == null) {
            return .{
                .state = .partial,
                .view = emptyView(),
                .error_code = .none,
                .consumed_bytes = 0,
                .keep_alive = keep_alive,
                .expect_continue = expect_continue,
            };
        }
        const chunked = decodeChunkedInPlace(_bytes, body_start) catch {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_chunked_body,
                .consumed_bytes = 0,
                .keep_alive = keep_alive,
                .expect_continue = false,
            };
        };
        const headers = _limits.headers_storage[0..header_count];
        const body = _bytes[chunked.body_start .. chunked.body_start + chunked.body_len];
        return .{
            .state = .complete,
            .view = .{
                .method = method,
                .path = path,
                .headers = headers,
                .body = body,
            },
            .error_code = .none,
            .consumed_bytes = chunked.consumed_bytes,
            .keep_alive = keep_alive,
            .expect_continue = false,
        };
    }
    const total_needed = body_start + content_length;
    if (total_needed > _bytes.len) {
        return .{
            .state = .partial,
            .view = emptyView(),
            .error_code = .none,
            .consumed_bytes = 0,
            .keep_alive = keep_alive,
            .expect_continue = expect_continue and content_length > 0,
        };
    }
    const headers = _limits.headers_storage[0..header_count];
    const body = _bytes[body_start..total_needed];
    return .{
        .state = .complete,
        .view = .{
            .method = method,
            .path = path,
            .headers = headers,
            .body = body,
        },
        .error_code = .none,
        .consumed_bytes = total_needed,
        .keep_alive = keep_alive,
        .expect_continue = false,
    };
}

pub const Limits = struct {
    max_header_bytes: usize,
    max_body_bytes: usize,
    max_header_count: usize,
    headers_storage: []request.Header,
};

fn emptyView() request.RequestView {
    return .{
        .method = "",
        .path = "",
        .headers = &[_]request.Header{},
        .body = "",
    };
}

fn isToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |ch| {
        if (!isTchar(ch)) return false;
    }
    return true;
}

fn isTchar(ch: u8) bool {
    return switch (ch) {
        '!' => true,
        '#' => true,
        '$' => true,
        '%' => true,
        '&' => true,
        '\'' => true,
        '*' => true,
        '+' => true,
        '-' => true,
        '.' => true,
        '^' => true,
        '_' => true,
        '`' => true,
        '|' => true,
        '~' => true,
        else => std.ascii.isAlphanumeric(ch),
    };
}

const ChunkedResult = struct {
    complete: bool,
    body_start: usize,
    body_len: usize,
    consumed_bytes: usize,
};

fn decodeChunkedInPlace(buf: []u8, body_start: usize) !ChunkedResult {
    var src = body_start;
    var dst = body_start;
    var total: usize = 0;
    while (true) {
        const line_end = std.mem.indexOfPos(u8, buf, src, "\r\n") orelse return ChunkedResult{
            .complete = false,
            .body_start = body_start,
            .body_len = 0,
            .consumed_bytes = 0,
        };
        const line = buf[src..line_end];
        const size = parseChunkSize(line) catch return error.InvalidChunk;
        if (line.len == 0) return error.InvalidChunk;
        src = line_end + 2;
        if (size == 0) {
            const trailer_end = std.mem.indexOfPos(u8, buf, src, "\r\n\r\n") orelse return ChunkedResult{
                .complete = false,
                .body_start = body_start,
                .body_len = total,
                .consumed_bytes = 0,
            };
            try validateTrailerHeaders(buf, src, trailer_end);
            return .{
                .complete = true,
                .body_start = body_start,
                .body_len = total,
                .consumed_bytes = trailer_end + 4,
            };
        }
        if (src + size + 2 > buf.len) {
            return ChunkedResult{
                .complete = false,
                .body_start = body_start,
                .body_len = total,
                .consumed_bytes = 0,
            };
        }
        if (dst != src) std.mem.copyForwards(u8, buf[dst..dst + size], buf[src..src + size]);
        dst += size;
        src += size;
        if (buf[src] != '\r' or buf[src + 1] != '\n') return error.InvalidChunk;
        src += 2;
        total += size;
    }
}

fn scanChunked(buf: []const u8, body_start: usize, max_body_bytes: usize) !?ChunkedResult {
    var src = body_start;
    var total: usize = 0;
    while (true) {
        const line_end = std.mem.indexOfPos(u8, buf, src, "\r\n") orelse return null;
        const line = buf[src..line_end];
        if (line.len == 0) return error.InvalidChunk;
        const size = parseChunkSize(line) catch return error.InvalidChunk;
        src = line_end + 2;
        if (size == 0) {
            const trailer_end = std.mem.indexOfPos(u8, buf, src, "\r\n\r\n") orelse return null;
            try validateTrailerHeaders(buf, src, trailer_end);
            return .{
                .complete = true,
                .body_start = body_start,
                .body_len = total,
                .consumed_bytes = trailer_end + 4,
            };
        }
        if (total + size > max_body_bytes) return error.BodyTooLarge;
        if (src + size + 2 > buf.len) return null;
        src += size;
        if (buf[src] != '\r' or buf[src + 1] != '\n') return error.InvalidChunk;
        src += 2;
        total += size;
    }
}

fn parseChunkSize(line: []const u8) !usize {
    const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
    const size_str = line[0..semi];
    if (size_str.len == 0) return error.InvalidChunk;
    return std.fmt.parseInt(usize, size_str, 16) catch return error.InvalidChunk;
}

fn validateTrailerHeaders(buf: []const u8, start: usize, end: usize) !void {
    var pos = start;
    if (end < start) return error.InvalidChunk;
    while (pos < end) {
        const line_end = std.mem.indexOfPos(u8, buf, pos, "\r\n") orelse return error.InvalidChunk;
        if (line_end > end) return error.InvalidChunk;
        if (line_end == pos) return error.InvalidChunk;
        const line = buf[pos..line_end];
        if (line.len == 0) return error.InvalidChunk;
        if (line[0] == ' ' or line[0] == '\t') return error.InvalidChunk;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidChunk;
        const name = line[0..colon];
        if (!isToken(name)) return error.InvalidChunk;
        pos = line_end + 2;
    }
}

/// Check if a comma-separated header value contains a specific token.
/// Tokens are compared case-insensitively and whitespace is trimmed.
fn containsToken(header_value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, header_value, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, token)) {
            return true;
        }
    }
    return false;
}
