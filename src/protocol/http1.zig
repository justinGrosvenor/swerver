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
    /// RFC 9110 §10.1.1: Expect header with unsupported expectation → 417
    expectation_failed,
};

/// Header-only parse result: returned by parseHeaders() once \r\n\r\n is found.
/// Does NOT require or validate the request body.
pub const HeaderParseResult = struct {
    state: ParseState,
    view: request.RequestView, // .body = "" (empty)
    error_code: ErrorCode,
    content_length: usize,
    is_chunked: bool,
    keep_alive: bool,
    expect_continue: bool,
    headers_consumed: usize, // bytes up to and including \r\n\r\n
};

/// Parse only the headers of an HTTP/1.1 request, returning immediately
/// after \r\n\r\n is found and headers validate. Does NOT check body presence.
pub fn parseHeaders(_bytes: []u8, _limits: Limits) HeaderParseResult {
    const result = parseHeadersInternal(_bytes, _limits);
    return result;
}

fn parseHeadersInternal(_bytes: []u8, _limits: Limits) HeaderParseResult {
    if (_limits.headers_storage.len < _limits.max_header_count) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .header_too_large,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    const header_end = std.mem.indexOf(u8, _bytes, "\r\n\r\n") orelse {
        return .{
            .state = .partial,
            .view = emptyView(),
            .error_code = .none,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    };
    if (header_end + 4 > _limits.max_header_bytes) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .header_too_large,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    const line_end = std.mem.indexOfPos(u8, _bytes, 0, "\r\n") orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    };
    const line = _bytes[0..line_end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    };
    const second_space = std.mem.indexOfScalarPos(u8, line, first_space + 1, ' ') orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    };
    const method_str = line[0..first_space];
    const request_target = line[first_space + 1 .. second_space];
    const version = line[second_space + 1 ..];
    const method = request.Method.fromStringExtended(method_str) orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_method,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    };
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
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    if (header_end + 4 > _bytes.len) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_header,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    if (request_target.len == 0) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = true,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    var path: []const u8 = request_target;
    var host_in_target = false;
    if (request_target[0] == '/') {
        path = request_target;
    } else if (request_target[0] == '*') {
        if (request_target.len != 1 or method != .OPTIONS) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_request_line,
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = keep_alive,
                .expect_continue = false,
                .headers_consumed = 0,
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
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = keep_alive,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        }
        const path_start = std.mem.indexOfScalarPos(u8, request_target, authority_start, '/') orelse request_target.len;
        if (path_start == authority_start) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_request_line,
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = keep_alive,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        }
        host_in_target = true;
        if (path_start < request_target.len) {
            path = request_target[path_start..];
        } else {
            path = "/";
        }
    } else if (method == .CONNECT) {
        if (std.mem.indexOfScalar(u8, request_target, ':') == null) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_request_line,
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = keep_alive,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        }
        path = request_target;
        host_in_target = true;
    } else {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_request_line,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = keep_alive,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    var header_count: usize = 0;
    var content_length: usize = 0;
    var has_content_length = false;
    var host_count: u8 = 0;
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
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = true,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        }
        const colon = std.mem.indexOfScalar(u8, header_line, ':') orelse {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_header,
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = true,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        };
        const name = header_line[0..colon];
        var value: []const u8 = header_line[colon + 1 ..];
        value = std.mem.trim(u8, value, " \t");
        if (header_count >= _limits.max_header_count or header_count >= _limits.headers_storage.len) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .header_too_large,
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = true,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        }
        if (!isToken(name)) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_header_name,
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = true,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        }
        if (!isValidFieldValue(value)) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_header_value,
                .content_length = 0,
                .is_chunked = false,
                .keep_alive = true,
                .expect_continue = false,
                .headers_consumed = 0,
            };
        }
        _limits.headers_storage[header_count] = .{ .name = name, .value = value };
        header_count += 1;
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            host_count += 1;
            if (host_count > 1) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_header,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (value.len == 0) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            }
            for (value) |ch| {
                if (ch < '0' or ch > '9') {
                    return .{
                        .state = .err,
                        .view = emptyView(),
                        .error_code = .invalid_content_length,
                        .content_length = 0,
                        .is_chunked = false,
                        .keep_alive = true,
                        .expect_continue = false,
                        .headers_consumed = 0,
                    };
                }
            }
            if (value.len > 1 and value[0] == '0') {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            }
            if (value.len > 19) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .body_too_large,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            }
            const parsed_len = std.fmt.parseUnsigned(usize, value, 10) catch {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            };
            if (parsed_len > _limits.max_body_bytes) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .body_too_large,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            }
            if (has_content_length and content_length != parsed_len) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            }
            content_length = parsed_len;
            has_content_length = true;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (containsToken(value, "chunked")) {
                is_chunked = true;
            } else {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .unsupported_transfer_encoding,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
                };
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "expect")) {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "100-continue")) {
                expect_continue = true;
            } else {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .expectation_failed,
                    .content_length = 0,
                    .is_chunked = false,
                    .keep_alive = true,
                    .expect_continue = false,
                    .headers_consumed = 0,
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
    if (std.mem.eql(u8, version, "HTTP/1.1") and host_count == 0 and !host_in_target) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .missing_host,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = keep_alive,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    if (is_chunked and has_content_length) {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_header,
            .content_length = 0,
            .is_chunked = false,
            .keep_alive = keep_alive,
            .expect_continue = false,
            .headers_consumed = 0,
        };
    }
    const wants_body = is_chunked or (has_content_length and content_length > 0);
    if (!wants_body) expect_continue = false;
    const headers_consumed = header_end + 4;
    const headers = _limits.headers_storage[0..header_count];
    return .{
        .state = .complete,
        .view = .{
            .method = method,
            .method_raw = method_str,
            .path = path,
            .headers = headers,
            .body = "",
        },
        .error_code = .none,
        .content_length = content_length,
        .is_chunked = is_chunked,
        .keep_alive = keep_alive,
        .expect_continue = expect_continue and content_length > 0,
        .headers_consumed = headers_consumed,
    };
}

/// Incremental chunk decoder for streaming chunked transfer encoding.
/// Dechunks data across read boundaries without requiring the entire
/// chunked body to be in memory at once.
pub const ChunkDecoder = struct {
    state: State,
    current_chunk_remaining: usize,
    total_decoded: usize,
    max_body_bytes: usize,
    size_buf: [20]u8, // partial size-line buffer
    size_buf_len: u8,
    trailer_term_pos: u3, // tracks 0-4 bytes of \r\n\r\n matched across boundaries

    pub const State = enum {
        size_line,
        data,
        data_crlf,
        trailer,
        done,
    };

    pub const FeedResult = struct {
        decoded: usize,
        consumed: usize,
    };

    pub const FeedError = error{
        InvalidChunk,
        BodyTooLarge,
    };

    pub fn init(max_body_bytes: usize) ChunkDecoder {
        return .{
            .state = .size_line,
            .current_chunk_remaining = 0,
            .total_decoded = 0,
            .max_body_bytes = max_body_bytes,
            .size_buf = undefined,
            .size_buf_len = 0,
            .trailer_term_pos = 0,
        };
    }

    /// Feed source data, decode into dst. Returns bytes decoded and consumed.
    pub fn feed(self: *ChunkDecoder, src: []const u8, dst: []u8) FeedError!FeedResult {
        var consumed: usize = 0;
        var decoded: usize = 0;

        while (consumed < src.len) {
            switch (self.state) {
                .size_line => {
                    // Accumulate until we find \r\n
                    while (consumed < src.len) {
                        const ch = src[consumed];
                        if (self.size_buf_len > 0 and self.size_buf[self.size_buf_len - 1] == '\r' and ch == '\n') {
                            // Found \r\n — parse the size line (excluding \r)
                            consumed += 1;
                            const line_len = self.size_buf_len - 1; // exclude \r
                            const line = self.size_buf[0..line_len];
                            const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
                            if (semi == 0) return error.InvalidChunk;
                            const chunk_size = std.fmt.parseInt(usize, line[0..semi], 16) catch return error.InvalidChunk;
                            self.size_buf_len = 0;
                            if (chunk_size == 0) {
                                self.state = .trailer;
                                break;
                            }
                            if (self.total_decoded + chunk_size > self.max_body_bytes) return error.BodyTooLarge;
                            self.current_chunk_remaining = chunk_size;
                            self.state = .data;
                            break;
                        }
                        if (self.size_buf_len >= self.size_buf.len) return error.InvalidChunk;
                        self.size_buf[self.size_buf_len] = ch;
                        self.size_buf_len += 1;
                        consumed += 1;
                    }
                },
                .data => {
                    const available = src.len - consumed;
                    const to_copy = @min(self.current_chunk_remaining, @min(available, dst.len - decoded));
                    if (to_copy > 0) {
                        @memcpy(dst[decoded .. decoded + to_copy], src[consumed .. consumed + to_copy]);
                        decoded += to_copy;
                        consumed += to_copy;
                        self.current_chunk_remaining -= to_copy;
                        self.total_decoded += to_copy;
                    }
                    if (self.current_chunk_remaining == 0) {
                        self.state = .data_crlf;
                    }
                    if (decoded >= dst.len or to_copy == 0) {
                        // dst full or no data available — return partial result
                        return .{ .decoded = decoded, .consumed = consumed };
                    }
                },
                .data_crlf => {
                    // Consume \r\n after chunk data
                    while (consumed < src.len) {
                        const ch = src[consumed];
                        if (self.size_buf_len == 0) {
                            if (ch != '\r') return error.InvalidChunk;
                            self.size_buf_len = 1;
                            consumed += 1;
                        } else {
                            if (ch != '\n') return error.InvalidChunk;
                            consumed += 1;
                            self.size_buf_len = 0;
                            self.state = .size_line;
                            break;
                        }
                    }
                },
                .trailer => {
                    // Consume trailer section terminated by \r\n\r\n.
                    // Uses trailer_term_pos to track partial match across buffer boundaries.
                    const terminator = "\r\n\r\n";
                    while (consumed < src.len) {
                        const ch = src[consumed];
                        consumed += 1;
                        if (ch == terminator[self.trailer_term_pos]) {
                            self.trailer_term_pos += 1;
                            if (self.trailer_term_pos == 4) {
                                self.state = .done;
                                break;
                            }
                        } else {
                            // Reset match — but check if current byte restarts the pattern
                            if (ch == '\r') {
                                self.trailer_term_pos = 1;
                            } else {
                                self.trailer_term_pos = 0;
                            }
                        }
                    }
                },
                .done => break,
            }
        }

        return .{ .decoded = decoded, .consumed = consumed };
    }

    pub fn isDone(self: *const ChunkDecoder) bool {
        return self.state == .done;
    }
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
    const method_str = line[0..first_space];
    const request_target = line[first_space + 1 .. second_space];
    const version = line[second_space + 1 ..];
    // Use extended parsing to accept any valid token method (RFC 7230 compliance)
    const method = request.Method.fromStringExtended(method_str) orelse {
        return .{
            .state = .err,
            .view = emptyView(),
            .error_code = .invalid_method,
            .consumed_bytes = 0,
            .keep_alive = true,
            .expect_continue = false,
        };
    };
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
    // Token validation is now done by Method.fromStringExtended
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
        // RFC 9112 §3.2.4: asterisk-form is exactly "*", only for OPTIONS
        if (request_target.len != 1 or method != .OPTIONS) {
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
    } else if (method == .CONNECT) {
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
    var host_count: u8 = 0;
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
        // Check both configured limit and actual storage capacity for defense-in-depth
        if (header_count >= _limits.max_header_count or header_count >= _limits.headers_storage.len) {
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
        // RFC 9110 §5.5: Reject header values containing NUL or bare CR/LF
        if (!isValidFieldValue(value)) {
            return .{
                .state = .err,
                .view = emptyView(),
                .error_code = .invalid_header_value,
                .consumed_bytes = 0,
                .keep_alive = true,
                .expect_continue = false,
            };
        }
        _limits.headers_storage[header_count] = .{ .name = name, .value = value };
        header_count += 1;
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            host_count += 1;
            // RFC 9112 §3.2: A server MUST respond with 400 if multiple Host headers
            if (host_count > 1) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_header,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            // Reject values with leading zeros, signs, or whitespace to prevent smuggling
            if (value.len == 0) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
            for (value) |ch| {
                if (ch < '0' or ch > '9') {
                    return .{
                        .state = .err,
                        .view = emptyView(),
                        .error_code = .invalid_content_length,
                        .consumed_bytes = 0,
                        .keep_alive = true,
                        .expect_continue = false,
                    };
                }
            }
            // RFC 9112 §6.3: Reject leading zeros to prevent smuggling
            if (value.len > 1 and value[0] == '0') {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
            // Reject unreasonably long digit strings to prevent overflow in parseInt
            if (value.len > 19) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .body_too_large,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
            const parsed_len = std.fmt.parseUnsigned(usize, value, 10) catch {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .invalid_content_length,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            };
            if (parsed_len > _limits.max_body_bytes) {
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .body_too_large,
                    .consumed_bytes = 0,
                    .keep_alive = true,
                    .expect_continue = false,
                };
            }
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
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            // RFC 9112 §6.1: TE value is a comma-separated list of tokens
            if (containsToken(value, "chunked")) {
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
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "100-continue")) {
                expect_continue = true;
            } else {
                // RFC 9110 §10.1.1: If expectation cannot be met, respond with 417
                return .{
                    .state = .err,
                    .view = emptyView(),
                    .error_code = .expectation_failed,
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
    if (std.mem.eql(u8, version, "HTTP/1.1") and host_count == 0 and !host_in_target) {
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
                .method_raw = method_str,
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
            .method_raw = method_str,
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
        .method = .GET,
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

/// RFC 9110 §5.5: Validate field value — reject NUL bytes and bare CR/LF.
/// Allowed: HTAB, SP, VCHAR (0x21-0x7E), obs-text (0x80-0xFF)
fn isValidFieldValue(value: []const u8) bool {
    for (value) |ch| {
        if (ch == 0) return false; // NUL
        if (ch == '\r' or ch == '\n') return false; // bare CR/LF (already split on CRLF)
    }
    return true;
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
        // Bounds check before accessing CRLF after chunk data
        if (src + 2 > buf.len) return error.InvalidChunk;
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
            // No-trailer fast path: just \r\n terminates the chunked body
            if (src + 2 <= buf.len and buf[src] == '\r' and buf[src + 1] == '\n') {
                return .{
                    .complete = true,
                    .body_start = body_start,
                    .body_len = total,
                    .consumed_bytes = src + 2,
                };
            }
            // Trailers present or incomplete — search for terminal \r\n\r\n
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

test "scanChunked: no trailers" {
    // "5\r\nhello\r\n0\r\n\r\n"
    const buf = "5\r\nhello\r\n0\r\n\r\n";
    const result = try scanChunked(buf, 0, 1024) orelse return error.UnexpectedNull;
    try std.testing.expect(result.complete);
    try std.testing.expectEqual(@as(usize, 5), result.body_len);
    try std.testing.expectEqual(@as(usize, buf.len), result.consumed_bytes);
}

test "scanChunked: with trailers" {
    const buf = "5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n";
    const result = try scanChunked(buf, 0, 1024) orelse return error.UnexpectedNull;
    try std.testing.expect(result.complete);
    try std.testing.expectEqual(@as(usize, 5), result.body_len);
    try std.testing.expectEqual(@as(usize, buf.len), result.consumed_bytes);
}

test "scanChunked: incomplete terminal returns null" {
    // Missing final \r\n — only "0\r\n" with one byte of the terminator
    const buf = "5\r\nhello\r\n0\r\n\r";
    const result = try scanChunked(buf, 0, 1024);
    try std.testing.expect(result == null);
}

test "scanChunked: zero-length body no trailers" {
    const buf = "0\r\n\r\n";
    const result = try scanChunked(buf, 0, 1024) orelse return error.UnexpectedNull;
    try std.testing.expect(result.complete);
    try std.testing.expectEqual(@as(usize, 0), result.body_len);
    try std.testing.expectEqual(@as(usize, buf.len), result.consumed_bytes);
}
