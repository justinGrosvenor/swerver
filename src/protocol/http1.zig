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
    invalid_path,
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
    view: request.RequestView, // .body = .empty
    error_code: ErrorCode,
    content_length: usize,
    is_chunked: bool,
    keep_alive: bool,
    expect_continue: bool,
    headers_consumed: usize, // bytes up to and including \r\n\r\n
};

/// Build an error ParseResult. `keep_alive` is explicit because some callers
/// propagate the connection's computed keep-alive onto the error response
/// (e.g. honoring `Connection: close` on a 400) while most default to true.
fn parseErr(code: ErrorCode, keep_alive: bool) ParseResult {
    return .{
        .state = .err,
        .view = emptyView(),
        .error_code = code,
        .consumed_bytes = 0,
        .keep_alive = keep_alive,
        .expect_continue = false,
    };
}

/// Build an error HeaderParseResult (see `parseErr`).
fn headerErr(code: ErrorCode, keep_alive: bool) HeaderParseResult {
    return .{
        .state = .err,
        .view = emptyView(),
        .error_code = code,
        .content_length = 0,
        .is_chunked = false,
        .keep_alive = keep_alive,
        .expect_continue = false,
        .headers_consumed = 0,
    };
}

/// Parse only the headers of an HTTP/1.1 request, returning immediately
/// after \r\n\r\n is found and headers validate. Does NOT check body presence.
pub fn parseHeaders(_bytes: []u8, _limits: Limits) HeaderParseResult {
    const result = parseHeadersInternal(_bytes, _limits);
    return result;
}

fn parseHeadersInternal(_bytes: []u8, _limits: Limits) HeaderParseResult {
    if (_limits.headers_storage.len < _limits.max_header_count) {
        return headerErr(.header_too_large, true);
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
        return headerErr(.header_too_large, true);
    }
    const line_end = std.mem.indexOfPos(u8, _bytes, 0, "\r\n") orelse {
        return headerErr(.invalid_request_line, true);
    };
    const line = _bytes[0..line_end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse {
        return headerErr(.invalid_request_line, true);
    };
    const second_space = std.mem.indexOfScalarPos(u8, line, first_space + 1, ' ') orelse {
        return headerErr(.invalid_request_line, true);
    };
    const method_str = line[0..first_space];
    if (method_str.len > 16) {
        return headerErr(.invalid_method, true);
    }
    const request_target = line[first_space + 1 .. second_space];
    // Reject paths containing control characters, non-ASCII, or
    // percent-encoded NUL (%00). RFC 9112 §3.2.1: request-target
    // must consist of visible ASCII (0x21-0x7E) plus SP in queries.
    for (request_target, 0..) |c, i| {
        if (c <= 0x1f or c == 0x7f or c >= 0x80) {
            return headerErr(.invalid_path, true);
        }
        if (c == '%' and i + 2 < request_target.len) {
            if (request_target[i + 1] == '0' and request_target[i + 2] == '0') {
                return headerErr(.invalid_path, true);
            }
        }
    }
    const version = line[second_space + 1 ..];
    const method = request.Method.fromStringExtended(method_str) orelse {
        return headerErr(.invalid_method, true);
    };
    var keep_alive = true;
    if (std.mem.eql(u8, version, "HTTP/1.1")) {
        keep_alive = true;
    } else if (std.mem.eql(u8, version, "HTTP/1.0")) {
        keep_alive = false;
    } else {
        return headerErr(.invalid_version, true);
    }
    if (header_end + 4 > _bytes.len) {
        return headerErr(.invalid_header, true);
    }
    if (request_target.len == 0) {
        return headerErr(.invalid_request_line, true);
    }
    var path: []const u8 = request_target;
    var host_in_target = false;
    if (request_target[0] == '/') {
        path = request_target;
    } else if (request_target[0] == '*') {
        if (request_target.len != 1 or method != .OPTIONS) {
            return headerErr(.invalid_request_line, keep_alive);
        }
        path = request_target;
    } else if (std.mem.indexOf(u8, request_target, "://")) |scheme_end| {
        const authority_start = scheme_end + 3;
        if (authority_start >= request_target.len) {
            return headerErr(.invalid_request_line, keep_alive);
        }
        const path_start = std.mem.indexOfScalarPos(u8, request_target, authority_start, '/') orelse request_target.len;
        if (path_start == authority_start) {
            return headerErr(.invalid_request_line, keep_alive);
        }
        host_in_target = true;
        if (path_start < request_target.len) {
            path = request_target[path_start..];
        } else {
            path = "/";
        }
    } else if (method == .CONNECT) {
        if (std.mem.indexOfScalar(u8, request_target, ':') == null) {
            return headerErr(.invalid_request_line, keep_alive);
        }
        path = request_target;
        host_in_target = true;
    } else {
        return headerErr(.invalid_request_line, keep_alive);
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
            return headerErr(.invalid_header_value, true);
        }
        const colon = std.mem.indexOfScalar(u8, header_line, ':') orelse {
            return headerErr(.invalid_header, true);
        };
        const name = header_line[0..colon];
        var value: []const u8 = header_line[colon + 1 ..];
        value = std.mem.trim(u8, value, " \t");
        if (header_count >= _limits.max_header_count or header_count >= _limits.headers_storage.len) {
            return headerErr(.header_too_large, true);
        }
        if (!isToken(name)) {
            return headerErr(.invalid_header_name, true);
        }
        if (!isValidFieldValue(value)) {
            return headerErr(.invalid_header_value, true);
        }
        _limits.headers_storage[header_count] = .{ .name = name, .value = value };
        header_count += 1;
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            host_count += 1;
            if (host_count > 1) {
                return headerErr(.invalid_header, true);
            }
            if (value.len == 0 or hasInvalidHostChar(value)) {
                return headerErr(.invalid_header_value, true);
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const parsed_len = parseContentLengthValue(value) catch {
                return headerErr(.invalid_content_length, true);
            };
            if (parsed_len > _limits.max_body_bytes) {
                return headerErr(.body_too_large, true);
            }
            if (has_content_length and content_length != parsed_len) {
                return headerErr(.invalid_content_length, true);
            }
            content_length = parsed_len;
            has_content_length = true;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (lastToken(value, "chunked")) {
                is_chunked = true;
            } else {
                return headerErr(.unsupported_transfer_encoding, true);
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "expect")) {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "100-continue")) {
                expect_continue = true;
            } else {
                return headerErr(.expectation_failed, true);
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
        return headerErr(.missing_host, keep_alive);
    }
    // RFC 9112 §6.1: Transfer-Encoding overrides Content-Length
    if (is_chunked and has_content_length) {
        has_content_length = false;
        content_length = 0;
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
            .body = .{ .slice = "" },
        },
        .error_code = .none,
        .content_length = content_length,
        .is_chunked = is_chunked,
        .keep_alive = keep_alive,
        .expect_continue = expect_continue and (content_length > 0 or is_chunked),
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
                            const size_str = line[0..semi];
                            for (size_str) |sc| {
                                if (!std.ascii.isHex(sc)) return error.InvalidChunk;
                            }
                            if (semi < line.len) {
                                validateChunkExtensions(line[semi..]) catch return error.InvalidChunk;
                            }
                            const chunk_size = std.fmt.parseInt(usize, size_str, 16) catch return error.InvalidChunk;
                            self.size_buf_len = 0;
                            if (chunk_size == 0) {
                                self.state = .trailer;
                                // The CRLF that ended the "0" size line is the
                                // first half of the blank-line terminator. Seed
                                // trailer_term_pos at 2 so a body with no
                                // trailers (just the closing CRLF remaining)
                                // completes; a real trailer line's first byte
                                // won't match terminator[2]='\r' and resets the
                                // match to scan for the full "\r\n\r\n".
                                self.trailer_term_pos = 2;
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

/// Fast request-line extraction for pre-encoded cache fast path.
/// Finds the first \r\n, extracts method + path + version, and
/// locates \r\n\r\n. Returns null if incomplete or if the request
/// has a body (Content-Length / Transfer-Encoding detected).
pub const QuickLine = struct {
    method: request.Method,
    path: []const u8,
    is_http11: bool,
    consumed: usize,
};

pub fn extractQuickLine(bytes: []const u8) ?QuickLine {
    const line_end = std.mem.indexOfPos(u8, bytes, 0, "\r\n") orelse return null;
    const line = bytes[0..line_end];
    if (line.len < 14) return null; // "GET / HTTP/1.1" minimum
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    if (first_space == 0 or first_space > 7) return null;
    const method = request.Method.fromString(line[0..first_space]) orelse return null;
    const second_space = std.mem.indexOfScalarPos(u8, line, first_space + 1, ' ') orelse return null;
    const path = line[first_space + 1 .. second_space];
    const version = line[second_space + 1 ..];
    const is_http11 = version.len == 8 and std.mem.eql(u8, version, "HTTP/1.1");
    if (!is_http11 and !(version.len == 8 and std.mem.eql(u8, version, "HTTP/1.0"))) return null;
    const header_end = std.mem.indexOfPos(u8, bytes, line_end + 2, "\r\n\r\n") orelse return null;
    const header_area = bytes[line_end + 2 .. header_end];
    // Header names are case-insensitive (RFC 9110 §5.1). A case-sensitive
    // match here would let a lowercase `content-length:` slip past the body
    // detector, leaving the body in the buffer to be parsed as the next
    // pipelined request — a request-smuggling desync on the cached-GET path.
    if (std.ascii.indexOfIgnoreCase(header_area, "content-length") != null) return null;
    if (std.ascii.indexOfIgnoreCase(header_area, "transfer-encoding") != null) return null;
    if (std.ascii.indexOfIgnoreCase(header_area, "connection") != null) return null;
    return .{
        .method = method,
        .path = path,
        .is_http11 = is_http11,
        .consumed = header_end + 4,
    };
}

pub fn parse(_bytes: []u8, _limits: Limits) ParseResult {
    if (_limits.headers_storage.len < _limits.max_header_count) {
        return parseErr(.header_too_large, true);
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
        return parseErr(.header_too_large, true);
    }
    const line_end = std.mem.indexOfPos(u8, _bytes, 0, "\r\n") orelse {
        return parseErr(.invalid_request_line, true);
    };
    const line = _bytes[0..line_end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse {
        return parseErr(.invalid_request_line, true);
    };
    const second_space = std.mem.indexOfScalarPos(u8, line, first_space + 1, ' ') orelse {
        return parseErr(.invalid_request_line, true);
    };
    const method_str = line[0..first_space];
    if (method_str.len > 16) {
        return parseErr(.invalid_method, true);
    }
    const request_target = line[first_space + 1 .. second_space];
    for (request_target, 0..) |c, i| {
        if (c <= 0x1f or c == 0x7f or c >= 0x80) {
            return parseErr(.invalid_path, true);
        }
        if (c == '%' and i + 2 < request_target.len) {
            if (request_target[i + 1] == '0' and request_target[i + 2] == '0') {
                return parseErr(.invalid_path, true);
            }
        }
    }
    const version = line[second_space + 1 ..];
    // Use extended parsing to accept any valid token method (RFC 7230 compliance)
    const method = request.Method.fromStringExtended(method_str) orelse {
        return parseErr(.invalid_method, true);
    };
    var keep_alive = true;
    if (std.mem.eql(u8, version, "HTTP/1.1")) {
        keep_alive = true;
    } else if (std.mem.eql(u8, version, "HTTP/1.0")) {
        keep_alive = false;
    } else {
        return parseErr(.invalid_version, true);
    }
    if (header_end + 4 > _bytes.len) {
        return parseErr(.invalid_header, true);
    }
    // Token validation is now done by Method.fromStringExtended
    if (request_target.len == 0) {
        return parseErr(.invalid_request_line, true);
    }
    var path: []const u8 = request_target;
    var host_in_target = false;
    if (request_target[0] == '/') {
        path = request_target;
    } else if (request_target[0] == '*') {
        // RFC 9112 §3.2.4: asterisk-form is exactly "*", only for OPTIONS
        if (request_target.len != 1 or method != .OPTIONS) {
            return parseErr(.invalid_request_line, keep_alive);
        }
        path = request_target;
    } else if (std.mem.indexOf(u8, request_target, "://")) |scheme_end| {
        const authority_start = scheme_end + 3;
        if (authority_start >= request_target.len) {
            return parseErr(.invalid_request_line, keep_alive);
        }
        const path_start = std.mem.indexOfScalarPos(u8, request_target, authority_start, '/') orelse request_target.len;
        if (path_start == authority_start) {
            return parseErr(.invalid_request_line, keep_alive);
        }
        host_in_target = true;
        if (path_start < request_target.len) {
            path = request_target[path_start..];
        } else {
            path = "/";
        }
    } else if (method == .CONNECT) {
        if (std.mem.indexOfScalar(u8, request_target, ':') == null) {
            return parseErr(.invalid_request_line, keep_alive);
        }
        path = request_target;
        host_in_target = true;
    } else {
        return parseErr(.invalid_request_line, keep_alive);
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
            return parseErr(.invalid_header_value, true);
        }
        const colon = std.mem.indexOfScalar(u8, header_line, ':') orelse {
            return parseErr(.invalid_header, true);
        };
        const name = header_line[0..colon];
        var value: []const u8 = header_line[colon + 1 ..];
        // RFC 7230 Section 3.2.4: OWS should be trimmed from both ends
        value = std.mem.trim(u8, value, " \t");
        // Check both configured limit and actual storage capacity for defense-in-depth
        if (header_count >= _limits.max_header_count or header_count >= _limits.headers_storage.len) {
            return parseErr(.header_too_large, true);
        }
        if (!isToken(name)) {
            return parseErr(.invalid_header_name, true);
        }
        // RFC 9110 §5.5: Reject header values containing NUL or bare CR/LF
        if (!isValidFieldValue(value)) {
            return parseErr(.invalid_header_value, true);
        }
        _limits.headers_storage[header_count] = .{ .name = name, .value = value };
        header_count += 1;
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            host_count += 1;
            // RFC 9112 §3.2: A server MUST respond with 400 if multiple Host headers
            if (host_count > 1) {
                return parseErr(.invalid_header, true);
            }
            if (value.len == 0 or hasInvalidHostChar(value)) {
                return parseErr(.invalid_header_value, true);
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const parsed_len = parseContentLengthValue(value) catch {
                return parseErr(.invalid_content_length, true);
            };
            if (parsed_len > _limits.max_body_bytes) {
                return parseErr(.body_too_large, true);
            }
            if (has_content_length and content_length != parsed_len) {
                return parseErr(.invalid_content_length, true);
            }
            content_length = parsed_len;
            has_content_length = true;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            // RFC 9112 §6.1: chunked must be the final transfer coding
            if (lastToken(value, "chunked")) {
                is_chunked = true;
            } else {
                return parseErr(.unsupported_transfer_encoding, true);
            }
        }
        if (std.ascii.eqlIgnoreCase(name, "expect")) {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "100-continue")) {
                expect_continue = true;
            } else {
                // RFC 9110 §10.1.1: If expectation cannot be met, respond with 417
                return parseErr(.expectation_failed, true);
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
        return parseErr(.missing_host, keep_alive);
    }
    // RFC 9112 §6.1: Transfer-Encoding overrides Content-Length
    if (is_chunked and has_content_length) {
        has_content_length = false;
        content_length = 0;
    }
    const wants_body = is_chunked or (has_content_length and content_length > 0);
    if (!wants_body) expect_continue = false;
    const body_start = header_end + 4;
    if (is_chunked) {
        const scan = scanChunked(_bytes, body_start, _limits.max_body_bytes) catch |err| {
            return parseErr(switch (err) {
                error.BodyTooLarge => .body_too_large,
                else => .invalid_chunked_body,
            }, keep_alive);
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
            return parseErr(.invalid_chunked_body, keep_alive);
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
                .body = .{ .slice = body },
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
            .expect_continue = expect_continue and (content_length > 0 or is_chunked),
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
            .body = .{ .slice = body },
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
        .body = .{ .slice = "" },
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
        // RFC 9110 §5.5: field-value = *field-content
        // field-content = field-vchar [ 1*(SP / HTAB / field-vchar) field-vchar ]
        // field-vchar = VCHAR / obs-text
        // Reject control chars (0x00-0x08, 0x0A-0x1F, 0x7F) — allow HTAB (0x09)
        if (ch < 0x20 and ch != '\t') return false;
        if (ch == 0x7f) return false;
    }
    return true;
}

fn hasInvalidHostChar(value: []const u8) bool {
    for (value) |ch| {
        if (ch == '@' or ch == '/' or ch == ',') return true;
    }
    return false;
}

/// RFC 9112 §6.3 + smuggling defense: validate and parse a Content-Length value.
/// Rejects empty, non-digit, leading-zero (except a lone "0"), signs/whitespace,
/// and over-long (>19 digit) values that could overflow. Returns the parsed
/// length or error.Invalid. The body-size limit and duplicate-header
/// consistency checks are the caller's responsibility (they need request state).
fn parseContentLengthValue(value: []const u8) error{Invalid}!usize {
    if (value.len == 0) return error.Invalid;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return error.Invalid;
    }
    if (value.len > 1 and value[0] == '0') return error.Invalid; // leading zero
    if (value.len > 19) return error.Invalid; // overflow guard for parseUnsigned
    return std.fmt.parseUnsigned(usize, value, 10) catch error.Invalid;
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
            // No-trailer fast path: just \r\n terminates (matches scanChunked)
            if (src + 2 <= buf.len and buf[src] == '\r' and buf[src + 1] == '\n') {
                return .{
                    .complete = true,
                    .body_start = body_start,
                    .body_len = total,
                    .consumed_bytes = src + 2,
                };
            }
            // Trailers present or incomplete
            const trailer_end = std.mem.indexOfPos(u8, buf, src, "\r\n\r\n") orelse {
                if (std.mem.indexOfPos(u8, buf, src, "\n")) |nl| {
                    if (nl == src or buf[nl - 1] != '\r') return error.InvalidChunk;
                }
                return ChunkedResult{
                    .complete = false,
                    .body_start = body_start,
                    .body_len = total,
                    .consumed_bytes = 0,
                };
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
            const trailer_end = std.mem.indexOfPos(u8, buf, src, "\r\n\r\n") orelse {
                // If we see bare LF (not preceded by CR), reject immediately
                // instead of waiting forever for \r\n\r\n that won't come.
                if (std.mem.indexOfPos(u8, buf, src, "\n")) |nl| {
                    if (nl == src or buf[nl - 1] != '\r') return error.InvalidChunk;
                }
                return null;
            };
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
    // RFC 9112 §7.1: chunk-size is 1*HEXDIG — reject non-hex chars
    for (size_str) |ch| {
        if (!std.ascii.isHex(ch)) return error.InvalidChunk;
    }
    // Validate chunk extensions if present
    if (semi < line.len) {
        try validateChunkExtensions(line[semi..]);
    }
    return std.fmt.parseInt(usize, size_str, 16) catch return error.InvalidChunk;
}

fn validateChunkExtensions(ext: []const u8) !void {
    // RFC 9112 §7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name [ "=" chunk-ext-val ] )
    // chunk-ext-name = token
    // chunk-ext-val = token / quoted-string
    // Reject control chars, bare CR/LF, or oversized extensions
    if (ext.len > 4096) return error.InvalidChunk;
    for (ext) |ch| {
        if (ch < 0x20 and ch != '\t') return error.InvalidChunk;
        if (ch == 0x7f) return error.InvalidChunk;
    }
    // After the semicolons, extension names must be valid tokens
    var pos: usize = 0;
    while (pos < ext.len) {
        if (ext[pos] != ';') return error.InvalidChunk;
        pos += 1;
        // Skip BWS
        while (pos < ext.len and (ext[pos] == ' ' or ext[pos] == '\t')) pos += 1;
        if (pos >= ext.len) return error.InvalidChunk;
        // ext-name must be a non-empty token
        const name_start = pos;
        while (pos < ext.len and isTchar(ext[pos])) pos += 1;
        if (pos == name_start) return error.InvalidChunk;
        // Optional = value
        if (pos < ext.len and ext[pos] == '=') {
            pos += 1;
            // Skip token or quoted-string value
            if (pos < ext.len and ext[pos] == '"') {
                pos += 1;
                while (pos < ext.len and ext[pos] != '"') {
                    if (ext[pos] == '\\' and pos + 1 < ext.len) pos += 1;
                    pos += 1;
                }
                if (pos < ext.len) pos += 1; // skip closing quote
            } else {
                while (pos < ext.len and isTchar(ext[pos])) pos += 1;
            }
        }
        // Skip BWS before next semicolon
        while (pos < ext.len and (ext[pos] == ' ' or ext[pos] == '\t')) pos += 1;
    }
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

/// RFC 9112 §6.1: "chunked" must be the LAST transfer coding.
fn lastToken(header_value: []const u8, token: []const u8) bool {
    var last: []const u8 = "";
    var it = std.mem.splitScalar(u8, header_value, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len > 0) last = trimmed;
    }
    return std.ascii.eqlIgnoreCase(last, token);
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

test "ChunkDecoder: completes without trailers (whole feed)" {
    var dec = ChunkDecoder.init(1024);
    var dst: [64]u8 = undefined;
    const r = try dec.feed("5\r\nhello\r\n0\r\n\r\n", &dst);
    try std.testing.expect(dec.isDone());
    try std.testing.expectEqual(@as(usize, 5), r.decoded);
    try std.testing.expectEqualStrings("hello", dst[0..r.decoded]);
}

test "ChunkDecoder: completes without trailers (byte-by-byte feed)" {
    var dec = ChunkDecoder.init(1024);
    var dst: [64]u8 = undefined;
    var total_decoded: usize = 0;
    const src = "5\r\nhello\r\n0\r\n\r\n";
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const r = try dec.feed(src[i .. i + 1], dst[total_decoded..]);
        total_decoded += r.decoded;
    }
    try std.testing.expect(dec.isDone());
    try std.testing.expectEqualStrings("hello", dst[0..total_decoded]);
}

test "ChunkDecoder: completes with trailers" {
    var dec = ChunkDecoder.init(1024);
    var dst: [64]u8 = undefined;
    const r = try dec.feed("5\r\nhello\r\n0\r\nX-T: a\r\n\r\n", &dst);
    try std.testing.expect(dec.isDone());
    try std.testing.expectEqual(@as(usize, 5), r.decoded);
}

// ── header-semantics primitives ──────────────────────────────────────────────

test "extractQuickLine: bails on body headers regardless of case" {
    // Canonical case — must bail (has a body).
    try std.testing.expect(extractQuickLine("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello") == null);
    // Lowercase — must ALSO bail (case-insensitive). Regression for the
    // case-sensitive sniff that let this fast-path and desync.
    try std.testing.expect(extractQuickLine("GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello") == null);
    try std.testing.expect(extractQuickLine("GET / HTTP/1.1\r\nTRANSFER-ENCODING: chunked\r\n\r\n") == null);
    // No body headers — fast path applies.
    const ql = extractQuickLine("GET /x HTTP/1.1\r\nHost: a\r\n\r\n") orelse return error.UnexpectedNull;
    try std.testing.expectEqual(request.Method.GET, ql.method);
}

test "parseContentLengthValue: valid lengths" {
    try std.testing.expectEqual(@as(usize, 0), try parseContentLengthValue("0"));
    try std.testing.expectEqual(@as(usize, 5), try parseContentLengthValue("5"));
    try std.testing.expectEqual(@as(usize, 123456), try parseContentLengthValue("123456"));
    // 19 digits is the max allowed length (fits in usize on 64-bit)
    try std.testing.expectEqual(@as(usize, 9_999_999_999_999_999_999), try parseContentLengthValue("9999999999999999999"));
}

test "parseContentLengthValue: rejects smuggling / malformed" {
    const bad = [_][]const u8{
        "", // empty
        "01", "00", "007", // leading zeros (RFC 9112 §6.3)
        "1a", "0x10", "12.0", // non-digit
        "+5", "-5", // signs
        " 5", "5 ", "\t5", "5\t", // whitespace
        "99999999999999999999", // 20 digits — overflow guard
    };
    for (bad) |v| {
        try std.testing.expectError(error.Invalid, parseContentLengthValue(v));
    }
}

test "isToken: RFC tchar set" {
    try std.testing.expect(isToken("GET"));
    try std.testing.expect(isToken("X-Custom-Header"));
    try std.testing.expect(isToken("!#$%&'*+-.^_`|~"));
    try std.testing.expect(!isToken("")); // empty
    try std.testing.expect(!isToken("a b")); // space
    try std.testing.expect(!isToken("a:b")); // colon
    try std.testing.expect(!isToken("a/b")); // slash
    try std.testing.expect(!isToken("a(b)")); // parens
}

test "isValidFieldValue: control chars rejected, obs-text allowed" {
    try std.testing.expect(isValidFieldValue("hello world"));
    try std.testing.expect(isValidFieldValue("with\ttab"));
    try std.testing.expect(isValidFieldValue("")); // empty is valid
    try std.testing.expect(isValidFieldValue("obs\x80text")); // obs-text 0x80-0xFF
    try std.testing.expect(!isValidFieldValue("bare\nlf"));
    try std.testing.expect(!isValidFieldValue("bare\rcr"));
    try std.testing.expect(!isValidFieldValue("nul\x00byte"));
    try std.testing.expect(!isValidFieldValue("del\x7fchar"));
}

test "hasInvalidHostChar: reject @ / ," {
    try std.testing.expect(!hasInvalidHostChar("example.com"));
    try std.testing.expect(!hasInvalidHostChar("example.com:8080"));
    try std.testing.expect(hasInvalidHostChar("user@evil.com")); // userinfo smuggling
    try std.testing.expect(hasInvalidHostChar("a/b"));
    try std.testing.expect(hasInvalidHostChar("a,b"));
}

test "containsToken: comma list, case-insensitive, trimmed" {
    try std.testing.expect(containsToken("close", "close"));
    try std.testing.expect(containsToken("keep-alive, close", "close"));
    try std.testing.expect(containsToken("Keep-Alive", "keep-alive")); // case
    try std.testing.expect(containsToken("  close  ", "close")); // OWS trimmed
    try std.testing.expect(!containsToken("closely", "close")); // not a substring match
    try std.testing.expect(!containsToken("keep-alive", "close"));
}

test "lastToken: chunked must be final coding" {
    try std.testing.expect(lastToken("gzip, chunked", "chunked"));
    try std.testing.expect(lastToken("chunked", "chunked"));
    try std.testing.expect(lastToken("chunked,", "chunked")); // trailing comma ignored
    try std.testing.expect(!lastToken("chunked, gzip", "chunked")); // not last — smuggling vector
    try std.testing.expect(!lastToken("gzip", "chunked"));
    try std.testing.expect(!lastToken("", "chunked"));
}
