const std = @import("std");
const upstream = @import("upstream.zig");
const pool_mod = @import("pool.zig");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");

/// Request/Response Forwarding
///
/// Handles forwarding HTTP requests to upstream servers and
/// relaying responses back to clients. Manages header manipulation,
/// hop-by-hop header filtering, and proxy header injection.

/// Context for a proxy request
pub const ForwardContext = struct {
    /// Original client request
    client_request: request.RequestView,
    /// Client's IP address (for X-Forwarded-For)
    client_ip: ?[]const u8,
    /// Whether client connection is TLS
    client_tls: bool,
    /// The route configuration
    route: *const upstream.ProxyRoute,
    /// Selected upstream server
    server: *const upstream.Server,
    /// Connection to upstream
    upstream_conn: *pool_mod.UpstreamConnection,
    /// Buffer for building upstream request
    request_buf: []u8,
    /// Buffer for reading upstream response
    response_buf: []u8,
};

/// Result of forwarding a request
pub const ForwardResult = union(enum) {
    /// Successfully received response from upstream
    success: UpstreamResponse,
    /// Upstream connection failed
    connect_error,
    /// Request send timed out
    send_timeout,
    /// Response read timed out
    read_timeout,
    /// Upstream returned error status (may retry)
    upstream_error: u16,
    /// Connection was reset
    connection_reset,
};

/// Parsed response from upstream
pub const UpstreamResponse = struct {
    status: u16,
    headers: []const response.Header,
    body: []const u8,
    keep_alive: bool,
    /// Raw response bytes for zero-copy forwarding
    raw_response: []const u8,
};

/// Build the HTTP/1.1 request to send to upstream
pub fn buildUpstreamRequest(
    buf: []u8,
    ctx: *const ForwardContext,
) !usize {
    var pos: usize = 0;

    // Request line
    const method_name = ctx.client_request.getMethodName();
    const path = rewritePath(ctx.client_request.path, ctx.route.rewrite);

    pos += (std.fmt.bufPrint(buf[pos..], "{s} {s} HTTP/1.1\r\n", .{ method_name, path }) catch return error.BufferFull).len;

    // Host header
    if (ctx.route.headers.preserve_host) {
        if (ctx.client_request.getHeader("Host")) |host| {
            pos += (std.fmt.bufPrint(buf[pos..], "Host: {s}\r\n", .{host}) catch return error.BufferFull).len;
        } else {
            pos += (std.fmt.bufPrint(buf[pos..], "Host: {s}:{d}\r\n", .{ ctx.server.address, ctx.server.port }) catch return error.BufferFull).len;
        }
    } else {
        pos += (std.fmt.bufPrint(buf[pos..], "Host: {s}:{d}\r\n", .{ ctx.server.address, ctx.server.port }) catch return error.BufferFull).len;
    }

    // RFC 9110 §7.6.1: Parse Connection header to find dynamic hop-by-hop headers
    var dynamic_hop_by_hop: [16][]const u8 = undefined;
    var dynamic_hop_count: usize = 0;
    if (ctx.client_request.getHeader("Connection")) |conn_value| {
        var it = std.mem.splitScalar(u8, conn_value, ',');
        while (it.next()) |token| {
            const trimmed = std.mem.trim(u8, token, " \t");
            if (trimmed.len > 0 and dynamic_hop_count < dynamic_hop_by_hop.len) {
                dynamic_hop_by_hop[dynamic_hop_count] = trimmed;
                dynamic_hop_count += 1;
            }
        }
    }

    // Forward non-hop-by-hop headers
    for (ctx.client_request.headers) |hdr| {
        // Skip static hop-by-hop headers
        if (upstream.isHopByHop(hdr.name)) continue;

        // Skip dynamic hop-by-hop headers from Connection header
        var is_dynamic_hop = false;
        for (dynamic_hop_by_hop[0..dynamic_hop_count]) |dh| {
            if (std.ascii.eqlIgnoreCase(hdr.name, dh)) {
                is_dynamic_hop = true;
                break;
            }
        }
        if (is_dynamic_hop) continue;

        // Skip Host (handled above)
        if (std.ascii.eqlIgnoreCase(hdr.name, "host")) continue;
        // Skip Via (handled separately in addProxyHeaders chaining logic)
        if (std.ascii.eqlIgnoreCase(hdr.name, "via")) continue;

        // Check if header should be removed
        var should_remove = false;
        for (ctx.route.headers.remove_request) |remove_name| {
            if (std.ascii.eqlIgnoreCase(hdr.name, remove_name)) {
                should_remove = true;
                break;
            }
        }
        if (should_remove) continue;

        pos += (std.fmt.bufPrint(buf[pos..], "{s}: {s}\r\n", .{ hdr.name, hdr.value }) catch return error.BufferFull).len;
    }

    // Add configured request headers
    for (ctx.route.headers.set_request) |hdr| {
        pos += (std.fmt.bufPrint(buf[pos..], "{s}: {s}\r\n", .{ hdr.name, hdr.value }) catch return error.BufferFull).len;
    }

    // Add proxy headers if enabled
    if (ctx.route.headers.add_proxy_headers) {
        pos = try addProxyHeaders(buf, pos, ctx);
    }

    // Ensure Content-Length is present when forwarding a body (e.g., after stripping Transfer-Encoding)
    if (ctx.client_request.body.len > 0 and ctx.client_request.getHeader("Content-Length") == null) {
        pos += (std.fmt.bufPrint(buf[pos..], "Content-Length: {d}\r\n", .{ctx.client_request.body.len}) catch return error.BufferFull).len;
    }

    // Connection header for keep-alive
    pos += (std.fmt.bufPrint(buf[pos..], "Connection: keep-alive\r\n", .{}) catch return error.BufferFull).len;

    // End of headers
    if (pos + 2 > buf.len) return error.BufferFull;
    buf[pos] = '\r';
    buf[pos + 1] = '\n';
    pos += 2;

    // Body (if any)
    if (ctx.client_request.body.len > 0) {
        if (pos + ctx.client_request.body.len > buf.len) return error.BufferFull;
        @memcpy(buf[pos .. pos + ctx.client_request.body.len], ctx.client_request.body);
        pos += ctx.client_request.body.len;
    }

    return pos;
}

/// Validate that a string contains no control characters (CR, LF, null)
/// to prevent header injection attacks.
fn isSafeHeaderValue(value: []const u8) bool {
    for (value) |ch| {
        if (ch == '\r' or ch == '\n' or ch == 0) return false;
    }
    return true;
}

/// Add standard proxy headers (X-Forwarded-For, X-Real-IP, etc.)
fn addProxyHeaders(buf: []u8, start_pos: usize, ctx: *const ForwardContext) !usize {
    var pos = start_pos;

    // X-Real-IP (only if IP is safe for header injection)
    if (ctx.client_ip) |ip| {
        if (isSafeHeaderValue(ip)) {
            pos += (std.fmt.bufPrint(buf[pos..], "X-Real-IP: {s}\r\n", .{ip}) catch return error.BufferFull).len;
        }
    }

    // X-Forwarded-For (append to existing if present, cap total length at 8KB)
    const max_xff_len = 8192;
    if (ctx.client_ip) |ip| {
        if (isSafeHeaderValue(ip)) {
            if (ctx.client_request.getHeader("X-Forwarded-For")) |existing| {
                if (isSafeHeaderValue(existing) and existing.len + ip.len + 2 <= max_xff_len) {
                    pos += (std.fmt.bufPrint(buf[pos..], "X-Forwarded-For: {s}, {s}\r\n", .{ existing, ip }) catch return error.BufferFull).len;
                } else {
                    // Existing header too large or unsafe — start fresh
                    pos += (std.fmt.bufPrint(buf[pos..], "X-Forwarded-For: {s}\r\n", .{ip}) catch return error.BufferFull).len;
                }
            } else {
                pos += (std.fmt.bufPrint(buf[pos..], "X-Forwarded-For: {s}\r\n", .{ip}) catch return error.BufferFull).len;
            }
        }
    }

    // X-Forwarded-Proto
    const proto = if (ctx.client_tls) "https" else "http";
    pos += (std.fmt.bufPrint(buf[pos..], "X-Forwarded-Proto: {s}\r\n", .{proto}) catch return error.BufferFull).len;

    // X-Forwarded-Host
    if (ctx.client_request.getHeader("Host")) |host| {
        if (isSafeHeaderValue(host)) {
            pos += (std.fmt.bufPrint(buf[pos..], "X-Forwarded-Host: {s}\r\n", .{host}) catch return error.BufferFull).len;
        }
    }

    // Via header (RFC 9110 §7.6.3: append to existing Via chain)
    if (ctx.client_request.getHeader("Via")) |existing_via| {
        if (isSafeHeaderValue(existing_via) and existing_via.len < 4096) {
            pos += (std.fmt.bufPrint(buf[pos..], "Via: {s}, 1.1 swerver\r\n", .{existing_via}) catch return error.BufferFull).len;
        } else {
            pos += (std.fmt.bufPrint(buf[pos..], "Via: 1.1 swerver\r\n", .{}) catch return error.BufferFull).len;
        }
    } else {
        pos += (std.fmt.bufPrint(buf[pos..], "Via: 1.1 swerver\r\n", .{}) catch return error.BufferFull).len;
    }

    return pos;
}

/// Scratch buffer for path rewriting (threadlocal to avoid data races on concurrent requests)
threadlocal var rewrite_buf: [4096]u8 = undefined;

/// Apply path rewrite rule, preserving the path suffix after the matched prefix.
/// E.g., pattern="/api", replacement="/backend", path="/api/v1/users" → "/backend/v1/users"
fn rewritePath(path: []const u8, rewrite: ?upstream.RewriteRule) []const u8 {
    if (rewrite) |rule| {
        if (std.mem.startsWith(u8, path, rule.pattern)) {
            const suffix = path[rule.pattern.len..];
            const total = rule.replacement.len + suffix.len;
            if (total > rewrite_buf.len) return path;
            @memcpy(rewrite_buf[0..rule.replacement.len], rule.replacement);
            @memcpy(rewrite_buf[rule.replacement.len..][0..suffix.len], suffix);
            return rewrite_buf[0..total];
        }
    }
    return path;
}

/// Parse an HTTP/1.1 response from upstream
pub fn parseUpstreamResponse(buf: []const u8) !ParsedResponse {
    var parser = ResponseParser{ .buf = buf };
    return parser.parse();
}

/// Response parser state
const ResponseParser = struct {
    buf: []const u8,
    pos: usize = 0,

    const ParseError = error{
        InvalidResponse,
        IncompleteResponse,
        BufferFull,
    };

    fn parse(self: *ResponseParser) ParseError!ParsedResponse {
        // Parse status line: HTTP/1.1 200 OK\r\n
        const status_line_end = std.mem.indexOf(u8, self.buf, "\r\n") orelse return error.IncompleteResponse;
        const status_line = self.buf[0..status_line_end];

        // Minimum valid: "HTTP/1.1 200"
        if (status_line.len < 12) return error.InvalidResponse;
        if (!std.mem.startsWith(u8, status_line, "HTTP/1.")) return error.InvalidResponse;

        // Parse status code
        const status_start = 9; // After "HTTP/1.X "
        if (status_line.len < status_start + 3) return error.InvalidResponse;
        const status = std.fmt.parseInt(u16, status_line[status_start .. status_start + 3], 10) catch return error.InvalidResponse;

        self.pos = status_line_end + 2;

        // Find end of headers
        const header_end = std.mem.indexOf(u8, self.buf[self.pos..], "\r\n\r\n") orelse return error.IncompleteResponse;
        const headers_section = self.buf[self.pos .. self.pos + header_end];
        self.pos += header_end + 4;

        // Parse headers
        var header_count: usize = 0;
        var headers: [64]response.Header = undefined;
        var content_length: ?usize = null;
        var is_chunked = false;
        // RFC 9112: HTTP/1.1 defaults to keep-alive, HTTP/1.0 defaults to close
        var keep_alive = status_line.len >= 8 and std.mem.eql(u8, status_line[0..8], "HTTP/1.1");

        var header_iter = std.mem.splitSequence(u8, headers_section, "\r\n");
        while (header_iter.next()) |line| {
            if (line.len == 0) continue;

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const name = line[0..colon_pos];
            const value = std.mem.trimStart(u8, line[colon_pos + 1 ..], " \t");

            if (header_count < headers.len) {
                headers[header_count] = .{ .name = name, .value = value };
                header_count += 1;
            }

            // Track important headers
            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                content_length = std.fmt.parseInt(usize, value, 10) catch null;
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                is_chunked = containsIgnoreCase(value, "chunked");
            } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
                keep_alive = !std.ascii.eqlIgnoreCase(value, "close");
            }
        }

        // Determine body bounds
        var body_end = self.buf.len;
        if (content_length) |len| {
            if (self.pos + len > self.buf.len) return error.IncompleteResponse;
            body_end = self.pos + len;
        } else if (is_chunked) {
            // For chunked, we need to parse chunks
            // Simplified: assume single chunk or find end
            if (std.mem.indexOf(u8, self.buf[self.pos..], "0\r\n\r\n")) |end| {
                body_end = self.pos + end + 5;
            }
        }

        var result = ParsedResponse{
            .status = status,
            .headers_storage = undefined,
            .header_count = header_count,
            .headers_end = self.pos,
            .body_start = self.pos,
            .body_end = body_end,
            .keep_alive = keep_alive,
            .is_chunked = is_chunked,
        };
        // Copy headers to struct-owned storage
        @memcpy(result.headers_storage[0..header_count], headers[0..header_count]);
        return result;
    }
};

/// Parsed response structure
pub const ParsedResponse = struct {
    status: u16,
    /// Headers storage - embedded to avoid use-after-free
    headers_storage: [64]response.Header,
    header_count: usize,
    headers_end: usize,
    body_start: usize,
    body_end: usize,
    keep_alive: bool,
    is_chunked: bool,

    /// Get headers slice (safe - points to struct-owned storage)
    pub fn headers(self: *const ParsedResponse) []const response.Header {
        return self.headers_storage[0..self.header_count];
    }
};

/// Build response to send to client from upstream response
pub fn buildClientResponse(
    buf: []u8,
    upstream_response: *const ParsedResponse,
    upstream_buf: []const u8,
    route: *const upstream.ProxyRoute,
) !usize {
    var pos: usize = 0;

    // Status line
    pos += (std.fmt.bufPrint(buf[pos..], "HTTP/1.1 {d} {s}\r\n", .{
        upstream_response.status,
        response.statusPhrase(upstream_response.status),
    }) catch return error.BufferFull).len;

    // RFC 9110 §7.6.1: Parse upstream Connection header for dynamic hop-by-hop headers
    var upstream_dynamic_hop: [16][]const u8 = undefined;
    var upstream_dynamic_count: usize = 0;
    for (upstream_response.headers()) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "connection")) {
            var it = std.mem.splitScalar(u8, hdr.value, ',');
            while (it.next()) |token| {
                const trimmed = std.mem.trim(u8, token, " \t");
                if (trimmed.len > 0 and upstream_dynamic_count < upstream_dynamic_hop.len) {
                    upstream_dynamic_hop[upstream_dynamic_count] = trimmed;
                    upstream_dynamic_count += 1;
                }
            }
        }
    }

    // RFC 9110 §6.3: 204/304 MUST NOT have a message body or Content-Length
    const suppress_body = upstream_response.status == 204 or upstream_response.status == 304;

    // Forward non-hop-by-hop headers from upstream response
    for (upstream_response.headers()) |hdr| {
        // Skip static hop-by-hop headers
        if (upstream.isHopByHop(hdr.name)) continue;
        // Skip Via (handled separately in chaining logic below)
        if (std.ascii.eqlIgnoreCase(hdr.name, "via")) continue;
        // Skip Content-Length for 204/304
        if (suppress_body and std.ascii.eqlIgnoreCase(hdr.name, "content-length")) continue;

        // Skip dynamic hop-by-hop headers listed in upstream Connection header
        var is_dynamic_hop = false;
        for (upstream_dynamic_hop[0..upstream_dynamic_count]) |dh| {
            if (std.ascii.eqlIgnoreCase(hdr.name, dh)) {
                is_dynamic_hop = true;
                break;
            }
        }
        if (is_dynamic_hop) continue;

        // Check if header should be removed
        var should_remove = false;
        for (route.headers.remove_response) |remove_name| {
            if (std.ascii.eqlIgnoreCase(hdr.name, remove_name)) {
                should_remove = true;
                break;
            }
        }
        if (should_remove) continue;

        pos += (std.fmt.bufPrint(buf[pos..], "{s}: {s}\r\n", .{ hdr.name, hdr.value }) catch return error.BufferFull).len;
    }

    // Add configured response headers
    for (route.headers.set_response) |hdr| {
        pos += (std.fmt.bufPrint(buf[pos..], "{s}: {s}\r\n", .{ hdr.name, hdr.value }) catch return error.BufferFull).len;
    }

    // RFC 9110 §7.6.3: MUST add Via header (append to existing chain from upstream)
    var upstream_via: ?[]const u8 = null;
    for (upstream_response.headers()) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "via")) {
            upstream_via = hdr.value;
            break;
        }
    }
    if (upstream_via) |existing_via| {
        if (isSafeHeaderValue(existing_via) and existing_via.len < 4096) {
            pos += (std.fmt.bufPrint(buf[pos..], "Via: {s}, 1.1 swerver\r\n", .{existing_via}) catch return error.BufferFull).len;
        } else {
            pos += (std.fmt.bufPrint(buf[pos..], "Via: 1.1 swerver\r\n", .{}) catch return error.BufferFull).len;
        }
    } else {
        pos += (std.fmt.bufPrint(buf[pos..], "Via: 1.1 swerver\r\n", .{}) catch return error.BufferFull).len;
    }

    // RFC 9110 §6.3: 204/304 responses MUST NOT contain a message body
    if (suppress_body) {
        if (pos + 2 > buf.len) return error.BufferFull;
        buf[pos] = '\r';
        buf[pos + 1] = '\n';
        pos += 2;
        return pos;
    }

    const raw_body = upstream_buf[upstream_response.body_start..upstream_response.body_end];

    if (upstream_response.is_chunked) {
        // Decode chunked body: calculate decoded size for Content-Length
        const decoded_size = chunkedDecodedSize(raw_body) orelse raw_body.len;
        pos += (std.fmt.bufPrint(buf[pos..], "Content-Length: {d}\r\n", .{decoded_size}) catch return error.BufferFull).len;

        // End of headers
        if (pos + 2 > buf.len) return error.BufferFull;
        buf[pos] = '\r';
        buf[pos + 1] = '\n';
        pos += 2;

        // Decode chunked body directly into output buffer
        if (decodeChunkedInto(raw_body, buf[pos..])) |written| {
            pos += written;
        } else {
            // Fallback: copy raw data if decode fails
            if (pos + raw_body.len > buf.len) return error.BufferFull;
            @memcpy(buf[pos .. pos + raw_body.len], raw_body);
            pos += raw_body.len;
        }
    } else {
        // Non-chunked: add Content-Length and copy body directly
        pos += (std.fmt.bufPrint(buf[pos..], "Content-Length: {d}\r\n", .{raw_body.len}) catch return error.BufferFull).len;

        // End of headers
        if (pos + 2 > buf.len) return error.BufferFull;
        buf[pos] = '\r';
        buf[pos + 1] = '\n';
        pos += 2;

        if (pos + raw_body.len > buf.len) return error.BufferFull;
        @memcpy(buf[pos .. pos + raw_body.len], raw_body);
        pos += raw_body.len;
    }

    return pos;
}

/// Calculate the decoded size of a chunked body (sum of all chunk sizes).
/// Returns null if parsing fails.
fn chunkedDecodedSize(data: []const u8) ?usize {
    var src: usize = 0;
    var total: usize = 0;
    while (src < data.len) {
        const line_end = std.mem.indexOfPos(u8, data, src, "\r\n") orelse return null;
        const size_str = data[src..line_end];
        if (size_str.len == 0) return null;
        const semi = std.mem.indexOfScalar(u8, size_str, ';') orelse size_str.len;
        const chunk_size = std.fmt.parseInt(usize, size_str[0..semi], 16) catch return null;
        src = line_end + 2;
        if (chunk_size == 0) break;
        if (src + chunk_size + 2 > data.len) return null;
        total += chunk_size;
        src += chunk_size + 2;
    }
    return total;
}

/// Copy decoded chunked body into output buffer, stripping chunk framing.
/// Returns bytes written, or null on parse failure.
fn decodeChunkedInto(data: []const u8, out: []u8) ?usize {
    var src: usize = 0;
    var dst: usize = 0;
    while (src < data.len) {
        const line_end = std.mem.indexOfPos(u8, data, src, "\r\n") orelse return null;
        const size_str = data[src..line_end];
        if (size_str.len == 0) return null;
        const semi = std.mem.indexOfScalar(u8, size_str, ';') orelse size_str.len;
        const chunk_size = std.fmt.parseInt(usize, size_str[0..semi], 16) catch return null;
        src = line_end + 2;
        if (chunk_size == 0) break;
        if (src + chunk_size + 2 > data.len) return null;
        if (dst + chunk_size > out.len) return null;
        @memcpy(out[dst .. dst + chunk_size], data[src .. src + chunk_size]);
        dst += chunk_size;
        src += chunk_size + 2;
    }
    return dst;
}

/// Check if a request method is idempotent (safe to retry)
pub fn isIdempotent(method: request.Method) bool {
    return switch (method) {
        .GET, .HEAD, .OPTIONS, .TRACE => true,
        else => false,
    };
}

/// Check if a status code indicates the request should be retried
pub fn shouldRetry(status: u16, config: *const upstream.RetryConfig) bool {
    for (config.retry_statuses) |retry_status| {
        if (status == retry_status) return true;
    }
    return false;
}

/// Check if a method is allowed for retry based on configuration
pub fn isMethodRetryable(method: request.Method, config: *const upstream.RetryConfig) bool {
    if (config.retry_non_idempotent) return true;

    const method_name = method.toString();
    for (config.retry_methods) |allowed| {
        if (std.mem.eql(u8, method_name, allowed)) return true;
    }
    return false;
}

/// Case-insensitive substring search
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    if (needle.len == 0) return true;

    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Create error response for proxy failures
pub fn createErrorResponse(status: u16) response.Response {
    const body = switch (status) {
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => "Proxy Error",
    };

    return .{
        .status = status,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = body },
    };
}

// Tests
test "buildUpstreamRequest basic" {
    var buf: [4096]u8 = undefined;

    const headers = [_]request.Header{
        .{ .name = "User-Agent", .value = "test/1.0" },
        .{ .name = "Accept", .value = "*/*" },
    };

    const req = request.RequestView{
        .method = .GET,
        .path = "/api/users",
        .headers = &headers,
        .body = "",
    };

    const server = upstream.Server{
        .address = "10.0.0.1",
        .port = 8080,
    };

    const route = upstream.ProxyRoute{
        .path_prefix = "/api/",
        .upstream = "backend",
    };

    const ctx = ForwardContext{
        .client_request = req,
        .client_ip = "192.168.1.100",
        .client_tls = false,
        .route = &route,
        .server = &server,
        .upstream_conn = undefined,
        .request_buf = &buf,
        .response_buf = undefined,
    };

    const len = try buildUpstreamRequest(&buf, &ctx);
    const result = buf[0..len];

    // Verify request line
    try std.testing.expect(std.mem.startsWith(u8, result, "GET /api/users HTTP/1.1\r\n"));

    // Verify Host header
    try std.testing.expect(std.mem.indexOf(u8, result, "Host: 10.0.0.1:8080\r\n") != null);

    // Verify proxy headers
    try std.testing.expect(std.mem.indexOf(u8, result, "X-Real-IP: 192.168.1.100\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "X-Forwarded-For: 192.168.1.100\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "X-Forwarded-Proto: http\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Via: 1.1 swerver\r\n") != null);
}

test "parseUpstreamResponse basic" {
    const resp_data = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello";

    const parsed = try parseUpstreamResponse(resp_data);

    try std.testing.expectEqual(@as(u16, 200), parsed.status);
    try std.testing.expect(parsed.keep_alive);
    try std.testing.expect(!parsed.is_chunked);
}

test "hop-by-hop header filtering" {
    // Connection header should be identified as hop-by-hop
    try std.testing.expect(upstream.isHopByHop("Connection"));
    try std.testing.expect(upstream.isHopByHop("connection"));
    try std.testing.expect(upstream.isHopByHop("Keep-Alive"));
    try std.testing.expect(upstream.isHopByHop("Transfer-Encoding"));

    // Regular headers should not be hop-by-hop
    try std.testing.expect(!upstream.isHopByHop("Content-Type"));
    try std.testing.expect(!upstream.isHopByHop("X-Custom-Header"));
}

test "isIdempotent" {
    try std.testing.expect(isIdempotent(.GET));
    try std.testing.expect(isIdempotent(.HEAD));
    try std.testing.expect(isIdempotent(.OPTIONS));
    try std.testing.expect(!isIdempotent(.POST));
    try std.testing.expect(!isIdempotent(.PUT));
    try std.testing.expect(!isIdempotent(.DELETE));
}

test "shouldRetry" {
    const config = upstream.RetryConfig{};

    try std.testing.expect(shouldRetry(502, &config));
    try std.testing.expect(shouldRetry(503, &config));
    try std.testing.expect(shouldRetry(504, &config));
    try std.testing.expect(!shouldRetry(500, &config));
    try std.testing.expect(!shouldRetry(200, &config));
}
