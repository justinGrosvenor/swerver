const std = @import("std");
const net = @import("runtime/net.zig");
const clock = @import("runtime/clock.zig");
const ffi = @import("tls/ffi.zig");
const build_options = @import("build_options");

pub const UrlConfig = struct {
    url: []const u8 = "",
    host: []const u8 = "",
    port: u16 = 443,
    path: []const u8 = "/",
    use_tls: bool = true,
    token: []const u8 = "",
    timeout_ms: u32 = 10_000,
    cache_path: ?[]const u8 = null,
};

pub const ConfigSource = union(enum) {
    file: []const u8,
    url: UrlConfig,

    pub fn configPath(self: ConfigSource) ?[]const u8 {
        return switch (self) {
            .file => |p| p,
            .url => null,
        };
    }
};

pub const FetchError = error{
    InvalidUrl,
    ConnectFailed,
    TlsNotEnabled,
    TlsInitFailed,
    TlsHandshakeFailed,
    SendFailed,
    RecvFailed,
    ResponseTooLarge,
    HttpRedirect,
    HttpClientError,
    HttpServerError,
    MalformedResponse,
    OutOfMemory,
};

const MAX_CONFIG_SIZE = 1024 * 1024; // 1MB
const REQUEST_BUF_SIZE = 2048;
const RESPONSE_BUF_SIZE = MAX_CONFIG_SIZE + 8192; // body + headers

pub fn parseConfigUrl(url: []const u8) ?UrlConfig {
    var config = UrlConfig{ .url = url };

    var rest = url;
    if (std.mem.startsWith(u8, rest, "https://")) {
        config.use_tls = true;
        config.port = 443;
        rest = rest["https://".len..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        config.use_tls = false;
        config.port = 80;
        rest = rest["http://".len..];
    } else {
        return null;
    }

    const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..path_start];
    config.path = if (path_start < rest.len) rest[path_start..] else "/";

    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
        config.host = host_port[0..colon];
        config.port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null;
    } else {
        config.host = host_port;
    }

    if (config.host.len == 0) return null;
    return config;
}

pub fn fetchConfigBytes(allocator: std.mem.Allocator, url_config: UrlConfig) FetchError![]u8 {
    if (url_config.use_tls and !build_options.enable_tls) {
        std.log.err("config URL uses HTTPS but TLS is not enabled (build with -Denable-tls=true)", .{});
        return error.TlsNotEnabled;
    }

    if (!url_config.use_tls) {
        std.log.warn("fetching config over plaintext HTTP — this is insecure", .{});
    }

    const fd = net.connectBlockingValidated(url_config.host, url_config.port, url_config.timeout_ms) catch
        return error.ConnectFailed;
    defer clock.closeFd(fd);

    net.setSocketTimeouts(fd, url_config.timeout_ms, url_config.timeout_ms);

    var req_buf: [REQUEST_BUF_SIZE]u8 = undefined;
    const req_bytes = buildGetRequest(&req_buf, url_config) catch return error.SendFailed;

    if (url_config.use_tls and build_options.enable_tls) {
        return fetchTls(allocator, fd, url_config, req_bytes);
    }

    return fetchPlain(allocator, fd, req_bytes);
}

fn fetchPlain(allocator: std.mem.Allocator, fd: std.posix.fd_t, req_bytes: []const u8) FetchError![]u8 {
    net.sendAll(fd, req_bytes) catch return error.SendFailed;
    return receiveAndExtractBody(allocator, fd, .{ .plain = {} });
}

fn fetchTls(allocator: std.mem.Allocator, fd: std.posix.fd_t, url_config: UrlConfig, req_bytes: []const u8) FetchError![]u8 {
    const ctx = ffi.SSL_CTX_new(ffi.TLS_client_method()) orelse return error.TlsInitFailed;
    defer ffi.SSL_CTX_free(ctx);
    ffi.loadDefaultVerifyPaths(ctx) catch return error.TlsInitFailed;
    ffi.setVerifyPeer(ctx, true);

    const ssl = ffi.SSL_new(ctx) orelse return error.TlsInitFailed;
    defer ffi.SSL_free(ssl);

    // Hostname verification — null-terminate the host for OpenSSL
    var host_z: [253:0]u8 = undefined;
    if (url_config.host.len >= host_z.len) return error.TlsInitFailed;
    @memcpy(host_z[0..url_config.host.len], url_config.host);
    host_z[url_config.host.len] = 0;
    const host_sentinel: [:0]const u8 = host_z[0..url_config.host.len :0];
    if (!ffi.setHostnameVerification(ssl, host_sentinel)) return error.TlsInitFailed;
    if (!ffi.setSniHostname(ssl, host_sentinel)) return error.TlsInitFailed;

    if (ffi.SSL_set_fd(ssl, @intCast(fd)) != 1) return error.TlsInitFailed;
    if (ffi.SSL_connect(ssl) != 1) return error.TlsHandshakeFailed;
    defer _ = ffi.SSL_shutdown(ssl);

    // Send request
    var sent: usize = 0;
    while (sent < req_bytes.len) {
        const n = ffi.SSL_write(ssl, req_bytes[sent..].ptr, @intCast(req_bytes.len - sent));
        if (n <= 0) return error.SendFailed;
        sent += @intCast(n);
    }

    return receiveAndExtractBody(allocator, fd, .{ .tls = ssl });
}

const ReadSource = union(enum) {
    plain: void,
    tls: *ffi.SSL,
};

fn readOnce(source: ReadSource, fd: std.posix.fd_t, buf: []u8) !usize {
    switch (source) {
        .plain => return net.recvBlocking(fd, buf) catch return error.RecvFailed,
        .tls => |ssl| {
            const n = ffi.SSL_read(ssl, buf.ptr, @intCast(buf.len));
            if (n <= 0) return 0;
            return @intCast(n);
        },
    }
}

fn receiveAndExtractBody(allocator: std.mem.Allocator, fd: std.posix.fd_t, source: ReadSource) FetchError![]u8 {
    // Use a stack buffer for initial recv, then heap-allocate the body
    var header_buf: [8192]u8 = undefined;
    var total: usize = 0;

    // Read headers
    while (total < header_buf.len) {
        const n = readOnce(source, fd, header_buf[total..]) catch return error.RecvFailed;
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, header_buf[0..total], "\r\n\r\n") != null) break;
    }
    if (total == 0) return error.MalformedResponse;

    const header_end_pos = std.mem.indexOf(u8, header_buf[0..total], "\r\n\r\n") orelse
        return error.MalformedResponse;
    const header_end = header_end_pos + 4;

    const status = extractStatusCode(header_buf[0..total]) orelse return error.MalformedResponse;
    if (status >= 300 and status < 400) return error.HttpRedirect;
    if (status >= 400 and status < 500) return error.HttpClientError;
    if (status >= 500) return error.HttpServerError;
    if (status < 200 or status >= 300) return error.MalformedResponse;

    const content_length = findContentLength(header_buf[0..total]);
    if (content_length) |cl| {
        if (cl > MAX_CONFIG_SIZE) return error.ResponseTooLarge;
    }

    // Body bytes already received in header_buf
    const body_in_header = total - header_end;
    const expected_len = content_length orelse MAX_CONFIG_SIZE;

    if (expected_len > MAX_CONFIG_SIZE) return error.ResponseTooLarge;

    const body = allocator.alloc(u8, expected_len) catch return error.OutOfMemory;
    errdefer allocator.free(body);

    // Copy body bytes already received
    const initial = @min(body_in_header, expected_len);
    @memcpy(body[0..initial], header_buf[header_end .. header_end + initial]);
    var body_total = initial;

    // Read remaining body
    if (content_length) |cl| {
        while (body_total < cl) {
            const n = readOnce(source, fd, body[body_total..cl]) catch break;
            if (n == 0) break;
            body_total += n;
        }
    } else {
        // No Content-Length: read until EOF, up to max
        while (body_total < expected_len) {
            const n = readOnce(source, fd, body[body_total..]) catch break;
            if (n == 0) break;
            body_total += n;
        }
    }

    // Shrink to actual size
    if (body_total == 0) return error.MalformedResponse;
    if (body_total < expected_len) {
        const shrunk = allocator.realloc(body, body_total) catch return body[0..body_total];
        return shrunk;
    }
    return body;
}

fn buildGetRequest(buf: []u8, config: UrlConfig) ![]const u8 {
    if (config.token.len > 0) {
        const result = std.fmt.bufPrint(buf,
            "GET {s} HTTP/1.1\r\nHost: {s}\r\nAuthorization: Bearer {s}\r\nUser-Agent: swerver/1.0\r\nConnection: close\r\n\r\n",
            .{ config.path, config.host, config.token },
        ) catch return error.BufferTooSmall;
        return result;
    }
    const result = std.fmt.bufPrint(buf,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: swerver/1.0\r\nConnection: close\r\n\r\n",
        .{ config.path, config.host },
    ) catch return error.BufferTooSmall;
    return result;
}

fn extractStatusCode(response: []const u8) ?u16 {
    // "HTTP/1.X YYY"
    if (response.len < 12) return null;
    if (!std.mem.startsWith(u8, response, "HTTP/1.")) return null;
    if (response[8] != ' ') return null;
    return std.fmt.parseInt(u16, response[9..12], 10) catch null;
}

fn findContentLength(response: []const u8) ?usize {
    const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return null;
    const headers = response[0..header_end];
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len > 16 and std.ascii.eqlIgnoreCase(line[0..16], "content-length: ")) {
            return std.fmt.parseInt(usize, std.mem.trim(u8, line[16..], " \t"), 10) catch null;
        }
    }
    return null;
}

pub fn writeCacheFile(path: []const u8, data: []const u8) !void {
    if (path.len == 0 or path.len >= 4090) return error.NameTooLong;

    // Build null-terminated path + .tmp variant
    var path_buf: [4096:0]u8 = undefined;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [:0]const u8 = path_buf[0..path.len :0];

    var tmp_buf: [4096:0]u8 = undefined;
    @memcpy(tmp_buf[0..path.len], path);
    @memcpy(tmp_buf[path.len .. path.len + 4], ".tmp");
    tmp_buf[path.len + 4] = 0;
    const tmp_z: [:0]const u8 = tmp_buf[0 .. path.len + 4 :0];

    const fd = std.posix.openat(std.posix.AT.FDCWD, tmp_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644) catch
        return error.WriteFailed;
    defer clock.closeFd(fd);

    var written: usize = 0;
    while (written < data.len) {
        const remaining = data[written..];
        const rc = std.posix.system.write(fd, remaining.ptr, remaining.len);
        const signed: isize = @bitCast(rc);
        if (signed < 0) return error.WriteFailed;
        written += @intCast(signed);
    }

    _ = std.c.rename(tmp_z.ptr, path_z.ptr);
}

// --- Tests ---

test "parseConfigUrl: https with path" {
    const cfg = parseConfigUrl("https://api.example.com/v1/config") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("api.example.com", cfg.host);
    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expectEqualStrings("/v1/config", cfg.path);
    try std.testing.expect(cfg.use_tls);
}

test "parseConfigUrl: http with port" {
    const cfg = parseConfigUrl("http://localhost:3000/config.json") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("localhost", cfg.host);
    try std.testing.expectEqual(@as(u16, 3000), cfg.port);
    try std.testing.expectEqualStrings("/config.json", cfg.path);
    try std.testing.expect(!cfg.use_tls);
}

test "parseConfigUrl: no path defaults to /" {
    const cfg = parseConfigUrl("https://example.com") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("example.com", cfg.host);
    try std.testing.expectEqualStrings("/", cfg.path);
}

test "parseConfigUrl: invalid scheme returns null" {
    try std.testing.expect(parseConfigUrl("ftp://example.com") == null);
    try std.testing.expect(parseConfigUrl("example.com/path") == null);
    try std.testing.expect(parseConfigUrl("") == null);
}

test "parseConfigUrl: empty host returns null" {
    try std.testing.expect(parseConfigUrl("https:///path") == null);
    try std.testing.expect(parseConfigUrl("https://:8080/path") == null);
}

test "buildGetRequest: with token" {
    var buf: [REQUEST_BUF_SIZE]u8 = undefined;
    const cfg = UrlConfig{
        .host = "api.example.com",
        .path = "/v1/config",
        .token = "my-secret-token",
    };
    const req = try buildGetRequest(&buf, cfg);
    try std.testing.expect(std.mem.startsWith(u8, req, "GET /v1/config HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, req, "Authorization: Bearer my-secret-token\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: api.example.com\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, req, "\r\n\r\n"));
}

test "buildGetRequest: without token" {
    var buf: [REQUEST_BUF_SIZE]u8 = undefined;
    const cfg = UrlConfig{
        .host = "localhost",
        .path = "/config.json",
        .token = "",
    };
    const req = try buildGetRequest(&buf, cfg);
    try std.testing.expect(std.mem.indexOf(u8, req, "Authorization") == null);
    try std.testing.expect(std.mem.startsWith(u8, req, "GET /config.json HTTP/1.1\r\n"));
}

test "extractStatusCode: valid responses" {
    try std.testing.expectEqual(@as(?u16, 200), extractStatusCode("HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqual(@as(?u16, 404), extractStatusCode("HTTP/1.0 404 Not Found\r\n"));
    try std.testing.expectEqual(@as(?u16, 301), extractStatusCode("HTTP/1.1 301 Moved\r\n"));
    try std.testing.expectEqual(@as(?u16, 500), extractStatusCode("HTTP/1.1 500 Server Error\r\n"));
}

test "extractStatusCode: invalid" {
    try std.testing.expectEqual(@as(?u16, null), extractStatusCode(""));
    try std.testing.expectEqual(@as(?u16, null), extractStatusCode("not http"));
    try std.testing.expectEqual(@as(?u16, null), extractStatusCode("HTTP/2 200 OK"));
}

test "findContentLength: present" {
    const resp = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\nContent-Type: application/json\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, 42), findContentLength(resp));
}

test "findContentLength: absent" {
    const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, null), findContentLength(resp));
}

test "findContentLength: case insensitive" {
    const resp = "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, 100), findContentLength(resp));
}
