const std = @import("std");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const request = @import("../protocol/request.zig");
const upstream = @import("upstream.zig");
const response_mod = @import("../response/response.zig");

/// WebSocket handshake headers that MUST be forwarded to upstream
/// (they are normally stripped as hop-by-hop).
const ws_required_headers = [_][]const u8{
    "upgrade",
    "connection",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
};

/// Detect whether a request is a WebSocket upgrade.
pub fn isWebSocketUpgrade(req: request.RequestView) bool {
    const upgrade_val = req.getHeader("Upgrade") orelse return false;
    if (!std.ascii.eqlIgnoreCase(upgrade_val, "websocket")) return false;
    const conn_val = req.getHeader("Connection") orelse return false;
    var it = std.mem.splitScalar(u8, conn_val, ',');
    while (it.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, "upgrade")) return true;
    }
    return false;
}

pub const UpgradeResult = union(enum) {
    ok: struct { upstream_fd: std.posix.fd_t, resp_data: []const u8, resp_len: usize },
    err: response_mod.Response,
};

/// Perform the blocking WebSocket upgrade handshake with upstream.
/// Returns the upstream FD (now connected and upgraded) and the raw
/// 101 response to relay to the client, or an error response.
pub fn performUpgrade(
    req: request.RequestView,
    server_addr: []const u8,
    server_port: u16,
    route: *const upstream.ProxyRoute,
    client_ip: ?[]const u8,
    resp_buf: []u8,
) UpgradeResult {
    const fd = net.connectBlocking(
        server_addr,
        server_port,
        route.timeouts.connect_ms,
    ) catch {
        return .{ .err = errorResp(502) };
    };

    net.setSocketTimeouts(fd, route.timeouts.send_ms, route.timeouts.read_ms);

    var req_buf: [8192]u8 = undefined;
    const req_len = buildUpgradeRequest(&req_buf, req, server_addr, server_port, route, client_ip) catch {
        clock.closeFd(fd);
        return .{ .err = errorResp(502) };
    };

    net.sendAll(fd, req_buf[0..req_len]) catch {
        clock.closeFd(fd);
        return .{ .err = errorResp(502) };
    };

    var total: usize = 0;
    while (total < resp_buf.len) {
        const n = net.recvBlocking(fd, resp_buf[total..]) catch {
            clock.closeFd(fd);
            return .{ .err = errorResp(502) };
        };
        if (n == 0) {
            clock.closeFd(fd);
            return .{ .err = errorResp(502) };
        }
        total += n;
        if (std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n")) |_| break;
    }

    if (!isValid101(resp_buf[0..total])) {
        clock.closeFd(fd);
        return .{ .err = errorResp(502) };
    }

    return .{ .ok = .{ .upstream_fd = fd, .resp_data = resp_buf, .resp_len = total } };
}

/// Build the HTTP/1.1 upgrade request to send to upstream, preserving
/// WebSocket-specific headers that are normally stripped as hop-by-hop.
fn buildUpgradeRequest(
    buf: []u8,
    req: request.RequestView,
    server_addr: []const u8,
    server_port: u16,
    route: *const upstream.ProxyRoute,
    client_ip: ?[]const u8,
) !usize {
    var pos: usize = 0;

    const method_name = req.getMethodName();
    const path = if (route.rewrite) |rw|
        rewritePath(req.path, rw)
    else
        req.path;

    pos += (std.fmt.bufPrint(buf[pos..], "{s} {s} HTTP/1.1\r\n", .{ method_name, path }) catch return error.BufferFull).len;
    pos += (std.fmt.bufPrint(buf[pos..], "Host: {s}:{d}\r\n", .{ server_addr, server_port }) catch return error.BufferFull).len;

    for (req.headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "host")) continue;
        if (upstream.isHopByHop(hdr.name) and !isWsHeader(hdr.name)) continue;
        pos += (std.fmt.bufPrint(buf[pos..], "{s}: {s}\r\n", .{ hdr.name, hdr.value }) catch return error.BufferFull).len;
    }

    if (client_ip) |ip| {
        pos += (std.fmt.bufPrint(buf[pos..], "X-Forwarded-For: {s}\r\n", .{ip}) catch return error.BufferFull).len;
    }

    if (pos + 2 > buf.len) return error.BufferFull;
    @memcpy(buf[pos .. pos + 2], "\r\n");
    pos += 2;
    return pos;
}

fn isWsHeader(name: []const u8) bool {
    for (ws_required_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

fn rewritePath(path: []const u8, rw: upstream.RewriteRule) []const u8 {
    if (std.mem.startsWith(u8, path, rw.pattern)) {
        const suffix = path[rw.pattern.len..];
        if (rw.replacement.len == 0 and suffix.len > 0) return suffix;
        const rewrite_buf = &rewrite_scratch;
        const total = rw.replacement.len + suffix.len;
        if (total > rewrite_buf.len) return path;
        @memcpy(rewrite_buf[0..rw.replacement.len], rw.replacement);
        @memcpy(rewrite_buf[rw.replacement.len..total], suffix);
        return rewrite_buf[0..total];
    }
    return path;
}

threadlocal var rewrite_scratch: [2048]u8 = undefined;

fn isValid101(data: []const u8) bool {
    return std.mem.startsWith(u8, data, "HTTP/1.1 101 ");
}

pub fn errorResp(status: u16) response_mod.Response {
    return .{
        .status = status,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Length", .value = "0" },
            .{ .name = "Connection", .value = "close" },
        },
        .body = .none,
    };
}

// Tests

test "isWebSocketUpgrade detects valid upgrade" {
    const headers = [_]request.Header{
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Sec-WebSocket-Key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/ws",
        .headers = &headers,
    };
    try std.testing.expect(isWebSocketUpgrade(req));
}

test "isWebSocketUpgrade rejects non-websocket upgrade" {
    const headers = [_]request.Header{
        .{ .name = "Upgrade", .value = "h2c" },
        .{ .name = "Connection", .value = "Upgrade" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/ws",
        .headers = &headers,
    };
    try std.testing.expect(!isWebSocketUpgrade(req));
}

test "isWebSocketUpgrade rejects missing connection upgrade" {
    const headers = [_]request.Header{
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "keep-alive" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/ws",
        .headers = &headers,
    };
    try std.testing.expect(!isWebSocketUpgrade(req));
}

test "isWebSocketUpgrade handles Connection with multiple values" {
    const headers = [_]request.Header{
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "keep-alive, Upgrade" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/ws",
        .headers = &headers,
    };
    try std.testing.expect(isWebSocketUpgrade(req));
}

test "isValid101 accepts valid response" {
    try std.testing.expect(isValid101("HTTP/1.1 101 Switching Protocols\r\n"));
}

test "isValid101 rejects non-101" {
    try std.testing.expect(!isValid101("HTTP/1.1 200 OK\r\n"));
}
