const std = @import("std");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const request = @import("../protocol/request.zig");
const forward = @import("forward.zig");
const response_mod = @import("../response/response.zig");

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
    ctx: *const forward.ForwardContext,
    resp_buf: []u8,
    allow_private: bool,
) UpgradeResult {
    const fd = net.proxyConnect(
        ctx.server.address,
        ctx.server.port,
        ctx.route.timeouts.connect_ms,
        allow_private,
    ) catch {
        return .{ .err = errorResp(502) };
    };

    net.setSocketTimeouts(fd, ctx.route.timeouts.send_ms, ctx.route.timeouts.read_ms);

    var req_buf: [8192]u8 = undefined;
    const req_len = forward.buildUpstreamRequestHeaders(&req_buf, ctx, 0) catch {
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
