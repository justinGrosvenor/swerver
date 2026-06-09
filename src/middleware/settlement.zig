const std = @import("std");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const json_write = @import("../runtime/json_write.zig");
const build_options = @import("build_options");
const ffi = if (build_options.enable_tls) @import("../tls/ffi.zig") else struct {};

const QUEUE_SIZE = 64;

pub const Record = struct {
    gateway_id: [64]u8 = undefined,
    gateway_id_len: u8 = 0,
    tx_hash: [128]u8 = undefined,
    tx_hash_len: u8 = 0,
    network: [64]u8 = undefined,
    network_len: u8 = 0,
    asset: [64]u8 = undefined,
    asset_len: u8 = 0,
    amount: [32]u8 = undefined,
    amount_len: u8 = 0,
};

pub const SettlementConfig = struct {
    url: []const u8 = "",
    host: []const u8 = "",
    port: u16 = 443,
    path: []const u8 = "/",
    use_tls: bool = true,
    token: []const u8 = "",
};

// SPSC ring: reactor writes via enqueue(), background thread reads.
var ring: [QUEUE_SIZE]Record = undefined;
var write_pos: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var read_pos: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var active_config: SettlementConfig = .{};
var sender_started: bool = false;

pub fn configure(url: []const u8, token: []const u8) void {
    if (url.len == 0) {
        active_config = .{};
        return;
    }
    const parsed = parseUrl(url) orelse {
        std.log.warn("settlement: invalid URL: {s}", .{url});
        return;
    };
    active_config = .{
        .url = url,
        .host = parsed.host,
        .port = parsed.port,
        .path = parsed.path,
        .use_tls = parsed.use_tls,
        .token = token,
    };
    startSender();
}

pub fn isConfigured() bool {
    return active_config.url.len > 0;
}

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    use_tls: bool,
};

fn parseUrl(url: []const u8) ?ParsedUrl {
    var rest: []const u8 = undefined;
    var use_tls = true;
    var default_port: u16 = 443;
    if (std.mem.startsWith(u8, url, "https://")) {
        rest = url["https://".len..];
    } else if (std.mem.startsWith(u8, url, "http://")) {
        rest = url["http://".len..];
        use_tls = false;
        default_port = 80;
    } else {
        return null;
    }
    const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "/";
    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
        return .{
            .host = host_port[0..colon],
            .port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null,
            .path = path,
            .use_tls = use_tls,
        };
    }
    return .{
        .host = host_port,
        .port = default_port,
        .path = path,
        .use_tls = use_tls,
    };
}

pub fn enqueue(
    gateway_id: []const u8,
    tx_hash: []const u8,
    network_str: []const u8,
    asset: []const u8,
    amount: []const u8,
) void {
    const wp = write_pos.load(.acquire);
    const rp = read_pos.load(.acquire);
    const used = wp -% rp;
    if (used >= QUEUE_SIZE) {
        std.log.warn("settlement queue full, dropping record", .{});
        return;
    }
    var rec = Record{};
    rec.gateway_id_len = @intCast(@min(gateway_id.len, 64));
    @memcpy(rec.gateway_id[0..rec.gateway_id_len], gateway_id[0..rec.gateway_id_len]);
    rec.tx_hash_len = @intCast(@min(tx_hash.len, 128));
    @memcpy(rec.tx_hash[0..rec.tx_hash_len], tx_hash[0..rec.tx_hash_len]);
    rec.network_len = @intCast(@min(network_str.len, 64));
    @memcpy(rec.network[0..rec.network_len], network_str[0..rec.network_len]);
    rec.asset_len = @intCast(@min(asset.len, 64));
    @memcpy(rec.asset[0..rec.asset_len], asset[0..rec.asset_len]);
    rec.amount_len = @intCast(@min(amount.len, 32));
    @memcpy(rec.amount[0..rec.amount_len], amount[0..rec.amount_len]);
    ring[wp % QUEUE_SIZE] = rec;
    write_pos.store(wp +% 1, .release);
}

/// Called from housekeeping — now a no-op since the background thread
/// handles flushing. Kept for API compatibility.
pub fn flush() void {}

fn startSender() void {
    if (sender_started) return;
    sender_started = true;
    _ = std.Thread.spawn(.{}, senderLoop, .{}) catch {
        std.log.warn("settlement: failed to start background sender", .{});
        sender_started = false;
        return;
    };
}

fn senderLoop() void {
    const config = active_config;
    while (true) {
        const wp = write_pos.load(.acquire);
        const rp = read_pos.load(.acquire);
        if (wp == rp) {
            sleepNs(1_000_000);
            continue;
        }
        const rec = &ring[rp % QUEUE_SIZE];
        postRecord(config, rec);
        read_pos.store(rp +% 1, .release);
    }
}

fn postRecord(config: SettlementConfig, rec: *const Record) void {
    var json_buf: [1024]u8 = undefined;
    const json_len = buildJson(&json_buf, rec) catch {
        std.log.warn("settlement report: json build failed", .{});
        return;
    };
    const body = json_buf[0..json_len];

    var http_buf: [2048]u8 = undefined;
    const http_len = buildPost(&http_buf, config, body) catch {
        std.log.warn("settlement report: http build failed", .{});
        return;
    };

    const fd = net.connectBlocking(config.host, config.port, 2000) catch {
        std.log.warn("settlement report: connect failed to {s}:{d}", .{ config.host, config.port });
        return;
    };
    defer clock.closeFd(fd);

    if (config.use_tls and build_options.enable_tls) {
        const ctx = ffi.SSL_CTX_new(ffi.TLS_client_method()) orelse {
            std.log.warn("settlement report: TLS init failed", .{});
            return;
        };
        defer ffi.SSL_CTX_free(ctx);
        ffi.loadDefaultVerifyPaths(ctx) catch {
            std.log.warn("settlement report: TLS verify paths failed", .{});
            return;
        };
        ffi.setVerifyPeer(ctx, true);
        const ssl = ffi.SSL_new(ctx) orelse {
            std.log.warn("settlement report: SSL_new failed", .{});
            return;
        };
        defer ffi.SSL_free(ssl);
        var host_z: [253:0]u8 = undefined;
        if (config.host.len < host_z.len) {
            @memcpy(host_z[0..config.host.len], config.host);
            host_z[config.host.len] = 0;
            const host_sentinel: [:0]const u8 = host_z[0..config.host.len :0];
            _ = ffi.setHostnameVerification(ssl, host_sentinel);
            _ = ffi.setSniHostname(ssl, host_sentinel);
        }
        if (ffi.SSL_set_fd(ssl, @intCast(fd)) != 1) {
            std.log.warn("settlement report: SSL_set_fd failed", .{});
            return;
        }
        if (ffi.SSL_connect(ssl) != 1) {
            std.log.warn("settlement report: TLS handshake failed", .{});
            return;
        }
        defer _ = ffi.SSL_shutdown(ssl);
        var sent: usize = 0;
        while (sent < http_len) {
            const n = ffi.SSL_write(ssl, http_buf[sent..http_len].ptr, @intCast(http_len - sent));
            if (n <= 0) {
                std.log.warn("settlement report: TLS send failed", .{});
                return;
            }
            sent += @intCast(n);
        }
        var resp_buf: [512]u8 = undefined;
        const n = ffi.SSL_read(ssl, &resp_buf, @intCast(resp_buf.len));
        if (n > 0) checkResponse(resp_buf[0..@intCast(n)], rec);
    } else {
        net.sendAll(fd, http_buf[0..http_len]) catch {
            std.log.warn("settlement report: send failed", .{});
            return;
        };
        var resp_buf: [512]u8 = undefined;
        const n = std.posix.read(fd, &resp_buf) catch 0;
        if (n > 0) checkResponse(resp_buf[0..n], rec);
    }
}

fn checkResponse(resp: []const u8, rec: *const Record) void {
    if (resp.len < 12) return;
    if (!std.mem.startsWith(u8, resp, "HTTP/1.")) return;
    const status = std.fmt.parseInt(u16, resp[9..12], 10) catch return;
    if (status < 200 or status >= 300) {
        std.log.warn("settlement report: HTTP {d} for tx {s}", .{
            status,
            rec.tx_hash[0..rec.tx_hash_len],
        });
    }
}

fn buildJson(buf: []u8, rec: *const Record) !usize {
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"gatewayId\":\"");
    off += jsonEscape(buf[off..], rec.gateway_id[0..rec.gateway_id_len]);
    off += copyInto(buf[off..], "\",\"txHash\":\"");
    off += jsonEscape(buf[off..], rec.tx_hash[0..rec.tx_hash_len]);
    off += copyInto(buf[off..], "\",\"network\":\"");
    off += jsonEscape(buf[off..], rec.network[0..rec.network_len]);
    off += copyInto(buf[off..], "\",\"asset\":\"");
    off += jsonEscape(buf[off..], rec.asset[0..rec.asset_len]);
    off += copyInto(buf[off..], "\",\"amount\":\"");
    off += jsonEscape(buf[off..], rec.amount[0..rec.amount_len]);
    off += copyInto(buf[off..], "\"}");
    if (off >= buf.len) return error.BufferTooSmall;
    return off;
}

fn buildPost(buf: []u8, config: SettlementConfig, body: []const u8) !usize {
    var off: usize = 0;
    const req_line = std.fmt.bufPrint(buf[off..], "POST {s} HTTP/1.1\r\nHost: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n", .{
        config.path,
        config.host,
        body.len,
    }) catch return error.BufferTooSmall;
    off += req_line.len;
    if (config.token.len > 0) {
        const auth = std.fmt.bufPrint(buf[off..], "Authorization: Bearer {s}\r\n", .{config.token}) catch return error.BufferTooSmall;
        off += auth.len;
    }
    off += copyInto(buf[off..], "Connection: close\r\n\r\n");
    if (off + body.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[off..][0..body.len], body);
    off += body.len;
    return off;
}

fn copyInto(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

fn jsonEscape(dst: []u8, src: []const u8) usize {
    const escaped = json_write.writeEscaped(dst, src) catch return 0;
    return escaped.len;
}

fn sleepNs(ns: u64) void {
    var ts = std.posix.timespec{ .sec = @intCast(ns / std.time.ns_per_s), .nsec = @intCast(ns % std.time.ns_per_s) };
    var rem: std.posix.timespec = .{ .sec = 0, .nsec = 0 };
    while (true) {
        const rc = std.posix.system.nanosleep(&ts, &rem);
        if (rc == 0) return;
        ts = rem;
    }
}

// --- Tests ---

test "buildJson: produces valid settlement JSON" {
    var rec = Record{};
    const gw = "test-gateway-id";
    rec.gateway_id_len = @intCast(gw.len);
    @memcpy(rec.gateway_id[0..gw.len], gw);
    const tx = "0xabc123";
    rec.tx_hash_len = @intCast(tx.len);
    @memcpy(rec.tx_hash[0..tx.len], tx);
    const nw = "eip155:84532";
    rec.network_len = @intCast(nw.len);
    @memcpy(rec.network[0..nw.len], nw);
    const asset_str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    rec.asset_len = @intCast(asset_str.len);
    @memcpy(rec.asset[0..asset_str.len], asset_str);
    const amt = "1000000";
    rec.amount_len = @intCast(amt.len);
    @memcpy(rec.amount[0..amt.len], amt);

    var buf: [1024]u8 = undefined;
    const len = try buildJson(&buf, &rec);
    const json = buf[0..len];

    try std.testing.expect(std.mem.indexOf(u8, json, "\"gatewayId\":\"test-gateway-id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"txHash\":\"0xabc123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"network\":\"eip155:84532\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"amount\":\"1000000\"") != null);
}

test "enqueue and count" {
    write_pos = std.atomic.Value(u32).init(0);
    read_pos = std.atomic.Value(u32).init(0);
    enqueue("gw1", "tx1", "eip155:1", "0xasset", "100");
    try std.testing.expectEqual(@as(u32, 1), write_pos.load(.acquire));
    enqueue("gw2", "tx2", "eip155:1", "0xasset", "200");
    try std.testing.expectEqual(@as(u32, 2), write_pos.load(.acquire));
    write_pos = std.atomic.Value(u32).init(0);
    read_pos = std.atomic.Value(u32).init(0);
}

test "buildPost: includes auth header when token present" {
    var rec = Record{};
    const gw = "gw1";
    rec.gateway_id_len = @intCast(gw.len);
    @memcpy(rec.gateway_id[0..gw.len], gw);
    rec.tx_hash_len = 2;
    @memcpy(rec.tx_hash[0..2], "tx");
    rec.network_len = 3;
    @memcpy(rec.network[0..3], "net");
    rec.asset_len = 5;
    @memcpy(rec.asset[0..5], "asset");
    rec.amount_len = 3;
    @memcpy(rec.amount[0..3], "100");

    var json_buf: [1024]u8 = undefined;
    const json_len = try buildJson(&json_buf, &rec);

    var buf: [2048]u8 = undefined;
    const config = SettlementConfig{
        .host = "api.example.com",
        .path = "/v1/settlements",
        .token = "secret-token",
    };
    const len = try buildPost(&buf, config, json_buf[0..json_len]);
    const http = buf[0..len];

    try std.testing.expect(std.mem.indexOf(u8, http, "POST /v1/settlements HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, http, "Authorization: Bearer secret-token\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, http, "Content-Type: application/json\r\n") != null);
}
