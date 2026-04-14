const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");
const clock = @import("../runtime/clock.zig");
const json_write = @import("../runtime/json_write.zig");

/// Access Logger
///
/// Post-response hook that logs requests in combined or JSON format.
/// Uses a pre-allocated buffer to avoid heap allocations on the hot path.
/// Output goes to stderr by default (to keep stdout clean for application output).

pub const Format = enum {
    /// Apache combined format:
    /// $remote_addr - - [$time] "$method $path HTTP/1.1" $status $bytes "$referer" "$user_agent" $request_time_ms
    combined,
    /// JSON format: one JSON object per line
    json,
};

/// Access log entry data collected during request processing
pub const LogEntry = struct {
    client_ip: [46]u8 = undefined,
    client_ip_len: u8 = 0,
    method: request.Method = .GET,
    path: [512]u8 = undefined,
    path_len: u16 = 0,
    protocol: middleware.Context.Protocol = .http1,
    status: u16 = 0,
    body_bytes: u64 = 0,
    elapsed_us: u64 = 0,

    pub fn setClientIp(self: *LogEntry, ip: []const u8) void {
        const len = @min(ip.len, 46);
        @memcpy(self.client_ip[0..len], ip[0..len]);
        self.client_ip_len = @intCast(len);
    }

    pub fn getClientIp(self: *const LogEntry) []const u8 {
        return self.client_ip[0..self.client_ip_len];
    }

    pub fn setPath(self: *LogEntry, path: []const u8) void {
        const len: u16 = @intCast(@min(path.len, 512));
        @memcpy(self.path[0..len], path[0..len]);
        self.path_len = len;
    }

    pub fn getPath(self: *const LogEntry) []const u8 {
        return self.path[0..self.path_len];
    }
};

/// Format a log entry in combined format into a buffer
pub fn formatCombined(entry: *const LogEntry, buf: []u8) []const u8 {
    const ip = if (entry.client_ip_len > 0) entry.getClientIp() else "-";
    const method_str = entry.method.toString();
    const proto = entry.protocol.toString();
    const elapsed_ms = entry.elapsed_us / 1000;

    // Sanitize path: replace control characters (CR, LF) to prevent log injection
    var safe_path: [512]u8 = undefined;
    const path = entry.getPath();
    const safe_len = sanitizePath(path, &safe_path);

    const result = std.fmt.bufPrint(buf, "{s} - - [{d}] \"{s} {s} {s}\" {d} {d} \"-\" \"-\" {d}ms\n", .{
        ip,
        nowTimestamp(),
        method_str,
        safe_path[0..safe_len],
        proto,
        entry.status,
        entry.body_bytes,
        elapsed_ms,
    }) catch return "";
    return result;
}

/// Format a log entry in JSON format into a buffer. The path is escaped
/// through the shared `json_write.writeEscaped` helper, which emits control
/// characters as `\u00XX` per RFC 8259 (the combined-log path goes through
/// `sanitizePath` instead, which replaces them with `?`). Offset math is
/// hand-rolled because `std.io.fixedBufferStream` was removed in Zig
/// 0.16.0-dev — the rest of the codebase uses the same bufPrint pattern.
pub fn formatJson(entry: *const LogEntry, buf: []u8) []const u8 {
    const ip = if (entry.client_ip_len > 0) entry.getClientIp() else "-";
    const method_str = entry.method.toString();
    const proto = entry.protocol.toString();
    const elapsed_ms = entry.elapsed_us / 1000;

    var off: usize = 0;

    const prefix = std.fmt.bufPrint(
        buf[off..],
        "{{\"client_ip\":\"{s}\",\"method\":\"{s}\",\"path\":\"",
        .{ ip, method_str },
    ) catch return "";
    off += prefix.len;

    const escaped = json_write.writeEscaped(buf[off..], entry.getPath()) catch return "";
    off += escaped.len;

    const suffix = std.fmt.bufPrint(
        buf[off..],
        "\",\"protocol\":\"{s}\",\"status\":{d},\"bytes\":{d},\"elapsed_ms\":{d}}}\n",
        .{ proto, entry.status, entry.body_bytes, elapsed_ms },
    ) catch return "";
    off += suffix.len;

    return buf[0..off];
}

/// Replace control characters in path with '?' to prevent log injection
fn sanitizePath(path: []const u8, out: []u8) usize {
    const len = @min(path.len, out.len);
    for (path[0..len], 0..) |ch, i| {
        out[i] = if (ch < 0x20 or ch == 0x7f) '?' else ch;
    }
    return len;
}


fn nowTimestamp() u64 {
    const ts = clock.realtimeTimespec() orelse return 0;
    return @intCast(ts.sec);
}

/// Post-response hook for access logging in combined format
pub fn postResponseCombined(ctx: *middleware.Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) void {
    var entry = buildEntry(ctx, req, resp, elapsed_ns);
    var buf: [4096]u8 = undefined;
    const line = formatCombined(&entry, &buf);
    if (line.len > 0) {
        _ = std.posix.system.write(2, line.ptr, line.len);
    }
}

/// Post-response hook for access logging in JSON format
pub fn postResponseJson(ctx: *middleware.Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) void {
    var entry = buildEntry(ctx, req, resp, elapsed_ns);
    var buf: [4096]u8 = undefined;
    const line = formatJson(&entry, &buf);
    if (line.len > 0) {
        _ = std.posix.system.write(2, line.ptr, line.len);
    }
}

fn buildEntry(ctx: *middleware.Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) LogEntry {
    var entry = LogEntry{
        .method = req.method,
        .status = resp.status,
        .body_bytes = resp.bodyLen(),
        .elapsed_us = elapsed_ns / 1000,
        .protocol = ctx.protocol,
    };
    entry.setPath(req.path);

    // Extract client IP from context
    if (ctx.client_ip) |ip4| {
        var ip_buf: [16]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "-";
        entry.setClientIp(ip_str);
    }

    return entry;
}

// Tests

test "format combined log line" {
    var entry = LogEntry{
        .method = .GET,
        .status = 200,
        .body_bytes = 1234,
        .elapsed_us = 5000,
        .protocol = .http1,
    };
    entry.setClientIp("127.0.0.1");
    entry.setPath("/api/test");

    var buf: [4096]u8 = undefined;
    const line = formatCombined(&entry, &buf);
    try std.testing.expect(line.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, line, "127.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "GET") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "/api/test") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "200") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "1234") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "5ms") != null);
}

test "format JSON log line" {
    var entry = LogEntry{
        .method = .POST,
        .status = 404,
        .body_bytes = 0,
        .elapsed_us = 12000,
        .protocol = .http2,
    };
    entry.setClientIp("10.0.0.1");
    entry.setPath("/missing");

    var buf: [4096]u8 = undefined;
    const line = formatJson(&entry, &buf);
    try std.testing.expect(line.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"client_ip\":\"10.0.0.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"method\":\"POST\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"status\":404") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"elapsed_ms\":12") != null);
}

test "log entry defaults" {
    const entry = LogEntry{};
    try std.testing.expectEqual(@as(u8, 0), entry.client_ip_len);
    try std.testing.expectEqual(@as(u16, 0), entry.path_len);
    try std.testing.expectEqualStrings("-", if (entry.client_ip_len > 0) entry.getClientIp() else "-");
}
