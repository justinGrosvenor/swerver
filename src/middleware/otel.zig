const std = @import("std");
const clock = @import("../runtime/clock.zig");
const net = @import("../runtime/net.zig");
const request_mod = @import("../protocol/request.zig");

const config_mod = @import("../config.zig");
pub const OtelConfig = config_mod.OtelConfig;

pub const Span = struct {
    trace_id: [16]u8,
    span_id: [8]u8,
    start_ns: i128,
    end_ns: i128,
    status: u16,
    method: request_mod.Method,
    path_len: u16,
    path_buf: [256]u8,

    fn path(self: *const Span) []const u8 {
        return self.path_buf[0..self.path_len];
    }
};

const RING_SIZE: usize = 1024;

pub const TraceExporter = struct {
    config: OtelConfig,
    ring: [RING_SIZE]Span = undefined,
    write_pos: usize = 0,
    read_pos: usize = 0,
    count: usize = 0,
    last_flush_ms: u64 = 0,
    rng: std.Random.DefaultPrng,
    sample_threshold: u16,

    pub fn init(config: OtelConfig) TraceExporter {
        return .{
            .config = config,
            .rng = std.Random.DefaultPrng.init(if (clock.Instant.now()) |i| i.ns else 42),
            .sample_threshold = config.sample_rate,
        };
    }

    pub fn recordSpan(
        self: *TraceExporter,
        method: request_mod.Method,
        path_slice: []const u8,
        status: u16,
        start_ns: i128,
        end_ns: i128,
    ) void {
        if (!self.config.enabled) return;

        // Sampling: skip if random value exceeds threshold
        if (self.sample_threshold < 100) {
            const rand_val = self.rng.random().intRangeAtMost(u16, 0, 99);
            if (rand_val >= self.sample_threshold) return;
        }

        var span: Span = undefined;
        self.rng.random().bytes(&span.trace_id);
        self.rng.random().bytes(&span.span_id);
        span.start_ns = start_ns;
        span.end_ns = end_ns;
        span.status = status;
        span.method = method;
        span.path_len = @intCast(@min(path_slice.len, span.path_buf.len));
        @memcpy(span.path_buf[0..span.path_len], path_slice[0..span.path_len]);

        self.ring[self.write_pos] = span;
        self.write_pos = (self.write_pos + 1) % RING_SIZE;
        if (self.count < RING_SIZE) {
            self.count += 1;
        } else {
            self.read_pos = (self.read_pos + 1) % RING_SIZE;
        }
    }

    pub fn tick(self: *TraceExporter, now_ms: u64) void {
        if (!self.config.enabled or self.count == 0) return;
        const interval_ms: u64 = @as(u64, self.config.flush_interval_s) * 1000;
        if (now_ms -% self.last_flush_ms < interval_ms) return;
        self.last_flush_ms = now_ms;
        self.flush();
    }

    fn flush(self: *TraceExporter) void {
        const batch_size = @min(self.count, self.config.max_batch_size);
        if (batch_size == 0) return;

        var buf: [65536]u8 = undefined;
        const json = self.encodeOtlpJson(&buf, batch_size) orelse return;

        self.sendToCollector(json);

        self.read_pos = (self.read_pos + batch_size) % RING_SIZE;
        self.count -= batch_size;
    }

    fn encodeOtlpJson(self: *TraceExporter, buf: []u8, batch_size: usize) ?[]const u8 {
        var off: usize = 0;
        const header = std.fmt.bufPrint(buf[off..],
            \\{{"resourceSpans":[{{"resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"{s}"}}}}]}},"scopeSpans":[{{"scope":{{"name":"swerver"}},"spans":[
        , .{self.config.service_name}) catch return null;
        off += header.len;

        var pos = self.read_pos;
        var i: usize = 0;
        while (i < batch_size) : (i += 1) {
            if (i > 0) {
                if (off >= buf.len) return null;
                buf[off] = ',';
                off += 1;
            }

            const span = &self.ring[pos];
            pos = (pos + 1) % RING_SIZE;

            var trace_hex: [32]u8 = undefined;
            var span_hex: [16]u8 = undefined;
            hexEncode(&trace_hex, &span.trace_id);
            hexEncode16(&span_hex, &span.span_id);

            const method_name = @tagName(span.method);
            const otel_status: u8 = if (span.status >= 400) 2 else 1;

            const span_json = std.fmt.bufPrint(buf[off..],
                \\{{"traceId":"{s}","spanId":"{s}","name":"HTTP {s} {s}","kind":2,"startTimeUnixNano":"{d}","endTimeUnixNano":"{d}","attributes":[{{"key":"http.method","value":{{"stringValue":"{s}"}}}},{{"key":"http.status_code","value":{{"intValue":"{d}"}}}},{{"key":"http.target","value":{{"stringValue":"{s}"}}}}],"status":{{"code":{d}}}}}
            , .{
                trace_hex,
                span_hex,
                method_name,
                span.path(),
                span.start_ns,
                span.end_ns,
                method_name,
                span.status,
                span.path(),
                otel_status,
            }) catch return null;
            off += span_json.len;
        }

        const footer = "]}]}]}";
        if (off + footer.len > buf.len) return null;
        @memcpy(buf[off .. off + footer.len], footer);
        off += footer.len;

        return buf[0..off];
    }

    fn sendToCollector(self: *TraceExporter, body: []const u8) void {
        const parsed = parseCollectorUrl(self.config.collector_url) orelse return;

        const fd = net.connectBlocking(parsed.host, parsed.port, 2000) catch return;
        defer clock.closeFd(fd);

        net.setSocketTimeouts(fd, 2000, 2000);

        var req_buf: [1024]u8 = undefined;
        const req_header = std.fmt.bufPrint(&req_buf,
            "POST {s}/v1/traces HTTP/1.1\r\nHost: {s}:{d}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
            .{ parsed.path, parsed.host, parsed.port, body.len },
        ) catch return;

        net.sendAll(fd, req_header) catch return;
        net.sendAll(fd, body) catch return;

        // Read response (don't care about status, just drain the socket)
        var resp_buf: [512]u8 = undefined;
        _ = net.recvBlocking(fd, &resp_buf) catch {};
    }
};

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseCollectorUrl(url: []const u8) ?ParsedUrl {
    var rest = url;
    var default_port: u16 = 80;

    if (std.mem.startsWith(u8, rest, "https://")) {
        rest = rest[8..];
        default_port = 443;
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest[7..];
    }

    const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "";

    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
        const port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null;
        return .{ .host = host_port[0..colon], .port = port, .path = path };
    }

    return .{ .host = host_port, .port = default_port, .path = path };
}

fn hexEncode(out: *[32]u8, in: *const [16]u8) void {
    const hex = "0123456789abcdef";
    for (in, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xf];
    }
}

fn hexEncode16(out: *[16]u8, in: *const [8]u8) void {
    const hex = "0123456789abcdef";
    for (in, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xf];
    }
}

// ── Tests ──

test "parseCollectorUrl parses http with port" {
    const result = parseCollectorUrl("http://otel.local:4318") orelse return error.ParseFailed;
    try std.testing.expectEqualStrings("otel.local", result.host);
    try std.testing.expectEqual(@as(u16, 4318), result.port);
    try std.testing.expectEqualStrings("", result.path);
}

test "parseCollectorUrl parses https without port" {
    const result = parseCollectorUrl("https://otel.example.com/v1") orelse return error.ParseFailed;
    try std.testing.expectEqualStrings("otel.example.com", result.host);
    try std.testing.expectEqual(@as(u16, 443), result.port);
    try std.testing.expectEqualStrings("/v1", result.path);
}

test "parseCollectorUrl parses localhost default" {
    const result = parseCollectorUrl("http://localhost:4318") orelse return error.ParseFailed;
    try std.testing.expectEqualStrings("localhost", result.host);
    try std.testing.expectEqual(@as(u16, 4318), result.port);
}

test "TraceExporter records and encodes spans" {
    var exporter = TraceExporter.init(.{
        .enabled = true,
        .collector_url = "http://localhost:4318",
        .service_name = "test-svc",
    });

    exporter.recordSpan(.GET, "/api/health", 200, 1000000, 2000000);
    try std.testing.expectEqual(@as(usize, 1), exporter.count);

    var buf: [65536]u8 = undefined;
    const json = exporter.encodeOtlpJson(&buf, 1) orelse return error.EncodeFailed;
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service.name\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "test-svc") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "/api/health") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"http.status_code\"") != null);
}

test "TraceExporter respects sampling" {
    var exporter = TraceExporter.init(.{
        .enabled = true,
        .sample_rate = 0,
    });

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        exporter.recordSpan(.GET, "/test", 200, 1000, 2000);
    }
    try std.testing.expectEqual(@as(usize, 0), exporter.count);
}

test "TraceExporter disabled does nothing" {
    var exporter = TraceExporter.init(.{ .enabled = false });
    exporter.recordSpan(.GET, "/test", 200, 1000, 2000);
    try std.testing.expectEqual(@as(usize, 0), exporter.count);
}

test "TraceExporter ring wraps correctly" {
    var exporter = TraceExporter.init(.{
        .enabled = true,
        .sample_rate = 100,
    });

    var i: usize = 0;
    while (i < RING_SIZE + 10) : (i += 1) {
        exporter.recordSpan(.GET, "/test", 200, @intCast(i * 1000), @intCast(i * 1000 + 500));
    }
    try std.testing.expectEqual(RING_SIZE, exporter.count);
}

test "hexEncode produces correct output" {
    const input = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    var output: [32]u8 = undefined;
    hexEncode(&output, &input);
    try std.testing.expectEqualStrings("0123456789abcdef0011223344556677", &output);
}
