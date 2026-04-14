const std = @import("std");
const builtin = @import("builtin");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");
const clock = @import("../runtime/clock.zig");
const json_write = @import("../runtime/json_write.zig");

const is_linux = builtin.os.tag == .linux;
const linux = if (is_linux) std.os.linux else undefined;

/// Observability Middleware
///
/// Provides structured logging, request tracing, and request ID propagation.
/// Uses pre-allocated buffers for zero heap allocations.

/// Log levels
pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }
};

/// Structured log entry
pub const LogEntry = struct {
    level: Level = .info,
    timestamp_ns: i128 = 0,
    request_id: ?[]const u8 = null,
    protocol: middleware.Context.Protocol = .http1,
    stream_id: u64 = 0,
    method: ?request.Method = null,
    path: ?[]const u8 = null,
    status: u16 = 0,
    latency_us: u64 = 0,
    client_ip: ?[4]u8 = null,
    route: ?[]const u8 = null,
    message: ?[]const u8 = null,
    error_msg: ?[]const u8 = null,

    /// Write a JSON `,"key":"escaped_value"` field into `out`, returning
    /// the total bytes written. `prefix` is the literal `,"key":"` segment
    /// — **the leading comma is not optional**. Closes the value with `"`.
    ///
    /// REQUIRES: at least one field must have already been written to the
    /// buffer before this is called, otherwise the resulting JSON will
    /// start with a stray `,`. In `formatJson`, the `ts` and `level` pair
    /// is always emitted first and unconditionally, which satisfies this
    /// invariant. If you add an earlier optional field, thread a
    /// `first: bool` through the helper instead — don't quietly rely on
    /// ordering.
    fn writeEscapedField(out: []u8, prefix: []const u8, value: []const u8) !usize {
        if (prefix.len > out.len) return error.NoSpaceLeft;
        @memcpy(out[0..prefix.len], prefix);
        var off: usize = prefix.len;
        const escaped = try json_write.writeEscaped(out[off..], value);
        off += escaped.len;
        if (off + 1 > out.len) return error.NoSpaceLeft;
        out[off] = '"';
        off += 1;
        return off;
    }

    /// Format as JSON (no heap allocation). Control characters in
    /// path/route/message/error fields are emitted as `\u00XX` per RFC 8259
    /// via `json_write.writeEscaped`. Returns `error.NoSpaceLeft` if `buf`
    /// is too small to hold the serialized entry.
    pub fn formatJson(self: *const LogEntry, buf: []u8) ![]const u8 {
        var off: usize = 0;

        const header = try std.fmt.bufPrint(
            buf[off..],
            "{{\"ts\":{d},\"level\":\"{s}\"",
            .{ self.timestamp_ns, self.level.toString() },
        );
        off += header.len;

        if (self.request_id) |rid| {
            const piece = try std.fmt.bufPrint(buf[off..], ",\"request_id\":\"{s}\"", .{rid});
            off += piece.len;
        }

        const protocol = try std.fmt.bufPrint(buf[off..], ",\"protocol\":\"{s}\"", .{self.protocol.toString()});
        off += protocol.len;

        if (self.stream_id != 0) {
            const piece = try std.fmt.bufPrint(buf[off..], ",\"stream_id\":{d}", .{self.stream_id});
            off += piece.len;
        }

        if (self.method) |m| {
            const piece = try std.fmt.bufPrint(buf[off..], ",\"method\":\"{s}\"", .{@tagName(m)});
            off += piece.len;
        }

        if (self.path) |p| {
            off += try writeEscapedField(buf[off..], ",\"path\":\"", p);
        }

        if (self.status != 0) {
            const piece = try std.fmt.bufPrint(buf[off..], ",\"status\":{d}", .{self.status});
            off += piece.len;
        }

        if (self.latency_us != 0) {
            const piece = try std.fmt.bufPrint(buf[off..], ",\"latency_us\":{d}", .{self.latency_us});
            off += piece.len;
        }

        if (self.client_ip) |ip| {
            const piece = try std.fmt.bufPrint(buf[off..], ",\"client_ip\":\"{d}.{d}.{d}.{d}\"", .{ ip[0], ip[1], ip[2], ip[3] });
            off += piece.len;
        }

        if (self.route) |r| {
            off += try writeEscapedField(buf[off..], ",\"route\":\"", r);
        }

        if (self.message) |msg| {
            off += try writeEscapedField(buf[off..], ",\"msg\":\"", msg);
        }

        if (self.error_msg) |err_msg| {
            off += try writeEscapedField(buf[off..], ",\"error\":\"", err_msg);
        }

        if (off + 2 > buf.len) return error.NoSpaceLeft;
        buf[off] = '}';
        buf[off + 1] = '\n';
        off += 2;

        return buf[0..off];
    }

    /// Format as logfmt (key=value pairs). No JSON escaping — logfmt uses
    /// simple quoting for values with spaces, and ingesters tolerate raw
    /// control chars in quoted values.
    pub fn formatLogfmt(self: *const LogEntry, buf: []u8) ![]const u8 {
        var off: usize = 0;

        const header = try std.fmt.bufPrint(
            buf[off..],
            "ts={d} level={s}",
            .{ self.timestamp_ns, self.level.toString() },
        );
        off += header.len;

        if (self.request_id) |rid| {
            const piece = try std.fmt.bufPrint(buf[off..], " request_id={s}", .{rid});
            off += piece.len;
        }

        const protocol = try std.fmt.bufPrint(buf[off..], " protocol={s}", .{self.protocol.toString()});
        off += protocol.len;

        if (self.stream_id != 0) {
            const piece = try std.fmt.bufPrint(buf[off..], " stream_id={d}", .{self.stream_id});
            off += piece.len;
        }

        if (self.method) |m| {
            const piece = try std.fmt.bufPrint(buf[off..], " method={s}", .{@tagName(m)});
            off += piece.len;
        }

        if (self.path) |p| {
            const piece = try std.fmt.bufPrint(buf[off..], " path=\"{s}\"", .{p});
            off += piece.len;
        }

        if (self.status != 0) {
            const piece = try std.fmt.bufPrint(buf[off..], " status={d}", .{self.status});
            off += piece.len;
        }

        if (self.latency_us != 0) {
            const piece = try std.fmt.bufPrint(buf[off..], " latency_us={d}", .{self.latency_us});
            off += piece.len;
        }

        if (self.client_ip) |ip| {
            const piece = try std.fmt.bufPrint(buf[off..], " client_ip={d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
            off += piece.len;
        }

        if (self.route) |r| {
            const piece = try std.fmt.bufPrint(buf[off..], " route=\"{s}\"", .{r});
            off += piece.len;
        }

        if (self.message) |msg| {
            const piece = try std.fmt.bufPrint(buf[off..], " msg=\"{s}\"", .{msg});
            off += piece.len;
        }

        if (self.error_msg) |err| {
            const piece = try std.fmt.bufPrint(buf[off..], " error=\"{s}\"", .{err});
            off += piece.len;
        }

        if (off + 1 > buf.len) return error.NoSpaceLeft;
        buf[off] = '\n';
        off += 1;

        return buf[0..off];
    }
};

/// Logger configuration
pub const Config = struct {
    /// Minimum log level
    min_level: Level = .info,
    /// Output format
    format: Format = .json,
    /// Log to stderr
    log_stderr: bool = true,
    /// Include request/response bodies in debug logs
    log_bodies: bool = false,
    /// Propagate request ID header
    request_id_header: []const u8 = "X-Request-Id",
    /// Generate request ID if not present
    generate_request_id: bool = true,
    /// Enable eBPF counters (requires kernel support)
    enable_ebpf: bool = false,

    pub const Format = enum {
        json,
        logfmt,
    };
};

// =============================================================================
// onExit Hooks - Callback registration for connection/request lifecycle events
// =============================================================================

/// Exit reason for onExit callbacks
pub const ExitReason = enum {
    normal,
    timeout,
    client_error,
    server_error,
    congestion,
    rate_limited,
    protocol_error,
};

/// Exit context passed to onExit callbacks
pub const ExitContext = struct {
    reason: ExitReason,
    request_id: ?[]const u8,
    protocol: middleware.Context.Protocol,
    stream_id: u64,
    latency_us: u64,
    bytes_sent: u64,
    bytes_received: u64,
    status: u16,
    error_msg: ?[]const u8,
};

/// onExit callback function type
pub const OnExitFn = *const fn (ctx: *const ExitContext) void;

/// Maximum registered onExit callbacks
const MAX_EXIT_HOOKS = 16;

/// Registered onExit callbacks
var exit_hooks: [MAX_EXIT_HOOKS]?OnExitFn = [_]?OnExitFn{null} ** MAX_EXIT_HOOKS;
var exit_hook_count: usize = 0;

/// Register an onExit callback
pub fn registerOnExit(callback: OnExitFn) bool {
    if (exit_hook_count >= MAX_EXIT_HOOKS) return false;
    exit_hooks[exit_hook_count] = callback;
    exit_hook_count += 1;
    return true;
}

/// Invoke all registered onExit callbacks
pub fn invokeOnExit(ctx: *const ExitContext) void {
    for (exit_hooks[0..exit_hook_count]) |maybe_hook| {
        if (maybe_hook) |hook| {
            hook(ctx);
        }
    }
}

/// Helper to determine exit reason from response status
pub fn exitReasonFromStatus(status: u16) ExitReason {
    if (status >= 500) return .server_error;
    if (status == 429) return .rate_limited;
    if (status >= 400) return .client_error;
    return .normal;
}

// =============================================================================
// eBPF Counter Interface - BPF maps on Linux, in-memory fallback elsewhere
// =============================================================================

/// eBPF counter types
pub const EbpfCounter = enum(u32) {
    requests_total = 0,
    responses_total = 1,
    bytes_sent = 2,
    bytes_received = 3,
    errors = 4,
    congestion_events = 5,
    rate_limit_hits = 6,
    connection_timeouts = 7,
};

const ebpf_counter_count = 8;

/// BPF map wrapper — creates a BPF_MAP_TYPE_ARRAY on Linux via bpf() syscall.
/// Falls back gracefully if not on Linux or if bpf() fails (no CAP_BPF).
const BpfMap = struct {
    fd: i32 = -1,

    const BPF_MAP_CREATE: usize = 0;
    const BPF_MAP_LOOKUP_ELEM: usize = 1;
    const BPF_MAP_UPDATE_ELEM: usize = 2;
    const BPF_MAP_TYPE_ARRAY: u32 = 2;
    const BPF_ANY: u64 = 0;

    const BpfMapCreateAttr = extern struct {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32 = 0,
        _pad: [48]u8 = [_]u8{0} ** 48,
    };

    const BpfMapElemAttr = extern struct {
        map_fd: u32,
        _pad0: u32 = 0,
        key: u64,
        value: u64,
        flags: u64 = BPF_ANY,
        _pad: [32]u8 = [_]u8{0} ** 32,
    };

    fn create(max_entries: u32) BpfMap {
        if (!is_linux) return .{};
        var attr = BpfMapCreateAttr{
            .map_type = BPF_MAP_TYPE_ARRAY,
            .key_size = @sizeOf(u32),
            .value_size = @sizeOf(u64),
            .max_entries = max_entries,
        };
        const rc = linux.syscall3(.bpf, BPF_MAP_CREATE, @intFromPtr(&attr), @sizeOf(BpfMapCreateAttr));
        const fd: i64 = @bitCast(rc);
        if (fd < 0) return .{}; // No CAP_BPF or not supported — fall back
        return .{ .fd = @intCast(fd) };
    }

    fn update(self: BpfMap, key: u32, value: u64) void {
        if (!is_linux or self.fd < 0) return;
        var k = key;
        var v = value;
        var attr = BpfMapElemAttr{
            .map_fd = @intCast(self.fd),
            .key = @intFromPtr(&k),
            .value = @intFromPtr(&v),
        };
        _ = linux.syscall3(.bpf, BPF_MAP_UPDATE_ELEM, @intFromPtr(&attr), @sizeOf(BpfMapElemAttr));
    }

    fn lookup(self: BpfMap, key: u32) u64 {
        if (!is_linux or self.fd < 0) return 0;
        var k = key;
        var v: u64 = 0;
        var attr = BpfMapElemAttr{
            .map_fd = @intCast(self.fd),
            .key = @intFromPtr(&k),
            .value = @intFromPtr(&v),
        };
        const rc = linux.syscall3(.bpf, BPF_MAP_LOOKUP_ELEM, @intFromPtr(&attr), @sizeOf(BpfMapElemAttr));
        const result: i64 = @bitCast(rc);
        if (result < 0) return 0;
        return v;
    }
};

/// eBPF counter interface — uses BPF maps on Linux (when available),
/// falls back to in-memory counters on other platforms or when bpf() fails.
pub const EbpfCounters = struct {
    enabled: bool = false,
    bpf_map: BpfMap = .{},

    // In-memory fallback counters (always maintained for atomicity)
    counters: [ebpf_counter_count]u64 = [_]u64{0} ** ebpf_counter_count,

    /// Initialize eBPF counters. On Linux, attempts to create a BPF array map.
    pub fn init(enable: bool) EbpfCounters {
        var self = EbpfCounters{ .enabled = enable };
        if (enable) {
            self.bpf_map = BpfMap.create(ebpf_counter_count);
        }
        return self;
    }

    /// Increment a counter (updates both in-memory and BPF map if available)
    pub fn increment(self: *EbpfCounters, counter: EbpfCounter, value: u64) void {
        if (!self.enabled) return;

        const idx = @intFromEnum(counter);
        self.counters[idx] +|= value;

        // Also update BPF map if available
        if (self.bpf_map.fd >= 0) {
            self.bpf_map.update(idx, self.counters[idx]);
        }
    }

    /// Read a counter value (prefers BPF map if available, else in-memory)
    pub fn read(self: *const EbpfCounters, counter: EbpfCounter) u64 {
        if (!self.enabled) return 0;

        const idx = @intFromEnum(counter);
        if (self.bpf_map.fd >= 0) {
            const bpf_val = self.bpf_map.lookup(idx);
            if (bpf_val > 0) return bpf_val;
        }
        return self.counters[idx];
    }
};

/// Global eBPF counters instance
var ebpf_counters: EbpfCounters = .{};

/// Get eBPF counters
pub fn getEbpfCounters() *EbpfCounters {
    return &ebpf_counters;
}

// =============================================================================
// Congestion Alert Hooks
// =============================================================================

/// Congestion level
pub const CongestionLevel = enum {
    none,
    mild, // >50% capacity
    moderate, // >75% capacity
    severe, // >90% capacity
    critical, // Dropping requests
};

/// Congestion alert callback
pub const CongestionAlertFn = *const fn (level: CongestionLevel, queue_depth: u64, active_connections: u64) void;

/// Registered congestion alert callbacks
var congestion_hooks: [MAX_EXIT_HOOKS]?CongestionAlertFn = [_]?CongestionAlertFn{null} ** MAX_EXIT_HOOKS;
var congestion_hook_count: usize = 0;

/// Register a congestion alert callback
pub fn registerCongestionAlert(callback: CongestionAlertFn) bool {
    if (congestion_hook_count >= MAX_EXIT_HOOKS) return false;
    congestion_hooks[congestion_hook_count] = callback;
    congestion_hook_count += 1;
    return true;
}

/// Invoke congestion alert callbacks
pub fn invokeCongestionAlert(level: CongestionLevel, queue_depth: u64, active_connections: u64) void {
    for (congestion_hooks[0..congestion_hook_count]) |maybe_hook| {
        if (maybe_hook) |hook| {
            hook(level, queue_depth, active_connections);
        }
    }

    // Also increment eBPF counter if severe
    if (level == .severe or level == .critical) {
        ebpf_counters.increment(.congestion_events, 1);
    }
}

/// Global logger config
var config: Config = .{};

/// Initialize logger
pub fn init(cfg: Config) void {
    config = cfg;
}

/// Thread-local format buffer
threadlocal var format_buf: [4096]u8 = undefined;

/// Log a structured entry
pub fn log(entry: LogEntry) void {
    if (@intFromEnum(entry.level) < @intFromEnum(config.min_level)) return;

    const output = switch (config.format) {
        .json => entry.formatJson(&format_buf) catch return,
        .logfmt => entry.formatLogfmt(&format_buf) catch return,
    };

    if (config.log_stderr) {
        _ = std.posix.system.write(2, output.ptr, output.len);
    }
}

/// Request ID storage (per-connection/request)
pub const RequestIdStorage = struct {
    buf: [64]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *RequestIdStorage, id: []const u8) void {
        const copy_len = @min(id.len, 64);
        @memcpy(self.buf[0..copy_len], id[0..copy_len]);
        self.len = copy_len;
    }

    pub fn generate(self: *RequestIdStorage) void {
        // Generate simple request ID from timestamp-derived seed.
        const realtime_ns = clock.realtimeNanos() orelse 0;
        const ts: u64 = @intCast(@mod(realtime_ns, std.math.maxInt(u64)));
        const hash = std.hash.Wyhash.hash(ts, &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 });

        const result = std.fmt.bufPrint(&self.buf, "{x:0>16}", .{hash}) catch {
            self.len = 0;
            return;
        };
        self.len = result.len;
    }

    pub fn get(self: *const RequestIdStorage) ?[]const u8 {
        if (self.len == 0) return null;
        return self.buf[0..self.len];
    }
};

/// Extract or generate request ID
pub fn getOrGenerateRequestId(req: request.RequestView, storage: *RequestIdStorage) []const u8 {
    // Look for existing request ID header
    for (req.headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, config.request_id_header)) {
            storage.set(hdr.value);
            return storage.get() orelse "";
        }
    }

    // Generate new ID if configured
    if (config.generate_request_id) {
        storage.generate();
        return storage.get() orelse "";
    }

    return "";
}

/// Observability middleware - extracts request ID
pub fn evaluate(ctx: *middleware.Context, req: request.RequestView) middleware.Decision {
    // Record request start time
    ctx.request_start = clock.Instant.now();

    // Look for existing request ID header
    var found_id: ?[]const u8 = null;
    for (req.headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, config.request_id_header)) {
            found_id = hdr.value;
            break;
        }
    }

    if (found_id) |id| {
        // Copy into context-owned buffer
        ctx.setRequestId(id);
    } else if (config.generate_request_id) {
        // Generate new ID into context-owned buffer
        ctx.generateRequestId();
    }

    // Return modification with request ID header if we have one
    if (ctx.request_id) |rid| {
        // Response header value points to context buffer (safe)
        return .{ .modify = .{
            .response_headers = &[_]response.Header{
                .{ .name = "X-Request-Id", .value = rid },
            },
            .continue_chain = true,
        } };
    }

    return .allow;
}

/// Post-response logging hook
pub fn postResponse(ctx: *middleware.Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) void {
    const latency_us = elapsed_ns / 1000;

    const level: Level = if (resp.status >= 500)
        .err
    else if (resp.status >= 400)
        .warn
    else
        .info;

    const entry = LogEntry{
        .level = level,
        .timestamp_ns = clock.realtimeNanos() orelse 0,
        .request_id = ctx.request_id,
        .protocol = ctx.protocol,
        .stream_id = ctx.stream_id,
        .method = req.method,
        .path = req.path,
        .status = resp.status,
        .latency_us = latency_us,
        .client_ip = ctx.client_ip,
        .route = ctx.route,
        .message = null,
        .error_msg = null,
    };

    log(entry);

    // Update eBPF counters
    ebpf_counters.increment(.responses_total, 1);
    ebpf_counters.increment(.bytes_sent, resp.bodyLen());
    if (resp.status >= 500) {
        ebpf_counters.increment(.errors, 1);
    }
    if (resp.status == 429) {
        ebpf_counters.increment(.rate_limit_hits, 1);
    }

    // Invoke onExit hooks
    const exit_ctx = ExitContext{
        .reason = exitReasonFromStatus(resp.status),
        .request_id = ctx.request_id,
        .protocol = ctx.protocol,
        .stream_id = ctx.stream_id,
        .latency_us = latency_us,
        .bytes_sent = resp.bodyLen(),
        .bytes_received = 0, // Not tracked at this level
        .status = resp.status,
        .error_msg = null,
    };
    invokeOnExit(&exit_ctx);
}

/// Log a custom message
pub fn logMessage(level: Level, ctx: *const middleware.Context, message: []const u8) void {
    const entry = LogEntry{
        .level = level,
        .timestamp_ns = clock.realtimeNanos() orelse 0,
        .request_id = ctx.request_id,
        .protocol = ctx.protocol,
        .stream_id = ctx.stream_id,
        .message = message,
    };

    log(entry);
}

test "observability postResponse updates ebpf counters" {
    init(.{ .log_stderr = false });
    getEbpfCounters().* = EbpfCounters.init(true);

    var ctx = middleware.Context{ .protocol = .http1 };
    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &[_]request.Header{},
        .body = "",
    };

    const resp_err = response.Response{
        .status = 500,
        .headers = &[_]response.Header{},
        .body = .{ .bytes = "nope" },
    };
    postResponse(&ctx, req, resp_err, 50_000);

    const resp_rate = response.Response{
        .status = 429,
        .headers = &[_]response.Header{},
        .body = .{ .bytes = "slow" },
    };
    postResponse(&ctx, req, resp_rate, 75_000);

    const counters = getEbpfCounters();
    try std.testing.expectEqual(@as(u64, 2), counters.read(.responses_total));
    try std.testing.expectEqual(@as(u64, 8), counters.read(.bytes_sent));
    try std.testing.expectEqual(@as(u64, 1), counters.read(.errors));
    try std.testing.expectEqual(@as(u64, 1), counters.read(.rate_limit_hits));
}

// Tests
test "log entry format json" {
    const entry = LogEntry{
        .level = .info,
        .timestamp_ns = 1234567890,
        .request_id = "abc123",
        .method = .GET,
        .path = "/api/users",
        .status = 200,
        .latency_us = 1500,
    };

    var buf: [1024]u8 = undefined;
    const output = try entry.formatJson(&buf);

    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"INFO\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"request_id\":\"abc123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"status\":200") != null);
}

test "log entry format logfmt" {
    const entry = LogEntry{
        .level = .warn,
        .timestamp_ns = 1234567890,
        .method = .POST,
        .path = "/api/data",
        .status = 400,
    };

    var buf: [1024]u8 = undefined;
    const output = try entry.formatLogfmt(&buf);

    try std.testing.expect(std.mem.indexOf(u8, output, "level=WARN") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "method=POST") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "status=400") != null);
}

test "request id generation" {
    var storage = RequestIdStorage{};
    storage.generate();

    const id = storage.get();
    try std.testing.expect(id != null);
    try std.testing.expect(id.?.len == 16);
}
