const std = @import("std");
const x402_mod = @import("x402.zig");
const clock = @import("../runtime/clock.zig");

pub const QUEUE_SIZE = 32;

pub const Kind = enum(u8) { verify, settle };

pub const RequestEntry = struct {
    kind: Kind = .verify,
    conn_index: u32 = 0,
    conn_id: u64 = 0,
    http_buf: [8192]u8 = undefined,
    http_len: u16 = 0,
    host: [253]u8 = undefined,
    host_len: u8 = 0,
    port: u16 = 443,
    use_tls: bool = true,
    timeout_ms: u32 = 5_000,
    gateway_id: [64]u8 = undefined,
    gateway_id_len: u8 = 0,
    settle_network: [64]u8 = undefined,
    settle_network_len: u8 = 0,
    settle_asset: [64]u8 = undefined,
    settle_asset_len: u8 = 0,
    settle_amount: [32]u8 = undefined,
    settle_amount_len: u8 = 0,
    has_settlement_url: bool = false,
};

pub const ResultEntry = struct {
    kind: Kind = .verify,
    conn_index: u32 = 0,
    conn_id: u64 = 0,
    is_valid: bool = false,
    success: bool = false,
    transaction: [128]u8 = undefined,
    transaction_len: u8 = 0,
    error_reason: [128]u8 = undefined,
    error_reason_len: u8 = 0,
    gateway_id: [64]u8 = undefined,
    gateway_id_len: u8 = 0,
    settle_network: [64]u8 = undefined,
    settle_network_len: u8 = 0,
    settle_asset: [64]u8 = undefined,
    settle_asset_len: u8 = 0,
    settle_amount: [32]u8 = undefined,
    settle_amount_len: u8 = 0,
    has_settlement_url: bool = false,
    receipt_b64: [512]u8 = undefined,
    receipt_b64_len: u16 = 0,
};

// SPSC ring buffers. Correctness relies on release/acquire pairing:
// producer writes entry data, then publishes tail with .release;
// consumer acquires tail with .acquire before reading entry data.
// The 10ms poll timeout in the reactor guarantees bounded result
// delivery latency without an eventfd wakeup primitive.
var request_queue: [QUEUE_SIZE]RequestEntry = undefined;
var request_head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var request_tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

var result_queue: [QUEUE_SIZE]ResultEntry = undefined;
var result_head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var result_tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

var shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var thread_handle: ?std.Thread = null;

const MAX_SETTLE_RETRIES: u8 = 3;
const SETTLE_RETRY_NS: u64 = 1_000_000_000;

pub var settle_fail_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var spill_fd: i32 = -1;
pub var worker_id: u16 = 0;

/// Spill file path and rotation cap. The file records lost settlements (lost
/// revenue), so it is fsync'd per line and rotated rather than grown without
/// bound.
const SPILL_PATH = "settle-failures.jsonl";
const SPILL_ROTATE_PATH = "settle-failures.jsonl.1";
const SPILL_MAX_BYTES: u64 = 16 * 1024 * 1024;
var spill_bytes: u64 = 0;
var spill_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub fn start() void {
    if (thread_handle != null) return;
    shutdown_flag.store(false, .release);
    request_head.store(0, .release);
    request_tail.store(0, .release);
    result_head.store(0, .release);
    result_tail.store(0, .release);
    // 0o600: the file holds financial metadata; keep it owner-only.
    spill_fd = std.posix.openat(std.posix.AT.FDCWD, SPILL_PATH, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o600) catch -1;
    spill_bytes = 0;
    thread_handle = std.Thread.spawn(.{}, workerLoop, .{}) catch |err| {
        std.log.warn("x402_client: failed to spawn thread: {}", .{err});
        return;
    };
}

pub fn stop() void {
    shutdown_flag.store(true, .release);
    if (thread_handle) |t| {
        t.join();
        thread_handle = null;
    }
    if (spill_fd >= 0) {
        clock.closeFd(spill_fd);
        spill_fd = -1;
    }
}

pub fn submit(entry: RequestEntry) bool {
    const tail = request_tail.load(.monotonic);
    const next_tail = (tail + 1) % QUEUE_SIZE;
    if (next_tail == request_head.load(.acquire)) return false;
    request_queue[tail] = entry;
    request_tail.store(next_tail, .release);
    return true;
}

pub fn pollResult() ?ResultEntry {
    const head = result_head.load(.monotonic);
    if (head == result_tail.load(.acquire)) return null;
    const entry = result_queue[head];
    result_head.store((head + 1) % QUEUE_SIZE, .release);
    return entry;
}

/// Write a failed/dropped settle to the spill file for manual recovery.
/// Safe to call from any thread — O_APPEND writes under PIPE_BUF are atomic.
pub fn spillSettle(gateway_id: []const u8, network: []const u8, asset: []const u8, amount: []const u8, err_reason: []const u8) void {
    _ = settle_fail_count.fetchAdd(1, .monotonic);
    if (spill_fd < 0) return;
    var buf: [1024]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{{\"worker\":{d},\"gateway_id\":\"{s}\",\"network\":\"{s}\",\"asset\":\"{s}\",\"amount\":\"{s}\",\"error\":\"{s}\"}}\n", .{ worker_id, gateway_id, network, asset, amount, err_reason }) catch return;

    // Serialize append + rotation; spillSettle may be called from the worker
    // thread and the reactor (on queue-full drop).
    while (spill_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {}
    defer spill_lock.store(0, .release);
    if (spill_fd < 0) return;

    // Rotate when the cap is reached so the file never grows without bound.
    if (spill_bytes + line.len > SPILL_MAX_BYTES) {
        _ = std.c.rename(SPILL_PATH, SPILL_ROTATE_PATH);
        clock.closeFd(spill_fd);
        spill_fd = std.posix.openat(std.posix.AT.FDCWD, SPILL_PATH, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o600) catch -1;
        spill_bytes = 0;
        if (spill_fd < 0) return;
    }

    const written = std.c.write(spill_fd, line.ptr, line.len);
    if (written > 0) {
        spill_bytes += @intCast(written);
        // Durability: this is a lost-revenue record, so flush to disk rather
        // than risk losing it in the page cache on crash/power-loss.
        _ = std.c.fsync(spill_fd);
    }
}

fn dequeueRequest() ?RequestEntry {
    const head = request_head.load(.monotonic);
    if (head == request_tail.load(.acquire)) return null;
    const entry = request_queue[head];
    request_head.store((head + 1) % QUEUE_SIZE, .release);
    return entry;
}

fn enqueueResult(entry: ResultEntry) void {
    const tail = result_tail.load(.monotonic);
    const next_tail = (tail + 1) % QUEUE_SIZE;
    if (next_tail == result_head.load(.acquire)) {
        std.log.warn("x402_client: result queue full, dropping", .{});
        return;
    }
    result_queue[tail] = entry;
    result_tail.store(next_tail, .release);
}

fn workerLoop() void {
    while (!shutdown_flag.load(.acquire)) {
        if (dequeueRequest()) |req| {
            const config = x402_mod.FacilitatorConfig{
                .host = req.host[0..req.host_len],
                .port = req.port,
                .use_tls = req.use_tls,
                .timeout_ms = req.timeout_ms,
            };
            switch (req.kind) {
                .verify => {
                    var result = ResultEntry{ .kind = .verify, .conn_index = req.conn_index, .conn_id = req.conn_id };
                    var resp_buf: [8192]u8 = undefined;
                    const resp_len = x402_mod.facilitatorRoundTrip(config, req.http_buf[0..req.http_len], &resp_buf) catch 0;
                    if (resp_len > 0) {
                        result.is_valid = x402_mod.parseVerifyResponse(resp_buf[0..resp_len]).is_valid;
                    }
                    enqueueResult(result);
                },
                .settle => {
                    var result = ResultEntry{ .kind = .settle, .conn_index = req.conn_index, .conn_id = req.conn_id };
                    var attempt: u8 = 0;
                    while (attempt < MAX_SETTLE_RETRIES) : (attempt += 1) {
                        if (shutdown_flag.load(.acquire)) break;
                        var resp_buf: [8192]u8 = undefined;
                        const resp_len = x402_mod.facilitatorRoundTrip(config, req.http_buf[0..req.http_len], &resp_buf) catch 0;
                        if (resp_len > 0) {
                            const sr = x402_mod.parseSettleResponse(resp_buf[0..resp_len]);
                            copyFixed(&result.error_reason, &result.error_reason_len, sr.error_reason);
                            if (sr.success) {
                                result.success = true;
                                copyFixed(&result.transaction, &result.transaction_len, sr.transaction);
                                if (x402_mod.buildReceiptB64(&sr)) |rb64| {
                                    const rlen: u16 = @intCast(@min(rb64.len, result.receipt_b64.len));
                                    @memcpy(result.receipt_b64[0..rlen], rb64[0..rlen]);
                                    result.receipt_b64_len = rlen;
                                }
                                break;
                            }
                        } else {
                            copyFixed(&result.error_reason, &result.error_reason_len, "facilitator unreachable");
                        }
                        if (attempt + 1 < MAX_SETTLE_RETRIES) sleepNs(SETTLE_RETRY_NS);
                    }
                    result.gateway_id = req.gateway_id;
                    result.gateway_id_len = req.gateway_id_len;
                    result.settle_network = req.settle_network;
                    result.settle_network_len = req.settle_network_len;
                    result.settle_asset = req.settle_asset;
                    result.settle_asset_len = req.settle_asset_len;
                    result.settle_amount = req.settle_amount;
                    result.settle_amount_len = req.settle_amount_len;
                    result.has_settlement_url = req.has_settlement_url;
                    if (!result.success) {
                        spillSettle(
                            req.gateway_id[0..req.gateway_id_len],
                            req.settle_network[0..req.settle_network_len],
                            req.settle_asset[0..req.settle_asset_len],
                            req.settle_amount[0..req.settle_amount_len],
                            result.error_reason[0..result.error_reason_len],
                        );
                    }
                    enqueueResult(result);
                },
            }
        } else {
            sleepNs(1_000_000);
        }
    }
}

fn sleepNs(ns: u64) void {
    var ts = std.posix.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: std.posix.timespec = .{ .sec = 0, .nsec = 0 };
    while (true) {
        const rc = std.posix.system.nanosleep(&ts, &rem);
        if (rc == 0) return;
        switch (std.posix.errno(rc)) {
            .INTR => ts = rem,
            else => return,
        }
    }
}

fn copyFixed(dst: *[128]u8, len: *u8, src: []const u8) void {
    const n: u8 = @intCast(@min(src.len, 128));
    @memcpy(dst[0..n], src[0..n]);
    len.* = n;
}

// ============================================================
// Tests
// ============================================================

test "submit and poll roundtrip" {
    request_head.store(0, .release);
    request_tail.store(0, .release);
    result_head.store(0, .release);
    result_tail.store(0, .release);

    try std.testing.expect(submit(.{ .kind = .verify, .conn_index = 42, .conn_id = 100 }));

    const req = dequeueRequest() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 42), req.conn_index);
    try std.testing.expectEqual(@as(u64, 100), req.conn_id);

    enqueueResult(.{ .kind = .verify, .conn_index = 42, .conn_id = 100, .is_valid = true });

    const polled = pollResult() orelse return error.TestUnexpectedResult;
    try std.testing.expect(polled.is_valid);
    try std.testing.expectEqual(@as(u32, 42), polled.conn_index);
}

test "queue full returns false" {
    request_head.store(0, .release);
    request_tail.store(0, .release);

    var i: u32 = 0;
    while (i < QUEUE_SIZE - 1) : (i += 1) {
        try std.testing.expect(submit(.{ .kind = .verify, .conn_index = i, .conn_id = i }));
    }
    try std.testing.expect(!submit(.{ .kind = .verify, .conn_index = 999, .conn_id = 999 }));
}

test "poll empty returns null" {
    result_head.store(0, .release);
    result_tail.store(0, .release);
    try std.testing.expect(pollResult() == null);
}

test "settle_fail_count increments on spill" {
    const before = settle_fail_count.load(.monotonic);
    const saved_fd = spill_fd;
    spill_fd = -1;
    spillSettle("gw1", "base", "USDC", "100", "test error");
    try std.testing.expectEqual(before + 1, settle_fail_count.load(.monotonic));
    spill_fd = saved_fd;
}

test "settle result carries receipt_b64" {
    result_head.store(0, .release);
    result_tail.store(0, .release);

    var r = ResultEntry{ .kind = .settle, .conn_index = 7, .conn_id = 42, .success = true };
    const receipt = "eyJzdWNjZXNzIjp0cnVlfQ==";
    const rlen: u16 = @intCast(receipt.len);
    @memcpy(r.receipt_b64[0..rlen], receipt);
    r.receipt_b64_len = rlen;
    enqueueResult(r);

    const polled = pollResult() orelse return error.TestUnexpectedResult;
    try std.testing.expect(polled.success);
    try std.testing.expectEqual(@as(u16, rlen), polled.receipt_b64_len);
    try std.testing.expectEqualStrings(receipt, polled.receipt_b64[0..polled.receipt_b64_len]);
}
