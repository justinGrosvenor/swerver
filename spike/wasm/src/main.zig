//! WASM edge-functions Phase 0 spike: the go/no-go benchmark.
//!
//! Measures per-invocation overhead of a trivial-but-representative metadata
//! filter under three implementations:
//!   1. native Zig   (baseline: the cost of NOT using wasm)
//!   2. wasm3         (vendored C interpreter)
//!   3. zware         (pure-Zig interpreter)
//!
//! The same compiled filter.wasm runs in both runtimes; the native baseline is
//! hand-written to do byte-for-byte identical work. The output is ns/op for
//! each, plus the native-multiple, against the design-10.0 bar: a trivial
//! filter must approach single-digit microseconds or the feature does not ship.

const std = @import("std");
const builtin = @import("builtin");

const request = @import("request.zig");
const native = @import("native_baseline.zig");
const wasm3 = @import("runtime_wasm3.zig");
const zware_rt = @import("runtime_zware.zig");

const FILTER_WASM = @embedFile("filter_wasm");

/// Iterations per implementation. Each iteration is one full filter invocation.
const ITERS: u64 = 10_000_000;

fn monoNanos() u64 {
    var ts: std.posix.timespec = undefined;
    const clock_id: std.posix.clockid_t = switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => std.posix.CLOCK.UPTIME_RAW,
        else => std.posix.CLOCK.MONOTONIC,
    };
    _ = std.posix.system.clock_gettime(clock_id, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// Three representative requests, rotated through the loop so the branch
// predictor cannot collapse the filter to one path:
//   - allowed under /api/ (has key)      -> exercises path check + header hit
//   - rejected under /api/ (no key)      -> path check + header miss (full scan)
//   - allowed elsewhere                  -> path check short-circuits
const REQUESTS = [_]request.Request{
    .{
        .path = "/api/v1/orders",
        .headers = &.{
            .{ .name = "host", .value = "example.com" },
            .{ .name = "accept", .value = "application/json" },
            .{ .name = "x-api-key", .value = "sk_live_abc123def456" },
            .{ .name = "user-agent", .value = "curl/8.4.0" },
        },
    },
    .{
        .path = "/api/v1/orders",
        .headers = &.{
            .{ .name = "host", .value = "example.com" },
            .{ .name = "accept", .value = "application/json" },
            .{ .name = "user-agent", .value = "curl/8.4.0" },
        },
    },
    .{
        .path = "/static/app.js",
        .headers = &.{
            .{ .name = "host", .value = "example.com" },
            .{ .name = "accept", .value = "*/*" },
        },
    },
};

const Stats = struct {
    name: []const u8,
    ns_per_op: f64,
    checksum: u64,
};

fn report(stats: []const Stats, baseline_ns: f64) void {
    const out = std.debug;
    out.print("\n", .{});
    out.print("{s:<14} {s:>12} {s:>14} {s:>12}\n", .{ "impl", "ns/op", "vs native", "checksum" });
    out.print("{s:-<14} {s:->12} {s:->14} {s:->12}\n", .{ "", "", "", "" });
    for (stats) |s| {
        const mult = s.ns_per_op / baseline_ns;
        out.print("{s:<14} {d:>12.1} {d:>13.1}x {d:>12}\n", .{ s.name, s.ns_per_op, mult, s.checksum });
    }
    out.print("\n", .{});
}

pub fn main() !void {
    // Setup-only allocations (zware module/store/instance); not on the hot path.
    const alloc = std.heap.c_allocator;

    const iters: u64 = ITERS;

    std.debug.print("wasm edge-function spike: {d} iterations x {d} request shapes\n", .{ iters, REQUESTS.len });
    std.debug.print("filter.wasm size: {d} bytes\n", .{FILTER_WASM.len});

    // --- setup runtimes (cost paid once, off the hot path) ------------------
    var w3 = try wasm3.Runtime.init(FILTER_WASM);
    defer w3.deinit();
    var zw = try zware_rt.Runtime.init(alloc, FILTER_WASM);
    defer zw.deinit();

    // --- correctness gate: all three must agree on every request ------------
    try verifyAgreement(&w3, &zw);

    var stats: [3]Stats = undefined;

    // 1. native
    {
        var checksum: u64 = 0;
        const start = monoNanos();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            request.current = &REQUESTS[i % REQUESTS.len];
            checksum +%= @intCast(@intFromEnum(native.onRequest()));
        }
        const elapsed = monoNanos() - start;
        stats[0] = .{ .name = "native", .ns_per_op = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iters)), .checksum = checksum };
    }

    // 2. wasm3
    {
        var checksum: u64 = 0;
        const start = monoNanos();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            request.current = &REQUESTS[i % REQUESTS.len];
            checksum +%= @intCast(try w3.onRequest());
        }
        const elapsed = monoNanos() - start;
        stats[1] = .{ .name = "wasm3", .ns_per_op = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iters)), .checksum = checksum };
    }

    // 3. zware
    {
        var checksum: u64 = 0;
        const start = monoNanos();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            request.current = &REQUESTS[i % REQUESTS.len];
            checksum +%= @intCast(try zw.onRequest());
        }
        const elapsed = monoNanos() - start;
        stats[2] = .{ .name = "zware", .ns_per_op = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iters)), .checksum = checksum };
    }

    report(&stats, stats[0].ns_per_op);

    // --- resource bounding: the security-critical dimension -----------------
    // The single-threaded reactor means a runaway filter wedges the whole
    // worker, so interruption is mandatory (design 10.0). Neither runtime ships
    // fuel; the wasm3 arm carries a ~5-line patch (op_Loop charge, see
    // vendor/wasm3/source/m3_exec.h). Prove it interrupts an infinite loop.
    std.debug.print("resource bounding (runaway-loop interruption):\n", .{});
    {
        const budget: i64 = 100_000;
        const trapped = w3.spinTrapsAt(budget);
        std.debug.print("  wasm3: spin() with {d} fuel -> {s} (remaining {d})\n", .{
            budget,
            if (trapped) "TRAPPED (interrupted)" else "DID NOT TRAP",
            wasm3.fuelRemaining(),
        });
    }
    std.debug.print("  zware: no fuel hook; calling spin() would hang the worker (not invoked).\n", .{});
    std.debug.print("         (zware fuel would require forking the inline dispatch chokepoint.)\n\n", .{});

    const bar_ns: f64 = 1000.0; // 1 microsecond
    std.debug.print("design-10.0 bar: trivial filter must approach single-digit us (< ~1000 ns).\n", .{});
    for (stats[1..]) |s| {
        const verdict = if (s.ns_per_op < bar_ns) "PASS" else "OVER BAR";
        std.debug.print("  {s:<8} {d:.1} ns/op  [{s}]\n", .{ s.name, s.ns_per_op, verdict });
    }
}

/// All three implementations must return identical decisions for every request
/// shape, or the benchmark is comparing different work.
fn verifyAgreement(w3: *wasm3.Runtime, zw: *zware_rt.Runtime) !void {
    for (&REQUESTS, 0..) |*req, idx| {
        request.current = req;
        const n: i32 = @intFromEnum(native.onRequest());
        const a: i32 = try w3.onRequest();
        const z: i32 = try zw.onRequest();
        if (n != a or n != z) {
            std.debug.print("DISAGREEMENT on request {d} ({s}): native={d} wasm3={d} zware={d}\n", .{ idx, req.path, n, a, z });
            return error.ImplementationsDisagree;
        }
    }
    std.debug.print("correctness: native/wasm3/zware agree on all {d} request shapes\n", .{REQUESTS.len});
}
