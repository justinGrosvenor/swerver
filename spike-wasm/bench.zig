const std = @import("std");
const c = @cImport({
    @cInclude("wasm3.h");
});

const filter_wasm = @embedFile("filter.wasm");
const KEY = "bench-key-1";
const N: u64 = 5_000_000;

fn nowNs() i128 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * 1_000_000_000 + ts.nsec;
}

fn die(comptime ctx: []const u8, res: c.M3Result) void {
    if (res != null) {
        std.debug.print("{s}: {s}\n", .{ ctx, res });
        std.process.exit(1);
    }
}

pub fn main() !void {
    const env = c.m3_NewEnvironment();
    const rt = c.m3_NewRuntime(env, 64 * 1024, null);

    var module: c.IM3Module = undefined;
    die("parse", c.m3_ParseModule(env, &module, filter_wasm.ptr, filter_wasm.len));
    die("load", c.m3_LoadModule(rt, module));

    var f_noop: c.IM3Function = undefined;
    var f_bufptr: c.IM3Function = undefined;
    var f_check: c.IM3Function = undefined;
    die("find noop", c.m3_FindFunction(&f_noop, rt, "noop"));
    die("find bufptr", c.m3_FindFunction(&f_bufptr, rt, "bufptr"));
    die("find check", c.m3_FindFunction(&f_check, rt, "check"));

    // Resolve the wasm-side buffer address and write the candidate key in.
    die("call bufptr", c.m3_Call(f_bufptr, 0, null));
    var buf_off: u32 = 0;
    var rets = [_]?*const anyopaque{&buf_off};
    die("results bufptr", c.m3_GetResults(f_bufptr, 1, &rets));

    var mem_size: u32 = 0;
    const mem = c.m3_GetMemory(rt, &mem_size, 0);
    const host_buf = mem + buf_off;
    @memcpy(host_buf[0..KEY.len], KEY);

    var sink: i64 = 0;

    // 1. Bare invocation overhead.
    {
        const t0 = nowNs();
        var i: u64 = 0;
        while (i < N) : (i += 1) {
            _ = c.m3_Call(f_noop, 0, null);
        }
        const dt = nowNs() - t0;
        std.debug.print("wasm noop            : {d:.1} ns/op\n", .{@as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(N))});
    }

    // 2. Realistic filter: invocation + read linear memory + scan.
    {
        var len_arg: u32 = KEY.len;
        var args = [_]?*const anyopaque{&len_arg};
        var ret: i32 = 0;
        var rrets = [_]?*const anyopaque{&ret};
        const t0 = nowNs();
        var i: u64 = 0;
        while (i < N) : (i += 1) {
            _ = c.m3_Call(f_check, 1, &args);
            _ = c.m3_GetResults(f_check, 1, &rrets);
            sink += ret;
        }
        const dt = nowNs() - t0;
        std.debug.print("wasm check (match)   : {d:.1} ns/op  (ret={d})\n", .{ @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(N)), ret });
    }

    // 3. Native baseline: the same byte compare in Zig, made
    //    optimizer-resistant by mutating the candidate each iteration so
    //    the comparison can't be hoisted or constant-folded.
    {
        var cand: [KEY.len]u8 = undefined;
        @memcpy(&cand, KEY);
        const t0 = nowNs();
        var i: u64 = 0;
        while (i < N) : (i += 1) {
            cand[0] = @truncate(i); // varies; only i%256==('b') matches
            const ok = std.mem.eql(u8, &cand, KEY);
            sink += @intFromBool(ok);
        }
        const dt = nowNs() - t0;
        std.debug.print("native check         : {d:.2} ns/op\n", .{@as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(N))});
    }

    std.debug.print("(sink={d})\n", .{sink});
}
