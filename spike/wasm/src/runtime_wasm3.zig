//! wasm3 runtime wrapper (vendored C interpreter).
//!
//! Lifecycle mirrors the design 10.0 plan: parse + load + link host imports
//! ONCE at setup; the hot path only calls the already-resolved exported
//! function. Per-call cost is therefore m3_Call + result fetch + whatever host
//! imports the guest invokes.

const std = @import("std");
const request = @import("request.zig");

pub const c = @cImport({
    @cInclude("wasm3.h");
    @cInclude("m3_env.h");
});

// SPIKE FUEL PATCH: the C global defined in m3_core.c and charged per loop
// iteration in m3_exec.h op_Loop. Setting it bounds guest execution.
extern var m3_spike_fuel: i64;

pub fn setFuel(units: i64) void {
    m3_spike_fuel = units;
}
pub fn fuelUnlimited() void {
    m3_spike_fuel = std.math.maxInt(i64);
}
pub fn fuelRemaining() i64 {
    return m3_spike_fuel;
}

pub const Error = error{
    NewEnvironment,
    NewRuntime,
    ParseModule,
    LoadModule,
    LinkFunction,
    FindFunction,
    CallFailed,
};

// --- host imports -----------------------------------------------------------
// Raw-call ABI (v0.5.0): sp[0] is the return slot, sp[1..] are args (each a
// full u64 slot, value in the low 32 bits). _mem is the base of guest linear
// memory; a guest offset O maps to host pointer _mem + O.

fn hostGetPath(
    rt: c.IM3Runtime,
    ctx: c.IM3ImportContext,
    sp: [*c]u64,
    mem: ?*anyopaque,
) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    const base: [*]u8 = @ptrCast(mem.?);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const out_ptr: u32 = @truncate(sp[1]);
    const cap: u32 = @truncate(sp[2]);

    const path = request.current.path;
    const n: u32 = @intCast(@min(path.len, cap));
    @memcpy(base[out_ptr .. out_ptr + n], path[0..n]);
    ret.* = @intCast(n);
    return null; // m3Err_none
}

fn hostGetHeader(
    rt: c.IM3Runtime,
    ctx: c.IM3ImportContext,
    sp: [*c]u64,
    mem: ?*anyopaque,
) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    const base: [*]u8 = @ptrCast(mem.?);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const name_ptr: u32 = @truncate(sp[1]);
    const name_len: u32 = @truncate(sp[2]);
    const out_ptr: u32 = @truncate(sp[3]);
    const out_cap: u32 = @truncate(sp[4]);

    const name = base[name_ptr .. name_ptr + name_len];
    const val = request.current.getHeader(name) orelse {
        ret.* = 0;
        return null;
    };
    const n: u32 = @intCast(@min(val.len, out_cap));
    @memcpy(base[out_ptr .. out_ptr + n], val[0..n]);
    ret.* = @intCast(n);
    return null;
}

pub const Runtime = struct {
    env: c.IM3Environment,
    runtime: c.IM3Runtime,
    module: c.IM3Module,
    on_request: c.IM3Function,
    spin: c.IM3Function,

    pub fn init(wasm_bytes: []const u8) Error!Runtime {
        const env = c.m3_NewEnvironment() orelse return Error.NewEnvironment;
        // 64 KB interpreter stack is generous for a metadata filter.
        const rt = c.m3_NewRuntime(env, 64 * 1024, null) orelse return Error.NewRuntime;

        var module: c.IM3Module = undefined;
        if (c.m3_ParseModule(env, &module, wasm_bytes.ptr, @intCast(wasm_bytes.len)) != null)
            return Error.ParseModule;
        if (c.m3_LoadModule(rt, module) != null) return Error.LoadModule;

        if (c.m3_LinkRawFunction(module, "env", "get_path", "i(ii)", hostGetPath) != null)
            return Error.LinkFunction;
        if (c.m3_LinkRawFunction(module, "env", "get_header", "i(iiii)", hostGetHeader) != null)
            return Error.LinkFunction;

        var on_req: c.IM3Function = undefined;
        if (c.m3_FindFunction(&on_req, rt, "on_request") != null) return Error.FindFunction;

        var spin_fn: c.IM3Function = undefined;
        // spin is optional for the bench; ignore lookup failure.
        _ = c.m3_FindFunction(&spin_fn, rt, "spin");

        return .{
            .env = env,
            .runtime = rt,
            .module = module,
            .on_request = on_req,
            .spin = spin_fn,
        };
    }

    pub fn deinit(self: *Runtime) void {
        c.m3_FreeRuntime(self.runtime);
        c.m3_FreeEnvironment(self.env);
    }

    /// Hot path: call on_request() -> i32.
    pub inline fn onRequest(self: *Runtime) Error!i32 {
        if (c.m3_CallV(self.on_request) != null) return Error.CallFailed;
        var result: i32 = -1;
        if (c.m3_GetResultsV(self.on_request, &result) != null) return Error.CallFailed;
        return result;
    }

    /// Resource-bounding test: call spin() (an infinite loop) with a fuel budget.
    /// Returns true if the runtime trapped (interrupted) rather than hanging.
    pub fn spinTrapsAt(self: *Runtime, budget: i64) bool {
        if (self.spin == null) return false;
        setFuel(budget);
        const trapped = c.m3_CallV(self.spin) != null;
        fuelUnlimited();
        return trapped;
    }
};
