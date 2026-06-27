//! zware runtime wrapper (pure-Zig interpreter).
//!
//! Lifecycle: decode + expose host imports + instantiate ONCE at setup. The hot
//! path calls `instance.invoke("on_request", ...)`. Note that zware rebuilds the
//! VM operand/frame/label stacks on every invoke (see Instance.invoke); we tune
//! those down via VM_OPTS so the per-call cost is measured at zware's best, not
//! with the 8 KB default operand stack that gets zeroed each call.

const std = @import("std");
const zware = @import("zware");
const request = @import("request.zig");

pub const Error = error{InitFailed} || std.mem.Allocator.Error;

// Our filter touches a handful of operands and one call frame. Sizing the VM
// stacks to the actual need avoids zware's default 8 KB operand-stack zeroing
// on every invocation.
// VirtualMachineOptions is private in zware; invoke takes it as a comptime
// param. A named const literal won't coerce (it freezes to its own anon type),
// so the literal is passed inline at the invoke call below. Sizing the VM
// stacks to the filter's actual need avoids zware's default 8 KB operand-stack
// zeroing on every invocation, measuring zware at its best.

// --- host imports -----------------------------------------------------------
// zware leaves params on the operand stack and expects the host fn to pop them
// (reverse param order: last param on top) and push its results.

fn hostGetPath(vm: *zware.VirtualMachine, ctx: usize) zware.WasmError!void {
    _ = ctx;
    const cap = vm.popOperand(u32);
    const out_ptr = vm.popOperand(u32);
    const mem = try vm.inst.getMemory(0);
    const buf = mem.memory();

    const path = request.current.path;
    const n: u32 = @intCast(@min(path.len, cap));
    @memcpy(buf[out_ptr .. out_ptr + n], path[0..n]);
    try vm.pushOperand(u32, n);
}

fn hostGetHeader(vm: *zware.VirtualMachine, ctx: usize) zware.WasmError!void {
    _ = ctx;
    const out_cap = vm.popOperand(u32);
    const out_ptr = vm.popOperand(u32);
    const name_len = vm.popOperand(u32);
    const name_ptr = vm.popOperand(u32);
    const mem = try vm.inst.getMemory(0);
    const buf = mem.memory();

    const name = buf[name_ptr .. name_ptr + name_len];
    const val = request.current.getHeader(name) orelse {
        try vm.pushOperand(u32, 0);
        return;
    };
    const n: u32 = @intCast(@min(val.len, out_cap));
    @memcpy(buf[out_ptr .. out_ptr + n], val[0..n]);
    try vm.pushOperand(u32, n);
}

pub const Runtime = struct {
    alloc: std.mem.Allocator,
    store: *zware.Store,
    module: *zware.Module,
    instance: *zware.Instance,

    pub fn init(alloc: std.mem.Allocator, wasm_bytes: []const u8) Error!Runtime {
        // Heap-allocate store/module/instance so their addresses are stable:
        // Instance keeps a *Store pointer, so the Store must not move.
        const store = try alloc.create(zware.Store);
        errdefer alloc.destroy(store);
        store.* = zware.Store.init(alloc);

        const module = try alloc.create(zware.Module);
        errdefer alloc.destroy(module);
        module.* = zware.Module.init(alloc, wasm_bytes);
        module.decode() catch return Error.InitFailed;

        store.exposeHostFunction("env", "get_path", hostGetPath, 0, &.{ .I32, .I32 }, &.{.I32}) catch return Error.InitFailed;
        store.exposeHostFunction("env", "get_header", hostGetHeader, 0, &.{ .I32, .I32, .I32, .I32 }, &.{.I32}) catch return Error.InitFailed;

        const instance = try alloc.create(zware.Instance);
        errdefer alloc.destroy(instance);
        instance.* = zware.Instance.init(alloc, store, module.*);
        instance.instantiate() catch return Error.InitFailed;

        return .{ .alloc = alloc, .store = store, .module = module, .instance = instance };
    }

    pub fn deinit(self: *Runtime) void {
        self.instance.deinit();
        self.module.deinit();
        self.store.deinit();
        self.alloc.destroy(self.instance);
        self.alloc.destroy(self.module);
        self.alloc.destroy(self.store);
    }

    pub inline fn onRequest(self: *Runtime) Error!i32 {
        var in: [0]u64 = .{};
        var out: [1]u64 = .{0};
        self.instance.invoke("on_request", &in, &out, .{
            .operand_stack_size = 64,
            .frame_stack_size = 16,
            .label_stack_size = 16,
        }) catch return Error.InitFailed;
        return @bitCast(@as(u32, @truncate(out[0])));
    }
};
