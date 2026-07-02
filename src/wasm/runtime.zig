//! Low-level wasm3 binding for swerver WASM edge functions (design 10.0).
//!
//! This is the runtime-agnostic layer: load/parse/link/call wasm modules, drive
//! the fuel counter, reach guest linear memory. It knows nothing about swerver's
//! request model. The custom filter ABI (host imports that read Context, the
//! Decision mapping) is built on top of this in abi.zig (increment 2).
//!
//! Compiled only when build_options.enable_wasm is set; lib.zig gates the
//! @import so the @cImport never runs in a build without vendored wasm3.

const std = @import("std");

pub const c = @cImport({
    @cInclude("wasm3.h");
    @cInclude("m3_env.h");
});

pub const Error = error{
    NewEnvironment,
    NewRuntime,
    ParseModule,
    LoadModule,
    LinkFunction,
    FunctionNotFound,
    /// An export EXISTS but failed wasm3's lazy compile/validation (distinct from
    /// FunctionNotFound = no such export). Most often a post-MVP wasm feature the
    /// vendored wasm3 cannot compile (e.g. reference_types). The real m3 message
    /// is logged where this is raised; see find()/findOptional().
    CompileFailed,
    CallFailed,
    Trap,
    NoMemory,
    MemoryCapTooSmall,
};

/// Render a wasm3 result (a const char* error message, or null) as a Zig slice.
fn m3Msg(r: c.M3Result) []const u8 {
    if (r == null) return "(none)";
    const s: [*:0]const u8 = @ptrCast(r);
    return std.mem.span(s);
}

/// The message from the most recent guest trap on this worker thread. callI32 /
/// callI32_2 / callVoidTraps set it before returning a trap so the filter layer
/// can log WHY a guest trapped (e.g. an out-of-bounds ABI pointer) instead of an
/// opaque 500. Valid only immediately after a trapping call.
threadlocal var last_trap_msg: []const u8 = "";
pub fn lastTrap() []const u8 {
    return last_trap_msg;
}

/// wasm linear-memory page size (64 KiB), per the wasm spec.
pub const PAGE_SIZE: u32 = 65536;

/// Raw wasm3 host-function signature (M3RawCall):
///   const void* (IM3Runtime, IM3ImportContext, uint64_t* sp, void* mem)
/// sp[0] is the return slot, sp[1..] are args (each a full u64 slot, value in
/// the low bits). `mem` is the base of guest linear memory: a guest offset O
/// maps to host pointer mem + O. Return null (m3Err_none) for success, or a
/// non-null const char* to trap.
pub const RawCall = *const fn (
    rt: c.IM3Runtime,
    ctx: c.IM3ImportContext,
    sp: [*c]u64,
    mem: ?*anyopaque,
) callconv(.c) ?*const anyopaque;

// --- fuel ------------------------------------------------------------------
// The swerver fuel patch: a process-global counter charged per loop back-edge
// in vendored wasm3 (vendor/wasm3/source/m3_exec.h). Setting it bounds guest
// execution; on exhaustion the guest call returns a trap.

extern var m3_swerver_fuel: i64;

pub const fuel = struct {
    /// Set the per-invocation budget. Call before each guest invocation.
    pub fn set(units: i64) void {
        m3_swerver_fuel = units;
    }
    /// Remove the bound (setup/trusted paths only).
    pub fn unlimited() void {
        m3_swerver_fuel = std.math.maxInt(i64);
    }
    pub fn remaining() i64 {
        return m3_swerver_fuel;
    }
};

/// A wasm3 environment + runtime + one loaded module. One per loaded module;
/// the instance pool (increment 2) owns several of these per module per worker.
pub const Module = struct {
    env: c.IM3Environment,
    runtime: c.IM3Runtime,
    module: c.IM3Module,

    /// Parse + load a module. `stack_bytes` is the interpreter value-stack size
    /// (not the guest linear memory). The wasm bytes must outlive the Module
    /// (wasm3 references them; it does not copy).
    pub fn load(wasm_bytes: []const u8, stack_bytes: u32) Error!Module {
        const env = c.m3_NewEnvironment() orelse return Error.NewEnvironment;
        errdefer c.m3_FreeEnvironment(env);

        const rt = c.m3_NewRuntime(env, stack_bytes, null) orelse return Error.NewRuntime;
        errdefer c.m3_FreeRuntime(rt);

        var module: c.IM3Module = undefined;
        if (c.m3_ParseModule(env, &module, wasm_bytes.ptr, @intCast(wasm_bytes.len)) != null)
            return Error.ParseModule;
        // After a successful load the runtime owns the module.
        if (c.m3_LoadModule(rt, module) != null) {
            c.m3_FreeModule(module);
            return Error.LoadModule;
        }

        return .{ .env = env, .runtime = rt, .module = module };
    }

    pub fn deinit(self: *Module) void {
        c.m3_FreeRuntime(self.runtime);
        c.m3_FreeEnvironment(self.env);
        // runtime owns the module; freeing the runtime frees it.
    }

    /// Link a host import the guest may call. `signature` is wasm3's format,
    /// e.g. "i(ii)" = i32 return, two i32 args; "v()" = void no args.
    pub fn link(
        self: *Module,
        namespace: [:0]const u8,
        name: [:0]const u8,
        signature: [:0]const u8,
        func: RawCall,
    ) Error!void {
        const r = c.m3_LinkRawFunction(self.module, namespace, name, signature, func);
        // SuppressLookupFailure (an unused import) is fine; a real link error is not.
        if (r != null and r != c.m3Err_functionLookupFailed) {
            // Name the import + expected signature + the real m3 message. Without
            // this a wrong host-import signature surfaces only as an opaque
            // LinkFunction error (and a Zig stack trace naming nothing).
            std.log.warn("wasm: linking host import '{s}.{s}' (signature '{s}') failed: {s} (filter declared this import with a mismatched signature?)", .{ namespace, name, signature, m3Msg(r) });
            return Error.LinkFunction;
        }
    }

    /// Resolve an exported function once (off the hot path); reuse the handle.
    pub fn find(self: *Module, name: [:0]const u8) Error!c.IM3Function {
        var f: c.IM3Function = undefined;
        const r = c.m3_FindFunction(&f, self.runtime, name);
        if (r != null) {
            // m3_FindFunction compiles lazily, so a non-null result can be EITHER
            // a missing export OR a real compile/validation failure. Distinguish
            // them: flattening both to FunctionNotFound hid (for hours) the fact
            // that a filter using a post-MVP feature wasm3 cannot compile (e.g.
            // reference_types) had simply failed to compile. See ISSUES.md R1.
            if (r != c.m3Err_functionLookupFailed) {
                std.log.warn("wasm: export '{s}' present but failed to compile: {s} (uses a wasm feature the runtime cannot compile? rebuild the filter with -mcpu=mvp)", .{ name, m3Msg(r) });
                return Error.CompileFailed;
            }
            return Error.FunctionNotFound;
        }
        return f;
    }

    /// Try to resolve; null if the export is absent (e.g. optional `spin`). A
    /// present-but-uncompilable export is logged (else a broken on_response /
    /// on_resume would be silently treated as "absent" -> hook quietly skipped).
    pub fn findOptional(self: *Module, name: [:0]const u8) ?c.IM3Function {
        var f: c.IM3Function = undefined;
        const r = c.m3_FindFunction(&f, self.runtime, name);
        if (r != null) {
            if (r != c.m3Err_functionLookupFailed)
                std.log.warn("wasm: optional export '{s}' present but failed to compile: {s} (rebuild the filter with -mcpu=mvp?)", .{ name, m3Msg(r) });
            return null;
        }
        return f;
    }

    // IM3Runtime is a `[*c]` C pointer; field access through it yields another
    // C pointer (no `.field`), so convert to a single-item pointer first.
    fn rtp(self: *Module) *c.struct_M3Runtime {
        return @ptrCast(self.runtime);
    }

    /// Current guest linear-memory size in pages (64 KiB each).
    pub fn memoryPages(self: *Module) u32 {
        return self.rtp().memory.numPages;
    }

    /// Maximum pages the guest may grow to (the enforced cap).
    pub fn maxMemoryPages(self: *Module) u32 {
        return self.rtp().memory.maxPages;
    }

    /// Cap the guest's maximum linear memory at `max_pages` (64 KiB each), so a
    /// runaway `memory.grow` returns -1 (wasm spec) instead of OOMing the worker
    /// rather than the module's declared/default max (up to 4 GiB). Errors if the
    /// module's initial memory already exceeds the cap. Call once after load.
    pub fn setMemoryCap(self: *Module, max_pages: u32) Error!void {
        const r = self.rtp();
        if (r.memory.numPages > max_pages) return Error.MemoryCapTooSmall;
        r.memory.maxPages = max_pages;
    }

    /// Base + length of guest linear memory[0]. Host functions normally use the
    /// `mem` arg instead; this is for setup/inspection.
    pub fn memory(self: *Module) []u8 {
        var size: u32 = 0;
        const base = c.m3_GetMemory(self.runtime, &size, 0);
        if (base == null) return &.{};
        return base[0..size];
    }
};

/// Call an export taking no args and returning one i32. Set fuel first.
pub fn callI32(func: c.IM3Function) Error!i32 {
    const r = c.m3_CallV(func);
    if (r != null) {
        last_trap_msg = m3Msg(r);
        return Error.Trap;
    }
    var result: i32 = 0;
    if (c.m3_GetResultsV(func, &result) != null) return Error.CallFailed;
    return result;
}

/// Call an export taking no args, returning nothing. Returns true if it trapped
/// (e.g. fuel exhausted). Set fuel first.
pub fn callVoidTraps(func: c.IM3Function) bool {
    const r = c.m3_CallV(func);
    if (r != null) {
        last_trap_msg = m3Msg(r);
        return true;
    }
    return false;
}

/// Call an export taking two i32 args and returning one i32 (non-varargs
/// m3_Call path). Returns Error.Trap if the guest trapped.
pub fn callI32_2(func: c.IM3Function, a0: i32, a1: i32) Error!i32 {
    var x0 = a0;
    var x1 = a1;
    var argv = [_]?*const anyopaque{ &x0, &x1 };
    const r = c.m3_Call(func, 2, &argv);
    if (r != null) {
        last_trap_msg = m3Msg(r);
        return Error.Trap;
    }
    var result: i32 = 0;
    var retv = [_]?*const anyopaque{&result};
    if (c.m3_GetResults(func, 1, &retv) != null) return Error.CallFailed;
    return result;
}

// ---------------------------------------------------------------------------
// Tests (run with: zig build test -Denable-wasm=true)
// ---------------------------------------------------------------------------

const testing = std.testing;
const PROBE_WASM = @embedFile("testdata/probe.wasm");

test "load module and call on_request" {
    fuel.unlimited();
    var mod = try Module.load(PROBE_WASM, 8 * 1024);
    defer mod.deinit();

    const on_request = try mod.find("on_request");
    try testing.expectEqual(@as(i32, 0), try callI32(on_request));
}

test "fuel interrupts a runaway loop" {
    var mod = try Module.load(PROBE_WASM, 8 * 1024);
    defer mod.deinit();

    const spin = mod.findOptional("spin") orelse return error.FunctionNotFound;

    // A bounded budget must trap rather than hang the worker.
    fuel.set(100_000);
    try testing.expect(callVoidTraps(spin));

    // Restore the bound; a normal call still works afterward.
    fuel.unlimited();
    const on_request = try mod.find("on_request");
    try testing.expectEqual(@as(i32, 0), try callI32(on_request));
}

test "missing export reports not found" {
    fuel.unlimited();
    var mod = try Module.load(PROBE_WASM, 8 * 1024);
    defer mod.deinit();
    try testing.expectError(Error.FunctionNotFound, mod.find("does_not_exist"));
    try testing.expect(mod.findOptional("does_not_exist") == null);
}

test "memory cap refuses growth beyond the limit" {
    fuel.unlimited();
    // Without a cap, the growth succeeds.
    {
        var mod = try Module.load(PROBE_WASM, 8 * 1024);
        defer mod.deinit();
        const before = mod.memoryPages();
        const grow = mod.findOptional("grow_some") orelse return error.FunctionNotFound;
        try testing.expect(try callI32(grow) >= 0); // returns prev page count
        try testing.expect(mod.memoryPages() > before);
    }
    // Capped at the current size, the same growth is refused (-1) and memory
    // stays put: a runaway memory.grow cannot OOM the worker.
    {
        var mod = try Module.load(PROBE_WASM, 8 * 1024);
        defer mod.deinit();
        const pages = mod.memoryPages();
        try mod.setMemoryCap(pages);
        const grow = mod.findOptional("grow_some") orelse return error.FunctionNotFound;
        try testing.expectEqual(@as(i32, -1), try callI32(grow));
        try testing.expectEqual(pages, mod.memoryPages());
    }
}

test "setMemoryCap rejects a cap below current memory" {
    fuel.unlimited();
    var mod = try Module.load(PROBE_WASM, 8 * 1024);
    defer mod.deinit();
    try testing.expectError(Error.MemoryCapTooSmall, mod.setMemoryCap(0));
}
