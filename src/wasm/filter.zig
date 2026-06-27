//! WASM edge-function filter layer (design 10.0, increment 2).
//!
//! Builds the custom filter ABI and the per-worker instance pool on top of the
//! low-level wasm3 binding (runtime.zig). A loaded filter module is
//! pre-instantiated N times per worker; the hot path acquires an idle instance,
//! runs `on_request()`, and maps its return code to a middleware `Decision`.
//!
//! ABI (custom, minimal, v1). Host imports the guest may call:
//!   get_method() -> i32                                  method enum (see Method)
//!   get_path(out_ptr, out_cap) -> len                    request path
//!   get_header(name_ptr,name_len,out_ptr,out_cap) -> len header value (0=absent)
//!   header_count() -> i32                                number of request headers
//!   body_len() -> i32                                    request body length (true total)
//!   read_body(src_off, out_ptr, out_cap) -> len          copy a body window in
//!   set_response_header(name_ptr,name_len,val_ptr,val_len)  stage a response header
//!   respond(status, body_ptr, body_len)                  stage a reject response
//!   log(ptr, len)                                        diagnostic log line
//! Guest export:
//!   on_request() -> i32   0=allow 1=reject 2=modify (3=parked reserved, Phase 3)
//!
//! Single-threaded worker: the active instance is a process-global, set around
//! each invocation so the C host callbacks can reach the staging scratch and the
//! live request without threading a pointer through the wasm3 ABI.
//!
//! STATELESSNESS CONTRACT (important). A pooled instance is REUSED across many
//! requests, from different end-users. invoke() resets the host-side staging
//! (status/body/headers/scratch) before each call, but it does NOT reset the
//! guest's linear memory or wasm globals: wasm3 has no cheap re-instantiate, and
//! zeroing megabytes of linear memory per request would defeat the microsecond
//! budget. Therefore a filter MUST be stateless across invocations: anything it
//! writes to a wasm global or to linear memory persists into the next request on
//! that instance. This is not a sandbox escape (same module, same tenant code),
//! but it is a real isolation property the filter author owns. Filters should
//! treat each on_request() as reading inputs and producing a Decision, never as
//! accumulating state. (Per-request scratch buffers reset by the guest at the
//! top of on_request() are fine; module-level mutable state is not.)

const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("runtime.zig");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("../middleware/middleware.zig");

const c = runtime.c;

pub const Error = runtime.Error || error{OutOfMemory};

// Capacities. Staged outputs live in per-instance scratch and stay valid until
// the instance is reused, which is after the response is built.
const MAX_RESPONSE_HEADERS = middleware.Chain.MAX_MIDDLEWARE_HEADERS; // 16
const STAGED_BODY_CAP = 4096;
const SCRATCH_CAP = 4096; // response-header name/value bytes
const GUEST_STACK_BYTES = 64 * 1024;
/// Largest request body a filter can read (the materialized view). The full body
/// still flows untouched to the handler/upstream; only the FILTER's view is
/// capped. A filter validating the body must reject when body_len() exceeds this
/// (otherwise an oversized body could hide content past the view). 64 KiB.
const MAX_BODY_VIEW = 64 * 1024;

/// Default per-invocation fuel budget (loop back-edges). Tunable per-route in
/// config; sized here to be generous for a metadata filter while still bounding
/// a runaway loop in well under a millisecond.
///
/// Resource-bounding model (design 10.0). The worker is single-threaded, so the
/// ONLY thing that can stop a runaway guest is in-interpreter preemption: a
/// housekeeping-tick wall-clock deadline cannot fire while the guest spins (the
/// tick never runs). Fuel is therefore THE compute bound for synchronous Phase-1
/// filters, and it doubles as the time bound (fuel is charged per loop iteration
/// ~ instructions ~ time). A separate wall-clock deadline only becomes
/// meaningful in Phase 3, where a host call PARKS the request and control
/// returns to the reactor, and there the tick can time out a stalled park. Until
/// then, fuel (compute) + the memory cap (below) are the enforced bounds.
pub const DEFAULT_FUEL: i64 = 5_000_000;

/// Default linear-memory cap per instance, in 64 KiB pages. 64 pages = 4 MiB,
/// the top of the design's 1-4 MiB range. A runaway memory.grow beyond this
/// returns -1 to the guest instead of OOMing the worker.
pub const DEFAULT_MAX_MEMORY_PAGES: u32 = 64;

/// Per-pool resource bounds. Fuel is per-invocation (passed to run); memory cap
/// and instance count are fixed at pool construction.
pub const Config = struct {
    /// Pre-instantiated instances per worker. Under the Phase-1 synchronous
    /// model the reactor is single-threaded and a filter never yields mid-call,
    /// so acquire() always returns the same idle instance and 1 is sufficient;
    /// each extra instance only reserves another `max_memory_pages` of linear
    /// memory. Phase 3 (parked host calls) is what needs N > 1: a parked filter
    /// pins its instance while the request is suspended, so the pool size caps
    /// concurrent parked filters.
    instances: usize = 1,
    max_memory_pages: u32 = DEFAULT_MAX_MEMORY_PAGES,
};

/// Stable ABI method codes (independent of request.Method's declaration order).
pub fn methodCode(m: request.Method) i32 {
    return switch (m) {
        .GET => 0,
        .HEAD => 1,
        .POST => 2,
        .PUT => 3,
        .DELETE => 4,
        .CONNECT => 5,
        .OPTIONS => 6,
        .TRACE => 7,
        .PATCH => 8,
        .OTHER => 255,
    };
}

const Decision = i32; // guest on_request() return
const DECISION_ALLOW: Decision = 0;
const DECISION_REJECT: Decision = 1;
const DECISION_MODIFY: Decision = 2;
const DECISION_PARKED: Decision = 3; // reserved (Phase 3)

// Trap messages returned by host functions on ABI misuse. Any non-null return
// from a raw function traps the guest call (unwinds to invoke()).
const TRAP_NO_ACTIVE: [*:0]const u8 = "[trap] wasm host call with no active invocation";
const TRAP_OOB: [*:0]const u8 = "[trap] wasm abi pointer out of bounds";

fn trap(msg: [*:0]const u8) ?*const anyopaque {
    return @ptrCast(msg);
}

/// A pre-instantiated filter instance. Owns its wasm3 runtime/module (and thus
/// its own linear memory) plus the per-invocation output staging scratch.
pub const Instance = struct {
    pub const State = enum { idle, running, parked };

    module: runtime.Module,
    on_request: c.IM3Function,
    state: State = .idle,

    // Per-invocation input (borrowed) and staged outputs (owned scratch).
    req: *const request.RequestView = undefined,
    staged_status: u16 = 0,
    staged_body_len: usize = 0,
    staged_body: [STAGED_BODY_CAP]u8 = undefined,
    staged_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined,
    staged_header_count: usize = 0,
    scratch: [SCRATCH_CAP]u8 = undefined,
    scratch_used: usize = 0,

    // Request body, materialized lazily on first body access (scattered -> linear
    // is the "zero-copy tax"). The view is bounded by MAX_BODY_VIEW; body_full_len
    // reports the true length so a filter can detect a body larger than its view.
    body_materialized: bool = false,
    body_view_len: usize = 0,
    body_full_len: usize = 0,
    body_buf: [MAX_BODY_VIEW]u8 = undefined,

    fn resetStaging(self: *Instance) void {
        self.staged_status = 0;
        self.staged_body_len = 0;
        self.staged_header_count = 0;
        self.scratch_used = 0;
        self.body_materialized = false;
        self.body_view_len = 0;
        self.body_full_len = 0;
    }

    /// Materialize the request body into the bounded view buffer on first access.
    /// Cheap and idempotent thereafter (per invocation).
    fn ensureBody(self: *Instance) void {
        if (self.body_materialized) return;
        self.body_materialized = true;
        self.body_full_len = self.req.body.len();
        self.body_view_len = materializeBody(self.req.body, &self.body_buf);
    }

    /// Copy bytes into the instance scratch; returns a stable slice or null if
    /// the scratch is full (the filter staged more than the cap allows).
    fn stash(self: *Instance, bytes: []const u8) ?[]const u8 {
        if (self.scratch_used + bytes.len > self.scratch.len) return null;
        const start = self.scratch_used;
        @memcpy(self.scratch[start .. start + bytes.len], bytes);
        self.scratch_used += bytes.len;
        return self.scratch[start .. start + bytes.len];
    }
};

/// The process-global active instance. Single-threaded worker, so this is set
/// around each invoke() and read by the C host callbacks.
var active: ?*Instance = null;

// --- guest-memory bounds helpers -------------------------------------------

/// Copy up to dst.len bytes of the request body into dst (scattered -> linear),
/// returning the number copied. Reuses the chunk walk from RequestBody.copyTo
/// but caps at dst.len instead of requiring the whole body to fit.
fn materializeBody(body: request.RequestBody, dst: []u8) usize {
    switch (body) {
        .slice => |s| {
            const n = @min(s.len, dst.len);
            @memcpy(dst[0..n], s[0..n]);
            return n;
        },
        .scattered => |b| {
            var off: usize = 0;
            for (b.handles, 0..) |handle, i| {
                if (off >= dst.len) break;
                const chunk_len = if (i == b.handles.len - 1) b.last_buf_len else b.buffer_size;
                const take = @min(chunk_len, dst.len - off);
                @memcpy(dst[off .. off + take], handle.bytes[0..take]);
                off += take;
            }
            return off;
        },
        .length_only => return 0,
    }
}

fn guestView(rt: c.IM3Runtime, mem: ?*anyopaque, ptr: u32, len: u32) ?[]u8 {
    const base_opt = mem orelse return null;
    const size = c.m3_GetMemorySize(rt);
    if (@as(u64, ptr) + @as(u64, len) > size) return null;
    const base: [*]u8 = @ptrCast(base_opt);
    return base[ptr .. ptr + len];
}

// --- host functions (raw wasm3 ABI) ----------------------------------------
// sp[0] is the return slot for functions that return a value; args follow.
// For void functions args start at sp[0]. See runtime.RawCall.

fn hostGetMethod(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    _ = mem;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    ret.* = methodCode(inst.req.method);
    return null;
}

fn hostHeaderCount(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    _ = mem;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    ret.* = @intCast(inst.req.headers.len);
    return null;
}

fn hostBodyLen(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    _ = mem;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    inst.ensureBody();
    const ret: *i32 = @ptrCast(@alignCast(sp));
    // True total length (may exceed the readable view; the filter can detect it).
    ret.* = @intCast(@min(inst.body_full_len, @as(usize, std.math.maxInt(i32))));
    return null;
}

fn hostReadBody(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    inst.ensureBody();
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const src_off: u32 = @truncate(sp[1]);
    const out_ptr: u32 = @truncate(sp[2]);
    const out_cap: u32 = @truncate(sp[3]);
    const dst = guestView(rt, mem, out_ptr, out_cap) orelse return trap(TRAP_OOB);
    if (src_off >= inst.body_view_len) {
        ret.* = 0;
        return null;
    }
    const avail = inst.body_view_len - src_off;
    const n = @min(avail, dst.len);
    @memcpy(dst[0..n], inst.body_buf[src_off .. src_off + n]);
    ret.* = @intCast(n);
    return null;
}

fn hostGetPath(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const out_ptr: u32 = @truncate(sp[1]);
    const out_cap: u32 = @truncate(sp[2]);
    const dst = guestView(rt, mem, out_ptr, out_cap) orelse return trap(TRAP_OOB);
    const path = inst.req.path;
    const n = @min(path.len, dst.len);
    @memcpy(dst[0..n], path[0..n]);
    ret.* = @intCast(n);
    return null;
}

fn hostGetHeader(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const name_ptr: u32 = @truncate(sp[1]);
    const name_len: u32 = @truncate(sp[2]);
    const out_ptr: u32 = @truncate(sp[3]);
    const out_cap: u32 = @truncate(sp[4]);
    const name = guestView(rt, mem, name_ptr, name_len) orelse return trap(TRAP_OOB);
    const dst = guestView(rt, mem, out_ptr, out_cap) orelse return trap(TRAP_OOB);
    const val = inst.req.getHeader(name) orelse {
        ret.* = 0;
        return null;
    };
    const n = @min(val.len, dst.len);
    @memcpy(dst[0..n], val[0..n]);
    ret.* = @intCast(n);
    return null;
}

fn hostSetResponseHeader(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const name_ptr: u32 = @truncate(sp[0]);
    const name_len: u32 = @truncate(sp[1]);
    const val_ptr: u32 = @truncate(sp[2]);
    const val_len: u32 = @truncate(sp[3]);
    if (inst.staged_header_count >= inst.staged_headers.len) return null; // silently capped
    const name_src = guestView(rt, mem, name_ptr, name_len) orelse return trap(TRAP_OOB);
    const val_src = guestView(rt, mem, val_ptr, val_len) orelse return trap(TRAP_OOB);
    const name = inst.stash(name_src) orelse return null; // scratch full: drop
    const val = inst.stash(val_src) orelse return null;
    inst.staged_headers[inst.staged_header_count] = .{ .name = name, .value = val };
    inst.staged_header_count += 1;
    return null;
}

fn hostRespond(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const status: u32 = @truncate(sp[0]);
    const body_ptr: u32 = @truncate(sp[1]);
    const body_len: u32 = @truncate(sp[2]);
    inst.staged_status = @intCast(status);
    if (body_len > 0) {
        const src = guestView(rt, mem, body_ptr, body_len) orelse return trap(TRAP_OOB);
        const n = @min(src.len, inst.staged_body.len);
        @memcpy(inst.staged_body[0..n], src[0..n]);
        inst.staged_body_len = n;
    } else {
        inst.staged_body_len = 0;
    }
    return null;
}

fn hostLog(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const ptr: u32 = @truncate(sp[0]);
    const len: u32 = @truncate(sp[1]);
    // Always bounds-check (an out-of-bounds log pointer must still trap), but
    // only emit in Debug. The message is guest-controlled and a guest can call
    // log() up to its fuel budget; a blocking, locked stderr write per call is a
    // log-spam/noise vector, so release builds drop the output (still trapping
    // on OOB). A future ABI revision can route this to a rate-limited sink.
    const msg = guestView(rt, mem, ptr, len) orelse return trap(TRAP_OOB);
    if (builtin.mode == .Debug) {
        std.debug.print("[wasm] {s}\n", .{msg});
    }
    return null;
}

/// Link the full ABI into a freshly loaded module.
fn linkAbi(mod: *runtime.Module) Error!void {
    try mod.link("env", "get_method", "i()", hostGetMethod);
    try mod.link("env", "get_path", "i(ii)", hostGetPath);
    try mod.link("env", "get_header", "i(iiii)", hostGetHeader);
    try mod.link("env", "header_count", "i()", hostHeaderCount);
    try mod.link("env", "body_len", "i()", hostBodyLen);
    try mod.link("env", "read_body", "i(iii)", hostReadBody);
    try mod.link("env", "set_response_header", "v(iiii)", hostSetResponseHeader);
    try mod.link("env", "respond", "v(iii)", hostRespond);
    try mod.link("env", "log", "v(ii)", hostLog);
}

// --- Decision mapping -------------------------------------------------------

fn failClosed() middleware.Decision {
    // A trapped or misbehaving filter must not let the request through.
    return .{ .reject = .{
        .status = 500,
        .headers = &.{},
        .body = .{ .bytes = "edge function error" },
    } };
}

fn buildDecision(inst: *Instance, code: Decision) middleware.Decision {
    return switch (code) {
        DECISION_ALLOW => .allow,
        DECISION_REJECT => .{ .reject = .{
            .status = if (inst.staged_status != 0) inst.staged_status else 403,
            .headers = inst.staged_headers[0..inst.staged_header_count],
            .body = .{ .bytes = inst.staged_body[0..inst.staged_body_len] },
        } },
        DECISION_MODIFY => .{ .modify = .{
            .response_headers = inst.staged_headers[0..inst.staged_header_count],
            .continue_chain = true,
        } },
        DECISION_PARKED => failClosed(), // Phase 3: not yet implemented
        else => failClosed(),
    };
}

/// Run one filter invocation. Returns a Decision whose reject body / modify
/// headers borrow `inst` scratch and stay valid until `inst` is reused.
pub fn invoke(inst: *Instance, req: *const request.RequestView, fuel_budget: i64) middleware.Decision {
    inst.resetStaging();
    inst.req = req;
    inst.state = .running;

    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }

    runtime.fuel.set(fuel_budget);
    const code = runtime.callI32(inst.on_request) catch {
        return failClosed();
    };
    return buildDecision(inst, code);
}

/// A per-worker pool of pre-instantiated instances for one filter module.
/// Mirrors the PG slot pool: fixed instances, acquire/release, zero per-request
/// heap allocation on the hot path.
pub const Pool = struct {
    alloc: std.mem.Allocator,
    instances: []Instance,
    /// The module bytes are referenced (not copied) by wasm3; the pool owns them.
    wasm_bytes: []u8,

    pub fn init(alloc: std.mem.Allocator, wasm_bytes: []const u8, config: Config) Error!Pool {
        std.debug.assert(config.instances > 0);
        const owned = try alloc.dupe(u8, wasm_bytes);
        errdefer alloc.free(owned);

        const instances = try alloc.alloc(Instance, config.instances);
        errdefer alloc.free(instances);

        var built: usize = 0;
        errdefer for (instances[0..built]) |*inst| inst.module.deinit();

        for (instances) |*inst| {
            var mod = try runtime.Module.load(owned, GUEST_STACK_BYTES);
            errdefer mod.deinit();
            try linkAbi(&mod);
            // Bound each instance's linear memory so a runaway memory.grow fails
            // closed (returns -1) instead of OOMing the worker.
            try mod.setMemoryCap(config.max_memory_pages);
            const on_request = try mod.find("on_request");
            inst.* = .{ .module = mod, .on_request = on_request };
            built += 1;
        }

        return .{ .alloc = alloc, .instances = instances, .wasm_bytes = owned };
    }

    pub fn deinit(self: *Pool) void {
        for (self.instances) |*inst| inst.module.deinit();
        self.alloc.free(self.instances);
        self.alloc.free(self.wasm_bytes);
    }

    /// Acquire an idle instance, or null if all are busy/parked.
    pub fn acquire(self: *Pool) ?*Instance {
        for (self.instances) |*inst| {
            if (inst.state == .idle) {
                inst.state = .running;
                return inst;
            }
        }
        return null;
    }

    /// Run a request through the pool: acquire, invoke, release. Returns
    /// fail-closed (503) if the pool is exhausted.
    pub fn run(self: *Pool, req: *const request.RequestView, fuel_budget: i64) middleware.Decision {
        const inst = self.acquire() orelse return .{ .reject = .{
            .status = 503,
            .headers = &.{},
            .body = .{ .bytes = "edge function pool exhausted" },
        } };
        // invoke() resets state to .idle on return (releases the instance).
        return invoke(inst, req, fuel_budget);
    }
};

// ---------------------------------------------------------------------------
// Tests (run with: zig build test -Denable-wasm=true)
// ---------------------------------------------------------------------------

const testing = std.testing;
const FILTER_WASM = @embedFile("testdata/filter_probe.wasm");

fn mkReq(method: request.Method, path: []const u8, headers: []const request.Header) request.RequestView {
    return .{ .method = method, .path = path, .headers = headers };
}

test "filter: allow path" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    const r = mkReq(.GET, "/public/index.html", &.{});
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .allow);
}

test "filter: reject /api without key -> 401 with staged body" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    const r = mkReq(.GET, "/api/orders", &.{
        .{ .name = "host", .value = "example.com" },
    });
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 401), d.reject.status);
    try testing.expectEqualStrings("missing api key", d.reject.bodyBytes());
}

test "filter: /api with key -> allow" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    const r = mkReq(.GET, "/api/orders", &.{
        .{ .name = "x-api-key", .value = "sk_live_123" },
    });
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .allow);
}

test "filter: /modify -> modify with staged response header" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    const r = mkReq(.GET, "/modify/thing", &.{});
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .modify);
    try testing.expectEqual(@as(usize, 1), d.modify.response_headers.len);
    try testing.expectEqualStrings("x-checked", d.modify.response_headers[0].name);
    try testing.expectEqualStrings("1", d.modify.response_headers[0].value);
}

test "filter: out-of-bounds host call traps -> fail closed (500)" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    const r = mkReq(.GET, "/oob", &.{});
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 500), d.reject.status);
}

test "filter: runaway loop hits fuel -> fail closed (500)" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    const r = mkReq(.GET, "/loop", &.{});
    const d = pool.run(&r, 100_000);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 500), d.reject.status);

    // The pool still works after a trapped invocation (instance reusable).
    const ok = mkReq(.GET, "/public", &.{});
    try testing.expect(pool.run(&ok, DEFAULT_FUEL) == .allow);
}

test "body: clean body allowed" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var r = mkReq(.POST, "/submit", &.{});
    r.body = .{ .slice = "hello world" };
    try testing.expect(pool.run(&r, DEFAULT_FUEL) == .allow);
}

test "body: denied body rejected via read_body" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    var r = mkReq(.POST, "/submit", &.{});
    r.body = .{ .slice = "deny this request" };
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 403), d.reject.status);
    try testing.expectEqualStrings("body rejected", d.reject.bodyBytes());
}

test "body: oversized body rejected; body_len reports true length" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    // 5000 > the fixture's 4096-byte view, so body_len() lets it detect and 413.
    var big: [5000]u8 = @splat('a');
    var r = mkReq(.POST, "/submit", &.{});
    r.body = .{ .slice = &big };
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 413), d.reject.status);
}

test "security: pool caps each instance's max linear memory" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 3, .max_memory_pages = 32 });
    defer pool.deinit();
    for (pool.instances) |*inst| {
        try testing.expectEqual(@as(u32, 32), inst.module.maxMemoryPages());
    }
}

test "security: ABI fuzz: out-of-bounds (ptr,len) always traps, never escapes memory" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();

    // Set up an active invocation by hand so we can call the arg-taking probe
    // export directly (the pool's run() only calls on_request).
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = mkReq(.GET, "/x", &.{});
    inst.req = &r;
    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }
    runtime.fuel.unlimited();

    const probe = inst.module.findOptional("abi_probe") orelse return error.FunctionNotFound;
    const mem_bytes: u32 = inst.module.memoryPages() * runtime.PAGE_SIZE;

    // In-bounds (offset 0, small len) is accepted.
    try testing.expectEqual(@as(i32, 0), try runtime.callI32_2(probe, 0, 16));

    // Every out-of-bounds (ptr,len) pair must trap (host returns an error),
    // never reading or writing outside linear memory. Includes boundary,
    // straddle, far-pointer, oversized-len, and near-u32-max (sum-overflow) cases.
    const cases = [_][2]u32{
        .{ mem_bytes, 1 }, // ptr exactly at end
        .{ mem_bytes -| 4, 64 }, // straddles the end
        .{ 0x7FFF_FFF0, 0x1000 }, // far pointer
        .{ 0, mem_bytes + 1 }, // length past end
        .{ 0xFFFF_FFF0, 0x20 }, // ptr+len would overflow u32 (caught by u64 math)
    };
    for (cases) |cse| {
        const ptr: i32 = @bitCast(cse[0]);
        const len: i32 = @bitCast(cse[1]);
        try testing.expectError(runtime.Error.Trap, runtime.callI32_2(probe, ptr, len));
    }
}

test "filter: pool exhaustion -> 503" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    // Pin both instances.
    const a = pool.acquire() orelse return error.AcquireFailed;
    const b = pool.acquire() orelse return error.AcquireFailed;
    try testing.expect(pool.acquire() == null);

    const r = mkReq(.GET, "/public", &.{});
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 503), d.reject.status);

    a.state = .idle;
    b.state = .idle;
}
