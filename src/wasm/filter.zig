//! WASM edge-function filter layer (design 10.0, increment 2).
//!
//! Builds the custom filter ABI and the per-worker instance pool on top of the
//! low-level wasm3 binding (runtime.zig). A loaded filter module is
//! pre-instantiated N times per worker; the hot path acquires an idle instance,
//! runs `on_request()`, and maps its return code to a middleware `Decision`.
//!
//! ABI (custom, minimal, v1). Host imports the guest may call:
//!   get_method() -> i32                                  method enum (see Method)
//!   get_path(out_ptr, out_cap) -> len                    request path (len=true size, copied=min)
//!   get_header(name_ptr,name_len,out_ptr,out_cap) -> len header value (0=absent; len=true size)
//!   header_count() -> i32                                number of request headers
//!   body_len() -> i32                                    request body length (true total)
//!   read_body(src_off, out_ptr, out_cap) -> len          copy a body window in
//!   set_response_header(name_ptr,name_len,val_ptr,val_len)  stage a response header
//!   respond(status, body_ptr, body_len)                  stage a reject response
//!   log(ptr, len)                                        diagnostic log line
//!   host_call(ptr, len) -> i32                           stage an outbound call, park (Phase 3)
//!   read_call_result(out_ptr, out_cap) -> len            read the call result in on_resume
//! Response-phase imports (Phase 2b, valid only inside on_response):
//!   get_response_status() -> i32                         the outgoing status
//!   get_response_header(name_ptr,name_len,out_ptr,out_cap) -> len  response header (0=absent)
//!   response_body_len() -> i32                           response body length (true total)
//!   read_response_body(src_off,out_ptr,out_cap) -> len   copy a response-body window in
//!   set_response_status(status)                          override the outgoing status
//!   replace_response_body(ptr,len) -> i32                replace the body (0 ok, -1 too large)
//!   (set_response_header also adds/overrides response headers in this phase)
//! Guest exports:
//!   on_request() -> i32   0=allow 1=reject 2=modify 3=parked (staged a host_call)
//!   on_resume() -> i32    re-entered after a host call completes; 0/1/2 (Phase 3)
//!   on_response() -> i32  optional; 0=apply staged response edits, nonzero=pass
//!                         through unchanged. A TRAP here fails OPEN (the original
//!                         response is served) -- the request already passed policy.
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
/// Phase 3 host-call buffers: the outbound request the filter stages, and the
/// result delivered back on resume. Both live in the pinned instance across the
/// park, so they are bounded.
const CALL_REQUEST_CAP = 4096;
/// The result buffer delivered to on_resume. resumeCall head-copies up to this
/// many bytes, so the control transport must size its delivered frame to fit
/// (keeping the 0x1e<exit> trailer) or the filter loses the verdict. pub so
/// control_client can honor it (R2).
pub const CALL_RESULT_CAP = 16 * 1024;

/// Max length of a set_upstream socket path (>= net.UNIX_PATH_MAX with slack).
/// Staged in the pinned instance and copied into the park slot on resume.
pub const UPSTREAM_PATH_CAP = 256;

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

/// Backpressure window (ms) applied to a connection when the filter pool (or the
/// park Table) is exhausted on a park-capable hook. Instead of CPU-burning an
/// immediate 503 for every excess request under a flood (which starves the few
/// real completions and collapses goodput, the G2 "concurrency cliff"), the
/// exhausted hook STILL fails closed (serves the 503) but ALSO pauses reads on
/// that connection for this window so the flood self-throttles. Reuses the
/// existing rate_limit_backpressure / setRateLimitPause path. Kept short so a
/// transient burst recovers quickly once instances free up.
pub const POOL_BACKPRESSURE_MS: u64 = 50;

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
    ///
    /// SIZING (Tier-2 fan-out): size `instances` to the expected number of
    /// CONCURRENT parked (Tier-2) requests for this filter. Each parked request
    /// pins exactly one instance for the WHOLE host-call round-trip, so the pool
    /// is the concurrency ceiling for parks: once all instances are pinned the
    /// next park is refused (now with connection backpressure instead of a bare
    /// 503, see POOL_BACKPRESSURE_MS). The park Table (`host_call.Table.CAP`,
    /// currently 64) is the HARD ceiling across all filters on a worker, so
    /// sizing a single filter's pool above CAP buys nothing. Cost: each extra
    /// instance reserves another `max_memory_pages` (default 4 MiB) of linear
    /// memory per worker. Rule of thumb: instances = min(expected concurrent
    /// fan-out, host_call.Table.CAP).
    instances: usize = 1,
    max_memory_pages: u32 = DEFAULT_MAX_MEMORY_PAGES,
    /// S3: opt-in fail-closed for the on_response hook. The response phase fails
    /// OPEN by default (a trap serves the original response unchanged) because
    /// the request already passed policy. But a redaction/scrub filter that
    /// traps would then LEAK the un-redacted response. Set this for such filters
    /// so a response-phase trap serves a 503 instead of the original.
    response_fail_closed: bool = false,
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
    /// Phase 3 resume entry, re-entered after a host call completes. Optional:
    /// a filter that never parks does not export it.
    on_resume: ?c.IM3Function = null,
    /// Phase 2b response hook, run after the handler/upstream produces a response.
    /// Optional: a request-only filter does not export it.
    on_response: ?c.IM3Function = null,
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

    // Phase 3 host call: the outbound request staged by host_call() during
    // on_request, and the result staged by the host before on_resume(). Both
    // persist in the pinned instance across the park.
    has_pending_call: bool = false,
    pending_call_len: usize = 0,
    call_buf: [CALL_REQUEST_CAP]u8 = undefined,
    call_result_len: usize = 0,
    call_result_buf: [CALL_RESULT_CAP]u8 = undefined,

    // Tenant-as-upstream (park-concurrency Phase 1): a UNIX socket path the guest
    // stages via set_upstream (in on_request or on_resume). The park machinery
    // copies it out at resume; the resumed request is forwarded there. Opaque to
    // the guest otherwise.
    staged_upstream_len: usize = 0,
    staged_upstream_buf: [UPSTREAM_PATH_CAP]u8 = undefined,

    // Phase 2b response phase. The outgoing response (borrowed) plus its body
    // materialized lazily for reads, and the staged replacement body / status
    // override. Response headers reuse staged_headers/scratch (this is a separate
    // invocation, so resetStaging clears them first).
    resp: ?*const response.Response = null,
    resp_body_materialized: bool = false,
    resp_body_view_len: usize = 0,
    resp_body_full_len: usize = 0,
    resp_body_buf: [MAX_BODY_VIEW]u8 = undefined,
    resp_has_repl: bool = false,
    resp_repl_len: usize = 0,
    resp_repl_buf: [MAX_BODY_VIEW]u8 = undefined,
    resp_new_status: u16 = 0,

    fn resetStaging(self: *Instance) void {
        self.staged_status = 0;
        self.staged_body_len = 0;
        self.staged_header_count = 0;
        self.scratch_used = 0;
        self.body_materialized = false;
        self.body_view_len = 0;
        self.body_full_len = 0;
        self.has_pending_call = false;
        self.pending_call_len = 0;
        self.call_result_len = 0;
        self.staged_upstream_len = 0;
    }

    fn resetResponseStaging(self: *Instance) void {
        self.resp = null;
        self.resp_body_materialized = false;
        self.resp_body_view_len = 0;
        self.resp_body_full_len = 0;
        self.resp_has_repl = false;
        self.resp_repl_len = 0;
        self.resp_new_status = 0;
    }

    /// Materialize the response body into the bounded view buffer on first access.
    fn ensureRespBody(self: *Instance) void {
        if (self.resp_body_materialized) return;
        self.resp_body_materialized = true;
        const r = self.resp orelse return;
        self.resp_body_full_len = r.bodyLen();
        self.resp_body_view_len = materializeResponseBody(r.*, &self.resp_body_buf);
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

/// Copy up to dst.len bytes of a response body into dst (scattered -> linear),
/// returning the number copied. Mirrors materializeBody for the response side.
fn materializeResponseBody(resp: response.Response, dst: []u8) usize {
    switch (resp.body) {
        .none => return 0,
        .bytes => |s| {
            const n = @min(s.len, dst.len);
            @memcpy(dst[0..n], s[0..n]);
            return n;
        },
        .managed => |m| {
            const n = @min(m.len, dst.len);
            @memcpy(dst[0..n], m.handle.bytes[0..n]);
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
    // Return the TRUE length (copied = min(len, cap)) so a guest with an
    // undersized buffer can detect truncation and grow/retry.
    ret.* = @intCast(path.len);
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
        ret.* = 0; // 0 = header absent (an empty present value also returns 0)
        return null;
    };
    const n = @min(val.len, dst.len);
    @memcpy(dst[0..n], val[0..n]);
    // True length (copied = min(len, cap)); lets the guest detect truncation.
    ret.* = @intCast(val.len);
    return null;
}

/// Framing / hop-by-hop headers a filter must not stage (the server owns these;
/// a staged copy would duplicate/conflict -> response smuggling).
fn isFramingHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "connection");
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
    // Drop framing / hop-by-hop headers a filter must not control: the server
    // computes Content-Length from the body and owns connection framing, so a
    // staged Content-Length / Transfer-Encoding (or Connection) would produce a
    // conflicting duplicate -> response smuggling. Filters run untrusted code, so
    // this is a real surface; ignore the staged header rather than emit it.
    if (isFramingHeader(name_src)) return null;
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

// Phase 3: stage an outbound host call. The guest encodes its request (target +
// payload, opaque to swerver here) into [ptr,len]; the host performs it while the
// request is parked and delivers the result to on_resume. Returns 0 on success,
// -1 if the request exceeds CALL_REQUEST_CAP (the guest can shrink and retry).
fn hostHostCall(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const ptr: u32 = @truncate(sp[1]);
    const len: u32 = @truncate(sp[2]);
    const src = guestView(rt, mem, ptr, len) orelse return trap(TRAP_OOB);
    if (src.len > inst.call_buf.len) {
        ret.* = -1;
        return null;
    }
    @memcpy(inst.call_buf[0..src.len], src);
    inst.pending_call_len = src.len;
    inst.has_pending_call = true;
    ret.* = 0;
    return null;
}

// Tenant-as-upstream (park-concurrency Phase 1): the guest stages the UNIX
// socket path of the microVM this request should be forwarded to (typically in
// on_resume, after reading the Tier-2 cold-start reply). The park machinery
// copies it out on resume; proxyResume validates it against the route's
// socket_dir before forwarding. Returns 0 on success, -1 if empty, over
// UPSTREAM_PATH_CAP, or containing a NUL (an invalid socket path).
fn hostSetUpstream(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const ptr: u32 = @truncate(sp[1]);
    const len: u32 = @truncate(sp[2]);
    const src = guestView(rt, mem, ptr, len) orelse return trap(TRAP_OOB);
    if (src.len == 0 or src.len > inst.staged_upstream_buf.len) {
        ret.* = -1;
        return null;
    }
    if (std.mem.indexOfScalar(u8, src, 0) != null) {
        ret.* = -1;
        return null;
    }
    @memcpy(inst.staged_upstream_buf[0..src.len], src);
    inst.staged_upstream_len = src.len;
    ret.* = 0;
    return null;
}

/// The socket path the guest staged via set_upstream (empty slice if none).
/// Read by the park table at resume time.
pub fn stagedUpstream(inst: *const Instance) []const u8 {
    return inst.staged_upstream_buf[0..inst.staged_upstream_len];
}

// Phase 3: in on_resume, copy the host-call result into guest memory.
fn hostReadCallResult(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const out_ptr: u32 = @truncate(sp[1]);
    const out_cap: u32 = @truncate(sp[2]);
    const dst = guestView(rt, mem, out_ptr, out_cap) orelse return trap(TRAP_OOB);
    const n = @min(inst.call_result_len, dst.len);
    @memcpy(dst[0..n], inst.call_result_buf[0..n]);
    ret.* = @intCast(n);
    return null;
}

// --- Phase 2b response-phase host functions --------------------------------
// These read `inst.resp` (the outgoing response) and stage edits. Valid only
// inside on_response; `inst.resp` is null otherwise and they no-op / return 0.

fn hostGetResponseStatus(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    _ = mem;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    ret.* = if (inst.resp) |r| @intCast(r.status) else 0;
    return null;
}

fn hostGetResponseHeader(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const name_ptr: u32 = @truncate(sp[1]);
    const name_len: u32 = @truncate(sp[2]);
    const out_ptr: u32 = @truncate(sp[3]);
    const out_cap: u32 = @truncate(sp[4]);
    const name = guestView(rt, mem, name_ptr, name_len) orelse return trap(TRAP_OOB);
    const dst = guestView(rt, mem, out_ptr, out_cap) orelse return trap(TRAP_OOB);
    const r = inst.resp orelse {
        ret.* = 0;
        return null;
    };
    for (r.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) {
            const n = @min(h.value.len, dst.len);
            @memcpy(dst[0..n], h.value[0..n]);
            ret.* = @intCast(h.value.len); // true length (copied = min)
            return null;
        }
    }
    ret.* = 0; // absent
    return null;
}

fn hostResponseBodyLen(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    _ = mem;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    inst.ensureRespBody();
    const ret: *i32 = @ptrCast(@alignCast(sp));
    ret.* = @intCast(@min(inst.resp_body_full_len, @as(usize, std.math.maxInt(i32))));
    return null;
}

fn hostReadResponseBody(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    inst.ensureRespBody();
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const src_off: u32 = @truncate(sp[1]);
    const out_ptr: u32 = @truncate(sp[2]);
    const out_cap: u32 = @truncate(sp[3]);
    const dst = guestView(rt, mem, out_ptr, out_cap) orelse return trap(TRAP_OOB);
    if (src_off >= inst.resp_body_view_len) {
        ret.* = 0;
        return null;
    }
    const avail = inst.resp_body_view_len - src_off;
    const n = @min(avail, dst.len);
    @memcpy(dst[0..n], inst.resp_body_buf[src_off .. src_off + n]);
    ret.* = @intCast(n);
    return null;
}

fn hostSetResponseStatus(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = rt;
    _ = ctx;
    _ = mem;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const status: u32 = @truncate(sp[0]);
    inst.resp_new_status = @intCast(status);
    return null;
}

fn hostReplaceResponseBody(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const inst = active orelse return trap(TRAP_NO_ACTIVE);
    const ret: *i32 = @ptrCast(@alignCast(sp));
    const ptr: u32 = @truncate(sp[1]);
    const len: u32 = @truncate(sp[2]);
    const src = guestView(rt, mem, ptr, len) orelse return trap(TRAP_OOB);
    if (src.len > inst.resp_repl_buf.len) {
        ret.* = -1; // too large; the guest can shrink and retry
        return null;
    }
    @memcpy(inst.resp_repl_buf[0..src.len], src);
    inst.resp_repl_len = src.len;
    inst.resp_has_repl = true;
    ret.* = 0;
    return null;
}

fn hostLog(rt: c.IM3Runtime, ctx: c.IM3ImportContext, sp: [*c]u64, mem: ?*anyopaque) callconv(.c) ?*const anyopaque {
    _ = ctx;
    const ptr: u32 = @truncate(sp[0]);
    const len: u32 = @truncate(sp[1]);
    // Always bounds-check (an out-of-bounds log pointer must still trap). D5: emit
    // through std.log at DEBUG level under the `wasm_filter` scope instead of the
    // old hard `builtin.mode == .Debug` gate. This makes filter logs available in
    // a release build when the operator raises the log level (previously
    // impossible -- they were compiled out), while staying off by default. The
    // message is guest-controlled, but the per-invocation fuel budget bounds how
    // many times a filter can call log() in one request, so this is not an
    // unbounded spam vector.
    const msg = guestView(rt, mem, ptr, len) orelse return trap(TRAP_OOB);
    std.log.scoped(.wasm_filter).debug("{s}", .{msg});
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
    try mod.link("env", "host_call", "i(ii)", hostHostCall);
    try mod.link("env", "read_call_result", "i(ii)", hostReadCallResult);
    // Tenant-as-upstream (Phase 1). Linked unconditionally; filters that do not
    // import it leave it unresolved (link tolerates that).
    try mod.link("env", "set_upstream", "i(ii)", hostSetUpstream);
    // Phase 2b response-phase imports. Linked unconditionally; a filter that
    // does not import them just leaves them unresolved (link tolerates that).
    try mod.link("env", "get_response_status", "i()", hostGetResponseStatus);
    try mod.link("env", "get_response_header", "i(iiii)", hostGetResponseHeader);
    try mod.link("env", "response_body_len", "i()", hostResponseBodyLen);
    try mod.link("env", "read_response_body", "i(iii)", hostReadResponseBody);
    try mod.link("env", "set_response_status", "v(i)", hostSetResponseStatus);
    try mod.link("env", "replace_response_body", "i(ii)", hostReplaceResponseBody);
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

threadlocal var trap_log_count: u64 = 0;

/// Log WHY a guest trapped (the wasm3 trap message, e.g. an out-of-bounds ABI
/// pointer or fuel exhaustion) so a fail-closed 500 is diagnosable instead of
/// opaque. Exponential-backoff sampled (logs at occurrences 1,2,4,8,...) so a
/// buggy or hostile filter that traps on every request cannot flood the log.
fn logTrap(phase: []const u8, path: []const u8) void {
    trap_log_count += 1;
    if (trap_log_count & (trap_log_count - 1) != 0) return;
    std.log.warn("wasm filter trapped in {s} -> fail-closed: {s} [path={s}, occurrence #{d}]", .{ phase, runtime.lastTrap(), path, trap_log_count });
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
        DECISION_PARKED => failClosed(), // handled by invokeOutcome, not here
        else => failClosed(),
    };
}

/// Result of a park-aware invocation (Phase 3).
pub const Outcome = union(enum) {
    /// Terminal decision; the instance has been released back to the pool.
    decision: middleware.Decision,
    /// The filter staged a host call and parked. The instance is PINNED
    /// (.parked, withheld from the pool) and must be resumed via resumeCall
    /// once the host call completes, or cancelled via cancelPark. The slice is
    /// the guest-encoded outbound request, borrowing the pinned instance's
    /// buffer (valid until resume/cancel).
    parked: []const u8,
};

/// Park-aware invocation (Phase 3). On a terminal decision the instance is
/// released; on a park it is pinned for a later resumeCall.
pub fn invokeOutcome(inst: *Instance, req: *const request.RequestView, fuel_budget: i64) Outcome {
    inst.resetStaging();
    inst.req = req;
    inst.state = .running;
    active = inst;

    runtime.fuel.set(fuel_budget);
    const code = runtime.callI32(inst.on_request) catch {
        logTrap("on_request", req.path);
        active = null;
        inst.state = .idle;
        return .{ .decision = failClosed() };
    };
    active = null;

    if (code == DECISION_PARKED) {
        if (inst.has_pending_call) {
            inst.state = .parked; // pinned; NOT returned to the pool
            return .{ .parked = inst.call_buf[0..inst.pending_call_len] };
        }
        // parked code with no staged host call is a guest protocol error.
        inst.state = .idle;
        return .{ .decision = failClosed() };
    }

    inst.state = .idle;
    return .{ .decision = buildDecision(inst, code) };
}

/// Deliver a completed host-call result to a parked instance and re-enter its
/// on_resume export, producing the terminal Decision. Releases the instance.
pub fn resumeCall(inst: *Instance, result_bytes: []const u8, fuel_budget: i64) middleware.Decision {
    // Runtime fail-closed guard (NOT a debug assert, which compiles out in
    // release): resuming an instance that is not parked would corrupt a live or
    // idle instance. The token generation in host_call.Table makes a stale resume
    // unreachable, but this is the last-line defense if that ever regresses.
    if (inst.state != .parked) return failClosed();
    const n = @min(result_bytes.len, inst.call_result_buf.len);
    @memcpy(inst.call_result_buf[0..n], result_bytes[0..n]);
    inst.call_result_len = n;

    const on_resume = inst.on_resume orelse {
        inst.state = .idle;
        return failClosed(); // parked but no resume export: protocol error
    };

    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }
    runtime.fuel.set(fuel_budget);
    const code = runtime.callI32(on_resume) catch {
        // NOT inst.req.path here: on the async resume path inst.req is the stale
        // original request (the owned snapshot lives on the host_call slot, not
        // on the instance), so dereferencing it would be a use-after-free.
        logTrap("on_resume", "(parked; request not retained on instance)");
        return failClosed();
    };
    return buildDecision(inst, code);
}

/// Release a parked instance without resuming (host call failed, timed out, or
/// the client disconnected). Returns the fail-closed Decision to serve if the
/// request is still live.
pub fn cancelPark(inst: *Instance) middleware.Decision {
    inst.state = .idle;
    return failClosed();
}

/// The response-phase edit a filter staged. All slices borrow the instance's
/// scratch and are valid until the instance is reused (after this response is
/// serialized -- the same non-reentrancy invariant the request phase relies on).
/// An all-null/empty value means "serve the original response unchanged".
pub const ResponseEdit = struct {
    new_status: ?u16 = null,
    add_headers: []const response.Header = &.{},
    new_body: ?[]const u8 = null,
    /// S3: the on_response hook TRAPPED (distinct from an empty edit, which means
    /// "serve original unchanged" after a clean pass). A caller whose pool is
    /// response_fail_closed must serve a 503 instead of the original response.
    trapped: bool = false,
};

/// Run the Phase 2b response hook on `inst` against the outgoing response.
/// FAIL-OPEN: a trap, a missing on_response export, or a nonzero return all
/// yield an empty edit (serve the original response unchanged). The request
/// already passed policy, so a misbehaving response filter must not break the
/// response. `req` is set so the filter can still read request metadata.
pub fn invokeResponse(
    inst: *Instance,
    req: *const request.RequestView,
    resp: *const response.Response,
    fuel_budget: i64,
) ResponseEdit {
    inst.resetStaging();
    inst.resetResponseStaging();
    inst.req = req;
    inst.resp = resp;
    inst.state = .running;
    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }

    const on_response = inst.on_response orelse return .{}; // no hook: pass through

    runtime.fuel.set(fuel_budget);
    // trap: signal it via .trapped so a response_fail_closed pool can serve a 503;
    // the default (fail-open) caller still treats an empty/trapped edit as
    // "serve original unchanged".
    const code = runtime.callI32(on_response) catch {
        logTrap("on_response", req.path);
        return .{ .trapped = true };
    };
    if (code != 0) return .{}; // guest opted out: pass through unchanged

    return .{
        .new_status = if (inst.resp_new_status != 0) inst.resp_new_status else null,
        .add_headers = inst.staged_headers[0..inst.staged_header_count],
        .new_body = if (inst.resp_has_repl) inst.resp_repl_buf[0..inst.resp_repl_len] else null,
    };
}

/// Terminal invocation for callers that cannot park (the synchronous router /
/// proxy pre-hook today). A filter that parks here fails closed until the
/// server-side resume path (Phase 3 reactor wiring) is in place.
pub fn invoke(inst: *Instance, req: *const request.RequestView, fuel_budget: i64) middleware.Decision {
    switch (invokeOutcome(inst, req, fuel_budget)) {
        .decision => |d| return d,
        .parked => {
            inst.state = .idle; // unpin: this path cannot resume
            return failClosed();
        },
    }
}

/// A per-worker pool of pre-instantiated instances for one filter module.
/// Mirrors the PG slot pool: fixed instances, acquire/release, zero per-request
/// heap allocation on the hot path.
pub const Pool = struct {
    alloc: std.mem.Allocator,
    instances: []Instance,
    /// The module bytes are referenced (not copied) by wasm3; the pool owns them.
    wasm_bytes: []u8,
    /// S3: serve a 503 (not the original response) when the on_response hook traps.
    response_fail_closed: bool = false,

    pub fn init(alloc: std.mem.Allocator, wasm_bytes: []const u8, config: Config) Error!Pool {
        // Clamp to at least one instance. A zero count is a config error (it
        // would make acquire() always fail and 503 every request); the assert
        // that used to guard this is compiled out in release, so clamp instead.
        const count = @max(config.instances, 1);
        const owned = try alloc.dupe(u8, wasm_bytes);
        errdefer alloc.free(owned);

        const instances = try alloc.alloc(Instance, count);
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
            inst.* = .{
                .module = mod,
                .on_request = on_request,
                .on_resume = mod.findOptional("on_resume"),
                .on_response = mod.findOptional("on_response"),
            };
            built += 1;
        }

        return .{ .alloc = alloc, .instances = instances, .wasm_bytes = owned, .response_fail_closed = config.response_fail_closed };
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

    /// True if this pool's module exports on_response (cheap gate so the router
    /// skips the response phase entirely for request-only filters).
    pub fn hasResponseHook(self: *const Pool) bool {
        return self.instances.len > 0 and self.instances[0].on_response != null;
    }

    /// Total instances in this pool (the park-concurrency ceiling for the filter).
    pub fn instanceCount(self: *const Pool) usize {
        return self.instances.len;
    }

    /// Instances NOT idle (running or pinned by a park). At == instanceCount the
    /// next park is refused with backpressure (observability for saturation).
    pub fn pinnedCount(self: *const Pool) usize {
        var n: usize = 0;
        for (self.instances) |*inst| {
            if (inst.state != .idle) n += 1;
        }
        return n;
    }

    /// Run the response phase: acquire, runResponse, release. FAIL-OPEN on a busy
    /// pool (returns an empty edit) -- a transient pool exhaustion must not break
    /// a response that already passed policy.
    pub fn runResponse(
        self: *Pool,
        req: *const request.RequestView,
        resp: *const response.Response,
        fuel_budget: i64,
    ) ResponseEdit {
        const inst = self.acquire() orelse return .{};
        return invokeResponse(inst, req, resp, fuel_budget);
    }
};

// ---------------------------------------------------------------------------
// Tests (run with: zig build test -Denable-wasm=true)
// ---------------------------------------------------------------------------

const testing = std.testing;
const FILTER_WASM = @embedFile("testdata/filter_probe.wasm");
// The canonical examples/wasm_filter SDK example, built through abi.zig (D2).
// Loading it exercises EVERY host import via abi.zig's signatures, so this is the
// drift guard: if abi.zig and linkAbi disagree, Pool.init's lazy compile of the
// exports fails and these tests fail. Rebuild with testdata/build_probe.sh.
const ABI_EXAMPLE_WASM = @embedFile("testdata/abi_example_filter.wasm");

fn mkReq(method: request.Method, path: []const u8, headers: []const request.Header) request.RequestView {
    return .{ .method = method, .path = path, .headers = headers };
}

test "D2: abi.zig SDK example links (all signatures match linkAbi) and runs" {
    var pool = try Pool.init(testing.allocator, ABI_EXAMPLE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    // Pool.init lazily compiles on_request / on_resume / on_response. Each compile
    // validates the host-import signatures those exports reference, so reaching
    // here at all means abi.zig's 17 externs match the host linkAbi. on_resume
    // (read_call_result) and on_response (the 6 response-phase imports) are the
    // ones a request-only test would never exercise:
    try testing.expect(pool.instances[0].on_resume != null);
    try testing.expect(pool.instances[0].on_response != null);
    try testing.expect(pool.hasResponseHook());
    // And it runs end to end through the abi.zig helpers: /secure with no
    // Authorization rejects 401; /public allows.
    const denied = mkReq(.GET, "/secure/x", &.{});
    const d = pool.run(&denied, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 401), d.reject.status);
    const ok = mkReq(.GET, "/public", &.{});
    try testing.expect(pool.run(&ok, DEFAULT_FUEL) == .allow);
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

test "D1: a guest trap records a diagnostic message (not an opaque 500)" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const r = mkReq(.GET, "/oob", &.{});
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    // The trap reason is captured (logTrap logs it; here we assert it is non-empty
    // so a fail-closed 500 is diagnosable rather than silent). The OOB ABI traps
    // carry the "out of bounds" message.
    const msg = runtime.lastTrap();
    try testing.expect(msg.len > 0);
    try testing.expect(std.mem.indexOf(u8, msg, "out of bounds") != null);
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

test "park/resume: filter parks, pins instance, resumes to allow" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();

    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = mkReq(.GET, "/enrich", &.{});
    const out = invokeOutcome(inst, &r, DEFAULT_FUEL);

    // Parked: the staged outbound request is visible and the instance is pinned.
    try testing.expect(out == .parked);
    try testing.expectEqualStrings("lookup:user", out.parked);
    try testing.expectEqual(Instance.State.parked, inst.state);
    // Pinned instance is withheld from the pool (1 instance -> exhausted).
    try testing.expect(pool.acquire() == null);

    // Host call returns "ok" -> on_resume allows; instance released.
    const d = resumeCall(inst, "ok", DEFAULT_FUEL);
    try testing.expect(d == .allow);
    try testing.expectEqual(Instance.State.idle, inst.state);
    try testing.expect(pool.acquire() != null);
    inst.state = .idle;
}

test "park/resume: resume result drives reject" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = mkReq(.GET, "/enrich", &.{});
    try testing.expect(invokeOutcome(inst, &r, DEFAULT_FUEL) == .parked);

    const d = resumeCall(inst, "no-such-user", DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 403), d.reject.status);
    try testing.expectEqualStrings("enrichment denied", d.reject.bodyBytes());
}

test "park/resume: cancelPark releases a pinned instance, fail-closed" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = mkReq(.GET, "/enrich", &.{});
    try testing.expect(invokeOutcome(inst, &r, DEFAULT_FUEL) == .parked);

    const d = cancelPark(inst);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 500), d.reject.status);
    try testing.expectEqual(Instance.State.idle, inst.state);
    try testing.expect(pool.acquire() != null);
    inst.state = .idle;
}

test "park/resume: terminal invoke() fails closed on a parking filter" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    // The synchronous run() path cannot resume, so a parking filter fails closed
    // (500) and the instance is released, not leaked as pinned.
    const r = mkReq(.GET, "/enrich", &.{});
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 500), d.reject.status);
    try testing.expect(pool.acquire() != null); // not stuck pinned
    // release the one we just acquired
    for (pool.instances) |*i| i.state = .idle;
}

test "abi: get_path returns the true length so truncation is detectable" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const p = "/a/fairly/long/path";
    const r = mkReq(.GET, p, &.{});
    inst.req = &r;
    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }
    runtime.fuel.unlimited();
    const f = inst.module.findOptional("get_path_ret") orelse return error.FunctionNotFound;
    // Tiny 4-byte cap: the host copies 4 bytes but reports the true length.
    const ret = try runtime.callI32_2(f, 0, 4);
    try testing.expectEqual(@as(i32, @intCast(p.len)), ret);
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

// --- Phase 2b response-phase tests -----------------------------------------

const RESPONSE_WASM = @embedFile("testdata/response_probe.wasm");

fn mkResp(status: u16, headers: []const response.Header, body: []const u8) response.Response {
    return .{ .status = status, .headers = headers, .body = .{ .bytes = body } };
}

fn hdrValue(headers: []const response.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

test "response phase: hasResponseHook distinguishes response- from request-only filters" {
    var rp = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer rp.deinit();
    var fp = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer fp.deinit();
    try testing.expect(rp.hasResponseHook());
    try testing.expect(!fp.hasResponseHook());
}

test "response phase: default path adds a header, body/status unchanged" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const req = mkReq(.GET, "/widgets", &.{});
    const resp = mkResp(200, &.{}, "hello");
    const edit = pool.runResponse(&req, &resp, DEFAULT_FUEL);
    try testing.expect(edit.new_status == null);
    try testing.expect(edit.new_body == null);
    try testing.expectEqualStrings("applied", hdrValue(edit.add_headers, "x-wasm-response") orelse return error.NoHeader);
}

test "response phase: status override + body replace" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const req = mkReq(.GET, "/widgets", &.{});
    const resp = mkResp(200, &.{}, "boom: sensitive data leaked");
    const edit = pool.runResponse(&req, &resp, DEFAULT_FUEL);
    try testing.expectEqual(@as(?u16, 403), edit.new_status);
    try testing.expectEqualStrings("blocked by edge", edit.new_body orelse return error.NoBody);
}

test "response phase: body transform" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const req = mkReq(.GET, "/widgets", &.{});
    const resp = mkResp(200, &.{}, "transform-me");
    const edit = pool.runResponse(&req, &resp, DEFAULT_FUEL);
    try testing.expect(edit.new_status == null);
    try testing.expectEqualStrings("transformed", edit.new_body orelse return error.NoBody);
}

test "response phase: opt out (return nonzero) leaves the response unchanged" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const req = mkReq(.GET, "/raw", &.{});
    const resp = mkResp(200, &.{}, "hello");
    const edit = pool.runResponse(&req, &resp, DEFAULT_FUEL);
    try testing.expect(edit.new_status == null);
    try testing.expect(edit.new_body == null);
    try testing.expectEqual(@as(usize, 0), edit.add_headers.len);
}

test "response phase: a trap fails OPEN (original response served)" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const req = mkReq(.GET, "/trap", &.{});
    const resp = mkResp(200, &.{}, "hello");
    const edit = pool.runResponse(&req, &resp, DEFAULT_FUEL);
    // Fail-open: empty edit, the original response is served unchanged.
    try testing.expect(edit.new_status == null);
    try testing.expect(edit.new_body == null);
    try testing.expectEqual(@as(usize, 0), edit.add_headers.len);
    // S3: the trap is now SIGNALED (the default fail-open caller ignores it, but a
    // response_fail_closed pool uses it to serve a 503 instead of the original).
    try testing.expect(edit.trapped);
}

test "S3: response_fail_closed pool sets the flag; trap signaled, clean pass not" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1, .response_fail_closed = true });
    defer pool.deinit();
    // The opt-in flag is recorded on the pool for the caller to consult.
    try testing.expect(pool.response_fail_closed);
    // A trapping on_response signals .trapped (caller will serve 503, not leak).
    const tr = mkReq(.GET, "/trap", &.{});
    const resp = mkResp(200, &.{}, "secret-original-body");
    const edit = pool.runResponse(&tr, &resp, DEFAULT_FUEL);
    try testing.expect(edit.trapped);
    // A clean pass is NOT trapped, so fail-closed must not fire on success.
    const ok = mkReq(.GET, "/widgets", &.{});
    const e2 = pool.runResponse(&ok, &resp, DEFAULT_FUEL);
    try testing.expect(!e2.trapped);
}

test "response phase: a request-only filter passes through (no on_response)" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const req = mkReq(.GET, "/widgets", &.{});
    const resp = mkResp(200, &.{}, "hello");
    const edit = pool.runResponse(&req, &resp, DEFAULT_FUEL);
    try testing.expect(edit.new_status == null);
    try testing.expect(edit.new_body == null);
    try testing.expectEqual(@as(usize, 0), edit.add_headers.len);
}

// ---------------------------------------------------------------------------
// D2 security probing (D2-2 fuel/memory bombs, D2-3 ABI fuzz, D2-4 fail-closed/
// fail-open invariant, D2-5 resource exhaustion). These EXTEND the coverage
// above: they exercise the response phase, the host_call/replace length caps,
// and make the core fail-closed (request) / fail-open (response) invariant
// explicit, including recovery after a fault.
// ---------------------------------------------------------------------------

// --- D2-2: fuel / memory bombs ---------------------------------------------

test "D2-2 request phase: memory.grow past the cap returns -1, no worker OOM" {
    // The default 64-page cap; the fixture starts well below it. A grow far past
    // the cap must return -1 (wasm spec) and leave linear memory untouched,
    // rather than OOMing the worker.
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = mkReq(.GET, "/x", &.{});
    inst.req = &r;
    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }
    runtime.fuel.unlimited();
    const grow = inst.module.findOptional("grow_pages") orelse return error.FunctionNotFound;
    const before = inst.module.memoryPages();
    try testing.expectEqual(@as(i32, -1), try runtime.callI32_2(grow, 100_000, 0));
    try testing.expectEqual(before, inst.module.memoryPages());
    // A small in-cap grow still succeeds: the cap is a ceiling, not a hard no.
    try testing.expect(try runtime.callI32_2(grow, 1, 0) >= 0);
}

test "D2-2 response phase: a fuel-exhausting spin in on_response fails OPEN" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const req = mkReq(.GET, "/spin", &.{});
    const resp = mkResp(200, &.{}, "original body");
    // A bounded budget must trap the spin rather than hang the worker; a trapped
    // on_response fails OPEN -> empty edit -> the original response is served.
    const edit = pool.runResponse(&req, &resp, 200_000);
    try testing.expect(edit.new_status == null);
    try testing.expect(edit.new_body == null);
    try testing.expectEqual(@as(usize, 0), edit.add_headers.len);
    // The pool is still usable after the trapped response invocation.
    const req2 = mkReq(.GET, "/widgets", &.{});
    const e2 = pool.runResponse(&req2, &resp, DEFAULT_FUEL);
    try testing.expectEqualStrings("applied", hdrValue(e2.add_headers, "x-wasm-response") orelse return error.NoHeader);
}

test "D2-2 response phase: memory.grow past the cap inside on_response returns -1" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const before = pool.instances[0].module.memoryPages();
    const req = mkReq(.GET, "/grow", &.{});
    const resp = mkResp(200, &.{}, "original body");
    const edit = pool.runResponse(&req, &resp, DEFAULT_FUEL);
    // The guest saw -1 from the over-cap grow (recorded in the body); the worker
    // did not OOM and linear memory did not actually grow.
    try testing.expectEqualStrings("grow-refused", edit.new_body orelse return error.NoBody);
    try testing.expectEqual(before, pool.instances[0].module.memoryPages());
}

// --- D2-3: ABI fuzz at scale (request host_call + response phase) -----------

// Out-of-bounds (ptr,len) pairs reused across every fuzzed import. Boundary,
// straddle, far-pointer, oversized-len, and near-u32-max (sum-overflow) cases.
fn oobCases(mem_bytes: u32) [5][2]u32 {
    return .{
        .{ mem_bytes, 1 }, // ptr exactly at end
        .{ mem_bytes -| 4, 64 }, // straddles the end
        .{ 0x7FFF_FFF0, 0x1000 }, // far pointer
        .{ 0, mem_bytes + 1 }, // length past end
        .{ 0xFFFF_FFF0, 0x20 }, // ptr+len overflows u32 (caught by u64 math)
    };
}

test "D2-3 ABI fuzz: host_call OOB always traps; over-cap length returns -1" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = mkReq(.GET, "/x", &.{});
    inst.req = &r;
    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }
    runtime.fuel.unlimited();
    const probe = inst.module.findOptional("host_call_probe") orelse return error.FunctionNotFound;
    const mem_bytes: u32 = inst.module.memoryPages() * runtime.PAGE_SIZE;

    // In-bounds, within CALL_REQUEST_CAP (4096): accepted (0).
    try testing.expectEqual(@as(i32, 0), try runtime.callI32_2(probe, 0, 16));
    // In-bounds but longer than the cap: -1 (not an overflow, not a host OOB).
    try testing.expectEqual(@as(i32, -1), try runtime.callI32_2(probe, 0, 5000));
    // Every out-of-bounds pair traps.
    for (oobCases(mem_bytes)) |cse| {
        try testing.expectError(runtime.Error.Trap, runtime.callI32_2(probe, @bitCast(cse[0]), @bitCast(cse[1])));
    }
}

test "D2-3 ABI fuzz: response-phase pointers always trap out of bounds" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const req = mkReq(.GET, "/widgets", &.{});
    const hdrs = [_]response.Header{.{ .name = "x-test", .value = "v" }};
    const resp = mkResp(200, &hdrs, "response body bytes");
    inst.req = &req;
    inst.resp = &resp;
    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }
    runtime.fuel.unlimited();
    const mem_bytes: u32 = inst.module.memoryPages() * runtime.PAGE_SIZE;

    const names = [_][:0]const u8{ "rp_read_resp_body", "rp_get_header_out", "rp_get_header_name", "rp_replace_body" };
    for (names) |fname| {
        const f = inst.module.findOptional(fname) orelse return error.FunctionNotFound;
        // In-bounds (offset/ptr 0, small len) is accepted (no trap).
        _ = try runtime.callI32_2(f, 0, 8);
        // Every out-of-bounds pair must trap (no host OOB read/write, no UB).
        for (oobCases(mem_bytes)) |cse| {
            try testing.expectError(runtime.Error.Trap, runtime.callI32_2(f, @bitCast(cse[0]), @bitCast(cse[1])));
        }
    }
}

test "D2-3 ABI fuzz: replace_response_body over the staging cap returns -1" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const req = mkReq(.GET, "/widgets", &.{});
    const resp = mkResp(200, &.{}, "body");
    inst.req = &req;
    inst.resp = &resp;
    active = inst;
    defer {
        active = null;
        inst.state = .idle;
    }
    runtime.fuel.unlimited();
    const f = inst.module.findOptional("rp_replace_body") orelse return error.FunctionNotFound;
    const cap: i32 = @intCast(MAX_BODY_VIEW); // resp_repl_buf staging cap (64 KiB)
    // Exactly at the cap, in bounds: accepted (0).
    try testing.expectEqual(@as(i32, 0), try runtime.callI32_2(f, 0, cap));
    // One byte past the cap, still in linear-memory bounds: -1 (no overflow).
    try testing.expectEqual(@as(i32, -1), try runtime.callI32_2(f, 0, cap + 1));
}

// --- D2-4: THE CORE -- fail-closed (request) / fail-open (response) ----------

test "D2-4 fail-closed: a request-phase trap is NEVER .allow (reject 500)" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    // /oob traps on an OOB ABI pointer; /loop traps on fuel exhaustion. Neither
    // may slip through as .allow -- both must fail closed with a reject.
    for ([_][]const u8{ "/oob", "/loop" }) |p| {
        const r = mkReq(.GET, p, &.{});
        const d = pool.run(&r, 200_000);
        try testing.expect(d != .allow);
        try testing.expect(d == .reject);
        try testing.expectEqual(@as(u16, 500), d.reject.status);
    }
    // Recovery: a normal request still works after the trapped invocations.
    const ok = mkReq(.GET, "/public", &.{});
    try testing.expect(pool.run(&ok, DEFAULT_FUEL) == .allow);
}

test "D2-4 fail-open: a response-phase trap yields an empty edit (serve original)" {
    var pool = try Pool.init(testing.allocator, RESPONSE_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const orig = mkResp(207, &.{}, "ORIGINAL-BODY");
    // Both a div-by-zero trap (/trap) and a fuel-trap (/spin) must fail OPEN:
    // no status override, no body replacement, no added headers -> the caller
    // serves `orig` unchanged.
    for ([_][]const u8{ "/trap", "/spin" }) |p| {
        const rq = mkReq(.GET, p, &.{});
        const edit = pool.runResponse(&rq, &orig, 200_000);
        try testing.expect(edit.new_status == null);
        try testing.expect(edit.new_body == null);
        try testing.expectEqual(@as(usize, 0), edit.add_headers.len);
    }
}

test "D2-4 fail-closed: a trap inside on_resume fails closed (resumeCall 500)" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 1 });
    defer pool.deinit();
    const inst = pool.acquire() orelse return error.AcquireFailed;
    const r = mkReq(.GET, "/enrich", &.{});
    try testing.expect(invokeOutcome(inst, &r, DEFAULT_FUEL) == .parked);
    // The fixture's on_resume traps when handed a "trap" result; resumeCall must
    // map that to a fail-closed reject (never a stale allow) and release it.
    const d = resumeCall(inst, "trap", DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 500), d.reject.status);
    try testing.expectEqual(Instance.State.idle, inst.state);
    try testing.expect(pool.acquire() != null);
    inst.state = .idle;
}

// --- D2-5: resource exhaustion (deterministic) ------------------------------

test "D2-5 pool exhaustion -> 503 then recovery, no instance leak" {
    var pool = try Pool.init(testing.allocator, FILTER_WASM, .{ .instances = 2 });
    defer pool.deinit();
    const a = pool.acquire() orelse return error.AcquireFailed;
    const b = pool.acquire() orelse return error.AcquireFailed;
    try testing.expect(pool.acquire() == null);

    // Exhausted: fail closed with 503 (never allow through with no instance).
    const r = mkReq(.GET, "/public", &.{});
    const d = pool.run(&r, DEFAULT_FUEL);
    try testing.expect(d == .reject);
    try testing.expectEqual(@as(u16, 503), d.reject.status);

    // Release one -> recovery: the next request succeeds.
    a.state = .idle;
    try testing.expect(pool.run(&r, DEFAULT_FUEL) == .allow);

    // No leak: after a successful run every instance is back to idle.
    b.state = .idle;
    var idle: usize = 0;
    for (pool.instances) |*i| {
        if (i.state == .idle) idle += 1;
    }
    try testing.expectEqual(@as(usize, 2), idle);
}
