//! Canonical host-ABI binding for swerver WASM edge filters (design 10.0).
//!
//! @import this next to your filter instead of hand-declaring `extern "env"`
//! functions. Hand-copied externs are the #1 filter-authoring footgun: a wrong
//! signature compiles fine but fails the HOST at load (an opaque LinkFunction
//! error). These signatures are verified against the host's `linkAbi`
//! (src/wasm/filter.zig) by the abi-example load test, so if they drift the test
//! fails.
//!
//! Build a filter with:
//!   zig build-exe my_filter.zig -target wasm32-freestanding -mcpu=mvp \
//!     -fno-entry -rdynamic -OReleaseSmall -femit-bin=my_filter.wasm
//! The `-mcpu=mvp` is REQUIRED: Zig's default wasm CPU enables reference_types,
//! which the vendored wasm3 cannot compile (the module fails to load). See
//! examples/wasm_filter/README.md.
//!
//! Exports your filter provides (the host calls these):
//!   export fn on_request() i32   -- required; return a Decision code below
//!   export fn on_resume() i32    -- only if you host_call/park
//!   export fn on_response() i32  -- optional; return 0 to apply staged edits

// --- Decision codes: return these from on_request / on_resume ---------------
pub const ALLOW: i32 = 0; // forward to the handler/upstream
pub const REJECT: i32 = 1; // short-circuit with the staged respond() body/status
pub const MODIFY: i32 = 2; // forward, applying staged response headers
pub const PARKED: i32 = 3; // staged a host_call and parked (resume in on_resume)

pub const Decision = enum(i32) { allow = ALLOW, reject = REJECT, modify = MODIFY, parked = PARKED };

// --- Method codes returned by get_method ------------------------------------
pub const Method = enum(i32) {
    GET = 0,
    HEAD = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
    CONNECT = 5,
    OPTIONS = 6,
    TRACE = 7,
    PATCH = 8,
    OTHER = 255,
    _,
};

// --- Raw host imports (verified 1:1 against linkAbi) ------------------------
// Pointers are guest linear-memory offsets (i32 on wasm32); lengths are u32. A
// "len" return is the TRUE length (may exceed your buffer) -- the helpers below
// clamp it so you never slice out of bounds. Use these directly only if you need
// the raw length; otherwise prefer the helpers.
pub const raw = struct {
    pub extern "env" fn get_method() i32;
    pub extern "env" fn get_path(out_ptr: [*]u8, out_cap: u32) u32;
    pub extern "env" fn get_header(name_ptr: [*]const u8, name_len: u32, out_ptr: [*]u8, out_cap: u32) u32;
    pub extern "env" fn header_count() i32;
    pub extern "env" fn body_len() i32;
    pub extern "env" fn read_body(src_off: u32, out_ptr: [*]u8, out_cap: u32) u32;
    pub extern "env" fn set_response_header(name_ptr: [*]const u8, name_len: u32, val_ptr: [*]const u8, val_len: u32) void;
    pub extern "env" fn respond(status: u32, body_ptr: [*]const u8, body_len: u32) void;
    pub extern "env" fn log(ptr: [*]const u8, len: u32) void;
    pub extern "env" fn host_call(ptr: [*]const u8, len: u32) i32;
    pub extern "env" fn read_call_result(out_ptr: [*]u8, out_cap: u32) u32;
    // Response-phase imports (valid in on_response).
    pub extern "env" fn get_response_status() i32;
    pub extern "env" fn get_response_header(name_ptr: [*]const u8, name_len: u32, out_ptr: [*]u8, out_cap: u32) u32;
    pub extern "env" fn response_body_len() i32;
    pub extern "env" fn read_response_body(src_off: u32, out_ptr: [*]u8, out_cap: u32) u32;
    pub extern "env" fn set_response_status(status: u32) void;
    pub extern "env" fn replace_response_body(ptr: [*]const u8, len: u32) i32;
};

fn clampLen(n: u32, cap: usize) usize {
    return @min(@as(usize, n), cap);
}

// --- Request-phase helpers (valid in on_request / on_resume) ----------------

/// The request method.
pub fn method() Method {
    return @enumFromInt(raw.get_method());
}

/// Copy the request path into `buf`; returns the clamped slice (never past buf).
pub fn path(buf: []u8) []const u8 {
    const n = raw.get_path(buf.ptr, @intCast(buf.len));
    return buf[0..clampLen(n, buf.len)];
}

/// Copy a request header value into `buf`; returns the clamped slice. NOTE: an
/// empty slice means the header is absent OR present-but-empty (the host cannot
/// yet distinguish the two).
pub fn header(name: []const u8, buf: []u8) []const u8 {
    const n = raw.get_header(name.ptr, @intCast(name.len), buf.ptr, @intCast(buf.len));
    return buf[0..clampLen(n, buf.len)];
}

pub fn headerCount() usize {
    return @intCast(@max(raw.header_count(), 0));
}

/// The TRUE request body length (may exceed the readable window; see readBody).
pub fn bodyLen() usize {
    return @intCast(@max(raw.body_len(), 0));
}

/// Copy request body bytes from `off` into `buf`; returns the clamped slice.
pub fn readBody(off: usize, buf: []u8) []const u8 {
    const n = raw.read_body(@intCast(off), buf.ptr, @intCast(buf.len));
    return buf[0..clampLen(n, buf.len)];
}

/// Stage a response status + body (served on REJECT, or as a 2xx short-circuit).
/// The body is truncated by the host past its staging cap.
pub fn respond(status: u16, body: []const u8) void {
    raw.respond(@intCast(status), body.ptr, @intCast(body.len));
}

/// Stage a response header (request phase: applied on MODIFY; response phase:
/// added to the outgoing response). Framing headers and over-budget headers are
/// dropped by the host.
pub fn setResponseHeader(name: []const u8, value: []const u8) void {
    raw.set_response_header(name.ptr, @intCast(name.len), value.ptr, @intCast(value.len));
}

/// Emit a debug log line (DROPPED in release host builds; dev aid only).
pub fn logMsg(msg: []const u8) void {
    raw.log(msg.ptr, @intCast(msg.len));
}

/// Stage an outbound Tier-2 host call and park. Returns false if `cmd` exceeds
/// the 4 KiB request cap. Do NOT append a newline -- the host owns the control
/// line terminator. On true, `return abi.PARKED;` from on_request.
pub fn hostCall(cmd: []const u8) bool {
    return raw.host_call(cmd.ptr, @intCast(cmd.len)) >= 0;
}

/// In on_resume: copy the completed host-call result into `buf` (clamped).
/// The result is the full agent reply frame: `<output>0x1e<exit>\n`. The host
/// un-escapes the output (R2b), so it may contain LITERAL 0x1e bytes; parse the
/// trailer from the END (see callResultParts), never the first 0x1e.
pub fn callResult(buf: []u8) []const u8 {
    const n = raw.read_call_result(buf.ptr, @intCast(buf.len));
    return buf[0..clampLen(n, buf.len)];
}

pub const CallResultParts = struct {
    /// Command output, literal bytes (host already un-escaped).
    output: []const u8,
    /// Exit code from the trailer; null when the trailer is absent/malformed
    /// (transport failure delivered a bare frame) -- treat as failure.
    exit_code: ?u8,
};

/// Split a callResult frame into output + exit code. The trailer is the frame's
/// SUFFIX `0x1e<digits>\n`, so it is found from the end: the LAST 0x1e. A
/// literal 0x1e inside the output (possible post-R2b) cannot forge it because
/// everything after the real trailer's 0x1e is only digits + newline.
pub fn callResultParts(frame: []const u8) CallResultParts {
    if (frame.len < 3 or frame[frame.len - 1] != '\n') return .{ .output = frame, .exit_code = null };
    var sep: usize = frame.len - 1;
    while (sep > 0) {
        sep -= 1;
        if (frame[sep] == 0x1e) {
            const digits = frame[sep + 1 .. frame.len - 1];
            if (digits.len == 0 or digits.len > 3) break;
            var code: u32 = 0;
            for (digits) |d| {
                if (d < '0' or d > '9') return .{ .output = frame, .exit_code = null };
                code = code * 10 + (d - '0');
            }
            if (code > 255) break;
            return .{ .output = frame[0..sep], .exit_code = @intCast(code) };
        }
        if (frame[sep] < '0' or frame[sep] > '9') break;
    }
    return .{ .output = frame, .exit_code = null };
}

// --- Response-phase helpers (valid in on_response) --------------------------

pub fn responseStatus() u16 {
    return @intCast(@max(raw.get_response_status(), 0));
}

pub fn responseHeader(name: []const u8, buf: []u8) []const u8 {
    const n = raw.get_response_header(name.ptr, @intCast(name.len), buf.ptr, @intCast(buf.len));
    return buf[0..clampLen(n, buf.len)];
}

pub fn responseBodyLen() usize {
    return @intCast(@max(raw.response_body_len(), 0));
}

pub fn readResponseBody(off: usize, buf: []u8) []const u8 {
    const n = raw.read_response_body(@intCast(off), buf.ptr, @intCast(buf.len));
    return buf[0..clampLen(n, buf.len)];
}

pub fn setResponseStatus(status: u16) void {
    raw.set_response_status(@intCast(status));
}

/// Replace the response body; returns false if it exceeds the host staging cap.
pub fn replaceResponseBody(body: []const u8) bool {
    return raw.replace_response_body(body.ptr, @intCast(body.len)) >= 0;
}
