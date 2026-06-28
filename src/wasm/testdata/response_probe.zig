//! Test fixture for the Phase 2b response phase (C4). on_request always allows
//! (pass-through); on_response exercises the response ABI:
//!   - default: add header "x-wasm-response: applied".
//!   - response body starting with "boom": set status 403 + replace body.
//!   - response body == "transform-me": replace body with "transformed".
//!   - request path "/raw": return 1 (opt out -> serve original unchanged).
//!   - request path "/trap": trap (integer div by zero) -> host fails OPEN.
//!
//! Build via testdata/build_probe.sh (committed as a binary fixture).

const std = @import("std");

extern "env" fn get_path(out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn set_response_header(name_ptr: [*]const u8, name_len: u32, val_ptr: [*]const u8, val_len: u32) void;
extern "env" fn get_response_status() i32;
extern "env" fn response_body_len() i32;
extern "env" fn read_response_body(src_off: u32, out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn set_response_status(status: u32) void;
extern "env" fn replace_response_body(ptr: [*]const u8, len: u32) i32;

var path_buf: [1024]u8 = undefined;
var body_buf: [4096]u8 = undefined;

export fn on_request() i32 {
    return 0; // allow: let the handler run, filter on the way out
}

export fn on_response() i32 {
    const plen = @min(get_path(&path_buf, path_buf.len), path_buf.len);
    const path = path_buf[0..plen];

    if (std.mem.eql(u8, path, "/raw")) return 1; // opt out: no changes

    if (std.mem.eql(u8, path, "/trap")) {
        // Force a wasm trap (integer div by zero); the host must fail OPEN so the
        // original response is served. zero_global is a runtime var (not folded).
        const boom: u32 = 1 / zero_global;
        return @intCast(boom);
    }

    // Always add a header in the default path.
    const hn = "x-wasm-response";
    const hv = "applied";
    set_response_header(hn.ptr, hn.len, hv.ptr, hv.len);

    // Read the response body and react to markers.
    const blen = @min(@as(usize, @intCast(response_body_len())), body_buf.len);
    const n = read_response_body(0, &body_buf, @intCast(blen));
    const body = body_buf[0..n];

    if (std.mem.startsWith(u8, body, "boom")) {
        set_response_status(403);
        const repl = "blocked by edge";
        _ = replace_response_body(repl.ptr, repl.len);
        return 0;
    }
    if (std.mem.eql(u8, body, "transform-me")) {
        const repl = "transformed";
        _ = replace_response_body(repl.ptr, repl.len);
        return 0;
    }
    return 0; // apply staged edits (just the header)
}

// A runtime-mutable zero so `1 / zero_global` is a real div-by-zero trap at
// runtime (not a comptime constant-fold error).
var zero_global: u32 = 0;
