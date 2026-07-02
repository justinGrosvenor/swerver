//! Test fixture for the Phase 2b response phase (C4). on_request always allows
//! (pass-through); on_response exercises the response ABI:
//!   - default: add header "x-wasm-response: applied".
//!   - response body starting with "boom": set status 403 + replace body.
//!   - response body == "transform-me": replace body with "transformed".
//!   - request path "/raw": return 1 (opt out -> serve original unchanged).
//!   - request path "/trap": trap (a genuine OOB ABI pointer) -> host fails OPEN.
//!   - request path "/spin": infinite loop (fuel trap) -> host fails OPEN.
//!   - request path "/grow": memory.grow past the cap -> replace body with a
//!     "grow-refused" marker (proves the cap holds inside on_response).
//!
//! It also exports arg-taking response-ABI fuzz probes (rp_*) so the host can be
//! handed arbitrary (ptr,len) pairs for the response-phase imports; an
//! out-of-bounds pair must trap and an over-cap replace length must return -1.
//!
//! Build via testdata/build_probe.sh (committed as a binary fixture).

const std = @import("std");

extern "env" fn get_path(out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn set_response_header(name_ptr: [*]const u8, name_len: u32, val_ptr: [*]const u8, val_len: u32) void;
extern "env" fn get_response_status() i32;
extern "env" fn get_response_header(name_ptr: [*]const u8, name_len: u32, out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn response_body_len() i32;
extern "env" fn read_response_body(src_off: u32, out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn set_response_status(status: u32) void;
extern "env" fn replace_response_body(ptr: [*]const u8, len: u32) i32;

var path_buf: [1024]u8 = undefined;
var body_buf: [4096]u8 = undefined;

export fn on_request() i32 {
    // For "/dual": stage a request-phase response header and return MODIFY (2).
    // Combined with on_response (which stages its own header on the SAME pooled
    // instance), this exercises the modify-headers-survive-the-response-phase fix
    // (the request-phase header must not be clobbered when the instance is reused).
    const plen = @min(get_path(&path_buf, path_buf.len), path_buf.len);
    if (std.mem.eql(u8, path_buf[0..plen], "/dual")) {
        const hn = "x-req-modify";
        const hv = "from-on-request";
        set_response_header(hn.ptr, hn.len, hv.ptr, hv.len);
        return 2; // modify: stage response headers, continue the chain
    }
    return 0; // allow: let the handler run, filter on the way out
}

export fn on_response() i32 {
    const plen = @min(get_path(&path_buf, path_buf.len), path_buf.len);
    const path = path_buf[0..plen];

    if (std.mem.eql(u8, path, "/raw")) return 1; // opt out: no changes

    if (std.mem.eql(u8, path, "/trap")) {
        // Force a genuine wasm trap (an OOB ABI pointer); the host must fail OPEN
        // so the original response is served. A div-by-zero would be folded away
        // by the optimizer (the divisor is a provably-zero global), so it would
        // not reliably trap.
        _ = read_response_body(0, @ptrFromInt(0xFFFF0000), 16);
        return 0;
    }

    if (std.mem.eql(u8, path, "/spin")) {
        // A runaway loop inside on_response: fuel must trap it and the host must
        // fail OPEN (the original response is served unchanged).
        while (true) {
            spin_counter +%= 1;
        }
    }

    if (std.mem.eql(u8, path, "/grow")) {
        // Memory bomb inside on_response: an over-cap grow must return -1 (no
        // worker OOM). Record the refusal in the body so the host can assert it.
        if (@wasmMemoryGrow(0, 100_000) == -1) {
            const repl = "grow-refused";
            _ = replace_response_body(repl.ptr, repl.len);
        }
        return 0;
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

// Touched only by the /spin loop; export var so it is not optimized away.
export var spin_counter: u64 = 0;

// --- response-ABI OOB fuzz probes ------------------------------------------
// Arg-taking entries (all 2-arg, so the host's callI32_2 helper drives them)
// that forward an arbitrary (ptr,len) to the pointer-bearing response-phase
// imports. A test sets up an active response invocation by hand and calls these
// with out-of-bounds pairs; every one must trap cleanly. The fixed args (offset,
// the "other" buffer) use known-valid in-bounds locations so the fuzzed pair is
// the only thing that can push the host out of bounds.

// Fuzz the OUTPUT buffer of read_response_body (offset fixed at 0, in bounds).
export fn rp_read_resp_body(out_ptr: u32, out_cap: u32) i32 {
    return @intCast(read_response_body(0, @ptrFromInt(out_ptr), out_cap));
}

// Fuzz the OUTPUT buffer of get_response_header (name fixed valid in bounds).
export fn rp_get_header_out(out_ptr: u32, out_cap: u32) i32 {
    const name = "x-test";
    return @intCast(get_response_header(name.ptr, name.len, @ptrFromInt(out_ptr), out_cap));
}

// Fuzz the NAME buffer of get_response_header (output fixed valid in bounds).
export fn rp_get_header_name(name_ptr: u32, name_len: u32) i32 {
    return @intCast(get_response_header(@ptrFromInt(name_ptr), name_len, &body_buf, body_buf.len));
}

// Fuzz replace_response_body's (ptr,len): an OOB pair must trap; an in-bounds
// length over the host staging cap must return -1 (not overflow).
export fn rp_replace_body(ptr: u32, len: u32) i32 {
    return replace_response_body(@ptrFromInt(ptr), len);
}
