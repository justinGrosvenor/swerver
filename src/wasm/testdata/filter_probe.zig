//! ABI test fixture: a filter that exercises the full custom ABI. Compiled to
//! wasm32-freestanding and committed as filter_probe.wasm (build_probe.sh).
//!
//!   /modify/*  -> set_response_header("x-checked","1"), return modify(2)
//!   /api/*     -> require x-api-key; if absent respond(401,...) + reject(1)
//!   else       -> allow(0)

const std = @import("std");

extern "env" fn get_method() i32;
extern "env" fn get_path(out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn get_header(name_ptr: [*]const u8, name_len: u32, out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn header_count() i32;
extern "env" fn body_len() i32;
extern "env" fn read_body(src_off: u32, out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn host_call(ptr: [*]const u8, len: u32) i32;
extern "env" fn read_call_result(out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn set_response_header(name_ptr: [*]const u8, name_len: u32, val_ptr: [*]const u8, val_len: u32) void;
extern "env" fn respond(status: u32, body_ptr: [*]const u8, body_len: u32) void;
extern "env" fn log(ptr: [*]const u8, len: u32) void;

var path_buf: [1024]u8 = undefined;
var key_buf: [256]u8 = undefined;
var body_buf: [4096]u8 = undefined;
var result_buf: [256]u8 = undefined;

export fn on_request() i32 {
    // get_path returns the TRUE length; clamp to our buffer when slicing.
    const plen = @min(get_path(&path_buf, path_buf.len), path_buf.len);
    const path = path_buf[0..plen];

    // Phase 3: stage an outbound host call and park. on_resume (below) decides
    // based on the result the host delivers.
    if (std.mem.startsWith(u8, path, "/enrich")) {
        const q = "lookup:user";
        _ = host_call(q.ptr, q.len);
        return 3; // parked
    }

    // Trap probes, reachable through the real on_request entry so invoke()'s
    // fail-closed path can be tested.
    if (std.mem.startsWith(u8, path, "/oob")) {
        // Hand the host a pointer far outside linear memory; host must trap.
        _ = get_path(@ptrFromInt(0xFFFF0000), 16);
        return 0;
    }
    if (std.mem.startsWith(u8, path, "/loop")) {
        while (true) {
            spin_counter +%= 1;
        }
    }

    // Body inspection: reject any /submit request whose body starts with "deny".
    // Demonstrates read_body + body_len; a too-large body is rejected rather
    // than trusted past the filter's view.
    if (std.mem.startsWith(u8, path, "/submit")) {
        const total: usize = @intCast(body_len());
        if (total > body_buf.len) {
            const msg = "body too large";
            respond(413, msg.ptr, msg.len);
            return 1;
        }
        const n = read_body(0, &body_buf, body_buf.len);
        if (std.mem.startsWith(u8, body_buf[0..n], "deny")) {
            const msg = "body rejected";
            respond(403, msg.ptr, msg.len);
            return 1;
        }
        return 0;
    }

    if (std.mem.startsWith(u8, path, "/modify/")) {
        const name = "x-checked";
        const val = "1";
        set_response_header(name.ptr, name.len, val.ptr, val.len);
        return 2; // modify
    }

    if (std.mem.startsWith(u8, path, "/api/")) {
        const key = "x-api-key";
        const klen = get_header(key.ptr, key.len, &key_buf, key_buf.len);
        if (klen == 0) {
            const body = "missing api key";
            respond(401, body.ptr, body.len);
            return 1; // reject
        }
    }

    return 0; // allow
}

/// ABI-fuzz entry: hand the host an arbitrary (ptr, len) for get_path. An
/// out-of-bounds pair must make the host trap (call fails) rather than read or
/// write outside linear memory. Returns 0 if the host accepted the pair.
export fn abi_probe(ptr: u32, len: u32) i32 {
    _ = get_path(@ptrFromInt(ptr), len);
    return 0;
}

// Phase 3 resume entry: read the host-call result and decide. "ok" -> allow,
// anything else -> reject 403.
export fn on_resume() i32 {
    const n = read_call_result(&result_buf, result_buf.len);
    if (std.mem.startsWith(u8, result_buf[0..n], "ok")) {
        return 0; // allow
    }
    const msg = "enrichment denied";
    respond(403, msg.ptr, msg.len);
    return 1; // reject
}

/// Returns get_path's raw return value (true path length) for a given output
/// buffer, so a test can verify truncation is detectable with an undersized cap.
export fn get_path_ret(out_ptr: [*]u8, out_cap: u32) i32 {
    return @intCast(get_path(out_ptr, out_cap));
}

export var spin_counter: u64 = 0;
