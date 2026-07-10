//! Phase 0 spike filter, compiled to wasm32-freestanding.
//!
//! Representative of a real Tier-1 edge filter: an auth/routing pre-hook that
//! inspects request metadata and returns a Decision code. The SAME compiled
//! .wasm bytes are run by BOTH candidate runtimes (zware, wasm3) and compared
//! against an identical native-Zig implementation, so the comparison is
//! apples-to-apples.
//!
//! ABI (custom, minimal, matches design 10.0 sketch):
//!   host imports (env):
//!     get_path(out_ptr, out_cap) -> len
//!     get_header(name_ptr, name_len, out_ptr, out_cap) -> len   (0 = absent)
//!   exports:
//!     on_request() -> i32   0=allow 1=reject
//!     spin()               infinite loop (fuel/interrupt test target)
//!     memory               (linear memory, exported for host access)

const std = @import("std");

extern "env" fn get_path(out_ptr: [*]u8, out_cap: u32) u32;
extern "env" fn get_header(name_ptr: [*]const u8, name_len: u32, out_ptr: [*]u8, out_cap: u32) u32;

// Scratch buffers live in the module's own linear memory.
var path_buf: [1024]u8 = undefined;
var hdr_buf: [256]u8 = undefined;

const API_KEY_NAME = "x-api-key";

/// Trivial-but-representative filter:
///   - requests under /api/ require a non-empty x-api-key header -> else reject
///   - everything else is allowed
/// This touches the path AND one header by name, which is the realistic
/// "read what you need on demand" cost the ABI is designed around.
export fn on_request() i32 {
    const path_len = get_path(&path_buf, path_buf.len);
    const path = path_buf[0..path_len];

    if (!std.mem.startsWith(u8, path, "/api/")) {
        return 0; // allow
    }

    const key_len = get_header(API_KEY_NAME, API_KEY_NAME.len, &hdr_buf, hdr_buf.len);
    if (key_len == 0) {
        return 1; // reject: missing api key
    }
    return 0; // allow
}

/// Runaway-loop target. Used by the resource-bounding test to prove whether a
/// runtime can interrupt a guest that never returns and never calls an import.
/// `volatile`-ish via the exported global so the optimizer cannot delete it.
export var spin_counter: u64 = 0;

export fn spin() void {
    while (true) {
        spin_counter +%= 1;
    }
}
