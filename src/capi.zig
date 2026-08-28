//! C ABI for embedding swerver in another process (e.g. a Bun/Node runtime via
//! FFI). This is the root source of `libswerver` (`zig build lib`).
//!
//! Stage 0: toolchain proof only. The real embedding API (init from a config
//! JSON, register FFI routes that park and hand off to a host callback, run the
//! event loop on a background thread, respond from the host thread via a
//! cross-thread wake) is built on top of this once the internals are wired.
//!
//! Convention: every exported symbol is prefixed `swerver_`, takes and returns
//! only C-ABI types (integers, pointers, lengths), and never surfaces a Zig
//! error across the boundary — errors become negative return codes or null.

const std = @import("std");
const builtin = @import("builtin");

/// ABI version of this library. Bumped when the exported surface changes so a
/// host can check compatibility after dlopen. Unrelated to the swerver release
/// version.
export fn swerver_abi_version() u32 {
    return 1;
}

/// Human-readable build identifier. Returns a NUL-terminated static string;
/// the caller must not free it. Lets a host confirm which library it loaded.
export fn swerver_build_id() [*:0]const u8 {
    return "swerver-capi/0 (" ++ @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.cpu.arch) ++ ")";
}
