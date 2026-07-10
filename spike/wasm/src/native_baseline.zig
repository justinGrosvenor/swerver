//! The native-Zig equivalent of the wasm filter. This is the baseline the whole
//! go/no-go decision is measured against: it does byte-for-byte the same work
//! (path prefix check + one header lookup + Decision), but as a direct function
//! call with zero runtime boundary. The ns/op gap between this and a wasm
//! runtime IS the cost of putting user code on the hot path.

const request = @import("request.zig");

pub const Decision = enum(i32) {
    allow = 0,
    reject = 1,
};

/// Mirror of filter.zig's on_request, in native Zig.
pub fn onRequest() Decision {
    const req = request.current;

    if (req.path.len < 5 or !startsWith(req.path, "/api/")) {
        return .allow;
    }

    const key = req.getHeader("x-api-key");
    if (key == null or key.?.len == 0) {
        return .reject;
    }
    return .allow;
}

inline fn startsWith(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    for (needle, 0..) |c, i| {
        if (haystack[i] != c) return false;
    }
    return true;
}
