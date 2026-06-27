//! Shared request model used by all three filter implementations (native,
//! zware, wasm3). A single global "current request" pointer stands in for what
//! would be the per-connection Context/RequestView in the real server. The
//! benchmark is single-threaded, matching swerver's per-worker reactor, so a
//! global is faithful to the real access pattern (host calls reach into the
//! live request, they do not get a copy).

const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    path: []const u8,
    headers: []const Header,

    /// Case-insensitive header lookup. This is the exact cost a host `get_header`
    /// call pays, and the native baseline pays the identical cost, so it cancels
    /// out of the comparison and only the runtime-crossing overhead remains.
    pub fn getHeader(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }
};

/// The live request the host functions read. Set before each invocation.
pub var current: *const Request = undefined;
