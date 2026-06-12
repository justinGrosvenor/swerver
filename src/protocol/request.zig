const std = @import("std");
const buffer_pool = @import("../runtime/buffer_pool.zig");

/// A single HTTP header. Both `name` and `value` are borrowed slices.
///
/// On the request side, these are slices into the receive buffer —
/// valid for the duration of the handler call and reclaimed before
/// the next request on the same worker. On the response side, they're
/// typically string literals from the handler's return statement.
///
/// The same struct is used for both requests and responses. Field
/// interpretation is per RFC 9110: header names are case-insensitive
/// (use `RequestView.getHeader` for lookups), header values are
/// opaque ASCII-ish bytes per field-specific rules.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP methods (RFC 9110 §9). Includes `.OTHER` for extension methods
/// like `PROPFIND`, `REPORT`, `MKCOL` — when `.OTHER` is returned,
/// `RequestView.method_raw` holds the actual method bytes.
pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
    /// Extension method - use method_raw field in RequestView for actual name
    OTHER,

    pub fn fromString(s: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "GET", .GET },
            .{ "HEAD", .HEAD },
            .{ "POST", .POST },
            .{ "PUT", .PUT },
            .{ "DELETE", .DELETE },
            .{ "CONNECT", .CONNECT },
            .{ "OPTIONS", .OPTIONS },
            .{ "TRACE", .TRACE },
            .{ "PATCH", .PATCH },
        });
        return map.get(s);
    }

    /// Parse method string, returning OTHER for valid extension methods
    pub fn fromStringExtended(s: []const u8) ?Method {
        if (fromString(s)) |m| {
            return m;
        }
        // Accept any valid token as an extension method
        if (isValidToken(s)) {
            return .OTHER;
        }
        return null;
    }

    pub fn toString(self: Method) []const u8 {
        return @tagName(self);
    }

    /// Check if a string is a valid HTTP token (RFC 7230)
    fn isValidToken(s: []const u8) bool {
        if (s.len == 0) return false;
        for (s) |c| {
            if (!isTokenChar(c)) return false;
        }
        return true;
    }

    fn isTokenChar(c: u8) bool {
        return switch (c) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            '0'...'9', 'A'...'Z', 'a'...'z' => true,
            else => false,
        };
    }
};

pub const RequestBody = union(enum) {
    slice: []const u8,
    scattered: ScatteredBuffers,
    length_only: usize,

    pub const ScatteredBuffers = struct {
        handles: []const buffer_pool.BufferHandle,
        last_buf_len: usize,
        total_len: usize,
        buffer_size: usize,
    };

    pub fn len(self: RequestBody) usize {
        return switch (self) {
            .slice => |s| s.len,
            .scattered => |b| b.total_len,
            .length_only => |n| n,
        };
    }

    pub fn sliceOrNull(self: RequestBody) ?[]const u8 {
        return switch (self) {
            .slice => |s| s,
            .scattered, .length_only => null,
        };
    }

    pub fn copyTo(self: RequestBody, dst: []u8) ?[]const u8 {
        const total = self.len();
        if (total > dst.len) return null;
        switch (self) {
            .slice => |s| {
                @memcpy(dst[0..s.len], s);
                return dst[0..s.len];
            },
            .scattered => |b| {
                var off: usize = 0;
                for (b.handles, 0..) |handle, i| {
                    const chunk_len = if (i == b.handles.len - 1) b.last_buf_len else b.buffer_size;
                    @memcpy(dst[off .. off + chunk_len], handle.bytes[0..chunk_len]);
                    off += chunk_len;
                }
                return dst[0..total];
            },
            .length_only => return null,
        }
    }

    pub const empty: RequestBody = .{ .slice = "" };
};

pub const RequestView = struct {
    method: Method,
    method_raw: []const u8 = "",
    path: []const u8,
    headers: []const Header,
    body: RequestBody = .{ .slice = "" },

    pub fn getMethodName(self: RequestView) []const u8 {
        if (self.method == .OTHER) {
            return self.method_raw;
        }
        return self.method.toString();
    }

    pub fn getHeader(self: RequestView, name: []const u8) ?[]const u8 {
        for (self.headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, name)) {
                return hdr.value;
            }
        }
        return null;
    }

    pub fn hasHeader(self: RequestView, name: []const u8) bool {
        return self.getHeader(name) != null;
    }
};

test "getHeader is case-insensitive and returns null for missing headers" {
    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "X-Custom", .value = "v1" },
    };
    const view = RequestView{
        .method = .GET,
        .path = "/",
        .headers = &headers,
    };

    // Exact case match.
    try std.testing.expectEqualStrings("application/json", view.getHeader("Content-Type").?);
    // Differing case still matches (RFC 9110 §5.1).
    try std.testing.expectEqualStrings("application/json", view.getHeader("content-type").?);
    try std.testing.expectEqualStrings("application/json", view.getHeader("CONTENT-TYPE").?);
    try std.testing.expectEqualStrings("v1", view.getHeader("x-custom").?);

    // Missing header returns null.
    try std.testing.expect(view.getHeader("Authorization") == null);
    try std.testing.expect(!view.hasHeader("Authorization"));
    try std.testing.expect(view.hasHeader("content-type"));
}

test "Method.fromString parses standard methods and rejects unknown" {
    try std.testing.expectEqual(Method.GET, Method.fromString("GET").?);
    try std.testing.expectEqual(Method.POST, Method.fromString("POST").?);
    try std.testing.expectEqual(Method.PUT, Method.fromString("PUT").?);
    try std.testing.expectEqual(Method.DELETE, Method.fromString("DELETE").?);

    // fromString only knows the registered set; case matters and extensions are unknown.
    try std.testing.expect(Method.fromString("PROPFIND") == null);
    try std.testing.expect(Method.fromString("get") == null);
    try std.testing.expect(Method.fromString("") == null);
}

test "Method.fromStringExtended maps extension tokens to OTHER and rejects invalid tokens" {
    // Known methods still resolve to their concrete tag.
    try std.testing.expectEqual(Method.GET, Method.fromStringExtended("GET").?);
    try std.testing.expectEqual(Method.PATCH, Method.fromStringExtended("PATCH").?);

    // Valid extension tokens become OTHER.
    try std.testing.expectEqual(Method.OTHER, Method.fromStringExtended("PROPFIND").?);
    try std.testing.expectEqual(Method.OTHER, Method.fromStringExtended("MKCOL").?);

    // Non-token characters (space, control) are rejected outright.
    try std.testing.expect(Method.fromStringExtended("BAD METHOD") == null);
    try std.testing.expect(Method.fromStringExtended("") == null);
    try std.testing.expect(Method.fromStringExtended("GET\r") == null);
}

test "getMethodName returns tag name for known methods and raw bytes for OTHER" {
    const known = RequestView{ .method = .DELETE, .path = "/", .headers = &.{} };
    try std.testing.expectEqualStrings("DELETE", known.getMethodName());

    const ext = RequestView{
        .method = .OTHER,
        .method_raw = "PROPFIND",
        .path = "/",
        .headers = &.{},
    };
    try std.testing.expectEqualStrings("PROPFIND", ext.getMethodName());
}

test "RequestBody slice exposes bytes via sliceOrNull, len and copyTo" {
    const body = RequestBody{ .slice = "hello body" };

    try std.testing.expectEqual(@as(usize, 10), body.len());
    try std.testing.expectEqualStrings("hello body", body.sliceOrNull().?);

    var dst: [16]u8 = undefined;
    const copied = body.copyTo(&dst).?;
    try std.testing.expectEqualStrings("hello body", copied);
    // Returned slice is trimmed to the body length, not the buffer length.
    try std.testing.expectEqual(@as(usize, 10), copied.len);
}

test "RequestBody.copyTo returns null when destination is too small" {
    const body = RequestBody{ .slice = "0123456789" };
    var too_small: [4]u8 = undefined;
    try std.testing.expect(body.copyTo(&too_small) == null);

    // Exact-fit destination succeeds.
    var exact: [10]u8 = undefined;
    try std.testing.expectEqualStrings("0123456789", body.copyTo(&exact).?);
}

test "RequestBody length_only and scattered have no contiguous slice" {
    const lo = RequestBody{ .length_only = 1234 };
    try std.testing.expectEqual(@as(usize, 1234), lo.len());
    try std.testing.expect(lo.sliceOrNull() == null);
    var dst: [2048]u8 = undefined;
    // length_only carries no bytes, so copyTo cannot materialize them.
    try std.testing.expect(lo.copyTo(&dst) == null);

    // empty helper is a zero-length contiguous slice.
    try std.testing.expectEqual(@as(usize, 0), RequestBody.empty.len());
    try std.testing.expectEqualStrings("", RequestBody.empty.sliceOrNull().?);
}
