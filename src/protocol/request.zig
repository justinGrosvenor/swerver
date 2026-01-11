const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP methods (RFC 7231 + common extensions)
/// Includes OTHER for extension methods like PROPFIND, REPORT, etc.
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

pub const RequestView = struct {
    method: Method,
    /// Raw method string (useful when method == .OTHER for extension methods)
    method_raw: []const u8 = "",
    path: []const u8,
    headers: []const Header,
    body: []const u8,

    /// Get the method name as a string
    /// Returns the raw method string for known methods or extension methods
    pub fn getMethodName(self: RequestView) []const u8 {
        if (self.method == .OTHER) {
            return self.method_raw;
        }
        return self.method.toString();
    }

    /// Get header value by name (case-insensitive)
    pub fn getHeader(self: RequestView, name: []const u8) ?[]const u8 {
        for (self.headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, name)) {
                return hdr.value;
            }
        }
        return null;
    }

    /// Check if request has a specific header
    pub fn hasHeader(self: RequestView, name: []const u8) bool {
        return self.getHeader(name) != null;
    }
};
