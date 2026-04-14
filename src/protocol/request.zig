const std = @import("std");

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

/// A parsed HTTP request, with all field slices borrowed from the
/// connection's receive buffer.
///
/// This type is uniform across HTTP/1.1, HTTP/2, and HTTP/3:
///   - **HTTP/1.1**: the parser slices headers and body out of the
///     raw request bytes in place.
///   - **HTTP/2**: HPACK decodes into a per-worker scratch buffer;
///     the decoded slices then live there for the duration of the
///     handler call.
///   - **HTTP/3**: QPACK decodes into a per-Stack scratch buffer;
///     single-DATA-frame bodies are a direct slice into the
///     decrypted packet payload (zero-copy).
///
/// All fields are stable across the handler's synchronous execution
/// — protocol layer guarantees the underlying buffers aren't reused
/// until the handler returns. Stashing `path` / `headers` / `body`
/// slices beyond the handler call is a use-after-reuse bug.
///
/// `body` is `[]const u8` — always non-null; an empty body is
/// represented as an empty slice, not `null`. `method_raw` is
/// non-empty only when `method == .OTHER` (extension methods like
/// `PROPFIND`).
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
