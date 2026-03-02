const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");

/// Security Headers Middleware
///
/// Injects security headers into responses:
/// - HSTS (HTTP Strict Transport Security)
/// - CSP (Content Security Policy)
/// - X-Content-Type-Options
/// - X-Frame-Options
/// - Referrer-Policy
/// - CORS headers

/// Security configuration
pub const Config = struct {
    /// Enable HSTS header
    hsts_enabled: bool = true,
    /// HSTS max-age in seconds (default: 1 year)
    hsts_max_age: u32 = 31536000,
    /// Include subdomains in HSTS
    hsts_include_subdomains: bool = true,
    /// HSTS preload flag
    hsts_preload: bool = false,

    /// Content Security Policy
    csp_enabled: bool = true,
    /// CSP directive (default: strict)
    csp_policy: []const u8 = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",

    /// X-Content-Type-Options
    content_type_options: bool = true,

    /// X-Frame-Options (DENY, SAMEORIGIN, or null to disable)
    frame_options: ?[]const u8 = "DENY",

    /// Referrer-Policy
    referrer_policy: ?[]const u8 = "strict-origin-when-cross-origin",

    /// CORS configuration
    cors_enabled: bool = false,
    cors_allow_origin: []const u8 = "*",
    cors_allow_methods: []const u8 = "GET, POST, PUT, DELETE, OPTIONS",
    cors_allow_headers: []const u8 = "Content-Type, Authorization",
    cors_max_age: u32 = 86400,
    cors_allow_credentials: bool = false,

    /// Only add HSTS on TLS connections
    hsts_tls_only: bool = true,
};

/// Global security config
var config: Config = .{};

/// Initialize with configuration.
/// Logs a warning if CORS is misconfigured (credentials + wildcard origin).
pub fn init(cfg: Config) void {
    if (cfg.cors_enabled and cfg.cors_allow_credentials and std.mem.eql(u8, cfg.cors_allow_origin, "*")) {
        std.log.warn("CORS misconfiguration: credentials with wildcard origin is invalid per spec. " ++
            "Browsers will reject credentialed requests. Set a specific origin instead of '*'.", .{});
    }
    config = cfg;
}

/// Pre-built header values (to avoid runtime formatting)
const HeaderCache = struct {
    hsts: [128]u8 = undefined,
    hsts_len: usize = 0,

    fn buildHsts(self: *HeaderCache, cfg: *const Config) void {
        var fbs = std.io.fixedBufferStream(&self.hsts);
        const writer = fbs.writer();

        writer.print("max-age={d}", .{cfg.hsts_max_age}) catch return;
        if (cfg.hsts_include_subdomains) {
            writer.writeAll("; includeSubDomains") catch return;
        }
        if (cfg.hsts_preload) {
            writer.writeAll("; preload") catch return;
        }

        self.hsts_len = fbs.pos;
    }

    fn getHsts(self: *const HeaderCache) []const u8 {
        return self.hsts[0..self.hsts_len];
    }
};

var header_cache: HeaderCache = .{};

/// Per-thread header buffer for security headers.
/// SAFETY: The returned slice from evaluate() must be consumed (copied into the
/// response write buffer) before the next call to evaluate() on the same thread.
/// This is guaranteed by the request processing pipeline which serializes
/// middleware evaluation and response writing per-thread.
threadlocal var tls_headers: [8]response.Header = undefined;

/// Build header cache (call during init)
pub fn buildCache() void {
    header_cache.buildHsts(&config);
}

/// Security headers middleware - adds headers to response
pub fn evaluate(ctx: *middleware.Context, req: request.RequestView) middleware.Decision {
    // Check for missing Host header first (security requirement)
    var has_host = false;
    for (req.headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "host") or
            std.ascii.eqlIgnoreCase(hdr.name, ":authority"))
        {
            has_host = true;
            break;
        }
    }

    if (!has_host) {
        // RFC 7230 Section 5.4: Host header required for HTTP/1.1
        // HTTP/2 and HTTP/3 require :authority pseudo-header
        return .{ .reject = badRequestResponse() };
    }

    // Handle CORS preflight — only respond to actual preflight requests
    // (must have Access-Control-Request-Method header per CORS spec)
    if (config.cors_enabled and req.method == .OPTIONS) {
        for (req.headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, "access-control-request-method")) {
                return .{ .reject = corsPreflightResponse() };
            }
        }
    }

    // Build response headers to add (use threadlocal buffer)
    var count: usize = 0;

    // HSTS (only on TLS if configured)
    if (config.hsts_enabled and (!config.hsts_tls_only or ctx.is_tls)) {
        if (header_cache.hsts_len == 0) {
            header_cache.buildHsts(&config);
        }
        tls_headers[count] = .{
            .name = "Strict-Transport-Security",
            .value = header_cache.getHsts(),
        };
        count += 1;
    }

    // CSP
    if (config.csp_enabled) {
        tls_headers[count] = .{
            .name = "Content-Security-Policy",
            .value = config.csp_policy,
        };
        count += 1;
    }

    // X-Content-Type-Options
    if (config.content_type_options) {
        tls_headers[count] = .{
            .name = "X-Content-Type-Options",
            .value = "nosniff",
        };
        count += 1;
    }

    // X-Frame-Options
    if (config.frame_options) |fo| {
        tls_headers[count] = .{
            .name = "X-Frame-Options",
            .value = fo,
        };
        count += 1;
    }

    // Referrer-Policy
    if (config.referrer_policy) |rp| {
        tls_headers[count] = .{
            .name = "Referrer-Policy",
            .value = rp,
        };
        count += 1;
    }

    // CORS headers
    if (config.cors_enabled) {
        tls_headers[count] = .{
            .name = "Access-Control-Allow-Origin",
            .value = config.cors_allow_origin,
        };
        count += 1;

        // Add credentials header only when origin is not wildcard (per CORS spec)
        if (config.cors_allow_credentials and !std.mem.eql(u8, config.cors_allow_origin, "*")) {
            tls_headers[count] = .{
                .name = "Access-Control-Allow-Credentials",
                .value = "true",
            };
            count += 1;
        }
    }

    if (count > 0) {
        return .{ .modify = .{
            .response_headers = tls_headers[0..count],
            .continue_chain = true,
        } };
    }

    return .allow;
}

fn corsPreflightResponse() response.Response {
    if (config.cors_allow_credentials and !std.mem.eql(u8, config.cors_allow_origin, "*")) {
        return .{
            .status = 204,
            .headers = &[_]response.Header{
                .{ .name = "Access-Control-Allow-Origin", .value = config.cors_allow_origin },
                .{ .name = "Access-Control-Allow-Methods", .value = config.cors_allow_methods },
                .{ .name = "Access-Control-Allow-Headers", .value = config.cors_allow_headers },
                .{ .name = "Access-Control-Allow-Credentials", .value = "true" },
                .{ .name = "Access-Control-Max-Age", .value = "86400" },
                .{ .name = "Content-Length", .value = "0" },
            },
            .body = .none,
        };
    }
    return .{
        .status = 204,
        .headers = &[_]response.Header{
            .{ .name = "Access-Control-Allow-Origin", .value = config.cors_allow_origin },
            .{ .name = "Access-Control-Allow-Methods", .value = config.cors_allow_methods },
            .{ .name = "Access-Control-Allow-Headers", .value = config.cors_allow_headers },
            .{ .name = "Access-Control-Max-Age", .value = "86400" },
            .{ .name = "Content-Length", .value = "0" },
        },
        .body = .none,
    };
}

fn badRequestResponse() response.Response {
    return .{
        .status = 400,
        .headers = &[_]response.Header{
            .{ .name = "Content-Length", .value = "0" },
        },
        .body = .none,
    };
}

// Tests
test "security headers added on TLS" {
    config = .{
        .hsts_enabled = true,
        .hsts_tls_only = true,
        .csp_enabled = true,
        .content_type_options = true,
    };
    header_cache.buildHsts(&config);

    var ctx = middleware.Context{
        .is_tls = true,
    };

    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &[_]request.Header{
            .{ .name = "Host", .value = "example.com" },
        },
    };

    const decision = evaluate(&ctx, req);
    switch (decision) {
        .modify => |mod| {
            try std.testing.expect(mod.response_headers.len >= 3);
        },
        else => try std.testing.expect(false),
    }
}

test "HSTS not added on non-TLS when tls_only" {
    config = .{
        .hsts_enabled = true,
        .hsts_tls_only = true,
        .csp_enabled = false,
        .content_type_options = false,
        .frame_options = null,
        .referrer_policy = null,
    };

    var ctx = middleware.Context{
        .is_tls = false,
    };

    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &[_]request.Header{
            .{ .name = "Host", .value = "example.com" },
        },
    };

    const decision = evaluate(&ctx, req);
    try std.testing.expect(decision == .allow);
}

test "CORS preflight handled" {
    config = .{
        .cors_enabled = true,
        .cors_allow_origin = "https://example.com",
    };

    var ctx = middleware.Context{};

    const req = request.RequestView{
        .method = .OPTIONS,
        .path = "/api/data",
        .headers = &.{},
    };

    const decision = evaluate(&ctx, req);
    switch (decision) {
        .reject => |resp| {
            try std.testing.expectEqual(@as(u16, 204), resp.status);
        },
        else => try std.testing.expect(false),
    }
}
