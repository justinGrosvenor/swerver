const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");

// ── Types ──────────────────────────────────────────────────────

pub const AuthMethod = union(enum) {
    none,
    anonymous: AnonymousConfig,
    api_key: ApiKeyConfig,
    jwt: JwtConfig,
    forward_auth: ForwardAuthConfig,
    chain: ChainConfig,
};

pub const AnonymousConfig = struct {
    subject: []const u8 = "anonymous",
};

pub const ApiKeyConfig = struct {
    keys: []const ApiKey,
    header_name: []const u8 = "X-API-Key",
    query_param: []const u8 = "api_key",
};

pub const ApiKey = struct {
    key: []const u8,
    name: []const u8,
};

pub const JwtConfig = struct {
    secret: []const u8,
    algorithm: Algorithm = .HS256,
    issuer: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    claims_to_headers: []const ClaimHeader = &.{},

    pub const Algorithm = enum { HS256 };
};

pub const ClaimHeader = struct {
    claim: []const u8,
    header: []const u8,
};

pub const ForwardAuthConfig = struct {
    url: []const u8,
    headers_forward: []const []const u8 = &.{},
    headers_upstream: []const []const u8 = &.{},
    timeout_ms: u32 = 5000,
};

pub const ChainConfig = struct {
    methods: []const AuthMethod,
};

pub const MAX_INJECTED_HEADERS = 8;

pub const InjectedHeader = struct {
    name: []const u8,
    value: []const u8,
};

pub const AuthResult = union(enum) {
    allow: AuthInfo,
    reject: response.Response,
};

pub const AuthInfo = struct {
    consumer_name: []const u8 = "",
    injected_headers: [MAX_INJECTED_HEADERS]InjectedHeader = undefined,
    injected_count: u8 = 0,

    pub fn addHeader(self: *AuthInfo, name: []const u8, value: []const u8) void {
        if (self.injected_count < MAX_INJECTED_HEADERS) {
            self.injected_headers[self.injected_count] = .{ .name = name, .value = value };
            self.injected_count += 1;
        }
    }

    pub fn headers(self: *const AuthInfo) []const InjectedHeader {
        return self.injected_headers[0..self.injected_count];
    }
};

const UNAUTHORIZED = response.Response{
    .status = 401,
    .headers = &[_]response.Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "WWW-Authenticate", .value = "Bearer" },
    },
    .body = .{ .bytes = "{\"error\":\"unauthorized\"}" },
};

const FORBIDDEN = response.Response{
    .status = 403,
    .headers = &[_]response.Header{
        .{ .name = "Content-Type", .value = "application/json" },
    },
    .body = .{ .bytes = "{\"error\":\"forbidden\"}" },
};

// ── Main evaluate ──────────────────────────────────────────────

pub fn evaluate(req: request.RequestView, auth: AuthMethod) AuthResult {
    return switch (auth) {
        .none => .{ .allow = .{} },
        .anonymous => |cfg| evaluateAnonymous(cfg),
        .api_key => |cfg| evaluateApiKey(req, cfg),
        .jwt => |cfg| evaluateJwt(req, cfg),
        .forward_auth => |cfg| evaluateForwardAuth(req, cfg),
        .chain => |cfg| evaluateChain(req, cfg),
    };
}

// ── Anonymous ──────────────────────────────────────────────────

fn evaluateAnonymous(cfg: AnonymousConfig) AuthResult {
    var info = AuthInfo{ .consumer_name = cfg.subject };
    info.addHeader("X-Consumer-Name", cfg.subject);
    return .{ .allow = info };
}

// ── Auth Chain ─────────────────────────────────────────────────

fn evaluateChain(req: request.RequestView, cfg: ChainConfig) AuthResult {
    var last_reject: response.Response = UNAUTHORIZED;
    for (cfg.methods) |method| {
        const result = evaluate(req, method);
        switch (result) {
            .allow => return result,
            .reject => |resp| last_reject = resp,
        }
    }
    return .{ .reject = last_reject };
}

// ── API Key ────────────────────────────────────────────────────

fn evaluateApiKey(req: request.RequestView, cfg: ApiKeyConfig) AuthResult {
    if (req.getHeader(cfg.header_name)) |key| {
        return matchApiKey(key, cfg.keys);
    }

    if (std.mem.indexOfScalar(u8, req.path, '?')) |q_start| {
        const query = req.path[q_start + 1 ..];
        var it = std.mem.splitScalar(u8, query, '&');
        while (it.next()) |pair| {
            if (std.mem.startsWith(u8, pair, cfg.query_param)) {
                if (pair.len > cfg.query_param.len and pair[cfg.query_param.len] == '=') {
                    return matchApiKey(pair[cfg.query_param.len + 1 ..], cfg.keys);
                }
            }
        }
    }

    return .{ .reject = UNAUTHORIZED };
}

fn matchApiKey(provided: []const u8, keys: []const ApiKey) AuthResult {
    for (keys) |entry| {
        if (constantTimeEqual(provided, entry.key)) {
            var info = AuthInfo{ .consumer_name = entry.name };
            info.addHeader("X-Consumer-Name", entry.name);
            return .{ .allow = info };
        }
    }
    return .{ .reject = FORBIDDEN };
}

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

// ── JWT ────────────────────────────────────────────────────────

fn evaluateJwt(req: request.RequestView, cfg: JwtConfig) AuthResult {
    const auth_header = req.getHeader("Authorization") orelse return .{ .reject = UNAUTHORIZED };

    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) return .{ .reject = UNAUTHORIZED };
    const token = auth_header[7..];

    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return .{ .reject = UNAUTHORIZED };
    const rest = token[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return .{ .reject = UNAUTHORIZED };

    const header_b64 = token[0..first_dot];
    const payload_b64 = rest[0..second_dot];
    const signature_b64 = rest[second_dot + 1 ..];

    const signed_part = token[0 .. first_dot + 1 + second_dot];
    if (!verifyHmacSha256(signed_part, signature_b64, cfg.secret)) {
        return .{ .reject = FORBIDDEN };
    }

    var header_buf: [256]u8 = undefined;
    const header_json = base64UrlDecode(header_b64, &header_buf) orelse return .{ .reject = UNAUTHORIZED };
    if (!validateJwtHeader(header_json)) return .{ .reject = UNAUTHORIZED };

    var payload_buf: [2048]u8 = undefined;
    const payload_json = base64UrlDecode(payload_b64, &payload_buf) orelse return .{ .reject = UNAUTHORIZED };
    if (!validateJwtPayload(payload_json, cfg)) return .{ .reject = FORBIDDEN };

    const sub = extractClaim(payload_json, "sub") orelse "";
    var info = AuthInfo{ .consumer_name = sub };

    if (sub.len > 0) {
        info.addHeader("X-Consumer-Name", sub);
    }

    for (cfg.claims_to_headers) |mapping| {
        if (extractClaim(payload_json, mapping.claim)) |value| {
            info.addHeader(mapping.header, value);
        }
    }

    return .{ .allow = info };
}

fn verifyHmacSha256(message: []const u8, signature_b64: []const u8, secret: []const u8) bool {
    var sig_buf: [32]u8 = undefined;
    const sig_bytes = base64UrlDecode(signature_b64, &sig_buf) orelse return false;
    if (sig_bytes.len != 32) return false;

    var computed: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&computed, message, secret);

    var diff: u8 = 0;
    for (computed, sig_buf) |a, b| {
        diff |= a ^ b;
    }
    return diff == 0;
}

pub fn base64UrlDecode(input: []const u8, buf: []u8) ?[]const u8 {
    var src_buf: [4096]u8 = undefined;
    if (input.len > src_buf.len) return null;
    @memcpy(src_buf[0..input.len], input);
    var src = src_buf[0..input.len];
    for (src) |*c| {
        switch (c.*) {
            '-' => c.* = '+',
            '_' => c.* = '/',
            else => {},
        }
    }

    var padded_buf: [4100]u8 = undefined;
    const pad_len = (4 - (src.len % 4)) % 4;
    if (src.len + pad_len > padded_buf.len) return null;
    @memcpy(padded_buf[0..src.len], src);
    for (padded_buf[src.len .. src.len + pad_len]) |*c| {
        c.* = '=';
    }
    const padded = padded_buf[0 .. src.len + pad_len];

    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(padded) catch return null;
    if (decoded_len > buf.len) return null;
    decoder.decode(buf[0..decoded_len], padded) catch return null;
    return buf[0..decoded_len];
}

fn validateJwtHeader(json: []const u8) bool {
    return std.mem.indexOf(u8, json, "\"HS256\"") != null;
}

fn validateJwtPayload(json: []const u8, cfg: JwtConfig) bool {
    if (extractNumericClaim(json, "exp")) |exp| {
        const now: i64 = @intCast(@divTrunc(clock_realtimeNanos(), 1_000_000_000));
        if (now > exp) return false;
    }

    if (extractNumericClaim(json, "nbf")) |nbf| {
        const now: i64 = @intCast(@divTrunc(clock_realtimeNanos(), 1_000_000_000));
        if (now < nbf) return false;
    }

    if (cfg.issuer) |expected_iss| {
        const actual_iss = extractClaim(json, "iss") orelse return false;
        if (!std.mem.eql(u8, actual_iss, expected_iss)) return false;
    }

    if (cfg.audience) |expected_aud| {
        const actual_aud = extractClaim(json, "aud") orelse return false;
        if (!std.mem.eql(u8, actual_aud, expected_aud)) return false;
    }

    return true;
}

fn clock_realtimeNanos() i128 {
    const clock_mod = @import("../runtime/clock.zig");
    return clock_mod.realtimeNanos() orelse 0;
}

pub fn extractClaim(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":\"", .{key}) catch return null;
    const start = (std.mem.indexOf(u8, json, needle) orelse return null) + needle.len;
    const end = std.mem.indexOfScalar(u8, json[start..], '"') orelse return null;
    return json[start .. start + end];
}

fn extractNumericClaim(json: []const u8, key: []const u8) ?i64 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;
    const after = (std.mem.indexOf(u8, json, needle) orelse return null) + needle.len;
    var pos = after;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) : (pos += 1) {}
    const num_start = pos;
    if (pos < json.len and json[pos] == '-') pos += 1;
    while (pos < json.len and json[pos] >= '0' and json[pos] <= '9') : (pos += 1) {}
    if (pos == num_start) return null;
    return std.fmt.parseInt(i64, json[num_start..pos], 10) catch null;
}

// ── Forward Auth ───────────────────────────────────────────────

fn evaluateForwardAuth(req: request.RequestView, cfg: ForwardAuthConfig) AuthResult {
    var url_buf: [1024]u8 = undefined;
    var host_buf: [256]u8 = undefined;
    var port: u16 = 80;

    const parsed = parseUrl(cfg.url, &host_buf, &url_buf) orelse return .{ .reject = UNAUTHORIZED };
    port = parsed.port;

    const fd = net.connectBlocking(parsed.host, port, cfg.timeout_ms) catch {
        return .{ .reject = UNAUTHORIZED };
    };
    defer clock.closeFd(fd);
    net.setSocketTimeouts(fd, cfg.timeout_ms, cfg.timeout_ms);

    var req_buf: [4096]u8 = undefined;
    var pos: usize = 0;

    const method_str = req.getMethodName();
    pos += (std.fmt.bufPrint(req_buf[pos..], "GET {s} HTTP/1.1\r\nHost: {s}\r\n", .{
        parsed.path,
        parsed.host,
    }) catch return .{ .reject = UNAUTHORIZED }).len;

    // Forward original method and path
    pos += (std.fmt.bufPrint(req_buf[pos..], "X-Original-Method: {s}\r\nX-Original-URI: {s}\r\n", .{
        method_str,
        req.path,
    }) catch return .{ .reject = UNAUTHORIZED }).len;

    // Forward configured client headers
    for (cfg.headers_forward) |hdr_name| {
        if (req.getHeader(hdr_name)) |value| {
            if (isSafeHeaderValue(value)) {
                pos += (std.fmt.bufPrint(req_buf[pos..], "{s}: {s}\r\n", .{
                    hdr_name,
                    value,
                }) catch break).len;
            }
        }
    }

    pos += (std.fmt.bufPrint(req_buf[pos..], "Connection: close\r\n\r\n", .{}) catch return .{ .reject = UNAUTHORIZED }).len;

    net.sendAll(fd, req_buf[0..pos]) catch return .{ .reject = UNAUTHORIZED };

    var resp_buf: [4096]u8 = undefined;
    var total_read: usize = 0;
    while (total_read < resp_buf.len) {
        const n = net.recvBlocking(fd, resp_buf[total_read..]) catch break;
        if (n == 0) break;
        total_read += n;
        if (std.mem.indexOf(u8, resp_buf[0..total_read], "\r\n\r\n") != null) break;
    }

    if (total_read == 0) return .{ .reject = UNAUTHORIZED };
    const resp_data = resp_buf[0..total_read];

    const status = parseResponseStatus(resp_data) orelse return .{ .reject = UNAUTHORIZED };
    if (status < 200 or status >= 300) return .{ .reject = UNAUTHORIZED };

    var info = AuthInfo{};

    for (cfg.headers_upstream) |hdr_name| {
        if (findResponseHeader(resp_data, hdr_name)) |value| {
            info.addHeader(hdr_name, value);
            if (std.ascii.eqlIgnoreCase(hdr_name, "X-Consumer-Name")) {
                info.consumer_name = value;
            }
        }
    }

    return .{ .allow = info };
}

fn parseUrl(url: []const u8, host_buf: []u8, path_buf: []u8) ?struct { host: []const u8, port: u16, path: []const u8 } {
    var remaining = url;
    var default_port: u16 = 80;

    if (std.mem.startsWith(u8, remaining, "http://")) {
        remaining = remaining[7..];
    } else if (std.mem.startsWith(u8, remaining, "https://")) {
        remaining = remaining[8..];
        default_port = 443;
    }

    const path_start = std.mem.indexOfScalar(u8, remaining, '/') orelse remaining.len;
    const host_part = remaining[0..path_start];
    const path = if (path_start < remaining.len) remaining[path_start..] else "/";

    if (path.len > path_buf.len) return null;
    @memcpy(path_buf[0..path.len], path);

    if (std.mem.indexOfScalar(u8, host_part, ':')) |colon| {
        const host = host_part[0..colon];
        const port_str = host_part[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        if (host.len > host_buf.len) return null;
        @memcpy(host_buf[0..host.len], host);
        return .{ .host = host_buf[0..host.len], .port = port, .path = path_buf[0..path.len] };
    }

    if (host_part.len > host_buf.len) return null;
    @memcpy(host_buf[0..host_part.len], host_part);
    return .{ .host = host_buf[0..host_part.len], .port = default_port, .path = path_buf[0..path.len] };
}

fn parseResponseStatus(data: []const u8) ?u16 {
    // HTTP/1.1 200 OK\r\n
    if (data.len < 12) return null;
    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return null;
    // Find space after version
    const space1 = std.mem.indexOfScalar(u8, data, ' ') orelse return null;
    if (space1 + 4 > data.len) return null;
    return std.fmt.parseInt(u16, data[space1 + 1 .. space1 + 4], 10) catch null;
}

fn findResponseHeader(data: []const u8, name: []const u8) ?[]const u8 {
    // Skip status line
    const headers_start = (std.mem.indexOf(u8, data, "\r\n") orelse return null) + 2;
    const headers_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse data.len;
    var remaining = data[headers_start..headers_end];

    while (remaining.len > 0) {
        const line_end = std.mem.indexOf(u8, remaining, "\r\n") orelse remaining.len;
        const line = remaining[0..line_end];

        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const hdr_name = std.mem.trim(u8, line[0..colon], " \t");
            if (std.ascii.eqlIgnoreCase(hdr_name, name)) {
                if (colon + 1 < line.len) {
                    return std.mem.trim(u8, line[colon + 1 ..], " \t");
                }
            }
        }

        if (line_end + 2 > remaining.len) break;
        remaining = remaining[line_end + 2 ..];
    }
    return null;
}

fn isSafeHeaderValue(value: []const u8) bool {
    for (value) |ch| {
        if (ch == '\r' or ch == '\n' or ch == 0) return false;
    }
    return true;
}

// ── Tests ──────────────────────────────────────────────────────

test "api_key: valid key in header" {
    const keys = [_]ApiKey{
        .{ .key = "secret-key-123", .name = "test-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };
    const headers = [_]request.Header{
        .{ .name = "X-API-Key", .value = "secret-key-123" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &headers,
    };
    const result = evaluate(req, .{ .api_key = cfg });
    switch (result) {
        .allow => |info| {
            try std.testing.expectEqualStrings("test-consumer", info.consumer_name);
            try std.testing.expectEqual(@as(u8, 1), info.injected_count);
            try std.testing.expectEqualStrings("X-Consumer-Name", info.headers()[0].name);
            try std.testing.expectEqualStrings("test-consumer", info.headers()[0].value);
        },
        .reject => return error.TestUnexpectedResult,
    }
}

test "api_key: wrong key returns forbidden" {
    const keys = [_]ApiKey{
        .{ .key = "secret-key-123", .name = "test-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };
    const headers = [_]request.Header{
        .{ .name = "X-API-Key", .value = "wrong-key" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &headers,
    };
    const result = evaluate(req, .{ .api_key = cfg });
    switch (result) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 403), resp.status),
    }
}

test "api_key: missing key returns unauthorized" {
    const keys = [_]ApiKey{
        .{ .key = "secret-key-123", .name = "test-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .api_key = cfg });
    switch (result) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
    }
}

test "api_key: key in query parameter" {
    const keys = [_]ApiKey{
        .{ .key = "qkey-456", .name = "query-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test?api_key=qkey-456",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .api_key = cfg });
    switch (result) {
        .allow => |info| try std.testing.expectEqualStrings("query-consumer", info.consumer_name),
        .reject => return error.TestUnexpectedResult,
    }
}

test "api_key: constant time comparison" {
    try std.testing.expect(constantTimeEqual("abc", "abc"));
    try std.testing.expect(!constantTimeEqual("abc", "abd"));
    try std.testing.expect(!constantTimeEqual("abc", "ab"));
    try std.testing.expect(!constantTimeEqual("ab", "abc"));
}

test "jwt: valid HS256 token" {
    const secret = "test-secret-key-for-hmac";
    const header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    // payload: {"sub":"user-1","iss":"test","exp":9999999999}
    const payload_b64 = "eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ";
    const signed_part = header_b64 ++ "." ++ payload_b64;
    var sig: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&sig, signed_part, secret);
    var sig_b64: [44]u8 = undefined;
    const sig_encoded = std.base64.url_safe_no_pad.Encoder.encode(&sig_b64, &sig);

    var token_buf: [512]u8 = undefined;
    const token = std.fmt.bufPrint(&token_buf, "Bearer {s}.{s}.{s}", .{ header_b64, payload_b64, sig_encoded }) catch unreachable;

    const cfg = JwtConfig{ .secret = secret, .issuer = "test" };
    const headers = [_]request.Header{
        .{ .name = "Authorization", .value = token },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &headers,
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => |info| {
            try std.testing.expectEqualStrings("user-1", info.consumer_name);
            try std.testing.expect(info.injected_count >= 1);
            try std.testing.expectEqualStrings("X-Consumer-Name", info.headers()[0].name);
        },
        .reject => return error.TestUnexpectedResult,
    }
}

test "jwt: claims_to_headers" {
    const secret = "test-secret-key-for-hmac";
    const header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    // payload: {"sub":"user-1","iss":"test","role":"admin","exp":9999999999}
    const payload_b64 = "eyJzdWIiOiJ1c2VyLTEiLCJpc3MiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ";
    const signed_part = header_b64 ++ "." ++ payload_b64;
    var sig: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&sig, signed_part, secret);
    var sig_b64: [44]u8 = undefined;
    const sig_encoded = std.base64.url_safe_no_pad.Encoder.encode(&sig_b64, &sig);

    var token_buf: [512]u8 = undefined;
    const token = std.fmt.bufPrint(&token_buf, "Bearer {s}.{s}.{s}", .{ header_b64, payload_b64, sig_encoded }) catch unreachable;

    const mappings = [_]ClaimHeader{
        .{ .claim = "role", .header = "X-User-Role" },
        .{ .claim = "sub", .header = "X-User-ID" },
    };
    const cfg = JwtConfig{
        .secret = secret,
        .issuer = "test",
        .claims_to_headers = &mappings,
    };
    const headers = [_]request.Header{
        .{ .name = "Authorization", .value = token },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &headers,
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => |info| {
            try std.testing.expectEqualStrings("user-1", info.consumer_name);
            // X-Consumer-Name + 2 claim mappings
            try std.testing.expectEqual(@as(u8, 3), info.injected_count);
            try std.testing.expectEqualStrings("X-User-Role", info.headers()[1].name);
            try std.testing.expectEqualStrings("admin", info.headers()[1].value);
            try std.testing.expectEqualStrings("X-User-ID", info.headers()[2].name);
            try std.testing.expectEqualStrings("user-1", info.headers()[2].value);
        },
        .reject => return error.TestUnexpectedResult,
    }
}

test "jwt: missing authorization header" {
    const cfg = JwtConfig{ .secret = "secret" };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
    }
}

test "jwt: invalid signature returns forbidden" {
    const cfg = JwtConfig{ .secret = "correct-secret" };
    const headers = [_]request.Header{
        .{ .name = "Authorization", .value = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalidsignaturehere" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &headers,
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 403), resp.status),
    }
}

test "base64url decode" {
    var buf: [256]u8 = undefined;
    const decoded = base64UrlDecode("SGVsbG8", &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Hello", decoded);
}

test "extract claim from json" {
    const json = "{\"sub\":\"user-1\",\"iss\":\"test-issuer\",\"aud\":\"my-app\"}";
    try std.testing.expectEqualStrings("user-1", extractClaim(json, "sub").?);
    try std.testing.expectEqualStrings("test-issuer", extractClaim(json, "iss").?);
    try std.testing.expectEqualStrings("my-app", extractClaim(json, "aud").?);
    try std.testing.expect(extractClaim(json, "nope") == null);
}

test "extract numeric claim from json" {
    const json = "{\"exp\":1700000000,\"nbf\":1699000000}";
    try std.testing.expectEqual(@as(i64, 1700000000), extractNumericClaim(json, "exp").?);
    try std.testing.expectEqual(@as(i64, 1699000000), extractNumericClaim(json, "nbf").?);
    try std.testing.expect(extractNumericClaim(json, "nope") == null);
}

test "auth none allows everything" {
    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &.{},
    };
    const result = evaluate(req, .none);
    switch (result) {
        .allow => {},
        .reject => return error.TestUnexpectedResult,
    }
}

test "anonymous: always allows with subject" {
    const req = request.RequestView{
        .method = .GET,
        .path = "/public",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .anonymous = .{} });
    switch (result) {
        .allow => |info| {
            try std.testing.expectEqualStrings("anonymous", info.consumer_name);
            try std.testing.expectEqual(@as(u8, 1), info.injected_count);
            try std.testing.expectEqualStrings("X-Consumer-Name", info.headers()[0].name);
        },
        .reject => return error.TestUnexpectedResult,
    }
}

test "anonymous: custom subject" {
    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .anonymous = .{ .subject = "guest" } });
    switch (result) {
        .allow => |info| try std.testing.expectEqualStrings("guest", info.consumer_name),
        .reject => return error.TestUnexpectedResult,
    }
}

test "chain: first allow wins" {
    const keys = [_]ApiKey{
        .{ .key = "key-1", .name = "consumer-1" },
    };
    const methods = [_]AuthMethod{
        .{ .api_key = .{ .keys = &keys } },
        .{ .anonymous = .{} },
    };
    const chain = ChainConfig{ .methods = &methods };

    // With valid API key — first method wins
    const headers = [_]request.Header{
        .{ .name = "X-API-Key", .value = "key-1" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &headers,
    };
    const result = evaluate(req, .{ .chain = chain });
    switch (result) {
        .allow => |info| try std.testing.expectEqualStrings("consumer-1", info.consumer_name),
        .reject => return error.TestUnexpectedResult,
    }
}

test "chain: falls through to anonymous" {
    const keys = [_]ApiKey{
        .{ .key = "key-1", .name = "consumer-1" },
    };
    const methods = [_]AuthMethod{
        .{ .api_key = .{ .keys = &keys } },
        .{ .anonymous = .{} },
    };
    const chain = ChainConfig{ .methods = &methods };

    // No API key — falls through to anonymous
    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .chain = chain });
    switch (result) {
        .allow => |info| try std.testing.expectEqualStrings("anonymous", info.consumer_name),
        .reject => return error.TestUnexpectedResult,
    }
}

test "chain: all reject returns last rejection" {
    const keys = [_]ApiKey{
        .{ .key = "key-1", .name = "consumer-1" },
    };
    const jwt_cfg = JwtConfig{ .secret = "secret" };
    const methods = [_]AuthMethod{
        .{ .api_key = .{ .keys = &keys } },
        .{ .jwt = jwt_cfg },
    };
    const chain = ChainConfig{ .methods = &methods };

    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .chain = chain });
    switch (result) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
    }
}

test "parseUrl: http with port" {
    var host_buf: [256]u8 = undefined;
    var path_buf: [1024]u8 = undefined;
    const parsed = parseUrl("http://auth-svc:9090/verify", &host_buf, &path_buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("auth-svc", parsed.host);
    try std.testing.expectEqual(@as(u16, 9090), parsed.port);
    try std.testing.expectEqualStrings("/verify", parsed.path);
}

test "parseUrl: http without port" {
    var host_buf: [256]u8 = undefined;
    var path_buf: [1024]u8 = undefined;
    const parsed = parseUrl("http://auth.internal/check", &host_buf, &path_buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("auth.internal", parsed.host);
    try std.testing.expectEqual(@as(u16, 80), parsed.port);
    try std.testing.expectEqualStrings("/check", parsed.path);
}

test "parseUrl: https default port" {
    var host_buf: [256]u8 = undefined;
    var path_buf: [1024]u8 = undefined;
    const parsed = parseUrl("https://auth.example.com/verify", &host_buf, &path_buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("auth.example.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 443), parsed.port);
}

test "parseResponseStatus: valid" {
    try std.testing.expectEqual(@as(u16, 200), parseResponseStatus("HTTP/1.1 200 OK\r\n").?);
    try std.testing.expectEqual(@as(u16, 401), parseResponseStatus("HTTP/1.1 401 Unauthorized\r\n").?);
    try std.testing.expectEqual(@as(u16, 403), parseResponseStatus("HTTP/1.1 403 Forbidden\r\n").?);
}

test "findResponseHeader: extracts header value" {
    const resp = "HTTP/1.1 200 OK\r\nX-User: admin\r\nX-Role: superadmin\r\n\r\n";
    try std.testing.expectEqualStrings("admin", findResponseHeader(resp, "X-User").?);
    try std.testing.expectEqualStrings("superadmin", findResponseHeader(resp, "X-Role").?);
    try std.testing.expect(findResponseHeader(resp, "X-Missing") == null);
}
