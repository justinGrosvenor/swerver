const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");

pub const AuthMethod = union(enum) {
    none,
    api_key: ApiKeyConfig,
    jwt: JwtConfig,
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

pub const AuthResult = union(enum) {
    allow: AuthInfo,
    reject: response.Response,
};

pub const AuthInfo = struct {
    consumer_name: []const u8 = "",
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

pub fn evaluate(req: request.RequestView, auth: AuthMethod) AuthResult {
    return switch (auth) {
        .none => .{ .allow = .{} },
        .api_key => |cfg| evaluateApiKey(req, cfg),
        .jwt => |cfg| evaluateJwt(req, cfg),
    };
}

// ── API Key ─────────────────────────────────────────────────────

fn evaluateApiKey(req: request.RequestView, cfg: ApiKeyConfig) AuthResult {
    // Check header first
    if (req.getHeader(cfg.header_name)) |key| {
        return matchApiKey(key, cfg.keys);
    }

    // Fall back to query parameter
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
            return .{ .allow = .{ .consumer_name = entry.name } };
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

// ── JWT ─────────────────────────────────────────────────────────

fn evaluateJwt(req: request.RequestView, cfg: JwtConfig) AuthResult {
    const auth_header = req.getHeader("Authorization") orelse return .{ .reject = UNAUTHORIZED };

    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) return .{ .reject = UNAUTHORIZED };
    const token = auth_header[7..];

    // Split header.payload.signature
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return .{ .reject = UNAUTHORIZED };
    const rest = token[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return .{ .reject = UNAUTHORIZED };

    const header_b64 = token[0..first_dot];
    const payload_b64 = rest[0..second_dot];
    const signature_b64 = rest[second_dot + 1 ..];

    // Verify signature
    const signed_part = token[0 .. first_dot + 1 + second_dot];
    if (!verifyHmacSha256(signed_part, signature_b64, cfg.secret)) {
        return .{ .reject = FORBIDDEN };
    }

    // Decode and validate header
    var header_buf: [256]u8 = undefined;
    const header_json = base64UrlDecode(header_b64, &header_buf) orelse return .{ .reject = UNAUTHORIZED };
    if (!validateJwtHeader(header_json)) return .{ .reject = UNAUTHORIZED };

    // Decode and validate payload
    var payload_buf: [2048]u8 = undefined;
    const payload_json = base64UrlDecode(payload_b64, &payload_buf) orelse return .{ .reject = UNAUTHORIZED };
    if (!validateJwtPayload(payload_json, cfg)) return .{ .reject = FORBIDDEN };

    return .{ .allow = .{ .consumer_name = extractClaim(payload_json, "sub") orelse "" } };
}

fn verifyHmacSha256(message: []const u8, signature_b64: []const u8, secret: []const u8) bool {
    // Decode expected signature
    var sig_buf: [32]u8 = undefined;
    const sig_bytes = base64UrlDecode(signature_b64, &sig_buf) orelse return false;
    if (sig_bytes.len != 32) return false;

    // Compute HMAC-SHA256
    var computed: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&computed, message, secret);

    // Constant-time compare
    var diff: u8 = 0;
    for (computed, sig_buf) |a, b| {
        diff |= a ^ b;
    }
    return diff == 0;
}

fn base64UrlDecode(input: []const u8, buf: []u8) ?[]const u8 {
    // Replace URL-safe chars with standard base64 chars in a stack copy
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

    // Add padding
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
    // Minimal validation: must contain "alg":"HS256"
    return std.mem.indexOf(u8, json, "\"HS256\"") != null;
}

fn validateJwtPayload(json: []const u8, cfg: JwtConfig) bool {
    // Check expiration
    if (extractNumericClaim(json, "exp")) |exp| {
        const now: i64 = @intCast(@divTrunc(clock_realtimeNanos(), 1_000_000_000));
        if (now > exp) return false;
    }

    // Check not-before
    if (extractNumericClaim(json, "nbf")) |nbf| {
        const now: i64 = @intCast(@divTrunc(clock_realtimeNanos(), 1_000_000_000));
        if (now < nbf) return false;
    }

    // Check issuer
    if (cfg.issuer) |expected_iss| {
        const actual_iss = extractClaim(json, "iss") orelse return false;
        if (!std.mem.eql(u8, actual_iss, expected_iss)) return false;
    }

    // Check audience
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

fn extractClaim(json: []const u8, key: []const u8) ?[]const u8 {
    // Find "key":"value" in JSON — lightweight extraction without full parser.
    // Handles the common case; nested objects or escaped quotes in values
    // could confuse it, but JWT payloads are flat by convention.
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
    // Skip whitespace
    var pos = after;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) : (pos += 1) {}
    // Read digits (possibly with leading minus)
    const num_start = pos;
    if (pos < json.len and json[pos] == '-') pos += 1;
    while (pos < json.len and json[pos] >= '0' and json[pos] <= '9') : (pos += 1) {}
    if (pos == num_start) return null;
    return std.fmt.parseInt(i64, json[num_start..pos], 10) catch null;
}

// ── Tests ───────────────────────────────────────────────────────

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
        .allow => |info| try std.testing.expectEqualStrings("test-consumer", info.consumer_name),
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
    // Build a valid JWT: header.payload.signature
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
        .allow => |info| try std.testing.expectEqualStrings("user-1", info.consumer_name),
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
    // Standard test vector: "Hello" = "SGVsbG8" in base64url (no padding)
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
