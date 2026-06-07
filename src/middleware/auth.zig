const std = @import("std");
const build_options = @import("build_options");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("middleware.zig");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const ffi = if (build_options.enable_tls) @import("../tls/ffi.zig") else struct {};

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
    key: []const u8 = "",
    key_hash: []const u8 = "",
    name: []const u8,
};

pub const JwtConfig = struct {
    secret: []const u8,
    algorithm: Algorithm = .HS256,
    issuer: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    claims_to_headers: []const ClaimHeader = &.{},
    clock_skew_seconds: i64 = 60,

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
const MAX_HEADER_VALUE_LEN = 256;
const MAX_CONSUMER_LEN = 128;
const MAX_CHAIN_DEPTH = 4;

pub const InjectedHeader = struct {
    name: []const u8,
    _vbuf: [MAX_HEADER_VALUE_LEN]u8 = undefined,
    _vlen: u16 = 0,

    pub fn value(self: *const InjectedHeader) []const u8 {
        return self._vbuf[0..self._vlen];
    }
};

pub const AuthResult = union(enum) {
    allow: AuthInfo,
    reject: response.Response,
};

pub const AuthInfo = struct {
    _consumer_buf: [MAX_CONSUMER_LEN]u8 = undefined,
    _consumer_len: u8 = 0,
    injected_headers: [MAX_INJECTED_HEADERS]InjectedHeader = undefined,
    injected_count: u8 = 0,

    pub fn consumerName(self: *const AuthInfo) []const u8 {
        return self._consumer_buf[0..self._consumer_len];
    }

    pub fn setConsumer(self: *AuthInfo, name: []const u8) void {
        const len: u8 = @intCast(@min(name.len, MAX_CONSUMER_LEN));
        @memcpy(self._consumer_buf[0..len], name[0..len]);
        self._consumer_len = len;
    }

    pub fn addHeader(self: *AuthInfo, name: []const u8, val: []const u8) void {
        if (self.injected_count >= MAX_INJECTED_HEADERS) return;
        if (!isSafeHeaderValue(val)) return;
        const len: u16 = @intCast(@min(val.len, MAX_HEADER_VALUE_LEN));
        self.injected_headers[self.injected_count] = .{ .name = name };
        @memcpy(self.injected_headers[self.injected_count]._vbuf[0..len], val[0..len]);
        self.injected_headers[self.injected_count]._vlen = len;
        self.injected_count += 1;
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
    return evaluateWithDepth(req, auth, 0);
}

fn evaluateWithDepth(req: request.RequestView, auth: AuthMethod, depth: u8) AuthResult {
    if (depth > MAX_CHAIN_DEPTH) return .{ .reject = UNAUTHORIZED };
    return switch (auth) {
        .none => .{ .allow = .{} },
        .anonymous => |cfg| evaluateAnonymous(cfg),
        .api_key => |cfg| evaluateApiKey(req, cfg),
        .jwt => |cfg| evaluateJwt(req, cfg),
        .forward_auth => |cfg| evaluateForwardAuth(req, cfg),
        .chain => |cfg| evaluateChain(req, cfg, depth),
    };
}

// ── Anonymous ──────────────────────────────────────────────────

fn evaluateAnonymous(cfg: AnonymousConfig) AuthResult {
    var info = AuthInfo{};
    info.setConsumer(cfg.subject);
    info.addHeader("X-Consumer-Name", cfg.subject);
    return .{ .allow = info };
}

// ── Auth Chain ─────────────────────────────────────────────────

fn evaluateChain(req: request.RequestView, cfg: ChainConfig, depth: u8) AuthResult {
    var last_reject: response.Response = UNAUTHORIZED;
    for (cfg.methods) |method| {
        const result = evaluateWithDepth(req, method, depth + 1);
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
                    const raw = pair[cfg.query_param.len + 1 ..];
                    if (percentDecodeQueryValue(raw)) |decoded| {
                        return matchApiKey(decoded, cfg.keys);
                    }
                    return matchApiKey(raw, cfg.keys);
                }
            }
        }
    }

    return .{ .reject = UNAUTHORIZED };
}

threadlocal var query_decode_buf: [512]u8 = undefined;

// Returned slice aliases query_decode_buf — consume before the next call.
fn percentDecodeQueryValue(input: []const u8) ?[]const u8 {
    if (std.mem.indexOfScalar(u8, input, '%') == null and std.mem.indexOfScalar(u8, input, '+') == null) return null;
    var src: usize = 0;
    var dst: usize = 0;
    while (src < input.len) {
        if (dst >= query_decode_buf.len) return null;
        if (input[src] == '%' and src + 2 < input.len) {
            const hi = hexVal(input[src + 1]) orelse return null;
            const lo = hexVal(input[src + 2]) orelse return null;
            query_decode_buf[dst] = (hi << 4) | lo;
            src += 3;
        } else if (input[src] == '+') {
            query_decode_buf[dst] = ' ';
            src += 1;
        } else {
            query_decode_buf[dst] = input[src];
            src += 1;
        }
        dst += 1;
    }
    return query_decode_buf[0..dst];
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'A'...'F' => c - 'A' + 10,
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
}

fn matchApiKey(provided: []const u8, keys: []const ApiKey) AuthResult {
    const provided_hash = hashKeyHex(provided);
    for (keys) |entry| {
        if (entry.key_hash.len > 0) {
            if (constantTimeEqualFixed(&provided_hash, entry.key_hash)) {
                return allowKey(entry);
            }
        } else if (entry.key.len > 0) {
            if (constantTimeEqual(provided, entry.key)) {
                return allowKey(entry);
            }
        }
    }
    return .{ .reject = FORBIDDEN };
}

fn allowKey(entry: ApiKey) AuthResult {
    var info = AuthInfo{};
    info.setConsumer(entry.name);
    info.addHeader("X-Consumer-Name", entry.name);
    return .{ .allow = info };
}

const Sha256 = std.crypto.hash.sha2.Sha256;

fn hashKeyHex(key: []const u8) [64]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(key, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn constantTimeEqualFixed(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac_a: [Hmac.mac_length]u8 = undefined;
    var mac_b: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&mac_a, a, "swerver-ct-eq");
    Hmac.create(&mac_b, b, "swerver-ct-eq");
    var diff: u8 = 0;
    for (mac_a, mac_b) |x, y| {
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

    // Verify signature FIRST — before trusting any header/payload content
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

    // Build AuthInfo with owned copies — payload_buf is stack-local
    var info = AuthInfo{};

    if (extractClaim(payload_json, "sub")) |sub| {
        info.setConsumer(sub);
        info.addHeader("X-Consumer-Name", sub);
    }

    for (cfg.claims_to_headers) |mapping| {
        if (extractClaim(payload_json, mapping.claim)) |val| {
            info.addHeader(mapping.header, val);
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
    for (computed, sig_buf[0..32]) |a, b| {
        diff |= a ^ b;
    }
    return diff == 0;
}

pub fn base64UrlDecode(input: []const u8, buf: []u8) ?[]const u8 {
    var src_buf: [4096]u8 = undefined;
    if (input.len > src_buf.len) return null;
    @memcpy(src_buf[0..input.len], input);
    const src = src_buf[0..input.len];
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
    const alg = extractClaim(json, "alg") orelse return false;
    return std.mem.eql(u8, alg, "HS256");
}

fn validateJwtPayload(json: []const u8, cfg: JwtConfig) bool {
    const skew = cfg.clock_skew_seconds;
    const now_ns = clock_realtimeNanos();
    if (now_ns == 0) return false;
    const now: i64 = @intCast(@divTrunc(now_ns, 1_000_000_000));

    const exp = extractNumericClaim(json, "exp") orelse return false;
    if (now > exp + skew) return false;

    if (extractNumericClaim(json, "nbf")) |nbf| {
        if (now < nbf - skew) return false;
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
    const parsed = parseJsonValue(json) orelse return null;
    const obj = switch (parsed) {
        .object => |o| o,
        else => return null,
    };
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

fn extractNumericClaim(json: []const u8, key: []const u8) ?i64 {
    const parsed = parseJsonValue(json) orelse return null;
    const obj = switch (parsed) {
        .object => |o| o,
        else => return null,
    };
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .integer => |n| n,
        .float => |f| if (f >= -9.2e18 and f <= 9.2e18) @as(i64, @intFromFloat(f)) else null,
        else => null,
    };
}

/// Shared JSON parse helper — uses a stack-backed arena so that no heap
/// allocation occurs on the hot path. The returned Value contains string
/// slices that point directly into `json`.
fn parseJsonValue(json: []const u8) ?std.json.Value {
    var fba_buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    return std.json.parseFromSliceLeaky(std.json.Value, fba.allocator(), json, .{}) catch null;
}

// ── Forward Auth ───────────────────────────────────────────────

fn evaluateForwardAuth(req: request.RequestView, cfg: ForwardAuthConfig) AuthResult {
    var url_buf: [1024]u8 = undefined;
    var host_buf: [256]u8 = undefined;

    const parsed = parseUrl(cfg.url, &host_buf, &url_buf) orelse return .{ .reject = UNAUTHORIZED };

    const fd = net.connectBlockingValidated(parsed.host, parsed.port, cfg.timeout_ms) catch {
        return .{ .reject = UNAUTHORIZED };
    };
    defer clock.closeFd(fd);
    net.setSocketTimeouts(fd, cfg.timeout_ms, cfg.timeout_ms);

    var req_buf: [4096]u8 = undefined;
    var pos: usize = 0;

    pos += (std.fmt.bufPrint(req_buf[pos..], "GET {s} HTTP/1.1\r\nHost: {s}\r\n", .{
        parsed.path,
        parsed.host,
    }) catch return .{ .reject = UNAUTHORIZED }).len;

    // Forward original method and path (validate path against CRLF injection)
    const method_str = req.getMethodName();
    if (isSafeHeaderValue(req.path)) {
        pos += (std.fmt.bufPrint(req_buf[pos..], "X-Original-Method: {s}\r\nX-Original-URI: {s}\r\n", .{
            method_str,
            req.path,
        }) catch return .{ .reject = UNAUTHORIZED }).len;
    } else {
        pos += (std.fmt.bufPrint(req_buf[pos..], "X-Original-Method: {s}\r\n", .{
            method_str,
        }) catch return .{ .reject = UNAUTHORIZED }).len;
    }

    // Forward configured client headers
    for (cfg.headers_forward) |hdr_name| {
        if (req.getHeader(hdr_name)) |val| {
            if (isSafeHeaderValue(val)) {
                pos += (std.fmt.bufPrint(req_buf[pos..], "{s}: {s}\r\n", .{
                    hdr_name,
                    val,
                }) catch break).len;
            }
        }
    }

    pos += (std.fmt.bufPrint(req_buf[pos..], "Connection: close\r\n\r\n", .{}) catch return .{ .reject = UNAUTHORIZED }).len;

    var resp_buf: [4096]u8 = undefined;
    var total_read: usize = 0;

    if (parsed.is_tls and build_options.enable_tls) {
        const ctx = ffi.SSL_CTX_new(ffi.TLS_client_method()) orelse return .{ .reject = UNAUTHORIZED };
        defer ffi.SSL_CTX_free(ctx);
        ffi.loadDefaultVerifyPaths(ctx) catch return .{ .reject = UNAUTHORIZED };
        ffi.setVerifyPeer(ctx, true);

        const ssl = ffi.SSL_new(ctx) orelse return .{ .reject = UNAUTHORIZED };
        defer ffi.SSL_free(ssl);

        var host_z: [253:0]u8 = undefined;
        if (parsed.host.len >= host_z.len) return .{ .reject = UNAUTHORIZED };
        @memcpy(host_z[0..parsed.host.len], parsed.host);
        host_z[parsed.host.len] = 0;
        const host_sentinel: [:0]const u8 = host_z[0..parsed.host.len :0];
        if (!ffi.setHostnameVerification(ssl, host_sentinel)) return .{ .reject = UNAUTHORIZED };
        if (!ffi.setSniHostname(ssl, host_sentinel)) return .{ .reject = UNAUTHORIZED };

        if (ffi.SSL_set_fd(ssl, @intCast(fd)) != 1) return .{ .reject = UNAUTHORIZED };
        if (ffi.SSL_connect(ssl) != 1) return .{ .reject = UNAUTHORIZED };
        defer _ = ffi.SSL_shutdown(ssl);

        sslWriteAll(ssl, req_buf[0..pos]) catch return .{ .reject = UNAUTHORIZED };
        while (total_read < resp_buf.len) {
            const n = ffi.SSL_read(ssl, resp_buf[total_read..].ptr, @intCast(resp_buf.len - total_read));
            if (n <= 0) break;
            total_read += @intCast(n);
            if (std.mem.indexOf(u8, resp_buf[0..total_read], "\r\n\r\n") != null) break;
        }
    } else {
        net.sendAll(fd, req_buf[0..pos]) catch return .{ .reject = UNAUTHORIZED };
        while (total_read < resp_buf.len) {
            const n = net.recvBlocking(fd, resp_buf[total_read..]) catch break;
            if (n == 0) break;
            total_read += n;
            if (std.mem.indexOf(u8, resp_buf[0..total_read], "\r\n\r\n") != null) break;
        }
    }

    if (total_read == 0) return .{ .reject = UNAUTHORIZED };
    const resp_data = resp_buf[0..total_read];

    const status = parseResponseStatus(resp_data) orelse return .{ .reject = UNAUTHORIZED };
    if (status < 200 or status >= 300) return .{ .reject = UNAUTHORIZED };

    // Build AuthInfo — addHeader copies values into owned storage,
    // so resp_buf going out of scope is safe.
    var info = AuthInfo{};

    for (cfg.headers_upstream) |hdr_name| {
        if (findResponseHeader(resp_data, hdr_name)) |val| {
            info.addHeader(hdr_name, val);
            if (std.ascii.eqlIgnoreCase(hdr_name, "X-Consumer-Name")) {
                info.setConsumer(val);
            }
        }
    }

    return .{ .allow = info };
}

fn sslWriteAll(ssl: *ffi.SSL, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = ffi.SSL_write(ssl, data[sent..].ptr, @intCast(data.len - sent));
        if (n <= 0) return error.TlsSendFailed;
        sent += @intCast(n);
    }
}

fn parseUrl(url: []const u8, host_buf: []u8, path_buf: []u8) ?struct { host: []const u8, port: u16, path: []const u8, is_tls: bool } {
    var remaining = url;
    var default_port: u16 = 80;
    var is_tls = false;

    if (std.mem.startsWith(u8, remaining, "http://")) {
        remaining = remaining[7..];
    } else if (std.mem.startsWith(u8, remaining, "https://")) {
        remaining = remaining[8..];
        default_port = 443;
        is_tls = true;
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
        return .{ .host = host_buf[0..host.len], .port = port, .path = path_buf[0..path.len], .is_tls = is_tls };
    }

    if (host_part.len > host_buf.len) return null;
    @memcpy(host_buf[0..host_part.len], host_part);
    return .{ .host = host_buf[0..host_part.len], .port = default_port, .path = path_buf[0..path.len], .is_tls = is_tls };
}

fn parseResponseStatus(data: []const u8) ?u16 {
    if (data.len < 12) return null;
    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return null;
    const space1 = std.mem.indexOfScalar(u8, data, ' ') orelse return null;
    if (space1 + 4 > data.len) return null;
    return std.fmt.parseInt(u16, data[space1 + 1 .. space1 + 4], 10) catch null;
}

fn findResponseHeader(data: []const u8, name: []const u8) ?[]const u8 {
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

fn isSafeHeaderValue(val: []const u8) bool {
    for (val) |ch| {
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
    const hdrs = [_]request.Header{
        .{ .name = "X-API-Key", .value = "secret-key-123" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .api_key = cfg });
    switch (result) {
        .allow => |*info| {
            try std.testing.expectEqualStrings("test-consumer", info.consumerName());
            try std.testing.expectEqual(@as(u8, 1), info.injected_count);
            try std.testing.expectEqualStrings("X-Consumer-Name", info.headers()[0].name);
            try std.testing.expectEqualStrings("test-consumer", info.headers()[0].value());
        },
        .reject => return error.TestUnexpectedResult,
    }
}

test "api_key: wrong key returns forbidden" {
    const keys = [_]ApiKey{
        .{ .key = "secret-key-123", .name = "test-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };
    const hdrs = [_]request.Header{
        .{ .name = "X-API-Key", .value = "wrong-key" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
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
        .allow => |*info| try std.testing.expectEqualStrings("query-consumer", info.consumerName()),
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
    const hdrs = [_]request.Header{
        .{ .name = "Authorization", .value = token },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => |*info| {
            try std.testing.expectEqualStrings("user-1", info.consumerName());
            try std.testing.expect(info.injected_count >= 1);
            try std.testing.expectEqualStrings("X-Consumer-Name", info.headers()[0].name);
            try std.testing.expectEqualStrings("user-1", info.headers()[0].value());
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
    const hdrs = [_]request.Header{
        .{ .name = "Authorization", .value = token },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => |*info| {
            try std.testing.expectEqualStrings("user-1", info.consumerName());
            // X-Consumer-Name + 2 claim mappings
            try std.testing.expectEqual(@as(u8, 3), info.injected_count);
            try std.testing.expectEqualStrings("X-User-Role", info.headers()[1].name);
            try std.testing.expectEqualStrings("admin", info.headers()[1].value());
            try std.testing.expectEqualStrings("X-User-ID", info.headers()[2].name);
            try std.testing.expectEqualStrings("user-1", info.headers()[2].value());
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
    const hdrs = [_]request.Header{
        .{ .name = "Authorization", .value = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalidsignaturehere" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 403), resp.status),
    }
}

test "jwt: crlf in claim value rejected" {
    const secret = "test-secret-key-for-hmac";
    const header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    // payload: {"sub":"evil\r\nX-Admin: true","exp":9999999999}
    // The \r\n is literal bytes 0x0d 0x0a in the JSON value
    const payload_b64 = "eyJzdWIiOiJldmlsXHJcblgtQWRtaW46IHRydWUiLCJleHAiOjk5OTk5OTk5OTl9";
    const signed_part = header_b64 ++ "." ++ payload_b64;
    var sig: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&sig, signed_part, secret);
    var sig_b64: [44]u8 = undefined;
    const sig_encoded = std.base64.url_safe_no_pad.Encoder.encode(&sig_b64, &sig);

    var token_buf: [512]u8 = undefined;
    const token = std.fmt.bufPrint(&token_buf, "Bearer {s}.{s}.{s}", .{ header_b64, payload_b64, sig_encoded }) catch unreachable;

    const mappings = [_]ClaimHeader{
        .{ .claim = "sub", .header = "X-User" },
    };
    const cfg = JwtConfig{
        .secret = secret,
        .claims_to_headers = &mappings,
    };
    const hdrs = [_]request.Header{
        .{ .name = "Authorization", .value = token },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .jwt = cfg });
    switch (result) {
        .allow => |*info| {
            // If the claim contained literal \r\n bytes, addHeader would reject it.
            // The test payload has escaped \r\n (JSON literal backslash-r backslash-n),
            // which our naive parser returns as "evil\\r\\nX-Admin: true" — no real
            // CRLF bytes. But the CRLF check in addHeader would catch real 0x0d/0x0a.
            // The key property: injected_count should be 0 or values should be safe.
            for (info.headers()) |*hdr| {
                for (hdr.value()) |ch| {
                    try std.testing.expect(ch != '\r' and ch != '\n');
                }
            }
        },
        .reject => {},
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

test "extract claim: immune to substring injection" {
    // Audit issue #27: a crafted payload with an embedded key in a prior
    // value must not trick the parser into returning the wrong claim.
    const json =
        \\{"fake":"\"sub\":\"admin\"","sub":"user"}
    ;
    try std.testing.expectEqualStrings("user", extractClaim(json, "sub").?);
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
        .allow => |*info| {
            try std.testing.expectEqualStrings("anonymous", info.consumerName());
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
        .allow => |*info| try std.testing.expectEqualStrings("guest", info.consumerName()),
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

    const hdrs = [_]request.Header{
        .{ .name = "X-API-Key", .value = "key-1" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .chain = chain });
    switch (result) {
        .allow => |*info| try std.testing.expectEqualStrings("consumer-1", info.consumerName()),
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

    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .chain = chain });
    switch (result) {
        .allow => |*info| try std.testing.expectEqualStrings("anonymous", info.consumerName()),
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

test "chain: depth limit rejects" {
    // Build a chain nested MAX_CHAIN_DEPTH + 1 levels deep
    const inner = AuthMethod{ .anonymous = .{} };
    const l3 = [_]AuthMethod{inner};
    const l2 = [_]AuthMethod{.{ .chain = .{ .methods = &l3 } }};
    const l1 = [_]AuthMethod{.{ .chain = .{ .methods = &l2 } }};
    const l0 = [_]AuthMethod{.{ .chain = .{ .methods = &l1 } }};
    const outer = [_]AuthMethod{.{ .chain = .{ .methods = &l0 } }};

    const req = request.RequestView{
        .method = .GET,
        .path = "/",
        .headers = &.{},
    };
    const result = evaluate(req, .{ .chain = .{ .methods = &outer } });
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

test "addHeader: rejects CRLF values" {
    var info = AuthInfo{};
    info.addHeader("X-Test", "safe-value");
    try std.testing.expectEqual(@as(u8, 1), info.injected_count);

    info.addHeader("X-Evil", "evil\r\nX-Injected: true");
    try std.testing.expectEqual(@as(u8, 1), info.injected_count); // still 1, rejected

    info.addHeader("X-Evil2", "evil\nonly-lf");
    try std.testing.expectEqual(@as(u8, 1), info.injected_count); // still 1

    info.addHeader("X-Null", "has\x00null");
    try std.testing.expectEqual(@as(u8, 1), info.injected_count); // still 1
}

test "jwt: validateJwtHeader requires alg field" {
    // Previously this was a substring match; now it uses extractClaim
    try std.testing.expect(validateJwtHeader("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
    try std.testing.expect(!validateJwtHeader("{\"alg\":\"none\",\"note\":\"HS256\"}"));
    try std.testing.expect(!validateJwtHeader("{\"alg\":\"RS256\"}"));
    try std.testing.expect(!validateJwtHeader("{\"typ\":\"JWT\"}"));
}

test "api_key: hash-based auth" {
    const hash = hashKeyHex("secret-key-123");
    const keys = [_]ApiKey{
        .{ .key_hash = &hash, .name = "hash-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };
    const hdrs = [_]request.Header{
        .{ .name = "X-API-Key", .value = "secret-key-123" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .api_key = cfg });
    switch (result) {
        .allow => |*info| try std.testing.expectEqualStrings("hash-consumer", info.consumerName()),
        .reject => return error.TestUnexpectedResult,
    }
}

test "api_key: hash-based auth rejects wrong key" {
    const hash = hashKeyHex("secret-key-123");
    const keys = [_]ApiKey{
        .{ .key_hash = &hash, .name = "hash-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };
    const hdrs = [_]request.Header{
        .{ .name = "X-API-Key", .value = "wrong-key" },
    };
    const req = request.RequestView{
        .method = .GET,
        .path = "/api/test",
        .headers = &hdrs,
    };
    const result = evaluate(req, .{ .api_key = cfg });
    switch (result) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 403), resp.status),
    }
}

test "api_key: mixed plaintext and hash keys" {
    const hash = hashKeyHex("hash-key-456");
    const keys = [_]ApiKey{
        .{ .key = "plain-key-123", .name = "plain-consumer" },
        .{ .key_hash = &hash, .name = "hash-consumer" },
    };
    const cfg = ApiKeyConfig{ .keys = &keys };

    // plaintext key works
    const hdrs1 = [_]request.Header{
        .{ .name = "X-API-Key", .value = "plain-key-123" },
    };
    const req1 = request.RequestView{ .method = .GET, .path = "/test", .headers = &hdrs1 };
    switch (evaluate(req1, .{ .api_key = cfg })) {
        .allow => |*info| try std.testing.expectEqualStrings("plain-consumer", info.consumerName()),
        .reject => return error.TestUnexpectedResult,
    }

    // hash key works
    const hdrs2 = [_]request.Header{
        .{ .name = "X-API-Key", .value = "hash-key-456" },
    };
    const req2 = request.RequestView{ .method = .GET, .path = "/test", .headers = &hdrs2 };
    switch (evaluate(req2, .{ .api_key = cfg })) {
        .allow => |*info| try std.testing.expectEqualStrings("hash-consumer", info.consumerName()),
        .reject => return error.TestUnexpectedResult,
    }
}

test "hashKeyHex produces consistent SHA-256 hex" {
    const hash = hashKeyHex("test");
    // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    try std.testing.expectEqualStrings("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", &hash);
}
