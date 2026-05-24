const std = @import("std");
const build_options = @import("build_options");
const response = @import("../response/response.zig");
const request = @import("../protocol/request.zig");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const json_write = @import("../runtime/json_write.zig");
const ffi = if (build_options.enable_tls) @import("../tls/ffi.zig") else struct {};
const x402_crypto = if (build_options.enable_x402_crypto) @import("x402_crypto.zig") else struct {};

pub const Decision = union(enum) {
    allow,
    reject: response.Response,
};

pub const RoutePaymentConfig = struct {
    require_payment: bool = false,
    payment_required_b64: []const u8 = "",
    payment_required_json: []const u8 = "",
    price: []const u8 = "",
    asset: []const u8 = "",
    network: []const u8 = "",
    pay_to: []const u8 = "",
    scheme: []const u8 = "exact",
    max_timeout_seconds: u32 = 60,
};

pub const Policy = RoutePaymentConfig;

pub const PaymentRequired = struct {
    x402Version: u8 = 2,
    @"error": []const u8,
    resource: Resource,
    accepts: []const Accept,
};

pub const Resource = struct {
    url: []const u8,
    description: []const u8,
    mimeType: []const u8,
};

pub const Accept = struct {
    scheme: []const u8,
    network: []const u8,
    amount: []const u8,
    asset: []const u8,
    payTo: []const u8,
    maxTimeoutSeconds: u32,
    extra: ?Extra = null,
};

pub const Extra = struct {
    name: []const u8,
    version: []const u8,
};

/// Evaluate x402 payment policy for a request.
///
/// Validates payment header structure: base64-encoded JSON with "signature"
/// and "payload" fields. Cryptographic signature verification (EIP-191
/// ecrecover with secp256k1) requires linking a secp256k1 library.
pub fn evaluate(req: request.RequestView, policy: Policy) Decision {
    if (!policy.require_payment) return .allow;

    // Check ALL payment headers, not just the first one. A request
    // may contain both X-Payment and Payment-Signature headers (or
    // duplicates). If ANY of them validates, allow the request.
    // Only reject after exhausting all candidates.
    var found_any = false;
    for (req.headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "x-payment") or
            std.ascii.eqlIgnoreCase(hdr.name, "payment-signature"))
        {
            if (hdr.value.len > 0) {
                found_any = true;
                if (validatePaymentHeader(hdr.value)) {
                    return .allow;
                }
                // Invalid — keep searching for a valid one
            }
        }
    }

    return .{ .reject = rejectWith(.missing_header, policy).resp };
}

/// Validate payment header structure: must be valid base64 containing JSON
/// with "signature" and "payload" fields. This is a structural check only —
/// the real gate is cryptographic signature verification, which runs after
/// this returns true. Keeps the header contract honest: a blob that claims
/// to be an x402 payment payload has to at least parse as one.
fn validatePaymentHeader(header_value: []const u8) bool {
    if (header_value.len == 0 or header_value.len > 11000) return false;

    // Decode base64 into a fixed stack buffer.
    const max_decoded = std.base64.standard.Decoder.calcSizeUpperBound(header_value.len) catch return false;
    if (max_decoded > 8192) return false;
    var decode_buf: [8192]u8 = undefined;
    const actual_len = std.base64.standard.Decoder.calcSizeForSlice(header_value) catch return false;
    std.base64.standard.Decoder.decode(decode_buf[0..max_decoded], header_value) catch return false;
    const decoded = decode_buf[0..actual_len];

    // Parse into a minimal typed shape. `ignore_unknown_fields = true` lets
    // the payload carry scheme/network/chainId/etc. without us having to
    // mirror every x402 field here — we only care that the two mandatory
    // fields are present and syntactically well-formed JSON.
    const MinimalPayment = struct {
        signature: []const u8,
        payload: std.json.Value,
    };

    // Stack-backed fixed buffer allocator. No `ArenaAllocator` wrapper
    // because the FBA already owns all the memory and `parseFromSliceLeaky`
    // is fine leaking into it — the whole buffer goes out of scope on return.
    var arena_buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);

    _ = std.json.parseFromSliceLeaky(
        MinimalPayment,
        fba.allocator(),
        decoded,
        .{ .ignore_unknown_fields = true },
    ) catch return false;

    return true;
}

pub const PaymentRequiredEncoded = struct {
    b64: []u8,
    json: []u8,
};

pub fn buildPaymentRequired(allocator: std.mem.Allocator, required: PaymentRequired) !PaymentRequiredEncoded {
    var json_list = std.ArrayList(u8).empty;
    var writer = std.Io.Writer.Allocating.fromArrayList(allocator, &json_list);
    defer writer.deinit();
    try std.json.Stringify.value(required, .{}, &writer.writer);
    json_list = writer.toArrayList();

    const json_copy = try allocator.alloc(u8, json_list.items.len);
    @memcpy(json_copy, json_list.items);

    const encoded_len = std.base64.standard.Encoder.calcSize(json_list.items.len);
    const b64 = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(b64, json_list.items);
    return .{ .b64 = b64, .json = json_copy };
}

pub fn demoPaymentRequiredB64(allocator: std.mem.Allocator, url: []const u8) !PaymentRequiredEncoded {
    const payload = PaymentRequired{
        .@"error" = "PAYMENT-SIGNATURE header is required",
        .resource = .{
            .url = url,
            .description = "Example protected resource",
            .mimeType = "text/plain",
        },
        .accepts = &[_]Accept{
            .{
                .scheme = "exact",
                .network = "eip155:8453",
                .amount = "10000",
                .asset = "0x0000000000000000000000000000000000000000",
                .payTo = "0x0000000000000000000000000000000000000000",
                .maxTimeoutSeconds = 60,
                .extra = .{
                    .name = "DEMO",
                    .version = "2",
                },
            },
        },
    };
    return buildPaymentRequired(allocator, payload);
}

pub fn configFromProxyRoute(proxy_x402: anytype, allocator: std.mem.Allocator, url: []const u8) !RoutePaymentConfig {
    const payload = PaymentRequired{
        .@"error" = "Payment required",
        .resource = .{ .url = url, .description = "Protected resource", .mimeType = "application/json" },
        .accepts = &[_]Accept{.{
            .scheme = proxy_x402.scheme,
            .network = proxy_x402.network,
            .amount = proxy_x402.price,
            .asset = proxy_x402.asset,
            .payTo = proxy_x402.pay_to,
            .maxTimeoutSeconds = proxy_x402.max_timeout_seconds,
        }},
    };
    const encoded = try buildPaymentRequired(allocator, payload);
    return .{
        .require_payment = true,
        .payment_required_b64 = encoded.b64,
        .payment_required_json = encoded.json,
        .price = proxy_x402.price,
        .asset = proxy_x402.asset,
        .network = proxy_x402.network,
        .pay_to = proxy_x402.pay_to,
        .scheme = proxy_x402.scheme,
        .max_timeout_seconds = proxy_x402.max_timeout_seconds,
    };
}

var reject_402_headers: [2]response.Header = undefined;

fn rejectWith(reason: RejectReason, policy: RoutePaymentConfig) RejectInfo {
    const status: u16 = switch (reason) {
        .missing_header, .facilitator_rejected => 402,
        .malformed_header, .invalid_signature => 400,
        .facilitator_error => 500,
    };
    if (status == 402 and policy.payment_required_json.len > 0) {
        reject_402_headers[0] = .{ .name = "Content-Type", .value = "application/json" };
        reject_402_headers[1] = .{ .name = "X-Payment-Required", .value = policy.payment_required_b64 };
        return .{
            .reason = reason,
            .resp = .{
                .status = 402,
                .headers = &reject_402_headers,
                .body = .{ .bytes = policy.payment_required_json },
            },
        };
    }
    const body: []const u8 = switch (reason) {
        .missing_header => "Payment required",
        .malformed_header => "Invalid payment header",
        .invalid_signature => "Invalid payment signature",
        .facilitator_rejected => "Payment verification failed",
        .facilitator_error => "Payment processing error",
    };
    return .{
        .reason = reason,
        .resp = .{
            .status = status,
            .headers = &.{},
            .body = .{ .bytes = body },
        },
    };
}

// ============================================================
// Facilitator Client
// ============================================================

pub const FacilitatorConfig = struct {
    host: []const u8 = "",
    port: u16 = 443,
    path_prefix: []const u8 = "",
    use_tls: bool = true,
    timeout_ms: u32 = 5_000,
};

pub const VerifyResult = struct {
    is_valid: bool,
    payer: []const u8 = "",
    invalid_reason: []const u8 = "",
};

pub const SettleResult = struct {
    success: bool,
    transaction: []const u8 = "",
    network: []const u8 = "",
    payer: []const u8 = "",
    error_reason: []const u8 = "",
    receipt_b64: []const u8 = "",
};

pub const PaymentContext = struct {
    payment_header: []const u8,
    needs_settlement: bool,
};

pub const RejectReason = enum {
    missing_header,
    malformed_header,
    invalid_signature,
    facilitator_rejected,
    facilitator_error,
};

pub const EvaluateResult = union(enum) {
    allow: PaymentContext,
    reject: RejectInfo,
};

pub const RejectInfo = struct {
    resp: response.Response,
    reason: RejectReason,
};

pub fn parseFacilitatorUrl(url: []const u8) ?FacilitatorConfig {
    var config = FacilitatorConfig{};

    var rest = url;
    if (std.mem.startsWith(u8, rest, "https://")) {
        config.use_tls = true;
        config.port = 443;
        rest = rest["https://".len..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        config.use_tls = false;
        config.port = 80;
        rest = rest["http://".len..];
    } else {
        return null;
    }

    const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..path_start];
    config.path_prefix = if (path_start < rest.len) rest[path_start..] else "";

    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
        config.host = host_port[0..colon];
        config.port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null;
    } else {
        config.host = host_port;
    }

    if (config.host.len == 0) return null;
    return config;
}

pub fn evaluateWithFacilitator(
    req: request.RequestView,
    policy: RoutePaymentConfig,
    facilitator: ?FacilitatorConfig,
) EvaluateResult {
    if (!policy.require_payment) return .{ .allow = .{ .payment_header = "", .needs_settlement = false } };

    const payment_header = findValidPaymentHeader(req) orelse {
        // Distinguish missing header from malformed: check if ANY payment header exists
        const has_any = for (req.headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, "x-payment") or
                std.ascii.eqlIgnoreCase(hdr.name, "payment-signature"))
            {
                if (hdr.value.len > 0) break true;
            }
        } else false;
        return .{
            .reject = rejectWith(
                if (has_any) .malformed_header else .missing_header,
                policy,
            ),
        };
    };

    // Local signature verification: fast-reject invalid signatures before
    // hitting the facilitator.
    if (build_options.enable_x402_crypto and policy.pay_to.len > 0) {
        const decoded = decodePaymentHeader(payment_header) orelse
            return .{ .reject = rejectWith(.malformed_header, policy) };
        if (!x402_crypto.verifyPaymentSignature(decoded, policy.pay_to)) {
            return .{ .reject = rejectWith(.invalid_signature, policy) };
        }
    }

    if (facilitator) |fac| {
        const result = facilitatorVerify(fac, payment_header, &policy);
        if (!result.is_valid) {
            return .{ .reject = rejectWith(.facilitator_rejected, policy) };
        }
        return .{ .allow = .{ .payment_header = payment_header, .needs_settlement = true } };
    }

    return .{ .allow = .{ .payment_header = payment_header, .needs_settlement = false } };
}

fn findValidPaymentHeader(req: request.RequestView) ?[]const u8 {
    for (req.headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "x-payment") or
            std.ascii.eqlIgnoreCase(hdr.name, "payment-signature"))
        {
            if (hdr.value.len > 0 and validatePaymentHeader(hdr.value)) {
                return hdr.value;
            }
        }
    }
    return null;
}

fn decodePaymentHeader(header_value: []const u8) ?[]const u8 {
    const S = struct {
        threadlocal var buf: [8192]u8 = undefined;
    };
    const max_decoded = std.base64.standard.Decoder.calcSizeUpperBound(header_value.len) catch return null;
    if (max_decoded > S.buf.len) return null;
    const actual_len = std.base64.standard.Decoder.calcSizeForSlice(header_value) catch return null;
    std.base64.standard.Decoder.decode(S.buf[0..max_decoded], header_value) catch return null;
    return S.buf[0..actual_len];
}

fn facilitatorVerify(config: FacilitatorConfig, payment_header: []const u8, policy: *const RoutePaymentConfig) VerifyResult {
    var req_buf: [4096]u8 = undefined;
    const req_len = buildVerifyRequestJson(&req_buf, payment_header, policy) catch
        return .{ .is_valid = false, .invalid_reason = "request build failed" };

    var http_buf: [8192]u8 = undefined;
    const http_len = buildFacilitatorPost(&http_buf, config, "/verify", req_buf[0..req_len]) catch
        return .{ .is_valid = false, .invalid_reason = "http build failed" };

    var resp_buf: [4096]u8 = undefined;
    const resp_len = facilitatorRoundTrip(config, http_buf[0..http_len], &resp_buf) catch
        return .{ .is_valid = false, .invalid_reason = "facilitator unreachable" };

    return parseVerifyResponse(resp_buf[0..resp_len]);
}

/// Settle a payment with the facilitator. For `upto` scheme, pass the actual
/// charge amount in `charge_amount` — the facilitator will settle that amount
/// instead of the max authorized. For `exact` scheme, pass "" or the configured price.
pub fn facilitatorSettle(
    config: FacilitatorConfig,
    payment_header: []const u8,
    policy: *const RoutePaymentConfig,
    charge_amount: []const u8,
) SettleResult {
    var req_buf: [4096]u8 = undefined;
    const req_len = buildSettleRequestJson(&req_buf, payment_header, policy, charge_amount) catch
        return .{ .success = false, .error_reason = "request build failed" };

    var http_buf: [8192]u8 = undefined;
    const http_len = buildFacilitatorPost(&http_buf, config, "/settle", req_buf[0..req_len]) catch
        return .{ .success = false, .error_reason = "http build failed" };

    var resp_buf: [4096]u8 = undefined;
    const resp_len = facilitatorRoundTrip(config, http_buf[0..http_len], &resp_buf) catch
        return .{ .success = false, .error_reason = "facilitator unreachable" };

    var result = parseSettleResponse(resp_buf[0..resp_len]);
    if (result.success) {
        result.receipt_b64 = buildReceiptB64(&result) orelse "";
    }
    return result;
}

threadlocal var receipt_buf: [1024]u8 = undefined;
threadlocal var receipt_b64_buf: [2048]u8 = undefined;

fn buildReceiptB64(settle: *const SettleResult) ?[]const u8 {
    const json_len = std.fmt.bufPrint(&receipt_buf,
        \\{{"success":true,"transaction":"{s}","network":"{s}","payer":"{s}"}}
    , .{ settle.transaction, settle.network, settle.payer }) catch return null;
    const b64_len = std.base64.standard.Encoder.calcSize(json_len.len);
    if (b64_len > receipt_b64_buf.len) return null;
    _ = std.base64.standard.Encoder.encode(receipt_b64_buf[0..b64_len], json_len);
    return receipt_b64_buf[0..b64_len];
}

fn facilitatorRoundTrip(config: FacilitatorConfig, req_bytes: []const u8, resp_buf: []u8) !usize {
    const fd = net.connectBlockingValidated(config.host, config.port, config.timeout_ms) catch
        return error.ConnectFailed;
    defer clock.closeFd(fd);

    net.setSocketTimeouts(fd, config.timeout_ms, config.timeout_ms);

    if (config.use_tls and build_options.enable_tls) {
        return facilitatorRoundTripTls(fd, config.host, req_bytes, resp_buf);
    }

    net.sendAll(fd, req_bytes) catch return error.SendFailed;

    var total: usize = 0;
    while (total < resp_buf.len) {
        const n = net.recvBlocking(fd, resp_buf[total..]) catch break;
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n") != null) {
            if (findContentLength(resp_buf[0..total])) |expected| {
                const header_end = std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n").? + 4;
                const body_received = total - header_end;
                if (body_received >= expected) break;
            } else break;
        }
    }
    return total;
}

fn facilitatorRoundTripTls(fd: std.posix.fd_t, host: []const u8, req_bytes: []const u8, resp_buf: []u8) !usize {
    if (!build_options.enable_tls) return error.TlsNotEnabled;

    const ctx = ffi.SSL_CTX_new(ffi.TLS_client_method()) orelse return error.TlsInitFailed;
    defer ffi.SSL_CTX_free(ctx);
    ffi.loadDefaultVerifyPaths(ctx) catch return error.TlsInitFailed;
    ffi.setVerifyPeer(ctx, true);

    const ssl = ffi.SSL_new(ctx) orelse return error.TlsInitFailed;
    defer ffi.SSL_free(ssl);

    var host_z: [253:0]u8 = undefined;
    if (host.len >= host_z.len) return error.TlsInitFailed;
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;
    const host_sentinel: [:0]const u8 = host_z[0..host.len :0];
    if (!ffi.setHostnameVerification(ssl, host_sentinel)) return error.TlsInitFailed;
    if (!ffi.setSniHostname(ssl, host_sentinel)) return error.TlsInitFailed;

    if (ffi.SSL_set_fd(ssl, @intCast(fd)) != 1) return error.TlsInitFailed;
    if (ffi.SSL_connect(ssl) != 1) return error.TlsHandshakeFailed;
    defer _ = ffi.SSL_shutdown(ssl);

    var sent: usize = 0;
    while (sent < req_bytes.len) {
        const n = ffi.SSL_write(ssl, req_bytes[sent..].ptr, @intCast(req_bytes.len - sent));
        if (n <= 0) return error.TlsSendFailed;
        sent += @intCast(n);
    }

    var total: usize = 0;
    while (total < resp_buf.len) {
        const n = ffi.SSL_read(ssl, resp_buf[total..].ptr, @intCast(resp_buf.len - total));
        if (n <= 0) break;
        total += @intCast(n);
        if (std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n") != null) {
            if (findContentLength(resp_buf[0..total])) |expected| {
                const header_end = std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n").? + 4;
                const body_received = total - header_end;
                if (body_received >= expected) break;
            } else break;
        }
    }
    return total;
}

fn findContentLength(http_response: []const u8) ?usize {
    const header_end = std.mem.indexOf(u8, http_response, "\r\n\r\n") orelse return null;
    const headers = http_response[0..header_end];
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len > 16 and std.ascii.eqlIgnoreCase(line[0..16], "content-length: ")) {
            return std.fmt.parseInt(usize, std.mem.trim(u8, line[16..], " \t"), 10) catch null;
        }
    }
    return null;
}

fn buildSettleRequestJson(buf: []u8, payment_header: []const u8, policy: *const RoutePaymentConfig, charge_amount: []const u8) !usize {
    const amount = if (std.mem.eql(u8, policy.scheme, "upto") and charge_amount.len > 0)
        charge_amount
    else
        policy.price;
    if (std.mem.eql(u8, policy.scheme, "upto") and charge_amount.len > 0) {
        if (parseU64(charge_amount)) |charge| {
            if (parseU64(policy.price)) |max| {
                if (charge > max) return error.ChargeExceedsMax;
            }
        }
    }
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"x402Version\":2,\"paymentPayload\":\"");
    off += jsonEscape(buf[off..], payment_header);
    off += copyInto(buf[off..], "\",\"paymentRequirements\":{\"scheme\":\"");
    off += jsonEscape(buf[off..], policy.scheme);
    off += copyInto(buf[off..], "\",\"network\":\"");
    off += jsonEscape(buf[off..], policy.network);
    off += copyInto(buf[off..], "\",\"maxAmountRequired\":\"");
    off += jsonEscape(buf[off..], policy.price);
    off += copyInto(buf[off..], "\",\"resource\":{\"url\":\"\",\"description\":\"\",\"mimeType\":\"\"},\"asset\":\"");
    off += jsonEscape(buf[off..], policy.asset);
    off += copyInto(buf[off..], "\",\"payTo\":\"");
    off += jsonEscape(buf[off..], policy.pay_to);
    const timeout = std.fmt.bufPrint(buf[off..], "\",\"maxTimeoutSeconds\":{d}}},\"settleAmount\":\"", .{policy.max_timeout_seconds}) catch return error.BufferTooSmall;
    off += timeout.len;
    off += jsonEscape(buf[off..], amount);
    off += copyInto(buf[off..], "\"}");
    return off;
}

fn buildVerifyRequestJson(buf: []u8, payment_header: []const u8, policy: *const RoutePaymentConfig) !usize {
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"x402Version\":2,\"paymentPayload\":\"");
    off += jsonEscape(buf[off..], payment_header);
    off += copyInto(buf[off..], "\",\"paymentRequirements\":{\"scheme\":\"");
    off += jsonEscape(buf[off..], policy.scheme);
    off += copyInto(buf[off..], "\",\"network\":\"");
    off += jsonEscape(buf[off..], policy.network);
    off += copyInto(buf[off..], "\",\"maxAmountRequired\":\"");
    off += jsonEscape(buf[off..], policy.price);
    off += copyInto(buf[off..], "\",\"resource\":{\"url\":\"\",\"description\":\"\",\"mimeType\":\"\"},\"asset\":\"");
    off += jsonEscape(buf[off..], policy.asset);
    off += copyInto(buf[off..], "\",\"payTo\":\"");
    off += jsonEscape(buf[off..], policy.pay_to);
    const timeout = std.fmt.bufPrint(buf[off..], "\",\"maxTimeoutSeconds\":{d}}}}}", .{policy.max_timeout_seconds}) catch return error.BufferTooSmall;
    off += timeout.len;
    return off;
}

fn buildFacilitatorPost(buf: []u8, config: FacilitatorConfig, endpoint: []const u8, body: []const u8) !usize {
    const result = std.fmt.bufPrint(buf,
        "POST {s}{s} HTTP/1.1\r\nHost: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ config.path_prefix, endpoint, config.host, body.len, body },
    ) catch return error.BufferTooSmall;
    return result.len;
}

fn parseVerifyResponse(http_response: []const u8) VerifyResult {
    const body = extractResponseBody(http_response) orelse
        return .{ .is_valid = false, .invalid_reason = "malformed response" };
    const status = extractStatusCode(http_response) orelse
        return .{ .is_valid = false, .invalid_reason = "malformed status" };
    if (status < 200 or status >= 300)
        return .{ .is_valid = false, .invalid_reason = "facilitator rejected" };

    var arena_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    const Resp = struct { isValid: bool = false, payer: []const u8 = "", invalidReason: []const u8 = "" };
    const parsed = std.json.parseFromSliceLeaky(Resp, fba.allocator(), body, .{ .ignore_unknown_fields = true }) catch
        return .{ .is_valid = false, .invalid_reason = "invalid json" };
    return .{ .is_valid = parsed.isValid, .payer = parsed.payer, .invalid_reason = parsed.invalidReason };
}

fn parseSettleResponse(http_response: []const u8) SettleResult {
    const body = extractResponseBody(http_response) orelse
        return .{ .success = false, .error_reason = "malformed response" };
    const status = extractStatusCode(http_response) orelse
        return .{ .success = false, .error_reason = "malformed status" };
    if (status < 200 or status >= 300)
        return .{ .success = false, .error_reason = "settlement failed" };

    var arena_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    const Resp = struct {
        success: bool = false,
        transaction: []const u8 = "",
        network: []const u8 = "",
        payer: []const u8 = "",
        errorReason: []const u8 = "",
    };
    const parsed = std.json.parseFromSliceLeaky(Resp, fba.allocator(), body, .{ .ignore_unknown_fields = true }) catch
        return .{ .success = false, .error_reason = "invalid json" };
    return .{
        .success = parsed.success,
        .transaction = parsed.transaction,
        .network = parsed.network,
        .payer = parsed.payer,
        .error_reason = parsed.errorReason,
    };
}

fn extractResponseBody(http_response: []const u8) ?[]const u8 {
    const sep = std.mem.indexOf(u8, http_response, "\r\n\r\n") orelse return null;
    return http_response[sep + 4 ..];
}

fn extractStatusCode(http_response: []const u8) ?u16 {
    if (http_response.len < 12) return null;
    if (!std.mem.startsWith(u8, http_response, "HTTP/1.")) return null;
    return std.fmt.parseInt(u16, http_response[9..12], 10) catch null;
}

fn copyInto(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

fn jsonEscape(dst: []u8, src: []const u8) usize {
    const escaped = json_write.writeEscaped(dst, src) catch return 0;
    return escaped.len;
}

fn parseU64(s: []const u8) ?u64 {
    return std.fmt.parseInt(u64, s, 10) catch null;
}

// ============================================================
// Tests
// ============================================================

fn makeRequest(path: []const u8, headers: []const request.Header) request.RequestView {
    return .{
        .method = .GET,
        .method_raw = "",
        .path = path,
        .headers = headers,
        .body = .{ .slice = "" },
    };
}

test "x402: disabled policy allows all requests" {
    const policy = Policy{ .require_payment = false, .payment_required_b64 = "" };
    const req = makeRequest("/", &.{});
    try std.testing.expectEqual(Decision.allow, evaluate(req, policy));
}

test "x402: enabled policy rejects requests without payment header" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const req = makeRequest("/protected", &.{});
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| {
            try std.testing.expectEqual(@as(u16, 402), resp.status);
        },
    }
}

test "x402: accepts valid X-Payment header" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    // Build a base64-encoded JSON with "signature" and "payload" fields
    const json = "{\"signature\":\"0xabc\",\"payload\":{\"amount\":\"100\"}}";
    var b64_buf: [256]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], json);

    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = b64_buf[0..b64_len] },
    };
    const req = makeRequest("/protected", &headers);
    try std.testing.expectEqual(Decision.allow, evaluate(req, policy));
}

test "x402: accepts Payment-Signature header (case insensitive)" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const json = "{\"signature\":\"0xdef\",\"payload\":{}}";
    var b64_buf: [256]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], json);

    const headers = [_]request.Header{
        .{ .name = "payment-signature", .value = b64_buf[0..b64_len] },
    };
    const req = makeRequest("/", &headers);
    try std.testing.expectEqual(Decision.allow, evaluate(req, policy));
}

test "x402: rejects empty payment header" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = "" },
    };
    const req = makeRequest("/", &headers);
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| {
            try std.testing.expectEqual(@as(u16, 402), resp.status);
        },
    }
}

test "x402: rejects invalid base64" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = "not-valid-base64!!!" },
    };
    const req = makeRequest("/", &headers);
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => {},
    }
}

test "x402: rejects base64 JSON missing signature field" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const json = "{\"payload\":{\"amount\":\"100\"}}"; // no "signature"
    var b64_buf: [256]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], json);

    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = b64_buf[0..b64_len] },
    };
    const req = makeRequest("/", &headers);
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => {},
    }
}

test "x402: rejects base64 JSON missing payload field" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const json = "{\"signature\":\"0xabc\"}"; // no "payload"
    var b64_buf: [256]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], json);

    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = b64_buf[0..b64_len] },
    };
    const req = makeRequest("/", &headers);
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => {},
    }
}

// Regression test for the substring-defeat attack the old validator
// was vulnerable to. The previous implementation did
//     std.mem.indexOf(u8, decoded, "\"signature\"")
// to check for presence of the key, which false-positived on payloads
// that happened to contain the literal bytes inside a string value.
// The typed parser rejects it because the top-level object has neither
// a `signature` nor a `payload` field — they're just characters inside
// an unrelated `msg` string.
test "x402: rejects JSON containing magic substrings inside string body" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const json = "{\"msg\":\"need \\\"signature\\\" and \\\"payload\\\" fields\"}";
    var b64_buf: [256]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], json);

    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = b64_buf[0..b64_len] },
    };
    const req = makeRequest("/", &headers);
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => {},
    }
}

test "x402: rejects oversized payment header (>11KB)" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const big_value = "A" ** 12000;
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = big_value },
    };
    const req = makeRequest("/", &headers);
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => {},
    }
}

test "x402: 402 response has correct status and body" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const req = makeRequest("/", &.{});
    switch (evaluate(req, policy)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| {
            try std.testing.expectEqual(@as(u16, 402), resp.status);
            // Body indicates payment required
            const body = switch (resp.body) {
                .bytes => |b| b,
                else => "",
            };
            try std.testing.expectEqualStrings("Payment required", body);
        },
    }
}

test "x402: accepts valid header even if earlier header is invalid" {
    const policy = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const valid_json = "{\"signature\":\"0xabc\",\"payload\":{}}";
    var b64_buf: [256]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(valid_json.len);
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], valid_json);

    // First header is garbage, second is valid — should still allow
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = "not-valid-at-all" },
        .{ .name = "Payment-Signature", .value = b64_buf[0..b64_len] },
    };
    const req = makeRequest("/", &headers);
    try std.testing.expectEqual(Decision.allow, evaluate(req, policy));
}

test "x402: validatePaymentHeader structural checks" {
    // Valid: has both fields
    try std.testing.expect(validatePaymentHeader(encodeJson("{\"signature\":\"x\",\"payload\":{}}")));
    // Missing signature
    try std.testing.expect(!validatePaymentHeader(encodeJson("{\"payload\":{}}")));
    // Missing payload
    try std.testing.expect(!validatePaymentHeader(encodeJson("{\"signature\":\"x\"}")));
    // Empty
    try std.testing.expect(!validatePaymentHeader(""));
    // Not base64
    try std.testing.expect(!validatePaymentHeader("!!!"));
}

test "x402: RoutePaymentConfig defaults to free" {
    const config = RoutePaymentConfig{};
    try std.testing.expect(!config.require_payment);
    try std.testing.expectEqualStrings("", config.payment_required_b64);
    try std.testing.expectEqualStrings("exact", config.scheme);
    try std.testing.expectEqual(@as(u32, 60), config.max_timeout_seconds);
}

test "x402: per-route config overrides global in evaluate" {
    const global = Policy{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const route_free = RoutePaymentConfig{};
    const req = makeRequest("/", &.{});

    // Global requires payment, route is free — effective policy depends on caller logic.
    // evaluate() with the free route config should allow.
    try std.testing.expectEqual(Decision.allow, evaluate(req, route_free));

    // evaluate() with the global config should reject (no payment header).
    switch (evaluate(req, global)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 402), resp.status),
    }
}

test "x402: per-route paid config rejects without header" {
    const route_paid = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
        .price = "10000",
        .asset = "0xUSDC",
        .network = "eip155:8453",
        .pay_to = "0xRecipient",
    };
    const req = makeRequest("/premium", &.{});
    switch (evaluate(req, route_paid)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |resp| try std.testing.expectEqual(@as(u16, 402), resp.status),
    }
}

test "x402: parseFacilitatorUrl parses https" {
    const config = parseFacilitatorUrl("https://x402.org/facilitator") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("x402.org", config.host);
    try std.testing.expectEqual(@as(u16, 443), config.port);
    try std.testing.expectEqualStrings("/facilitator", config.path_prefix);
    try std.testing.expect(config.use_tls);
}

test "x402: parseFacilitatorUrl parses http with port" {
    const config = parseFacilitatorUrl("http://localhost:9090/api") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("localhost", config.host);
    try std.testing.expectEqual(@as(u16, 9090), config.port);
    try std.testing.expectEqualStrings("/api", config.path_prefix);
    try std.testing.expect(!config.use_tls);
}

test "x402: parseFacilitatorUrl rejects invalid" {
    try std.testing.expect(parseFacilitatorUrl("ftp://invalid") == null);
    try std.testing.expect(parseFacilitatorUrl("") == null);
}

test "x402: parseVerifyResponse parses valid response" {
    const http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"isValid\":true,\"payer\":\"0xabc\"}";
    const result = parseVerifyResponse(http_resp);
    try std.testing.expect(result.is_valid);
    try std.testing.expectEqualStrings("0xabc", result.payer);
}

test "x402: parseVerifyResponse rejects on non-200" {
    const http_resp = "HTTP/1.1 400 Bad Request\r\n\r\n{\"isValid\":false}";
    const result = parseVerifyResponse(http_resp);
    try std.testing.expect(!result.is_valid);
}

test "x402: parseVerifyResponse rejects on isValid=false" {
    const http_resp = "HTTP/1.1 200 OK\r\n\r\n{\"isValid\":false,\"invalidReason\":\"insufficient_funds\"}";
    const result = parseVerifyResponse(http_resp);
    try std.testing.expect(!result.is_valid);
    try std.testing.expectEqualStrings("insufficient_funds", result.invalid_reason);
}

test "x402: parseSettleResponse parses transaction" {
    const http_resp = "HTTP/1.1 200 OK\r\n\r\n{\"success\":true,\"transaction\":\"0xabc123\",\"network\":\"eip155:8453\",\"payer\":\"0xdef\"}";
    const result = parseSettleResponse(http_resp);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("0xabc123", result.transaction);
    try std.testing.expectEqualStrings("eip155:8453", result.network);
    try std.testing.expectEqualStrings("0xdef", result.payer);
}

test "x402: parseSettleResponse failure includes errorReason" {
    const http_resp = "HTTP/1.1 200 OK\r\n\r\n{\"success\":false,\"errorReason\":\"insufficient_funds\"}";
    const result = parseSettleResponse(http_resp);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("insufficient_funds", result.error_reason);
}

test "x402: buildVerifyRequestJson matches spec format" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .price = "10000",
        .asset = "0xUSDC",
        .network = "eip155:8453",
        .pay_to = "0xRecv",
        .scheme = "exact",
    };
    var buf: [4096]u8 = undefined;
    const len = try buildVerifyRequestJson(&buf, "payment_b64_data", &policy);
    const json = buf[0..len];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"paymentPayload\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"paymentRequirements\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"x402Version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"maxAmountRequired\":\"10000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"0xUSDC\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"payTo\":\"0xRecv\"") != null);
}

test "x402: evaluateWithFacilitator allows without facilitator" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
    };
    const json = "{\"signature\":\"0xabc\",\"payload\":{}}";
    var b64_buf: [256]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], json);
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = b64_buf[0..b64_len] },
    };
    const req = makeRequest("/", &headers);
    switch (evaluateWithFacilitator(req, policy, null)) {
        .allow => |ctx| try std.testing.expect(!ctx.needs_settlement),
        .reject => return error.TestUnexpectedResult,
    }
}

test "x402: evaluateWithFacilitator rejects without header" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
    };
    const req = makeRequest("/", &.{});
    switch (evaluateWithFacilitator(req, policy, null)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |info| {
            try std.testing.expectEqual(@as(u16, 402), info.resp.status);
            try std.testing.expectEqual(RejectReason.missing_header, info.reason);
        },
    }
}

test "x402: evaluateWithFacilitator returns 400 for malformed header" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
    };
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = "not-valid-base64!!!" },
    };
    const req = makeRequest("/", &headers);
    switch (evaluateWithFacilitator(req, policy, null)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |info| {
            try std.testing.expectEqual(@as(u16, 400), info.resp.status);
            try std.testing.expectEqual(RejectReason.malformed_header, info.reason);
        },
    }
}

test "x402: local crypto verification rejects wrong signer" {
    if (!build_options.enable_x402_crypto) return error.SkipZigTest;
    // Payment header signed by 0xb2BA25C6..., but pay_to expects a different address
    const json =
        \\{"signature":"0x693db4a72b7e8fd75c1894ace1058706c4be88a30830a63658489250e4fd89053fe9863ad7e748c51fab5fcbf5a44772776d1afc94d34d277a2bae702b7137331c","payload":{"amount":"10000","asset":"0xUSDC","network":"eip155:8453"}}
    ;
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
        .pay_to = "0x0000000000000000000000000000000000000001",
    };
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = encodeJson(json) },
    };
    const req = makeRequest("/", &headers);
    switch (evaluateWithFacilitator(req, policy, null)) {
        .allow => return error.TestUnexpectedResult,
        .reject => |info| {
            try std.testing.expectEqual(@as(u16, 400), info.resp.status);
            try std.testing.expectEqual(RejectReason.invalid_signature, info.reason);
        },
    }
}

test "x402: local crypto verification allows correct signer" {
    if (!build_options.enable_x402_crypto) return error.SkipZigTest;
    const json =
        \\{"signature":"0x693db4a72b7e8fd75c1894ace1058706c4be88a30830a63658489250e4fd89053fe9863ad7e748c51fab5fcbf5a44772776d1afc94d34d277a2bae702b7137331c","payload":{"amount":"10000","asset":"0xUSDC","network":"eip155:8453"}}
    ;
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
        .pay_to = "0xb2BA25C6A5d758a6599A400FFA8810e68b2Ac4Db",
    };
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = encodeJson(json) },
    };
    const req = makeRequest("/", &headers);
    switch (evaluateWithFacilitator(req, policy, null)) {
        .allow => |ctx| {
            try std.testing.expect(ctx.payment_header.len > 0);
            try std.testing.expect(!ctx.needs_settlement);
        },
        .reject => return error.TestUnexpectedResult,
    }
}

test "x402: local crypto skipped when pay_to is empty" {
    if (!build_options.enable_x402_crypto) return error.SkipZigTest;
    // Structurally valid payment header with garbage signature — passes because
    // pay_to is empty, so local crypto verification is skipped.
    const json = "{\"signature\":\"0xabc\",\"payload\":{\"amount\":\"100\"}}";
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
        .pay_to = "",
    };
    const headers = [_]request.Header{
        .{ .name = "X-Payment", .value = encodeJson(json) },
    };
    const req = makeRequest("/", &headers);
    switch (evaluateWithFacilitator(req, policy, null)) {
        .allow => {},
        .reject => return error.TestUnexpectedResult,
    }
}

test "x402: buildReceiptB64 encodes settlement" {
    const settle = SettleResult{
        .success = true,
        .transaction = "0xdeadbeef",
        .network = "eip155:8453",
        .payer = "0xabc",
    };
    const b64 = buildReceiptB64(&settle) orelse return error.TestUnexpectedResult;
    try std.testing.expect(b64.len > 0);
    // Decode and verify it's valid JSON with expected fields
    const max_decoded = std.base64.standard.Decoder.calcSizeUpperBound(b64.len) catch return error.TestUnexpectedResult;
    var decode_buf: [1024]u8 = undefined;
    std.base64.standard.Decoder.decode(decode_buf[0..max_decoded], b64) catch return error.TestUnexpectedResult;
    const actual_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return error.TestUnexpectedResult;
    const decoded = decode_buf[0..actual_len];
    try std.testing.expect(std.mem.indexOf(u8, decoded, "\"transaction\":\"0xdeadbeef\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, decoded, "\"network\":\"eip155:8453\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, decoded, "\"payer\":\"0xabc\"") != null);
}

test "x402: error differentiation - missing header = 402 with JSON body" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
        .payment_required_json = "{\"test\":true}",
    };
    const info = rejectWith(.missing_header, policy);
    try std.testing.expectEqual(@as(u16, 402), info.resp.status);
    try std.testing.expectEqual(@as(usize, 2), info.resp.headers.len);
    try std.testing.expectEqualStrings("Content-Type", info.resp.headers[0].name);
    try std.testing.expectEqualStrings("application/json", info.resp.headers[0].value);
    try std.testing.expectEqualStrings("X-Payment-Required", info.resp.headers[1].name);
    try std.testing.expectEqualStrings("dGVzdA==", info.resp.headers[1].value);
    try std.testing.expectEqualStrings("{\"test\":true}", info.resp.bodyBytes());
}

test "x402: error differentiation - malformed header = 400" {
    const policy = RoutePaymentConfig{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const info = rejectWith(.malformed_header, policy);
    try std.testing.expectEqual(@as(u16, 400), info.resp.status);
    try std.testing.expectEqual(@as(usize, 0), info.resp.headers.len);
}

test "x402: error differentiation - invalid signature = 400" {
    const policy = RoutePaymentConfig{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const info = rejectWith(.invalid_signature, policy);
    try std.testing.expectEqual(@as(u16, 400), info.resp.status);
}

test "x402: error differentiation - facilitator rejected = 402" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .payment_required_b64 = "dGVzdA==",
        .payment_required_json = "{\"test\":true}",
    };
    const info = rejectWith(.facilitator_rejected, policy);
    try std.testing.expectEqual(@as(u16, 402), info.resp.status);
    try std.testing.expect(info.resp.headers.len > 0);
}

test "x402: error differentiation - facilitator error = 500" {
    const policy = RoutePaymentConfig{ .require_payment = true, .payment_required_b64 = "dGVzdA==" };
    const info = rejectWith(.facilitator_error, policy);
    try std.testing.expectEqual(@as(u16, 500), info.resp.status);
}

test "x402: buildSettleRequestJson uses charge_amount for upto scheme" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .price = "100000",
        .asset = "0xUSDC",
        .network = "eip155:8453",
        .pay_to = "0xRecv",
        .scheme = "upto",
    };
    var buf: [4096]u8 = undefined;
    const len = try buildSettleRequestJson(&buf, "payment_b64", &policy, "42000");
    const json = buf[0..len];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"settleAmount\":\"42000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"maxAmountRequired\":\"100000\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"scheme\":\"upto\"") != null);
}

test "x402: buildSettleRequestJson uses configured price for exact scheme" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .price = "50000",
        .asset = "0xUSDC",
        .network = "eip155:8453",
        .pay_to = "0xRecv",
        .scheme = "exact",
    };
    var buf: [4096]u8 = undefined;
    const len = try buildSettleRequestJson(&buf, "payment_b64", &policy, "99999");
    const json = buf[0..len];
    // exact scheme ignores charge_amount, uses configured price
    try std.testing.expect(std.mem.indexOf(u8, json, "\"settleAmount\":\"50000\"") != null);
}

test "x402: buildSettleRequestJson upto with empty charge falls back to price" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .price = "100000",
        .asset = "0xUSDC",
        .network = "eip155:8453",
        .pay_to = "0xRecv",
        .scheme = "upto",
    };
    var buf: [4096]u8 = undefined;
    const len = try buildSettleRequestJson(&buf, "payment_b64", &policy, "");
    const json = buf[0..len];
    // No charge_amount provided, falls back to configured price
    try std.testing.expect(std.mem.indexOf(u8, json, "\"settleAmount\":\"100000\"") != null);
}

test "x402: buildSettleRequestJson rejects charge exceeding max" {
    const policy = RoutePaymentConfig{
        .require_payment = true,
        .price = "100000",
        .asset = "0xUSDC",
        .network = "eip155:8453",
        .pay_to = "0xRecv",
        .scheme = "upto",
    };
    var buf: [4096]u8 = undefined;
    try std.testing.expectError(error.ChargeExceedsMax, buildSettleRequestJson(&buf, "payment_b64", &policy, "999999"));
}

fn encodeJson(json: []const u8) []const u8 {
    const S = struct {
        var buf: [1024]u8 = undefined;
    };
    const len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(S.buf[0..len], json);
    return S.buf[0..len];
}
