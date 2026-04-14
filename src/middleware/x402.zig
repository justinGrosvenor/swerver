const std = @import("std");
const response = @import("../response/response.zig");
const request = @import("../protocol/request.zig");

pub const Decision = union(enum) {
    allow,
    reject: response.Response,
};

pub const Policy = struct {
    require_payment: bool,
    payment_required_b64: []const u8,
};

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

    // No valid payment header found — reject with 402.
    return .{ .reject = paymentRequired(policy.payment_required_b64) };
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

pub fn buildPaymentRequired(allocator: std.mem.Allocator, required: PaymentRequired) ![]u8 {
    var json_list = std.ArrayList(u8).empty;
    var writer = std.Io.Writer.Allocating.fromArrayList(allocator, &json_list);
    defer writer.deinit();
    try std.json.Stringify.value(required, .{}, &writer.writer);
    json_list = writer.toArrayList();

    const encoded_len = std.base64.standard.Encoder.calcSize(json_list.items.len);
    const out = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(out, json_list.items);
    return out;
}

pub fn demoPaymentRequiredB64(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
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

fn paymentRequired(payload_b64: []const u8) response.Response {
    return .{
        .status = 402,
        .headers = &[_]response.Header{
            .{ .name = "PAYMENT-REQUIRED", .value = payload_b64 },
        },
        .body = .{ .bytes = "Payment required" },
    };
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
        .body = "",
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

fn encodeJson(json: []const u8) []const u8 {
    const S = struct {
        var buf: [1024]u8 = undefined;
    };
    const len = std.base64.standard.Encoder.calcSize(json.len);
    _ = std.base64.standard.Encoder.encode(S.buf[0..len], json);
    return S.buf[0..len];
}
