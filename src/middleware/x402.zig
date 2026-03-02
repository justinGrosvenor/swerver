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

    for (req.headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "x-payment") or
            std.ascii.eqlIgnoreCase(hdr.name, "payment-signature"))
        {
            if (hdr.value.len > 0) {
                if (validatePaymentHeader(hdr.value)) {
                    return .allow;
                }
                return .{ .reject = paymentRequired(policy.payment_required_b64) };
            }
        }
    }

    return .{ .reject = paymentRequired(policy.payment_required_b64) };
}

/// Validate payment header structure: must be valid base64 containing JSON
/// with "signature" and "payload" fields.
fn validatePaymentHeader(header_value: []const u8) bool {
    if (header_value.len == 0 or header_value.len > 11000) return false;

    // Decode base64
    const max_decoded = std.base64.standard.Decoder.calcSizeUpperBound(header_value.len) catch return false;
    if (max_decoded > 8192) return false;
    var decode_buf: [8192]u8 = undefined;
    // calcSizeForSlice gives exact decoded length (vs upper bound)
    const actual_len = std.base64.standard.Decoder.calcSizeForSlice(header_value) catch return false;
    std.base64.standard.Decoder.decode(decode_buf[0..max_decoded], header_value) catch return false;
    const decoded = decode_buf[0..actual_len];

    // Structural validation: must contain "signature" and "payload" fields
    if (std.mem.indexOf(u8, decoded, "\"signature\"") == null) return false;
    if (std.mem.indexOf(u8, decoded, "\"payload\"") == null) return false;

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
