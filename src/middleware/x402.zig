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

pub fn evaluate(req: request.RequestView, policy: Policy) Decision {
    _ = req;
    if (!policy.require_payment) return .allow;
    return .{ .reject = paymentRequired(policy.payment_required_b64) };
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
        .body = "Payment required",
    };
}
