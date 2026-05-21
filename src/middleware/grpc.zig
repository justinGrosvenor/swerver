const std = @import("std");

pub const GrpcStatus = enum(u8) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,
};

pub fn isGrpcContentType(content_type: []const u8) bool {
    if (content_type.len < 16) return false;
    if (!std.ascii.eqlIgnoreCase(content_type[0..16], "application/grpc")) return false;
    if (content_type.len == 16) return true;
    const next = content_type[16];
    return next == '+' or next == ';';
}

pub fn isGrpcRequest(headers: []const @import("../protocol/request.zig").Header) bool {
    for (headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "content-type")) {
            return isGrpcContentType(hdr.value);
        }
    }
    return false;
}

pub fn isGrpcHeader(name: []const u8) bool {
    if (name.len < 5) return false;
    return std.ascii.eqlIgnoreCase(name[0..5], "grpc-");
}

pub fn httpStatusFromGrpcStatus(grpc_status: u8) u16 {
    return switch (@as(GrpcStatus, @enumFromInt(@min(grpc_status, 16)))) {
        .ok => 200,
        .invalid_argument => 400,
        .failed_precondition => 400,
        .out_of_range => 400,
        .unauthenticated => 401,
        .permission_denied => 403,
        .not_found => 404,
        .aborted => 409,
        .already_exists => 409,
        .resource_exhausted => 429,
        .cancelled => 499,
        .unknown => 500,
        .internal => 500,
        .data_loss => 500,
        .unimplemented => 501,
        .unavailable => 503,
        .deadline_exceeded => 504,
    };
}

pub fn grpcStatusFromHttp(http_status: u16) GrpcStatus {
    return switch (http_status) {
        200 => .ok,
        400 => .invalid_argument,
        401 => .unauthenticated,
        403 => .permission_denied,
        404 => .not_found,
        409 => .aborted,
        429 => .resource_exhausted,
        499 => .cancelled,
        500 => .internal,
        501 => .unimplemented,
        503 => .unavailable,
        504 => .deadline_exceeded,
        else => .unknown,
    };
}

pub fn parseGrpcStatus(value: []const u8) ?u8 {
    if (value.len == 0 or value.len > 2) return null;
    var result: u8 = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return null;
        result = result * 10 + (ch - '0');
    }
    if (result > 16) return null;
    return result;
}

// ── Tests ──

test "isGrpcContentType" {
    try std.testing.expect(isGrpcContentType("application/grpc"));
    try std.testing.expect(isGrpcContentType("application/grpc+proto"));
    try std.testing.expect(isGrpcContentType("application/grpc+json"));
    try std.testing.expect(isGrpcContentType("Application/GRPC"));
    try std.testing.expect(!isGrpcContentType("application/json"));
    try std.testing.expect(!isGrpcContentType("text/plain"));
    try std.testing.expect(!isGrpcContentType("short"));
}

test "isGrpcHeader" {
    try std.testing.expect(isGrpcHeader("grpc-status"));
    try std.testing.expect(isGrpcHeader("grpc-message"));
    try std.testing.expect(isGrpcHeader("grpc-encoding"));
    try std.testing.expect(isGrpcHeader("Grpc-Timeout"));
    try std.testing.expect(!isGrpcHeader("content-type"));
    try std.testing.expect(!isGrpcHeader("grp"));
}

test "httpStatusFromGrpcStatus" {
    try std.testing.expectEqual(@as(u16, 200), httpStatusFromGrpcStatus(0));
    try std.testing.expectEqual(@as(u16, 400), httpStatusFromGrpcStatus(3));
    try std.testing.expectEqual(@as(u16, 401), httpStatusFromGrpcStatus(16));
    try std.testing.expectEqual(@as(u16, 503), httpStatusFromGrpcStatus(14));
}

test "grpcStatusFromHttp" {
    try std.testing.expectEqual(GrpcStatus.ok, grpcStatusFromHttp(200));
    try std.testing.expectEqual(GrpcStatus.unavailable, grpcStatusFromHttp(503));
    try std.testing.expectEqual(GrpcStatus.unknown, grpcStatusFromHttp(418));
}

test "parseGrpcStatus" {
    try std.testing.expectEqual(@as(?u8, 0), parseGrpcStatus("0"));
    try std.testing.expectEqual(@as(?u8, 14), parseGrpcStatus("14"));
    try std.testing.expectEqual(@as(?u8, 16), parseGrpcStatus("16"));
    try std.testing.expectEqual(@as(?u8, null), parseGrpcStatus("17"));
    try std.testing.expectEqual(@as(?u8, null), parseGrpcStatus(""));
    try std.testing.expectEqual(@as(?u8, null), parseGrpcStatus("abc"));
}
