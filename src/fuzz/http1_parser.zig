const std = @import("std");
const request = @import("../protocol/request.zig");
const http1 = @import("../protocol/http1.zig");

pub fn testFuzz(data: []const u8) void {
    var headers: [128]request.Header = undefined;
    const limits = http1.Limits{
        .max_header_bytes = 8192,
        .max_body_bytes = 32768,
        .max_header_count = headers.len,
        .headers_storage = headers[0..],
    };
    _ = http1.parse(data, limits);
}
