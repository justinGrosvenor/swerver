const std = @import("std");

const config = @import("config.zig");
const server = @import("server.zig");
const x402 = @import("middleware/x402.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var cfg = config.ServerConfig.default();
    var x402_payload: ?[]const u8 = null;
    defer if (x402_payload) |p| allocator.free(p);

    if (cfg.x402.enabled and cfg.x402.payment_required_b64.len == 0) {
        const payload = try x402.demoPaymentRequiredB64(allocator, "http://localhost:8080/");
        x402_payload = payload;
        cfg.x402.payment_required_b64 = payload;
    }
    try cfg.validate();
    const run_for_ms = try parseRunForMs(init.minimal.args, allocator);
    var srv = try server.Server.init(allocator, cfg);
    defer srv.deinit();

    try srv.run(run_for_ms);
}

fn parseRunForMs(args: std.process.Args, allocator: std.mem.Allocator) !?u64 {
    var it = try std.process.Args.Iterator.initAllocator(args, allocator);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |arg_z| {
        const arg = std.mem.sliceTo(arg_z, 0);
        if (std.mem.eql(u8, arg, "--run-for-ms")) {
            const value = it.next() orelse return error.InvalidRunForMs;
            return std.fmt.parseInt(u64, std.mem.sliceTo(value, 0), 10) catch error.InvalidRunForMs;
        }
        if (std.mem.startsWith(u8, arg, "--run-for-ms=")) {
            const value = arg["--run-for-ms=".len..];
            return std.fmt.parseInt(u64, value, 10) catch error.InvalidRunForMs;
        }
    }
    return null;
}
