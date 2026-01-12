const std = @import("std");

const swerver = @import("swerver");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var cfg = swerver.config.ServerConfig.default();
    var x402_payload: ?[]const u8 = null;
    defer if (x402_payload) |p| allocator.free(p);

    if (cfg.x402.enabled and cfg.x402.payment_required_b64.len == 0) {
        const payload = try swerver.middleware.x402.demoPaymentRequiredB64(allocator, "http://localhost:8080/");
        x402_payload = payload;
        cfg.x402.payment_required_b64 = payload;
    }
    const args = try parseArgs(init.minimal.args, allocator);
    cfg.static_root = args.static_root;
    try cfg.validate();

    var app_router = swerver.router.Router.init(.{
        .require_payment = cfg.x402.enabled,
        .payment_required_b64 = cfg.x402.payment_required_b64,
    });
    try swerver.registerDefaultRoutes(&app_router);

    var srv = try swerver.ServerBuilder
        .config(cfg)
        .router(app_router)
        .build(allocator);
    defer srv.deinit();

    try srv.run(args.run_for_ms);
}

const Args = struct {
    run_for_ms: ?u64,
    static_root: []const u8,
};

fn parseArgs(args: std.process.Args, allocator: std.mem.Allocator) !Args {
    var result = Args{
        .run_for_ms = null,
        .static_root = "",
    };
    var it = try std.process.Args.Iterator.initAllocator(args, allocator);
    defer it.deinit();
    _ = it.next(); // Skip program name
    while (it.next()) |arg_z| {
        const arg = std.mem.sliceTo(arg_z, 0);
        if (std.mem.eql(u8, arg, "--run-for-ms")) {
            const value = it.next() orelse return error.InvalidRunForMs;
            result.run_for_ms = std.fmt.parseInt(u64, std.mem.sliceTo(value, 0), 10) catch return error.InvalidRunForMs;
        } else if (std.mem.startsWith(u8, arg, "--run-for-ms=")) {
            const value = arg["--run-for-ms=".len..];
            result.run_for_ms = std.fmt.parseInt(u64, value, 10) catch return error.InvalidRunForMs;
        } else if (std.mem.eql(u8, arg, "--static-root")) {
            const value = it.next() orelse return error.InvalidStaticRoot;
            result.static_root = std.mem.sliceTo(value, 0);
        } else if (std.mem.startsWith(u8, arg, "--static-root=")) {
            result.static_root = arg["--static-root=".len..];
        }
    }
    return result;
}
