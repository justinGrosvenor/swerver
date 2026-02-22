const std = @import("std");
const swerver = @import("swerver");

const AppState = struct {
    greeting: []const u8,
};

const Services = struct {
    build_sha: []const u8,
};

fn hello(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const state = ctx.state(AppState);
    return ctx.text(200, state.greeting);
}

fn build(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    const ptr = ctx.get([]const u8) orelse return ctx.text(500, "service not found");
    return ctx.text(200, ptr.*);
}

fn echo(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    var builder = ctx.respond() catch return swerver.response.Response{
        .status = 503,
        .headers = &.{},
        .body = .{ .bytes = "No buffers available" },
    };
    defer ctx.releaseBuilder(&builder);
    return builder.json(200, ctx.request.body) catch swerver.response.Response{
        .status = 500,
        .headers = &.{},
        .body = .{ .bytes = "Response buffer full" },
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var state = AppState{ .greeting = "hello, galaxy" };
    var services = Services{ .build_sha = "dev" };

    var router = swerver.router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    var api = router.group("/api");
    try api.get("/hello", hello);
    try api.get("/build", build);
    try api.post("/echo", echo);

    var server = try swerver.ServerBuilder
        .configDefault()
        .router(router)
        .withState(&state)
        .withServices(&services)
        .build(gpa.allocator());
    defer server.deinit();

    try server.run(null);
}
