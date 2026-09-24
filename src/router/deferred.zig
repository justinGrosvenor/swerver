//! Owned router metadata for a suspended handler. Allocated only on suspension;
//! retained across continuation chains, freed after final response encoding.
const std = @import("std");
const router = @import("router.zig");
const suspension = @import("../runtime/suspension.zig");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const middleware = @import("../middleware/middleware.zig");
const x402 = @import("../middleware/x402.zig");

pub const Prepare = struct {
    otel_start: i128 = 0,
    allocator: std.mem.Allocator,
    ctx: *router.HandlerContext,
    route: *const router.Route,
    payment: *const x402.EvaluateResult,
    policy: *const x402.RoutePaymentConfig,
    mw_headers: []const response.Header,
    wasm_headers: []const response.Header,

    pub fn capture(ptr: *anyopaque) suspension.Error!suspension.Attachment {
        const self: *Prepare = @ptrCast(@alignCast(ptr));
        const req = self.ctx.request;
        if (req.headers.len > 128 or self.mw_headers.len > 64 or self.wasm_headers.len > 64)
            return error.SnapshotTooLarge;
        var remaining: usize = 64 * 1024;
        for ([_]usize{ req.path.len, req.method_raw.len, req.body.len(), self.ctx.charge_amount.len, self.route.pattern.len }) |len| try countBytes(&remaining, len);
        for ([_][]const response.Header{ req.headers, self.mw_headers, self.wasm_headers }) |headers| {
            for (headers) |h| {
                try countBytes(&remaining, h.name.len);
                try countBytes(&remaining, h.value.len);
            }
        }
        if (self.payment.* == .allow) try countBytes(&remaining, self.payment.allow.payment_header.len);

        const state = try self.allocator.create(State);
        state.* = .{ .allocator = self.allocator, .arena = std.heap.ArenaAllocator.init(self.allocator), .route = self.route.*, .payment = self.payment.*, .policy = self.policy.*, .mw_ctx = self.ctx.middleware_ctx.*, .req = req, .otel_start = self.otel_start };
        errdefer State.release(state);
        const a = state.arena.allocator();
        state.req.path = try a.dupe(u8, req.path);
        state.req.method_raw = try a.dupe(u8, req.method_raw);
        state.req.headers = try copyHeaders(a, req.headers);
        const body = try a.alloc(u8, req.body.len());
        state.req.body = .{ .slice = if (body.len == 0) "" else req.body.copyTo(body) orelse return error.SnapshotTooLarge };
        state.route.pattern = try a.dupe(u8, self.route.pattern);
        state.mw_ctx.route = state.route.pattern;
        // request_id pointed inside a stack Context; rebind to the owned copy.
        if (self.ctx.middleware_ctx.request_id) |id| state.mw_ctx.setRequestId(id);
        state.charge = try a.dupe(u8, self.ctx.charge_amount);
        state.mw_headers = try copyHeaders(a, self.mw_headers);
        state.wasm_headers = try copyHeaders(a, self.wasm_headers);
        if (state.payment == .allow) state.payment.allow.payment_header = try a.dupe(u8, self.payment.allow.payment_header);
        return state.attachment();
    }
};

fn countBytes(remaining: *usize, len: usize) suspension.Error!void {
    if (len > remaining.*) return error.SnapshotTooLarge;
    remaining.* -= len;
}

fn copyHeaders(a: std.mem.Allocator, headers: []const response.Header) ![]const response.Header {
    const result = try a.alloc(response.Header, headers.len);
    for (headers, result) |h, *out| out.* = .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) };
    return result;
}

pub const State = struct {
    otel_start: i128 = 0,
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    refs: usize = 1,
    route: router.Route,
    payment: x402.EvaluateResult,
    policy: x402.RoutePaymentConfig,
    mw_ctx: middleware.Context,
    req: request.RequestView,
    charge: []const u8 = "",
    mw_headers: []const response.Header = &.{},
    wasm_headers: []const response.Header = &.{},

    pub fn attachment(self: *State) suspension.Attachment {
        return .{ .ctx = self, .retain = retain, .release = release };
    }
    fn retain(ctx: *anyopaque) void {
        const self: *State = @ptrCast(@alignCast(ctx));
        self.refs += 1;
    }
    fn release(ctx: *anyopaque) void {
        const self: *State = @ptrCast(@alignCast(ctx));
        self.refs -= 1;
        if (self.refs != 0) return;
        const a = self.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
};
