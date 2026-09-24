const std = @import("std");
const s = @import("swerver");
const Context = s.router.HandlerContext;
const Resume = s.suspension.ResumeContext;
const Response = s.response.Response;

const State = struct {
    tickets: [128]?s.suspension.Token = @splat(null),
    resumed: usize = 0,
    cancelled: usize = 0,
};
const WaitState = struct { ms: u32, remaining: u8 = 0, key: ?u8 = null };

fn milliseconds(ctx: *Context) ?u32 {
    const ms = std.fmt.parseInt(u32, ctx.getParam("ms") orelse return null, 10) catch return null;
    return if (ms <= 60_000) ms else null;
}

fn delay(ctx: *Context) Response {
    const ms = milliseconds(ctx) orelse return ctx.text(400, "invalid delay");
    const remaining: u8 = if (std.mem.startsWith(u8, ctx.request.path, "/chain/")) 1 else 0;
    return ctx.suspension.sleep(ms, WaitState, .{ .ms = ms, .remaining = remaining }, resumed) catch
        return ctx.text(503, "wait unavailable");
}

fn resumed(ctx: *Resume) Response {
    const st = ctx.stash(WaitState);
    if (st.remaining > 0) {
        st.remaining -= 1;
        return ctx.suspension.sleep(st.ms, WaitState, st.*, resumed) catch
            return ctx.text(503, "wait unavailable");
    }
    const app = ctx.state(State);
    app.resumed += 1;
    if (st.key) |key| app.tickets[key] = null;
    if (ctx.event == .timeout) return ctx.text(504, "timeout");
    const body = std.fmt.bufPrint(ctx.response_buf, "{d}", .{st.ms}) catch unreachable;
    return ctx.text(200, body);
}

fn cancelled(ctx: *s.suspension.CancelContext) void {
    const app: *State = @ptrCast(@alignCast(ctx.app_state.?));
    app.cancelled += 1;
    if (ctx.stash(WaitState).key) |key| app.tickets[key] = null;
}

fn keyFrom(ctx: *Context) ?u8 {
    const key = std.fmt.parseInt(u8, ctx.getParam("key") orelse return null, 10) catch return null;
    return if (key < 128) key else null;
}

// A reactor-owned event source can keep a token and complete it later. Here a
// second request provides that event; real adapters can use socket readiness.
fn wait(ctx: *Context) Response {
    const key = keyFrom(ctx) orelse return ctx.text(400, "invalid key");
    const ms = milliseconds(ctx) orelse return ctx.text(400, "invalid delay");
    const app = ctx.state(State);
    if (app.tickets[key] != null) return ctx.text(409, "already waiting");
    const pending = ctx.suspension.wait(ms, WaitState, .{ .ms = ms, .key = key }, resumed, .{ .on_cancel = cancelled }) catch
        return ctx.text(503, "wait unavailable");
    app.tickets[key] = pending.token;
    return pending.response;
}

fn complete(ctx: *Context) Response {
    const key = keyFrom(ctx) orelse return ctx.text(400, "invalid key");
    const token = ctx.state(State).tickets[key] orelse return ctx.text(404, "no waiter");
    return if (ctx.suspension.complete(token)) ctx.text(200, "completed") else ctx.text(409, "expired");
}

fn plain(ctx: *Context) Response {
    return ctx.text(200, "ok");
}
fn stats(ctx: *Context) Response {
    const app = ctx.state(State);
    return ctx.jsonValue(200, .{ .resumed = app.resumed, .cancelled = app.cancelled });
}

pub fn main(init: std.process.Init) !void {
    var app_state = State{};
    var app = s.router.Router.init(.{});
    app.setState(&app_state);
    try app.get("/delay/:ms", delay);
    try app.get("/chain/:ms", delay);
    try app.get("/wait/:key/:ms", wait);
    try app.get("/complete/:key", complete);
    try app.get("/plain", plain);
    try app.get("/stats", stats);
    const args = try s.bootstrap.parseArgs(init.minimal.args, init.gpa);
    var options = s.bootstrap.optionsFromArgs(&args);
    options.router = app;
    options.workers_override = 1;
    try s.bootstrap.run(init.gpa, options);
}
