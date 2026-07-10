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

// ── PostgreSQL park-and-resume (design 9.0) ────────────────────────
// GET /api/db-sum runs two chained queries: sum a generated series,
// then multiply the result server-side via a bound parameter. The
// handler parks twice; the stash carries state between steps.

const DbStash = struct {
    step: u8 = 0,
    sum: i64 = 0,
};

fn dbUnavailable() swerver.response.Response {
    return .{ .status = 503, .headers = &.{}, .body = .{ .bytes = "db unavailable\n" } };
}

fn dbError(rctx: *swerver.db.pg.handler_api.ResumeContext) swerver.response.Response {
    if (rctx.server_error) |se| {
        std.log.warn("db error {s}: {s}", .{ se.sqlstate, se.message() });
    }
    return .{ .status = 502, .headers = &.{}, .body = .{ .bytes = "db query failed\n" } };
}

fn dbSum(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.pg.query(
        "select generate_series(1, 5)",
        &.{},
        DbStash,
        .{},
        onDbSum,
    ) catch dbUnavailable();
}

fn onDbSum(rctx: *swerver.db.pg.handler_api.ResumeContext) swerver.response.Response {
    const st = rctx.stash(DbStash);
    switch (st.step) {
        0 => {
            const res = rctx.result catch return dbError(rctx);
            var rows = res.rows();
            var sum: i64 = 0;
            while (rows.next()) |row| sum += row.int4(0) catch 0;
            st.sum = sum;
            st.step = 1;
            // Chain: bind the sum as a text parameter (copied into the
            // wire message during query(), so a stack buffer is fine).
            var buf: [24]u8 = undefined;
            const arg = std.fmt.bufPrint(&buf, "{d}", .{sum}) catch unreachable;
            return rctx.query("select $1::int8 * 10", &.{arg}, onDbSum) catch dbUnavailable();
        },
        1 => {
            const res = rctx.result catch return dbError(rctx);
            var rows = res.rows();
            const row = rows.next() orelse return dbError(rctx);
            const product = row.int8(0) catch return dbError(rctx);
            const body = std.fmt.bufPrint(
                rctx.response_buf,
                "sum={d} times10={d}\n",
                .{ st.sum, product },
            ) catch return dbError(rctx);
            return .{ .status = 200, .headers = &.{}, .body = .{ .bytes = body } };
        },
        else => unreachable,
    }
}

fn echo(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    var builder = ctx.respond() catch return swerver.response.Response{
        .status = 503,
        .headers = &.{},
        .body = .{ .bytes = "No buffers available" },
    };
    defer ctx.releaseBuilder(&builder);
    return builder.json(200, ctx.request.body.sliceOrNull() orelse "") catch swerver.response.Response{
        .status = 500,
        .headers = &.{},
        .body = .{ .bytes = "Response buffer full" },
    };
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var state = AppState{ .greeting = "hello, galaxy" };
    var services = Services{ .build_sha = "dev" };

    var router = swerver.router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    var api = router.group("/api");
    try api.get("/hello", hello);
    try api.get("/build", build);
    try api.get("/db-sum", dbSum);
    try api.post("/echo", echo);
    // QUERY (RFC 10008): a safe, idempotent method whose query lives in the
    // request body. Same handler contract as POST; the body carries the query.
    try api.query("/search", echo);

    // /api/db-sum needs a PostgreSQL server; enable the client when
    // PG_DEMO_HOST is set (password read from PG_DEMO_PASSWORD):
    //   PG_DEMO_HOST=127.0.0.1 PG_DEMO_PORT=5432 PG_DEMO_USER=postgres \
    //   PG_DEMO_DB=postgres PG_DEMO_PASSWORD=... ./swerver-embedded-example
    var cfg = swerver.config.ServerConfig.default();
    if (std.c.getenv("PG_DEMO_HOST")) |pg_host| {
        cfg.postgres = .{
            .enabled = true,
            .host = std.mem.sliceTo(pg_host, 0),
            .port = if (std.c.getenv("PG_DEMO_PORT")) |p|
                std.fmt.parseInt(u16, std.mem.sliceTo(p, 0), 10) catch 5432
            else
                5432,
            .user = if (std.c.getenv("PG_DEMO_USER")) |u| std.mem.sliceTo(u, 0) else "postgres",
            .database = if (std.c.getenv("PG_DEMO_DB")) |d| std.mem.sliceTo(d, 0) else "postgres",
            .password_env = "PG_DEMO_PASSWORD",
        };
    }

    var server = try swerver.ServerBuilder
        .config(cfg)
        .router(router)
        .withState(&state)
        .withServices(&services)
        .build(gpa.allocator());
    defer server.deinit();

    try server.run(null);
}
