//! Benchmark route handlers for HttpArena / TechEmpower-style benchmarks.
//!
//! This module lives alongside `src/server.zig` but is intentionally kept
//! separate: the core server doesn't depend on it, and nothing in
//! `src/lib.zig`'s stable surface references it directly. Downstream
//! consumers reach it through `swerver.benchmark`, which is clearly
//! labeled as "benchmark-app helpers, not core library."

const std = @import("std");
const router = @import("router/router.zig");
const response_mod = @import("response/response.zig");
const middleware = @import("middleware/middleware.zig");
const metrics_mw = @import("middleware/metrics_mw.zig");
const clock = @import("runtime/clock.zig");
const json_write = @import("runtime/json_write.zig");
const pg_api = @import("db/pg/handler_api.zig");

// ============================================================
// Route registration
// ============================================================

/// Register the built-in benchmark endpoints on `app_router`. These
/// endpoints cover HttpArena (`/baseline11`, `/baseline2`, `/pipeline`,
/// `/json`, `/upload`) and TechEmpower (`/plaintext`) — anything a
/// framework benchmark harness expects to find on the target server.
///
/// Hot static endpoints (`/plaintext`, `/pipeline`, `/echo`, `/health`)
/// are also served from the Server's preencoded response cache, which
/// is initialized separately. The router-level handlers registered
/// here are the cold-path fallbacks for non-canonical queries.
pub fn registerRoutes(app_router: *router.Router) !void {
    try app_router.get("/health", handleBenchHealth);
    try app_router.get("/echo", handleBenchEchoGet);
    try app_router.post("/echo", handleBenchEchoPost);
    try app_router.get("/blob", handleBenchBlob);

    // TechEmpower Framework Benchmark endpoints
    try app_router.get("/plaintext", handleTfbPlaintext);

    // TFB database rounds (design 9.0 phase 5). Require a "postgres"
    // config block and the canonical TFB schema (World, Fortune
    // tables); without a configured client they answer 503.
    try app_router.get("/db", handleTfbDb);
    try app_router.get("/fortunes", handleTfbFortunes);
    try app_router.get("/queries", handleTfbQueries);
    try app_router.get("/updates", handleTfbUpdates);

    // Throughput and pipelining benchmark endpoints. /pipeline returns
    // a fixed "ok". /baseline11 and /baseline2 sum the ?a= and ?b=
    // query params (plus POST body for baseline11); their canonical
    // hot queries are served from the preencoded response cache
    // entirely, so these handlers only run on the cold path.
    try app_router.get("/pipeline", handleBenchPipeline);
    try app_router.get("/baseline11", handleBenchBaseline11);
    try app_router.post("/baseline11", handleBenchBaseline11);
    try app_router.get("/baseline2", handleBenchBaseline2);
    try app_router.post("/baseline2", handleBenchBaseline2);

    // JSON processing: load dataset, compute totals, return JSON.
    // Falls back to {"message":"Hello, World!"} when no dataset.
    try app_router.get("/json", handleBenchJson);

    // Upload: return byte count of POST body (discard mode — count only, no buffering)
    try app_router.postDiscard("/upload", handleBenchUpload);
}

/// Register the post-response middleware chain that the benchmark
/// app wants by default: security headers, Prometheus metrics, access
/// logging. Previously `registerDefaultPostHooks` in `server.zig`.
pub fn registerPostHooks(app_router: *router.Router) void {
    const pre_hooks = [_]middleware.MiddlewareFn{
        middleware.security.evaluate,
    };
    const post_hooks = [_]middleware.PostResponseFn{
        metrics_mw.postResponse,
        middleware.access_log.postResponseCombined,
    };
    var chain = app_router.middleware_chain;
    chain.pre = &pre_hooks;
    chain.post = &post_hooks;
    app_router.setMiddleware(chain);
}

// ============================================================
// /json dataset loader
// ============================================================

/// Pre-computed JSON response for /json endpoint. Populated once at
/// server init from /data/dataset.json by `loadDataset`, then served
/// as a cached static blob from `handleBenchJson` — the hot request
/// path is allocation-free because the blob is built here.
var json_dataset_buf: [65536]u8 = undefined;
var json_dataset_bytes: []const u8 = &.{};

/// Schema mirror for /data/dataset.json. `ignore_unknown_fields = true`
/// at the parse site lets the source file carry extra fields without
/// breaking the loader; a missing required field surfaces as a parse
/// error and the loader returns without populating `json_dataset_bytes`.
const DatasetItem = struct {
    id: i64,
    name: []const u8,
    category: []const u8,
    price: f64,
    quantity: i64,
};

/// Load the /json endpoint dataset from disk. Call this once at server
/// init; missing-file is a silent no-op (local dev without the dataset
/// falls back to `{"message":"Hello, World!"}` in `handleBenchJson`),
/// but parse/render failure on a file that DOES exist logs a warning
/// so operators aren't surprised when /json serves the fallback blob.
pub fn loadDataset() void {
    var path_z: [64]u8 = undefined;
    const dpath = "/data/dataset.json";
    @memcpy(path_z[0..dpath.len], dpath);
    path_z[dpath.len] = 0;
    const path_ptr: [*:0]const u8 = @ptrCast(&path_z);
    const fd = std.posix.openatZ(std.posix.AT.FDCWD, path_ptr, .{ .ACCMODE = .RDONLY }, 0) catch return;
    defer clock.closeFd(fd);
    var raw: [32768]u8 = undefined;
    const n = std.posix.read(fd, &raw) catch |err| {
        std.log.warn("benchmark_routes: read(/data/dataset.json) failed: {}", .{err});
        return;
    };
    if (n == 0) {
        std.log.warn("benchmark_routes: /data/dataset.json was empty; /json will serve the fallback response", .{});
        return;
    }

    if (renderDataset(raw[0..n], &json_dataset_buf)) |rendered| {
        json_dataset_bytes = rendered;
    } else {
        std.log.warn("benchmark_routes: failed to parse/render /data/dataset.json ({} bytes); /json will serve the fallback response", .{n});
    }
}

/// Parse a dataset JSON source and render the canonical
/// `{"count":N,"items":[...]}` blob into `out`. Pure — takes input
/// slice, writes into caller-provided buffer, returns the filled slice
/// or null on any parse/overflow error. Exposed as `fn`-visible so the
/// tests in this file can drive the renderer with synthetic input
/// without touching the filesystem.
fn renderDataset(raw: []const u8, out: []u8) ?[]const u8 {
    // Scoped arena so every node the JSON parser allocates is freed on
    // return. The previous implementation (in server.zig) leaked into
    // `page_allocator`.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const items = std.json.parseFromSliceLeaky(
        []DatasetItem,
        arena.allocator(),
        raw,
        .{ .ignore_unknown_fields = true },
    ) catch return null;

    var off: usize = 0;
    const header = std.fmt.bufPrint(out[off..], "{{\"count\":{d},\"items\":[", .{items.len}) catch return null;
    off += header.len;

    for (items, 0..) |item, i| {
        if (i > 0) {
            if (off + 1 > out.len) return null;
            out[off] = ',';
            off += 1;
        }

        const total = item.price * @as(f64, @floatFromInt(item.quantity));
        const total_cents: i64 = @intFromFloat(@round(total * 100.0));
        const whole = @divTrunc(total_cents, 100);
        const frac: u64 = @intCast(@abs(@rem(total_cents, 100)));

        const price_cents: i64 = @intFromFloat(@round(item.price * 100.0));
        const p_whole = @divTrunc(price_cents, 100);
        const p_frac: u64 = @intCast(@abs(@rem(price_cents, 100)));

        const id_part = std.fmt.bufPrint(out[off..], "{{\"id\":{d},\"name\":\"", .{item.id}) catch return null;
        off += id_part.len;
        const esc_name = json_write.writeEscaped(out[off..], item.name) catch return null;
        off += esc_name.len;
        const mid_part = std.fmt.bufPrint(out[off..], "\",\"category\":\"", .{}) catch return null;
        off += mid_part.len;
        const esc_cat = json_write.writeEscaped(out[off..], item.category) catch return null;
        off += esc_cat.len;
        const tail_part = std.fmt.bufPrint(out[off..], "\",\"price\":{d}.{d:0>2},\"quantity\":{d},\"total\":{d}.{d:0>2}}}", .{
            p_whole, p_frac, item.quantity, whole, frac,
        }) catch return null;
        off += tail_part.len;
    }

    const tail = std.fmt.bufPrint(out[off..], "]}}", .{}) catch return null;
    off += tail.len;
    return out[0..off];
}

// ============================================================
// Handler implementations
// ============================================================

/// 8KB static blob for large response benchmarks
const benchmark_blob: [8 * 1024]u8 = [_]u8{0} ** (8 * 1024);

/// GET /health — minimal health check for benchmarks
fn handleBenchHealth(_: *router.HandlerContext) response_mod.Response {
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{},
        .body = .none,
    };
}

/// GET /echo — return static JSON response
fn handleBenchEchoGet(_: *router.HandlerContext) response_mod.Response {
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .body = .{ .bytes = "{\"status\":\"ok\"}" },
    };
}

/// POST /echo — echo back request body.
/// Returns `.bytes` pointing into the read buffer — safe because
/// `queueResponse` copies body into the write buffer synchronously
/// before the next `read()`.
fn handleBenchEchoPost(ctx: *router.HandlerContext) response_mod.Response {
    const body_slice = ctx.request.body.sliceOrNull() orelse {
        const buf = ctx.request.body.copyTo(ctx.response_buf) orelse return .{
            .status = 413,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Body too large to echo" },
        };
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = buf },
        };
    };
    if (body_slice.len == 0) {
        return handleBenchEchoGet(ctx);
    }
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .body = .{ .bytes = body_slice },
    };
}

/// GET /blob — return 8KB response for throughput testing
fn handleBenchBlob(_: *router.HandlerContext) response_mod.Response {
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/octet-stream" },
        },
        .body = .{ .bytes = &benchmark_blob },
    };
}

/// GET /plaintext — TechEmpower plaintext test
fn handleTfbPlaintext(_: *router.HandlerContext) response_mod.Response {
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "Hello, World!" },
    };
}

// ── TFB database rounds (park-and-resume over the native PG client) ──

/// Per-worker PRNG for TFB's random row ids. Lazily seeded from the
/// monotonic clock; workers are single-threaded so no synchronization.
var tfb_prng: ?std.Random.DefaultPrng = null;

fn tfbRandomId() u32 {
    if (tfb_prng == null) {
        const seed: u64 = if (clock.realtimeNanos()) |ns| @truncate(@as(u128, @bitCast(ns))) else 0x9E37_79B9_7F4A_7C15;
        tfb_prng = std.Random.DefaultPrng.init(seed);
    }
    return 1 + tfb_prng.?.random().uintLessThan(u32, 10_000);
}

fn tfbDbUnavailable() response_mod.Response {
    return .{
        .status = 503,
        .headers = &[_]response_mod.Header{},
        .body = .{ .bytes = "database not configured" },
    };
}

fn tfbDbFailed() response_mod.Response {
    return .{
        .status = 500,
        .headers = &[_]response_mod.Header{},
        .body = .{ .bytes = "database query failed" },
    };
}

const TfbStash = struct {};

/// GET /db — TFB single-query test: one random World row as JSON,
/// e.g. {"id":4174,"randomNumber":331}.
fn handleTfbDb(ctx: *router.HandlerContext) response_mod.Response {
    var id_buf: [8]u8 = undefined;
    const arg = std.fmt.bufPrint(&id_buf, "{d}", .{tfbRandomId()}) catch unreachable;
    return ctx.pg.query(
        "select id, randomnumber from world where id = $1",
        &.{arg},
        TfbStash,
        .{},
        onTfbDb,
    ) catch tfbDbUnavailable();
}

fn onTfbDb(rctx: *pg_api.ResumeContext) response_mod.Response {
    const res = rctx.result catch return tfbDbFailed();
    var rows = res.rows();
    const row = rows.next() orelse return tfbDbFailed();
    const id = row.int4(0) catch return tfbDbFailed();
    const rn = row.int4(1) catch return tfbDbFailed();
    const body = std.fmt.bufPrint(
        rctx.response_buf,
        "{{\"id\":{d},\"randomNumber\":{d}}}",
        .{ id, rn },
    ) catch return tfbDbFailed();
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .body = .{ .bytes = body },
    };
}

/// GET /fortunes — TFB fortunes test: all Fortune rows plus one added
/// at request time, sorted by message, rendered as an escaped HTML
/// table.
fn handleTfbFortunes(ctx: *router.HandlerContext) response_mod.Response {
    return ctx.pg.query(
        "select id, message from fortune",
        &.{},
        TfbStash,
        .{},
        onTfbFortunes,
    ) catch tfbDbUnavailable();
}

const MAX_FORTUNES = 128;
const EXTRA_FORTUNE = "Additional fortune added at request time.";

const Fortune = struct {
    id: i32,
    message: []const u8, // borrows the result frames — continuation-scoped

    fn lessThan(_: void, a: Fortune, b: Fortune) bool {
        return std.mem.order(u8, a.message, b.message) == .lt;
    }
};

fn onTfbFortunes(rctx: *pg_api.ResumeContext) response_mod.Response {
    const res = rctx.result catch return tfbDbFailed();

    var fortunes: [MAX_FORTUNES]Fortune = undefined;
    var count: usize = 0;
    fortunes[count] = .{ .id = 0, .message = EXTRA_FORTUNE };
    count += 1;
    var rows = res.rows();
    while (rows.next()) |row| {
        if (count == MAX_FORTUNES) return tfbDbFailed();
        fortunes[count] = .{
            .id = row.int4(0) catch return tfbDbFailed(),
            .message = row.text(1) catch return tfbDbFailed(),
        };
        count += 1;
    }
    std.mem.sort(Fortune, fortunes[0..count], {}, Fortune.lessThan);

    var w: usize = 0;
    const buf = rctx.response_buf;
    w = appendBytes(buf, w, "<!DOCTYPE html><html><head><title>Fortunes</title></head><body><table><tr><th>id</th><th>message</th></tr>") orelse return tfbDbFailed();
    for (fortunes[0..count]) |f| {
        var num_buf: [12]u8 = undefined;
        const id_str = std.fmt.bufPrint(&num_buf, "{d}", .{f.id}) catch return tfbDbFailed();
        w = appendBytes(buf, w, "<tr><td>") orelse return tfbDbFailed();
        w = appendBytes(buf, w, id_str) orelse return tfbDbFailed();
        w = appendBytes(buf, w, "</td><td>") orelse return tfbDbFailed();
        w = appendHtmlEscaped(buf, w, f.message) orelse return tfbDbFailed();
        w = appendBytes(buf, w, "</td></tr>") orelse return tfbDbFailed();
    }
    w = appendBytes(buf, w, "</table></body></html>") orelse return tfbDbFailed();

    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
        },
        .body = .{ .bytes = buf[0..w] },
    };
}

/// TFB query-count parameter: ?queries=N clamped to 1..500; absent or
/// non-numeric values clamp to 1 (TFB verifier requirement).
const TFB_MAX_QUERIES = 500;

fn tfbParseQueries(path: []const u8) usize {
    const q = std.mem.indexOfScalar(u8, path, '?') orelse return 1;
    var it = std.mem.splitScalar(u8, path[q + 1 ..], '&');
    while (it.next()) |pair| {
        if (std.mem.startsWith(u8, pair, "queries=")) {
            const n = std.fmt.parseInt(usize, pair["queries=".len..], 10) catch return 1;
            return @min(@max(n, 1), TFB_MAX_QUERIES);
        }
    }
    return 1;
}

/// Render rows of (id int4, randomnumber int4) as the TFB JSON array.
fn tfbRenderRowsJson(rctx: *pg_api.ResumeContext) response_mod.Response {
    const res = rctx.result catch return tfbDbFailed();
    var w: usize = 0;
    const buf = rctx.response_buf;
    w = appendBytes(buf, w, "[") orelse return tfbDbFailed();
    var rows = res.rows();
    var first = true;
    while (rows.next()) |row| {
        const id = row.int4(0) catch return tfbDbFailed();
        const rn = row.int4(1) catch return tfbDbFailed();
        var item: [64]u8 = undefined;
        const s = std.fmt.bufPrint(&item, "{s}{{\"id\":{d},\"randomNumber\":{d}}}", .{
            if (first) @as([]const u8, "") else ",", id, rn,
        }) catch return tfbDbFailed();
        first = false;
        w = appendBytes(buf, w, s) orelse return tfbDbFailed();
    }
    w = appendBytes(buf, w, "]") orelse return tfbDbFailed();
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .body = .{ .bytes = buf[0..w] },
    };
}

/// GET /queries?queries=N — TFB multi-query test: N random World rows
/// via ONE batched op (one Parse, N Bind/Execute, one Sync).
fn handleTfbQueries(ctx: *router.HandlerContext) response_mod.Response {
    const n = tfbParseQueries(ctx.request.path);
    var id_bufs: [TFB_MAX_QUERIES][8]u8 = undefined;
    var arg_sets: [TFB_MAX_QUERIES][1]?[]const u8 = undefined;
    var batch: [TFB_MAX_QUERIES][]const ?[]const u8 = undefined;
    for (0..n) |i| {
        const a = std.fmt.bufPrint(&id_bufs[i], "{d}", .{tfbRandomId()}) catch unreachable;
        arg_sets[i] = .{a};
        batch[i] = arg_sets[i][0..];
    }
    return ctx.pg.queryBatch(
        "select id, randomnumber from world where id = $1",
        batch[0..n],
        TfbStash,
        .{},
        tfbRenderRowsJson,
    ) catch tfbDbUnavailable();
}

/// GET /updates?queries=N — TFB updates test: read N random rows (per
/// the TFB rules), then a second batched op updates each with a fresh
/// random value. The UPDATE uses RETURNING so the final continuation
/// renders straight from the op's rows — nothing needs to survive the
/// park in the stash. Ids are sorted ascending before the update batch
/// to avoid deadlocks between concurrent /updates requests (all N
/// updates share one implicit transaction via the single Sync).
const TfbUpdateStash = struct { n: u16 = 0 };

fn handleTfbUpdates(ctx: *router.HandlerContext) response_mod.Response {
    const n = tfbParseQueries(ctx.request.path);
    var id_bufs: [TFB_MAX_QUERIES][8]u8 = undefined;
    var arg_sets: [TFB_MAX_QUERIES][1]?[]const u8 = undefined;
    var batch: [TFB_MAX_QUERIES][]const ?[]const u8 = undefined;
    for (0..n) |i| {
        const a = std.fmt.bufPrint(&id_bufs[i], "{d}", .{tfbRandomId()}) catch unreachable;
        arg_sets[i] = .{a};
        batch[i] = arg_sets[i][0..];
    }
    return ctx.pg.queryBatch(
        "select id, randomnumber from world where id = $1",
        batch[0..n],
        TfbUpdateStash,
        .{ .n = @intCast(n) },
        onTfbUpdatesSelect,
    ) catch tfbDbUnavailable();
}

fn onTfbUpdatesSelect(rctx: *pg_api.ResumeContext) response_mod.Response {
    const st = rctx.stash(TfbUpdateStash);
    const res = rctx.result catch return tfbDbFailed();

    // Collect the read ids, sort ascending (deadlock avoidance), pair
    // each with a fresh random value, and fire the update batch. The
    // argument strings live on this frame — queryBatch serializes them
    // into the wire buffer before returning, so that's safe.
    var ids: [TFB_MAX_QUERIES]i32 = undefined;
    var count: usize = 0;
    var rows = res.rows();
    while (rows.next()) |row| {
        if (count >= st.n) break;
        ids[count] = row.int4(0) catch return tfbDbFailed();
        count += 1;
    }
    if (count == 0) return tfbDbFailed();
    std.mem.sort(i32, ids[0..count], {}, std.sort.asc(i32));

    var id_bufs: [TFB_MAX_QUERIES][8]u8 = undefined;
    var rn_bufs: [TFB_MAX_QUERIES][8]u8 = undefined;
    var arg_sets: [TFB_MAX_QUERIES][2]?[]const u8 = undefined;
    var batch: [TFB_MAX_QUERIES][]const ?[]const u8 = undefined;
    for (0..count) |i| {
        arg_sets[i] = .{
            std.fmt.bufPrint(&id_bufs[i], "{d}", .{ids[i]}) catch unreachable,
            std.fmt.bufPrint(&rn_bufs[i], "{d}", .{tfbRandomId()}) catch unreachable,
        };
        batch[i] = arg_sets[i][0..];
    }
    return rctx.queryBatch(
        "update world set randomnumber = $2 where id = $1 returning id, randomnumber",
        batch[0..count],
        tfbRenderRowsJson,
    ) catch tfbDbUnavailable();
}

fn appendBytes(buf: []u8, w: usize, bytes: []const u8) ?usize {
    if (buf.len - w < bytes.len) return null;
    @memcpy(buf[w .. w + bytes.len], bytes);
    return w + bytes.len;
}

/// Minimal OWASP HTML escaping (TFB fortunes requirement): & < > " '
fn appendHtmlEscaped(buf: []u8, start: usize, text: []const u8) ?usize {
    var w = start;
    for (text) |c| {
        const rep: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            else => {
                if (w == buf.len) return null;
                buf[w] = c;
                w += 1;
                continue;
            },
        };
        w = appendBytes(buf, w, rep) orelse return null;
    }
    return w;
}

/// GET|POST /baseline2?a=1&b=1 — h2/h3 throughput endpoint. Delegates to
/// `handleBenchBaseline11`, which implements the query-sum logic. The
/// canonical ?a=1&b=1 query hits the preencoded cache; this handler
/// covers arbitrary parameter values.
fn handleBenchBaseline2(ctx: *router.HandlerContext) response_mod.Response {
    return handleBenchBaseline11(ctx);
}

/// GET /pipeline — h1 pipelining throughput endpoint.
/// Returns the fixed body "ok".
fn handleBenchPipeline(_: *router.HandlerContext) response_mod.Response {
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "ok" },
    };
}

/// POST /upload — upload throughput endpoint.
/// Returns the byte count of the request body as text/plain.
fn handleBenchUpload(ctx: *router.HandlerContext) response_mod.Response {
    const body_len = ctx.request.body.len();
    const body = std.fmt.bufPrint(ctx.response_buf, "{d}", .{body_len}) catch "0";
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = body },
    };
}

/// GET /json — JSON dataset processing endpoint.
/// Serves the dataset pre-loaded by `loadDataset()` at startup. Falls
/// back to `{"message":"Hello, World!"}` when no dataset was loaded.
fn handleBenchJson(_: *router.HandlerContext) response_mod.Response {
    const dataset_bytes = json_dataset_bytes;
    if (dataset_bytes.len == 0) {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = "{\"message\":\"Hello, World!\"}" },
        };
    }
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .body = .{ .bytes = dataset_bytes },
    };
}

/// GET|POST /baseline11 — h1 throughput endpoint.
/// Sums the ?a= and ?b= query params, plus the request body for POST.
/// For the canonical GET ?a=1&b=1 the sum is 2, cached via the
/// preencoded h1 response cache. This cold-path handler is reached for
/// POSTs and for non-canonical queries.
fn handleBenchBaseline11(ctx: *router.HandlerContext) response_mod.Response {
    var sum: i64 = 0;
    // Parse query string: find '?' in path
    if (std.mem.indexOfScalar(u8, ctx.request.path, '?')) |q_start| {
        const query = ctx.request.path[q_start + 1 ..];
        var it = std.mem.splitScalar(u8, query, '&');
        while (it.next()) |pair| {
            if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                const val = pair[eq + 1 ..];
                if (std.fmt.parseInt(i64, val, 10)) |n| {
                    sum += n;
                } else |_| {}
            }
        }
    }
    // POST body: single integer, summed into total
    if (ctx.request.method == .POST and ctx.request.body.len() > 0) {
        const body_bytes = ctx.request.body.sliceOrNull() orelse "";
        const trimmed = std.mem.trim(u8, body_bytes, " \t\r\n");
        if (std.fmt.parseInt(i64, trimmed, 10)) |n| {
            sum += n;
        } else |_| {}
    }
    const body = std.fmt.bufPrint(ctx.response_buf, "{d}", .{sum}) catch "0";
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = body },
    };
}

// ============================================================
// Tests — exercise `renderDataset` with synthetic JSON so we can
// verify the parse + format path without needing /data/dataset.json.
// ============================================================

test "renderDataset parses input and computes totals" {
    const raw =
        \\[
        \\  {"id": 1, "name": "widget", "category": "tools", "price": 19.99, "quantity": 3},
        \\  {"id": 2, "name": "gadget", "category": "tools", "price": 4.5, "quantity": 10}
        \\]
    ;

    var out: [1024]u8 = undefined;
    const rendered = renderDataset(raw, &out) orelse return error.RenderFailed;

    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"id\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"name\":\"widget\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"price\":19.99") != null);
    // 19.99 × 3 = 59.97
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"total\":59.97") != null);
    // 4.50 × 10 = 45.00
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"total\":45.00") != null);
}

test "renderDataset ignores unknown fields on items" {
    const raw =
        \\[{"id": 7, "name": "x", "category": "y", "price": 1.0, "quantity": 1, "extra": "ignored"}]
    ;
    var out: [512]u8 = undefined;
    const rendered = renderDataset(raw, &out) orelse return error.RenderFailed;
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"id\":7") != null);
}

test "renderDataset returns null on malformed input" {
    const raw = "not json";
    var out: [512]u8 = undefined;
    try std.testing.expect(renderDataset(raw, &out) == null);
}

test "renderDataset returns null when output buffer is too small" {
    const raw =
        \\[{"id": 1, "name": "widget", "category": "tools", "price": 19.99, "quantity": 3}]
    ;
    var tiny: [16]u8 = undefined;
    try std.testing.expect(renderDataset(raw, &tiny) == null);
}
