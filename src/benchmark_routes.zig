//! Benchmark route handlers for HttpArena / TechEmpower-style benchmarks.
//!
//! This module lives alongside `src/server.zig` but is intentionally kept
//! separate: the core server doesn't depend on it, and nothing in
//! `src/lib.zig`'s stable surface references it directly. Downstream
//! consumers reach it through `swerver.benchmark`, which is clearly
//! labeled as "benchmark-app helpers, not core library."
//!
//! Moving the handlers out of `src/server.zig` accomplishes three things:
//!  1. The main server module stays focused on the event loop, protocol
//!     dispatch, and preencoded cache — none of which are benchmark-
//!     specific.
//!  2. The `examples/httparena/` downstream consumer has a real reference
//!     point for "how do I register the HttpArena endpoints from
//!     swerver-as-library?" — just call `swerver.benchmark.registerRoutes`.
//!  3. The `lib.zig` surface can be trimmed without losing functionality
//!     (see 2.2 in the launch grind — `registerDefaultRoutes` and friends
//!     moved out of the core library namespace into `swerver.benchmark`).

const std = @import("std");
const router = @import("router/router.zig");
const response_mod = @import("response/response.zig");
const middleware = @import("middleware/middleware.zig");
const metrics_mw = @import("middleware/metrics_mw.zig");
const clock = @import("runtime/clock.zig");

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

    // Upload: return byte count of POST body
    try app_router.post("/upload", handleBenchUpload);
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

        const written = std.fmt.bufPrint(out[off..], "{{\"id\":{d},\"name\":\"{s}\",\"category\":\"{s}\",\"price\":{d}.{d:0>2},\"quantity\":{d},\"total\":{d}.{d:0>2}}}", .{
            item.id, item.name, item.category, p_whole, p_frac, item.quantity, whole, frac,
        }) catch return null;
        off += written.len;
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
    const body = ctx.request.body;
    if (body.len == 0) {
        return handleBenchEchoGet(ctx);
    }
    return .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .body = .{ .bytes = body },
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
    const body_len = ctx.request.body.len;
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
    if (ctx.request.method == .POST and ctx.request.body.len > 0) {
        const trimmed = std.mem.trim(u8, ctx.request.body, " \t\r\n");
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
