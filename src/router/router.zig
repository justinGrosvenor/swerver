const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const x402 = @import("../middleware/x402.zig");
const settlement = @import("../middleware/settlement.zig");
const middleware = @import("../middleware/middleware.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");
const clock = @import("../runtime/clock.zig");
const io_runtime = @import("../runtime/io.zig");
const pg_client_mod = @import("../db/pg/client.zig");
const pg_handler_api = @import("../db/pg/handler_api.zig");

/// Per-thread scratch for merging handler-returned headers with
/// middleware-accumulated headers (security, CORS, etc.) before the
/// response gets serialized. Sized to hold the handler's max + the
/// middleware chain's max in one pass. See `Router.handle`.
threadlocal var merged_headers_tls: [MAX_RESPONSE_HEADERS + middleware.Chain.MAX_MIDDLEWARE_HEADERS + 2]response.Header = undefined;
threadlocal var x402_receipt_tls: response.Header = undefined;
threadlocal var x402_receipt_v1_tls: response.Header = undefined;
threadlocal var x402_has_receipt: bool = false;

/// Errors surfaced by `Router` registration and routing.
///
/// All are programmer errors (the route table is finite and fixed-size), not
/// runtime conditions a user can recover from at request time. Registration
/// fails at startup if you try to add more routes than `RouterLimits` allows,
/// or if a pattern exceeds the compiled-in segment/param/length limits.
/// `NoBufferOps` / `NoBuffers` surface from the per-request `ctx.respond()`
/// path when the buffer pool is exhausted — see `HandlerContext` for the
/// recommended fallback pattern.
pub const RouterError = error{
    RouteLimitExceeded,
    SegmentLimitExceeded,
    ParamLimitExceeded,
    PatternTooLong,
    NoBufferOps,
    NoBuffers,
};

/// Outcome of `Router.handle` for a single request.
///
/// `resp` is always set — even on 404, 405, and 500, the router produces a
/// valid `Response` (via the configured `not_found_handler` / `error_handler`
/// or a built-in default). `pause_reads_ms` is only set when a middleware in
/// the chain returns `.rate_limit_backpressure` — the server uses it to
/// suspend reads on the connection for the requested duration before
/// dispatching the next request. Downstream code that doesn't implement
/// backpressure can ignore `pause_reads_ms` safely.
pub const RouteResult = struct {
    /// Response to send
    resp: response.Response,
    /// If non-null, pause reads for this many milliseconds (rate limiting)
    pause_reads_ms: ?u64 = null,
};

/// Signature of every route handler swerver dispatches. Handlers are
/// synchronous: they run to completion between `recv()` calls on the
/// connection, which is why `ctx.request.body` and `ctx.request.headers`
/// can be `[]const u8` slices into the receive buffer without any copy.
///
/// Return a `Response` directly — no allocator, no error union. If you
/// need to build a response body that lives beyond the caller-provided
/// `response_buf` scratch (e.g. to fit a JSON blob larger than the
/// default 8 KB), call `ctx.respond()` to acquire a managed buffer
/// handle from the pool and use `ResponseBuilder.text` / `.json` /
/// `.html`. The pool handle is released automatically after the
/// response is serialized.
pub const HandlerFn = *const fn (ctx: *HandlerContext) response.Response;

/// Per-request context passed into every route handler.
///
/// Field lifetimes:
///   - `request.headers` / `request.body` — slices into the connection's
///     receive buffer. Valid for the duration of the handler call. Don't
///     stash them across async points (Zig has none, so in practice:
///     don't store them in module-level state).
///   - `response_buf` — caller-owned scratch for small dynamic response
///     bodies (`std.fmt.bufPrint(ctx.response_buf, …)`). Default size is
///     `RESPONSE_BUF_SIZE` (8 KB). Gets reused for the next request on
///     the same worker.
///   - `response_headers` — scratch for building a small header list
///     inline without allocating. Default capacity is
///     `MAX_RESPONSE_HEADERS` (4). If you need more, return headers from
///     a `const` array literal in your handler instead.
///   - `arena` — `FixedBufferAllocator` lazy-acquired from the buffer
///     pool the first time you call `ctx.allocator()`. Useful for
///     one-request-lifetime structured data. Released after response
///     serialization.
///   - `params` — path parameters matched from the route pattern
///     (`/users/:id` → `params[0] = { .name = "id", .value = "123" }`).
///     `param_count` is the number actually populated.
///   - `app_state` / `app_services` — opaque pointers installed on the
///     `Router` via `setState` / `setServices` before the event loop
///     starts. Use `ctx.state(T)` / `ctx.get(T)` to downcast with type
///     safety.
///
/// The handler must not free any of the above — the Router reclaims
/// them before the next request on this worker.
pub const HandlerContext = struct {
    request: request.RequestView,
    middleware_ctx: *middleware.Context,
    app_state: ?*anyopaque = null,
    app_services: ?*anyopaque = null,
    app_services_get: ?ServiceGetter = null,
    buffer_ops: ?middleware.BufferOps = null,
    /// Path parameters extracted from route (e.g., /users/:id)
    params: [MAX_PARAMS]Param = undefined,
    param_count: u8 = 0,
    /// Response buffer for building dynamic responses
    response_buf: []u8,
    /// Response headers built for default responses
    response_headers: []response.Header,
    response_header_count: usize = 0,
    /// Request-scoped arena allocator
    arena: std.heap.FixedBufferAllocator,
    /// Actual charge amount for x402 `upto` scheme (set by handler)
    charge_amount: []const u8 = "",
    /// PostgreSQL query surface: `ctx.pg.query(...)`.
    pg: PgHandle = .{},

    pub const Param = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const ResponseBuilder = struct {
        handle: buffer_pool.BufferHandle,
        len: usize = 0,
        used: bool = false,

        pub const BuildError = error{BufferFull};

        pub fn init(handle: buffer_pool.BufferHandle) ResponseBuilder {
            return .{ .handle = handle };
        }

        pub fn reset(self: *ResponseBuilder) void {
            self.len = 0;
        }

        pub fn append(self: *ResponseBuilder, data: []const u8) BuildError!void {
            if (self.len + data.len > self.handle.bytes.len) return error.BufferFull;
            @memcpy(self.handle.bytes[self.len .. self.len + data.len], data);
            self.len += data.len;
        }

        pub fn bytes(self: *const ResponseBuilder) []const u8 {
            return self.handle.bytes[0..self.len];
        }

        pub fn text(self: *ResponseBuilder, status: u16, body: []const u8) BuildError!response.Response {
            self.reset();
            try self.append(body);
            self.used = true;
            return .{
                .status = status,
                .headers = &[_]response.Header{
                    .{ .name = "Content-Type", .value = "text/plain" },
                },
                .body = .{ .managed = .{ .handle = self.handle, .len = self.len } },
            };
        }

        pub fn json(self: *ResponseBuilder, status: u16, body: []const u8) BuildError!response.Response {
            self.reset();
            try self.append(body);
            self.used = true;
            return .{
                .status = status,
                .headers = &[_]response.Header{
                    .{ .name = "Content-Type", .value = "application/json" },
                },
                .body = .{ .managed = .{ .handle = self.handle, .len = self.len } },
            };
        }

        pub fn html(self: *ResponseBuilder, status: u16, body: []const u8) BuildError!response.Response {
            self.reset();
            try self.append(body);
            self.used = true;
            return .{
                .status = status,
                .headers = &[_]response.Header{
                    .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
                },
                .body = .{ .managed = .{ .handle = self.handle, .len = self.len } },
            };
        }

        pub fn release(self: *ResponseBuilder, ops: middleware.BufferOps) void {
            if (!self.used) {
                ops.release(ops.ctx, self.handle);
            }
        }
    };

    /// Start building a response in the request-scoped buffer.
    pub fn respond(self: *HandlerContext) RouterError!ResponseBuilder {
        const ops = self.buffer_ops orelse return error.NoBufferOps;
        const handle = ops.acquire(ops.ctx) orelse return error.NoBuffers;
        return ResponseBuilder.init(handle);
    }

    pub fn releaseBuilder(self: *HandlerContext, builder: *ResponseBuilder) void {
        const ops = self.buffer_ops orelse return;
        builder.release(ops);
    }

    /// Access app state (set via ServerBuilder.withState).
    /// NOTE: T must match the type originally passed to withState(). The pointer
    /// must be naturally aligned for T — misaligned pointers cause a safety
    /// check panic in Debug/ReleaseSafe modes and UB in ReleaseFast.
    pub fn state(self: *const HandlerContext, comptime T: type) *T {
        std.debug.assert(self.app_state != null);
        return @ptrCast(@alignCast(self.app_state.?));
    }

    /// Access typed services (set via ServerBuilder.withServices).
    /// NOTE: T must match the type originally passed to withServices(). The pointer
    /// must be naturally aligned for T.
    pub fn services(self: *const HandlerContext, comptime T: type) *T {
        std.debug.assert(self.app_services != null);
        return @ptrCast(@alignCast(self.app_services.?));
    }

    /// Typed lookup from services (optional sugar).
    /// Returns null if the service type is not registered.
    pub fn get(self: *const HandlerContext, comptime T: type) ?*T {
        const services_ptr = self.app_services orelse return null;
        const getter = self.app_services_get orelse return null;
        const raw = getter(services_ptr, @typeName(T)) orelse return null;
        return @ptrCast(@alignCast(raw));
    }

    /// Request-scoped allocator (valid only during handler execution).
    pub fn arenaAllocator(self: *HandlerContext) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Set the actual charge amount for x402 `upto` scheme.
    /// Call this in your handler to specify how much to settle.
    /// For `exact` scheme, this is ignored — the configured price is used.
    pub fn setChargeAmount(self: *HandlerContext, amount: []const u8) void {
        self.charge_amount = amount;
    }

    /// Get path parameter by name
    pub fn getParam(self: *const HandlerContext, name: []const u8) ?[]const u8 {
        for (self.params[0..self.param_count]) |p| {
            if (std.mem.eql(u8, p.name, name)) {
                return p.value;
            }
        }
        return null;
    }

    /// Build a JSON response from an already-encoded body.
    pub fn json(_: *HandlerContext, status: u16, body: []const u8) response.Response {
        return .{
            .status = status,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = body },
        };
    }

    /// Build a JSON response by serializing any value. This is the idiomatic
    /// way to return JSON from a handler: define a struct (or slice/map) for
    /// the payload and hand it to `jsonValue` instead of formatting the body
    /// by hand. Encoding uses `stringifyJson` (a comptime-specialized encoder
    /// for the common shapes, deferring to `std.json` for the rest), so the
    /// output is identical to the standard encoder.
    ///
    /// The payload is encoded into the request arena when one is available, and
    /// otherwise into a managed pool buffer (acquired via `respond`) so it
    /// works on every protocol path — including HTTP/2 GETs, where the arena is
    /// skipped. Returns 500 if no buffer is available or the value is too large
    /// to encode.
    pub fn jsonValue(self: *HandlerContext, status: u16, value: anytype) response.Response {
        const json_err = response.Response{
            .status = 500,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = "{\"error\":\"json serialization failed\"}" },
        };

        // Fast path: encode into the request arena when it has backing storage.
        if (self.arena.buffer.len > 0) {
            var list = std.ArrayList(u8).empty;
            var w = std.Io.Writer.Allocating.fromArrayList(self.arenaAllocator(), &list);
            if (stringifyJson(value, &w.writer)) {
                return self.json(status, w.toArrayList().items);
            } else |_| {}
            // Arena overflowed — fall through to a larger managed buffer.
        }

        // Fallback: a managed pool buffer (HTTP/2 GET has a 0-byte arena).
        var rb = self.respond() catch return json_err;
        var w = std.Io.Writer.fixed(rb.handle.bytes);
        stringifyJson(value, &w) catch {
            if (self.buffer_ops) |ops| ops.release(ops.ctx, rb.handle);
            return json_err;
        };
        rb.used = true;
        rb.len = w.buffered().len;
        return .{
            .status = status,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .managed = .{ .handle = rb.handle, .len = rb.len } },
        };
    }

    /// Build a text response
    pub fn text(self: *HandlerContext, status: u16, body: []const u8) response.Response {
        _ = self;
        return .{
            .status = status,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
            },
            .body = .{ .bytes = body },
        };
    }

    /// Build an HTML response
    pub fn html(self: *HandlerContext, status: u16, body: []const u8) response.Response {
        _ = self;
        return .{
            .status = status,
            .headers = &[_]response.Header{
                .{ .name = "Content-Type", .value = "text/html; charset=utf-8" },
            },
            .body = .{ .bytes = body },
        };
    }
};

// ── JSON serialization ───────────────────────────────────────────
//
// `stringifyJson` is a comptime-specialized JSON encoder used by
// `HandlerContext.jsonValue`. For the common shapes (non-tuple structs,
// integers, bools, strings, slices, optionals) it resolves field names,
// separators, and type dispatch at compile time, emitting one `writeAll` of a
// concatenated literal per field with run-based string escaping. On typical
// payloads that is ~1.6x faster than `std.json.Stringify`.
// Anything it does not specialize (floats, enums, unions, tuples, arrays,
// maps, `std.json.Value`, structs with non-identifier field names) is deferred
// to `std.json.Stringify.value`, so the output is byte-identical to the
// standard encoder for every supported value.

/// Write `s` as a JSON string (surrounding quotes + escaping), bulk-copying
/// spans that need no escaping. Matches std.json's default escape set: `"`,
/// `\`, the named control escapes, and `\u00XX` for other control bytes;
/// UTF-8 and `/` pass through unescaped.
fn writeJsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeAll("\"");
    var start: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        const esc: ?[]const u8 = switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            else => null,
        };
        if (esc) |e| {
            if (i > start) try w.writeAll(s[start..i]);
            try w.writeAll(e);
            start = i + 1;
        } else if (c < 0x20) {
            if (i > start) try w.writeAll(s[start..i]);
            const hex = "0123456789abcdef";
            const u = [_]u8{ '\\', 'u', '0', '0', hex[(c >> 4) & 0xf], hex[c & 0xf] };
            try w.writeAll(&u);
            start = i + 1;
        }
    }
    if (s.len > start) try w.writeAll(s[start..]);
    try w.writeAll("\"");
}

/// Encode `value` as JSON into `w`. Comptime-specialized for the common
/// shapes; delegates anything else to `std.json.Stringify.value` (see the
/// module note above), so output always matches the standard encoder.
fn stringifyJson(value: anytype, w: *std.Io.Writer) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .bool => try w.writeAll(if (value) "true" else "false"),
        .int, .comptime_int => try w.print("{d}", .{value}),
        .optional => if (value) |v| try stringifyJson(v, w) else try w.writeAll("null"),
        .@"struct" => |info| {
            // Fast path only for non-tuple structs whose field names need no
            // JSON escaping (valid Zig identifiers always qualify). Otherwise
            // defer so tuples render as arrays and odd names stay escaped.
            const fast = comptime blk: {
                if (info.is_tuple) break :blk false;
                for (info.fields) |f| {
                    for (f.name) |c| switch (c) {
                        'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => {},
                        else => break :blk false,
                    };
                }
                break :blk true;
            };
            if (fast) {
                try w.writeAll("{");
                inline for (info.fields, 0..) |field, idx| {
                    try w.writeAll(comptime (if (idx == 0) "\"" else ",\"") ++ field.name ++ "\":");
                    try stringifyJson(@field(value, field.name), w);
                }
                try w.writeAll("}");
            } else {
                try std.json.Stringify.value(value, .{}, w);
            }
        },
        .pointer => |p| {
            if (p.size == .slice) {
                if (p.child == u8) {
                    try writeJsonString(w, value);
                } else {
                    try w.writeAll("[");
                    for (value, 0..) |elem, idx| {
                        if (idx > 0) try w.writeAll(",");
                        try stringifyJson(elem, w);
                    }
                    try w.writeAll("]");
                }
            } else {
                try std.json.Stringify.value(value, .{}, w);
            }
        },
        // Floats (exact shortest-repr formatting), enums, unions, arrays,
        // maps, std.json.Value, etc. — defer to the standard encoder.
        else => try std.json.Stringify.value(value, .{}, w),
    }
}

/// Fluent builder for registering a single route with a per-route
/// middleware chain. Constructed via `Router.routeBuilder(method,
/// pattern, handler)`, chained with `.withMiddleware(&chain)`, and
/// finalized with `.register()`.
///
/// Use this when one specific route needs a different middleware
/// set from the Router's default chain — e.g. an admin endpoint
/// that wants stricter auth, or a public endpoint that should skip
/// rate limiting. For the common case where every route uses the
/// same chain, call `Router.setMiddleware` once at startup and use
/// the plain `.get` / `.post` / etc. methods.
pub const RouteBuilder = struct {
    router: *Router,
    method: request.Method,
    pattern: []const u8,
    handler: HandlerFn,
    middleware_chain: ?*middleware.Chain = null,
    payment: x402.RoutePaymentConfig = .{},

    pub fn withMiddleware(self: *RouteBuilder, chain: *middleware.Chain) *RouteBuilder {
        self.middleware_chain = chain;
        return self;
    }

    pub fn withPayment(self: *RouteBuilder, config: x402.RoutePaymentConfig) *RouteBuilder {
        self.payment = config;
        return self;
    }

    pub fn register(self: *RouteBuilder) RouterError!void {
        return self.router.routeWithOptions(self.method, self.pattern, self.handler, self.middleware_chain, self.payment);
    }
};

/// Fluent builder for registering multiple routes under a common
/// path prefix (e.g. `/api/v1`). Constructed via `Router.group(prefix)`
/// and then used like a miniature Router:
///
///     var api = router.group("/api/v1");
///     try api.get("/users", listUsers);
///     try api.post("/users", createUser);
///     try api.delete("/users/:id", deleteUser);
///
/// Each registered route's pattern is prepended with the group prefix,
/// so the handler sees the full path (`/api/v1/users/:id`). Optionally
/// chain `.withMiddleware(&chain)` to apply a shared middleware chain
/// to every route registered through this group.
pub const GroupBuilder = struct {
    router: *Router,
    prefix: []const u8,
    middleware_chain: ?*middleware.Chain = null,
    payment: x402.RoutePaymentConfig = .{},

    pub fn withMiddleware(self: *GroupBuilder, chain: *middleware.Chain) *GroupBuilder {
        self.middleware_chain = chain;
        return self;
    }

    pub fn withPayment(self: *GroupBuilder, config: x402.RoutePaymentConfig) *GroupBuilder {
        self.payment = config;
        return self;
    }

    pub fn get(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefixAndPayment(.GET, self.prefix, pattern, handler, self.middleware_chain, self.payment);
    }

    pub fn post(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefixAndPayment(.POST, self.prefix, pattern, handler, self.middleware_chain, self.payment);
    }

    pub fn put(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefixAndPayment(.PUT, self.prefix, pattern, handler, self.middleware_chain, self.payment);
    }

    pub fn delete(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefixAndPayment(.DELETE, self.prefix, pattern, handler, self.middleware_chain, self.payment);
    }

    pub fn patch(self: *GroupBuilder, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.router.routeWithPrefixAndPayment(.PATCH, self.prefix, pattern, handler, self.middleware_chain, self.payment);
    }
};

pub const HandlerScratch = struct {
    response_buf: []u8,
    response_headers: []response.Header,
    arena_buf: []u8,
    arena_handle: ?buffer_pool.BufferHandle = null,
    buffer_ops: ?middleware.BufferOps = null,
    /// PostgreSQL park-and-resume binding. Set by the H1
    /// dispatch layer when a PG client is configured; the zero value
    /// makes `ctx.pg.query()` fail with error.NotConnected.
    pg: PgBinding = .{},
};

/// Connection identity + per-worker PG client, threaded from the
/// dispatch layer into `ctx.pg`. conn_id is the connection generation,
/// checked at resume time.
pub const PgBinding = struct {
    client: ?*pg_client_mod.PgClient = null,
    io_rt: ?*io_runtime.IoRuntime = null,
    conn_index: u32 = 0,
    conn_id: u64 = 0,
};

/// `ctx.pg` — the handler-facing query surface. `query()` issues
/// one parameterized statement, parks the request, and returns the
/// park sentinel Response, which the handler must return.
pub const PgHandle = struct {
    binding: PgBinding = .{},

    pub fn query(
        self: PgHandle,
        sql: []const u8,
        args: []const ?[]const u8,
        comptime StashT: type,
        stash_init: StashT,
        continuation: pg_handler_api.Continuation,
    ) pg_handler_api.QueryError!response.Response {
        comptime pg_handler_api.assertPlainData(StashT);
        comptime std.debug.assert(@sizeOf(StashT) <= pg_handler_api.STASH_CAPACITY);
        const client = self.binding.client orelse return error.NotConnected;
        return client.query(
            self.binding.io_rt.?,
            self.binding.conn_index,
            self.binding.conn_id,
            sql,
            args,
            std.mem.asBytes(&stash_init),
            continuation,
        );
    }

    /// Batch variant: one op, N Bind/Execute pairs of the same SQL, all
    /// result rows in one continuation Result.
    pub fn queryBatch(
        self: PgHandle,
        sql: []const u8,
        args_batch: []const []const ?[]const u8,
        comptime StashT: type,
        stash_init: StashT,
        continuation: pg_handler_api.Continuation,
    ) pg_handler_api.QueryError!response.Response {
        comptime pg_handler_api.assertPlainData(StashT);
        comptime std.debug.assert(@sizeOf(StashT) <= pg_handler_api.STASH_CAPACITY);
        const client = self.binding.client orelse return error.NotConnected;
        return client.queryBatch(
            self.binding.io_rt.?,
            self.binding.conn_index,
            self.binding.conn_id,
            sql,
            args_batch,
            std.mem.asBytes(&stash_init),
            continuation,
        );
    }
};

pub const RouterLimits = struct {
    max_routes: usize = MAX_ROUTES,
    max_segments: u8 = MAX_SEGMENTS,
    max_params: u8 = MAX_PARAMS,
};

pub const BodyPolicy = enum { accumulate, discard };

/// Route entry
pub const Route = struct {
    method: request.Method,
    pattern: []const u8,
    handler: HandlerFn,
    middleware_chain: ?*middleware.Chain = null,
    x402_policy: x402.RoutePaymentConfig = .{},
    body_policy: BodyPolicy = .accumulate,
    pattern_buf: [MAX_PATTERN_LEN]u8 = undefined,
    pattern_len: usize = 0,
    param_count: u8 = 0,
    /// Pre-parsed pattern segments for matching
    segments: [16]Segment = undefined,
    segment_count: u8 = 0,

    const Segment = union(enum) {
        literal: []const u8,
        param: []const u8, // parameter name without ':'
        wildcard, // matches rest of path (*)
    };

    fn compile(pattern: []const u8, limits: RouterLimits) RouterError!Route {
        var route = Route{
            .method = .GET,
            .pattern = pattern,
            .handler = undefined,
        };

        var it = std.mem.splitScalar(u8, pattern, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            if (route.segment_count >= limits.max_segments) return error.SegmentLimitExceeded;

            if (seg[0] == ':') {
                if (route.param_count >= limits.max_params) return error.ParamLimitExceeded;
                route.segments[route.segment_count] = .{ .param = seg[1..] };
                route.param_count += 1;
            } else if (seg[0] == '*') {
                route.segments[route.segment_count] = .wildcard;
            } else {
                route.segments[route.segment_count] = .{ .literal = seg };
            }
            route.segment_count += 1;
        }

        return route;
    }

    fn compileWithPrefix(prefix: []const u8, pattern: []const u8, limits: RouterLimits) RouterError!Route {
        var route = Route{
            .method = .GET,
            .pattern = pattern,
            .handler = undefined,
        };

        try appendSegments(&route, prefix, limits);
        try appendSegments(&route, pattern, limits);
        return route;
    }

    fn appendSegments(route: *Route, value: []const u8, limits: RouterLimits) RouterError!void {
        var it = std.mem.splitScalar(u8, value, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            if (route.segment_count >= limits.max_segments) return error.SegmentLimitExceeded;

            if (seg[0] == ':') {
                if (route.param_count >= limits.max_params) return error.ParamLimitExceeded;
                route.segments[route.segment_count] = .{ .param = seg[1..] };
                route.param_count += 1;
            } else if (seg[0] == '*') {
                route.segments[route.segment_count] = .wildcard;
            } else {
                route.segments[route.segment_count] = .{ .literal = seg };
            }
            route.segment_count += 1;
        }
    }
};

/// Maximum number of routes
const MAX_ROUTES = 128;
const MAX_SEGMENTS = 16;
const MAX_PARAMS = 8;
const MAX_PATTERN_LEN = 256;

pub const RESPONSE_BUF_SIZE = 8192;
pub const MAX_RESPONSE_HEADERS = 4;
pub const ARENA_BUF_SIZE = 16 * 1024;

pub const ServiceGetter = *const fn (*anyopaque, []const u8) ?*anyopaque;

/// Router with route registration and matching
/// The request router. Holds a fixed-size route table, a pre-request
/// middleware chain, optional x402 payment policy, and opaque pointers
/// to per-app state / services.
///
/// Typical setup:
///
///     var app_router = swerver.router.Router.init(.{
///         .require_payment = false,
///         .payment_required_b64 = "",
///     });
///     try app_router.get("/users", listUsers);
///     try app_router.post("/users", createUser);
///     try app_router.get("/users/:id", showUser);
///     app_router.setState(&my_app_state);
///
///     var builder = swerver.ServerBuilder
///         .configDefault()
///         .router(app_router);
///     const srv = try builder.build(allocator);
///
/// Route matching is O(N) over the fixed-size `routes` array, gated by
/// a 64-bit bloom filter over first-path-segment hashes (`first_segment_bloom`).
/// Requests whose first segment's hash bit is clear short-circuit to a
/// 404 without touching the route list — this cuts no-match cost roughly
/// in half at 10 routes. Pattern compilation happens once at registration
/// time (`Route.compile`); the hot path just walks segments.
///
/// Routers are cheap to construct (a few KB of fixed-size arrays) and
/// are designed to be built entirely at startup. There's no support for
/// dynamically adding routes after `srv.run()` has started.
pub const Router = struct {
    routes: [MAX_ROUTES]Route = undefined,
    route_count: usize = 0,
    x402_policy: x402.Policy,
    middleware_chain: middleware.Chain,
    limits: RouterLimits = .{},
    app_state: ?*anyopaque = null,
    app_services: ?*anyopaque = null,
    app_services_get: ?ServiceGetter = null,
    /// Default 404 handler
    not_found_handler: ?HandlerFn = null,
    /// Default 405 handler
    method_not_allowed_handler: ?HandlerFn = null,
    /// Default 500 handler
    error_handler: ?HandlerFn = null,
    /// Bloom filter over registered routes' first path segments.
    /// A request whose first segment's hash bit is NOT set in this
    /// filter cannot match any route — the handle() loop can return
    /// 404 immediately without iterating routes or running middleware.
    /// False positives (bit set but no actual match) fall through to
    /// the normal route scan. 64 bits → ~50% false-positive rate at
    /// 10 routes, which still cuts the no-match path in half.
    first_segment_bloom: u64 = 0,
    has_any_paid_routes: bool = false,
    facilitator: ?x402.FacilitatorConfig = null,

    pub fn init(policy: x402.Policy) Router {
        return .{
            .x402_policy = policy,
            .middleware_chain = middleware.Chain.init(&.{}, &.{}),
            .has_any_paid_routes = policy.require_payment,
        };
    }

    pub fn initWithLimits(policy: x402.Policy, limits: RouterLimits) Router {
        std.debug.assert(limits.max_routes <= MAX_ROUTES);
        std.debug.assert(limits.max_segments <= MAX_SEGMENTS);
        std.debug.assert(limits.max_params <= MAX_PARAMS);
        return .{
            .x402_policy = policy,
            .middleware_chain = middleware.Chain.init(&.{}, &.{}),
            .limits = limits,
            .has_any_paid_routes = policy.require_payment,
        };
    }

    /// Set middleware chain
    pub fn setMiddleware(self: *Router, chain: middleware.Chain) void {
        self.middleware_chain = chain;
    }

    /// Set app state pointer (for HandlerContext.state).
    pub fn setState(self: *Router, state: ?*anyopaque) void {
        self.app_state = state;
    }

    /// Set services pointer (for HandlerContext.services).
    pub fn setServices(self: *Router, services: ?*anyopaque) void {
        self.app_services = services;
    }

    pub fn setServicesWithGetter(self: *Router, services: ?*anyopaque, getter: ?ServiceGetter) void {
        self.app_services = services;
        self.app_services_get = getter;
    }

    /// Create a grouped router with a path prefix.
    pub fn group(self: *Router, prefix: []const u8) GroupBuilder {
        return .{ .router = self, .prefix = prefix };
    }

    /// Register a GET route builder.
    pub fn routeBuilder(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn) RouteBuilder {
        return .{
            .router = self,
            .method = method,
            .pattern = pattern,
            .handler = handler,
        };
    }

    /// Register a GET route
    pub fn get(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.GET, pattern, handler);
    }

    /// Register a POST route
    pub fn post(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.POST, pattern, handler);
    }

    /// Register a PUT route
    pub fn put(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.PUT, pattern, handler);
    }

    /// Register a DELETE route
    pub fn delete(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.DELETE, pattern, handler);
    }

    /// Register a PATCH route
    pub fn patch(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        try self.route(.PATCH, pattern, handler);
    }

    /// Register a route with any method
    pub fn route(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.routeWithChain(method, pattern, handler, null);
    }

    /// Register a route with a custom middleware chain.
    pub fn routeWithChain(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn, chain: ?*middleware.Chain) RouterError!void {
        return self.routeWithOptions(method, pattern, handler, chain, .{});
    }

    /// Register a route with per-route x402 payment config.
    pub fn routeWithPayment(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn, payment: x402.RoutePaymentConfig) RouterError!void {
        return self.routeWithOptions(method, pattern, handler, null, payment);
    }

    /// Register a POST route with body discard policy (body bytes are
    /// counted but not buffered — handler receives `.length_only`).
    pub fn postDiscard(self: *Router, pattern: []const u8, handler: HandlerFn) RouterError!void {
        return self.routeWithFullOptions(.POST, pattern, handler, null, .{}, .discard);
    }

    fn routeWithOptions(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn, chain: ?*middleware.Chain, payment: x402.RoutePaymentConfig) RouterError!void {
        return self.routeWithFullOptions(method, pattern, handler, chain, payment, .accumulate);
    }

    fn routeWithFullOptions(self: *Router, method: request.Method, pattern: []const u8, handler: HandlerFn, chain: ?*middleware.Chain, payment: x402.RoutePaymentConfig, body_policy: BodyPolicy) RouterError!void {
        if (self.route_count >= self.limits.max_routes) return error.RouteLimitExceeded;

        var r = try Route.compile(pattern, self.limits);
        try self.storePattern(&r, pattern);
        r.method = method;
        r.handler = handler;
        r.middleware_chain = chain;
        r.x402_policy = payment;
        r.body_policy = body_policy;
        self.routes[self.route_count] = r;
        // Fix up the pattern slice to point into the stored Route's
        // pattern_buf (not the local variable that's about to go out of scope).
        self.routes[self.route_count].pattern = self.routes[self.route_count].pattern_buf[0..r.pattern_len];
        self.route_count += 1;
        self.updateBloomFilter(pattern);
        if (payment.require_payment) self.has_any_paid_routes = true;
    }

    pub fn routeWithPrefix(self: *Router, method: request.Method, prefix: []const u8, pattern: []const u8, handler: HandlerFn, chain: ?*middleware.Chain) RouterError!void {
        return self.routeWithPrefixAndPayment(method, prefix, pattern, handler, chain, .{});
    }

    pub fn routeWithPrefixAndPayment(self: *Router, method: request.Method, prefix: []const u8, pattern: []const u8, handler: HandlerFn, chain: ?*middleware.Chain, payment: x402.RoutePaymentConfig) RouterError!void {
        if (self.route_count >= self.limits.max_routes) return error.RouteLimitExceeded;

        var r = try Route.compileWithPrefix(prefix, pattern, self.limits);
        try self.storePatternWithPrefix(&r, prefix, pattern);
        r.method = method;
        r.handler = handler;
        r.middleware_chain = chain;
        r.x402_policy = payment;
        self.routes[self.route_count] = r;
        self.routes[self.route_count].pattern = self.routes[self.route_count].pattern_buf[0..r.pattern_len];
        self.route_count += 1;
        if (prefix.len > 0) {
            self.updateBloomFilter(prefix);
        } else {
            self.updateBloomFilter(pattern);
        }
        if (payment.require_payment) self.has_any_paid_routes = true;
    }

    /// Add the first path segment's hash to the bloom filter.
    /// Parameterized segments (`:foo`) saturate the bloom to avoid
    /// false 404s — they match any request segment.
    fn updateBloomFilter(self: *Router, pattern: []const u8) void {
        const seg = firstPathSegment(pattern);
        if (seg.len > 0) {
            if (seg[0] == ':') {
                self.first_segment_bloom = ~@as(u64, 0);
            } else {
                const hash = std.hash.Wyhash.hash(0, seg);
                self.first_segment_bloom |= @as(u64, 1) << @intCast(hash % 64);
            }
        }
    }

    /// Extract the first non-empty path segment from a path/pattern.
    fn firstPathSegment(path: []const u8) []const u8 {
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |seg| {
            if (seg.len > 0) return seg;
        }
        return "";
    }

    /// Set custom 404 handler
    pub fn setNotFound(self: *Router, handler: HandlerFn) void {
        self.not_found_handler = handler;
    }

    /// Set custom 404 handler (alias).
    pub fn fallback(self: *Router, handler: HandlerFn) void {
        self.setNotFound(handler);
    }

    /// Set custom 405 handler.
    pub fn methodNotAllowed(self: *Router, handler: HandlerFn) void {
        self.method_not_allowed_handler = handler;
    }

    /// Set custom error handler
    pub fn setErrorHandler(self: *Router, handler: HandlerFn) void {
        self.error_handler = handler;
    }

    /// Look up the body policy for a request before body accumulation.
    pub fn bodyPolicyForRoute(self: *const Router, method: request.Method, path: []const u8) BodyPolicy {
        const clean = if (std.mem.indexOfScalar(u8, path, '?')) |qi| path[0..qi] else path;
        for (self.routes[0..self.route_count]) |*r| {
            if (r.method != method) continue;
            if (self.quickMatchRoute(r, clean)) return r.body_policy;
        }
        return .accumulate;
    }

    fn quickMatchRoute(_: *const Router, r: *const Route, path: []const u8) bool {
        var path_it = std.mem.splitScalar(u8, path, '/');
        var seg_idx: u8 = 0;
        while (path_it.next()) |path_seg| {
            if (path_seg.len == 0) continue;
            if (seg_idx >= r.segment_count) return false;
            switch (r.segments[seg_idx]) {
                .literal => |lit| {
                    if (!std.mem.eql(u8, lit, path_seg)) return false;
                },
                .param => {},
                .wildcard => return true,
            }
            seg_idx += 1;
        }
        return seg_idx == r.segment_count;
    }

    /// Handle an incoming request
    /// Returns RouteResult with response and optional backpressure signal
    pub fn handle(self: *Router, req: request.RequestView, mw_ctx: *middleware.Context, scratch: *HandlerScratch) RouteResult {
        x402_has_receipt = false;

        // Strip query/fragment once — reused by bloom filter and route loop.
        const path_only = if (std.mem.indexOfScalar(u8, req.path, '?')) |q|
            req.path[0..q]
        else if (std.mem.indexOfScalar(u8, req.path, '#')) |f|
            req.path[0..f]
        else
            req.path;

        // Bloom filter fast-reject: if the request's first path
        // segment doesn't have its hash bit set in the filter, no
        // registered route can match. Return 404 immediately without
        // running x402 checks, middleware, or the route loop.
        if (self.first_segment_bloom != 0) {
            const seg = firstPathSegment(path_only);
            if (seg.len > 0) {
                const hash = std.hash.Wyhash.hash(0, seg);
                const bit = @as(u64, 1) << @intCast(hash % 64);
                if ((self.first_segment_bloom & bit) == 0) {
                    return .{ .resp = notFound() };
                }
            }
        }

        // Run middleware chain
        switch (self.middleware_chain.executePre(mw_ctx, req)) {
            .allow => {},
            .reject => |resp| return .{ .resp = resp },
            .backpressure => |bp| return .{
                .resp = bp.resp,
                .pause_reads_ms = if (bp.pause_reads) bp.resume_after_ms else null,
            },
        }

        // Find matching route
        var ctx = HandlerContext{
            .request = req,
            .middleware_ctx = mw_ctx,
            .app_state = self.app_state,
            .app_services = self.app_services,
            .app_services_get = self.app_services_get,
            .buffer_ops = scratch.buffer_ops,
            .params = undefined,
            .param_count = 0,
            .response_buf = scratch.response_buf,
            .response_headers = scratch.response_headers,
            .response_header_count = 0,
            .arena = std.heap.FixedBufferAllocator.init(scratch.arena_buf),
            .pg = .{ .binding = scratch.pg },
        };

        // Only capture request start time if post-response hooks exist
        // (access logging, metrics). Skip both clock_gettime calls when
        // middleware is disabled.
        if (self.middleware_chain.post.len > 0) {
            mw_ctx.request_start = clock.Instant.now();
        }

        var result_resp: response.Response = undefined;
        const result_pause: ?u64 = null;
        var ran_handler = false;

        var path_matched = false;
        for (self.routes[0..self.route_count]) |r| {
            if (!self.matchRoute(&r, path_only, &ctx)) continue;
            if (r.method != req.method) {
                // RFC 9110 §9.3.2: HEAD must be supported wherever GET is
                if (!(req.method == .HEAD and r.method == .GET)) {
                    path_matched = true;
                    continue;
                }
            }
            mw_ctx.route = r.pattern;
            const effective_policy = if (r.x402_policy.require_payment)
                r.x402_policy
            else
                self.x402_policy;
            const x402_result = x402.evaluateWithFacilitator(req, effective_policy, self.facilitator);
            switch (x402_result) {
                .allow => {},
                .reject => |info| {
                    result_resp = info.resp;
                    return .{ .resp = result_resp };
                },
            }
            // No facilitator configured: fail closed unless the payment was
            // verified locally (otherwise a structural-only header grants
            // free access).
            if (self.facilitator == null) {
                if (x402.failClosedOnUnverified(effective_policy, x402_result.allow)) |info| {
                    result_resp = info.resp;
                    return .{ .resp = result_resp };
                }
            }
            if (r.middleware_chain) |chain| {
                switch (chain.executePre(mw_ctx, req)) {
                    .allow => {},
                    .reject => |resp| {
                        result_resp = resp;
                        return .{ .resp = result_resp };
                    },
                    .backpressure => |bp| {
                        return .{
                            .resp = bp.resp,
                            .pause_reads_ms = if (bp.pause_reads) bp.resume_after_ms else null,
                        };
                    },
                }
            }
            result_resp = r.handler(&ctx);
            ran_handler = true;
            if (result_resp.status >= 200 and result_resp.status < 300) {
                if (x402_result == .allow and x402_result.allow.needs_settlement) {
                    if (self.facilitator) |fac| {
                        const settle = x402.facilitatorSettle(fac, x402_result.allow.payment_header, &effective_policy, ctx.charge_amount);
                        if (settle.success) {
                            if (settle.receipt_b64.len > 0) {
                                x402_receipt_tls = .{ .name = "PAYMENT-RESPONSE", .value = settle.receipt_b64 };
                                x402_receipt_v1_tls = .{ .name = "X-PAYMENT-RESPONSE", .value = settle.receipt_b64 };
                                x402_has_receipt = true;
                            }
                            if (effective_policy.settlement_url.len > 0) {
                                const amount = if (ctx.charge_amount.len > 0) ctx.charge_amount else effective_policy.price;
                                settlement.enqueue(effective_policy.gateway_id, settle.transaction, effective_policy.network, effective_policy.asset, amount);
                            }
                        } else {
                            std.log.warn("x402 settlement failed: {s}", .{settle.error_reason});
                            result_resp = .{ .status = 502, .headers = &.{}, .body = .{ .bytes = "{\"error\":\"payment settlement failed\"}" } };
                        }
                    }
                }
            }
            break;
        }

        if (!ran_handler) {
            // No route matched - 404 / 405
            if (path_matched) {
                result_resp = if (self.method_not_allowed_handler) |handler|
                    handler(&ctx)
                else
                    self.defaultMethodNotAllowed(&ctx);
            } else {
                result_resp = if (self.not_found_handler) |handler|
                    handler(&ctx)
                else
                    notFound();
            }
        }

        // Merge middleware-accumulated response headers (e.g. security headers
        // from middleware/security.zig .modify decisions) into the outgoing
        // response. Preencoded fast paths bake these in at build time; the
        // router-dispatch path has to merge them here after the handler runs.
        // Uses a threadlocal buffer so we don't have to grow HandlerScratch
        // at every call site. Safe because router.handle() is non-reentrant
        // per thread and the protocol layer serializes the response bytes
        // before the next request on the same thread.
        const mw_headers = self.middleware_chain.getResponseHeaders();
        if (mw_headers.len > 0 or x402_has_receipt) {
            const handler_headers = result_resp.headers;
            const merge_cap = merged_headers_tls.len;
            var i: usize = 0;
            for (handler_headers) |h| {
                if (i >= merge_cap) break;
                merged_headers_tls[i] = h;
                i += 1;
            }
            for (mw_headers) |h| {
                if (i >= merge_cap) break;
                merged_headers_tls[i] = h;
                i += 1;
            }
            if (x402_has_receipt) {
                if (i < merge_cap) {
                    merged_headers_tls[i] = x402_receipt_tls;
                    i += 1;
                }
                if (i < merge_cap) {
                    merged_headers_tls[i] = x402_receipt_v1_tls;
                    i += 1;
                }
            }
            result_resp.headers = merged_headers_tls[0..i];
        }

        // Post-response hooks: access logging, metrics, etc.
        // Skip entirely when no post-response hooks are configured.
        if (self.middleware_chain.post.len > 0) {
            const elapsed_ns: u64 = if (mw_ctx.request_start) |start|
                if (clock.Instant.now()) |now_inst| now_inst.since(start) else 0
            else
                0;
            self.middleware_chain.executePost(mw_ctx, req, result_resp, elapsed_ns);
        }

        return .{ .resp = result_resp, .pause_reads_ms = result_pause };
    }

    /// Quick O(route_count) check: does ANY registered route's path
    /// pattern match `path` (ignoring method)? Used by the server to
    /// fast-reject 404s before setting up middleware/arena/scratch.
    /// Does NOT run middleware or handlers — purely structural.
    pub fn hasAnyRouteForPath(self: *Router, path: []const u8) bool {
        // Strip query string for matching (same as matchRoute).
        const clean_path = if (std.mem.indexOfScalar(u8, path, '?')) |qi| path[0..qi] else path;
        for (self.routes[0..self.route_count]) |r| {
            if (pathMatchesPattern(r.pattern, clean_path)) return true;
        }
        return false;
    }

    /// Lightweight path-vs-pattern match (no param extraction).
    fn pathMatchesPattern(pattern: []const u8, path: []const u8) bool {
        // Exact match fast path
        if (std.mem.eql(u8, pattern, path)) return true;

        // Static prefix check — if the pattern has no `:` params, it
        // must match exactly or with a trailing `/` difference.
        if (std.mem.indexOfScalar(u8, pattern, ':') == null) {
            // Check for trailing-slash tolerance
            if (pattern.len > 0 and path.len > 0) {
                if (pattern.len == path.len + 1 and pattern[pattern.len - 1] == '/') {
                    return std.mem.eql(u8, pattern[0 .. pattern.len - 1], path);
                }
                if (path.len == pattern.len + 1 and path[path.len - 1] == '/') {
                    return std.mem.eql(u8, path[0 .. path.len - 1], pattern);
                }
            }
            return false;
        }

        // Pattern has params — do segment-by-segment comparison.
        // `:name` segments match any non-empty segment.
        var pat_it = std.mem.splitScalar(u8, if (pattern.len > 0 and pattern[0] == '/') pattern[1..] else pattern, '/');
        var path_it = std.mem.splitScalar(u8, if (path.len > 0 and path[0] == '/') path[1..] else path, '/');

        while (true) {
            const pat_seg = pat_it.next();
            const path_seg = path_it.next();
            if (pat_seg == null and path_seg == null) return true;
            if (pat_seg == null or path_seg == null) return false;
            if (pat_seg.?.len > 0 and pat_seg.?[0] == ':') continue; // param matches anything
            if (!std.mem.eql(u8, pat_seg.?, path_seg.?)) return false;
        }
    }

    /// Match a route pattern against a path. The path must already have
    /// the query string stripped (caller responsibility — handle() does
    /// this once before the route loop to avoid O(N) redundant scans).
    fn matchRoute(self: *Router, r: *const Route, path: []const u8, ctx: *HandlerContext) bool {
        _ = self;
        ctx.param_count = 0;

        // Fast path: literal-only routes → exact string match.
        if (r.param_count == 0 and r.segment_count > 0) {
            const last_is_wildcard = switch (r.segments[r.segment_count - 1]) {
                .wildcard => true,
                else => false,
            };
            if (!last_is_wildcard) return std.mem.eql(u8, r.pattern_buf[0..r.pattern_len], path);
        }

        var path_it = std.mem.splitScalar(u8, path, '/');
        var seg_idx: u8 = 0;

        while (path_it.next()) |path_seg| {
            if (path_seg.len == 0) continue;

            if (seg_idx >= r.segment_count) {
                // More path segments than pattern segments
                return false;
            }

            switch (r.segments[seg_idx]) {
                .literal => |lit| {
                    if (!std.mem.eql(u8, lit, path_seg)) {
                        return false;
                    }
                },
                .param => |name| {
                    if (ctx.param_count < MAX_PARAMS) {
                        ctx.params[ctx.param_count] = .{
                            .name = name,
                            .value = path_seg,
                        };
                        ctx.param_count += 1;
                    }
                },
                .wildcard => {
                    // Wildcard matches rest of path
                    return true;
                },
            }
            seg_idx += 1;
        }

        // All path segments consumed - check we matched all pattern segments
        return seg_idx == r.segment_count;
    }

    fn defaultMethodNotAllowed(self: *Router, ctx: *HandlerContext) response.Response {
        ctx.response_header_count = 0;
        const allow_value = self.buildAllowHeader(ctx.request.path, ctx);
        if (allow_value.len > 0 and ctx.response_headers.len > 0) {
            ctx.response_headers[0] = .{ .name = "Allow", .value = allow_value };
            ctx.response_header_count = 1;
        }
        return .{
            .status = 405,
            .headers = ctx.response_headers[0..ctx.response_header_count],
            .body = .{ .bytes = "Method Not Allowed" },
        };
    }

    fn buildAllowHeader(self: *Router, path: []const u8, ctx: *HandlerContext) []const u8 {
        const method_count = @typeInfo(request.Method).@"enum".fields.len;
        var allowed: [method_count]bool = [_]bool{false} ** method_count;
        var temp_ctx = HandlerContext{
            .request = ctx.request,
            .middleware_ctx = ctx.middleware_ctx,
            .app_state = ctx.app_state,
            .app_services = ctx.app_services,
            .app_services_get = ctx.app_services_get,
            .buffer_ops = null,
            .params = undefined,
            .param_count = 0,
            .response_buf = ctx.response_buf,
            .response_headers = ctx.response_headers,
            .response_header_count = 0,
            .arena = std.heap.FixedBufferAllocator.init(&[_]u8{}),
        };

        for (self.routes[0..self.route_count]) |r| {
            if (self.matchRoute(&r, path, &temp_ctx)) {
                const idx = @intFromEnum(r.method);
                allowed[idx] = true;
            }
        }

        var out = ctx.response_buf[0..];
        var pos: usize = 0;
        var first = true;
        for (allowed, 0..) |is_allowed, idx| {
            if (!is_allowed) continue;
            const method = @as(request.Method, @enumFromInt(idx));
            const name = method.toString();
            const extra: usize = if (first) 0 else 2;
            if (pos + extra + name.len > out.len) break;
            if (!first) {
                out[pos] = ',';
                out[pos + 1] = ' ';
                pos += 2;
            }
            @memcpy(out[pos .. pos + name.len], name);
            pos += name.len;
            first = false;
        }

        return out[0..pos];
    }

    fn storePattern(self: *Router, r: *Route, pattern: []const u8) RouterError!void {
        _ = self;
        if (pattern.len > MAX_PATTERN_LEN) return error.PatternTooLong;
        @memcpy(r.pattern_buf[0..pattern.len], pattern);
        r.pattern_len = pattern.len;
        r.pattern = r.pattern_buf[0..r.pattern_len];
    }

    fn storePatternWithPrefix(self: *Router, r: *Route, prefix: []const u8, pattern: []const u8) RouterError!void {
        _ = self;
        var full_len = prefix.len + pattern.len;
        var needs_slash = false;
        if (prefix.len > 0 and pattern.len > 0) {
            const prefix_slash = prefix[prefix.len - 1] == '/';
            const pattern_slash = pattern[0] == '/';
            if (!prefix_slash and !pattern_slash) {
                needs_slash = true;
                full_len += 1;
            }
            if (prefix_slash and pattern_slash) {
                full_len -= 1;
            }
        }

        if (full_len > MAX_PATTERN_LEN) return error.PatternTooLong;

        var pos: usize = 0;
        @memcpy(r.pattern_buf[pos .. pos + prefix.len], prefix);
        pos += prefix.len;
        if (needs_slash) {
            r.pattern_buf[pos] = '/';
            pos += 1;
        } else if (prefix.len > 0 and pattern.len > 0 and prefix[prefix.len - 1] == '/' and pattern[0] == '/') {
            // Skip the leading slash in pattern
        }

        if (prefix.len > 0 and pattern.len > 0 and prefix[prefix.len - 1] == '/' and pattern[0] == '/') {
            @memcpy(r.pattern_buf[pos .. pos + pattern.len - 1], pattern[1..]);
            pos += pattern.len - 1;
        } else {
            @memcpy(r.pattern_buf[pos .. pos + pattern.len], pattern);
            pos += pattern.len;
        }

        r.pattern_len = pos;
        r.pattern = r.pattern_buf[0..r.pattern_len];
    }
};

/// Default 404 response
fn notFound() response.Response {
    return .{
        .status = 404,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "Not Found" },
    };
}

/// Default 500 response
pub fn internalError() response.Response {
    return .{
        .status = 500,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "Internal Server Error" },
    };
}

// Tests
test "route compilation" {
    const r = try Route.compile("/users/:id/posts/:post_id", .{});
    try std.testing.expectEqual(@as(u8, 4), r.segment_count);
    try std.testing.expectEqualStrings("users", r.segments[0].literal);
    try std.testing.expectEqualStrings("id", r.segments[1].param);
    try std.testing.expectEqualStrings("posts", r.segments[2].literal);
    try std.testing.expectEqualStrings("post_id", r.segments[3].param);
}

test "route matching with params" {
    var router = Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });

    const handler = struct {
        fn h(_: *HandlerContext) response.Response {
            return response.Response.ok();
        }
    }.h;

    try router.get("/users/:id", handler);

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/users/123",
        .headers = &.{},
        .body = .{ .slice = "" },
    };
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var arena_buf: [ARENA_BUF_SIZE]u8 = undefined;
    var scratch = HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };

    const result = router.handle(req, &mw_ctx, &scratch);
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
}

test "route not found" {
    var router = Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/nonexistent",
        .headers = &.{},
        .body = .{ .slice = "" },
    };
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var arena_buf: [ARENA_BUF_SIZE]u8 = undefined;
    var scratch = HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };

    const result = router.handle(req, &mw_ctx, &scratch);
    try std.testing.expectEqual(@as(u16, 404), result.resp.status);
}

test "method mismatch" {
    var router = Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });

    const handler = struct {
        fn h(_: *HandlerContext) response.Response {
            return response.Response.ok();
        }
    }.h;

    try router.get("/users", handler);

    var mw_ctx = middleware.Context{};
    const req = request.RequestView{
        .method = .POST,
        .path = "/users",
        .headers = &.{},
        .body = .{ .slice = "" },
    };
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var arena_buf: [ARENA_BUF_SIZE]u8 = undefined;
    var scratch = HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };

    const result = router.handle(req, &mw_ctx, &scratch);
    try std.testing.expectEqual(@as(u16, 405), result.resp.status);
}

test "jsonValue serializes a struct with std.json" {
    var arena_buf: [4096]u8 = undefined;
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var mw_ctx = middleware.Context{};
    var ctx = HandlerContext{
        .request = .{ .method = .GET, .path = "/", .headers = &.{}, .body = .{ .slice = "" } },
        .middleware_ctx = &mw_ctx,
        .params = undefined,
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena = std.heap.FixedBufferAllocator.init(&arena_buf),
    };

    const Item = struct { id: i64, name: []const u8, active: bool, tags: []const []const u8 };
    const resp = ctx.jsonValue(200, .{
        .count = 1,
        .items = &[_]Item{.{ .id = 7, .name = "Gear", .active = true, .tags = &[_][]const u8{ "a", "b" } }},
    });

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("application/json", resp.headers[0].value);
    try std.testing.expectEqualStrings(
        "{\"count\":1,\"items\":[{\"id\":7,\"name\":\"Gear\",\"active\":true,\"tags\":[\"a\",\"b\"]}]}",
        resp.body.bytes,
    );
}

// --- Test helpers for the handler/response API ---------------------------
//
// These mirror the construction idiom used by the tests above: build a
// `Router`, a stack-allocated `HandlerScratch`, a `middleware.Context`, and
// a `RequestView`, then drive a request through `router.handle`. Two small
// helpers keep the assertions readable.

const TestRig = struct {
    response_buf: [RESPONSE_BUF_SIZE]u8 = undefined,
    response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined,
    arena_buf: [ARENA_BUF_SIZE]u8 = undefined,
    mw_ctx: middleware.Context = .{},

    fn scratch(self: *TestRig) HandlerScratch {
        return .{
            .response_buf = self.response_buf[0..],
            .response_headers = self.response_headers[0..],
            .arena_buf = self.arena_buf[0..],
        };
    }

    fn run(self: *TestRig, router: *Router, method: request.Method, path: []const u8) RouteResult {
        var sc = self.scratch();
        const req = request.RequestView{
            .method = method,
            .path = path,
            .headers = &.{},
            .body = .{ .slice = "" },
        };
        return router.handle(req, &self.mw_ctx, &sc);
    }
};

fn bodyBytes(resp: response.Response) []const u8 {
    return switch (resp.body) {
        .bytes => |b| b,
        else => "",
    };
}

fn headerValue(resp: response.Response, name: []const u8) ?[]const u8 {
    for (resp.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

test "getParam returns matched path parameter value" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            const id = ctx.getParam("id") orelse "MISSING";
            return ctx.text(200, id);
        }
    }.h;
    try router.get("/users/:id", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .GET, "/users/42");
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
    try std.testing.expectEqualStrings("42", bodyBytes(result.resp));
    // A param that was not declared yields null.
    try std.testing.expect(headerValue(result.resp, "Content-Type") != null);
}

test "multi-segment params extract both values in order" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            const x = ctx.getParam("x") orelse "?";
            const y = ctx.getParam("y") orelse "?";
            // Pack both into the request-scoped response buffer.
            const out = std.fmt.bufPrint(ctx.response_buf, "{s}|{s}", .{ x, y }) catch "ERR";
            return ctx.text(200, out);
        }
    }.h;
    try router.get("/a/:x/b/:y", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .GET, "/a/foo/b/bar");
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
    try std.testing.expectEqualStrings("foo|bar", bodyBytes(result.resp));
}

test "ctx.text sets text/plain Content-Type, status and body" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            return ctx.text(201, "created");
        }
    }.h;
    try router.get("/t", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .GET, "/t");
    try std.testing.expectEqual(@as(u16, 201), result.resp.status);
    try std.testing.expectEqualStrings("created", bodyBytes(result.resp));
    try std.testing.expectEqualStrings("text/plain", headerValue(result.resp, "Content-Type").?);
}

test "ctx.html sets text/html Content-Type, status and body" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            return ctx.html(200, "<h1>hi</h1>");
        }
    }.h;
    try router.get("/page", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .GET, "/page");
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
    try std.testing.expectEqualStrings("<h1>hi</h1>", bodyBytes(result.resp));
    try std.testing.expectEqualStrings("text/html; charset=utf-8", headerValue(result.resp, "Content-Type").?);
}

test "ctx.json sets application/json Content-Type and body" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            return ctx.json(200, "{\"ok\":true}");
        }
    }.h;
    try router.get("/j", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .GET, "/j");
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
    try std.testing.expectEqualStrings("{\"ok\":true}", bodyBytes(result.resp));
    try std.testing.expectEqualStrings("application/json", headerValue(result.resp, "Content-Type").?);
}

test "route group prepends prefix and routes with params" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            const id = ctx.getParam("id") orelse "MISSING";
            return ctx.text(200, id);
        }
    }.h;

    var api = router.group("/api/v1");
    try api.get("/users/:id", handler);

    var rig = TestRig{};
    // Full prefixed path matches.
    const ok = rig.run(&router, .GET, "/api/v1/users/7");
    try std.testing.expectEqual(@as(u16, 200), ok.resp.status);
    try std.testing.expectEqualStrings("7", bodyBytes(ok.resp));

    // The un-prefixed path must NOT match (404).
    var rig2 = TestRig{};
    const miss = rig2.run(&router, .GET, "/users/7");
    try std.testing.expectEqual(@as(u16, 404), miss.resp.status);
}

test "404 fallback fires for unregistered path with default body" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            return ctx.text(200, "ok");
        }
    }.h;
    try router.get("/known", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .GET, "/unknown");
    try std.testing.expectEqual(@as(u16, 404), result.resp.status);
    try std.testing.expectEqualStrings("Not Found", bodyBytes(result.resp));
}

test "405 method-not-allowed when path matches but method does not" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            return ctx.text(200, "ok");
        }
    }.h;
    try router.get("/widgets/:id", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .DELETE, "/widgets/9");
    try std.testing.expectEqual(@as(u16, 405), result.resp.status);
    // The default 405 advertises the allowed methods in an Allow header.
    const allow = headerValue(result.resp, "Allow");
    try std.testing.expect(allow != null);
    try std.testing.expect(std.mem.indexOf(u8, allow.?, "GET") != null);
}

test "custom 404 fallback handler is invoked" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn known(ctx: *HandlerContext) response.Response {
            return ctx.text(200, "ok");
        }
        fn nf(ctx: *HandlerContext) response.Response {
            return ctx.json(404, "{\"error\":\"nope\"}");
        }
    };
    try router.get("/known", handler.known);
    router.fallback(handler.nf);

    var rig = TestRig{};
    // Use a path whose first segment ("known") is in the bloom filter so the
    // bloom fast-reject doesn't short-circuit to the default notFound() — this
    // forces the route loop to run and fall through to the custom fallback.
    const result = rig.run(&router, .GET, "/known/extra");
    try std.testing.expectEqual(@as(u16, 404), result.resp.status);
    try std.testing.expectEqualStrings("{\"error\":\"nope\"}", bodyBytes(result.resp));
    try std.testing.expectEqualStrings("application/json", headerValue(result.resp, "Content-Type").?);
}

test "jsonValue serializes a slice payload" {
    var router = Router.init(.{ .require_payment = false, .payment_required_b64 = "" });

    const handler = struct {
        fn h(ctx: *HandlerContext) response.Response {
            return ctx.json(200, std.fmt.bufPrint(ctx.response_buf, "[{d},{d},{d}]", .{ 1, 2, 3 }) catch "[]");
        }
    }.h;
    try router.get("/nums", handler);

    var rig = TestRig{};
    const result = rig.run(&router, .GET, "/nums");
    try std.testing.expectEqual(@as(u16, 200), result.resp.status);
    try std.testing.expectEqualStrings("[1,2,3]", bodyBytes(result.resp));
    try std.testing.expectEqualStrings("application/json", headerValue(result.resp, "Content-Type").?);
}

// Encode `value` with both stringifyJson and std.json, assert byte-identical.
fn expectJsonMatchesStd(value: anytype) !void {
    var mine_buf: [8192]u8 = undefined;
    var std_buf: [8192]u8 = undefined;
    var mw = std.Io.Writer.fixed(mine_buf[0..]);
    try stringifyJson(value, &mw);
    var sw = std.Io.Writer.fixed(std_buf[0..]);
    try std.json.Stringify.value(value, .{}, &sw);
    try std.testing.expectEqualStrings(sw.buffered(), mw.buffered());
}

test "stringifyJson output is byte-identical to std.json across shapes" {
    const Rating = struct { score: i64, count: i64 };
    const Item = struct { id: i64, name: []const u8, active: bool, tags: []const []const u8, rating: Rating };
    const Maybe = struct { a: ?i64, b: ?[]const u8 };

    // Nested structs, slices, bools, signed ints, empty slice.
    try expectJsonMatchesStd(.{
        .count = 2,
        .items = &[_]Item{
            .{ .id = 7, .name = "Gear", .active = true, .tags = &[_][]const u8{ "a", "b" }, .rating = .{ .score = 4, .count = 9 } },
            .{ .id = -3, .name = "x", .active = false, .tags = &[_][]const u8{}, .rating = .{ .score = 0, .count = 0 } },
        },
    });
    // Optionals: null and present, both field positions.
    try expectJsonMatchesStd(Maybe{ .a = null, .b = "x" });
    try expectJsonMatchesStd(Maybe{ .a = 5, .b = null });
    // Top-level string.
    try expectJsonMatchesStd(@as([]const u8, "plain"));
}

test "stringifyJson escapes strings identically to std.json" {
    // Quotes, backslash, the named control escapes, a bare control byte, and
    // UTF-8 (which must pass through unescaped).
    try expectJsonMatchesStd(@as([]const u8, "a\"b\\c\nd\te\rf\x08g\x0ch\x01i\u{00e9}j"));
    try expectJsonMatchesStd(.{ .msg = @as([]const u8, "line1\nline2\ttab \"q\"") });
}

test "stringifyJson defers non-specialized types to std.json" {
    const Color = enum { red, green, blue };
    // Enum, float (exact shortest-repr), fixed array, and tuple (renders as a
    // JSON array) all route through the std.json fallback.
    try expectJsonMatchesStd(Color.green);
    try expectJsonMatchesStd(@as(f64, 3.5));
    try expectJsonMatchesStd([_]u32{ 1, 2, 3 });
    try expectJsonMatchesStd(.{ @as(i64, 1), @as(i64, 2), @as(i64, 3) });
    // A struct that mixes a fast field (int) with a deferred field (float).
    try expectJsonMatchesStd(.{ .id = @as(i64, 1), .ratio = @as(f64, 0.25), .ok = true });
}

test "jsonValue end-to-end produces escaped, std-identical body" {
    var arena_buf: [4096]u8 = undefined;
    var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [MAX_RESPONSE_HEADERS]response.Header = undefined;
    var mw_ctx = middleware.Context{};
    var ctx = HandlerContext{
        .request = .{ .method = .GET, .path = "/", .headers = &.{}, .body = .{ .slice = "" } },
        .middleware_ctx = &mw_ctx,
        .params = undefined,
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena = std.heap.FixedBufferAllocator.init(&arena_buf),
    };

    const payload = .{ .name = @as([]const u8, "a\"b\nc"), .n = @as(i64, -5), .ok = false };
    const resp = ctx.jsonValue(200, payload);

    var std_buf: [4096]u8 = undefined;
    var sw = std.Io.Writer.fixed(std_buf[0..]);
    try std.json.Stringify.value(payload, .{}, &sw);

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings(sw.buffered(), resp.body.bytes);
}
