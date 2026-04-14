//! Middleware framework.
//!
//! Middleware in swerver is a chain of pre-request function pointers
//! that run before the router handler, plus a chain of post-response
//! function pointers that run after the handler returns. Both chains
//! are zero-allocation hot-path code — the call happens through a
//! static `Chain` struct that holds two `[]const …Fn` slices, and every
//! evaluation is a linear walk over them.
//!
//! Pre-request middleware returns a `Decision` that controls what the
//! router does next: continue the chain, short-circuit with a response,
//! inject response headers, or apply rate-limit backpressure. Post-
//! response middleware runs for side effects only (access logs,
//! metrics, tracing) and has no return value.
//!
//! The whole system works identically across HTTP/1.1, HTTP/2, and
//! HTTP/3 — the protocol layer sets `Context.protocol` and, for h2/h3,
//! `Context.stream_id` before dispatching, so middleware can observe
//! per-stream detail without knowing which version it's running under.

const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");
const clock = @import("../runtime/clock.zig");

/// The outcome of a pre-request middleware evaluation.
///
/// Each middleware in the chain returns one of these. The Chain's
/// evaluation loop honors the first non-`.allow` decision from the
/// front of the chain and acts on it:
///   - `.allow` — advance to the next middleware (or the handler).
///   - `.modify` — accumulate headers into the Chain's threadlocal
///     header buffer; the router merges them with the handler's
///     response before serialization. `continue_chain = true` advances
///     to the next middleware; `false` short-circuits to the handler.
///   - `.reject` — stop dispatching, return this response immediately.
///     The router still runs post-response middleware on it.
///   - `.skip` — skip remaining pre-request middleware and go straight
///     to the handler. Used by pre-hooks that want to bypass other
///     pre-hooks for their specific case (e.g. health probes).
///   - `.rate_limit_backpressure` — send the included 429 response and
///     ask the server to pause reads on the connection for the given
///     duration before the next request. Server integration is
///     optional; middleware that doesn't need backpressure just uses
///     `.reject` instead.
pub const Decision = union(enum) {
    /// Allow request to continue to next middleware/handler
    allow,
    /// Modify and continue (for adding headers, etc.)
    modify: Modification,
    /// Reject request with immediate response
    reject: response.Response,
    /// Skip remaining middleware and go directly to handler
    skip,
    /// Rate limit with backpressure - pause reads until tokens available
    rate_limit_backpressure: BackpressureInfo,
};

/// Backpressure information for rate limiting
pub const BackpressureInfo = struct {
    /// Response to send (429)
    resp: response.Response,
    /// Whether to pause reads on the connection
    pause_reads: bool = true,
    /// Time in milliseconds until reads should resume
    resume_after_ms: u64 = 0,
};

/// Modifications that can be applied to requests/responses
pub const Modification = struct {
    /// Headers to add to response
    response_headers: []const response.Header = &.{},
    /// Whether to continue to next middleware
    continue_chain: bool = true,
};

/// Per-request, per-connection context passed into every middleware
/// and handler. Populated by the protocol layer (h1/h2/h3) when a
/// request comes in and reset between requests on the same connection.
///
/// Not all fields are populated in all cases — some are protocol-
/// specific (`stream_id` is 0 for HTTP/1.1 and set for h2/h3) and
/// some depend on whether the server has access to the data (e.g.
/// `client_ip` is only set when the connection was accepted through
/// a codepath that filled it in).
pub const Context = struct {
    /// Client IP address (if available)
    client_ip: ?[4]u8 = null,
    /// Client IPv6 address (if available)
    client_ip6: ?[16]u8 = null,
    /// Protocol in use
    protocol: Protocol = .http1,
    /// HTTP/2 or HTTP/3 stream ID (0 for HTTP/1.1)
    stream_id: u64 = 0,
    /// Connection start time
    conn_start: ?clock.Instant = null,
    /// Request start time
    request_start: ?clock.Instant = null,
    /// Whether connection is TLS
    is_tls: bool = false,
    /// Request ID (from header or generated) - slice into request_id_buf
    request_id: ?[]const u8 = null,
    /// Storage for request ID (lives with context)
    request_id_buf: [64]u8 = undefined,
    request_id_len: u8 = 0,
    /// Route matched (if any)
    route: ?[]const u8 = null,
    /// Buffer operations for managed response bodies
    buffer_ops: ?BufferOps = null,

    /// Set request ID and update slice
    pub fn setRequestId(self: *Context, id: []const u8) void {
        const copy_len = @min(id.len, 64);
        @memcpy(self.request_id_buf[0..copy_len], id[0..copy_len]);
        self.request_id_len = @intCast(copy_len);
        self.request_id = self.request_id_buf[0..self.request_id_len];
    }

    /// Generate a request ID derived from a realtime-nanosecond seed.
    /// The 16-hex-char format is compact enough to fit in a log line
    /// without truncation and random enough that collisions across a
    /// reasonable time window are negligible.
    pub fn generateRequestId(self: *Context) void {
        const realtime_ns = clock.realtimeNanos() orelse 0;
        const ts: u64 = @intCast(@mod(realtime_ns, std.math.maxInt(u64)));
        const hash = std.hash.Wyhash.hash(ts, &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 });
        const result = std.fmt.bufPrint(&self.request_id_buf, "{x:0>16}", .{hash}) catch {
            self.request_id_len = 0;
            self.request_id = null;
            return;
        };
        self.request_id_len = @intCast(result.len);
        self.request_id = self.request_id_buf[0..self.request_id_len];
    }

    pub const Protocol = enum {
        http1,
        http2,
        http3,

        pub fn toString(self: Protocol) []const u8 {
            return switch (self) {
                .http1 => "http/1.1",
                .http2 => "http/2",
                .http3 => "http/3",
            };
        }
    };
};

pub const BufferOps = struct {
    ctx: *anyopaque,
    acquire: *const fn (*anyopaque) ?buffer_pool.BufferHandle,
    release: *const fn (*anyopaque, buffer_pool.BufferHandle) void,
};

pub fn respondManaged(ctx: *Context, status: u16, content_type: []const u8, body: []const u8) ?response.Response {
    const ops = ctx.buffer_ops orelse return null;
    const handle = ops.acquire(ops.ctx) orelse return null;
    if (body.len > handle.bytes.len) {
        ops.release(ops.ctx, handle);
        return null;
    }
    @memcpy(handle.bytes[0..body.len], body);
    return response.Response{
        .status = status,
        .headers = &[_]response.Header{
            .{ .name = "Content-Type", .value = content_type },
        },
        .body = .{ .managed = .{ .handle = handle, .len = body.len } },
    };
}

/// Pre-request middleware function. Called with the per-connection
/// `Context` and the parsed `RequestView` (headers + body as borrowed
/// slices). Returns a `Decision` that steers the Chain. Must be pure
/// or use its own per-thread state — the hot path gives it no allocator.
pub const MiddlewareFn = *const fn (ctx: *Context, req: request.RequestView) Decision;

/// Post-response hook function. Called after the handler returns and
/// the response has been serialized, with the finalized response and
/// the elapsed nanoseconds since the request started. Runs for side
/// effects only — access logs, metrics, tracing spans. The return
/// type is `void`: a post-hook can't affect what goes out on the wire,
/// it can only observe.
pub const PostResponseFn = *const fn (ctx: *Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) void;

/// Aggregated outcome of a full pre-request chain evaluation. The
/// router uses this to decide whether to dispatch the handler, serve
/// an immediate response, or apply backpressure.
pub const PreResult = union(enum) {
    /// Request should continue to handler
    allow,
    /// Request rejected with response
    reject: response.Response,
    /// Request rate limited with backpressure
    backpressure: BackpressureInfo,
};

/// A pair of middleware slices — one pre-request, one post-response —
/// plus scratch space for headers that pre-hooks inject via `.modify`.
///
/// Constructed once at startup, usually by the benchmark-app helper or
/// an application's own setup code, and shared across every request on
/// a single router. The slice fields are borrowed — typical usage is:
///
///     const pre_hooks = [_]MiddlewareFn{ security.evaluate, auth.check };
///     const post_hooks = [_]PostResponseFn{ access_log.postResponse };
///     var chain = Chain.init(&pre_hooks, &post_hooks);
///     app_router.setMiddleware(chain);
///
/// `response_headers` is an instance-local buffer that accumulates
/// header additions from `.modify` decisions between `executePre` and
/// the router's header merge. `executePre` resets the count at the
/// start of every call, so a previous request's headers can't leak
/// into the next one.
///
/// The buffer is sized to `MAX_MIDDLEWARE_HEADERS` (16) entries —
/// enough for HSTS, CSP, X-Frame-Options, Referrer-Policy, CORS, and
/// a few app-specific additions. Overflows are silently dropped, so
/// keep the per-middleware `response_headers` slice small.
pub const Chain = struct {
    /// Pre-request middleware (run before handler)
    pre: []const MiddlewareFn,
    /// Post-response hooks (run after response)
    post: []const PostResponseFn,
    /// Accumulated response headers from modifications
    response_headers: [MAX_MIDDLEWARE_HEADERS]response.Header = undefined,
    response_header_count: usize = 0,

    pub const MAX_MIDDLEWARE_HEADERS = 16;

    pub fn init(pre: []const MiddlewareFn, post: []const PostResponseFn) Chain {
        return .{
            .pre = pre,
            .post = post,
        };
    }

    /// Execute pre-request middleware chain
    /// Returns result indicating how to proceed
    pub fn executePre(self: *Chain, ctx: *Context, req: request.RequestView) PreResult {
        self.response_header_count = 0;

        for (self.pre) |middleware| {
            const decision = middleware(ctx, req);
            switch (decision) {
                .allow => continue,
                .modify => |mod| {
                    // Accumulate response headers
                    for (mod.response_headers) |hdr| {
                        if (self.response_header_count < MAX_MIDDLEWARE_HEADERS) {
                            self.response_headers[self.response_header_count] = hdr;
                            self.response_header_count += 1;
                        }
                    }
                    if (!mod.continue_chain) break;
                },
                .reject => |resp| return .{ .reject = resp },
                .skip => break,
                .rate_limit_backpressure => |bp| return .{ .backpressure = bp },
            }
        }
        return .allow;
    }

    /// Execute post-response hooks
    pub fn executePost(self: *Chain, ctx: *Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) void {
        for (self.post) |hook| {
            hook(ctx, req, resp, elapsed_ns);
        }
    }

    /// Get accumulated response headers from middleware
    pub fn getResponseHeaders(self: *const Chain) []const response.Header {
        return self.response_headers[0..self.response_header_count];
    }
};

/// Pre-allocated buffer for formatting without heap allocations
pub const FormatBuffer = struct {
    buf: [BUFFER_SIZE]u8 = undefined,
    len: usize = 0,

    const BUFFER_SIZE = 4096;

    pub fn reset(self: *FormatBuffer) void {
        self.len = 0;
    }

    pub fn append(self: *FormatBuffer, data: []const u8) void {
        const copy_len = @min(data.len, BUFFER_SIZE - self.len);
        @memcpy(self.buf[self.len .. self.len + copy_len], data[0..copy_len]);
        self.len += copy_len;
    }

    pub fn appendFmt(self: *FormatBuffer, comptime fmt: []const u8, args: anytype) void {
        const remaining = self.buf[self.len..];
        const result = std.fmt.bufPrint(remaining, fmt, args) catch {
            // Buffer full, truncate
            self.len = BUFFER_SIZE;
            return;
        };
        self.len += result.len;
    }

    pub fn slice(self: *const FormatBuffer) []const u8 {
        return self.buf[0..self.len];
    }
};

// Re-export sub-middleware modules
pub const health = @import("health.zig");
pub const metrics = @import("metrics_mw.zig");
pub const access_log = @import("access_log.zig");
pub const ratelimit = @import("ratelimit.zig");
pub const security = @import("security.zig");
pub const observability = @import("observability.zig");
pub const x402 = @import("x402.zig");

// Tests
test "chain executes middleware in order" {
    const middleware1 = struct {
        fn run(_: *Context, _: request.RequestView) Decision {
            return .allow;
        }
    }.run;

    const middleware2 = struct {
        fn run(_: *Context, _: request.RequestView) Decision {
            return .allow;
        }
    }.run;

    const pre = [_]MiddlewareFn{ middleware1, middleware2 };
    var chain = Chain.init(&pre, &.{});

    var ctx = Context{};
    const req = request.RequestView{
        .method = .GET,
        .path = "/test",
        .headers = &.{},
        .body = "",
    };

    const result = chain.executePre(&ctx, req);
    try std.testing.expect(result == .allow); // No rejection
}

test "format buffer append" {
    var buf = FormatBuffer{};
    buf.append("hello");
    buf.append(" ");
    buf.append("world");

    try std.testing.expectEqualStrings("hello world", buf.slice());
}

test "format buffer appendFmt" {
    var buf = FormatBuffer{};
    buf.appendFmt("status={d} path={s}", .{ 200, "/api" });

    try std.testing.expectEqualStrings("status=200 path=/api", buf.slice());
}
