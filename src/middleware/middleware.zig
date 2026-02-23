const std = @import("std");
const request = @import("../protocol/request.zig");
const response = @import("../response/response.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");

/// Middleware Framework
///
/// Provides a unified interface for request/response middleware that works
/// across HTTP/1.1, HTTP/2, and HTTP/3. Designed for zero heap allocations
/// in the hot path.

/// Decision returned by middleware evaluation
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

/// Context passed to middleware, providing connection and request info
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
    conn_start: ?std.time.Instant = null,
    /// Request start time
    request_start: ?std.time.Instant = null,
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

    /// Generate a request ID
    pub fn generateRequestId(self: *Context) void {
        const ts: u64 = @intCast(@mod(std.time.nanoTimestamp(), std.math.maxInt(i64)));
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

/// Middleware function signature
/// Returns a Decision indicating how to proceed
pub const MiddlewareFn = *const fn (ctx: *Context, req: request.RequestView) Decision;

/// Post-response hook signature (for logging, metrics)
pub const PostResponseFn = *const fn (ctx: *Context, req: request.RequestView, resp: response.Response, elapsed_ns: u64) void;

/// Result from executing pre-request middleware chain
pub const PreResult = union(enum) {
    /// Request should continue to handler
    allow,
    /// Request rejected with response
    reject: response.Response,
    /// Request rate limited with backpressure
    backpressure: BackpressureInfo,
};

/// Middleware chain that executes multiple middleware in order
pub const Chain = struct {
    /// Pre-request middleware (run before handler)
    pre: []const MiddlewareFn,
    /// Post-response hooks (run after response)
    post: []const PostResponseFn,
    /// Accumulated response headers from modifications
    response_headers: [MAX_MIDDLEWARE_HEADERS]response.Header = undefined,
    response_header_count: usize = 0,

    const MAX_MIDDLEWARE_HEADERS = 16;

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
