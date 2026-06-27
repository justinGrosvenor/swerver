//! # swerver
//!
//! HTTP/1.1, HTTP/2, and HTTP/3 server in pure Zig, with zero-copy
//! request parsing, fixed-size buffer pools, and io_uring / epoll /
//! kqueue backends.
//!
//! ## Getting started
//!
//! The normal path for embedding swerver is:
//!
//!     const std = @import("std");
//!     const swerver = @import("swerver");
//!
//!     fn hello(ctx: *swerver.router.HandlerContext) swerver.response.Response {
//!         _ = ctx;
//!         return .{
//!             .status = 200,
//!             .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
//!             .body = .{ .bytes = "Hello, World!\n" },
//!         };
//!     }
//!
//!     pub fn main() !void {
//!         var gpa = std.heap.DebugAllocator(.{}){};
//!         defer _ = gpa.deinit();
//!         const allocator = gpa.allocator();
//!
//!         var app_router = swerver.router.Router.init(.{
//!             .require_payment = false,
//!             .payment_required_b64 = "",
//!         });
//!         try app_router.get("/hello", hello);
//!
//!         const srv = try swerver.ServerBuilder
//!             .configDefault()
//!             .router(app_router)
//!             .build(allocator);
//!         defer {
//!             srv.deinit();
//!             allocator.destroy(srv);
//!         }
//!         try srv.run(null);
//!     }
//!
//! ## Public surface
//!
//! ### Core
//! - `Server` — the single-threaded event-loop HTTP server. One per
//!   worker process.
//! - `ServerBuilder` — fluent builder for constructing a `Server`;
//!   the usual entry point for applications.
//! - `Master` — multi-process worker manager (fork + SO_REUSEPORT).
//!   Only needed if you want the multi-worker deployment model
//!   without `ServerBuilder`'s defaults.
//! - `router.Router` / `router.HandlerContext` / `router.HandlerFn` —
//!   route registration, per-request context, handler signature.
//! - `request.RequestView` / `request.Method` / `request.Header` —
//!   the parsed request types handlers receive.
//! - `response.Response` / `response.Body` — the response types
//!   handlers return.
//! - `middleware.Chain` / `middleware.MiddlewareFn` /
//!   `middleware.PostResponseFn` / `middleware.Decision` — the
//!   middleware framework. Identical across h1/h2/h3.
//! - `runtime.clock` — monotonic and realtime clock helpers.
//!   `runtime.buffer_pool` and `runtime.connection` are exposed for
//!   advanced embedding but most applications don't need them.
//!
//! ### Reverse proxy
//! - `proxy.handler.Proxy` + the `upstream` / `pool` / `balancer` /
//!   `forward` / `health` submodules. Typically constructed from
//!   `config_file.loadConfigFile` which parses JSON upstream and
//!   route definitions.
//!
//! ### Configuration
//! - `config.ServerConfig` — the validated in-memory config struct.
//! - `config_file.loadConfigFile` — JSON file parser that returns a
//!   `LoadedConfig` with arena-owned strings.
//!
//! ## Stability
//!
//! This is an alpha release. The public API may change between alpha
//! versions. Breaking changes are announced in release notes, so
//! downstream consumers should expect to touch their imports at
//! least once before beta.
//!
//! See the module-level docs on `Server`, `ServerBuilder`, `router`,
//! `request`, `response`, and `middleware` for the detailed shape.

pub const config = @import("config.zig");
pub const config_file = @import("config_file.zig");
pub const config_fetch = @import("config_fetch.zig");

// Core library surface
const server_mod = @import("server.zig");
pub const Server = server_mod.Server;
pub const ServerBuilder = @import("server_builder.zig").ServerBuilder;
pub const Master = @import("master.zig").Master;
pub const router = @import("router/router.zig");
pub const request = @import("protocol/request.zig");
pub const response = @import("response/response.zig");
pub const middleware = @import("middleware/middleware.zig");
pub const auth = @import("middleware/auth.zig");
pub const otel = @import("middleware/otel.zig");
pub const body_schema = @import("middleware/body_schema.zig");
pub const grpc = @import("middleware/grpc.zig");
pub const compress = @import("middleware/compress.zig");

/// Runtime primitives: clock helpers, buffer pool, connection state.
///
/// `runtime.clock` is the expected consumer — use it instead of
/// `std.time.Instant` / `std.time.nanoTimestamp` (both removed in
/// Zig 0.16.0-dev). `runtime.buffer_pool` and `runtime.connection`
/// are internal plumbing exposed only for advanced embedding and
/// should be considered unstable.
pub const runtime = struct {
    pub const buffer_pool = @import("runtime/buffer_pool.zig");
    pub const connection = @import("runtime/connection.zig");
    pub const clock = @import("runtime/clock.zig");
};

/// Reverse proxy support
pub const proxy = struct {
    pub const upstream = @import("proxy/upstream.zig");
    pub const pool = @import("proxy/pool.zig");
    pub const balancer = @import("proxy/balancer.zig");
    pub const forward = @import("proxy/forward.zig");
    pub const health = @import("proxy/health.zig");
    pub const handler = @import("proxy/proxy.zig");
    pub const cache = @import("proxy/cache.zig");
    pub const dns = @import("proxy/dns.zig");
    pub const consul = @import("proxy/consul.zig");
    pub const websocket = @import("proxy/websocket.zig");
};

/// Admin API for runtime route/upstream management
pub const admin = @import("admin/admin.zig");

/// Native PostgreSQL client: wire codec, SCRAM-SHA-256, binary type decoders,
/// a socket-free handshake state machine, and a park/resume handler API
/// (`db.pg.handler_api`) integrated with the event loop. Experimental: the
/// API may change before 1.0.
pub const db = struct {
    pub const pg = @import("db/pg/pg.zig");
};

// WASM edge functions (design 10.0). Gated on the build flag so the @cImport of
// vendored wasm3 never runs in a build without it. Mirrors the enable_tls gate.
const build_options = @import("build_options");
pub const wasm = if (build_options.enable_wasm)
    struct {
        pub const runtime = @import("wasm/runtime.zig");
        pub const filter = @import("wasm/filter.zig");
        pub const manager = @import("wasm/manager.zig");
        pub const host_call = @import("wasm/host_call.zig");
    }
else
    struct {};
