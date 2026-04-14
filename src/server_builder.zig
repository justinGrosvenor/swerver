const std = @import("std");

const config_mod = @import("config.zig");
const middleware_mod = @import("middleware/middleware.zig");
const router_mod = @import("router/router.zig");
const server = @import("server.zig");
const proxy_mod = @import("proxy/proxy.zig");

/// Fluent builder for constructing a `Server`. The primary
/// user-facing entry point for applications that embed swerver as a
/// library.
///
/// Usage pattern — all chain methods return a new `ServerBuilder` by
/// value, so typical code reads as a pipeline:
///
///     const srv = try swerver.ServerBuilder
///         .configDefault()
///         .router(my_router)
///         .withState(&app_state)
///         .withServices(&service_registry)
///         .withProxy(&reverse_proxy)
///         .build(allocator);
///     defer {
///         srv.deinit();
///         allocator.destroy(srv);
///     }
///     try srv.run(null);
///
/// Fields are applied in `build()`:
///   - `config` / `configDefault` — the `ServerConfig` to validate
///     and install. `configDefault` uses `ServerConfig.default()`;
///     `config(cfg)` takes a pre-built one, typically from
///     `config_file.loadConfigFile`.
///   - `router` — the `Router` with your registered routes. If
///     omitted, `build()` constructs an empty router with the config's
///     x402 policy pre-applied.
///   - `middleware` — overrides the router's middleware chain with
///     this one. Rarely needed — prefer calling `Router.setMiddleware`
///     directly on the router before handing it in.
///   - `withState(T*)` — opaque pointer to app state, later retrieved
///     in handlers via `ctx.state(T)`. The pointer must remain valid
///     for the lifetime of the server.
///   - `withServices(T*)` — opaque pointer to a services struct,
///     retrieved by field type via `ctx.get(T)`. Expands to a
///     reflection-driven dispatch at comptime.
///   - `withProxy(*Proxy)` — attaches a reverse-proxy instance that
///     intercepts matching requests before the router. Typically
///     constructed from `config_file.loadConfigFile`'s proxy routes.
///
/// `build()` validates the config, finalizes the router with any
/// state/services/middleware overrides, heap-allocates a `Server`,
/// initializes it in place, and returns the pointer. The caller is
/// responsible for `defer srv.deinit()` + `allocator.destroy(srv)`.
pub const ServerBuilder = struct {
    cfg: config_mod.ServerConfig,
    router_opt: ?router_mod.Router = null,
    middleware_chain: ?middleware_mod.Chain = null,
    app_state: ?*anyopaque = null,
    app_services: ?*anyopaque = null,
    app_services_get: ?router_mod.ServiceGetter = null,
    proxy_instance: ?*proxy_mod.Proxy = null,

    pub fn configDefault() ServerBuilder {
        return .{ .cfg = config_mod.ServerConfig.default() };
    }

    pub fn config(cfg: config_mod.ServerConfig) ServerBuilder {
        return .{ .cfg = cfg };
    }

    pub fn router(self: ServerBuilder, app_router: router_mod.Router) ServerBuilder {
        var next = self;
        next.router_opt = app_router;
        return next;
    }

    pub fn middleware(self: ServerBuilder, chain: middleware_mod.Chain) ServerBuilder {
        var next = self;
        next.middleware_chain = chain;
        return next;
    }

    pub fn withState(self: ServerBuilder, state: anytype) ServerBuilder {
        var next = self;
        next.app_state = toAnyopaquePtr(state);
        return next;
    }

    pub fn withServices(self: ServerBuilder, services: anytype) ServerBuilder {
        var next = self;
        next.app_services = toAnyopaquePtr(services);
        next.app_services_get = makeServiceGetter(@TypeOf(services.*));
        return next;
    }

    /// Attach a reverse proxy instance to the server.
    /// The proxy will intercept matching requests before the router.
    pub fn withProxy(self: ServerBuilder, proxy: *proxy_mod.Proxy) ServerBuilder {
        var next = self;
        next.proxy_instance = proxy;
        return next;
    }

    /// Build a heap-allocated Server. Caller must call srv.deinit() and
    /// allocator.destroy(srv) when done.
    pub fn build(self: ServerBuilder, allocator: std.mem.Allocator) !*server.Server {
        try self.cfg.validate();

        var app_router = self.router_opt orelse router_mod.Router.init(.{
            .require_payment = self.cfg.x402.enabled,
            .payment_required_b64 = self.cfg.x402.payment_required_b64,
        });

        if (self.middleware_chain) |chain| {
            app_router.setMiddleware(chain);
        }
        if (self.app_state) |state| {
            app_router.setState(state);
        }
        if (self.app_services) |services| {
            app_router.setServicesWithGetter(services, self.app_services_get);
        }

        const srv = try allocator.create(server.Server);
        errdefer allocator.destroy(srv);
        try srv.initInPlace(allocator, self.cfg, app_router);
        srv.proxy = self.proxy_instance;
        return srv;
    }
};

fn toAnyopaquePtr(value: anytype) *anyopaque {
    comptime {
        const info = @typeInfo(@TypeOf(value));
        if (info != .pointer) {
            @compileError("expected a mutable pointer");
        }
        if (info.pointer.size != .one) {
            @compileError("expected a single-item pointer");
        }
        if (info.pointer.is_const) {
            @compileError("expected a mutable pointer");
        }
    }
    return @ptrCast(value);
}

fn makeServiceGetter(comptime Services: type) router_mod.ServiceGetter {
    return struct {
        fn get(ptr: *anyopaque, type_name: []const u8) ?*anyopaque {
            const services: *Services = @ptrCast(@alignCast(ptr));
            inline for (@typeInfo(Services).@"struct".fields) |field| {
                if (std.mem.eql(u8, type_name, @typeName(field.type))) {
                    return @ptrCast(&@field(services, field.name));
                }
                switch (@typeInfo(field.type)) {
                    .pointer => |info| {
                        if (std.mem.eql(u8, type_name, @typeName(info.child))) {
                            return @ptrCast(@constCast(@field(services, field.name)));
                        }
                    },
                    else => {},
                }
            }
            std.log.err("service not found: {s}", .{type_name});
            return null;
        }
    }.get;
}
