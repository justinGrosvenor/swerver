const std = @import("std");

const config_mod = @import("config.zig");
const middleware_mod = @import("middleware/middleware.zig");
const router_mod = @import("router/router.zig");
const server = @import("server.zig");

pub const ServerBuilder = struct {
    cfg: config_mod.ServerConfig,
    router_opt: ?router_mod.Router = null,
    middleware_chain: ?middleware_mod.Chain = null,
    app_state: ?*anyopaque = null,
    app_services: ?*anyopaque = null,
    app_services_get: ?router_mod.ServiceGetter = null,

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

    pub fn build(self: ServerBuilder, allocator: std.mem.Allocator) !server.Server {
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

        return server.Server.initWithRouter(allocator, self.cfg, app_router);
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
        fn get(ptr: *anyopaque, type_name: []const u8) *anyopaque {
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
            @panic("service not found");
        }
    }.get;
}
