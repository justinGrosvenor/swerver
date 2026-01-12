pub const config = @import("config.zig");
const server_mod = @import("server.zig");
pub const Server = server_mod.Server;
pub const registerDefaultRoutes = server_mod.registerDefaultRoutes;
pub const ServerBuilder = @import("server_builder.zig").ServerBuilder;
pub const router = @import("router/router.zig");
pub const request = @import("protocol/request.zig");
pub const response = @import("response/response.zig");
pub const middleware = @import("middleware/middleware.zig");
pub const runtime = struct {
    pub const buffer_pool = @import("runtime/buffer_pool.zig");
    pub const connection = @import("runtime/connection.zig");
};

/// Reverse proxy support
pub const proxy = struct {
    pub const upstream = @import("proxy/upstream.zig");
    pub const pool = @import("proxy/pool.zig");
    pub const balancer = @import("proxy/balancer.zig");
    pub const forward = @import("proxy/forward.zig");
    pub const health = @import("proxy/health.zig");
    pub const handler = @import("proxy/proxy.zig");
};
