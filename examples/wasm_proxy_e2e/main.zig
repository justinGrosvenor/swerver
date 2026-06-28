//! Runnable WASM edge-function round-trip on a PROXY route (C-stream proxy park
//! path). This validates the CONFIG-DRIVEN product surface the review flagged: a
//! wasm_filter attached to a proxy route (loadAndAttachProxy, the same path the
//! config file uses) now PARKS on a host_call, drives a Nether sandbox over the
//! control socket, and FORWARDS to the upstream on resume-to-allow -- instead of
//! failing closed.
//!
//! Topology: client -> swerver (proxy, /agent/* + wasm filter) -> upstream backend.
//! The filter stages a host_call and parks; swerver drives the control socket;
//! exit 0 -> resume ALLOW -> forward to the backend (the response body proves the
//! forward happened); nonzero -> REJECT 403 (no forward, body from the filter).
//!
//! Build + run (requires -Denable-wasm):
//!   zig build wasm-proxy-e2e -Denable-wasm=true
//!   WASM_FILTER_PATH=shell_probe.wasm NETHER_CONTROL_SOCKET=/tmp/n.sock \
//!     UPSTREAM_PORT=8097 ./zig-out/bin/swerver-wasm-proxy-e2e
//! then: curl -H 'authorization: t' localhost:8096/agent/echo  (-> 200, BACKEND body)
//!       curl localhost:8096/agent/echo                         (-> 403, filter body)

const std = @import("std");
const swerver = @import("swerver");

fn envDup(name: [*:0]const u8) ?[]const u8 {
    return if (std.c.getenv(name)) |p| std.mem.span(p) else null;
}

fn healthHandler(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.text(200, "ok\n");
}

pub fn main() !void {
    const alloc = std.heap.c_allocator;

    const filter_path = envDup("WASM_FILTER_PATH") orelse return error.MissingFilterPath;
    const sock_path = envDup("NETHER_CONTROL_SOCKET") orelse return error.MissingControlSocket;
    const up_port_str = envDup("UPSTREAM_PORT") orelse "8097";
    const up_port = std.fmt.parseInt(u16, up_port_str, 10) catch 8097;

    // Proxy: /agent/* -> the upstream backend on UPSTREAM_PORT.
    const servers = [_]swerver.proxy.upstream.Server{.{ .address = "127.0.0.1", .port = up_port }};
    const upstreams = [_]swerver.proxy.upstream.Upstream{.{ .name = "backend", .servers = &servers }};
    const routes = [_]swerver.proxy.upstream.ProxyRoute{.{ .path_prefix = "/agent/", .upstream = "backend" }};
    const proxy = try alloc.create(swerver.proxy.handler.Proxy);
    proxy.* = try swerver.proxy.handler.Proxy.init(alloc, .{ .upstreams = &upstreams, .routes = &routes });

    // Embedded router handles non-proxy paths (/health); proxy is checked first.
    var router = swerver.router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    try router.get("/health", healthHandler);

    var cfg = swerver.config.ServerConfig.default();
    cfg.port = 8096;

    const server = try swerver.ServerBuilder
        .config(cfg)
        .router(router)
        .withProxy(proxy)
        .build(alloc);
    defer server.deinit();

    // Attach the wasm filter to the proxy route via the CONFIG path
    // (loadAndAttachProxy), and wire the control-socket transport. setupWasmFilters
    // runs at run() start and binds specs whose match == route.path_prefix.
    const specs = [_]swerver.config_file.WasmFilterConfig{.{
        .match = "/agent/",
        .module_path = filter_path,
        .instances = 4,
    }};
    server.wasm_filter_specs = &specs;
    server.wasm_control_socket_path = sock_path;

    // Optional override of the host_call (park) deadline so a timeout e2e does not
    // wait the 30s default. Unset -> the built-in default stands.
    if (envDup("WASM_HOST_CALL_DEADLINE_MS")) |v| {
        const ms = std.fmt.parseInt(u64, std.mem.trim(u8, v, " \t\r\n"), 10) catch {
            std.log.err("WASM_HOST_CALL_DEADLINE_MS is not a valid u64: '{s}'", .{v});
            return error.BadDeadline;
        };
        server.wasm_host_call_deadline_ms = ms;
        std.log.info("wasm host_call deadline overridden to {d} ms", .{ms});
    }

    std.log.info("wasm proxy e2e on :{d} (/agent/* -> filter parks -> control {s} -> forward :{d})", .{ cfg.port, sock_path, up_port });
    try server.run(null);
}
