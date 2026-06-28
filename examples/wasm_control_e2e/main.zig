//! Runnable WASM edge-function round-trip server over the REAL Nether control
//! socket (C3 live lane). A wasm filter on /agent/* stages a host_call and parks;
//! swerver drives the call over a Nether sandbox's Unix-domain control socket
//! (proto_version=1) and resumes the filter from the framed reply. The guest's
//! exit code is the verdict: 0 -> allow (the handler then runs), non-zero ->
//! reject 403, no/empty reply -> 502.
//!
//! Unlike examples/wasm_e2e (the mock lane, embedded fixture), this loads the
//! filter from disk and requires a live control socket, so both come from env:
//!   WASM_FILTER_PATH       path to the compiled filter .wasm (enrich_filter.wasm)
//!   NETHER_CONTROL_SOCKET  path to the sandbox control socket (real nether or stub)
//!
//! Build + run (requires -Denable-wasm):
//!   zig build wasm-control-e2e -Denable-wasm=true
//!   WASM_FILTER_PATH=enrich_filter.wasm NETHER_CONTROL_SOCKET=/tmp/nether.sock \
//!     ./zig-out/bin/swerver-wasm-control-e2e
//! then: curl -H 'authorization: t' localhost:8098/agent/echo   (-> 200, allow)
//!       curl localhost:8098/agent/echo                          (-> 403, reject)
//!       curl localhost:8098/health                              (-> 200, no filter)

const std = @import("std");
const swerver = @import("swerver");

const ROUTE = "/agent/echo";

fn agentHandler(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.text(200, "tier1+tier2 allowed: handler ran after control-socket resume\n");
}

fn healthHandler(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.text(200, "ok\n");
}

fn envDup(name: [*:0]const u8) ?[]const u8 {
    return if (std.c.getenv(name)) |p| std.mem.span(p) else null;
}

pub fn main() !void {
    const alloc = std.heap.c_allocator;

    const filter_path = envDup("WASM_FILTER_PATH") orelse {
        std.log.err("WASM_FILTER_PATH not set (path to the compiled filter .wasm)", .{});
        return error.MissingFilterPath;
    };
    const sock_path = envDup("NETHER_CONTROL_SOCKET") orelse {
        std.log.err("NETHER_CONTROL_SOCKET not set (path to the sandbox control socket)", .{});
        return error.MissingControlSocket;
    };

    var router = swerver.router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    try router.get(ROUTE, agentHandler);
    try router.get("/health", healthHandler);

    // Load the filter from disk and attach it to the route. The manager owns the
    // pool and must outlive the server (the route references it).
    var manager = swerver.wasm.manager.Manager.init(alloc);
    defer manager.deinit();
    const specs = [_]swerver.wasm.manager.Spec{.{
        .match = ROUTE,
        .module_path = filter_path,
        .instances = 4,
    }};
    const n = try manager.loadAndAttachRouter(&router, &specs);
    if (n == 0) {
        std.log.err("filter '{s}' attached to no routes", .{filter_path});
        return error.NoAttachment;
    }

    var cfg = swerver.config.ServerConfig.default();
    cfg.port = 8098;

    const server = try swerver.ServerBuilder
        .config(cfg)
        .router(router)
        .build(alloc);
    defer server.deinit();

    // Drive the real control-socket transport (C3).
    server.wasm_control_socket_path = sock_path;

    std.log.info("wasm control-socket e2e on :{d} (GET {s} -> control socket {s} -> verdict)", .{ cfg.port, ROUTE, sock_path });
    try server.run(null);
}
