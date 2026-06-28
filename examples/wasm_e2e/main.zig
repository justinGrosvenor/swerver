//! Runnable WASM edge-function e2e server (mock lane). Validates the Phase 3
//! park-and-resume gate over real HTTP without a Nether guest: a wasm filter on
//! /enrich stages a host_call and PARKS; the mock transport completes it with
//! "ok" on the next housekeeping tick; the filter's on_resume allows; and the
//! handler then runs. The handler body is the proof the resume + re-dispatch
//! fired (the handler is unreachable unless the parked filter resumed to allow).
//!
//! Build + run (requires -Denable-wasm):
//!   zig build wasm-e2e -Denable-wasm=true
//! then: curl localhost:8099/enrich   (-> 200, handler body)
//!       curl localhost:8099/health   (-> 200, no filter)
//!
//! Drives the C1 mock transport + C2 park/resume/re-dispatch end to end.

const std = @import("std");
const swerver = @import("swerver");

// The committed filter fixture (src/wasm/testdata/filter_probe.wasm): /enrich
// stages host_call("lookup:user") and returns parked; on_resume allows when the
// host-call result starts with "ok", else rejects 403.
const filter_wasm = @embedFile("filter_wasm");

fn enrichHandler(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.text(200, "enriched: handler ran after host_call resume\n");
}

fn healthHandler(ctx: *swerver.router.HandlerContext) swerver.response.Response {
    return ctx.text(200, "ok\n");
}

pub fn main() !void {
    const alloc = std.heap.c_allocator;

    var router = swerver.router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    try router.get("/enrich", enrichHandler);
    try router.get("/health", healthHandler);

    // Build a per-worker filter pool from the embedded module and bind it to
    // /enrich. The pool must outlive the server (the route references it).
    var pool = try swerver.wasm.filter.Pool.init(alloc, filter_wasm, .{ .instances = 4 });
    defer pool.deinit();
    _ = router.attachWasmFilter("/enrich", &pool, swerver.wasm.filter.DEFAULT_FUEL);

    var cfg = swerver.config.ServerConfig.default();
    cfg.port = 8099;

    const server = try swerver.ServerBuilder
        .config(cfg)
        .router(router)
        .build(alloc);
    defer server.deinit();

    // Mock host-call transport: complete every parked filter with "ok" on the
    // next tick (no Nether guest). The real vsock transport (C3) replaces this.
    server.wasm_mock_enabled = true;
    server.wasm_mock_reply = "ok";

    std.log.info("wasm e2e mock server on :{d} (GET /enrich parks -> mock ok -> handler runs)", .{cfg.port});
    try server.run(null);
}
