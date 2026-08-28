//! C ABI for embedding swerver in another process (e.g. a Bun/Node runtime via
//! FFI). Root source of `libswerver` (`zig build lib`).
//!
//! Convention: every exported symbol is prefixed `swerver_`, takes and returns
//! only C-ABI types (integers, pointers, lengths), and never surfaces a Zig
//! error across the boundary — errors become negative codes or null.
//!
//! Threading: one embedded server per process (shutdown state and the x402
//! worker are process-global). `swerver_start` runs the reactor on a background
//! thread; the host keeps running its own event loop. The server is built with
//! `embedded = true` so it does NOT install process-wide signal handlers.

const std = @import("std");
const builtin = @import("builtin");
const swerver = @import("swerver");
const ffi_bridge = swerver.ffi_bridge;

const Server = swerver.Server;
const ServerBuilder = swerver.ServerBuilder;
const config_file = swerver.config_file;
const Router = swerver.router.Router;
const Proxy = swerver.proxy.handler.Proxy;

// Embedders link libc, so the C allocator is the natural choice: thread-safe
// and free of teardown of its own.
const gpa = std.heap.c_allocator;

/// Opaque handle returned by swerver_init and passed to the other calls.
const Embed = struct {
    loaded: config_file.LoadedConfig,
    proxy: ?*Proxy,
    server: *Server,
    thread: ?std.Thread = null,
    run_error: ?anyerror = null,
};

/// ABI version. Bumped when the exported surface changes.
export fn swerver_abi_version() u32 {
    return 3;
}

export fn swerver_build_id() [*:0]const u8 {
    return "swerver-capi/0 (" ++ @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.cpu.arch) ++ ")";
}

/// Build an embedded server from a JSON config (same schema as the CLI's
/// --config file). Returns an opaque handle, or null on parse/validation
/// failure. Does not start serving; call swerver_start.
export fn swerver_init(config_json: [*]const u8, config_json_len: usize) ?*Embed {
    return initInner(config_json[0..config_json_len]) catch |err| {
        std.log.err("swerver_init failed: {}", .{err});
        return null;
    };
}

fn initInner(bytes: []const u8) !*Embed {
    // Set up the FFI bridge (idempotent) and clear any routes/callback from a
    // previous embed cycle. Routes and the callback are registered between init
    // and start via swerver_route / swerver_on_request.
    try ffi_bridge.instance.init(gpa);
    ffi_bridge.instance.resetRoutes();

    const embed = try gpa.create(Embed);
    errdefer gpa.destroy(embed);

    embed.* = .{
        .loaded = try config_file.parseJsonFromBytes(gpa, bytes),
        .proxy = null,
        .server = undefined,
    };
    errdefer embed.loaded.deinit();

    var cfg = embed.loaded.server_config;
    // An embedder must never fork the host: force single-process mode.
    cfg.workers = 1;
    try cfg.validate();

    if (embed.loaded.routes.len > 0 and embed.loaded.upstreams.len > 0) {
        const p = try gpa.create(Proxy);
        errdefer gpa.destroy(p);
        p.* = try Proxy.init(gpa, .{
            .upstreams = embed.loaded.upstreams,
            .routes = embed.loaded.routes,
        });
        embed.proxy = p;
    }
    errdefer if (embed.proxy) |p| {
        p.deinit();
        gpa.destroy(p);
    };

    var builder = ServerBuilder.config(cfg).router(Router.init(.{}));
    if (embed.proxy) |p| builder = builder.withProxy(p);
    const srv = try builder.build(gpa);
    srv.embedded = true;
    embed.server = srv;
    return embed;
}

/// Register an FFI route by path prefix. Requests whose path starts with
/// `pattern` are handed to the host callback instead of the router. Call
/// between swerver_init and swerver_start. Returns 0 on success, -1 if the
/// route table is full or the pattern is invalid.
export fn swerver_route(embed: *Embed, pattern: [*]const u8, pattern_len: usize, route_id: u32) c_int {
    _ = embed;
    return if (ffi_bridge.instance.addRoute(pattern[0..pattern_len], route_id)) 0 else -1;
}

/// Register the host request callback (a thread-safe C function pointer, e.g.
/// a Bun JSCallback). The reactor invokes it with a req_id when a request is
/// parked; the host reads it with swerver_request and answers with
/// swerver_respond. Call between swerver_init and swerver_start.
export fn swerver_on_request(embed: *Embed, cb: ffi_bridge.RequestCallback) void {
    _ = embed;
    ffi_bridge.instance.setCallback(cb);
}

/// Host thread: pop the next parked request id, or 0 if none are pending. The
/// host drains this in a loop (on the wake callback, and/or on a timer), reads
/// each with swerver_request, and answers with swerver_respond.
export fn swerver_poll() u64 {
    return ffi_bridge.instance.pollRequest();
}

/// Host thread: re-arm the coalesced wake after draining to empty. Call when
/// swerver_poll returns 0, then poll once more to catch a request that arrived
/// mid-drain.
export fn swerver_notify_done() void {
    ffi_bridge.instance.notifyDone();
}

/// Fill `out` (6 usize slots) with [method_ptr, method_len, path_ptr,
/// path_len, body_ptr, body_len] for a parked request. Returns 0 on success,
/// -1 if req_id is stale. Pointers are valid until swerver_respond(req_id).
export fn swerver_request(req_id: u64, out: [*]usize) c_int {
    return ffi_bridge.instance.requestInfo(req_id, out[0..6]);
}

/// Answer a parked request. `ctype` is the Content-Type value (may be empty).
/// Callable from any thread; wakes the reactor, which resumes the connection.
/// Returns 0 on success, -1 if req_id is stale/already answered, -2 if too big.
export fn swerver_respond(
    req_id: u64,
    status: u16,
    ctype: [*]const u8,
    ctype_len: usize,
    body: [*]const u8,
    body_len: usize,
) c_int {
    return ffi_bridge.instance.respond(req_id, status, ctype[0..ctype_len], body[0..body_len]);
}

/// Start serving on a background thread. Returns 0 on success, negative on
/// error. Returns immediately; the listeners are bound as the reactor starts,
/// so the host should poll-connect until the port accepts before sending
/// traffic. Idempotent-guarded: a second call while running returns -1.
export fn swerver_start(embed: *Embed) c_int {
    if (embed.thread != null) return -1;
    embed.thread = std.Thread.spawn(.{}, runThread, .{embed}) catch return -2;
    return 0;
}

fn runThread(embed: *Embed) void {
    embed.server.run(null) catch |err| {
        embed.run_error = err;
        std.log.err("swerver embedded run exited with error: {}", .{err});
    };
}

/// Stop serving, join the reactor thread, and free everything. The handle is
/// invalid after this call. Safe to call whether or not swerver_start ran.
export fn swerver_stop(embed: *Embed) void {
    if (embed.thread) |t| {
        embed.server.shutdown(); // thread-safe atomic; loop exits within ~10ms
        embed.server.io.wake(); // immediate nudge once a wake is registered (else no-op)
        t.join();
        embed.thread = null;
    }
    // The reactor thread is gone; clear the bridge's pointer to this server's
    // io (about to be freed) and its callback.
    ffi_bridge.instance.resetRoutes();
    embed.server.deinit(); // also destroys the proxy it was given
    gpa.destroy(embed.server);
    embed.loaded.deinit();
    gpa.destroy(embed);
}
