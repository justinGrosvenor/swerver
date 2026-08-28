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
var embed_active = std.atomic.Value(bool).init(false);

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
    return 5;
}

export fn swerver_build_id() [*:0]const u8 {
    return "swerver-capi/0 (" ++ @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.cpu.arch) ++ ")";
}

/// Build an embedded server from a JSON config (same schema as the CLI's
/// --config file). Returns an opaque handle, or null on parse/validation
/// failure. Does not start serving; call swerver_start.
export fn swerver_init(config_json: [*]const u8, config_json_len: usize) ?*Embed {
    if (embed_active.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) {
        std.log.err("swerver_init failed: only one embedded server is supported per process", .{});
        return null;
    }
    return initInner(config_json[0..config_json_len]) catch |err| {
        embed_active.store(false, .release);
        std.log.err("swerver_init failed: {}", .{err});
        return null;
    };
}

fn initInner(bytes: []const u8) !*Embed {
    // Set up the FFI bridge (idempotent) and clear any routes/callback from a
    // previous embed cycle. Routes and the callback are registered between init
    // and start via swerver_route / swerver_on_request.
    try ffi_bridge.instance.init(gpa);
    errdefer ffi_bridge.instance.deinit(gpa);
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
    // The reactor runs on a background thread; pickBackend uses this to select a
    // cross-thread-safe backend (epoll on Linux, not the thread-pinned io_uring).
    cfg.embedded = true;
    try cfg.validate();
    ffi_bridge.instance.setResponseCapacity(cfg.buffer_pool.buffer_size);

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

/// Connect the push-wake channel to a unix socket the host is listening on, so
/// the reactor can wake the host on park instead of the host polling on a timer.
/// The host listens (e.g. Bun.listen({unix})), then calls this; on a `data`
/// event the host calls swerver_wake_clear and drains with swerver_poll.
/// Returns 0 on success, -1 on failure. Call after swerver_init.
export fn swerver_wake_connect(embed: *Embed, path: [*]const u8, path_len: usize) c_int {
    _ = embed;
    return if (ffi_bridge.instance.connectJsWake(path[0..path_len])) 0 else -1;
}

/// Host thread: re-arm the push wake and drain any pending wake bytes. Call on
/// each wake, before draining the request ring.
export fn swerver_wake_clear() void {
    ffi_bridge.instance.clearJsWake();
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

/// Fill `out` (8 usize slots) with [method_ptr, method_len, path_ptr,
/// path_len, body_ptr, body_len, response_ptr, response_cap] for a parked
/// request. Returns 0 on success; pointers are valid until it is answered.
export fn swerver_request(req_id: u64, out: [*]usize) c_int {
    return ffi_bridge.instance.requestInfo(req_id, out[0..8]);
}

/// Fill `out` with [headers_ptr, headers_len]. Headers are packed as
/// NUL-delimited name/value pairs and remain valid until the request is
/// answered. Returns 0 on success or -1 for a stale request id.
export fn swerver_request_headers(req_id: u64, out: [*]usize) c_int {
    return ffi_bridge.instance.requestHeaders(req_id, out[0..2]);
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

/// Answer with arbitrary response headers packed as NUL-delimited name/value
/// pairs. The bridge copies both headers and body before waking the reactor.
/// Returns 0 on success, -1 if stale/already answered, or -2 if too large.
export fn swerver_respond_full(
    req_id: u64,
    status: u16,
    headers: [*]const u8,
    headers_len: usize,
    body: [*]const u8,
    body_len: usize,
) c_int {
    return ffi_bridge.instance.respondFull(req_id, status, headers[0..headers_len], body[0..body_len]);
}

/// Answer with arbitrary packed headers and a body already written into the
/// response slot exposed by swerver_request.
export fn swerver_respond_inplace_full(
    req_id: u64,
    status: u16,
    headers: [*]const u8,
    headers_len: usize,
    body_len: usize,
) c_int {
    return ffi_bridge.instance.respondInplaceFull(req_id, status, headers[0..headers_len], body_len);
}

/// Answer a parked request whose body was written DIRECTLY into the slot's
/// response buffer (via the resp_ptr from swerver_request) — no body copy. Only
/// status, content-type, and length are recorded. Same return codes as
/// swerver_respond.
export fn swerver_respond_inplace(
    req_id: u64,
    status: u16,
    ctype: [*]const u8,
    ctype_len: usize,
    body_len: usize,
) c_int {
    return ffi_bridge.instance.respondInplace(req_id, status, ctype[0..ctype_len], body_len);
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

/// Close FFI route admission without stopping the reactor. Embedders use this
/// before awaiting host-language handlers: new FFI requests receive 503 while
/// admitted slots and their completions drain. The final swerver_stop shuts
/// down the reactor and frees the server.
export fn swerver_shutdown(embed: *Embed) void {
    ffi_bridge.instance.beginShutdown();
    embed.server.io.wake();
}

/// Number of admitted host requests still occupying bridge slots. After
/// swerver_shutdown, embedders drain this to zero before swerver_stop.
export fn swerver_pending() u32 {
    return ffi_bridge.instance.pending();
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
    ffi_bridge.instance.deinit(gpa);
    embed_active.store(false, .release);
}
