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
    return 2;
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
    embed.server.deinit(); // also destroys the proxy it was given
    gpa.destroy(embed.server);
    embed.loaded.deinit();
    gpa.destroy(embed);
}
