//! WASM filter manager (design 10.0, increment 3).
//!
//! Owns the per-worker filter pools and bridges declarative config to the
//! runtime: load a `.wasm` from disk once at startup/reload, build a pool of N
//! pre-instantiated instances, and attach it to routes (embedded Router by
//! pattern, or proxy ProxyRoute by path prefix). Module loading happens off the
//! hot path, exactly as the design requires.
//!
//! Lifetime: the manager owns every pool and frees them on deinit. Pools (and
//! thus the modules' linear memory) live for the worker. Attached routes hold
//! an opaque pointer to a pool the manager keeps alive.

const std = @import("std");
const filter = @import("filter.zig");
const router_mod = @import("../router/router.zig");
const upstream = @import("../proxy/upstream.zig");
const clock = @import("../runtime/clock.zig");

pub const Error = filter.Error || error{ FileTooLarge, ModuleReadFailed };

/// Declarative spec for one filter binding. Produced by config parsing or built
/// programmatically. `match` is a route pattern (embedded Router) or path prefix
/// (proxy), interpreted by whichever attach call is used.
pub const Spec = struct {
    match: []const u8,
    module_path: []const u8,
    instances: usize = 4,
    fuel: i64 = filter.DEFAULT_FUEL,
};

/// Largest module file the manager will load (sanity bound, not a wasm limit).
pub const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;

const Entry = struct {
    match: []u8,
    pool: *filter.Pool,
    fuel: i64,
};

pub const Manager = struct {
    alloc: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    pub fn init(alloc: std.mem.Allocator) Manager {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Manager) void {
        for (self.entries.items) |*e| {
            e.pool.deinit();
            self.alloc.destroy(e.pool);
            self.alloc.free(e.match);
        }
        self.entries.deinit(self.alloc);
    }

    /// Build a pool from in-memory module bytes and record the binding. Core of
    /// the disk `load` path; also directly usable when bytes are embedded.
    pub fn addPool(self: *Manager, match: []const u8, bytes: []const u8, instances: usize, fuel: i64) Error!*filter.Pool {
        const pool = try self.alloc.create(filter.Pool);
        errdefer self.alloc.destroy(pool);
        pool.* = try filter.Pool.init(self.alloc, bytes, .{ .instances = instances });
        errdefer pool.deinit();

        const match_copy = try self.alloc.dupe(u8, match);
        errdefer self.alloc.free(match_copy);

        try self.entries.append(self.alloc, .{ .match = match_copy, .pool = pool, .fuel = fuel });
        return pool;
    }

    /// Load a module from disk and build its pool, recording the binding.
    /// Returns the owned pool (also retained by the manager).
    pub fn load(self: *Manager, spec: Spec) Error!*filter.Pool {
        const bytes = readModule(self.alloc, spec.module_path) catch return Error.ModuleReadFailed;
        defer self.alloc.free(bytes);
        return self.addPool(spec.match, bytes, spec.instances, spec.fuel);
    }

    /// Load every spec and attach to an embedded Router by route pattern.
    /// Returns the number of (spec, route) attachments made.
    pub fn loadAndAttachRouter(self: *Manager, router: *router_mod.Router, specs: []const Spec) Error!usize {
        var attached: usize = 0;
        for (specs) |spec| {
            const pool = try self.load(spec);
            attached += router.attachWasmFilter(spec.match, pool, spec.fuel);
        }
        return attached;
    }

    /// Load every spec and attach to proxy routes whose path_prefix equals the
    /// spec match. `routes` is the mutable proxy route table. Returns the number
    /// of attachments made.
    pub fn loadAndAttachProxy(self: *Manager, routes: []upstream.ProxyRoute, specs: []const Spec) Error!usize {
        var attached: usize = 0;
        for (specs) |spec| {
            const pool = try self.load(spec);
            for (routes) |*r| {
                if (std.mem.eql(u8, r.path_prefix, spec.match)) {
                    r.wasm_pool = pool;
                    r.wasm_fuel = spec.fuel;
                    attached += 1;
                }
            }
        }
        return attached;
    }
};

fn readModule(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    // posix read loop (this Zig's std.fs/std.Io API is in flux); mirrors
    // config_file.zig. Grows into an ArrayList so we don't preallocate the cap.
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0) catch return Error.ModuleReadFailed;
    defer clock.closeFd(fd);

    var list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer list.deinit(alloc);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &chunk) catch return Error.ModuleReadFailed;
        if (n == 0) break;
        if (list.items.len + n > MAX_MODULE_BYTES) return Error.FileTooLarge;
        try list.appendSlice(alloc, chunk[0..n]);
    }
    return list.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Tests (run with: zig build test -Denable-wasm=true)
// ---------------------------------------------------------------------------

const testing = std.testing;
const request = @import("../protocol/request.zig");

test "manager owns pool, attaches to router by pattern, filters" {
    const fixture = @embedFile("testdata/filter_probe.wasm");

    var mgr = Manager.init(testing.allocator);
    defer mgr.deinit();

    var router = router_mod.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    const handler = struct {
        fn h(_: *router_mod.HandlerContext) @import("../response/response.zig").Response {
            return @import("../response/response.zig").Response.ok();
        }
    }.h;
    try router.get("/api/orders", handler);

    // addPool exercises the in-memory core; load() layers a disk read on top.
    const pool = try mgr.addPool("/api/orders", fixture, 2, filter.DEFAULT_FUEL);
    try testing.expectEqual(@as(usize, 1), router.attachWasmFilter("/api/orders", pool, filter.DEFAULT_FUEL));

    // /api/orders without key -> filter rejects 401.
    var mw_ctx = @import("../middleware/middleware.zig").Context{};
    var response_buf: [4096]u8 = undefined;
    var response_headers: [16]@import("../response/response.zig").Header = undefined;
    var arena_buf: [4096]u8 = undefined;
    var scratch = router_mod.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };
    const req = request.RequestView{ .method = .GET, .path = "/api/orders", .headers = &.{} };
    const result = router.handle(req, &mw_ctx, &scratch);
    try testing.expectEqual(@as(u16, 401), result.resp.status);
}

test "manager.load reads a module from disk and filters" {
    const fixture = @embedFile("testdata/filter_probe.wasm");
    const path = "/tmp/swerver_wasm_load_test.wasm";

    // Write the fixture to disk, then load it through the disk path (readModule).
    const wfd = try std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    {
        var written: usize = 0;
        while (written < fixture.len) {
            const rc = std.posix.system.write(wfd, fixture[written..].ptr, fixture.len - written);
            const signed: isize = @bitCast(rc);
            if (signed < 0) return error.TestWriteFailed;
            written += @intCast(signed);
        }
    }
    clock.closeFd(wfd);
    defer _ = std.c.unlink("/tmp/swerver_wasm_load_test.wasm");

    var mgr = Manager.init(testing.allocator);
    defer mgr.deinit();

    var router = router_mod.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    const handler = struct {
        fn h(_: *router_mod.HandlerContext) @import("../response/response.zig").Response {
            return @import("../response/response.zig").Response.ok();
        }
    }.h;
    try router.get("/api/orders", handler);

    const specs = [_]Spec{.{ .match = "/api/orders", .module_path = path, .instances = 2 }};
    try testing.expectEqual(@as(usize, 1), try mgr.loadAndAttachRouter(&router, &specs));

    var mw_ctx = @import("../middleware/middleware.zig").Context{};
    var response_buf: [4096]u8 = undefined;
    var response_headers: [16]@import("../response/response.zig").Header = undefined;
    var arena_buf: [4096]u8 = undefined;
    var scratch = router_mod.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf[0..],
    };
    const req = request.RequestView{ .method = .GET, .path = "/api/orders", .headers = &.{} };
    try testing.expectEqual(@as(u16, 401), router.handle(req, &mw_ctx, &scratch).resp.status);

    // A bad path surfaces ModuleReadFailed rather than crashing.
    const bad = [_]Spec{.{ .match = "/x", .module_path = "/nonexistent/nope.wasm" }};
    try testing.expectError(Error.ModuleReadFailed, mgr.loadAndAttachRouter(&router, &bad));
}
