const std = @import("std");
const config = @import("config.zig");
const ServerBuilder = @import("server_builder.zig").ServerBuilder;
const router = @import("router/router.zig");
const clock = @import("runtime/clock.zig");
const proxy_mod = @import("proxy/proxy.zig");

const MAX_WORKERS = 256;

var master_shutdown_requested = std.atomic.Value(bool).init(false);
var master_reload_requested = std.atomic.Value(bool).init(false);
var master_child_exited = std.atomic.Value(bool).init(false);

fn handleMasterShutdown(_: std.posix.SIG) callconv(.c) void {
    master_shutdown_requested.store(true, .release);
}

fn handleMasterReload(_: std.posix.SIG) callconv(.c) void {
    master_reload_requested.store(true, .release);
}

fn handleMasterChild(_: std.posix.SIG) callconv(.c) void {
    master_child_exited.store(true, .release);
}

pub const Master = struct {
    allocator: std.mem.Allocator,
    cfg: config.ServerConfig,
    app_router: router.Router,
    proxy: ?*proxy_mod.Proxy,
    worker_count: u16,
    worker_pids: []std.c.pid_t,
    /// Timestamp of last crash per worker slot (for backoff)
    last_crash_ms: []u64,
    /// Consecutive crash count per worker slot
    crash_count: []u8,

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: config.ServerConfig,
        app_router: router.Router,
        proxy: ?*proxy_mod.Proxy,
    ) !Master {
        const count = if (cfg.workers == 0) detectCpuCount() else cfg.workers;
        const pids = try allocator.alloc(std.c.pid_t, count);
        @memset(pids, 0);
        const last_crash = try allocator.alloc(u64, count);
        @memset(last_crash, 0);
        const crash_cnt = try allocator.alloc(u8, count);
        @memset(crash_cnt, 0);

        return .{
            .allocator = allocator,
            .cfg = cfg,
            .app_router = app_router,
            .proxy = proxy,
            .worker_count = count,
            .worker_pids = pids,
            .last_crash_ms = last_crash,
            .crash_count = crash_cnt,
        };
    }

    pub fn deinit(self: *Master) void {
        self.allocator.free(self.worker_pids);
        self.allocator.free(self.last_crash_ms);
        self.allocator.free(self.crash_count);
    }

    pub fn run(self: *Master, run_for_ms: ?u64) !void {
        installMasterSignals();

        std.log.info("[master] starting {d} workers on :{d}", .{ self.worker_count, self.cfg.port });

        // Fork all workers
        for (0..self.worker_count) |i| {
            self.forkWorker(@intCast(i));
        }

        const start_ms = nowMs();

        // Master wait loop
        while (true) {
            if (master_shutdown_requested.load(.acquire)) {
                std.log.info("[master] shutdown requested, stopping workers", .{});
                self.signalAllWorkers(std.posix.SIG.TERM);
                self.waitAllWorkers();
                return;
            }

            if (run_for_ms) |limit| {
                if (nowMs() - start_ms >= limit) {
                    std.log.info("[master] run duration reached, stopping workers", .{});
                    self.signalAllWorkers(std.posix.SIG.TERM);
                    self.waitAllWorkers();
                    return;
                }
            }

            if (master_reload_requested.swap(false, .acq_rel)) {
                std.log.info("[master] reload requested, rolling restart", .{});
                self.rollingRestart();
            }

            if (master_child_exited.swap(false, .acq_rel)) {
                self.reapChildren();
            }

            // Sleep 100ms between checks
            sleepMs(100);
        }
    }

    fn forkWorker(self: *Master, worker_id: u16) void {
        const pid = std.c.fork();

        if (pid < 0) {
            std.log.err("[master] fork failed for worker {d}", .{worker_id});
            return;
        }

        if (pid == 0) {
            // Child process
            resetChildSignals();
            worker_id_global = worker_id;

            std.log.info("[w{d}] worker starting", .{worker_id});

            var builder = ServerBuilder
                .config(self.cfg)
                .router(self.app_router);
            if (self.proxy) |p| builder = builder.withProxy(p);
            const srv = builder.build(self.allocator) catch |err| {
                std.log.err("[w{d}] failed to build server: {}", .{ worker_id, err });
                std.process.exit(1);
            };
            defer {
                srv.deinit();
                self.allocator.destroy(srv);
            }

            srv.run(null) catch |err| {
                std.log.err("[w{d}] server error: {}", .{ worker_id, err });
                std.process.exit(1);
            };

            std.log.info("[w{d}] worker exiting cleanly", .{worker_id});
            std.process.exit(0);
        }

        // Parent
        self.worker_pids[worker_id] = pid;
        std.log.info("[master] forked worker {d} (pid {d})", .{ worker_id, pid });
    }

    fn signalAllWorkers(self: *Master, sig: std.posix.SIG) void {
        for (self.worker_pids, 0..) |pid, i| {
            if (pid > 0) {
                std.posix.kill(pid, sig) catch |err| {
                    std.log.warn("[master] failed to signal worker {d} (pid {d}): {}", .{ i, pid, err });
                };
            }
        }
    }

    fn waitAllWorkers(self: *Master) void {
        for (self.worker_pids, 0..) |pid, i| {
            if (pid > 0) {
                // Retry waitpid on EINTR to avoid leaving zombie processes
                while (true) {
                    const rc = std.c.waitpid(pid, null, 0);
                    if (rc >= 0) break;
                    if (std.posix.errno(rc) == .INTR) continue;
                    break; // Other errors (e.g., ECHILD) — child already reaped
                }
                self.worker_pids[i] = 0;
            }
        }
    }

    fn reapChildren(self: *Master) void {
        while (true) {
            var status: c_int = 0;
            const pid = std.c.waitpid(-1, &status, std.c.W.NOHANG);
            if (pid <= 0) break; // No more children to reap

            const worker_idx = self.findWorkerByPid(pid);
            if (worker_idx == null) continue;
            const idx = worker_idx.?;

            self.worker_pids[idx] = 0;

            if (master_shutdown_requested.load(.acquire)) continue;

            const ustatus: u32 = @bitCast(status);
            if (std.c.W.IFSIGNALED(ustatus)) {
                const sig = std.c.W.TERMSIG(ustatus);
                std.log.warn("[master] worker {d} (pid {d}) killed by signal {d}", .{ idx, pid, @intFromEnum(sig) });
                self.respawnWithBackoff(idx);
            } else if (std.c.W.IFEXITED(ustatus)) {
                const code = std.c.W.EXITSTATUS(ustatus);
                if (code != 0) {
                    std.log.warn("[master] worker {d} (pid {d}) exited with code {d}", .{ idx, pid, code });
                    self.respawnWithBackoff(idx);
                } else {
                    std.log.info("[master] worker {d} (pid {d}) exited cleanly", .{ idx, pid });
                }
            }
        }
    }

    fn respawnWithBackoff(self: *Master, worker_id: u16) void {
        const now = nowMs();
        const last = self.last_crash_ms[worker_id];

        // If crashed within 1 second of last crash, increase backoff
        if (last > 0 and now - last < 1000) {
            self.crash_count[worker_id] = @min(self.crash_count[worker_id] + 1, 5);
        } else {
            self.crash_count[worker_id] = 0;
        }

        self.last_crash_ms[worker_id] = now;

        // Backoff: 0, 1s, 2s, 4s, 8s, 16s (capped at 5 consecutive)
        const delay_ms: u64 = if (self.crash_count[worker_id] == 0)
            0
        else
            @as(u64, 1000) << @intCast(self.crash_count[worker_id] - 1);

        if (delay_ms > 0) {
            std.log.warn("[master] respawning worker {d} after {d}ms backoff", .{ worker_id, delay_ms });
            sleepMs(@intCast(delay_ms));
        }

        self.forkWorker(worker_id);
    }

    fn rollingRestart(self: *Master) void {
        // Simple rolling restart: signal old workers, fork new ones
        self.signalAllWorkers(std.posix.SIG.TERM);
        self.waitAllWorkers();

        for (0..self.worker_count) |i| {
            self.forkWorker(@intCast(i));
        }

        std.log.info("[master] rolling restart complete", .{});
    }

    fn findWorkerByPid(self: *Master, pid: std.c.pid_t) ?u16 {
        for (self.worker_pids, 0..) |p, i| {
            if (p == pid) return @intCast(i);
        }
        return null;
    }
};

var worker_id_global: ?u16 = null;

pub fn getWorkerId() ?u16 {
    return worker_id_global;
}

fn detectCpuCount() u16 {
    const count = std.Thread.getCpuCount() catch 1;
    return @intCast(@min(count, MAX_WORKERS));
}

fn installMasterSignals() void {
    const shutdown_sa = std.posix.Sigaction{
        .handler = .{ .handler = handleMasterShutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &shutdown_sa, null);
    std.posix.sigaction(std.posix.SIG.INT, &shutdown_sa, null);

    const reload_sa = std.posix.Sigaction{
        .handler = .{ .handler = handleMasterReload },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &reload_sa, null);

    const child_sa = std.posix.Sigaction{
        .handler = .{ .handler = handleMasterChild },
        .mask = std.posix.sigemptyset(),
        .flags = std.c.SA.NOCLDSTOP,
    };
    std.posix.sigaction(std.posix.SIG.CHLD, &child_sa, null);
}

fn resetChildSignals() void {
    const default_sa = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.CHLD, &default_sa, null);
    std.posix.sigaction(std.posix.SIG.HUP, &default_sa, null);
    // TERM and INT will be re-installed by Server.run()
}

fn sleepMs(ms: u32) void {
    const ts = std.posix.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    while (true) {
        const rc = std.posix.system.nanosleep(&ts, null);
        if (rc == 0) return;
        switch (std.posix.errno(rc)) {
            .INTR => continue,
            else => return,
        }
    }
}

fn nowMs() u64 {
    const instant = clock.Instant.now() orelse return 0;
    return instant.ns / @as(u64, std.time.ns_per_ms);
}

test "detectCpuCount returns at least 1" {
    const count = detectCpuCount();
    try std.testing.expect(count >= 1);
    try std.testing.expect(count <= MAX_WORKERS);
}

test "master init with explicit worker count" {
    var cfg = config.ServerConfig.default();
    cfg.workers = 4;
    const app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    var m = try Master.init(std.testing.allocator, cfg, app_router, null);
    defer m.deinit();

    try std.testing.expectEqual(@as(u16, 4), m.worker_count);
    try std.testing.expectEqual(@as(usize, 4), m.worker_pids.len);
}

test "master init auto-detect" {
    var cfg = config.ServerConfig.default();
    cfg.workers = 0;
    const app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    var m = try Master.init(std.testing.allocator, cfg, app_router, null);
    defer m.deinit();

    try std.testing.expect(m.worker_count >= 1);
}
