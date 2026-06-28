//! # Event loop dispatch
//!
//! The "pull the plug" module at the end of the server.zig
//! decomposition: this owns the main event loop (`runLoop`), the
//! per-event handlers (`handleRead`, `handleWrite`, `handleError`),
//! the low-level socket read/write wrappers (`connRead`, `connWrite`),
//! the kernel-delivery plumbing (`seedReadBuffer`,
//! `advanceAsyncWriteQueue`, `submitConnAsyncWritev`), and the
//! signal-handler atomics that drive graceful shutdown and SIGHUP
//! hot reload.
//!
//! After this extraction, `server.zig` holds only the `Server`
//! struct definition, init/deinit, a thin `run()` wrapper that
//! calls `runLoop(self, run_for_ms)`, and the shared helpers
//! (date cache, buildHttp3RequestView, isAllowedHost,
//! guessContentType, the small canned responses).
//!
//! `handleRead` stays a single monolithic function that routes
//! h1 / h2 / h3 paths inline — splitting it by protocol is a
//! follow-up restructure, not a pure movement.

const std = @import("std");
const build_options = @import("build_options");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const connection = @import("../runtime/connection.zig");
const clock = @import("../runtime/clock.zig");
const io_mod = @import("../runtime/io.zig");
const net = @import("../runtime/net.zig");
const config = @import("../config.zig");
const request_mod = @import("../protocol/request.zig");
const http1 = @import("../protocol/http1.zig");
const http2 = @import("../protocol/http2.zig");
const response_mod = @import("../response/response.zig");
const router = @import("../router/router.zig");
const middleware = @import("../middleware/middleware.zig");

const x402_mod = @import("../middleware/x402.zig");
const auth_mod = @import("../middleware/auth.zig");
const ratelimit_mod = @import("../middleware/ratelimit.zig");
const usage_mod = @import("../middleware/usage.zig");
const ws_mod = @import("../proxy/websocket.zig");
const accept_mod = @import("accept.zig");
const http1_mod = @import("http1.zig");
const pg_client_mod = @import("../db/pg/client.zig");
const pg_handler_api = @import("../db/pg/handler_api.zig");
const wasm_host_call_mod = if (build_options.enable_wasm) @import("../wasm/host_call.zig") else struct {};
const wasm_control_mod = if (build_options.enable_wasm) @import("../wasm/control_client.zig") else struct {};
// The WASM filter host-call (park) deadline is configurable per-server via
// `Server.wasm_host_call_deadline_ms` (default 30s). Binding sites below set the
// park `deadline_ms` from it; the reactor tick fails the call closed past it
// (fuel bounds compute, this backstops a stalled/dead guest).
const http2_mod = @import("http2.zig");
const http3_mod = @import("http3.zig");
const preencoded = @import("preencoded.zig");
const server_tls = @import("tls.zig");
const write_queue = @import("write_queue.zig");
const admin_mod = @import("../admin/admin.zig");
const cache_mod = @import("../proxy/cache.zig");
const otel_mod = @import("../middleware/otel.zig");
const body_schema_mod = @import("../middleware/body_schema.zig");
const settlement_mod = @import("../middleware/settlement.zig");
const x402_client = @import("../middleware/x402_client.zig");

/// Global shutdown flag set by signal handler (atomic for signal safety)
var shutdown_requested = std.atomic.Value(bool).init(false);
/// Graceful drain flag — first SIGTERM sets this, second sets shutdown_requested
var draining = std.atomic.Value(bool).init(false);
/// Global reload flag set by SIGHUP handler (atomic for signal safety)
var reload_requested = std.atomic.Value(bool).init(false);

fn handleShutdownSignal(_: std.posix.SIG) callconv(.c) void {
    if (draining.load(.acquire)) {
        shutdown_requested.store(true, .release);
    } else {
        draining.store(true, .release);
    }
}

fn handleReloadSignal(_: std.posix.SIG) callconv(.c) void {
    reload_requested.store(true, .release);
}

/// Called from `Server.shutdown()` to request a graceful exit from
/// the event loop. Thread/signal safe.
pub fn requestShutdown() void {
    shutdown_requested.store(true, .release);
}

pub fn runLoop(server: *Server, run_for_ms: ?u64) !void {
    shutdown_requested.store(false, .release);
    draining.store(false, .release);
    reload_requested.store(false, .release);

    const sa = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    // Ignore SIGPIPE — SSL_shutdown/SSL_write on a closed socket triggers it
    const pipe_sa = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.PIPE, &pipe_sa, null);
    // Install SIGHUP handler for config hot reload
    const reload_sa = std.posix.Sigaction{
        .handler = .{ .handler = handleReloadSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &reload_sa, null);

    // Install the PG park-resume hook here rather than at Server init:
    // initWithRouter returns the Server by value, so `server` only has
    // its stable address once the loop owns it.
    if (server.pg_client) |pgc| pgc.installResume(@ptrCast(server), pgResume);

    // Build the WASM control-socket transport (C3) for this worker and install
    // its resume hooks. No-op when wasm is off or no control socket is set (the
    // mock transport, if enabled, then drives completions instead).
    server.setupWasmControl();
    if (build_options.enable_wasm) {
        if (server.wasmControlClient()) |cc| cc.installResume(@ptrCast(server), wasmCompleteThunk, wasmFailThunk);
    }

    try server.io.start();
    // Eagerly start PG pool connects at worker boot. Otherwise the pool
    // relies on the first housekeeping tick, which is wall-clock gated and
    // can be delayed for a worker that receives no traffic under CPU
    // oversubscription — its slots stay .closed and the first request
    // routed to it (via SO_REUSEPORT) 503s with NotConnected.
    if (server.pg_client) |pgc| pgc.tick(&server.io, server.io.nowMs());
    // Eagerly start the control-socket connect at worker boot (same rationale as
    // the PG pool: don't wait for the first wall-clock-gated housekeeping tick).
    if (build_options.enable_wasm) {
        if (server.wasmControlClient()) |cc| cc.tick(&server.io, server.io.nowMs());
    }
    server.refreshCachedDate();
    // Bind + register every effective listener. The effective set is the
    // explicit `listeners` array when present, else a single synthesized
    // listener from the legacy single-port fields (listenerForPort). Each
    // worker binds all of them via SO_REUSEPORT. Config is resolved
    // per-connection at accept (getsockname), so the backends stay unaware of
    // which listener a connection arrived on.
    if (server.listeners_count == 0) {
        const synth_listener = server.cfg.listenerForPort(server.cfg.port);
        const effective: []const config.ListenerConfig =
            if (server.cfg.listeners.len > 0) server.cfg.listeners else &[_]config.ListenerConfig{synth_listener};
        for (effective) |lcfg| {
            if (server.listeners_count >= server.listeners_buf.len) {
                std.log.warn("Too many listeners ({d} max); ignoring port {d}", .{ server.listeners_buf.len, lcfg.port });
                continue;
            }
            const fd = try net.listen(lcfg.address, lcfg.port, 4096);
            server.listeners_buf[server.listeners_count] = .{ .fd = fd, .cfg = lcfg };
            server.listeners_count += 1;
        }
        // Keep listener_fd aliased to the first listener for the legacy drain
        // path and any code that still reads it.
        if (server.listeners_count > 0) server.listener_fd = server.listeners_buf[0].fd;
    }
    {
        var li: usize = 0;
        while (li < server.listeners_count) : (li += 1) try server.io.registerListener(server.listeners_buf[li].fd);
    }
    if (server.spare_fd == null) {
        server.spare_fd = std.posix.openat(std.posix.AT.FDCWD, "/dev/null", .{}, 0) catch null;
    }
    // Initialize UDP listener for QUIC if enabled. Only one QUIC listener is
    // expected; use the configured quic_port (a listener entry's quic_port
    // overrides it when one has quic_enabled).
    if (server.quic != null) {
        if (server.udp_fd == null) {
            var quic_port = server.cfg.quic.port;
            for (server.listeners_buf[0..server.listeners_count]) |bl| {
                if (bl.cfg.quic_enabled and bl.cfg.quic_port > 0) {
                    quic_port = bl.cfg.quic_port;
                    break;
                }
            }
            if (quic_port > 0) {
                server.udp_fd = net.bindUdp(server.cfg.address, quic_port) catch |err| {
                    std.log.warn("Failed to bind UDP port {}: {}", .{ quic_port, err });
                    return err;
                };
            }
        }
        if (server.udp_fd) |udp_fd| {
            server.io.registerUdpSocket(udp_fd) catch |err| {
                std.log.warn("Failed to register UDP socket: {}", .{err});
                clock.closeFd(udp_fd);
                server.udp_fd = null;
            };
        }
    }
    // Bind admin API listener if enabled
    if (server.cfg.admin.enabled and server.admin_listener_fd == null) {
        if (admin_mod.bindAdminSocket(server.cfg.admin.address, server.cfg.admin.port)) |fd| {
            server.admin_listener_fd = fd;
            std.log.info("Admin API listening on :{d}", .{server.cfg.admin.port});
        } else |err| {
            std.log.warn("Admin API: failed to bind port {}: {}", .{ server.cfg.admin.port, err });
        }
    }

    // Initialize settlement reporting from proxy route config + auth token
    initSettlement(server);

    // Start async x402 facilitator thread unconditionally. Idle-sleeps 10ms
    // when no work — negligible. Must be unconditional so a hot-reload that
    // adds a facilitator route doesn't leave paid requests unserviced.
    x402_client.start();
    defer x402_client.stop();

    // Start the OTel exporter's background sender thread so flushes never block
    // the reactor on the (remote, TLS) collector. No-op when otel is disabled.
    if (server.otel) |otel_exp| otel_mod.startSender(otel_exp.config);
    defer otel_mod.stopSender();

    const deadline = if (run_for_ms) |ms| server.io.nowMs() + ms else null;
    var last_housekeeping_ms: u64 = server.io.nowMs();
    var drain_deadline_ms: u64 = 0;
    var is_draining = false;
    while (true) {
        if (shutdown_requested.load(.acquire)) return;
        if (!is_draining and draining.load(.acquire)) {
            is_draining = true;
            drain_deadline_ms = server.io.nowMs() + server.cfg.drain_timeout_ms;
            std.log.info("graceful shutdown: draining connections ({d}ms timeout)", .{server.cfg.drain_timeout_ms});
            // Unregister + close every bound listener so no new connections
            // arrive while draining. listener_fd aliases listeners_buf[0].fd,
            // so we drive everything off the array and zero listener_fd to
            // prevent a later double-close in deinit.
            var dli: usize = 0;
            while (dli < server.listeners_count) : (dli += 1) {
                const lfd = server.listeners_buf[dli].fd;
                _ = server.io.unregister(lfd) catch {};
                clock.closeFd(lfd);
            }
            server.listeners_count = 0;
            server.listener_fd = null;
            if (server.admin_listener_fd) |afd| {
                clock.closeFd(afd);
                server.admin_listener_fd = null;
            }
        }
        if (is_draining) {
            if (server.io.connections.active_count == 0) {
                std.log.info("graceful shutdown: all connections drained", .{});
                return;
            }
            if (server.io.nowMs() >= drain_deadline_ms) {
                std.log.info("graceful shutdown: drain timeout, closing {d} remaining connections", .{server.io.connections.active_count});
                return;
            }
        }
        if (reload_requested.load(.acquire)) {
            if (!server.reload_in_progress.load(.acquire)) {
                reload_requested.store(false, .release);
                server.startBackgroundReload();
            }
        }
        server.applyPendingReload();
        if (deadline) |limit| {
            if (server.io.nowMs() >= limit) return;
        }
        // Single clock call per loop iteration — reused for poll
        // timeout, timeout enforcement, proxy maintenance, and all
        // per-event markActive calls (avoids repeated clock_gettime
        // within the same event batch).
        const now_ms = server.io.nowMs();
        server.now_ms = now_ms;
        server.refreshCachedDate();

        // Housekeeping runs at most every 100ms. Poll with timeout=0
        // when housekeeping is due so we don't block while work waits.
        const housekeeping_interval_ms: u64 = 100;
        const needs_housekeeping = (now_ms -% last_housekeeping_ms) >= housekeeping_interval_ms;
        const timeout_ms: u32 = if (needs_housekeeping) 0 else 10;
        const events = try server.io.pollWithTimeout(timeout_ms);

        // Process I/O events BEFORE housekeeping so that requests
        // buffered during the poll are dispatched with minimal latency.
        // Housekeeping (timeout scans, proxy maintenance, admin poll)
        // can add milliseconds of work; deferring it avoids penalizing
        // requests that arrived while we were waiting.
        if (events.len == 0 and !needs_housekeeping) continue;
        for (events) |event| {
            switch (event.kind) {
                .accept => {
                    // Two delivery models:
                    // 1. Pre-accepted: the backend hands us a
                    //    fresh client fd inline (native io_uring
                    //    with its threaded multishot accept).
                    //    Go straight to setup.
                    // 2. Readiness: the backend woke us because
                    //    the listener has pending connections;
                    //    we call accept4() in a userspace loop
                    //    until EAGAIN (epoll, poll, io_uring_poll,
                    //    and native-with-inline-accept).
                    if (event.handle) |client_fd| {
                        accept_mod.handlePreAccepted(server, client_fd) catch |err| {
                            std.log.warn("Pre-accepted setup failed: {}", .{err});
                        };
                    } else {
                        // Readiness model: the backend can't tell us WHICH
                        // listener is ready (kqueue/epoll tag all listener fds
                        // identically), so drain every bound listener. Each
                        // handleAccept loops accept4() until WouldBlock, so a
                        // non-ready fd just returns immediately.
                        var li: usize = 0;
                        while (li < server.listeners_count) : (li += 1) {
                            accept_mod.handleAccept(server, server.listeners_buf[li].fd) catch |err| {
                                std.log.warn("Accept failed: {}", .{err});
                            };
                        }
                    }
                },
                .datagram => {
                    // Native io_uring backend: the multishot recvmsg
                    // CQE delivered the packet payload + peer addr
                    // inline. Process this one datagram, release
                    // the kernel buffer, and continue. Other
                    // backends deliver a readiness event and we
                    // drain the UDP fd via recvfrom.
                    if (event.data) |payload| {
                        http3_mod.handleInlineDatagram(server, payload, event.datagram_peer[0..event.datagram_peer_len], event.datagram_gso_size);
                        if (event.kernel_buffer) |kb| kb.release();
                    } else {
                        try http3_mod.handleDatagram(server);
                    }
                },
                .read, .write, .err => {
                    // External-fd events (PostgreSQL client sockets) are
                    // tagged with EXTERNAL_ID_BIT and routed to their
                    // owner instead of the connection table. Exact
                    // high-bits match (isExternalId), NOT a bare bit
                    // test: UDP_SOCKET_ID also has bit 62 set and its
                    // .err events must not land here. The kernel_buffer
                    // is always null on the readiness backends that
                    // support external fds, but release defensively in
                    // case that ever changes.
                    if (io_mod.isExternalId(event.conn_id)) {
                        if (event.kernel_buffer) |kb| kb.release();
                        const slot: u32 = @intCast(event.conn_id & 0xFFFF_FFFF);
                        // External-fd slots are partitioned by owner: the PG pool
                        // owns 0..MAX_SLOTS-1; the WASM control socket takes the
                        // next slot(s). Route by slot range.
                        if (slot < pg_client_mod.MAX_SLOTS) {
                            if (server.pg_client) |pgc| pgc.onEvent(&server.io, slot, event.kind);
                        } else if (build_options.enable_wasm) {
                            if (server.wasmControlClient()) |cc| cc.onEvent(&server.io, event.kind);
                        }
                        continue;
                    }
                    // Validate conn_id fits in u32 before casting
                    if (event.conn_id > std.math.maxInt(u32)) {
                        if (event.kernel_buffer) |kb| kb.release();
                        continue;
                    }
                    const index: u32 = @intCast(event.conn_id);
                    // Guard against stale events: if the connection slot was freed
                    // and reused between event generation and dispatch, the fd will
                    // be null (freed) or the connection state will be closed/accept.
                    // We MUST still return the kernel buffer in that case — with
                    // multishot recv the backend can deliver multiple CQEs for the
                    // same slot in a single poll() batch, and a close triggered by
                    // an earlier event in the batch will leave any later buffers
                    // stranded if we don't release them here.
                    const conn = server.io.getConnection(index) orelse {
                        if (event.kernel_buffer) |kb| kb.release();
                        continue;
                    };
                    if (conn.fd == null or conn.state == .closed or conn.state == .accept) {
                        if (event.kernel_buffer) |kb| kb.release();
                        continue;
                    }
                    // If the backend delivered read data inline
                    // (io_uring native multishot recv), seed it before
                    // anything else — the handshake path also needs to
                    // see the ciphertext bytes since TLS sessions use
                    // memory BIOs (the kernel has already drained the
                    // fd, so SSL_read via a socket BIO would miss it).
                    // seedReadBuffer routes plaintext to conn.read_buffer
                    // and ciphertext to the TLS rbio memory BIO.
                    if (event.kind == .read) {
                        if (event.data) |kernel_data| {
                            seedReadBuffer(server, conn, kernel_data);
                        }
                        // Release the kernel buffer back to the ring
                        // AFTER seeding but BEFORE running handlers.
                        // The data has been copied out of kernel
                        // memory, so we're safe to return the slot.
                        if (event.kernel_buffer) |kb| kb.release();
                    }
                    // TLS handshake in progress — any I/O event continues it
                    if (conn.state == .handshake) {
                        server_tls.handleTlsHandshake(server, conn) catch {
                            server.closeConnection(conn);
                            continue;
                        };
                        // Re-arm recv on the native backend so the next
                        // handshake segment (or post-handshake data)
                        // triggers a read event.
                        const hconn = server.io.getConnection(index) orelse continue;
                        if (hconn.state != .closed and !hconn.close_after_write) {
                            if (hconn.fd) |hfd| {
                                server.io.rearmRecv(index, hfd);
                            }
                        }
                        continue;
                    }
                    switch (event.kind) {
                        .read => {
                            // Snapshot conn.id so we can detect slot
                            // reuse after handleRead runs. If the
                            // slot gets released and re-acquired for
                            // a new connection, the id changes and
                            // we must NOT rearm recv — the new
                            // connection has its own recv SQE from
                            // registerConnection, and a stray rearm
                            // would create a double-recv race on
                            // the same fd.
                            const pre_id: u64 = conn.id;
                            handleRead(server, index) catch |err| {
                                std.log.debug("handleRead conn={} failed: {}", .{ index, err });
                            };
                            // Edge-triggered epoll: EPOLLOUT may have been consumed earlier
                            // (e.g., sending h2 SETTINGS). Flush any responses queued by handleRead.
                            const rconn = server.io.getConnection(index) orelse continue;
                            if (rconn.write_count > 0 or rconn.hasPendingH2Streams()) {
                                handleWrite(server, index) catch {};
                            }
                            // Re-arm single-shot recv on the native backend
                            // if the connection is still the same incarnation
                            // AND is not about to close. For close-mode
                            // requests with async writev, the close happens
                            // when the write CQE arrives (later, in the
                            // .write dispatcher arm), not synchronously in
                            // handleWrite. At this point the connection is
                            // still .active with an in-flight async write,
                            // but `close_after_write` is set — we must NOT
                            // arm a new recv because the kernel may reuse
                            // the fd number for a new connection as soon
                            // as our close lands, and the zombie recv SQE
                            // would then race with that new connection's
                            // own recv.
                            const postconn = server.io.getConnection(index) orelse continue;
                            if (postconn.id == pre_id and
                                postconn.state != .closed and
                                !postconn.close_after_write and
                                postconn.x402 == .none)
                            {
                                if (postconn.fd) |pfd| {
                                    server.io.rearmRecv(index, pfd);
                                }
                            }
                        },
                        .write => {
                            // Async writev CQE from the native backend:
                            // `event.bytes` carries `cqe.res` (the bytes
                            // the kernel actually sent). Advance the
                            // write queue before entering handleWrite so
                            // the next submission sees the post-ack state.
                            if (conn.send_in_flight) {
                                write_queue.advanceAsyncWriteQueue(server, conn, event.bytes);
                            }
                            handleWrite(server, index) catch |err| {
                                std.log.debug("handleWrite conn={} failed: {}", .{ index, err });
                            };
                        },
                        .err => handleError(server, index) catch |err| {
                            std.log.debug("handleError conn={} failed: {}", .{ index, err });
                        },
                        .accept, .datagram => unreachable,
                    }
                },
            }
        }

        // Housekeeping runs AFTER event dispatch so that requests
        // already sitting in the completion queue (io_uring) or
        // signalled by epoll are served first.
        if (needs_housekeeping) {
            last_housekeeping_ms = now_ms;
            while (true) {
                const timeout_result = server.io.enforceTimeouts(now_ms);
                for (timeout_result.to_close[0..timeout_result.count]) |conn_index| {
                    if (server.io.getConnection(conn_index)) |conn| {
                        server.closeConnection(conn);
                    }
                }
                if (timeout_result.count < timeout_result.to_close.len) break;
            }
            if (server.quic) |*q| {
                q.cleanup();
            }
            if (server.proxy) |proxy| {
                proxy.runMaintenance(now_ms);
            }
            if (server.pg_client) |pgc| {
                pgc.tick(&server.io, now_ms);
            }
            if (build_options.enable_wasm) {
                if (server.wasmControlClient()) |cc| cc.tick(&server.io, now_ms);
            }
            wasmTick(server, now_ms);
            if (server.otel) |otel_exp| {
                otel_exp.tick(now_ms);
            }
            admin_mod.pollAdmin(server);
            settlement_mod.flush();
        }
        // Drain async x402 facilitator results.
        while (x402_client.pollResult()) |result| {
            switch (result.kind) {
                .verify => {
                    const rconn = server.io.getConnection(result.conn_index) orelse continue;
                    if (rconn.id != result.conn_id) continue;
                    if (rconn.x402 != .pending) continue;
                    rconn.x402 = if (result.is_valid) .resolved_allow else .resolved_reject;
                    if (rconn.isAccumulatingBody()) {
                        http1_mod.dispatchWithAccumulatedBody(server, rconn) catch {};
                    } else {
                        handleRead(server, result.conn_index) catch {};
                    }
                    const postconn = server.io.getConnection(result.conn_index) orelse continue;
                    if (postconn.id == result.conn_id and postconn.state != .closed) {
                        if (postconn.write_count > 0 or postconn.hasPendingH2Streams()) {
                            handleWrite(server, result.conn_index) catch {};
                        }
                        if (!postconn.close_after_write and postconn.x402 == .none) {
                            if (postconn.fd) |pfd| server.io.rearmRecv(result.conn_index, pfd);
                        }
                    }
                },
                .settle => {
                    const sconn = server.io.getConnection(result.conn_index);
                    const is_parked = if (sconn) |sc| sc.id == result.conn_id and sc.x402 == .settle_pending else false;

                    if (is_parked) {
                        resumeSettlePark(server, sconn.?, &result);
                        handleRead(server, result.conn_index) catch {};
                        const postconn = server.io.getConnection(result.conn_index) orelse continue;
                        if (postconn.id == result.conn_id and postconn.state != .closed) {
                            if (postconn.write_count > 0 or postconn.hasPendingH2Streams()) {
                                handleWrite(server, result.conn_index) catch {};
                            }
                            if (!postconn.close_after_write and postconn.x402 == .none) {
                                if (postconn.fd) |pfd| server.io.rearmRecv(result.conn_index, pfd);
                            }
                        }
                    }

                    if (result.success and result.has_settlement_url) {
                        settlement_mod.enqueue(
                            result.gateway_id[0..result.gateway_id_len],
                            result.transaction[0..result.transaction_len],
                            result.settle_network[0..result.settle_network_len],
                            result.settle_asset[0..result.settle_asset_len],
                            result.settle_amount[0..result.settle_amount_len],
                            result.request_path[0..result.request_path_len],
                        );
                    } else if (!result.success) {
                        std.log.warn("x402 async settlement failed: {s}", .{result.error_reason[0..result.error_reason_len]});
                        x402_client.spillSettle(
                            result.gateway_id[0..result.gateway_id_len],
                            result.settle_network[0..result.settle_network_len],
                            result.settle_asset[0..result.settle_asset_len],
                            result.settle_amount[0..result.settle_amount_len],
                            result.error_reason[0..result.error_reason_len],
                        );
                    }
                },
            }
        }
    }
}

/// Copy kernel-delivered read data into the connection's read buffer.
/// Called by the event dispatcher when the backend (io_uring native)
/// delivered the data inline with the read event. After seeding,
/// handleRead's existing pipeline loop picks up the data the same
/// way it would after a read() syscall.
///
/// For TLS connections the incoming bytes are ciphertext and go into
/// the session's rbio (memory BIO) instead of `conn.read_buffer`.
/// handleTlsHandshake / connRead then call SSL_do_handshake / SSL_read
/// which pull from rbio, run the decrypt, and deliver plaintext into
/// `conn.read_buffer`.
pub fn seedReadBuffer(server: *Server, conn: *connection.Connection, data: []const u8) void {
    if (data.len == 0) return;
    if (conn.is_tls) {
        // Feed ciphertext into rbio. BIO_write may consume less than
        // requested on an internal failure; loop until drained or the
        // BIO refuses progress.
        if (conn.tls_session) |*session| {
            var remaining = data;
            while (remaining.len > 0) {
                const n = session.feedCryptoData(remaining) catch {
                    // rbio write failed — drop the remaining bytes; the
                    // next SSL_read will hit a TLS error and close the
                    // connection cleanly.
                    return;
                };
                if (n == 0) return;
                remaining = remaining[n..];
            }
            conn.markActive(server.now_ms);
        }
        return;
    }
    const buf = conn.read_buffer orelse return;
    const end = conn.read_offset + conn.read_buffered_bytes;
    if (end + data.len > buf.bytes.len) {
        // Data doesn't fit in the remaining buffer space, and the extra bytes
        // were already consumed from the kernel ring (we can't get them back).
        // Buffer what fits so any complete request already present is still
        // handled, then close the connection: keeping it open would strand it
        // waiting for bytes we discarded (a parser stuck on .partial until the
        // idle timeout). close_after_write lets a queued response flush first.
        const available = if (end >= buf.bytes.len) 0 else buf.bytes.len - end;
        conn.close_after_write = true;
        if (available == 0) return;
        @memcpy(buf.bytes[end..][0..available], data[0..available]);
        server.io.onReadBuffered(conn, available);
        conn.markActive(server.now_ms);
        return;
    }
    @memcpy(buf.bytes[end..][0..data.len], data);
    server.io.onReadBuffered(conn, data.len);
    conn.markActive(server.now_ms);
}

/// Chaining hook handed to continuations via ResumeContext.query():
/// issues the next query on the same connection, carrying the previous
/// stash forward (the blessed step-switch pattern mutates the stash
/// BEFORE re-parking, so copying it into the new park entry preserves
/// the chain's state).
const PgRepark = struct {
    server: *Server,
    conn_index: u32,
    conn_id: u64,
    stash: *[pg_handler_api.STASH_CAPACITY]u8,

    fn repark(
        ctx_ptr: *anyopaque,
        sql: []const u8,
        args: []const ?[]const u8,
        continuation: pg_handler_api.Continuation,
    ) pg_handler_api.QueryError!response_mod.Response {
        const self: *PgRepark = @ptrCast(@alignCast(ctx_ptr));
        const pgc = self.server.pg_client orelse return error.NotConnected;
        return pgc.query(
            &self.server.io,
            self.conn_index,
            self.conn_id,
            sql,
            args,
            self.stash,
            continuation,
        );
    }

    fn reparkBatch(
        ctx_ptr: *anyopaque,
        sql: []const u8,
        args_batch: []const []const ?[]const u8,
        continuation: pg_handler_api.Continuation,
    ) pg_handler_api.QueryError!response_mod.Response {
        const self: *PgRepark = @ptrCast(@alignCast(ctx_ptr));
        const pgc = self.server.pg_client orelse return error.NotConnected;
        return pgc.queryBatch(
            &self.server.io,
            self.conn_index,
            self.conn_id,
            sql,
            args_batch,
            self.stash,
            continuation,
        );
    }
};

/// Continuation response scratch. Larger than the handler path's 8KB:
/// batch results (TFB /queries, /updates at 500 rows) render ~18KB of
/// JSON, and continuations have no preencoded fast path to fall back
/// on. Stack-allocated per resume, same lifetime discipline as
/// dispatchToRouter's response_buf.
const PG_RESUME_BUF_SIZE: usize = 24 * 1024;

/// Park-resume hook (installed on PgClient at runLoop start). Runs on
/// the reactor when a parked request's PG op completes — success,
/// server error, timeout, or connection loss all arrive here exactly
/// once per park. Mirrors dispatchToRouter's scratch environment around
/// the continuation, then queues its response and restarts the
/// connection's I/O (writes first, then any pipelined requests that
/// were gated behind the park).
fn pgResume(ctx: *anyopaque, outcome: *const pg_client_mod.Outcome) void {
    const server: *Server = @ptrCast(@alignCast(ctx));
    // Generation check: the HTTP connection may have been closed and
    // its slot recycled while the op was in flight. cancelForConn on
    // the close path makes this unreachable in practice; it stays as
    // the load-bearing backstop.
    const conn = server.io.getConnection(outcome.conn_index) orelse return;
    if (conn.id != outcome.conn_id) return;
    if (conn.x402 != .db_parked) return;
    conn.x402 = .none;

    var response_buf: [PG_RESUME_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const arena_handle = server.io.acquireBuffer();
    defer if (arena_handle) |h| server.io.releaseBuffer(h);
    var empty_arena: [0]u8 = undefined;
    const arena_buf = if (arena_handle) |h| h.bytes else empty_arena[0..];

    var repark_state = PgRepark{
        .server = server,
        .conn_index = outcome.conn_index,
        .conn_id = outcome.conn_id,
        .stash = outcome.stash,
    };
    var rctx = pg_handler_api.ResumeContext{
        .result = outcome.result,
        .server_error = outcome.server_error,
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena = std.heap.FixedBufferAllocator.init(arena_buf),
        .stash_bytes = outcome.stash,
        .repark_ctx = @ptrCast(&repark_state),
        .repark_fn = PgRepark.repark,
        .repark_batch_fn = PgRepark.reparkBatch,
    };
    const resp = outcome.continuation(&rctx);

    // Same sentinel discipline as the handler path (http1
    // handleParkSentinel): a re-park flips the connection back to
    // .db_parked and waits; anything else gets queued now.
    if (http1_mod.handleParkSentinel(server, conn, resp)) {
        if (conn.x402 == .db_parked) return; // re-parked; resume again later
    } else {
        http1_mod.queueResponse(server, conn, resp) catch {
            conn.close_after_write = true;
        };
    }

    // Restart the connection's I/O: flush the queued response, then
    // process any pipelined requests that buffered behind the park
    // (no new readiness event will fire for bytes already in the read
    // buffer). Re-fetch the connection — the write path can close it.
    if (conn.write_count > 0) handleWrite(server, outcome.conn_index) catch {};
    const postconn = server.io.getConnection(outcome.conn_index) orelse return;
    if (postconn.id != outcome.conn_id or postconn.state == .closed) return;
    if (postconn.x402 == .none and postconn.read_buffered_bytes > 0) {
        handleRead(server, outcome.conn_index) catch {};
    }
    // Re-arm recv (same as the x402 drain): the native io_uring backend
    // uses single-shot recv, and the normal read path's re-arm was
    // skipped when the pipeline loop broke to park. Without this, a
    // keep-alive connection goes silent after its first DB response —
    // readiness backends don't need it (persistent registration) but it
    // is harmless there.
    const rconn = server.io.getConnection(outcome.conn_index) orelse return;
    if (rconn.id != outcome.conn_id or rconn.state == .closed) return;
    if (!rconn.close_after_write and rconn.x402 == .none) {
        if (rconn.fd) |pfd| server.io.rearmRecv(outcome.conn_index, pfd);
    }
}

/// Drive a completed WASM host call: deliver the resumed filter Decision to the
/// parked HTTP connection and restart its I/O. Mirrors pgResume, but a wasm
/// FILTER parked before the handler, so allow/modify RE-DISPATCH the request
/// (re-enter router.handle with the filter skipped so the handler runs); reject
/// and backpressure are served directly. The transport (C1) and the deadline
/// tick call this. Routes delivery by completion.protocol: .http1 is implemented;
/// .http2/.http3 are E2 stubs. Compiled only when wasm is enabled.
fn wasmResume(server: *Server, completion: wasm_host_call_mod.Completion) void {
    switch (completion.protocol) {
        .http1 => {},
        .http2 => {
            // E2a: deliver a resumed parked H2 stream's response on its own
            // stream via queueHttp2Response, keyed by completion.stream_id. The
            // connection kept multiplexing while this stream was parked.
            wasmResumeHttp2(server, completion);
            return;
        },
        .http3 => {
            // E2b: deliver a resumed parked H3 stream's response on its own QUIC
            // stream via the h3 send path, keyed by the QUIC connection id +
            // stream id. The connection kept multiplexing its other streams while
            // this one was parked.
            wasmResumeHttp3(server, completion);
            return;
        },
    }
    const conn = server.io.getConnection(completion.conn_index) orelse return;
    if (conn.id != completion.conn_id) return; // slot recycled while parked
    if (conn.x402 != .wasm_parked) return;
    conn.x402 = .none;

    switch (completion.decision) {
        .reject => |resp| {
            http1_mod.queueResponse(server, conn, resp) catch {
                conn.close_after_write = true;
            };
            // The reject body borrows the resumed instance's staged scratch
            // (released to .idle by resumeCall/cancel); copy any spilled tail to
            // stable pool buffers before the next request reuses the instance.
            if (conn.pending_body.len > 0) http1_mod.materializePendingBody(server, conn);
        },
        .rate_limit_backpressure => |bp| {
            http1_mod.queueResponse(server, conn, bp.resp) catch {
                conn.close_after_write = true;
            };
            if (bp.pause_reads) conn.setRateLimitPause(server.now_ms, bp.resume_after_ms);
        },
        .allow, .skip, .modify => {
            // Proxy route? Re-forward through the proxy with the filter skipped
            // (the upstream was never contacted at park time). Falls through to
            // the embedded-Router re-dispatch when it is not a proxy route.
            if (proxyResume(server, conn, completion)) {
                // Restart I/O below (shared tail).
                if (conn.write_count > 0) handleWrite(server, completion.conn_index) catch {};
                const pc = server.io.getConnection(completion.conn_index) orelse return;
                if (pc.id != completion.conn_id or pc.state == .closed) return;
                if (pc.x402 == .none and pc.read_buffered_bytes > 0) handleRead(server, completion.conn_index) catch {};
                const rc = server.io.getConnection(completion.conn_index) orelse return;
                if (rc.id != completion.conn_id or rc.state == .closed) return;
                if (!rc.close_after_write and rc.x402 == .none) {
                    if (rc.fd) |pfd| server.io.rearmRecv(completion.conn_index, pfd);
                }
                return;
            }
            // Re-run the pipeline with the resumed decision injected so the
            // filter is skipped and the handler runs. completion.req is the
            // park slot's OWNED snapshot (valid through this synchronous resume),
            // not a borrow of the connection read buffer.
            var response_buf: [PG_RESUME_BUF_SIZE]u8 = undefined;
            var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
            const arena_handle = server.io.acquireBuffer();
            defer if (arena_handle) |h| server.io.releaseBuffer(h);
            var empty_arena: [0]u8 = undefined;
            const arena_buf = if (arena_handle) |h| h.bytes else empty_arena[0..];
            var mw_ctx = middleware.Context{
                .client_ip = conn.cached_peer_ip,
                .protocol = .http1,
            };
            var scratch = router.HandlerScratch{
                .response_buf = response_buf[0..],
                .response_headers = response_headers[0..],
                .arena_buf = arena_buf,
                .pg = .{
                    .client = server.pg_client,
                    .io_rt = &server.io,
                    .conn_index = completion.conn_index,
                    .conn_id = completion.conn_id,
                },
                .wasm = .{
                    .table = if (build_options.enable_wasm) @ptrCast(&server.wasm_host_calls) else null,
                    .conn_index = completion.conn_index,
                    .conn_id = completion.conn_id,
                    .stream_id = completion.stream_id, // 0 for H1
                    .protocol = .http1,
                    .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
                    .resume_decision = completion.decision,
                },
            };
            const result = server.app_router.handle(completion.req, &mw_ctx, &scratch);
            // The handler may itself park (PG); handleParkSentinel catches that.
            if (http1_mod.handleParkSentinel(server, conn, result.resp)) {
                if (conn.x402 != .none) return; // re-parked; resume again later
            } else {
                http1_mod.queueResponse(server, conn, result.resp) catch {
                    conn.close_after_write = true;
                };
                // Same Phase 2b hazard as the main loop: a replaced response body
                // borrows the (now-idle, soon-reused) instance scratch; copy any
                // spilled tail into stable pool buffers before returning.
                if (conn.pending_body.len > 0) http1_mod.materializePendingBody(server, conn);
            }
        },
    }

    // Restart connection I/O (same tail as pgResume): flush, drain pipelined
    // requests buffered behind the park, re-arm recv.
    if (conn.write_count > 0) handleWrite(server, completion.conn_index) catch {};
    const postconn = server.io.getConnection(completion.conn_index) orelse return;
    if (postconn.id != completion.conn_id or postconn.state == .closed) return;
    if (postconn.x402 == .none and postconn.read_buffered_bytes > 0) {
        handleRead(server, completion.conn_index) catch {};
    }
    const rconn = server.io.getConnection(completion.conn_index) orelse return;
    if (rconn.id != completion.conn_id or rconn.state == .closed) return;
    if (!rconn.close_after_write and rconn.x402 == .none) {
        if (rconn.fd) |pfd| server.io.rearmRecv(completion.conn_index, pfd);
    }
}

/// Park-time context the proxy post-forward processing needs on resume. Holds
/// only what cannot be recomputed from (server, conn, proxy, req, route_idx):
/// the route index, the otel span start, and the live x402 evaluation result.
/// The main loop builds this on the stack from its locals; proxyResume rebuilds
/// it from the stashed connection.WasmProxyResumeCtx plus the owned snapshot.
const ProxyPostCtx = struct {
    route_idx: usize,
    otel_start: i128,
    x402_result: x402_mod.EvaluateResult,
};

/// Outcome of proxyForwardAndRespond: whether the response was served, or the
/// connection parked for inline-receipt settlement (response held, delivered
/// when settlement completes). The main loop ignores it (its loop tail is the
/// same either way); proxyResume relies on conn.x402 (set to .settle_pending on
/// a settle-park) to drive the I/O restart, so the enum is informational.
const ProxyRespondOutcome = enum { responded, settle_parked };

/// Run the post-`proxy.handle` processing the main dispatch loop performs after a
/// proxy forward, factored out so the resumed (wasm-parked) proxy path runs it
/// too: response-cache store/invalidate, the otel span, x402 settlement (incl.
/// the inline-receipt settle-park via packHeldResponse), then queueResponse plus
/// the owned-buffer tail. Behavior is identical to the inline tail it replaces.
///
/// On a settle-park it sets conn.x402 = .settle_pending, holds the response, and
/// returns .settle_parked WITHOUT calling queueResponse (the held response is
/// delivered when settlement completes); otherwise it queues the response and
/// returns .responded. The vary keys and per-route config are recomputed from
/// route_idx so both call sites pass a minimal context. Compiled in all builds
/// (no wasm dependency).
fn proxyForwardAndRespond(
    server: *Server,
    conn: *connection.Connection,
    proxy: *proxy_mod.Proxy,
    req: request_mod.RequestView,
    proxy_result: *proxy_mod.ProxyResult,
    pctx: ProxyPostCtx,
) !ProxyRespondOutcome {
    const route_idx = pctx.route_idx;
    const cache_cfg = proxy.config.routes[route_idx].cache;

    // Recompute the vary keys exactly as the pre-forward cache lookup did: base
    // vary from config + the implicit accept-encoding key (the proxy may compress
    // per the client's Accept-Encoding before the store below).
    var vary_buf: [16][]const u8 = undefined;
    const vary_keys: []const []const u8 = blk: {
        const base_vary: []const []const u8 = if (cache_cfg) |cc| cc.vary else &.{};
        const n = @min(base_vary.len, vary_buf.len - 1);
        for (base_vary[0..n], 0..) |v, vi| vary_buf[vi] = v;
        vary_buf[n] = "accept-encoding";
        break :blk vary_buf[0 .. n + 1];
    };

    // Cache store: cache successful GET responses
    if (cache_cfg) |cc| {
        if (req.method == .GET and proxy_result.resp.status == 200) {
            if (proxy.route_caches[route_idx]) |*rc| {
                rc.store(
                    req.path,
                    req.headers,
                    vary_keys,
                    proxy_result.resp.status,
                    proxy_result.resp.headers,
                    proxy_result.resp.bodyBytes(),
                    @as(u64, cc.ttl_s) * 1000,
                    server.now_ms,
                );
            }
        }
    }
    // Invalidate cache on mutating methods
    if (cache_cfg != null and req.method != .GET and req.method != .HEAD) {
        if (proxy.route_caches[route_idx]) |*rc| {
            rc.invalidate(req.path);
        }
    }

    if (server.otel) |otel_exp| {
        otel_exp.recordSpan(req.method, req.path, proxy_result.resp.status, pctx.otel_start, clock.realtimeNanos() orelse 0);
    }

    // Settlement: submit async, optionally park for inline receipt
    const x402_result = pctx.x402_result;
    const x402_policy = proxy.route_x402_policies[route_idx];
    const route_fac = proxy.route_facilitators[route_idx] orelse server.app_router.facilitator;
    settle_blk: {
        if (proxy_result.resp.status < 200 or proxy_result.resp.status >= 300) break :settle_blk;
        if (!(x402_result == .allow and x402_result.allow.needs_settlement)) break :settle_blk;
        const fac = route_fac orelse break :settle_blk;
        const charge = for (proxy_result.resp.headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, "x-charge-amount")) break hdr.value;
        } else "";
        var settle_entry = x402_client.RequestEntry{ .kind = .settle, .conn_index = conn.index, .conn_id = conn.id };
        fillSettleEntry(&settle_entry, fac, x402_result.allow.payment_header, &x402_policy, charge, req.path);
        if (settle_entry.http_len == 0) break :settle_blk;

        // Settle-park: hold response until settlement completes, then inject receipt header.
        // Enabled by config (inline_receipt) or per-request header (X-Inline-Receipt: true).
        const want_receipt = x402_policy.inline_receipt or for (req.headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, "x-inline-receipt")) break std.mem.eql(u8, hdr.value, "true");
        } else false;
        if (want_receipt and packHeldResponse(server, conn, proxy_result.resp)) {
            if (x402_client.submit(settle_entry)) {
                conn.x402 = .settle_pending;
                server.io.setTimeoutPhase(conn, .write);
                conn.phase_enter_ms = server.now_ms;
                conn.markActive(server.now_ms);
                return .settle_parked;
            }
            releaseHeldBuffer(server, conn);
        }

        // Fire-and-forget: submit settle without parking
        if (!x402_client.submit(settle_entry)) {
            x402_client.spillSettle(
                x402_policy.gateway_id,
                x402_policy.network,
                x402_policy.asset,
                if (charge.len > 0) charge else x402_policy.price,
                "settle queue full",
            );
        }
    }

    try http1_mod.queueResponse(server, conn, proxy_result.resp);
    if (conn.pending_body.len > 0) {
        if (proxy_result.takeOwnedBuf()) |owned| {
            // Large proxied response: the unsent tail points into the proxy's
            // heap buffer. Take ownership so it outlives proxy_result.release();
            // freed when the tail drains (handleWrite) or the connection closes.
            std.debug.assert(conn.pending_body_owned == null);
            conn.pending_body_owned = owned;
        } else {
            // Pool-buffer response: copy the tail out before proxy_result.release()
            // frees the upstream buffer.
            http1_mod.materializePendingBody(server, conn);
        }
    }
    return .responded;
}

/// Re-forward a parked PROXY request after its host call completed (resume to
/// allow). Returns true if the parked request was a proxy route (handled here);
/// false if not (the caller falls back to the embedded-Router re-dispatch).
///
/// Re-enters proxy.handle with the filter skipped (resume_decision injected) then
/// runs the SAME post-forward processing the main loop runs via
/// proxyForwardAndRespond -- response-cache store/invalidate, the otel span, and
/// x402 settlement (incl. the inline-receipt settle-park) -- so a parked-then-
/// allowed proxy request is cached/metered/settled like a non-parked one (E1).
/// The upstream was not contacted at park time, so this is where the forward
/// actually happens. The post-forward context is read from the connection's
/// WasmProxyResumeCtx (stashed by the main loop, reached via completion.resume_ctx)
/// plus the owned request snapshot. v1 limitation that REMAINS: auth_info/cert_dn
/// are not re-derived, so upstream auth-header injection is absent for parked
/// reqs. Compiled only when wasm is enabled.
fn proxyResume(server: *Server, conn: *connection.Connection, completion: wasm_host_call_mod.Completion) bool {
    if (!build_options.enable_wasm) return false;
    const proxy = server.proxy orelse return false;
    const route = proxy.matchRoute(&completion.req) orelse return false;
    if (route.wasm_pool == null) return false; // not a wasm-filtered proxy route

    var ip_buf: [64]u8 = undefined;
    var client_ip_str: ?[]const u8 = null;
    if (conn.cached_peer_ip) |ip4| {
        const n = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
        if (n.len > 0) client_ip_str = ip_buf[0..n.len];
    }
    var mw_ctx = middleware.Context{ .client_ip = conn.cached_peer_ip, .protocol = .http1 };
    // resume_decision skips the filter; auth_info/cert_dn are not re-derived on
    // the resumed path (v1) -- upstream auth injection is absent for parked reqs.
    const binding = proxy_mod.WasmBinding{ .resume_decision = completion.decision };
    var pr = proxy.handle(
        completion.req,
        &mw_ctx,
        client_ip_str,
        conn.tls_session != null,
        server.now_ms,
        null,
        null,
        binding,
    );
    defer pr.release();

    // Rebuild the post-forward context stashed by the main loop at park time. The
    // resume_ctx pointer aliases this connection's WasmProxyResumeCtx; fall back
    // to the field directly if a transport ever delivers a null ctx.
    const rctx: *const connection.Connection.WasmProxyResumeCtx = if (completion.resume_ctx) |p|
        @ptrCast(@alignCast(p))
    else
        &conn.wasm_proxy_resume;
    // Reconstruct the x402 evaluation result from the carried needs_settlement
    // flag (the result at park time is always .allow -- rejects fast-return before
    // the forward). Re-point payment_header at the OWNED request snapshot; the
    // original slice borrowed the now-reused read buffer.
    const x402_result: x402_mod.EvaluateResult = .{ .allow = .{
        .payment_header = x402_mod.findValidPaymentHeader(completion.req) orelse "",
        .needs_settlement = rctx.needs_settlement,
    } };
    _ = proxyForwardAndRespond(server, conn, proxy, completion.req, &pr, .{
        .route_idx = rctx.route_idx,
        .otel_start = rctx.otel_start,
        .x402_result = x402_result,
    }) catch {
        conn.close_after_write = true;
    };
    return true;
}

/// Deliver a resumed parked HTTP/2 stream's filter Decision on its own stream
/// (E2a). Mirrors the H1 wasmResume body but routes delivery through
/// queueHttp2Response on completion.stream_id, leaving the rest of the
/// connection's streams untouched (the connection kept multiplexing while this
/// stream was parked, so there is no pipeline gate to lift). allow/modify
/// RE-DISPATCH the request (proxy re-forward or router re-run with the filter
/// skipped); reject/backpressure are served directly on the stream. Compiled
/// only when wasm is enabled.
fn wasmResumeHttp2(server: *Server, completion: wasm_host_call_mod.Completion) void {
    if (!build_options.enable_wasm) return;
    const conn = server.io.getConnection(completion.conn_index) orelse return;
    if (conn.id != completion.conn_id) return; // slot recycled while parked
    if (conn.protocol != .http2 or conn.http2_stack == null) return;
    const stream_id = completion.stream_id;
    const is_head = completion.req.method == .HEAD;

    switch (completion.decision) {
        .reject => |resp| {
            http2_mod.queueHttp2Response(server, conn, stream_id, resp, is_head) catch {};
        },
        .rate_limit_backpressure => |bp| {
            // Serve the backpressure response on this stream only. A
            // connection-level read pause would stall sibling streams, so H2
            // does not pause reads here; per-stream backpressure (a STREAM-level
            // flow-control stall) is a deferred refinement.
            http2_mod.queueHttp2Response(server, conn, stream_id, bp.resp, is_head) catch {};
        },
        .allow, .skip, .modify => {
            // Proxy route? Re-forward with the filter skipped (the upstream was
            // never contacted at park time). Falls through to the embedded-Router
            // re-dispatch when it is not a proxy route.
            if (!proxyResumeHttp2(server, conn, completion)) {
                // Re-run the router with the resumed decision injected so the
                // filter is skipped and the handler runs. completion.req is the
                // park slot's OWNED snapshot (valid through this synchronous
                // resume), not a borrow of a reused frame buffer.
                var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
                var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
                const needs_eager_arena = (completion.req.method != .GET and completion.req.method != .HEAD and completion.req.method != .DELETE);
                const arena_handle = if (needs_eager_arena) server.io.acquireBuffer() else null;
                var empty_arena: [0]u8 = undefined;
                const arena_buf = if (arena_handle) |h| h.bytes else empty_arena[0..];
                var mw_ctx = middleware.Context{
                    .protocol = .http2,
                    .is_tls = conn.is_tls,
                    .stream_id = stream_id,
                    .buffer_ops = .{
                        .ctx = &server.io,
                        .acquire = write_queue.acquireBufferOpaque,
                        .release = write_queue.releaseBufferOpaque,
                    },
                };
                if (conn.cached_peer_ip) |ip4| {
                    mw_ctx.client_ip = ip4;
                } else if (conn.cached_peer_ip6) |ip6| {
                    mw_ctx.client_ip6 = ip6;
                }
                var scratch = router.HandlerScratch{
                    .response_buf = response_buf[0..],
                    .response_headers = response_headers[0..],
                    .arena_buf = arena_buf,
                    .arena_handle = arena_handle,
                    .buffer_ops = mw_ctx.buffer_ops,
                    .wasm = .{
                        .table = @ptrCast(&server.wasm_host_calls),
                        .conn_index = completion.conn_index,
                        .conn_id = completion.conn_id,
                        .stream_id = stream_id,
                        .protocol = .http2,
                        .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
                        .resume_decision = completion.decision,
                    },
                };
                const result = server.app_router.handle(completion.req, &mw_ctx, &scratch);
                if (scratch.arena_handle) |h| server.io.releaseBuffer(h);
                if (result.pause_reads_ms) |pause_ms| conn.setRateLimitPause(server.now_ms, pause_ms);
                http2_mod.queueHttp2Response(server, conn, stream_id, result.resp, is_head) catch {};
            }
        },
    }

    // Flush the freshly queued frames and re-arm recv. handleWrite is a no-op
    // when the connection has no fd (unit tests inspect the queue directly) and
    // flushes to the socket in production. No x402/.wasm_parked gate exists for
    // H2: the connection was never suspended, only this one stream.
    if (conn.write_count > 0) handleWrite(server, completion.conn_index) catch {};
    const rc = server.io.getConnection(completion.conn_index) orelse return;
    if (rc.id != completion.conn_id or rc.state == .closed) return;
    if (!rc.close_after_write) {
        if (rc.fd) |pfd| server.io.rearmRecv(completion.conn_index, pfd);
    }
}

/// Re-forward a parked PROXY request on an HTTP/2 stream after its host call
/// completed (resume to allow). Returns true if the parked request was a proxy
/// route (handled here); false if not (the caller falls back to the
/// embedded-Router re-dispatch). Mirrors proxyResume but delivers via
/// queueHttp2Response on completion.stream_id. Compiled only when wasm is enabled.
fn proxyResumeHttp2(server: *Server, conn: *connection.Connection, completion: wasm_host_call_mod.Completion) bool {
    if (!build_options.enable_wasm) return false;
    const proxy = server.proxy orelse return false;
    const route = proxy.matchRoute(&completion.req) orelse return false;
    if (route.wasm_pool == null) return false; // not a wasm-filtered proxy route

    var ip_buf: [64]u8 = undefined;
    var client_ip_str: ?[]const u8 = null;
    if (conn.cached_peer_ip) |ip4| {
        const n = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
        if (n.len > 0) client_ip_str = ip_buf[0..n.len];
    }
    var mw_ctx = middleware.Context{ .client_ip = conn.cached_peer_ip, .protocol = .http2, .is_tls = conn.is_tls, .stream_id = completion.stream_id };
    // resume_decision skips the filter; the upstream was not contacted at park
    // time, so this is where the forward actually happens. Cache/otel/x402 are
    // not re-run on the resumed proxy path (H1 parity, v1 limitation).
    const binding = proxy_mod.WasmBinding{ .resume_decision = completion.decision };
    var pr = proxy.handle(
        completion.req,
        &mw_ctx,
        client_ip_str,
        conn.tls_session != null,
        server.now_ms,
        null,
        null,
        binding,
    );
    defer pr.release();
    http2_mod.queueHttp2Response(server, conn, completion.stream_id, pr.resp, completion.req.method == .HEAD) catch {};
    return true;
}

/// Deliver a resumed parked HTTP/3 stream's filter Decision on its own QUIC
/// stream (E2b). The H3 analog of wasmResumeHttp2: it routes delivery through
/// the h3 send path (http3_mod.deliverResume), keyed by the QUIC connection id
/// (completion.conn_id) + stream id, leaving the connection's other streams
/// untouched (the connection kept multiplexing while this stream was parked).
/// allow/modify RE-DISPATCH the request (proxy re-forward or router re-run with
/// the filter skipped); reject/backpressure are served directly on the stream.
/// The QUIC connection is re-found by id inside deliverResume; if it was freed
/// while parked the delivery is a no-op. Compiled only when wasm is enabled.
fn wasmResumeHttp3(server: *Server, completion: wasm_host_call_mod.Completion) void {
    if (!build_options.enable_wasm) return;
    const stream_id = completion.stream_id;
    const conn_id = completion.conn_id;

    switch (completion.decision) {
        .reject => |resp| {
            http3_mod.deliverResume(server, conn_id, stream_id, resp);
        },
        .rate_limit_backpressure => |bp| {
            // Serve the backpressure response on this stream only. A
            // connection-level read pause would stall sibling streams, so H3
            // (like H2) does not pause the connection here; per-stream
            // backpressure is a deferred refinement.
            http3_mod.deliverResume(server, conn_id, stream_id, bp.resp);
        },
        .allow, .skip, .modify => {
            // Proxy route? Re-forward with the filter skipped (the upstream was
            // never contacted at park time). Falls through to the embedded-Router
            // re-dispatch when it is not a proxy route.
            if (proxyResumeHttp3(server, completion)) return;

            // Re-run the router with the resumed decision injected so the filter
            // is skipped and the handler runs. completion.req is the park slot's
            // OWNED snapshot (valid through this synchronous resume), not a borrow
            // of a reused frame buffer.
            var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
            var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
            const needs_eager_arena = (completion.req.method != .GET and completion.req.method != .HEAD and completion.req.method != .DELETE);
            const arena_handle = if (needs_eager_arena) server.io.acquireBuffer() else null;
            var empty_arena: [0]u8 = undefined;
            const arena_buf = if (arena_handle) |h| h.bytes else empty_arena[0..];
            var mw_ctx = middleware.Context{
                .protocol = .http3,
                .is_tls = true, // QUIC is always TLS
                .stream_id = stream_id,
                .buffer_ops = .{
                    .ctx = &server.io,
                    .acquire = write_queue.acquireBufferOpaque,
                    .release = write_queue.releaseBufferOpaque,
                },
            };
            var scratch = router.HandlerScratch{
                .response_buf = response_buf[0..],
                .response_headers = response_headers[0..],
                .arena_buf = arena_buf,
                .arena_handle = arena_handle,
                .buffer_ops = mw_ctx.buffer_ops,
                .wasm = .{
                    .table = @ptrCast(&server.wasm_host_calls),
                    .conn_index = completion.conn_index,
                    .conn_id = conn_id,
                    .stream_id = stream_id,
                    .protocol = .http3,
                    .deadline_ms = server.now_ms + WASM_HOST_CALL_TIMEOUT_MS,
                    .resume_decision = completion.decision,
                },
            };
            const result = server.app_router.handle(completion.req, &mw_ctx, &scratch);
            if (scratch.arena_handle) |h| server.io.releaseBuffer(h);
            // The handler may itself park again (PG, or another host call): leave
            // the stream suspended rather than sending the park sentinel.
            if (result.resp.isParked()) {
                if (server.wasmHasParkForStream(completion.conn_index, conn_id, stream_id)) return;
                server.wasmCancelForStream(completion.conn_index, conn_id, stream_id);
                http3_mod.deliverResume(server, conn_id, stream_id, response_mod.Response{
                    .status = 500,
                    .headers = &.{},
                    .body = .{ .bytes = "Internal Server Error" },
                });
                return;
            }
            http3_mod.deliverResume(server, conn_id, stream_id, result.resp);
        },
    }
}

/// Re-forward a parked PROXY request on an HTTP/3 stream after its host call
/// completed (resume to allow). Returns true if the parked request was a proxy
/// route (handled here); false if not (the caller falls back to the
/// embedded-Router re-dispatch). Mirrors proxyResumeHttp2 but delivers via the
/// h3 send path on completion.stream_id. Compiled only when wasm is enabled.
fn proxyResumeHttp3(server: *Server, completion: wasm_host_call_mod.Completion) bool {
    if (!build_options.enable_wasm) return false;
    const proxy = server.proxy orelse return false;
    const route = proxy.matchRoute(&completion.req) orelse return false;
    if (route.wasm_pool == null) return false; // not a wasm-filtered proxy route

    var mw_ctx = middleware.Context{ .protocol = .http3, .is_tls = true, .stream_id = completion.stream_id };
    // resume_decision skips the filter; the upstream was not contacted at park
    // time, so this is where the forward actually happens. Cache/otel/x402 are
    // not re-run on the resumed proxy path (H1/H2 parity, v1 limitation).
    const binding = proxy_mod.WasmBinding{ .resume_decision = completion.decision };
    var pr = proxy.handle(
        completion.req,
        &mw_ctx,
        null,
        true, // QUIC is always TLS
        server.now_ms,
        null,
        null,
        binding,
    );
    defer pr.release();
    http3_mod.deliverResume(server, completion.conn_id, completion.stream_id, pr.resp);
    return true;
}

/// Fire WASM host-call wall-clock deadlines from the housekeeping tick: each
/// timed-out park is failed closed and delivered via wasmResume. No-op when wasm
/// is disabled or nothing is parked.
fn wasmTick(server: *Server, now_ms: u64) void {
    if (build_options.enable_wasm) {
        // Mock transport (e2e mock lane): complete parks queued since the last
        // tick with the canned reply. Drained here, off any handler stack frame.
        if (server.wasm_mock_enabled and server.wasm_mock_count > 0) {
            const reply = server.wasm_mock_reply;
            const n = server.wasm_mock_count;
            server.wasm_mock_count = 0;
            for (server.wasm_mock_pending[0..n]) |token| wasmComplete(server, token, reply);
        }
        // Wall-clock deadlines.
        var completions: [16]wasm_host_call_mod.Completion = undefined;
        const n = server.wasm_host_calls.tick(now_ms, &completions);
        for (completions[0..n]) |c| wasmResume(server, c);
    }
}

/// Transport start hook (router.WasmBinding.start_fn). Routes a freshly parked
/// filter's host call to the Server's transport (control socket or mock).
fn wasmStartThunk(ctx: *anyopaque, token: u32, request: []const u8) void {
    const server: *Server = @ptrCast(@alignCast(ctx));
    server.wasmStartHostCall(token, request);
}

/// ControlClient.CompleteFn adapter: the *anyopaque ctx is the Server.
fn wasmCompleteThunk(ctx: *anyopaque, token: u32, result: []const u8) void {
    wasmComplete(@ptrCast(@alignCast(ctx)), token, result);
}

/// ControlClient.FailFn adapter: fail the park closed (transport error).
fn wasmFailThunk(ctx: *anyopaque, token: u32) void {
    wasmFail(@ptrCast(@alignCast(ctx)), token);
}

/// Deliver a completed host call (success path). The transport calls this when
/// the guest reply is in; it resumes the filter and re-dispatches. `token` is a
/// wasm.host_call.Token (u32).
pub fn wasmComplete(server: *Server, token: u32, result: []const u8) void {
    if (build_options.enable_wasm) {
        if (server.wasm_host_calls.complete(token, result)) |c| wasmResume(server, c);
    }
}

/// Fail a parked host call closed (transport failure: connect error, EOF,
/// command timeout). Mirrors wasmComplete but cancels the park to a fail-closed
/// Decision. A no-op if the token already resolved (e.g. the table deadline fired
/// first), so a late/duplicate failure from the transport is harmless.
pub fn wasmFail(server: *Server, token: u32) void {
    if (build_options.enable_wasm) {
        if (server.wasm_host_calls.cancel(token, .host_call_failed)) |c| wasmResume(server, c);
    }
}

pub fn handleRead(server: *Server, index: u32) !void {
    const conn = server.io.getConnection(index) orelse return;
    if (conn.fd == null) return;
    if (!conn.canRead(server.io.cfg.backpressure, server.now_ms)) return;

    // WebSocket tunnel: forward raw bytes to peer, no HTTP parsing.
    if (conn.is_tunnel) {
        handleTunnelRead(server, conn);
        return;
    }

    if (conn.timeout_phase == .idle) {
        server.io.setTimeoutPhase(conn, .header);
        conn.phase_enter_ms = server.now_ms;
    }
    const buffer_handle = conn.read_buffer orelse return;

    // If we're accumulating a large body, continue that instead of parsing.
    // Loop until EAGAIN to drain all available data (edge-triggered epoll).
    if (conn.isAccumulatingBody()) {
        // Completion-model backends deliver plaintext directly into the
        // buffer, so we can consume it without another syscall. TLS on
        // native still needs to run through connRead (SSL_read) because
        // the bytes the kernel delivered are ciphertext living in rbio.
        if (server.io.capabilities().delivers_read_data and !conn.is_tls) {
            http1_mod.continueBodyAccumulation(server, conn) catch {
                http1_mod.abortBodyAccumulation(server, conn, 400);
                return;
            };
            if (!conn.isAccumulatingBody()) return handleRead(server, index);
            return;
        }
        while (true) {
            const accum_buf = conn.read_buffer orelse return;
            const acc_offset = conn.read_offset + conn.read_buffered_bytes;
            if (acc_offset >= accum_buf.bytes.len) {
                // Read buffer full — should have been drained; just return
                return;
            }
            const slice = accum_buf.bytes[acc_offset..];
            const count = switch (connRead(server, conn, slice)) {
                .bytes => |n| n,
                .eof => {
                    http1_mod.abortBodyAccumulation(server, conn, 400);
                    return;
                },
                .again => return,
                .err => {
                    http1_mod.cleanupBodyAccumulation(server, conn);
                    server.closeConnection(conn);
                    return;
                },
            };
            server.io.onReadBuffered(conn, count);
            conn.markActive(server.now_ms);
            http1_mod.continueBodyAccumulation(server, conn) catch {
                http1_mod.abortBodyAccumulation(server, conn, 400);
                return;
            };
            if (!conn.isAccumulatingBody()) return handleRead(server, index);
        }
    }

    var read_start = conn.read_offset + conn.read_buffered_bytes;
    if (read_start >= buffer_handle.bytes.len) {
        if (build_options.enable_http2 and conn.protocol == .http2) {
            // H2 read buffer fragmented: unconsumed partial frame sits at
            // a high read_offset leaving no room to append new data.
            // Compact the buffer by sliding the partial data to the front.
            if (conn.read_offset > 0) {
                const start = conn.read_offset;
                const len = conn.read_buffered_bytes;
                std.mem.copyForwards(u8, buffer_handle.bytes[0..len], buffer_handle.bytes[start .. start + len]);
                conn.read_offset = 0;
                read_start = len;
            } else {
                // read_offset already 0 — buffer genuinely full, process what we have
                try http2_mod.handleHttp2Read(server, conn);
                return;
            }
        } else {
            // Buffer full — try header-only parse to see if we can start body accumulation
            if (conn.canEnqueueWrite()) {
                const start = conn.read_offset;
                const end = start + conn.read_buffered_bytes;
                const hparse = http1.parseHeaders(buffer_handle.bytes[start..end], .{
                    .max_header_bytes = server.cfg.limits.max_header_bytes,
                    .max_body_bytes = server.cfg.limits.max_body_bytes,
                    .max_header_count = server.cfg.limits.max_header_count,
                    .headers_storage = conn.headers[0..],
                });
                if (hparse.state == .err) {
                    conn.close_after_write = true;
                    server.io.onReadConsumed(conn, conn.read_buffered_bytes);
                    try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(hparse.error_code));
                } else if (hparse.state == .complete) {
                    // Headers valid, body too big for buffer → init body accumulation
                    const needs_body = hparse.is_chunked or hparse.content_length > 0;
                    if (needs_body) {
                        http1_mod.initBodyAccumulation(server, conn, hparse, buffer_handle) catch {
                            conn.close_after_write = true;
                            server.io.onReadConsumed(conn, conn.read_buffered_bytes);
                            try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(.body_too_large));
                            return;
                        };
                        // Body accumulation started — re-enter handleRead to drain socket
                        // (edge-triggered epoll won't fire again for data already buffered)
                        return handleRead(server, index);
                    } else {
                        // No body but buffer full → shouldn't happen (parse() would've completed)
                        conn.close_after_write = true;
                        server.io.onReadConsumed(conn, conn.read_buffered_bytes);
                        try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(.body_too_large));
                    }
                } else {
                    // .partial — headers not even complete yet → 431 (header too large)
                    conn.close_after_write = true;
                    server.io.onReadConsumed(conn, conn.read_buffered_bytes);
                    try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(.header_too_large));
                }
            }
            return;
        }
    }
    // With completion-model backends (io_uring native), the event
    // dispatcher has already seeded read_buffered_bytes from the
    // kernel's provided buffer. Skip the read() syscall in that
    // case — the data is already there. For TLS on native, the
    // kernel-delivered bytes are ciphertext living in rbio; we still
    // need to call connRead (SSL_read) to pull plaintext out.
    if (!server.io.capabilities().delivers_read_data or conn.is_tls) {
        const slice = buffer_handle.bytes[read_start..];
        switch (connRead(server, conn, slice)) {
            .bytes => |n| {
                server.io.onReadBuffered(conn, n);
                conn.markActive(server.now_ms);
            },
            .eof => {
                server.closeConnection(conn);
                return;
            },
            .again => {
                if (conn.read_buffered_bytes == 0) return;
            },
            .err => {
                server.closeConnection(conn);
                return;
            },
        }
    } else if (conn.read_buffered_bytes == 0) {
        // Completion backend but no data seeded (shouldn't happen
        // unless the event was spurious). Nothing to do.
        return;
    }

    if (build_options.enable_http2 and conn.protocol == .http1 and conn.read_offset == 0) {
        const end = conn.read_offset + conn.read_buffered_bytes;
        if (end <= buffer_handle.bytes.len) {
            const candidate = buffer_handle.bytes[0..end];
            if (!http2_mod.matchesHttp2Preface(candidate)) {
                // h2c-only listener: refuse anything that isn't the HTTP/2
                // connection preface (i.e. an HTTP/1.1 request) so a dedicated
                // h2c port can't silently serve h1. `matchesHttp2Preface` is a
                // prefix match, so a partially-arrived preface still passes
                // and we wait for more bytes via the branch below.
                if (conn.h2c_only) {
                    server.closeConnection(conn);
                    return;
                }
            } else {
                if (candidate.len < http2.Preface.len) return;
                if (conn.http2_stack == null) {
                    const stack_ptr = try server.allocator.create(http2.Stack);
                    stack_ptr.* = http2.Stack.initWithConfig(.{
                        .max_streams = server.cfg.http2.max_streams,
                        .max_header_list_size = server.cfg.http2.max_header_list_size,
                        .initial_window_size = server.cfg.http2.initial_window_size,
                        .max_frame_size = server.cfg.http2.max_frame_size,
                        .max_dynamic_table_size = server.cfg.http2.max_dynamic_table_size,
                    });
                    conn.http2_stack = stack_ptr;
                }
                if (conn.h2_pending == null) {
                    conn.h2_pending = try server.allocator.create([connection.MAX_PENDING_H2_BODIES]connection.PendingH2Body);
                    conn.h2_pending.?.* = [_]connection.PendingH2Body{.{}} ** connection.MAX_PENDING_H2_BODIES;
                }
                conn.protocol = .http2;
                // RFC 9113 §3.4: Server MUST send SETTINGS as first frame
                http2_mod.sendHttp2ServerPreface(server, conn) catch {
                    server.closeConnection(conn);
                    return;
                };
            }
        }
    }

    if (conn.protocol == .http2) {
        try http2_mod.handleHttp2Read(server, conn);
        // For TLS h2, OpenSSL can have more decrypted records buffered
        // internally. Drain the SSL buffer by looping until WouldBlock —
        // epoll is edge-triggered on the kernel socket and won't fire
        // EPOLLIN for data that's already in SSL's buffer.
        if (conn.is_tls) {
            var tls_drain_rounds: u8 = 0;
            while (tls_drain_rounds < 64) : (tls_drain_rounds += 1) {
                // Flush queued control frames (WINDOW_UPDATE, SETTINGS
                // ACK) between read rounds so the peer can open its
                // send window while we keep draining. Without this,
                // WINDOW_UPDATEs sit in the write queue until
                // handleRead returns, and the peer stalls.
                if (conn.write_count > 0) {
                    drainTlsWriteQueue(server, conn);
                    if (conn.state == .closed) return;
                }
                const drain_buf = conn.read_buffer orelse break;
                var drain_offset = conn.read_offset + conn.read_buffered_bytes;
                if (drain_offset >= drain_buf.bytes.len) {
                    if (conn.read_offset > 0) {
                        const start = conn.read_offset;
                        const len = conn.read_buffered_bytes;
                        std.mem.copyForwards(u8, drain_buf.bytes[0..len], drain_buf.bytes[start .. start + len]);
                        conn.read_offset = 0;
                        drain_offset = len;
                    } else {
                        try http2_mod.handleHttp2Read(server, conn);
                        break;
                    }
                }
                const drain_slice = drain_buf.bytes[drain_offset..];
                switch (connRead(server, conn, drain_slice)) {
                    .bytes => |n| {
                        server.io.onReadBuffered(conn, n);
                        conn.markActive(server.now_ms);
                        try http2_mod.handleHttp2Read(server, conn);
                    },
                    .eof => {
                        server.closeConnection(conn);
                        return;
                    },
                    .again, .err => {
                        break;
                    },
                }
            }
        }
        return;
    }

    // H1 TLS drain: SSL_read returns one TLS record at a time. If the
    // kernel delivered a TCP segment spanning multiple TLS records
    // (e.g. HTTP headers in one record, body in another), seedReadBuffer
    // fed all ciphertext to rbio but the initial SSL_read above only
    // decrypted the first record. Drain remaining records now so the
    // dispatch loop sees the complete request. Without this, a partial
    // parse (body still encrypted in rbio) strands the connection — no
    // kernel event will fire for data already in userspace.
    if (conn.is_tls) {
        var tls_drain: u8 = 0;
        while (tls_drain < 64) : (tls_drain += 1) {
            const drain_start = conn.read_offset + conn.read_buffered_bytes;
            if (drain_start >= buffer_handle.bytes.len) break;
            switch (connRead(server, conn, buffer_handle.bytes[drain_start..])) {
                .bytes => |n| {
                    server.io.onReadBuffered(conn, n);
                    conn.markActive(server.now_ms);
                },
                .eof => {
                    server.closeConnection(conn);
                    return;
                },
                .again, .err => break,
            }
        }
    }

    // The `!hasPendingFile()` guard is a wire-ordering invariant: a static
    // (sendfile) response enqueues only its HEADERS as a write entry and
    // pumps the file body later, once the queue drains (write_count == 0).
    // Processing further pipelined requests now would put their response
    // bytes on the wire BEFORE the file body — corrupting the stream. Break
    // instead; handleWrite re-enters handleRead once the file is fully sent.
    // Memoize the last preencoded cache hit across pipelined iterations.
    // Pipelined batches almost always repeat one URL, so after the first
    // lookup we can skip the linear scan on subsequent requests — just
    // verify the path still matches.
    var memo_entry: ?*preencoded.PreencodedH1Response = null;
    var memo_path: []const u8 = "";

    while (conn.state != .closed and conn.read_buffered_bytes > 0 and conn.canEnqueueWrite() and !conn.hasPendingFile()) {
        if (conn.x402 == .pending or conn.x402 == .settle_pending or conn.x402 == .db_parked) break;
        // Opportunistic inline write drain: push enqueued responses
        // to the kernel while still processing pipelined requests.
        // At low connection counts (e.g. 512 conns / 64 workers =
        // 8 per worker), the pipeline loop enqueues all responses
        // before any get flushed, so the client can't start its
        // next batch until a full write event fires. Draining inline
        // lets the client receive partial responses mid-batch and
        // overlap its next send with our remaining processing.
        // Guard: plain TCP only, keep-alive only, no pending body.
        if (conn.write_count >= 4 and !conn.is_tls and
            !conn.close_after_write and !conn.send_in_flight and
            !conn.hasPendingBody())
        {
            drainWritesInline(server, conn);
        }
        const start = conn.read_offset;
        const end = start + conn.read_buffered_bytes;
        if (end > buffer_handle.bytes.len) break;
        const buf_slice = buffer_handle.bytes[start..end];

        // Quick-line fast path: extract method+path from the request
        // line without parsing headers. On pre-encoded cache hit we
        // skip the full parse, router, middleware, and response
        // encoding entirely — saving ~100-130ns per pipelined request.
        if (!conn.close_after_write and server.proxy == null and
            server.cfg.allowed_hosts.len == 0 and
            !server.app_router.has_any_paid_routes)
        {
            if (http1.extractQuickLine(buf_slice)) |ql| {
                if (ql.method == .GET) {
                    const entry = if (memo_entry) |me| blk: {
                        break :blk if (ql.path.len == memo_path.len and std.mem.eql(u8, ql.path, memo_path)) me else preencoded.findAndRefreshPreencodedH1(server, "GET", ql.path);
                    } else preencoded.findAndRefreshPreencodedH1(server, "GET", ql.path);

                    if (entry) |e| {
                        memo_entry = e;
                        memo_path = ql.path;
                        const resp_bytes = if (ql.has_connection_close)
                            e.close_bytes[0..e.close_len]
                        else
                            e.bytes[0..e.len];
                        if (resp_bytes.len > 0 and preencoded.sendH1PreencodedBytes(server, conn, resp_bytes)) {
                            if (ql.has_connection_close) conn.close_after_write = true;
                            server.io.onReadConsumed(conn, ql.consumed);
                            if (conn.read_buffered_bytes == 0) break;
                            continue;
                        } else if (resp_bytes.len == 0) {
                            // fall through to full parse
                        } else {
                            break; // pool exhausted
                        }
                    }
                }
            }
        }

        const parse = http1.parse(buf_slice, .{
            .max_header_bytes = server.cfg.limits.max_header_bytes,
            .max_body_bytes = server.cfg.limits.max_body_bytes,
            .max_header_count = server.cfg.limits.max_header_count,
            .headers_storage = conn.headers[0..],
        });
        if (parse.state == .partial) {
            if (parse.expect_continue and !conn.sent_continue) {
                conn.sent_continue = true;
                try http1_mod.queueResponse(server, conn, http1_mod.continueResponse());
            }
            // If buffer is full (or nearly full on completion-model
            // backends), attempt body accumulation now. On io_uring
            // native, recv buffers are fixed-size and seedReadBuffer
            // truncates silently if the read buffer overflows. Trigger
            // body accumulation before the next recv chunk would
            // overflow, so no data is lost.
            const parse_end = conn.read_offset + conn.read_buffered_bytes;
            const recv_margin = server.io.capabilities().recv_buffer_size;
            const buffer_full = parse_end >= buffer_handle.bytes.len;
            const near_full = recv_margin > 0 and parse_end + recv_margin > buffer_handle.bytes.len;
            if (buffer_full or near_full) {
                const hparse = http1.parseHeaders(buffer_handle.bytes[conn.read_offset..parse_end], .{
                    .max_header_bytes = server.cfg.limits.max_header_bytes,
                    .max_body_bytes = server.cfg.limits.max_body_bytes,
                    .max_header_count = server.cfg.limits.max_header_count,
                    .headers_storage = conn.headers[0..],
                });
                if (hparse.state == .complete and (hparse.is_chunked or hparse.content_length > 0)) {
                    http1_mod.initBodyAccumulation(server, conn, hparse, buffer_handle) catch {
                        conn.close_after_write = true;
                        server.io.onReadConsumed(conn, conn.read_buffered_bytes);
                        try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(.body_too_large));
                        return;
                    };
                    // Re-enter to drain remaining socket data
                    return handleRead(server, index);
                } else if (hparse.state == .partial and buffer_full) {
                    // Headers not complete and buffer truly full → 431
                    conn.close_after_write = true;
                    server.io.onReadConsumed(conn, conn.read_buffered_bytes);
                    try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(.header_too_large));
                }
            }
            return;
        }
        if (parse.state == .err) {
            conn.close_after_write = true;
            server.io.onReadConsumed(conn, conn.read_buffered_bytes);
            try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(parse.error_code));
            return;
        }
        conn.header_count = parse.view.headers.len;
        conn.is_head_request = (parse.view.method == .HEAD);
        // Reset sent_continue for each new request in pipelined connections
        conn.sent_continue = false;
        if (!parse.keep_alive) conn.close_after_write = true;
        const saved_read_offset = conn.read_offset;
        const saved_read_buffered = conn.read_buffered_bytes;
        server.io.onReadConsumed(conn, parse.consumed_bytes);

        if (!server.isAllowedHost(parse.view)) {
            conn.close_after_write = true;
            try http1_mod.queueResponse(server, conn, Server.badRequestResponse());
            return;
        }

        // RFC 9110 §9.3.6: OPTIONS with asterisk-form request-target
        if (parse.view.method == .OPTIONS and std.mem.eql(u8, parse.view.path, "*")) {
            try http1_mod.queueResponse(server, conn, .{
                .status = 200,
                .headers = &[_]response_mod.Header{
                    .{ .name = "Content-Length", .value = "0" },
                },
                .body = .{ .bytes = "" },
            });
            if (conn.read_buffered_bytes == 0) break;
            continue;
        }

        // RFC 9110 §9.3.6: CONNECT uses authority-form — not supported
        if (parse.view.method == .CONNECT) {
            try http1_mod.queueResponse(server, conn, .{
                .status = 501,
                .headers = &[_]response_mod.Header{
                    .{ .name = "Content-Length", .value = "0" },
                },
                .body = .{ .bytes = "" },
            });
            if (conn.read_buffered_bytes == 0) break;
            continue;
        }

        // Check for static file requests - use sendfile for zero-copy
        if (server.cfg.static_root.len > 0 and std.mem.startsWith(u8, parse.view.path, "/static/")) {
            const file_path = parse.view.path[8..]; // Skip "/static/"
            const content_type = Server.guessContentType(file_path);
            const accept_encoding = parse.view.getHeader("accept-encoding") orelse "";
            if (server.staticCacheGetOrLoad(file_path, content_type, accept_encoding)) |entry| {
                var hdrs: [3]response_mod.Header = undefined;
                try http1_mod.queueResponse(server, conn, Server.staticCacheResponse(entry, &hdrs));
            } else {
                try http1_mod.queueFileResponse(server, conn, server.cfg.static_root, file_path, content_type, accept_encoding);
            }
            if (conn.read_buffered_bytes == 0) break;
            continue;
        }

        // Check proxy routes before router dispatch
        if (server.proxy) |proxy| {
            if (proxy.matchRoute(&parse.view)) |matched_route| {
                const route_idx = proxy.routeIndex(matched_route);
                const x402_policy = proxy.route_x402_policies[route_idx];
                const route_fac = proxy.route_facilitators[route_idx] orelse server.app_router.facilitator;
                var x402_result: x402_mod.EvaluateResult = undefined;
                if (conn.x402 == .resolved_allow) {
                    conn.x402 = .none;
                    const pay_hdr = x402_mod.findValidPaymentHeader(parse.view) orelse "";
                    if (pay_hdr.len > 0) x402_mod.recordPayment(pay_hdr, x402_policy.max_timeout_seconds);
                    x402_result = .{ .allow = .{
                        .payment_header = pay_hdr,
                        .needs_settlement = true,
                    } };
                } else if (conn.x402 == .resolved_reject) {
                    conn.x402 = .none;
                    const reject_info = x402_mod.rejectWith(.facilitator_rejected, x402_policy);
                    if (parse.view.method == .POST or parse.view.method == .PUT or parse.view.method == .PATCH) conn.close_after_write = true;
                    try http1_mod.queueResponse(server, conn, reject_info.resp);
                    if (conn.read_buffered_bytes == 0) break;
                    continue;
                } else {
                    x402_result = x402_mod.evaluateWithFacilitator(parse.view, x402_policy, null);
                    switch (x402_result) {
                        .reject => |info| {
                            if (parse.view.method == .POST or parse.view.method == .PUT or parse.view.method == .PATCH) conn.close_after_write = true;
                            try http1_mod.queueResponse(server, conn, info.resp);
                            if (conn.read_buffered_bytes == 0) break;
                            continue;
                        },
                        .allow => |ctx| {
                            if (route_fac != null and x402_policy.require_payment and ctx.payment_header.len > 0) {
                                var entry = x402_client.RequestEntry{ .kind = .verify, .conn_index = conn.index, .conn_id = conn.id };
                                const rf = route_fac.?;
                                const hl: u8 = @intCast(@min(rf.host.len, entry.host.len));
                                @memcpy(entry.host[0..hl], rf.host[0..hl]);
                                entry.host_len = hl;
                                entry.port = rf.port;
                                entry.use_tls = rf.use_tls;
                                entry.timeout_ms = rf.timeout_ms;
                                var json_buf: [4096]u8 = undefined;
                                const req_json_len = x402_mod.buildVerifyRequestJson(&json_buf, ctx.payment_header, &x402_policy) catch 0;
                                if (req_json_len > 0) {
                                    entry.http_len = @intCast(x402_mod.buildFacilitatorPost(&entry.http_buf, rf, "/verify", json_buf[0..req_json_len]) catch 0);
                                }
                                if (entry.http_len > 0 and x402_client.submit(entry)) {
                                    conn.x402 = .pending;
                                    conn.markActive(server.now_ms);
                                    server.io.unReadConsumed(conn, saved_read_offset, saved_read_buffered);
                                    break;
                                }
                                // Queue full or build failed — fast-reject
                                conn.close_after_write = true;
                                try http1_mod.queueResponse(server, conn, .{
                                    .status = 503,
                                    .headers = &[_]response_mod.Header{
                                        .{ .name = "Retry-After", .value = "1" },
                                        .{ .name = "Content-Length", .value = "0" },
                                    },
                                    .body = .{ .bytes = "" },
                                });
                                if (conn.read_buffered_bytes == 0) break;
                                continue;
                            } else if (x402_mod.failClosedOnUnverified(x402_policy, ctx)) |reject_info| {
                                // No facilitator will be consulted and the
                                // payment was not verified locally — fail
                                // closed instead of granting free access.
                                if (parse.view.method == .POST or parse.view.method == .PUT or parse.view.method == .PATCH) conn.close_after_write = true;
                                try http1_mod.queueResponse(server, conn, reject_info.resp);
                                if (conn.read_buffered_bytes == 0) break;
                                continue;
                            }
                        },
                    }
                }
                const auth_result = auth_mod.evaluate(parse.view, matched_route.auth);
                switch (auth_result) {
                    .allow => {},
                    .reject => |resp| {
                        if (parse.view.method == .POST or parse.view.method == .PUT or parse.view.method == .PATCH) conn.close_after_write = true;
                        try http1_mod.queueResponse(server, conn, resp);
                        if (conn.read_buffered_bytes == 0) break;
                        continue;
                    },
                }
                const auth_info_ptr: ?*const auth_mod.AuthInfo = switch (auth_result) {
                    .allow => |*info| info,
                    .reject => null,
                };
                if (auth_info_ptr) |ai| {
                    const name = ai.consumerName();
                    if (name.len > 0) usage_mod.record(name, server.now_ms);
                }
                if (matched_route.rate_limit) |rl_cfg| {
                    const consumer = if (auth_info_ptr) |ai| ai.consumerName() else "";
                    const client_key = if (conn.cached_peer_ip) |ip4|
                        ratelimit_mod.IpKey.fromIpv4(ip4)
                    else if (conn.cached_peer_ip6) |ip6|
                        ratelimit_mod.IpKey.fromIpv6(ip6)
                    else
                        null;
                    if (ratelimit_mod.evaluateRoute(consumer, client_key, rl_cfg)) |rl_resp| {
                        conn.setRateLimitPause(server.now_ms, rl_resp.pause_ms);
                        if (parse.view.method == .POST or parse.view.method == .PUT or parse.view.method == .PATCH) conn.close_after_write = true;
                        try http1_mod.queueResponse(server, conn, rl_resp.resp);
                        if (conn.read_buffered_bytes == 0) break;
                        continue;
                    }
                }
                if (matched_route.body_schema) |route_schema| {
                    const body_slice = parse.view.body.sliceOrNull() orelse "";
                    if (body_slice.len > 0 and body_slice.len <= 1024 * 1024) {
                        const vr = body_schema_mod.validate(route_schema, body_slice);
                        if (!vr.valid) {
                            var err_buf: [1024]u8 = undefined;
                            const err_json = body_schema_mod.formatErrorResponse(&vr, &err_buf);
                            const json_ct = [_]response_mod.Header{.{ .name = "Content-Type", .value = "application/json" }};
                            try http1_mod.queueResponse(server, conn, .{
                                .status = 400,
                                .headers = &json_ct,
                                .body = .{ .bytes = err_json },
                            });
                            if (conn.read_buffered_bytes == 0) break;
                            continue;
                        }
                    }
                }
                // WebSocket upgrade: detect and set up bidirectional tunnel
                if (ws_mod.isWebSocketUpgrade(parse.view)) {
                    var ws_ip_buf: [64]u8 = undefined;
                    var ws_client_ip: ?[]const u8 = null;
                    if (conn.cached_peer_ip) |ip4| {
                        const ip_len = std.fmt.bufPrint(&ws_ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                        if (ip_len.len > 0) ws_client_ip = ws_ip_buf[0..ip_len.len];
                    }
                    setupWebSocketTunnel(server, conn, parse.view, matched_route, proxy, ws_client_ip);
                    return;
                }

                var mw_ctx = middleware.Context{
                    .protocol = .http1,
                    .buffer_ops = .{
                        .ctx = &server.io,
                        .acquire = write_queue.acquireBufferOpaque,
                        .release = write_queue.releaseBufferOpaque,
                    },
                };
                // Use cached client IP for proxy headers
                var ip_buf: [64]u8 = undefined;
                var client_ip_str: ?[]const u8 = null;
                if (conn.cached_peer_ip) |ip4| {
                    const ip_len = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                    if (ip_len.len > 0) client_ip_str = ip_buf[0..ip_len.len];
                }
                var cert_dn_buf: [256]u8 = undefined;
                const cert_dn: ?[]const u8 = if (conn.tls_session) |*session| session.getPeerCertSubject(&cert_dn_buf) else null;

                // Response cache: check before forwarding to upstream
                const cache_cfg = matched_route.cache;
                // The proxy may gzip/deflate the response based on the client's
                // Accept-Encoding (proxy.maybeCompress), and that happens before
                // the cache store below — so the cached body can be compressed.
                // Include accept-encoding in the cache key so a client that does
                // not accept that encoding cannot hit a compressed entry.
                var vary_buf: [16][]const u8 = undefined;
                const vary_keys: []const []const u8 = blk: {
                    const base_vary: []const []const u8 = if (cache_cfg) |cc| cc.vary else &.{};
                    const n = @min(base_vary.len, vary_buf.len - 1);
                    for (base_vary[0..n], 0..) |v, vi| vary_buf[vi] = v;
                    vary_buf[n] = "accept-encoding";
                    break :blk vary_buf[0 .. n + 1];
                };
                if (cache_cfg != null) {
                    if (proxy.route_caches[route_idx]) |*rc| {
                        switch (rc.lookup(parse.view.method, parse.view.path, parse.view.headers, vary_keys, server.now_ms)) {
                            .hit => |info| {
                                var resp_headers_buf: [64]response_mod.Header = undefined;
                                const hdr_count = @min(info.headers.len, resp_headers_buf.len);
                                for (info.headers[0..hdr_count], 0..) |sh, hi| {
                                    resp_headers_buf[hi] = .{ .name = sh.name, .value = sh.value };
                                }
                                try http1_mod.queueResponse(server, conn, .{
                                    .status = info.status,
                                    .headers = resp_headers_buf[0..hdr_count],
                                    .body = .{ .bytes = info.body },
                                });
                                if (conn.read_buffered_bytes == 0) break;
                                continue;
                            },
                            .not_modified => {
                                try http1_mod.queueResponse(server, conn, response_mod.Response.notModified());
                                if (conn.read_buffered_bytes == 0) break;
                                continue;
                            },
                            .miss => {},
                        }
                    }
                }

                const otel_start = if (server.otel != null) clock.realtimeNanos() orelse 0 else 0;
                // E1: stash the post-forward processing context BEFORE the
                // forward so a wasm filter park on this proxy route can run
                // cache-store/otel/settlement on resume (proxyResume reads this
                // via the binding's resume_ctx). x402_result is always .allow
                // here (rejects fast-returned above); carry only needs_settlement
                // (the payment header is re-derived from the owned snapshot on
                // resume). Harmless dead data when the filter does not park.
                if (build_options.enable_wasm) {
                    conn.wasm_proxy_resume = .{
                        .route_idx = route_idx,
                        .otel_start = otel_start,
                        .needs_settlement = x402_result == .allow and x402_result.allow.needs_settlement,
                    };
                }
                // Park binding: a host_call filter on this proxy route parks
                // (H1 only). On park, runWasmFilter registers in the table, kicks
                // the transport (start_fn), and returns the park sentinel; we
                // suspend the connection and let wasmResume re-forward on allow.
                const proxy_wasm: proxy_mod.WasmBinding = if (build_options.enable_wasm) .{
                    .table = @ptrCast(&server.wasm_host_calls),
                    .conn_index = conn.index,
                    .conn_id = conn.id,
                    .stream_id = 0, // H1 sentinel
                    .protocol = .http1,
                    .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
                    .resume_ctx = @ptrCast(&conn.wasm_proxy_resume),
                    .start_fn = wasmStartThunk,
                    .start_ctx = @ptrCast(server),
                } else .{};
                var proxy_result = proxy.handle(
                    parse.view,
                    &mw_ctx,
                    client_ip_str,
                    conn.tls_session != null,
                    server.now_ms,
                    auth_info_ptr,
                    cert_dn,
                    proxy_wasm,
                );
                defer proxy_result.release();

                // Park sentinel from a proxy filter: suspend (set .wasm_parked)
                // and stop the pipeline. Skip cache/otel/settlement/queueResponse;
                // wasmResume re-forwards on allow. Same break semantics as the
                // router park path below.
                if (build_options.enable_wasm and proxy_result.resp.isParked()) {
                    _ = http1_mod.handleParkSentinel(server, conn, proxy_result.resp);
                    break;
                }

                // Post-forward processing (cache store/invalidate, otel span,
                // x402 settlement incl. the inline-receipt settle-park, then
                // queueResponse + the owned-buffer tail), shared with the resumed
                // (wasm-parked) proxy path so parity holds (E1). On a settle-park
                // this sets conn.x402 = .settle_pending and holds the response;
                // either outcome takes the same loop tail below.
                _ = try proxyForwardAndRespond(server, conn, proxy, parse.view, &proxy_result, .{
                    .route_idx = route_idx,
                    .otel_start = otel_start,
                    .x402_result = x402_result,
                });
                if (conn.read_buffered_bytes == 0) break;
                continue;
            }
        }

        // Fast path: pre-encoded h1 response cache. Hot static
        // endpoints skip the router, middleware, and response
        // encoding entirely and write cached bytes directly.
        switch (preencoded.tryDispatchPreencodedH1(server, conn, parse.view)) {
            .dispatched => {
                if (conn.read_buffered_bytes == 0) break;
                continue;
            },
            .pool_exhausted => {
                // Buffer pool is temporarily full. Break the
                // pipelining loop — do NOT fall through to the
                // router (it would also fail to acquire a buffer
                // and close the connection). Pending writes will
                // drain, return buffers to the pool, and the next
                // event-loop iteration picks up remaining pipelined
                // requests from the read buffer.
                break;
            },
            .not_cached => {},
        }

        var mw_ctx = middleware.Context{
            .protocol = .http1,
            .is_tls = conn.is_tls,
            .buffer_ops = .{
                .ctx = &server.io,
                .acquire = write_queue.acquireBufferOpaque,
                .release = write_queue.releaseBufferOpaque,
            },
        };
        // Use cached client IP for rate limiting and logging
        if (conn.cached_peer_ip) |ip4| {
            mw_ctx.client_ip = ip4;
        } else if (conn.cached_peer_ip6) |ip6| {
            mw_ctx.client_ip6 = ip6;
        }
        var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
        var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;

        // Lazy arena acquire: GETs that miss the pre-encoded cache
        // are likely 404s or simple handlers that don't need arena
        // memory. Skip the buffer-pool acquire for GETs; POST/PUT
        // handlers that accumulate request bodies need the arena
        // so we acquire eagerly for those.
        //
        // This saves ~200ns/req from the pool acquire+release on
        // the error-handling benchmark where 45% of requests are
        // 404/405 GETs that never touch the arena.
        const needs_eager_arena = (parse.view.method != .GET and parse.view.method != .HEAD and parse.view.method != .DELETE);
        const arena_handle = if (needs_eager_arena) server.io.acquireBuffer() else null;
        var empty_arena: [0]u8 = undefined;
        const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
        var scratch = router.HandlerScratch{
            .response_buf = response_buf[0..],
            .response_headers = response_headers[0..],
            .arena_buf = arena_buf,
            .arena_handle = arena_handle,
            .buffer_ops = mw_ctx.buffer_ops,
            .pg = .{
                .client = server.pg_client,
                .io_rt = &server.io,
                .conn_index = conn.index,
                .conn_id = conn.id,
            },
            .wasm = .{
                // *wasm.host_call.Table (opaque); null when wasm is compiled out,
                // which makes a parking filter fail closed.
                .table = if (build_options.enable_wasm) @ptrCast(&server.wasm_host_calls) else null,
                .conn_index = conn.index,
                .conn_id = conn.id,
                .stream_id = 0, // H1 sentinel
                .protocol = .http1,
                .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
                .start_fn = if (build_options.enable_wasm) wasmStartThunk else null,
                .start_ctx = if (build_options.enable_wasm) @ptrCast(server) else null,
            },
        };
        const otel_start = if (server.otel != null) clock.realtimeNanos() orelse 0 else 0;
        const result = server.app_router.handle(parse.view, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
        if (result.pause_reads_ms) |pause_ms| {
            conn.setRateLimitPause(server.now_ms, pause_ms);
        }
        // Park sentinel: the request parked for a PG op (or returned a
        // bogus sentinel and got a 500). Either way stop the pipeline
        // loop — same break semantics as the x402 .pending gate; any
        // responses already enqueued this batch drain via the inline
        // drain and write-readiness events.
        if (http1_mod.handleParkSentinel(server, conn, result.resp)) break;
        try http1_mod.queueResponse(server, conn, result.resp);
        // A Phase 2b on_response filter can REPLACE the body with a slice that
        // borrows the wasm instance's scratch, which invokeResponse releases to
        // .idle immediately (reused by the next request). If the body did not fit
        // the write queue, the spilled tail in conn.pending_body still borrows
        // that scratch -> the next request would overwrite it (cross-request body
        // corruption). Materialize the tail into stable pool buffers now, while
        // the scratch is still valid. Mirrors the proxy path's tail handling.
        if (conn.pending_body.len > 0) http1_mod.materializePendingBody(server, conn);
        if (server.otel) |otel_exp| {
            otel_exp.recordSpan(parse.view.method, parse.view.path, result.resp.status, otel_start, clock.realtimeNanos() orelse 0);
        }
        if (conn.read_buffered_bytes == 0) break;
    }

    // Read-loop draining: if buffer is fully consumed and we can
    // still process, try one more non-blocking read to avoid an
    // extra event loop round-trip. Helps fast persistent clients
    // (e.g. k6 benchmarks) on readiness backends. Skip on
    // completion-model backends (native io_uring) — the kernel's
    // multishot recv will deliver any further data as a separate
    // CQE, so a speculative read here is always EAGAIN and wastes
    // a syscall.
    if (!server.io.capabilities().delivers_read_data and
        conn.read_buffered_bytes == 0 and
        conn.canEnqueueWrite() and
        !conn.close_after_write)
    {
        conn.read_offset = 0;
        const drain_buf = conn.read_buffer orelse return;
        switch (connRead(server, conn, drain_buf.bytes)) {
            .bytes => |drain_count| {
                server.io.onReadBuffered(conn, drain_count);
                conn.markActive(server.now_ms);
                return handleRead(server, index);
            },
            .eof, .again, .err => {},
        }
        // No more data available, continue normally
    }
}

// ── WebSocket tunnel relay ────────────────────────────────────

const proxy_mod = @import("../proxy/proxy.zig");
const upstream_mod = @import("../proxy/upstream.zig");

fn handleTunnelRead(server: *Server, conn: *connection.Connection) void {
    const read_buf = conn.read_buffer orelse return;
    const offset = conn.read_offset + conn.read_buffered_bytes;
    if (offset >= read_buf.bytes.len) return;

    const count = switch (connRead(server, conn, read_buf.bytes[offset..])) {
        .bytes => |n| n,
        .eof => {
            closeTunnel(server, conn);
            return;
        },
        .again => return,
        .err => {
            closeTunnel(server, conn);
            return;
        },
    };
    if (count == 0) {
        closeTunnel(server, conn);
        return;
    }
    conn.markActive(server.now_ms);

    const peer_index = conn.tunnel_peer_index orelse {
        closeTunnel(server, conn);
        return;
    };
    const peer = server.io.getConnection(peer_index) orelse {
        closeTunnel(server, conn);
        return;
    };
    if (!peer.is_tunnel or peer.fd == null or peer.id != conn.tunnel_peer_id) {
        closeTunnel(server, conn);
        return;
    }

    if (!peer.canEnqueueWrite()) {
        closeTunnel(server, conn);
        return;
    }

    const write_handle = server.io.acquireBuffer() orelse {
        closeTunnel(server, conn);
        return;
    };
    const copy_len = @min(count, write_handle.bytes.len);
    @memcpy(write_handle.bytes[0..copy_len], read_buf.bytes[offset .. offset + copy_len]);

    if (!peer.enqueueWrite(write_handle, copy_len)) {
        server.io.releaseBuffer(write_handle);
        closeTunnel(server, conn);
        return;
    }
    peer.markActive(server.now_ms);

    // Kick a write on the peer
    handleWrite(server, peer.index) catch {
        closeTunnel(server, conn);
    };
}

fn closeTunnel(server: *Server, conn: *connection.Connection) void {
    const peer_index = conn.tunnel_peer_index;
    conn.tunnel_peer_index = null;
    conn.is_tunnel = false;
    server.closeConnection(conn);

    if (peer_index) |pi| {
        if (server.io.getConnection(pi)) |peer| {
            if (peer.is_tunnel) {
                peer.tunnel_peer_index = null;
                peer.is_tunnel = false;
                server.closeConnection(peer);
            }
        }
    }
}

fn setupWebSocketTunnel(
    server: *Server,
    conn: *connection.Connection,
    req: request_mod.RequestView,
    matched_route: *const upstream_mod.ProxyRoute,
    proxy: *proxy_mod.Proxy,
    client_ip: ?[]const u8,
) void {
    const effective_upstream = matched_route.selectUpstream();
    const upstream_def = proxy.upstreams_by_name.get(effective_upstream) orelse {
        http1_mod.queueResponse(server, conn, ws_mod.errorResp(502)) catch {
            conn.close_after_write = true;
        };
        return;
    };
    const bal = proxy.balancers.get(effective_upstream) orelse {
        http1_mod.queueResponse(server, conn, ws_mod.errorResp(502)) catch {
            conn.close_after_write = true;
        };
        return;
    };

    const selection = bal.select(null, server.now_ms) orelse {
        http1_mod.queueResponse(server, conn, ws_mod.errorResp(502)) catch {
            conn.close_after_write = true;
        };
        return;
    };

    var resp_buf: [4096]u8 = undefined;
    const result = ws_mod.performUpgrade(req, selection.server.address, selection.server.port, matched_route, client_ip, &resp_buf, upstream_def.allow_private);

    switch (result) {
        .err => |resp| {
            http1_mod.queueResponse(server, conn, resp) catch {
                conn.close_after_write = true;
            };
        },
        .ok => |info| {
            const upstream_fd = info.upstream_fd;
            const raw_101 = info.resp_data[0..info.resp_len];

            // Queue the raw 101 response to the client
            const write_handle = server.io.acquireBuffer() orelse {
                clock.closeFd(upstream_fd);
                conn.close_after_write = true;
                return;
            };
            const copy_len = @min(raw_101.len, write_handle.bytes.len);
            @memcpy(write_handle.bytes[0..copy_len], raw_101[0..copy_len]);
            if (!conn.enqueueWrite(write_handle, copy_len)) {
                server.io.releaseBuffer(write_handle);
                clock.closeFd(upstream_fd);
                return;
            }

            // Acquire a connection slot for the upstream side of the tunnel
            const upstream_conn = server.io.acquireConnection(server.now_ms) orelse {
                clock.closeFd(upstream_fd);
                conn.close_after_write = true;
                return;
            };
            upstream_conn.fd = upstream_fd;
            upstream_conn.state = .active;
            upstream_conn.is_tunnel = true;
            upstream_conn.tunnel_peer_index = conn.index;
            upstream_conn.tunnel_peer_id = conn.id;
            upstream_conn.is_tls = false;

            // Give upstream connection a read buffer
            const upstream_read_buf = server.io.acquireBuffer() orelse {
                server.io.releaseConnection(upstream_conn);
                clock.closeFd(upstream_fd);
                conn.close_after_write = true;
                return;
            };
            upstream_conn.read_buffer = upstream_read_buf;

            // Set upstream FD to non-blocking for event loop
            net.setNonBlocking(upstream_fd) catch {
                server.io.releaseBuffer(upstream_read_buf);
                upstream_conn.read_buffer = null;
                server.io.releaseConnection(upstream_conn);
                clock.closeFd(upstream_fd);
                conn.close_after_write = true;
                return;
            };

            // Register upstream FD in the event loop
            server.io.registerConnection(upstream_conn.index, upstream_fd) catch {
                server.io.releaseBuffer(upstream_read_buf);
                upstream_conn.read_buffer = null;
                upstream_conn.fd = null;
                server.io.releaseConnection(upstream_conn);
                clock.closeFd(upstream_fd);
                conn.close_after_write = true;
                return;
            };

            // Mark client connection as tunnel
            conn.is_tunnel = true;
            conn.tunnel_peer_index = upstream_conn.index;
            conn.tunnel_peer_id = upstream_conn.id;

            // Consume all buffered data from client read (the HTTP request)
            server.io.onReadConsumed(conn, conn.read_buffered_bytes);

            // Kick a write on client to send the 101 response
            handleWrite(server, conn.index) catch {};
        },
    }
}

/// Result of one drain pass — see handleWrite.
const WritePass = enum { done, reenter_read };

/// Free the heap buffer backing a large proxied response once its queued
/// tail (conn.pending_body) has fully drained. No-op otherwise. The buffer
/// is also freed by closeConnection if the connection dies first.
fn freePendingBodyOwnedIfDrained(server: *Server, conn: *connection.Connection) void {
    if (conn.pending_body_owned) |owned| {
        if (!conn.hasPendingBody()) {
            server.allocator.free(owned);
            conn.pending_body_owned = null;
        }
    }
}

pub fn handleWrite(server: *Server, index: u32) !void {
    // Drive drain passes and pipelined-read re-entry as a LOOP, never
    // recursion. A pipelined batch can interleave reads and writes many
    // times (e.g. each static sendfile response breaks the pipeline loop),
    // and all of that work comes from bytes that are already buffered — no
    // kernel event will fire to resume it. Recursing handleWrite <->
    // handleRead here would let a crafted batch of pipelined requests grow
    // the stack without bound.
    while (true) {
        switch (try handleWritePass(server, index)) {
            .done => return,
            .reenter_read => {
                handleRead(server, index) catch {};
                const conn = server.io.getConnection(index) orelse return;
                if (conn.state == .closed) return;
                // Loop only while handleRead produces drainable work.
                // Otherwise stop: either the batch is fully processed, or
                // the request is parked (e.g. x402 pending) and an event
                // will resume us.
                if (conn.write_count == 0 and !conn.hasPendingFile() and
                    !conn.hasPendingBody() and !conn.hasPendingH2Streams())
                {
                    if (conn.read_buffered_bytes == 0) server.io.setTimeoutPhase(conn, .idle);
                    return;
                }
            },
        }
    }
}

fn handleWritePass(server: *Server, index: u32) !WritePass {
    const conn = server.io.getConnection(index) orelse return .done;
    const socket_fd = conn.fd orelse return .done;

    while (true) {
        if (conn.is_tls) {
            // Flush any ciphertext stashed from a prior partial writev
            // before touching SSL_write — we must preserve encryption
            // order, and SSL_write would otherwise produce a record
            // that races ahead of the carried record on the wire.
            switch (server_tls.tlsDrainCarry(server, conn)) {
                .done => {},
                .again => {
                    server.io.armWritable(conn.index, socket_fd) catch {};
                    return .done;
                },
                .err => {
                    server.closeConnection(conn);
                    return .done;
                },
            }
            // TLS: coalesce as many consecutive write-queue entries as fit
            // in one TLS record (TLS_PLAINTEXT_WRITE_CAP) into a single
            // SSL_write, so N small frames (e.g. concurrent h2 stream
            // responses, or a static file split into DATA frames) become one
            // record + one socket write instead of one per entry.
            while (conn.write_count > 0) {
                // Drain any leading empty entries.
                while (conn.peekWrite()) |e| {
                    if (e.len - e.offset != 0) break;
                    server.io.releaseBuffer(e.handle);
                    conn.popWrite();
                }
                if (conn.write_count == 0) break;

                const cap = server_tls.TLS_PLAINTEXT_WRITE_CAP;
                const first = conn.peekWrite() orelse break;
                const s0 = first.handle.bytes[first.offset..first.len];

                // Single queued entry (the common small-response case) — or a
                // first entry that already fills a TLS record — is written
                // directly, with NO staging copy. Coalescing only pays off when
                // there are ≥2 small entries to merge into one record;
                // copying a lone response into the staging buffer just adds an
                // extra memcpy per response (measured ~9% loss on baseline-h2).
                var to_write: []const u8 = undefined;
                if (conn.write_count == 1 or s0.len >= cap) {
                    to_write = s0[0..@min(s0.len, cap)];
                } else {
                    // Coalesce consecutive small entries into one record.
                    var gathered: usize = 0;
                    var idx = conn.write_head;
                    var rem_entries = conn.write_count;
                    while (rem_entries > 0 and gathered < cap) : (rem_entries -= 1) {
                        const e = &conn.write_queue[idx];
                        const s = e.handle.bytes[e.offset..e.len];
                        if (s.len > 0) {
                            const take = @min(s.len, cap - gathered);
                            @memcpy(server.tls_gather[gathered..][0..take], s[0..take]);
                            gathered += take;
                            if (take < s.len) break; // record cap reached mid-entry
                        }
                        idx = if (idx + 1 >= conn.write_queue.len) 0 else idx + 1;
                    }
                    to_write = server.tls_gather[0..gathered];
                }
                switch (connWrite(server, conn, to_write)) {
                    .bytes => |n| {
                        conn.markActive(server.now_ms);
                        consumeTlsWritten(server, conn, n);
                        if (conn.hasPendingBody()) {
                            http1_mod.streamBodyChunks(server, conn, conn.pending_body);
                        }
                        freePendingBodyOwnedIfDrained(server, conn);
                        // If connWrite populated the carry (socket write only
                        // partially absorbed the record), pause — we resume
                        // when the next writable event drains the carry.
                        if (conn.tls_cipher_carry_handle != null) {
                            server.io.armWritable(conn.index, socket_fd) catch {};
                            return .done;
                        }
                    },
                    .again => {
                        server.io.armWritable(conn.index, socket_fd) catch {};
                        return .done;
                    },
                    .err => {
                        server.closeConnection(conn);
                        return .done;
                    },
                }
            }
            if (conn.write_count == 0 and conn.hasPendingFile() and http1_mod.bufferPendingFileWrites(server, conn)) {
                continue;
            }
            if (conn.hasPendingH2Streams()) {
                http2_mod.drainPendingH2Streams(server, conn);
                if (conn.write_count > 0) continue;
            }
            if (conn.state == .closed) return .done;
        } else {
            // Plain TCP path.
            //
            // Sync `writev(2)` is the fast path for plain TCP on
            // every backend. We tried routing keepalive responses
            // through IORING_OP_WRITEV, but the CQE round trip
            // between submit and continuation cost more than the
            // memcpy-into-kernel-buffer it was supposed to
            // overlap, and the resulting send-in-flight gating
            // serialized subsequent requests on the same
            // connection. Sync writev runs inline, lets us close
            // the fd in the same dispatcher tick for close-mode
            // requests, and never blocks the reactor because the
            // socket is non-blocking.
            if (conn.send_in_flight) return .done;
            while (conn.write_count > 0) {
                var iov: [16]std.posix.iovec_const = undefined;
                var iov_count: u32 = 0;
                {
                    var scan_head = conn.write_head;
                    var scan_remaining = conn.write_count;
                    while (scan_remaining > 0 and iov_count < 16) {
                        const e = &conn.write_queue[scan_head];
                        const s = e.handle.bytes[e.offset..e.len];
                        iov[iov_count] = .{ .base = s.ptr, .len = s.len };
                        iov_count += 1;
                        scan_head = if (scan_head + 1 >= conn.write_queue.len) 0 else scan_head + 1;
                        scan_remaining -= 1;
                    }
                }
                if (iov_count == 0) break;

                const bytes_written = std.c.writev(socket_fd, &iov, @intCast(iov_count));
                if (bytes_written < 0) {
                    switch (std.posix.errno(bytes_written)) {
                        .AGAIN => {
                            // Socket send buffer is full.
                            // On completion-model backends (native
                            // io_uring) the reactor has no generic
                            // POLLOUT readiness event, so we must
                            // explicitly arm one — otherwise the
                            // connection stalls forever waiting
                            // for a wake that never comes. Other
                            // backends re-arm their POLL_ADD mask
                            // through the standard dispatcher path
                            // so this call is a no-op for them.
                            server.io.armWritable(conn.index, socket_fd) catch {};
                            return .done;
                        },
                        .INTR => continue,
                        else => {
                            server.closeConnection(conn);
                            return .done;
                        },
                    }
                }
                if (bytes_written == 0) return .done;
                var written: usize = @intCast(bytes_written);
                conn.markActive(server.now_ms);

                while (written > 0) {
                    const entry = conn.peekWrite() orelse break;
                    const remaining_in_entry = entry.len - entry.offset;
                    if (written >= remaining_in_entry) {
                        written -= remaining_in_entry;
                        server.io.onWriteCompleted(conn, remaining_in_entry);
                        server.io.releaseBuffer(entry.handle);
                        conn.popWrite();
                        if (conn.hasPendingBody()) {
                            http1_mod.streamBodyChunks(server, conn, conn.pending_body);
                        }
                        freePendingBodyOwnedIfDrained(server, conn);
                    } else {
                        entry.offset += written;
                        server.io.onWriteCompleted(conn, written);
                        written = 0;
                    }
                }
            }
        }
        if (conn.hasPendingH2Streams()) {
            http2_mod.drainPendingH2Streams(server, conn);
            if (conn.write_count > 0) continue;
        }
        break;
    }

    // All buffer writes done, try sendfile if file is pending.
    if (!conn.is_tls) {
        while (conn.hasPendingFile()) {
            const file_fd = conn.pending_file_fd.?;
            const result = net.sendfile(socket_fd, file_fd, &conn.pending_file_offset, conn.pending_file_remaining) catch |err| {
                switch (err) {
                    error.WouldBlock => return .done,
                    error.Closed, error.Failed => {
                        conn.cleanupPendingFile();
                        server.closeConnection(conn);
                        return .done;
                    },
                }
            };
            if (result.bytes_sent == 0) return .done;
            conn.pending_file_remaining -= result.bytes_sent;
            conn.markActive(server.now_ms);

            if (conn.pending_file_remaining == 0) {
                conn.cleanupPendingFile();
                break;
            }
        }
    }

    // Check if all writes are complete
    if (conn.state == .closed) return .done;
    if (conn.write_count == 0 and !conn.hasPendingBody() and !conn.hasPendingFile() and !conn.hasPendingH2Streams()) {
        if (conn.close_after_write) {
            server.closeConnection(conn);
            return .done;
        }
        // If there's still data in the read buffer (from a pipelining
        // backpressure or sendfile-ordering break), hand control back to
        // handleWrite's driver loop to re-enter the read handler now that
        // writes have drained and buffers are free. With edge-triggered
        // epoll, no new read event will fire since the data is already
        // buffered — it must be processed explicitly.
        if (conn.read_buffered_bytes > 0) {
            return .reenter_read;
        }
        server.io.setTimeoutPhase(conn, .idle);
    }
    return .done;
}

/// Non-blocking writev drain for use inside the pipelining loop.
/// Pushes enqueued response bytes to the kernel without touching any
/// close/lifecycle state. On EAGAIN (socket buffer full) it simply
/// returns — the normal handleWrite path handles the remainder.
fn drainWritesInline(server: *Server, conn: *connection.Connection) void {
    const socket_fd = conn.fd orelse return;
    while (conn.write_count > 0) {
        var iov: [16]std.posix.iovec_const = undefined;
        var iov_count: u32 = 0;
        {
            var scan_head = conn.write_head;
            var scan_remaining = conn.write_count;
            while (scan_remaining > 0 and iov_count < 16) {
                const e = &conn.write_queue[scan_head];
                const s = e.handle.bytes[e.offset..e.len];
                iov[iov_count] = .{ .base = s.ptr, .len = s.len };
                iov_count += 1;
                scan_head = if (scan_head + 1 >= conn.write_queue.len) 0 else scan_head + 1;
                scan_remaining -= 1;
            }
        }
        if (iov_count == 0) break;
        const bytes_written = std.c.writev(socket_fd, &iov, @intCast(iov_count));
        if (bytes_written <= 0) return;
        var written: usize = @intCast(bytes_written);
        while (written > 0) {
            const entry = conn.peekWrite() orelse break;
            const remaining_in_entry = entry.len - entry.offset;
            if (written >= remaining_in_entry) {
                written -= remaining_in_entry;
                server.io.onWriteCompleted(conn, remaining_in_entry);
                server.io.releaseBuffer(entry.handle);
                conn.popWrite();
            } else {
                entry.offset += written;
                server.io.onWriteCompleted(conn, written);
                written = 0;
            }
        }
    }
}

/// Flush the write queue through TLS during the H2 drain loop.
/// Sends queued WINDOW_UPDATE / SETTINGS ACK frames to the peer so it
/// can open its send window while we keep reading. Unlike handleWrite,
/// this never calls handleRead, avoiding mutual recursion.
fn drainTlsWriteQueue(server: *Server, conn: *connection.Connection) void {
    const socket_fd = conn.fd orelse return;
    while (conn.write_count > 0) {
        switch (server_tls.tlsDrainCarry(server, conn)) {
            .done => {},
            .again => {
                server.io.armWritable(conn.index, socket_fd) catch {};
                return;
            },
            .err => {
                server.closeConnection(conn);
                return;
            },
        }
        const entry = conn.peekWrite() orelse break;
        const data = entry.handle.bytes[entry.offset..entry.len];
        if (data.len == 0) {
            server.io.releaseBuffer(entry.handle);
            conn.popWrite();
            continue;
        }
        switch (connWrite(server, conn, data)) {
            .bytes => |n| {
                if (n >= data.len) {
                    server.io.onWriteCompleted(conn, data.len);
                    server.io.releaseBuffer(entry.handle);
                    conn.popWrite();
                } else {
                    entry.offset += n;
                    server.io.onWriteCompleted(conn, n);
                }
                if (conn.tls_cipher_carry_handle != null) {
                    server.io.armWritable(conn.index, socket_fd) catch {};
                    return;
                }
            },
            .again => {
                server.io.armWritable(conn.index, socket_fd) catch {};
                return;
            },
            .err => {
                server.closeConnection(conn);
                return;
            },
        }
    }
}

pub fn handleError(server: *Server, index: u32) !void {
    const conn = server.io.getConnection(index) orelse return;
    server.closeConnection(conn);
}

// ==================== Low-level socket I/O ====================

pub const ReadResult = union(enum) {
    bytes: usize,
    eof: void,
    again: void,
    err: void,
};

/// Read from a connection, using TLS if enabled. Returns bytes read, or error.
pub fn connRead(server: *Server, conn: *connection.Connection, buf: []u8) ReadResult {
    if (conn.is_tls) {
        // Pull any newly-arrived ciphertext into rbio on non-completion
        // backends (no-op on native — the event dispatcher seeded it).
        _ = server_tls.tlsPumpRead(server, conn);
        var session = &(conn.tls_session orelse return .err);
        const n = session.read(buf) catch |err| return switch (err) {
            error.WouldBlock => .again,
            error.ConnectionClosed => .eof,
            else => .err,
        };
        if (n == 0) return .eof;
        return .{ .bytes = n };
    }
    const fd = conn.fd orelse return .err;
    const raw = std.posix.system.read(fd, buf.ptr, buf.len);
    if (raw == 0) return .eof;
    if (raw < 0) {
        return switch (std.posix.errno(raw)) {
            .AGAIN, .INTR => .again,
            else => .err,
        };
    }
    return .{ .bytes = @intCast(raw) };
}

pub const WriteResult = union(enum) {
    bytes: usize,
    again: void,
    err: void,
};

/// Write to a connection, using TLS if enabled. Returns bytes written, or error.
/// Account `n` plaintext bytes written by a coalesced TLS SSL_write back
/// across the write queue: pop fully-consumed entries (releasing their
/// buffers) and advance the offset of a partially-consumed final entry.
/// Mirrors the per-entry completion bookkeeping the non-coalesced path did.
fn consumeTlsWritten(server: *Server, conn: *connection.Connection, n: usize) void {
    var rem = n;
    while (conn.write_count > 0) {
        const e = conn.peekWrite() orelse break;
        const avail = e.len - e.offset;
        if (rem >= avail) {
            // Whole entry consumed (avail may be 0 for an empty entry).
            if (avail > 0) server.io.onWriteCompleted(conn, avail);
            server.io.releaseBuffer(e.handle);
            conn.popWrite();
            rem -= avail;
            if (rem == 0) break;
        } else {
            e.offset += rem;
            server.io.onWriteCompleted(conn, rem);
            rem = 0;
            break;
        }
    }
}

pub fn connWrite(server: *Server, conn: *connection.Connection, data: []const u8) WriteResult {
    if (conn.is_tls) {
        // Cap plaintext per SSL_write so wbio never holds more ciphertext
        // than one TLS record — that guarantees a full drain through
        // `tls_cipher_scratch` in a single BIO_read/writev round.
        const chunk_len = @min(data.len, server_tls.TLS_PLAINTEXT_WRITE_CAP);
        if (chunk_len == 0) return .{ .bytes = 0 };
        var session = &(conn.tls_session orelse return .err);
        const n = session.write(data[0..chunk_len]) catch |err| return switch (err) {
            error.WouldBlock => .again,
            else => .err,
        };
        if (n == 0) return .again;
        // Drain the fresh ciphertext straight to the socket. On
        // backpressure the remainder is stashed into the per-conn
        // cipher carry, and we return .bytes (the plaintext was already
        // consumed by SSL_write). handleWrite checks the carry at the
        // top of its loop on the next write event and flushes it there.
        server_tls.tlsFlushWbio(server, conn) catch |err| return switch (err) {
            error.TlsCarryAllocFailed => .err,
            else => .err,
        };
        return .{ .bytes = n };
    }
    const fd = conn.fd orelse return .err;
    const raw = std.c.write(fd, data.ptr, data.len);
    if (raw < 0) {
        return switch (std.posix.errno(raw)) {
            .AGAIN, .INTR => .again,
            else => .err,
        };
    }
    return .{ .bytes = @intCast(raw) };
}

// ============================================================
// x402 settle-park helpers
// ============================================================

fn fillSettleEntry(
    entry: *x402_client.RequestEntry,
    fac: x402_mod.FacilitatorConfig,
    payment_header: []const u8,
    policy: *const x402_mod.RoutePaymentConfig,
    charge: []const u8,
    request_path: []const u8,
) void {
    const shl: u8 = @intCast(@min(fac.host.len, entry.host.len));
    @memcpy(entry.host[0..shl], fac.host[0..shl]);
    entry.host_len = shl;
    entry.port = fac.port;
    entry.use_tls = fac.use_tls;
    entry.timeout_ms = fac.timeout_ms;
    var settle_json_buf: [4096]u8 = undefined;
    const settle_json_len = x402_mod.buildSettleRequestJson(&settle_json_buf, payment_header, policy, charge) catch return;
    entry.http_len = @intCast(x402_mod.buildFacilitatorPost(&entry.http_buf, fac, "/settle", settle_json_buf[0..settle_json_len]) catch return);
    entry.has_settlement_url = policy.settlement_url.len > 0;
    const gid_len: u8 = @intCast(@min(policy.gateway_id.len, entry.gateway_id.len));
    @memcpy(entry.gateway_id[0..gid_len], policy.gateway_id[0..gid_len]);
    entry.gateway_id_len = gid_len;
    const net_len: u8 = @intCast(@min(policy.network.len, entry.settle_network.len));
    @memcpy(entry.settle_network[0..net_len], policy.network[0..net_len]);
    entry.settle_network_len = net_len;
    const asset_len: u8 = @intCast(@min(policy.asset.len, entry.settle_asset.len));
    @memcpy(entry.settle_asset[0..asset_len], policy.asset[0..asset_len]);
    entry.settle_asset_len = asset_len;
    const amt = if (charge.len > 0) charge else policy.price;
    const amt_len: u8 = @intCast(@min(amt.len, entry.settle_amount.len));
    @memcpy(entry.settle_amount[0..amt_len], amt[0..amt_len]);
    entry.settle_amount_len = amt_len;
    const rp_len: u8 = @intCast(@min(request_path.len, entry.request_path.len));
    @memcpy(entry.request_path[0..rp_len], request_path[0..rp_len]);
    entry.request_path_len = rp_len;
}

/// Pack upstream response (status + headers + body) into a pool buffer
/// so it survives proxy_result.release(). Returns false if the response
/// doesn't fit (> ~64KB) or no buffer is available — caller falls back
/// to fire-and-forget settlement.
fn packHeldResponse(server: *Server, conn: *connection.Connection, resp: response_mod.Response) bool {
    const buf = server.io.acquireBuffer() orelse return false;
    const body_bytes = resp.bodyBytes();
    const result = packHeaders(buf.bytes, resp.headers, body_bytes) orelse {
        server.io.releaseBuffer(buf);
        return false;
    };
    conn.x402_held_buf = buf;
    conn.x402_held_status = resp.status;
    conn.x402_held_hdr_count = result.count;
    conn.x402_held_body_offset = result.body_offset;
    conn.x402_held_body_len = @intCast(body_bytes.len);
    return true;
}

const PackResult = struct { count: u8, body_offset: u16 };

/// Encode response headers + body into a flat byte buffer.
/// Format per header: [name_len:u8][value_len_lo:u8][value_len_hi:u8][name][value]
/// Body follows immediately after the last header.
fn packHeaders(bytes: []u8, headers: []const response_mod.Header, body: []const u8) ?PackResult {
    var pos: usize = 0;
    var count: u8 = 0;
    for (headers) |hdr| {
        if (count >= 62) break;
        if (hdr.name.len > 255) continue;
        const val_len: u16 = @intCast(@min(hdr.value.len, 65535));
        const need = 3 + hdr.name.len + val_len;
        if (pos + need > bytes.len) return null;
        bytes[pos] = @intCast(hdr.name.len);
        bytes[pos + 1] = @truncate(val_len);
        bytes[pos + 2] = @truncate(val_len >> 8);
        pos += 3;
        @memcpy(bytes[pos..][0..hdr.name.len], hdr.name);
        pos += hdr.name.len;
        @memcpy(bytes[pos..][0..val_len], hdr.value[0..val_len]);
        pos += val_len;
        count += 1;
    }
    if (pos > std.math.maxInt(u16) or pos + body.len > bytes.len) return null;
    const body_offset: u16 = @intCast(pos);
    @memcpy(bytes[pos..][0..body.len], body);
    return .{ .count = count, .body_offset = body_offset };
}

/// Decode headers from the packed format written by packHeaders.
fn unpackHeaders(
    buf_bytes: []const u8,
    hdr_count: u8,
    body_offset: u16,
    out: []response_mod.Header,
) usize {
    var pos: usize = 0;
    var idx: usize = 0;
    while (idx < hdr_count and pos < body_offset) : (idx += 1) {
        if (pos + 3 > buf_bytes.len) break;
        const name_len: usize = buf_bytes[pos];
        const value_len: usize = @as(u16, buf_bytes[pos + 1]) | (@as(u16, buf_bytes[pos + 2]) << 8);
        pos += 3;
        if (pos + name_len + value_len > buf_bytes.len) break;
        if (idx >= out.len) break;
        out[idx] = .{
            .name = buf_bytes[pos..][0..name_len],
            .value = buf_bytes[pos + name_len ..][0..value_len],
        };
        pos += name_len + value_len;
    }
    return idx;
}

fn releaseHeldBuffer(server: *Server, conn: *connection.Connection) void {
    if (conn.x402_held_buf) |buf| {
        server.io.releaseBuffer(buf);
        conn.x402_held_buf = null;
    }
}

/// Resume a settle-parked connection: unpack the held response, inject
/// receipt headers, and queue it for transmission.
fn resumeSettlePark(server: *Server, conn: *connection.Connection, result: *const x402_client.ResultEntry) void {
    const held_buf = conn.x402_held_buf orelse {
        conn.x402 = .none;
        return;
    };
    const buf_bytes = held_buf.bytes;

    var held_headers: [64]response_mod.Header = undefined;
    var hdr_idx = unpackHeaders(buf_bytes, conn.x402_held_hdr_count, conn.x402_held_body_offset, &held_headers);

    // Inject receipt headers (V2 PAYMENT-RESPONSE + V1 X-PAYMENT-RESPONSE)
    if (result.success and result.receipt_b64_len > 0 and hdr_idx + 2 <= held_headers.len) {
        const receipt = result.receipt_b64[0..result.receipt_b64_len];
        held_headers[hdr_idx] = .{ .name = "PAYMENT-RESPONSE", .value = receipt };
        hdr_idx += 1;
        held_headers[hdr_idx] = .{ .name = "X-PAYMENT-RESPONSE", .value = receipt };
        hdr_idx += 1;
    }

    const body_end = @as(usize, conn.x402_held_body_offset) + conn.x402_held_body_len;
    const body = if (conn.x402_held_body_len > 0 and body_end <= buf_bytes.len)
        buf_bytes[conn.x402_held_body_offset..body_end]
    else
        @as([]const u8, "");

    const resp = response_mod.Response{
        .status = conn.x402_held_status,
        .headers = held_headers[0..hdr_idx],
        .body = .{ .bytes = body },
    };
    http1_mod.queueResponse(server, conn, resp) catch {
        conn.close_after_write = true;
    };
    // Materialize pending_body before releasing the held buffer
    if (conn.pending_body.len > 0) {
        http1_mod.materializePendingBody(server, conn);
    }
    releaseHeldBuffer(server, conn);
    conn.x402 = .none;
}

// ============================================================
// Tests — settle-park pack/unpack roundtrip
// ============================================================

test "packHeaders roundtrip with body" {
    var buf: [4096]u8 = undefined;
    const headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "X-Request-Id", .value = "abc-123" },
    };
    const body = "{\"ok\":true}";
    const result = packHeaders(&buf, &headers, body) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 2), result.count);

    var out: [64]response_mod.Header = undefined;
    const n = unpackHeaders(&buf, result.count, result.body_offset, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("Content-Type", out[0].name);
    try std.testing.expectEqualStrings("application/json", out[0].value);
    try std.testing.expectEqualStrings("X-Request-Id", out[1].name);
    try std.testing.expectEqualStrings("abc-123", out[1].value);

    const body_end = @as(usize, result.body_offset) + body.len;
    try std.testing.expectEqualStrings(body, buf[result.body_offset..body_end]);
}

test "packHeaders empty body" {
    var buf: [4096]u8 = undefined;
    const headers = [_]response_mod.Header{
        .{ .name = "Content-Length", .value = "0" },
    };
    const result = packHeaders(&buf, &headers, "") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 1), result.count);

    var out: [64]response_mod.Header = undefined;
    const n = unpackHeaders(&buf, result.count, result.body_offset, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("Content-Length", out[0].name);
    try std.testing.expectEqualStrings("0", out[0].value);
}

test "packHeaders no headers with body" {
    var buf: [4096]u8 = undefined;
    const result = packHeaders(&buf, &.{}, "hello") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 0), result.count);
    try std.testing.expectEqual(@as(u16, 0), result.body_offset);
    try std.testing.expectEqualStrings("hello", buf[0..5]);
}

test "packHeaders rejects when buffer too small" {
    var buf: [10]u8 = undefined;
    const headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "application/json" },
    };
    try std.testing.expect(packHeaders(&buf, &headers, "") == null);
}

test "packHeaders caps at 62 headers" {
    var buf: [65536]u8 = undefined;
    var headers: [70]response_mod.Header = undefined;
    for (&headers) |*h| h.* = .{ .name = "X", .value = "Y" };
    const result = packHeaders(&buf, &headers, "") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 62), result.count);

    var out: [64]response_mod.Header = undefined;
    const n = unpackHeaders(&buf, result.count, result.body_offset, &out);
    try std.testing.expectEqual(@as(usize, 62), n);
}

test "packHeaders skips headers with name > 255 bytes" {
    var buf: [4096]u8 = undefined;
    var long_name: [256]u8 = undefined;
    @memset(&long_name, 'X');
    const headers = [_]response_mod.Header{
        .{ .name = &long_name, .value = "v" },
        .{ .name = "Ok", .value = "yes" },
    };
    const result = packHeaders(&buf, &headers, "") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 1), result.count);

    var out: [64]response_mod.Header = undefined;
    const n = unpackHeaders(&buf, result.count, result.body_offset, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("Ok", out[0].name);
}

test "packHeaders body too large for buffer" {
    var buf: [32]u8 = undefined;
    const headers = [_]response_mod.Header{
        .{ .name = "A", .value = "B" },
    };
    var body: [30]u8 = undefined;
    @memset(&body, 'Z');
    try std.testing.expect(packHeaders(&buf, &headers, &body) == null);
}

fn initSettlement(server: *Server) void {
    const token = if (server.config_source) |cs| switch (cs) {
        .url => |uc| uc.token,
        .file => "",
    } else "";
    if (server.proxy) |proxy| {
        for (proxy.route_x402_policies) |policy| {
            if (policy.settlement_url.len > 0) {
                settlement_mod.configure(policy.settlement_url, token);
                return;
            }
        }
    }
}
