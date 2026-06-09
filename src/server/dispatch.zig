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
const net = @import("../runtime/net.zig");
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

    try server.io.start();
    server.refreshCachedDate();
    if (server.listener_fd == null) {
        const fd = try net.listen(server.cfg.address, server.cfg.port, 4096);
        server.listener_fd = fd;
    }
    try server.io.registerListener(server.listener_fd.?);
    if (server.spare_fd == null) {
        server.spare_fd = std.posix.openat(std.posix.AT.FDCWD, "/dev/null", .{}, 0) catch null;
    }
    // Initialize UDP listener for QUIC if enabled
    if (server.quic != null) {
        if (server.udp_fd == null) {
            const quic_port = server.cfg.quic.port;
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

    // Start async x402 facilitator thread unconditionally. Idle-sleeps 1ms
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
            if (server.listener_fd) |lfd| {
                _ = server.io.unregister(lfd) catch {};
                clock.closeFd(lfd);
                server.listener_fd = null;
            }
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
                        const fd = server.listener_fd orelse continue;
                        accept_mod.handleAccept(server, fd) catch |err| {
                            std.log.warn("Accept failed: {}", .{err});
                        };
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
                        http3_mod.handleInlineDatagram(server, payload, event.datagram_peer[0..event.datagram_peer_len]);
                        if (event.kernel_buffer) |kb| kb.release();
                    } else {
                        try http3_mod.handleDatagram(server);
                    }
                },
                .read, .write, .err => {
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
            if (http2_mod.matchesHttp2Preface(candidate)) {
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

    while (conn.state != .closed and conn.read_buffered_bytes > 0 and conn.canEnqueueWrite()) {
        if (conn.x402 == .pending or conn.x402 == .settle_pending) break;
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
                    if (preencoded.findAndRefreshPreencodedH1(server, "GET", ql.path)) |entry| {
                        if (preencoded.sendH1PreencodedBytes(server, conn, entry.bytes[0..entry.len])) {
                            if (!ql.is_http11) conn.close_after_write = true;
                            server.io.onReadConsumed(conn, ql.consumed);
                            if (conn.read_buffered_bytes == 0) break;
                            continue;
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
            try http1_mod.queueFileResponse(server, conn, server.cfg.static_root, file_path, content_type);
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
                var proxy_result = proxy.handle(
                    parse.view,
                    &mw_ctx,
                    client_ip_str,
                    conn.tls_session != null,
                    server.now_ms,
                    auth_info_ptr,
                    cert_dn,
                );
                defer proxy_result.release();

                // Cache store: cache successful GET responses
                if (cache_cfg) |cc| {
                    if (parse.view.method == .GET and proxy_result.resp.status == 200) {
                        if (proxy.route_caches[route_idx]) |*rc| {
                            rc.store(
                                parse.view.path,
                                parse.view.headers,
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
                if (cache_cfg != null and parse.view.method != .GET and parse.view.method != .HEAD) {
                    if (proxy.route_caches[route_idx]) |*rc| {
                        rc.invalidate(parse.view.path);
                    }
                }

                if (server.otel) |otel_exp| {
                    otel_exp.recordSpan(parse.view.method, parse.view.path, proxy_result.resp.status, otel_start, clock.realtimeNanos() orelse 0);
                }

                // Settlement: submit async, optionally park for inline receipt
                settle_blk: {
                    if (proxy_result.resp.status < 200 or proxy_result.resp.status >= 300) break :settle_blk;
                    if (!(x402_result == .allow and x402_result.allow.needs_settlement)) break :settle_blk;
                    const fac = route_fac orelse break :settle_blk;
                    const charge = for (proxy_result.resp.headers) |hdr| {
                        if (std.ascii.eqlIgnoreCase(hdr.name, "x-charge-amount")) break hdr.value;
                    } else "";
                    var settle_entry = x402_client.RequestEntry{ .kind = .settle, .conn_index = conn.index, .conn_id = conn.id };
                    fillSettleEntry(&settle_entry, fac, x402_result.allow.payment_header, &x402_policy, charge);
                    if (settle_entry.http_len == 0) break :settle_blk;

                    // Settle-park: hold response until settlement completes, then inject receipt header.
                    // Enabled by config (inline_receipt) or per-request header (X-Inline-Receipt: true).
                    const want_receipt = x402_policy.inline_receipt or for (parse.view.headers) |hdr| {
                        if (std.ascii.eqlIgnoreCase(hdr.name, "x-inline-receipt")) break std.mem.eql(u8, hdr.value, "true");
                    } else false;
                    if (want_receipt and packHeldResponse(server, conn, proxy_result.resp)) {
                        if (x402_client.submit(settle_entry)) {
                            conn.x402 = .settle_pending;
                            server.io.setTimeoutPhase(conn, .write);
                            conn.phase_enter_ms = server.now_ms;
                            conn.markActive(server.now_ms);
                            if (conn.read_buffered_bytes == 0) break;
                            continue;
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
                // Materialize pending_body before proxy_result.release() frees the upstream buffer
                if (conn.pending_body.len > 0) {
                    http1_mod.materializePendingBody(server, conn);
                }
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
        };
        const otel_start = if (server.otel != null) clock.realtimeNanos() orelse 0 else 0;
        const result = server.app_router.handle(parse.view, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
        if (result.pause_reads_ms) |pause_ms| {
            conn.setRateLimitPause(server.now_ms, pause_ms);
        }
        try http1_mod.queueResponse(server, conn, result.resp);
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

pub fn handleWrite(server: *Server, index: u32) !void {
    const conn = server.io.getConnection(index) orelse return;
    const socket_fd = conn.fd orelse return;

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
                    return;
                },
                .err => {
                    server.closeConnection(conn);
                    return;
                },
            }
            // TLS: coalesce as many consecutive write-queue entries as fit
            // in one TLS record (TLS_PLAINTEXT_WRITE_CAP) into a single
            // SSL_write, so N small frames (e.g. concurrent h2 stream
            // responses, or a static file split into DATA frames) become one
            // record + one socket write instead of one per entry.
            while (conn.write_count > 0) {
                var gathered: usize = 0;
                {
                    var idx = conn.write_head;
                    var rem_entries = conn.write_count;
                    while (rem_entries > 0 and gathered < server_tls.TLS_PLAINTEXT_WRITE_CAP) : (rem_entries -= 1) {
                        const e = &conn.write_queue[idx];
                        const s = e.handle.bytes[e.offset..e.len];
                        if (s.len > 0) {
                            const take = @min(s.len, server_tls.TLS_PLAINTEXT_WRITE_CAP - gathered);
                            @memcpy(server.tls_gather[gathered..][0..take], s[0..take]);
                            gathered += take;
                            if (take < s.len) break; // record cap reached mid-entry
                        }
                        idx = if (idx + 1 >= conn.write_queue.len) 0 else idx + 1;
                    }
                }
                if (gathered == 0) {
                    // Only empty entries remain — drain and stop.
                    while (conn.peekWrite()) |e| {
                        if (e.len - e.offset != 0) break;
                        server.io.releaseBuffer(e.handle);
                        conn.popWrite();
                    }
                    break;
                }
                switch (connWrite(server, conn, server.tls_gather[0..gathered])) {
                    .bytes => |n| {
                        conn.markActive(server.now_ms);
                        consumeTlsWritten(server, conn, n);
                        if (conn.hasPendingBody()) {
                            http1_mod.streamBodyChunks(server, conn, conn.pending_body);
                        }
                        // If connWrite populated the carry (socket write only
                        // partially absorbed the record), pause — we resume
                        // when the next writable event drains the carry.
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
            if (conn.write_count == 0 and conn.hasPendingFile() and http1_mod.bufferPendingFileWrites(server, conn)) {
                continue;
            }
            if (conn.hasPendingH2Streams()) {
                http2_mod.drainPendingH2Streams(server, conn);
                if (conn.write_count > 0) continue;
            }
            if (conn.state == .closed) return;
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
            if (conn.send_in_flight) return;
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
                            return;
                        },
                        .INTR => continue,
                        else => {
                            server.closeConnection(conn);
                            return;
                        },
                    }
                }
                if (bytes_written == 0) return;
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
                    error.WouldBlock => return,
                    error.Closed, error.Failed => {
                        conn.cleanupPendingFile();
                        server.closeConnection(conn);
                        return;
                    },
                }
            };
            if (result.bytes_sent == 0) return;
            conn.pending_file_remaining -= result.bytes_sent;
            conn.markActive(server.now_ms);

            if (conn.pending_file_remaining == 0) {
                conn.cleanupPendingFile();
                break;
            }
        }
    }

    // Check if all writes are complete
    if (conn.state == .closed) return;
    if (conn.write_count == 0 and !conn.hasPendingBody() and !conn.hasPendingFile() and !conn.hasPendingH2Streams()) {
        if (conn.close_after_write) {
            server.closeConnection(conn);
            return;
        }
        // If there's still data in the read buffer (from a pipelining
        // backpressure break), re-enter the read handler now that
        // writes have drained and buffers are free. With edge-triggered
        // epoll, no new read event will fire since the data is already
        // buffered — we must process it explicitly here.
        if (conn.read_buffered_bytes > 0) {
            handleRead(server, index) catch {};
            return;
        }
        server.io.setTimeoutPhase(conn, .idle);
    }
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
