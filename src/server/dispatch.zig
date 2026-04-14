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
const http1 = @import("../protocol/http1.zig");
const http2 = @import("../protocol/http2.zig");
const response_mod = @import("../response/response.zig");
const router = @import("../router/router.zig");
const middleware = @import("../middleware/middleware.zig");

const accept_mod = @import("accept.zig");
const http1_mod = @import("http1.zig");
const http2_mod = @import("http2.zig");
const http3_mod = @import("http3.zig");
const preencoded = @import("preencoded.zig");
const server_tls = @import("tls.zig");

/// Global shutdown flag set by signal handler (atomic for signal safety)
var shutdown_requested = std.atomic.Value(bool).init(false);
/// Global reload flag set by SIGHUP handler (atomic for signal safety)
var reload_requested = std.atomic.Value(bool).init(false);

fn handleShutdownSignal(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
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
    // Install signal handlers for graceful shutdown
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
    if (server.listener_fd == null) {
        const fd = try net.listen(server.cfg.address, server.cfg.port, 4096);
        server.listener_fd = fd;
    }
    try server.io.registerListener(server.listener_fd.?);
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
    const deadline = if (run_for_ms) |ms| server.io.nowMs() + ms else null;
    var last_housekeeping_ms: u64 = server.io.nowMs();
    while (true) {
        if (shutdown_requested.load(.acquire)) return;
        if (reload_requested.swap(false, .acq_rel)) {
            server.applyReload();
        }
        if (deadline) |limit| {
            if (server.io.nowMs() >= limit) return;
        }
        // Single clock call per loop iteration — reused for poll
        // timeout, timeout enforcement, and proxy maintenance.
        const now_ms = server.io.nowMs();

        // Housekeeping (timeout enforcement, QUIC cleanup, proxy
        // maintenance) runs at most every 100ms. Under high load
        // the event loop processes thousands of requests between
        // housekeeping passes. This eliminates per-tick O(active)
        // connection scans that dominated CPU at high core counts.
        const housekeeping_interval_ms: u64 = 100;
        const needs_housekeeping = (now_ms -% last_housekeeping_ms) >= housekeeping_interval_ms;
        const timeout_ms: u32 = if (needs_housekeeping) 0 else 10;
        const events = try server.io.pollWithTimeout(timeout_ms);

        if (needs_housekeeping) {
            last_housekeeping_ms = now_ms;
            // Enforce timeouts and close timed-out connections
            const timeout_result = server.io.enforceTimeouts(now_ms);
            for (timeout_result.to_close[0..timeout_result.count]) |conn_index| {
                if (server.io.getConnection(conn_index)) |conn| {
                    server.closeConnection(conn);
                }
            }
            // Periodic QUIC cleanup
            if (server.quic) |*q| {
                q.cleanup();
            }
            // Periodic proxy maintenance (pool eviction + health checks)
            if (server.proxy) |proxy| {
                proxy.runMaintenance(now_ms);
            }
        }
        if (events.len == 0) continue;
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
                        };
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
                            if (rconn.write_count > 0) {
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
                                !postconn.close_after_write)
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
                                advanceAsyncWriteQueue(server, conn, event.bytes);
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
            conn.markActive(server.io.nowMs());
        }
        return;
    }
    const buf = conn.read_buffer orelse return;
    const end = conn.read_offset + conn.read_buffered_bytes;
    if (end + data.len > buf.bytes.len) {
        // Data doesn't fit in the remaining buffer space. In this
        // case we simply drop the extra bytes — they were
        // already consumed from the kernel ring. The connection
        // will likely hit a parse error and close, which is the
        // correct behavior for an oversized request.
        const available = if (end >= buf.bytes.len) 0 else buf.bytes.len - end;
        if (available == 0) return;
        @memcpy(buf.bytes[end..][0..available], data[0..available]);
        server.io.onReadBuffered(conn, available);
        conn.markActive(server.io.nowMs());
        return;
    }
    @memcpy(buf.bytes[end..][0..data.len], data);
    server.io.onReadBuffered(conn, data.len);
    conn.markActive(server.io.nowMs());
}

/// Build an iovec batch from the connection's write queue and
/// submit it as an async `IORING_OP_WRITEV` SQE on the native
/// io_uring backend. Returns `true` if the SQE was accepted (the
/// caller should `return` and wait for the CQE) or `false` if
/// the submission failed and the caller should fall back to a
/// sync writev.
///
/// On success the iovec array is parked on `conn.async_send_iov`
/// so its address stays stable until the kernel has copied the
/// bytes out; `conn.send_in_flight` is set to lock out further
/// submissions until the `.write` CQE fires.
pub fn submitConnAsyncWritev(server: *Server, conn: *connection.Connection, fd: std.posix.fd_t) bool {
    var iov_count: u16 = 0;
    var total_bytes: usize = 0;
    var scan_head = conn.write_head;
    var scan_remaining = conn.write_count;
    const cap = connection.async_send_iov_capacity;
    while (scan_remaining > 0 and iov_count < cap) : (iov_count += 1) {
        const e = &conn.write_queue[scan_head];
        const s = e.handle.bytes[e.offset..e.len];
        conn.async_send_iov[iov_count] = .{ .base = s.ptr, .len = s.len };
        total_bytes += s.len;
        scan_head = if (scan_head + 1 >= conn.write_queue.len) 0 else scan_head + 1;
        scan_remaining -= 1;
    }
    if (iov_count == 0) return false;
    const iov_slice = conn.async_send_iov[0..iov_count];
    server.io.submitAsyncWritev(conn.index, fd, iov_slice) catch return false;
    conn.send_in_flight = true;
    conn.async_send_iov_count = iov_count;
    conn.async_send_total_bytes = total_bytes;
    return true;
}

/// Advance the connection's write queue after an async writev
/// CQE reports `bytes_written`. Pops any fully-sent entries,
/// releases their buffers, and updates `entry.offset` on a
/// partially-sent entry. Called from the event dispatcher when a
/// `.write` event arrives for a connection with `send_in_flight`.
pub fn advanceAsyncWriteQueue(server: *Server, conn: *connection.Connection, bytes_written: usize) void {
    var remaining = bytes_written;
    while (remaining > 0) {
        const entry = conn.peekWrite() orelse break;
        const left_in_entry = entry.len - entry.offset;
        if (remaining >= left_in_entry) {
            remaining -= left_in_entry;
            server.io.onWriteCompleted(conn, left_in_entry);
            server.io.releaseBuffer(entry.handle);
            conn.popWrite();
            if (conn.hasPendingBody()) {
                http1_mod.streamBodyChunks(server, conn, conn.pending_body);
            }
        } else {
            entry.offset += remaining;
            server.io.onWriteCompleted(conn, remaining);
            remaining = 0;
        }
    }
    conn.send_in_flight = false;
    conn.async_send_iov_count = 0;
    conn.async_send_total_bytes = 0;
    conn.markActive(server.io.nowMs());
}

pub fn handleRead(server: *Server, index: u32) !void {
    const conn = server.io.getConnection(index) orelse return;
    if (conn.fd == null) return;
    if (!server.io.canRead(conn)) return;
    if (conn.timeout_phase == .idle) server.io.setTimeoutPhase(conn, .header);
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
            conn.markActive(server.io.nowMs());
            http1_mod.continueBodyAccumulation(server, conn) catch {
                http1_mod.abortBodyAccumulation(server, conn, 400);
                return;
            };
            // Body complete — dispatch already happened
            if (!conn.isAccumulatingBody()) return;
        }
    }

    const offset = conn.read_offset + conn.read_buffered_bytes;
    if (offset >= buffer_handle.bytes.len) {
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
    // With completion-model backends (io_uring native), the event
    // dispatcher has already seeded read_buffered_bytes from the
    // kernel's provided buffer. Skip the read() syscall in that
    // case — the data is already there. For TLS on native, the
    // kernel-delivered bytes are ciphertext living in rbio; we still
    // need to call connRead (SSL_read) to pull plaintext out.
    if (!server.io.capabilities().delivers_read_data or conn.is_tls) {
        const slice = buffer_handle.bytes[offset..];
        const count = switch (connRead(server, conn, slice)) {
            .bytes => |n| n,
            .eof => {
                server.closeConnection(conn);
                return;
            },
            .again => return,
            .err => {
                server.closeConnection(conn);
                return;
            },
        };
        server.io.onReadBuffered(conn, count);
        conn.markActive(server.io.nowMs());
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
            while (true) {
                const drain_buf = conn.read_buffer orelse break;
                const drain_offset = conn.read_offset + conn.read_buffered_bytes;
                if (drain_offset >= drain_buf.bytes.len) break;
                const drain_slice = drain_buf.bytes[drain_offset..];
                switch (connRead(server, conn, drain_slice)) {
                    .bytes => |n| {
                        server.io.onReadBuffered(conn, n);
                        conn.markActive(server.io.nowMs());
                        try http2_mod.handleHttp2Read(server, conn);
                    },
                    .eof => {
                        server.closeConnection(conn);
                        return;
                    },
                    .again, .err => break,
                }
            }
        }
        return;
    }

    while (conn.read_buffered_bytes > 0 and conn.canEnqueueWrite()) {
        const start = conn.read_offset;
        const end = start + conn.read_buffered_bytes;
        if (end > buffer_handle.bytes.len) break;
        const parse = http1.parse(buffer_handle.bytes[start..end], .{
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
            // If buffer is full with a partial request, attempt body accumulation now.
            // With edge-triggered epoll, we may not get another read event to trigger
            // the buffer-full handler at the top of handleRead.
            const parse_end = conn.read_offset + conn.read_buffered_bytes;
            if (parse_end >= buffer_handle.bytes.len) {
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
                } else if (hparse.state == .partial) {
                    // Headers not complete → 431
                    conn.close_after_write = true;
                    server.io.onReadConsumed(conn, conn.read_buffered_bytes);
                    try http1_mod.queueResponse(server, conn, http1_mod.errorResponseFor(.header_too_large));
                }
                // else: hparse.state == .err handled by returning (let next event handle it)
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
        server.io.onReadConsumed(conn, parse.consumed_bytes);

        if (!server.isAllowedHost(parse.view)) {
            conn.close_after_write = true;
            try http1_mod.queueResponse(server, conn, Server.badRequestResponse());
            return;
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
            if (proxy.matchRoute(&parse.view) != null) {
                var mw_ctx = middleware.Context{
                    .protocol = .http1,
                    .buffer_ops = .{
                        .ctx = &server.io,
                        .acquire = server_mod.acquireBufferOpaque,
                        .release = server_mod.releaseBufferOpaque,
                    },
                };
                // Use cached client IP for proxy headers
                var ip_buf: [64]u8 = undefined;
                var client_ip_str: ?[]const u8 = null;
                if (conn.cached_peer_ip) |ip4| {
                    const ip_len = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                    if (ip_len.len > 0) client_ip_str = ip_buf[0..ip_len.len];
                }
                var proxy_result = proxy.handle(
                    parse.view,
                    &mw_ctx,
                    client_ip_str,
                    false, // HTTP/1.1 listener is non-TLS; QUIC/HTTP3 connections don't use this proxy path
                    server.io.nowMs(),
                );
                defer proxy_result.release();

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
                .acquire = server_mod.acquireBufferOpaque,
                .release = server_mod.releaseBufferOpaque,
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
        const result = server.app_router.handle(parse.view, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
        // Apply rate limit backpressure if signaled
        if (result.pause_reads_ms) |pause_ms| {
            conn.setRateLimitPause(server.io.nowMs(), pause_ms);
        }
        try http1_mod.queueResponse(server, conn, result.resp);
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
                conn.markActive(server.io.nowMs());
                return handleRead(server, index);
            },
            .eof, .again, .err => {},
        }
        // No more data available, continue normally
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
                .again => return,
                .err => {
                    server.closeConnection(conn);
                    return;
                },
            }
            // TLS: write one buffer at a time through SSL_write
            while (conn.write_count > 0) {
                const entry = conn.peekWrite() orelse break;
                const data = entry.handle.bytes[entry.offset..entry.len];
                if (data.len == 0) {
                    server.io.releaseBuffer(entry.handle);
                    conn.popWrite();
                    continue;
                }
                switch (connWrite(server, conn, data)) {
                    .bytes => |n| {
                        conn.markActive(server.io.nowMs());
                        if (n >= data.len) {
                            server.io.onWriteCompleted(conn, data.len);
                            server.io.releaseBuffer(entry.handle);
                            conn.popWrite();
                            if (conn.hasPendingBody()) {
                                http1_mod.streamBodyChunks(server, conn, conn.pending_body);
                            }
                        } else {
                            entry.offset += n;
                            server.io.onWriteCompleted(conn, n);
                        }
                        // If connWrite populated the carry (writev was
                        // only partially absorbed), pause the loop —
                        // we'll resume once the next writable event
                        // drains the carry.
                        if (conn.tls_cipher_carry_handle != null) return;
                    },
                    .again => return,
                    .err => {
                        server.closeConnection(conn);
                        return;
                    },
                }
            }
            if (conn.write_count == 0 and conn.hasPendingFile() and http1_mod.bufferPendingFileWrites(server, conn)) {
                continue;
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
                conn.markActive(server.io.nowMs());

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
            conn.markActive(server.io.nowMs());

            if (conn.pending_file_remaining == 0) {
                conn.cleanupPendingFile();
                break;
            }
        }
    }

    // Check if all writes are complete
    if (conn.state == .closed) return;
    if (conn.write_count == 0 and !conn.hasPendingBody() and !conn.hasPendingFile()) {
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
