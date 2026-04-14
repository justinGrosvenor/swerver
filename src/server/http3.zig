//! # HTTP/3 dispatch and send path
//!
//! Everything that runs after a UDP datagram lands on the server:
//! QUIC packet processing, HTTP/3 event dispatch, router invocation
//! for cold-path requests, and the packet-building / sendmsg batch
//! path for responses.
//!
//! Two datagram entry points, mirrored from the two backend shapes:
//!
//!   - `handleDatagram` drains the UDP fd via `recvfrom` in a loop.
//!     Called on poll/epoll backends that only deliver readiness
//!     events, not data.
//!   - `handleInlineDatagram` runs on the native io_uring backend
//!     where the multishot `recvmsg` CQE already carries the payload
//!     and peer sockaddr — we reinterpret the sockaddr and feed it
//!     straight into `processOneDatagram`.
//!
//! The send path (`sendHttp3ResponseBytes`) batches packets into a
//! single buffer and uses `UDP_SEGMENT` (GSO) to hand them to the
//! kernel in one sendmsg on Linux, falling back to per-packet
//! `sendto` on macOS or when GSO fails.
//!
//! Pre-encoded cache hits bypass `encodeHttp3Response` entirely and
//! feed the cached bytes directly into `sendHttp3ResponseBytes` —
//! see `server/preencoded.zig`.

const std = @import("std");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const net = @import("../runtime/net.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");
const router = @import("../router/router.zig");
const request = @import("../protocol/request.zig");
const response_mod = @import("../response/response.zig");
const http3 = @import("../protocol/http3.zig");
const middleware = @import("../middleware/middleware.zig");
const quic_handler = @import("../quic/handler.zig");
const quic_connection = @import("../quic/connection.zig");
const preencoded = @import("preencoded.zig");

/// Maximum datagrams to drain per handleDatagram call before
/// yielding back to the event loop. Prevents starvation of TCP
/// connections when the UDP socket has a burst of queued packets.
const MAX_DATAGRAMS_PER_DRAIN = 64;

/// GSO segment size — the maximum UDP payload we pad each QUIC
/// packet to when batching via `sendGso`. 1280 is the QUIC minimum
/// MTU; every segment except the last is padded to this size so the
/// kernel can split the buffer evenly.
const GSO_SEGMENT_SIZE: u16 = 1280;

pub fn handleDatagram(server: *Server) !void {
    const udp_fd = server.udp_fd orelse return;
    const quic = &(server.quic orelse return);

    // Drain all available datagrams in one event-loop iteration
    // (edge-triggered drain). Each recvfrom returns one datagram;
    // we loop until WouldBlock or the drain cap. This saves re-
    // entering the event loop per datagram and is the first step
    // toward recvmmsg batching (PR PERF-2 follow-up).
    var drained: usize = 0;
    while (drained < MAX_DATAGRAMS_PER_DRAIN) : (drained += 1) {
        const recv_result = net.recvfrom(udp_fd, &server.udp_recv_buf) catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return,
            }
        };
        if (recv_result.bytes_read == 0) return;

        processOneDatagram(
            server,
            udp_fd,
            quic,
            server.udp_recv_buf[0..recv_result.bytes_read],
            recv_result.peer_addr,
        );
    }
}

/// Handle a datagram whose payload + peer sockaddr were delivered
/// inline by the native io_uring backend (multishot recvmsg). The
/// kernel wrote the sockaddr into the provided buffer's reserved
/// name area; we reinterpret those bytes as SockAddrIn/SockAddrIn6
/// based on the family field so the QUIC stack can use it.
pub fn handleInlineDatagram(server: *Server, payload: []const u8, peer_bytes: []const u8) void {
    const udp_fd = server.udp_fd orelse return;
    const quic = &(server.quic orelse return);
    // The sockaddr family lives at offset 0 (u16 on Linux; we only
    // support Linux here since the native backend is Linux-only).
    // IPv4 sockaddr is 16 bytes; IPv6 is 28.
    if (peer_bytes.len < @sizeOf(u16)) return;
    const family = std.mem.readInt(u16, peer_bytes[0..2], .little);
    const net_peer: net.SockAddrStorage = blk: {
        if (family == std.posix.AF.INET) {
            if (peer_bytes.len < @sizeOf(net.SockAddrIn)) return;
            var sa: net.SockAddrIn = undefined;
            @memcpy(std.mem.asBytes(&sa)[0..@sizeOf(net.SockAddrIn)], peer_bytes[0..@sizeOf(net.SockAddrIn)]);
            break :blk .{ .ip4 = sa };
        } else if (family == std.posix.AF.INET6) {
            if (peer_bytes.len < @sizeOf(net.SockAddrIn6)) return;
            var sa: net.SockAddrIn6 = undefined;
            @memcpy(std.mem.asBytes(&sa)[0..@sizeOf(net.SockAddrIn6)], peer_bytes[0..@sizeOf(net.SockAddrIn6)]);
            break :blk .{ .ip6 = sa };
        } else {
            // Unsupported address family — drop the datagram.
            return;
        }
    };
    processOneDatagram(server, udp_fd, quic, payload, net_peer);
}

/// Process a single received UDP datagram through the QUIC stack,
/// dispatch any HTTP/3 events, and send any resulting response.
fn processOneDatagram(
    server: *Server,
    udp_fd: std.posix.fd_t,
    quic: *quic_handler.Handler,
    payload: []const u8,
    net_peer: net.SockAddrStorage,
) void {
    // Convert peer address to the QUIC stack's internal format
    // (zero-init to avoid undefined bytes leaking into the hash).
    var peer_addr: quic_handler.connection_pool.SockAddrStorage = undefined;
    @memset(std.mem.asBytes(&peer_addr), 0);
    const peer_src = std.mem.asBytes(&net_peer);
    const peer_copy_len = @min(peer_src.len, @sizeOf(quic_handler.connection_pool.SockAddrStorage));
    @memcpy(std.mem.asBytes(&peer_addr)[0..peer_copy_len], peer_src[0..peer_copy_len]);

    // Process the QUIC packet
    const result = quic.processPacket(payload, peer_addr) catch |err| {
        std.log.debug("QUIC packet error: {}", .{err});
        return;
    };

    // Send response if any (handshake responses)
    if (result.response) |resp| {
        if (resp.len > 0) {
            _ = net.sendto(udp_fd, resp, net_peer) catch |err| {
                std.log.debug("Failed to send QUIC response: {}", .{err});
            };
        }
    }

    // Process HTTP/3 events. Per the defer-until-FIN model in
    // `src/protocol/http3.zig::processRequestStream`, request
    // streams emit a single `request_ready` event once the stream
    // has finished arriving. `req.body` and `req.headers` both
    // point into buffers owned by the Stack / Stream and stay
    // valid for the duration of the synchronous handler call.
    // After dispatch we reclaim the Stream's receive buffer via
    // `clearH3RequestStream` — that's the first point at which
    // the body slice is no longer referenced.
    if (result.conn) |conn| {
        for (result.http3_events) |event| {
            switch (event) {
                .request_ready => |req| {
                    handleHttp3Request(server, udp_fd, conn, req, net_peer);
                    conn.clearH3RequestStream(req.stream_id);
                },
                .settings, .goaway, .stream_error => {},
            }
        }
    }

    // Handle connection state changes
    if (result.close_connection) {
        if (result.conn) |conn| {
            quic.pool.removeConnection(conn);
        }
    }
}

/// Handle an HTTP/3 request and send response.
///
/// Invoked from the defer-until-FIN dispatch path in
/// `handleDatagram` when the Stack emits a `RequestReadyEvent`.
/// `req.headers` slices point into the Stack's fixed-size owned
/// storage and stay valid until the next `ingest` call; `req.body`
/// is a slice into the decrypted STREAM frame payload and stays
/// valid for the duration of this synchronous call.
///
/// Fast path (PR PERF-3): before running the router, check the
/// pre-encoded h3 response cache for hot static endpoints
/// (/plaintext, /json, /health, ...). On a cache hit, skip the
/// router + middleware + encodeHttp3Response entirely and feed
/// the cached bytes straight to the QUIC send loop. Saves
/// 600-1500 cycles per request on the hottest paths.
fn handleHttp3Request(
    server: *Server,
    udp_fd: std.posix.fd_t,
    conn: *quic_connection.Connection,
    req: http3.RequestReadyEvent,
    peer_addr: net.SockAddrStorage,
) void {
    var req_headers: [65]request.Header = undefined;
    const req_view = Server.buildHttp3RequestView(req, req_headers[0..]) orelse return;

    if (!server.isAllowedHost(req_view)) {
        // Host not in allowlist — send the bad-request response
        // through the normal encode path since it's not cached.
        sendHttp3ResponseFromResponse(server, udp_fd, conn, req.stream_id, peer_addr, Server.badRequestResponse());
        return;
    }

    // --- Fast path: pre-encoded response cache ---
    // x402 gate: skip cache when payment required (must run x402.evaluate first)
    const method_str = req_view.getMethodName();
    if (!server.app_router.x402_policy.require_payment) {
        if (preencoded.findAndRefreshPreencodedH3(server, method_str, req_view.path)) |entry| {
            sendHttp3ResponseBytes(server, udp_fd, conn, req.stream_id, peer_addr, entry.bytes[0..entry.len]);
            return;
        }
    }

    // --- Cold path: full router dispatch ---
    var mw_ctx = middleware.Context{
        .protocol = .http3,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = server_mod.acquireBufferOpaque,
            .release = server_mod.releaseBufferOpaque,
        },
    };
    var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const arena_handle = server.io.acquireBuffer();
    var empty_arena: [0]u8 = undefined;
    const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
    var scratch = router.HandlerScratch{
        .response_buf = response_buf[0..],
        .response_headers = response_headers[0..],
        .arena_buf = arena_buf,
        .arena_handle = arena_handle,
        .buffer_ops = mw_ctx.buffer_ops,
    };
    const result = server.app_router.handle(req_view, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    const managed_handle: ?buffer_pool.BufferHandle = switch (result.resp.body) {
        .managed => |managed| managed.handle,
        else => null,
    };
    defer if (managed_handle) |handle| server.io.releaseBuffer(handle);

    sendHttp3ResponseFromResponse(server, udp_fd, conn, req.stream_id, peer_addr, result.resp);
}

/// Encode a router Response into h3 bytes and send it over the
/// wire. Used by the cold-path (router-dispatched) h3 flow.
/// The hot path uses `sendHttp3ResponseBytes` directly with
/// pre-encoded bytes.
fn sendHttp3ResponseFromResponse(
    server: *Server,
    udp_fd: std.posix.fd_t,
    conn: *quic_connection.Connection,
    stream_id: u64,
    peer_addr: net.SockAddrStorage,
    resp: response_mod.Response,
) void {
    const body_bytes = resp.bodyBytes();
    const body_len = resp.bodyLen();
    var encoded_response_buf: [16384]u8 = undefined;
    const resp_len = conn.encodeHttp3Response(
        &encoded_response_buf,
        resp.status,
        @ptrCast(resp.headers),
        if (body_len > 0) body_bytes else null,
    ) catch return;
    sendHttp3ResponseBytes(server, udp_fd, conn, stream_id, peer_addr, encoded_response_buf[0..resp_len]);
}

/// Send already-encoded h3 response bytes over the wire for a
/// given QUIC stream. Splits into MTU-sized chunks and feeds each
/// chunk through the unified `quic.handler::buildShortPacket`
/// builder (PR PERF-0). Shared hot-path / cold-path helper.
///
/// On Linux with GSO support, all packets are built contiguously
/// into a batch buffer and sent in a single `sendmsg()` syscall
/// with `UDP_SEGMENT`. This eliminates N-1 syscalls for multi-
/// packet responses (e.g., a 10 KiB response = ~8 packets = 1
/// syscall instead of 8). On macOS or non-GSO kernels, falls
/// back to one `sendto()` per packet.
pub fn sendHttp3ResponseBytes(
    server: *Server,
    udp_fd: std.posix.fd_t,
    conn: *quic_connection.Connection,
    stream_id: u64,
    peer_addr: net.SockAddrStorage,
    h3_bytes: []const u8,
) void {
    _ = server;
    const keys = conn.crypto_ctx.application.server orelse return;
    const max_stream_payload = 1200;

    // Piggyback any pending ACK onto the FIRST response packet.
    // This coalesces ACK + STREAM data into one UDP datagram
    // instead of two (processPacket deferred the ACK when h3
    // events were present — see the comment in handler.zig).
    const pending_ack = if (conn.application_space.ack_needed)
        conn.application_space.largest_received
    else
        null;

    // Fast path: single packet — no batching needed.
    if (h3_bytes.len <= max_stream_payload) {
        var packet_buf: [2048]u8 = undefined;
        const built = quic_handler.buildShortPacket(
            &packet_buf,
            .{
                .conn = conn,
                .keys = &keys,
                .ack_largest = pending_ack,
                .stream_data = .{
                    .stream_id = stream_id,
                    .offset = 0,
                    .data = h3_bytes,
                    .fin = true,
                },
            },
        ) catch return;
        conn.application_space.ack_needed = false;
        _ = net.sendto(udp_fd, packet_buf[0..built.bytes_written], peer_addr) catch return;
        return;
    }

    // Multi-packet path: build all packets into a contiguous batch
    // buffer. On Linux, send via GSO in one syscall. On other
    // platforms, send each packet individually.
    //
    // Max batch: 65536 / 1280 = 51 segments. More than enough for
    // even large responses. If the response exceeds the batch
    // buffer, flush mid-way and start a new batch.
    var batch_buf: [65536]u8 = undefined;
    var batch_offset: usize = 0;
    var stream_offset: u64 = 0;
    var remaining = h3_bytes;
    var pkt_count: usize = 0;
    var ack_sent = false;

    while (remaining.len > 0) {
        // Congestion control gate (RFC 9002 §7): don't send if the
        // congestion window is full. Data-bearing packets count
        // against the window; ACK-only packets are exempt.
        if (!conn.canSendPacket(GSO_SEGMENT_SIZE)) break;

        const chunk_len = @min(remaining.len, max_stream_payload);
        const is_last = (chunk_len == remaining.len);

        // Piggyback pending ACK onto the FIRST packet only.
        const ack_for_this_pkt = if (!ack_sent) pending_ack else null;

        // Build the packet into the batch buffer at the current offset.
        const built = quic_handler.buildShortPacket(
            batch_buf[batch_offset..],
            .{
                .conn = conn,
                .keys = &keys,
                .ack_largest = ack_for_this_pkt,
                .stream_data = .{
                    .stream_id = stream_id,
                    .offset = stream_offset,
                    .data = remaining[0..chunk_len],
                    .fin = is_last,
                },
            },
        ) catch return;
        if (!ack_sent and pending_ack != null) {
            conn.application_space.ack_needed = false;
            ack_sent = true;
        }

        // Pad non-final packets to the GSO segment size so the
        // kernel splits evenly. Final packet can be shorter.
        if (!is_last and built.bytes_written < GSO_SEGMENT_SIZE) {
            const pad = GSO_SEGMENT_SIZE - built.bytes_written;
            if (batch_offset + GSO_SEGMENT_SIZE <= batch_buf.len) {
                @memset(batch_buf[batch_offset + built.bytes_written .. batch_offset + built.bytes_written + pad], 0);
            }
            batch_offset += GSO_SEGMENT_SIZE;
        } else {
            batch_offset += built.bytes_written;
        }
        pkt_count += 1;
        remaining = remaining[chunk_len..];
        stream_offset += chunk_len;

        // If the batch buffer is nearly full, flush now and start
        // a new batch. (Safety margin: leave room for one more
        // max-sized packet.)
        if (!is_last and batch_offset + GSO_SEGMENT_SIZE > batch_buf.len) {
            flushGsoBatch(udp_fd, batch_buf[0..batch_offset], peer_addr, pkt_count);
            batch_offset = 0;
            pkt_count = 0;
        }
    }

    // Flush whatever remains in the batch buffer.
    if (batch_offset > 0) {
        flushGsoBatch(udp_fd, batch_buf[0..batch_offset], peer_addr, pkt_count);
    }
}

/// Flush a batch of contiguously-built QUIC packets. Tries GSO
/// first (one `sendmsg` syscall for all packets on Linux). Falls
/// back to one `sendto` per GSO_SEGMENT_SIZE chunk on macOS or
/// if GSO fails.
fn flushGsoBatch(
    udp_fd: std.posix.fd_t,
    buf: []const u8,
    peer: net.SockAddrStorage,
    pkt_count: usize,
) void {
    if (buf.len == 0) return;

    // Single packet — sendto is sufficient.
    if (pkt_count <= 1) {
        _ = net.sendto(udp_fd, buf, peer) catch return;
        return;
    }

    // Try GSO. On macOS this compiles to a plain sendto (no GSO
    // support), which will likely fail for oversized buffers, so
    // we fall through to the per-packet loop. On Linux, sendGso
    // uses sendmsg + UDP_SEGMENT to send the whole batch in one
    // syscall.
    if (net.sendGso(udp_fd, buf, peer, GSO_SEGMENT_SIZE)) |_| {
        return; // GSO succeeded — all packets sent in one call.
    } else |_| {
        // GSO failed — fall through to per-packet loop.
    }

    // Per-packet fallback: split the batch buffer into segments
    // and send each one individually.
    var offset: usize = 0;
    while (offset < buf.len) {
        const end = @min(offset + GSO_SEGMENT_SIZE, buf.len);
        _ = net.sendto(udp_fd, buf[offset..end], peer) catch return;
        offset = end;
    }
}
