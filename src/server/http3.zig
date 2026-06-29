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
const clock = @import("../runtime/clock.zig");
const write_queue = @import("write_queue.zig");
const build_options = @import("build_options");
const proxy_mod = @import("../proxy/proxy.zig");
const quic_crypto = @import("../quic/crypto.zig");
const quic_types = @import("../quic/types.zig");
const wasm_filter_mod = if (build_options.enable_wasm) @import("../wasm/filter.zig") else struct {};

// The WASM host-call (park) deadline for an H3 stream is configurable per-server
// via `Server.wasm_host_call_deadline_ms` (default 30s, F2), mirroring H1/H2. A
// parked stream past this is failed closed by the reactor's wasmTick backstop.

/// Sentinel `conn_index` for H3 parks in the per-stream host_call table (E2b).
/// H1/H2 use the io-runtime connection slot index as `conn_index` and the slot
/// generation as `conn_id`; H3 has no io-runtime connection (the QUIC connection
/// lives in the QUIC pool), so it uses this fixed sentinel index for every H3
/// park and the QUIC connection's stable `Connection.id` as `conn_id`. The
/// sentinel keeps the H3 key space disjoint from any real io slot index, so a
/// cancel/lookup never collides with an H1/H2 park. maxInt(u32) is never a valid
/// io connection slot (those run 0..max_connections-1).
const H3_CONN_INDEX: u32 = std.math.maxInt(u32);

/// Transport start hook (router/proxy WasmBinding.start_fn) for H3 parks. Routes
/// a freshly parked filter's host call to the Server's transport (control socket
/// or mock). `ctx` is the Server. Mirrors http2.wasmStartThunkH2.
fn wasmStartThunkH3(ctx: *anyopaque, token: u32, req_bytes: []const u8) void {
    const server: *Server = @ptrCast(@alignCast(ctx));
    server.wasmStartHostCall(token, req_bytes);
}

/// Reconstruct a `net.SockAddrStorage` (tagged ip4/ip6 union the send path
/// wants) from the QUIC pool's flat `SockAddrStorage` (family + raw bytes). The
/// flat storage holds the original sockaddr bytes verbatim (copied at ingest in
/// `processOneDatagram`), so we reinterpret them by family, mirroring
/// `net.recvfrom`. Used by the H3 park resume path, which sends off the datagram
/// flow and so cannot thread the original peer address through.
pub fn netPeerFromQuic(qaddr: *const quic_handler.connection_pool.SockAddrStorage) net.SockAddrStorage {
    var storage: net.SockAddrStorage = .{ .ip6 = undefined };
    const dst = std.mem.asBytes(&storage.ip6);
    const src = std.mem.asBytes(qaddr);
    const n = @min(dst.len, src.len);
    @memset(dst, 0);
    @memcpy(dst[0..n], src[0..n]);
    const sa: *const std.posix.sockaddr = @ptrCast(&storage.ip6);
    if (sa.family == std.posix.AF.INET) {
        const sa4: *const net.SockAddrIn = @ptrCast(&storage.ip6);
        storage = .{ .ip4 = sa4.* };
    }
    return storage;
}

/// Deliver a resumed parked H3 stream's response (E2b). Re-locates the QUIC
/// connection by its stable id (the host_call `conn_id`), recovers the peer
/// address, and sends `resp` on `stream_id` via the normal h3 encode/send path.
/// No-op if the connection was freed while parked (the peer disconnected or the
/// stream/connection was reset): the lookup fails and there is nobody to serve.
/// Called from dispatch.wasmResumeHttp3, which runs off the datagram flow.
pub fn deliverResume(server: *Server, conn_id: u64, stream_id: u32, resp: response_mod.Response) void {
    const quic = &(server.quic orelse return);
    const udp_fd = server.udp_fd orelse return;
    const conn = quic.pool.findById(conn_id) orelse return;
    const qaddr = quic.pool.getPeerAddr(conn) orelse return;
    const peer = netPeerFromQuic(&qaddr);
    sendHttp3ResponseFromResponse(server, udp_fd, conn, @as(u64, stream_id), peer, resp);
}

/// Release any WASM filter parked on a stream the peer reset (E2b). Called from
/// the datagram path for each `ProcessResult.reset_streams` entry; the H3 analog
/// of http2.zig releasing a park on RST_STREAM. No-op (generation-checked in the
/// table) when nothing is parked on the stream. Compiled in all builds; the
/// cancel itself is wasm-gated inside `wasmCancelForStream`.
fn releaseResetParks(server: *Server, conn: *quic_connection.Connection, reset_streams: []const u64) void {
    if (!build_options.enable_wasm) return;
    for (reset_streams) |sid| {
        server.wasmCancelForStream(H3_CONN_INDEX, conn.id, @truncate(sid));
    }
}

/// Maximum datagrams to drain per handleDatagram call before
/// yielding back to the event loop. Prevents starvation of TCP
/// connections when the UDP socket has a burst of queued packets.
const MAX_DATAGRAMS_PER_DRAIN = 64;

/// QUIC minimum MTU — used as the congestion control packet-size
/// estimate and the maximum UDP datagram target size. Also the GSO
/// segment size (UDP_SEGMENT) for batched sends.
pub const GSO_SEGMENT_SIZE: u16 = 1280;

/// Max QUIC packets coalesced into one GSO sendmsg. The kernel caps a
/// UDP_SEGMENT send at 64 segments and ~64 KiB total; 45 * 1280 = 57600
/// stays safely under both. The Server reuses one batch buffer of this
/// size (single-threaded reactor, no reentrancy).
pub const GSO_MAX_SEGMENTS: usize = 45;
pub const GSO_BATCH_BYTES: usize = GSO_MAX_SEGMENTS * GSO_SEGMENT_SIZE;

pub fn handleDatagram(server: *Server) !void {
    const udp_fd = server.udp_fd orelse return;
    const quic = &(server.quic orelse return);

    // Drain all available datagrams in one event-loop iteration
    // (edge-triggered drain). Each recvfrom returns one datagram;
    // we loop until WouldBlock or the drain cap. This saves re-
    // entering the event loop per datagram and is the first step
    // toward recvmmsg batching.
    var drained: usize = 0;
    while (drained < MAX_DATAGRAMS_PER_DRAIN) : (drained += 1) {
        // recvmsg variant reads the UDP_GRO cmsg so the kernel can
        // hand us several coalesced same-flow datagrams in one syscall.
        const recv_result = net.recvmsgGro(udp_fd, &server.udp_recv_buf) catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return,
            }
        };
        if (recv_result.bytes_read == 0) return;

        processDatagramBuf(
            server,
            udp_fd,
            quic,
            server.udp_recv_buf[0..recv_result.bytes_read],
            recv_result.gso_size,
            recv_result.peer_addr,
        );
    }
}

/// Split a (possibly GRO-coalesced) receive buffer into individual QUIC
/// datagrams and process each. When `gso_size` is 0 the buffer is a single
/// datagram; otherwise it holds back-to-back `gso_size`-byte datagrams
/// from one flow (the last may be shorter). All segments share `net_peer`
/// since GRO only coalesces datagrams of the same 4-tuple.
fn processDatagramBuf(
    server: *Server,
    udp_fd: std.posix.fd_t,
    quic: *quic_handler.Handler,
    buf: []const u8,
    gso_size: u16,
    net_peer: net.SockAddrStorage,
) void {
    if (gso_size == 0 or buf.len <= gso_size) {
        processOneDatagram(server, udp_fd, quic, buf, net_peer);
        return;
    }
    const seg: usize = gso_size;
    var off: usize = 0;
    while (off < buf.len) {
        const end = @min(off + seg, buf.len);
        processOneDatagram(server, udp_fd, quic, buf[off..end], net_peer);
        off = end;
    }
}

/// Handle a datagram whose payload + peer sockaddr were delivered
/// inline by the native io_uring backend (multishot recvmsg). The
/// kernel wrote the sockaddr into the provided buffer's reserved
/// name area; we reinterpret those bytes as SockAddrIn/SockAddrIn6
/// based on the family field so the QUIC stack can use it.
pub fn handleInlineDatagram(server: *Server, payload: []const u8, peer_bytes: []const u8, gso_size: u16) void {
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
    processDatagramBuf(server, udp_fd, quic, payload, gso_size, net_peer);
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
        // Peer reset a stream: release any per-stream WASM filter park on it
        // (E2b) before dispatching this packet's request events, so a reset that
        // arrives in the same packet as new work cannot resume onto a dead
        // stream. No-op when nothing is parked.
        if (build_options.enable_wasm and result.reset_streams.len > 0) {
            releaseResetParks(server, conn, result.reset_streams);
        }
        for (result.http3_events) |event| {
            switch (event) {
                .request_ready => |req| {
                    handleHttp3Request(server, udp_fd, conn, req, net_peer);
                    conn.clearH3RequestStream(req.stream_id);
                },
                .settings => {},
                .goaway, .stream_error => {},
            }
        }
    }

    // Drain any pending response data that was buffered because
    // the congestion window was full. ACK frames in the packet we
    // just processed may have freed window capacity.
    if (result.conn) |conn| {
        if (conn.pending_send != null) {
            drainPendingSend(server, udp_fd, conn, net_peer);
        }
    }

    // Handle connection state changes
    if (result.close_connection) {
        if (result.conn) |conn| {
            // Release every per-stream WASM filter parked on this connection
            // (E2b) before the QUIC connection is freed, so no instance leaks
            // when the peer closes mid-park. O(1) when nothing is parked. The
            // host-call deadline tick is the backstop for the idle-timeout
            // cleanup path (pool.cleanup), which frees connections without a
            // Server reference; a late completion there fails pool.findById.
            if (build_options.enable_wasm) server.wasmCancelForConn(H3_CONN_INDEX, conn.id);
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

    // --- Static file serving ---
    if (server.cfg.static_root.len > 0 and std.mem.startsWith(u8, req_view.path, "/static/")) {
        const file_path = req_view.path[8..];
        const content_type = Server.guessContentType(file_path);
        const accept_encoding = req_view.getHeader("accept-encoding") orelse "";
        if (server.staticCacheGetOrLoad(file_path, content_type, accept_encoding)) |entry| {
            var hdrs: [3]response_mod.Header = undefined;
            sendHttp3ResponseFromResponse(server, udp_fd, conn, req.stream_id, peer_addr, Server.staticCacheResponse(entry, &hdrs));
        } else {
            serveStaticFileH3(server, udp_fd, conn, req.stream_id, peer_addr, file_path, content_type, accept_encoding);
        }
        return;
    }

    // --- Cold path: full router dispatch ---
    var mw_ctx = middleware.Context{
        .protocol = .http3,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = write_queue.acquireBufferOpaque,
            .release = write_queue.releaseBufferOpaque,
        },
    };

    // Reverse-proxy routing over HTTP/3: forward matching routes to the
    // upstream and emit the response on this stream, so swerver works as an
    // h3/QUIC edge gateway. Mirrors the H1/H2 proxy paths; guarded by
    // `server.proxy` so non-proxy servers are unaffected. QUIC is always TLS.
    if (server.proxy) |proxy| {
        if (proxy.matchRoute(&req_view)) |_| {
            const stream_id32: u32 = @truncate(req.stream_id);
            // Real per-stream park binding (E2b): a parking proxy filter suspends
            // THIS stream and resumes via wasmResume's .http3 arm, keyed by the
            // QUIC connection id + stream id. Other streams on the connection keep
            // flowing. The empty binding (`.{}`) is kept when wasm is off, where a
            // parking filter fails closed.
            const proxy_binding: proxy_mod.WasmBinding = if (build_options.enable_wasm) .{
                .table = @ptrCast(&server.wasm_host_calls),
                .conn_index = H3_CONN_INDEX,
                .conn_id = conn.id,
                .stream_id = stream_id32,
                .protocol = .http3,
                .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
                .start_fn = wasmStartThunkH3,
                .start_ctx = @ptrCast(server),
            } else .{};
            var proxy_result = proxy.handle(
                req_view,
                &mw_ctx,
                null,
                true,
                server.now_ms,
                null,
                null,
                proxy_binding,
            );
            defer proxy_result.release();
            // Park sentinel: the filter parked on a host_call. Leave the stream
            // suspended (no frames sent, stream stays open); wasmResume delivers
            // the response on this stream once the host call completes.
            if (build_options.enable_wasm and proxy_result.resp.isParked()) {
                if (server.wasmHasParkForStream(H3_CONN_INDEX, conn.id, stream_id32)) return;
                // Sentinel without a live park (orphaned park): release any orphan
                // and fail closed, mirroring the router orphan branch below.
                server.wasmCancelForStream(H3_CONN_INDEX, conn.id, stream_id32);
                sendHttp3ResponseFromResponse(server, udp_fd, conn, req.stream_id, peer_addr, Server.internalErrorResponse());
                return;
            }
            // On pool/park-table exhaustion proxy_result.pause_reads_ms is set,
            // but H3/QUIC multiplexes every connection over one shared UDP socket
            // with no per-connection read-pause (unlike TCP), so the backpressure
            // window does not apply here: the 503 stays a plain fail-closed reject.
            sendHttp3ResponseFromResponse(server, udp_fd, conn, req.stream_id, peer_addr, proxy_result.resp);
            return;
        }
    }

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
    // Real per-stream park binding (E2b): a parking WASM filter suspends THIS
    // stream (recorded in the host_call table, keyed by the QUIC connection id +
    // stream id) and resumes via wasmResume's .http3 arm. The connection keeps
    // multiplexing its other streams while this one waits.
    const stream_id32: u32 = @truncate(req.stream_id);
    if (build_options.enable_wasm) {
        scratch.wasm = .{
            .table = @ptrCast(&server.wasm_host_calls),
            .conn_index = H3_CONN_INDEX,
            .conn_id = conn.id,
            .stream_id = stream_id32,
            .protocol = .http3,
            .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
            .start_fn = wasmStartThunkH3,
            .start_ctx = @ptrCast(server),
        };
    }
    const result = server.app_router.handle(req_view, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    // Park sentinel: a filter parked on a host_call. Leave the stream suspended
    // (no frames sent, stream stays open); wasmResume delivers the response on
    // this stream once the host call completes. Checked before the send so the
    // park sentinel is never serialized.
    if (build_options.enable_wasm and result.resp.isParked()) {
        if (server.wasmHasParkForStream(H3_CONN_INDEX, conn.id, stream_id32)) return;
        // Sentinel without a live park (orphaned park): fail closed on this
        // stream and release any orphan to avoid an instance leak.
        server.wasmCancelForStream(H3_CONN_INDEX, conn.id, stream_id32);
        sendHttp3ResponseFromResponse(server, udp_fd, conn, req.stream_id, peer_addr, Server.internalErrorResponse());
        return;
    }
    const managed_handle: ?buffer_pool.BufferHandle = switch (result.resp.body) {
        .managed => |managed| managed.handle,
        else => null,
    };
    defer if (managed_handle) |handle| server.io.releaseBuffer(handle);

    sendHttp3ResponseFromResponse(server, udp_fd, conn, req.stream_id, peer_addr, result.resp);
}

fn serveStaticFileH3(
    server: *Server,
    udp_fd: std.posix.fd_t,
    conn: *quic_connection.Connection,
    stream_id: u64,
    peer_addr: net.SockAddrStorage,
    file_path: []const u8,
    content_type: []const u8,
    accept_encoding: []const u8,
) void {
    if (std.mem.indexOfScalar(u8, file_path, '%') != null) return sendNotFoundH3(server, udp_fd, conn, stream_id, peer_addr);
    if (std.mem.indexOf(u8, file_path, "..") != null) return sendNotFoundH3(server, udp_fd, conn, stream_id, peer_addr);
    if (std.mem.indexOfScalar(u8, file_path, 0) != null) return sendNotFoundH3(server, udp_fd, conn, stream_id, peer_addr);
    if (file_path.len > 0 and file_path[0] == '/') return sendNotFoundH3(server, udp_fd, conn, stream_id, peer_addr);

    const root_fd = server.static_root_fd orelse return sendNotFoundH3(server, udp_fd, conn, stream_id, peer_addr);

    const variant = Server.resolveStaticVariant(root_fd, file_path, accept_encoding) orelse return sendNotFoundH3(server, udp_fd, conn, stream_id, peer_addr);
    const file_fd = variant.fd;
    defer clock.closeFd(file_fd);

    const buf_handle = server.io.acquireBuffer() orelse return;
    var total_read: usize = 0;
    while (total_read < buf_handle.bytes.len) {
        const n = std.posix.read(file_fd, buf_handle.bytes[total_read..]) catch {
            server.io.releaseBuffer(buf_handle);
            return;
        };
        if (n == 0) break;
        total_read += n;
    }

    // Content-Type from the original path; advertise a chosen precompressed
    // sibling via Content-Encoding + Vary.
    var hdrs_buf: [3]response_mod.Header = undefined;
    var nh: usize = 0;
    hdrs_buf[nh] = .{ .name = "Content-Type", .value = content_type };
    nh += 1;
    if (variant.encoding != .identity) {
        hdrs_buf[nh] = .{ .name = "Content-Encoding", .value = variant.encoding.token() };
        nh += 1;
        hdrs_buf[nh] = .{ .name = "Vary", .value = "Accept-Encoding" };
        nh += 1;
    }
    const resp: response_mod.Response = .{
        .status = 200,
        .headers = hdrs_buf[0..nh],
        .body = .{ .managed = .{ .handle = buf_handle, .len = total_read } },
    };
    sendHttp3ResponseFromResponse(server, udp_fd, conn, stream_id, peer_addr, resp);
    server.io.releaseBuffer(buf_handle);
}

fn sendNotFoundH3(
    server: *Server,
    udp_fd: std.posix.fd_t,
    conn: *quic_connection.Connection,
    stream_id: u64,
    peer_addr: net.SockAddrStorage,
) void {
    sendHttp3ResponseFromResponse(server, udp_fd, conn, stream_id, peer_addr, Server.notFoundResponse());
}

/// Encode a router Response into h3 bytes and send it over the
/// wire. Used by the cold-path (router-dispatched) h3 flow.
/// The hot path uses `sendHttp3ResponseBytes` directly with
/// pre-encoded bytes.
///
/// Responses up to ~16 KB are encoded into a stack buffer (zero
/// allocation). Larger bodies use a pool buffer to avoid blowing
/// the stack frame while still supporting the echo-POST benchmark
/// path (which echoes bodies up to 256 KB).
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

    const SMALL_BUF_SIZE = 16384;
    const HEADER_OVERHEAD = 512;

    if (body_len + HEADER_OVERHEAD <= SMALL_BUF_SIZE) {
        var encoded_response_buf: [SMALL_BUF_SIZE]u8 = undefined;
        const resp_len = conn.encodeHttp3Response(
            &encoded_response_buf,
            resp.status,
            @ptrCast(resp.headers),
            if (body_len > 0) body_bytes else null,
        ) catch return;
        sendHttp3ResponseBytes(server, udp_fd, conn, stream_id, peer_addr, encoded_response_buf[0..resp_len]);
    } else {
        const needed = body_len + HEADER_OVERHEAD;
        const heap_buf = server.allocator.alloc(u8, needed) catch {
            var err_buf: [256]u8 = undefined;
            const err_len = conn.encodeHttp3Response(
                &err_buf,
                500,
                @ptrCast(&[0]request.Header{}),
                null,
            ) catch return;
            sendHttp3ResponseBytes(server, udp_fd, conn, stream_id, peer_addr, err_buf[0..err_len]);
            return;
        };
        defer server.allocator.free(heap_buf);
        const resp_len = conn.encodeHttp3Response(
            heap_buf,
            resp.status,
            @ptrCast(resp.headers),
            if (body_len > 0) body_bytes else null,
        ) catch return;
        sendHttp3ResponseBytes(server, udp_fd, conn, stream_id, peer_addr, heap_buf[0..resp_len]);
    }
}

/// Send already-encoded h3 response bytes over the wire for a
/// given QUIC stream. Splits into MTU-sized chunks and feeds each
/// chunk through the unified `quic.handler::buildShortPacket`
/// builder. Shared hot-path / cold-path helper.
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
    const keys = conn.crypto_ctx.application.server orelse return;

    const pending_ack = if (conn.application_space.ack_needed)
        conn.application_space.largest_received
    else
        null;

    sendStreamData(server, conn, udp_fd, &keys, stream_id, peer_addr, h3_bytes, 0, pending_ack);
}

/// Send STREAM data for a single stream. On a GSO-capable kernel a
/// multi-packet response is coalesced into one `sendmsg(UDP_SEGMENT)`
/// per batch (one syscall for up to GSO_MAX_SEGMENTS packets); otherwise
/// it falls back to one `sendto` per packet. When the congestion window
/// is full, the remaining bytes are buffered on the Connection for later
/// draining.
fn sendStreamData(
    server: *Server,
    conn: *quic_connection.Connection,
    udp_fd: std.posix.fd_t,
    keys: *const @import("../quic/crypto.zig").Keys,
    stream_id: u64,
    peer_addr: net.SockAddrStorage,
    h3_bytes: []const u8,
    initial_offset: u64,
    pending_ack: ?u64,
) void {
    const max_stream_payload = 1200;
    const seg: usize = GSO_SEGMENT_SIZE;
    var stream_offset: u64 = initial_offset;
    var remaining = h3_bytes;
    var ack_sent = false;

    // ---- Per-packet fallback (no GSO: macOS / older kernels) ----
    if (!server.quic_gso) {
        while (remaining.len > 0) {
            if (!conn.canSendPacket(GSO_SEGMENT_SIZE)) {
                if (conn.pending_send != null) return;
                const copy = conn.allocator.alloc(u8, remaining.len) catch return;
                @memcpy(copy, remaining);
                conn.pending_send = .{ .stream_id = stream_id, .data = copy, .stream_offset = stream_offset, .alloc = conn.allocator };
                return;
            }
            const chunk_len = @min(remaining.len, max_stream_payload);
            const is_last = (chunk_len == remaining.len);
            const ack_for_this_pkt = if (!ack_sent) pending_ack else null;
            var packet_buf: [2048]u8 = undefined;
            const built = quic_handler.buildShortPacket(&packet_buf, .{
                .conn = conn,
                .keys = keys,
                .ack_largest = ack_for_this_pkt,
                .stream_data = .{ .stream_id = stream_id, .offset = stream_offset, .data = remaining[0..chunk_len], .fin = is_last },
            }) catch return;
            if (!ack_sent and pending_ack != null) {
                conn.application_space.ack_needed = false;
                ack_sent = true;
            }
            _ = net.sendto(udp_fd, packet_buf[0..built.bytes_written], peer_addr) catch return;
            remaining = remaining[chunk_len..];
            stream_offset += chunk_len;
        }
        return;
    }

    // ---- GSO batched path ----
    // Build up to GSO_MAX_SEGMENTS packets contiguously, each padded to
    // exactly `seg` bytes except the response's final chunk, then emit the
    // whole batch in one sendmsg. The only short segment is the last
    // packet of the whole response, which is always the final segment of
    // its batch — satisfying the GSO "all segments equal except the last"
    // rule.
    const batch = &server.quic_gso_batch;
    while (remaining.len > 0) {
        var batch_used: usize = 0;
        var seg_count: usize = 0;
        var cw_blocked = false;
        var build_failed = false;

        while (remaining.len > 0 and seg_count < GSO_MAX_SEGMENTS) {
            if (!conn.canSendPacket(GSO_SEGMENT_SIZE)) {
                cw_blocked = true;
                break;
            }
            const chunk_len = @min(remaining.len, max_stream_payload);
            const is_last_chunk = (chunk_len == remaining.len);
            const ack_for_this_pkt = if (!ack_sent) pending_ack else null;

            const slot = batch[seg_count * seg ..][0..seg];
            const built = quic_handler.buildShortPacket(slot, .{
                .conn = conn,
                .keys = keys,
                .ack_largest = ack_for_this_pkt,
                .stream_data = .{ .stream_id = stream_id, .offset = stream_offset, .data = remaining[0..chunk_len], .fin = is_last_chunk },
                // Pad every packet to a full segment except the response's
                // final chunk (which becomes the short trailing segment).
                .pad_to = if (is_last_chunk) 0 else seg,
            }) catch {
                build_failed = true;
                break;
            };
            if (!ack_sent and pending_ack != null) {
                conn.application_space.ack_needed = false;
                ack_sent = true;
            }
            batch_used = seg_count * seg + built.bytes_written;
            seg_count += 1;
            remaining = remaining[chunk_len..];
            stream_offset += chunk_len;
            if (is_last_chunk) break;
        }

        // Flush whatever was built (these packets are already recorded as
        // sent in the loss-detection ring, so they must go on the wire).
        if (seg_count == 1) {
            _ = net.sendto(udp_fd, batch[0..batch_used], peer_addr) catch return;
        } else if (seg_count > 1) {
            _ = net.sendGso(udp_fd, batch[0..batch_used], peer_addr, GSO_SEGMENT_SIZE) catch return;
        }

        if (build_failed) return;

        if (cw_blocked) {
            // Congestion window full — buffer the remainder for drainPendingSend.
            if (remaining.len > 0 and conn.pending_send == null) {
                const copy = conn.allocator.alloc(u8, remaining.len) catch return;
                @memcpy(copy, remaining);
                conn.pending_send = .{ .stream_id = stream_id, .data = copy, .stream_offset = stream_offset, .alloc = conn.allocator };
            }
            return;
        }
    }
}

/// Drain any buffered response data on a connection after ACK
/// processing may have opened the congestion window.
pub fn drainPendingSend(
    server: *Server,
    udp_fd: std.posix.fd_t,
    conn: *quic_connection.Connection,
    peer_addr: net.SockAddrStorage,
) void {
    const ps = conn.pending_send orelse return;
    const keys = conn.crypto_ctx.application.server orelse return;

    const pending_ack = if (conn.application_space.ack_needed)
        conn.application_space.largest_received
    else
        null;

    const data = ps.data;
    const stream_id = ps.stream_id;
    const stream_offset = ps.stream_offset;
    const alloc = ps.alloc;

    conn.pending_send = null;
    sendStreamData(server, conn, udp_fd, &keys, stream_id, peer_addr, data, stream_offset, pending_ack);
    // If sendStreamData buffered a new pending_send (partial drain),
    // the old allocation can be freed — the new buffer is a fresh copy.
    alloc.free(data);
}

// ---------------------------------------------------------------------------
// Tests (E2b: HTTP/3 per-stream WASM filter park). Run with:
//   zig build test -Denable-tls=true -Denable-http3=true -Denable-wasm=true
// (needs OpenSSL 3.5+ for the QUIC TLS symbols). Skipped (SkipZigTest) when
// either flag is off, since the path is gated on both.
// ---------------------------------------------------------------------------

const testing = std.testing;
const config = @import("../config.zig");

/// Build a flat QUIC pool address for 127.0.0.1:9999 by populating a net
/// SockAddrIn and copying its bytes into the pool's flat storage exactly as the
/// datagram ingest path does. Lets netPeerFromQuic reconstruct a sendable IPv4
/// address in tests without depending on std.net (absent from the test module).
fn testLoopbackQuicAddr() quic_handler.connection_pool.SockAddrStorage {
    var sin: net.SockAddrIn = std.mem.zeroes(net.SockAddrIn);
    sin.family = @intCast(std.posix.AF.INET);
    sin.port = std.mem.nativeToBig(u16, 9999);
    sin.addr = @bitCast([4]u8{ 127, 0, 0, 1 });
    const ns: net.SockAddrStorage = .{ .ip4 = sin };
    var q: quic_handler.connection_pool.SockAddrStorage = undefined;
    @memset(std.mem.asBytes(&q), 0);
    const src = std.mem.asBytes(&ns);
    const n = @min(src.len, @sizeOf(@TypeOf(q)));
    @memcpy(std.mem.asBytes(&q)[0..n], src[0..n]);
    return q;
}

test "netPeerFromQuic: round-trips an IPv4 peer address" {
    if (!build_options.enable_http3) return error.SkipZigTest;
    const q = testLoopbackQuicAddr();
    const peer = netPeerFromQuic(&q);
    switch (peer) {
        .ip4 => |sa| {
            try testing.expectEqual(@as(u16, 9999), std.mem.bigToNative(u16, sa.port));
            try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, @as([4]u8, @bitCast(sa.addr)));
        },
        .ip6 => return error.WrongFamily,
    }
}

fn h3EnrichHandler(_: *router.HandlerContext) response_mod.Response {
    return .{ .status = 200, .headers = &.{}, .body = .{ .bytes = "enriched" } };
}

fn h3PlainHandler(_: *router.HandlerContext) response_mod.Response {
    return .{ .status = 200, .headers = &.{}, .body = .{ .bytes = "plain-ok" } };
}

/// Heap-allocated test harness for the H3 park tests. The Server struct embeds
/// the 64-slot host_call Table plus the H3 GSO batch buffer, so it must NOT live
/// on the test thread's stack (it overflows it); we initInPlace it on the heap.
/// Stands up a QUIC handler + bound UDP socket + a connected QUIC connection
/// (stream manager + h3 stack + application keys + loopback peer) so the resume
/// send path runs end-to-end (encode + sendto) without a real handshake.
const TestH3Env = struct {
    allocator: std.mem.Allocator,
    server: *Server,
    udp_fd: std.posix.fd_t,
    conn: *quic_connection.Connection,
    net_peer: net.SockAddrStorage,

    fn init(allocator: std.mem.Allocator, app_router: router.Router) !TestH3Env {
        var cfg = config.ServerConfig.default();
        cfg.max_connections = 4;
        cfg.buffer_pool = .{ .buffer_size = 16 * 1024, .buffer_count = 8 };

        const server = try allocator.create(Server);
        errdefer allocator.destroy(server);
        try server.initInPlace(allocator, cfg, app_router);
        server.wasm_mock_enabled = true;
        server.wasm_mock_reply = "ok"; // probe resumes /enrich to .allow

        server.quic = quic_handler.Handler.init(allocator, true, cfg.max_connections);
        const udp_fd = try net.bindUdp("127.0.0.1", 0);
        server.udp_fd = udp_fd;

        const dcid = quic_types.ConnectionId.init(&[_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 });
        const conn = try server.quic.?.pool.createConnection(dcid, testLoopbackQuicAddr());
        conn.initStreamManager(); // sets stream_manager + http3_stack
        conn.state = .connected;
        // Application keys so sendHttp3ResponseBytes does not early-return; the
        // exact bytes are irrelevant (we never decrypt in-test).
        conn.crypto_ctx.application.server = quic_crypto.deriveKeysFromSecret(&([_]u8{0x42} ** 32));

        return .{
            .allocator = allocator,
            .server = server,
            .udp_fd = udp_fd,
            .conn = conn,
            .net_peer = netPeerFromQuic(&(server.quic.?.pool.getPeerAddr(conn).?)),
        };
    }

    fn deinit(self: *TestH3Env) void {
        clock.closeFd(self.udp_fd);
        self.server.deinit();
        self.allocator.destroy(self.server);
    }

    fn dispatch(self: *TestH3Env, stream_id: u64, path: []const u8) void {
        const hdrs = [_]http3.Header{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = path } };
        handleHttp3Request(self.server, self.udp_fd, self.conn, .{ .stream_id = stream_id, .headers = &hdrs, .body = "" }, self.net_peer);
    }
};

fn testEnrichRouter(pool: *anyopaque, with_plain: bool) !router.Router {
    var app_router = router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
    try app_router.get("/enrich", h3EnrichHandler);
    if (with_plain) try app_router.get("/plain", h3PlainHandler);
    _ = app_router.attachWasmFilter("/enrich", pool, wasm_filter_mod.DEFAULT_FUEL);
    return app_router;
}

test "wasm h3: stream park then resume releases on its stream; sibling flows while parked" {
    if (build_options.enable_http3 and build_options.enable_wasm) {
        const dispatch_mod = @import("dispatch.zig");
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");

        var gpa = std.heap.DebugAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var pool = try wasm_filter_mod.Pool.init(allocator, FILTER, .{ .instances = 2 });
        defer pool.deinit();

        var env = try TestH3Env.init(allocator, try testEnrichRouter(&pool, true));
        defer env.deinit();
        const server = env.server;
        const conn = env.conn;

        // Stream 0 -> /enrich: the filter stages a host_call and PARKS. No frames
        // sent for it yet; the stream stays suspended.
        env.dispatch(0, "/enrich");
        try testing.expectEqual(@as(usize, 1), server.wasm_host_calls.liveCount());
        try testing.expect(server.wasmHasParkForStream(H3_CONN_INDEX, conn.id, 0));
        try testing.expectEqual(@as(usize, 1), server.wasm_mock_count);

        // Stream 4 -> /plain: a SIBLING stream completes immediately while stream
        // 0 is still parked. The connection kept multiplexing.
        env.dispatch(4, "/plain");
        try testing.expectEqual(@as(usize, 1), server.wasm_host_calls.liveCount());
        try testing.expect(!server.wasmHasParkForStream(H3_CONN_INDEX, conn.id, 4));

        // Complete the parked host call (mock): resumes stream 0 -> allow ->
        // re-dispatch the handler -> deliver "enriched" on stream 0.
        const k = server.wasm_mock_count;
        var i: usize = 0;
        while (i < k) : (i += 1) dispatch_mod.wasmComplete(server, server.wasm_mock_pending[i], "ok");
        server.wasm_mock_count = 0;

        try testing.expectEqual(@as(usize, 0), server.wasm_host_calls.liveCount()); // released
        // The freed instance is reacquirable from the pool (no leak).
        try testing.expect(pool.acquire() != null);
    } else return error.SkipZigTest;
}

test "wasm h3: peer stream reset during park releases the pinned instance (no leak)" {
    if (build_options.enable_http3 and build_options.enable_wasm) {
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");

        var gpa = std.heap.DebugAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var pool = try wasm_filter_mod.Pool.init(allocator, FILTER, .{ .instances = 1 });
        defer pool.deinit();

        var env = try TestH3Env.init(allocator, try testEnrichRouter(&pool, false));
        defer env.deinit();
        const server = env.server;
        const conn = env.conn;

        // Park stream 0. The single pool instance is now pinned.
        env.dispatch(0, "/enrich");
        try testing.expectEqual(@as(usize, 1), server.wasm_host_calls.liveCount());

        // A peer RESET_STREAM on stream 0 surfaces as a reset id; the datagram
        // path drains it via releaseResetParks, releasing the pinned instance
        // (the same code processOneDatagram runs for result.reset_streams).
        conn.recordResetStream(0);
        releaseResetParks(server, conn, conn.resetStreams());

        try testing.expectEqual(@as(usize, 0), server.wasm_host_calls.liveCount()); // released
        try testing.expect(pool.acquire() != null); // reacquirable from the 1-slot pool
    } else return error.SkipZigTest;
}

test "wasm h3: connection close during park releases the pinned instance (no leak)" {
    if (build_options.enable_http3 and build_options.enable_wasm) {
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");

        var gpa = std.heap.DebugAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var pool = try wasm_filter_mod.Pool.init(allocator, FILTER, .{ .instances = 1 });
        defer pool.deinit();

        var env = try TestH3Env.init(allocator, try testEnrichRouter(&pool, false));
        defer env.deinit();
        const server = env.server;
        const conn = env.conn;

        env.dispatch(0, "/enrich");
        try testing.expectEqual(@as(usize, 1), server.wasm_host_calls.liveCount());

        // Connection close releases every park on the connection (the call the
        // datagram path makes before pool.removeConnection on close_connection).
        server.wasmCancelForConn(H3_CONN_INDEX, conn.id);

        try testing.expectEqual(@as(usize, 0), server.wasm_host_calls.liveCount()); // released
        try testing.expect(pool.acquire() != null);
    } else return error.SkipZigTest;
}

