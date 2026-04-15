//! # HTTP/2 dispatch and response path
//!
//! Handles the lifecycle of an HTTP/2 connection after the preface
//! is accepted: ingesting frames, dispatching HEADERS/DATA events
//! through the router, queueing HEADERS+DATA response frames, and
//! emitting the control frames the stack requires (SETTINGS ACK,
//! PING ACK, WINDOW_UPDATE, GOAWAY).
//!
//! Frame pipelining:
//!
//!   1. `sendHttp2ServerPreface` runs once per connection right
//!      after the client preface is seen (plain TCP + TLS ALPN=h2).
//!      It queues a SETTINGS frame through the connection's normal
//!      write queue.
//!   2. `handleHttp2Read` loops over frame batches from the stack's
//!      ingest, stashes HEADERS-then-DATA pairs for same-batch POST
//!      body completion, and calls into `dispatchHttp2Request` or
//!      the pre-encoded fast path for each complete request.
//!   3. `queueHttp2Response` encodes HEADERS (via HPACK) + DATA
//!      frames back into the write queue. `queueFileResponseH2`
//!      serves static files by reading into a managed buffer and
//!      queueing a single DATA frame.
//!
//! The h2 preface sniff at the plain-TCP h1→h2 transition lives in
//! `server.zig`'s dispatch loop because it runs before the h1/h2
//! split; it calls `matchesHttp2Preface` here as a helper.

const std = @import("std");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const connection = @import("../runtime/connection.zig");
const request = @import("../protocol/request.zig");
const response_mod = @import("../response/response.zig");
const http2 = @import("../protocol/http2.zig");
const middleware = @import("../middleware/middleware.zig");
const router = @import("../router/router.zig");
const clock = @import("../runtime/clock.zig");
const preencoded = @import("preencoded.zig");
const write_queue = @import("write_queue.zig");

pub fn matchesHttp2Preface(candidate: []const u8) bool {
    const n = if (candidate.len < http2.Preface.len) candidate.len else http2.Preface.len;
    return std.mem.eql(u8, candidate[0..n], http2.Preface[0..n]);
}

/// Send the HTTP/2 server connection preface (SETTINGS frame)
pub fn sendHttp2ServerPreface(server: *Server, conn: *connection.Connection) !void {
    const buf = server.io.acquireBuffer() orelse return error.OutOfMemory;
    const len = http2.writeServerSettings(buf.bytes, .{
        .max_streams = server.cfg.http2.max_streams,
        .max_header_list_size = server.cfg.http2.max_header_list_size,
        .initial_window_size = server.cfg.http2.initial_window_size,
        .max_frame_size = server.cfg.http2.max_frame_size,
        .max_dynamic_table_size = server.cfg.http2.max_dynamic_table_size,
    }) catch {
        server.io.releaseBuffer(buf);
        return error.OutOfMemory;
    };
    if (!conn.enqueueWrite(buf, len)) {
        server.io.releaseBuffer(buf);
        return error.OutOfMemory;
    }
    server.io.onWriteBuffered(conn, len);
}

/// Send an HTTP/2 control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE, GOAWAY)
fn sendHttp2ControlFrame(server: *Server, conn: *connection.Connection, frame_data: []const u8) void {
    const buf = server.io.acquireBuffer() orelse return;
    if (frame_data.len > buf.bytes.len) {
        server.io.releaseBuffer(buf);
        return;
    }
    @memcpy(buf.bytes[0..frame_data.len], frame_data);
    if (!conn.enqueueWrite(buf, frame_data.len)) {
        server.io.releaseBuffer(buf);
        return;
    }
    server.io.onWriteBuffered(conn, frame_data.len);
}

pub fn handleHttp2Read(server: *Server, conn: *connection.Connection) !void {
    const buffer_handle = conn.read_buffer orelse return;
    const stack = conn.http2_stack orelse return;
    // Reserve enough write queue space for a full ingest batch:
    // 16 events × 2 frames (HEADERS+DATA) per event + control frames headroom.
    const min_write_slots: u8 = 36;
    while (conn.read_buffered_bytes > 0 and conn.writeQueueAvailable() >= min_write_slots) {
        const start = conn.read_offset;
        const end = start + conn.read_buffered_bytes;
        if (end > buffer_handle.bytes.len) break;
        const slice = buffer_handle.bytes[start..end];
        var frames: [16]http2.Frame = undefined;
        var events: [16]http2.Event = undefined;
        const ingest = stack.ingest(slice, frames[0..], events[0..]);
        // .partial means either we need more bytes from the socket OR the
        // frames buffer was full (16 slots) and more frames remain in the
        // read buffer. If we made progress, continue the loop to drain.
        // If we made no progress, we genuinely need more socket data.
        if (ingest.state == .partial and ingest.consumed_bytes == 0) return;
        if (ingest.state == .err) {
            // RFC 9113 §5.4.1: Send GOAWAY before closing on connection error
            var goaway_buf: [17]u8 = undefined;
            const goaway_len = http2.writeGoaway(&goaway_buf, stack.last_stream_id, 0x01) catch 0;
            if (goaway_len > 0) {
                sendHttp2ControlFrame(server, conn, goaway_buf[0..goaway_len]);
            }
            server.closeConnection(conn);
            return;
        }
        server.io.onReadConsumed(conn, ingest.consumed_bytes);

        // Pending headers table: h2 POST/PUT with a body sends a
        // HEADERS frame (end_stream=false) followed by one or more
        // DATA frames. We stash the headers here and match them
        // up with the next DATA(end_stream=true) for the same
        // stream_id so the router sees a complete request with
        // a non-empty body. Before this PR, the .data arm was
        // `_ = data;` and body-bearing requests were silently
        // dropped — visible on the Mixed GET+POST benchmark
        // where swerver was at 12K vs actix's 33K.
        //
        // Scope: single-ingest-batch. For small POST bodies
        // (curl-sized, benchmark-sized) the HEADERS and DATA
        // frames fit in one TCP read and one ingest call, so
        // they're both in this events array together. Large
        // POST bodies that span multiple TCP reads still fall
        // through to 501 — tracked as a follow-up alongside
        // Connection-level pending state.
        var pending_headers: [16]?http2.HeadersEvent = [_]?http2.HeadersEvent{null} ** 16;
        var pending_count: usize = 0;

        for (events[0..ingest.event_count]) |event| {
            switch (event) {
                .headers => |hdr| {
                    if (!server.isAllowedHost(hdr.request)) {
                        try queueHttp2Response(server, conn, hdr.stream_id, Server.badRequestResponse(), hdr.request.method == .HEAD);
                    } else if (hdr.end_stream) {
                        // GET/HEAD/DELETE or any no-body request —
                        // hot endpoints skip the router via the
                        // pre-encoded cache; otherwise dispatch
                        // normally.
                        const method_str = hdr.request.getMethodName();
                        // x402 gate: skip cache when payment required
                        if (!server.app_router.x402_policy.require_payment and
                            preencoded.findAndRefreshPreencodedH2(server, method_str, hdr.request.path) != null)
                        {
                            const entry = preencoded.findAndRefreshPreencodedH2(server, method_str, hdr.request.path).?;
                            preencoded.sendH2PreencodedBytes(server, conn, hdr.stream_id, entry);
                        } else if (server.cfg.static_root.len > 0 and std.mem.startsWith(u8, hdr.request.path, "/static/")) {
                            // Static file serving over h2 — same
                            // open+read path as h1 but the response
                            // goes through queueHttp2Response.
                            const file_path = hdr.request.path[8..];
                            const content_type = Server.guessContentType(file_path);
                            queueFileResponseH2(server, conn, hdr.stream_id, server.cfg.static_root, file_path, content_type) catch {
                                try queueHttp2Response(server, conn, hdr.stream_id, Server.notFoundResponse(), false);
                            };
                        } else {
                            try dispatchHttp2Request(server, conn, hdr.stream_id, hdr.request, "");
                        }
                    } else {
                        // Body-bearing request. Stash the HEADERS
                        // until a matching DATA(end_stream=true)
                        // arrives in this batch.
                        if (pending_count < pending_headers.len) {
                            pending_headers[pending_count] = hdr;
                            pending_count += 1;
                        } else {
                            // Pending table full — fall back to
                            // the legacy 501 path for this stream.
                            try queueHttp2Response(server, conn, hdr.stream_id, Server.notImplementedResponse(), hdr.request.method == .HEAD);
                        }
                    }
                },
                .data => |data_ev| {
                    // Find matching stashed HEADERS for this stream_id.
                    var matched: ?usize = null;
                    var i: usize = 0;
                    while (i < pending_count) : (i += 1) {
                        if (pending_headers[i]) |p| {
                            if (p.stream_id == data_ev.stream_id) {
                                matched = i;
                                break;
                            }
                        }
                    }
                    if (matched) |idx| {
                        const hdr_opt = pending_headers[idx];
                        pending_headers[idx] = null;
                        if (hdr_opt) |hdr| {
                            if (data_ev.end_stream) {
                                // Single-DATA-frame body complete —
                                // dispatch the request with the body slice.
                                // DataEvent.data is a slice into the
                                // connection's read buffer, valid for the
                                // synchronous handler call.
                                try dispatchHttp2Request(server, conn, hdr.stream_id, hdr.request, data_ev.data);
                            } else {
                                // Multi-DATA-frame body not supported in
                                // this fix. Return 501 instead of silently
                                // buffering across DATA events.
                                try queueHttp2Response(server, conn, hdr.stream_id, Server.notImplementedResponse(), hdr.request.method == .HEAD);
                            }
                        }
                    }
                    // Data frame with no matching pending HEADERS: drop.
                    // Either the headers were already dispatched (impossible
                    // for a well-formed client, HEADERS come before DATA) or
                    // the pending table was full. Either way nothing to do.
                },
                .settings => |settings_event| {
                    if (!settings_event.ack) {
                        // RFC 9113 §6.5.3: MUST send SETTINGS ACK
                        var ack_buf: [9]u8 = undefined;
                        const ack_len = http2.writeSettingsAck(&ack_buf) catch 0;
                        if (ack_len > 0) {
                            sendHttp2ControlFrame(server, conn, ack_buf[0..ack_len]);
                        }
                    }
                },
                .ping => |ping_event| {
                    // RFC 9113 §6.7: MUST respond with PING ACK
                    var ping_buf: [17]u8 = undefined;
                    const ping_len = http2.writePingAck(&ping_buf, ping_event.opaque_data) catch 0;
                    if (ping_len > 0) {
                        sendHttp2ControlFrame(server, conn, ping_buf[0..ping_len]);
                    }
                },
                .window_update_needed => |wu| {
                    // RFC 9113 §6.9: Send WINDOW_UPDATE
                    var wu_buf: [13]u8 = undefined;
                    const wu_len = http2.writeWindowUpdate(&wu_buf, wu.stream_id, wu.increment) catch 0;
                    if (wu_len > 0) {
                        sendHttp2ControlFrame(server, conn, wu_buf[0..wu_len]);
                    }
                },
                .err => {},
            }
        }
        if (conn.read_buffered_bytes == 0) break;
    }
}

/// Serve a static file over HTTP/2. Opens the file, reads into a
/// managed buffer, and queues the response via queueHttp2Response.
/// Less efficient than the h1 sendfile path but correct for h2
/// multiplexed streams.
fn queueFileResponseH2(
    server: *Server,
    conn: *connection.Connection,
    stream_id: u32,
    static_root: []const u8,
    file_path: []const u8,
    content_type: []const u8,
) !void {
    _ = static_root;
    // Path validation (same as h1)
    if (std.mem.indexOfScalar(u8, file_path, '%') != null) return error.NotFound;
    if (std.mem.indexOf(u8, file_path, "..") != null) return error.NotFound;
    if (std.mem.indexOfScalar(u8, file_path, 0) != null) return error.NotFound;
    if (file_path.len > 0 and file_path[0] == '/') return error.NotFound;

    const root_fd = server.static_root_fd orelse return error.NotFound;

    var path_buf: [4096]u8 = undefined;
    if (file_path.len >= path_buf.len) return error.NotFound;
    @memcpy(path_buf[0..file_path.len], file_path);
    path_buf[file_path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);

    var o_flags: std.posix.O = .{ .ACCMODE = .RDONLY };
    if (@hasField(std.posix.O, "NOFOLLOW")) o_flags.NOFOLLOW = true;
    if (@hasField(std.posix.O, "CLOEXEC")) o_flags.CLOEXEC = true;
    const file_fd = std.posix.openatZ(root_fd, path_z, o_flags, 0) catch return error.NotFound;
    defer clock.closeFd(file_fd);

    // Read file into a managed buffer
    const buf_handle = server.io.acquireBuffer() orelse return error.NotFound;
    const n = std.posix.read(file_fd, buf_handle.bytes) catch {
        server.io.releaseBuffer(buf_handle);
        return error.NotFound;
    };

    const resp: response_mod.Response = .{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = content_type },
        },
        .body = .{ .managed = .{ .handle = buf_handle, .len = n } },
    };
    try queueHttp2Response(server, conn, stream_id, resp, false);
}

pub fn queueHttp2Response(server: *Server, conn: *connection.Connection, stream_id: u32, resp: response_mod.Response, is_head: bool) !void {
    const body_len = resp.bodyLen();
    const body_bytes = resp.bodyBytes();
    const managed_body = switch (resp.body) {
        .managed => |managed| managed,
        else => null,
    };
    defer if (managed_body) |managed| server.io.releaseBuffer(managed.handle);
    const header_buf = server.io.acquireBuffer() orelse {
        server.closeConnection(conn);
        return;
    };
    // Build headers array with Alt-Svc if enabled
    var headers_with_alt_svc: [65]response_mod.Header = undefined;
    var header_count = resp.headers.len;
    for (resp.headers, 0..) |h, i| {
        headers_with_alt_svc[i] = h;
    }
    // Add Alt-Svc header to advertise HTTP/3
    if (server.alt_svc_len > 0 and header_count < headers_with_alt_svc.len) {
        headers_with_alt_svc[header_count] = .{
            .name = "alt-svc",
            .value = server.alt_svc_value[0..server.alt_svc_len],
        };
        header_count += 1;
    }
    const header_block_len = http2.encodeResponseHeaders(header_buf.bytes[9..], resp.status, headers_with_alt_svc[0..header_count], body_len) catch {
        server.io.releaseBuffer(header_buf);
        server.closeConnection(conn);
        return;
    };
    const max_frame_size: usize = if (conn.http2_stack) |stack| @intCast(stack.max_frame_size) else 16384;
    if (header_block_len > max_frame_size) {
        server.io.releaseBuffer(header_buf);
        server.closeConnection(conn);
        return;
    }
    // RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body
    const headers_flags: u8 = if (body_len == 0 or is_head) 0x5 else 0x4;
    // RFC 9113 §8.1: Response MUST be on the stream that carried the request
    const resp_stream_id: u32 = stream_id;
    http2.writeFrameHeader(header_buf.bytes, .headers, headers_flags, resp_stream_id, header_block_len) catch {
        server.io.releaseBuffer(header_buf);
        server.closeConnection(conn);
        return;
    };
    const header_frame_len = 9 + header_block_len;
    if (!conn.enqueueWrite(header_buf, header_frame_len)) {
        server.io.releaseBuffer(header_buf);
        server.closeConnection(conn);
        return;
    }
    server.io.onWriteBuffered(conn, header_frame_len);
    server.io.setTimeoutPhase(conn, .write);

    if (body_len == 0 or is_head) {
        // END_STREAM was set on HEADERS frame — stream is fully closed
        if (conn.http2_stack) |stack| stack.closeStream(resp_stream_id);
        return;
    }
    var remaining = body_bytes;
    while (remaining.len > 0) {
        const data_buf = server.io.acquireBuffer() orelse {
            // Cannot complete response - close connection
            server.closeConnection(conn);
            return;
        };
        const max_payload = @min(data_buf.bytes.len - 9, max_frame_size);
        const chunk_len = if (remaining.len < max_payload) remaining.len else max_payload;
        @memcpy(data_buf.bytes[9 .. 9 + chunk_len], remaining[0..chunk_len]);
        const flags: u8 = if (remaining.len == chunk_len) 0x1 else 0x0;
        http2.writeFrameHeader(data_buf.bytes, .data, flags, resp_stream_id, chunk_len) catch {
            server.io.releaseBuffer(data_buf);
            server.closeConnection(conn);
            return;
        };
        const frame_len = 9 + chunk_len;
        if (!conn.enqueueWrite(data_buf, frame_len)) {
            server.io.releaseBuffer(data_buf);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, frame_len);
        remaining = remaining[chunk_len..];
    }
    // END_STREAM was set on last DATA frame — stream is fully closed
    if (conn.http2_stack) |stack| stack.closeStream(resp_stream_id);
}

fn dispatchHttp2Request(
    server: *Server,
    conn: *connection.Connection,
    stream_id: u32,
    hdr_request: request.RequestView,
    body: []const u8,
) !void {
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
    // Inject the body into the request view. HEADERS events from
    // the h2 stack carry request.body = "" because the body arrives
    // in separate DATA frames; we patch it here at dispatch time.
    var request_with_body = hdr_request;
    request_with_body.body = body;

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
    const result = server.app_router.handle(request_with_body, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    if (result.pause_reads_ms) |pause_ms| {
        conn.setRateLimitPause(server.io.nowMs(), pause_ms);
    }
    try queueHttp2Response(server, conn, stream_id, result.resp, hdr_request.method == .HEAD);
}
