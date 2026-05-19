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

/// Send the HTTP/2 server connection preface (SETTINGS frame +
/// connection-level WINDOW_UPDATE). SETTINGS_INITIAL_WINDOW_SIZE
/// only governs per-stream windows (RFC 9113 §6.5.2); the
/// connection-level window starts at 65535 and must be raised
/// via WINDOW_UPDATE (RFC 9113 §6.9.2).
pub fn sendHttp2ServerPreface(server: *Server, conn: *connection.Connection) !void {
    const buf = server.io.acquireBuffer() orelse return error.OutOfMemory;
    var len = http2.writeServerSettings(buf.bytes, .{
        .max_streams = server.cfg.http2.max_streams,
        .max_header_list_size = server.cfg.http2.max_header_list_size,
        .initial_window_size = server.cfg.http2.initial_window_size,
        .max_frame_size = server.cfg.http2.max_frame_size,
        .max_dynamic_table_size = server.cfg.http2.max_dynamic_table_size,
    }) catch {
        server.io.releaseBuffer(buf);
        return error.OutOfMemory;
    };
    const conn_window = server.cfg.http2.initial_window_size;
    if (conn_window > 65535) {
        const increment = conn_window - 65535;
        const wu_len = http2.writeWindowUpdate(buf.bytes[len..], 0, increment) catch 0;
        len += wu_len;
    }
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
        // Scope: single-ingest-batch for small bodies, persistent
        // conn.h2_pending slots for bodies spanning TCP reads.
        var pending_headers: [16]?http2.HeadersEvent = [_]?http2.HeadersEvent{null} ** 16;
        var pending_count: usize = 0;
        var ctrl_buf: [256]u8 = undefined;
        var ctrl_len: usize = 0;
        const h2_pending = conn.h2_pending orelse return;

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
                        const h2_cached = if (!server.app_router.has_any_paid_routes)
                            preencoded.findAndRefreshPreencodedH2(server, method_str, hdr.request.path)
                        else
                            null;
                        if (h2_cached) |entry| {
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
                        // Body-bearing request. Stash in batch-local
                        // array AND persist to connection for cross-
                        // TCP-read delivery.
                        if (pending_count < pending_headers.len) {
                            pending_headers[pending_count] = hdr;
                            pending_count += 1;
                        }
                        // Persist to connection-level slots so DATA
                        // arriving in a later TCP read can find them.
                        var stashed = false;
                        for (h2_pending) |*slot| {
                            if (!slot.active) {
                                stashed = slot.stash(hdr.stream_id, hdr.request);
                                break;
                            }
                        }
                        if (!stashed) {
                            // All persistent slots full — RST_STREAM so the
                            // client retries on a new stream rather than
                            // hanging forever waiting for a response.
                            var rst_buf: [13]u8 = undefined;
                            const rst_len = http2.writeRstStream(&rst_buf, hdr.stream_id, 0x7) catch 0; // REFUSED_STREAM
                            if (rst_len > 0 and ctrl_len + rst_len <= ctrl_buf.len) {
                                @memcpy(ctrl_buf[ctrl_len .. ctrl_len + rst_len], rst_buf[0..rst_len]);
                                ctrl_len += rst_len;
                            }
                            if (conn.http2_stack) |s| s.closeStream(hdr.stream_id);
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
                                try dispatchHttp2Request(server, conn, hdr.stream_id, hdr.request, data_ev.data);
                                // Clear persistent slot too
                                for (h2_pending) |*slot| {
                                    if (slot.active and slot.stream_id == data_ev.stream_id) {
                                        slot.clear();
                                        break;
                                    }
                                }
                            } else {
                                // Multi-DATA: accumulate in persistent slot
                                accumulateH2Body(server, conn, data_ev);
                            }
                        }
                    } else {
                        // No batch-local match — check persistent slots
                        // for headers that arrived in a previous TCP read.
                        var found_persistent = false;
                        for (h2_pending) |*slot| {
                            if (slot.active and slot.stream_id == data_ev.stream_id) {
                                found_persistent = true;
                                if (data_ev.end_stream) {
                                    // Collect full body: slot body + this DATA frame
                                    const body = if (slot.body_handle) |bh|
                                        bh.bytes[0..slot.body_len]
                                    else
                                        "";
                                    // If slot has accumulated body, combine with final chunk
                                    if (body.len > 0 and data_ev.data.len > 0) {
                                        // Append final chunk to accumulated buffer
                                        if (slot.body_len + data_ev.data.len <= slot.body_handle.?.bytes.len) {
                                            @memcpy(slot.body_handle.?.bytes[slot.body_len .. slot.body_len + data_ev.data.len], data_ev.data);
                                            slot.body_len += data_ev.data.len;
                                        }
                                        const full_body = slot.body_handle.?.bytes[0..slot.body_len];
                                        try dispatchHttp2Request(server, conn, slot.stream_id, slot.toRequestView(full_body), full_body);
                                    } else {
                                        // Only this frame's data (or only accumulated)
                                        const final_body = if (data_ev.data.len > 0) data_ev.data else body;
                                        try dispatchHttp2Request(server, conn, slot.stream_id, slot.toRequestView(final_body), final_body);
                                    }
                                    if (slot.body_handle) |bh| server.io.releaseBuffer(bh);
                                    slot.clear();
                                } else {
                                    accumulateH2Body(server, conn, data_ev);
                                }
                                break;
                            }
                        }
                        if (!found_persistent) {
                            // Orphaned DATA frame — stream will time out on the client side.
                            // Nothing we can do without headers.
                        }
                    }
                },
                .settings => |settings_event| {
                    if (!settings_event.ack) {
                        const n = http2.writeSettingsAck(ctrl_buf[ctrl_len..]) catch 0;
                        ctrl_len += n;
                    }
                },
                .ping => |ping_event| {
                    const n = http2.writePingAck(ctrl_buf[ctrl_len..], ping_event.opaque_data) catch 0;
                    ctrl_len += n;
                },
                .window_update_needed => |wu| {
                    const n = http2.writeWindowUpdate(ctrl_buf[ctrl_len..], wu.stream_id, wu.increment) catch 0;
                    ctrl_len += n;
                },
                .err => {},
            }
        }
        if (ctrl_len > 0) {
            sendHttp2ControlFrame(server, conn, ctrl_buf[0..ctrl_len]);
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

    // Read file into a managed buffer (loop to handle short reads)
    const buf_handle = server.io.acquireBuffer() orelse return error.NotFound;
    var total_read: usize = 0;
    while (total_read < buf_handle.bytes.len) {
        const n = std.posix.read(file_fd, buf_handle.bytes[total_read..]) catch {
            server.io.releaseBuffer(buf_handle);
            return error.NotFound;
        };
        if (n == 0) break;
        total_read += n;
    }
    const n = total_read;

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
    const buf = server.io.acquireBuffer() orelse {
        server.closeConnection(conn);
        return;
    };
    const max_frame_size: usize = if (conn.http2_stack) |stack| @intCast(stack.max_frame_size) else 16384;
    const has_body = body_len > 0 and !is_head;

    // Build HPACK headers directly into the buffer after the 9-byte
    // frame header slot. Only copy the header array when Alt-Svc
    // needs to be appended; otherwise pass resp.headers straight through.
    const hpack_start: usize = 9;
    const date_str = server.getCachedDate();
    const header_block_len = blk: {
        if (server.alt_svc_len > 0) {
            var hdrs_with_alt: [65]response_mod.Header = undefined;
            const n = @min(resp.headers.len, hdrs_with_alt.len - 1);
            for (resp.headers[0..n], 0..) |h, i| hdrs_with_alt[i] = h;
            hdrs_with_alt[n] = .{ .name = "alt-svc", .value = server.alt_svc_value[0..server.alt_svc_len] };
            break :blk http2.encodeResponseHeaders(buf.bytes[hpack_start..], resp.status, hdrs_with_alt[0 .. n + 1], body_len, date_str) catch {
                server.io.releaseBuffer(buf);
                server.closeConnection(conn);
                return;
            };
        } else {
            break :blk http2.encodeResponseHeaders(buf.bytes[hpack_start..], resp.status, resp.headers, body_len, date_str) catch {
                server.io.releaseBuffer(buf);
                server.closeConnection(conn);
                return;
            };
        }
    };
    if (header_block_len > max_frame_size) {
        server.io.releaseBuffer(buf);
        server.closeConnection(conn);
        return;
    }
    const headers_flags: u8 = if (!has_body) 0x5 else 0x4; // END_HEADERS + maybe END_STREAM
    http2.writeFrameHeader(buf.bytes, .headers, headers_flags, stream_id, header_block_len) catch {
        server.io.releaseBuffer(buf);
        server.closeConnection(conn);
        return;
    };
    var total_len: usize = 9 + header_block_len;

    if (!has_body) {
        if (!conn.enqueueWrite(buf, total_len)) {
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, total_len);
        server.io.setTimeoutPhase(conn, .write);
        if (conn.http2_stack) |stack| stack.closeStream(stream_id);
        return;
    }

    // Small body: pack HEADERS + DATA into the same buffer. This
    // halves buffer acquisitions and write-queue slots for the
    // overwhelmingly common case (bodies < max_frame_size).
    if (body_len <= max_frame_size and total_len + 9 + body_len <= buf.bytes.len) {
        const data_offset = total_len;
        http2.writeFrameHeader(buf.bytes[data_offset..], .data, 0x1, stream_id, body_len) catch {
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        };
        @memcpy(buf.bytes[data_offset + 9 .. data_offset + 9 + body_len], body_bytes);
        total_len += 9 + body_len;

        if (!conn.enqueueWrite(buf, total_len)) {
            server.io.releaseBuffer(buf);
            server.closeConnection(conn);
            return;
        }
        server.io.onWriteBuffered(conn, total_len);
        server.io.setTimeoutPhase(conn, .write);
        if (conn.http2_stack) |stack| stack.closeStream(stream_id);
        return;
    }

    // Large body: enqueue HEADERS first, then chunk DATA frames into
    // separate buffers (each up to max_frame_size).
    if (!conn.enqueueWrite(buf, total_len)) {
        server.io.releaseBuffer(buf);
        server.closeConnection(conn);
        return;
    }
    server.io.onWriteBuffered(conn, total_len);
    server.io.setTimeoutPhase(conn, .write);

    var remaining = body_bytes;
    while (remaining.len > 0) {
        const data_buf = server.io.acquireBuffer() orelse {
            server.closeConnection(conn);
            return;
        };
        const max_payload = @min(data_buf.bytes.len - 9, max_frame_size);
        const chunk_len = @min(remaining.len, max_payload);
        @memcpy(data_buf.bytes[9 .. 9 + chunk_len], remaining[0..chunk_len]);
        const flags: u8 = if (remaining.len == chunk_len) 0x1 else 0x0;
        http2.writeFrameHeader(data_buf.bytes, .data, flags, stream_id, chunk_len) catch {
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
    if (conn.http2_stack) |stack| stack.closeStream(stream_id);
}

fn accumulateH2Body(server: *Server, conn: *connection.Connection, data_ev: http2.DataEvent) void {
    const pending = conn.h2_pending orelse return;
    for (pending) |*slot| {
        if (slot.active and slot.stream_id == data_ev.stream_id) {
            if (slot.body_handle == null) {
                slot.body_handle = server.io.acquireBuffer() orelse return;
                slot.body_len = 0;
            }
            const buf = slot.body_handle.?.bytes;
            const avail = buf.len - slot.body_len;
            const to_copy = @min(data_ev.data.len, avail);
            @memcpy(buf[slot.body_len .. slot.body_len + to_copy], data_ev.data[0..to_copy]);
            slot.body_len += to_copy;
            return;
        }
    }
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
    // the h2 stack carry request.body = .{ .slice = "" } because the body arrives
    // in separate DATA frames; we patch it here at dispatch time.
    var request_with_body = hdr_request;
    request_with_body.body = .{ .slice = body };

    var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
    var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
    const needs_eager_arena = (hdr_request.method != .GET and hdr_request.method != .HEAD and hdr_request.method != .DELETE);
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
    const result = server.app_router.handle(request_with_body, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    if (result.pause_reads_ms) |pause_ms| {
        conn.setRateLimitPause(server.now_ms, pause_ms);
    }
    try queueHttp2Response(server, conn, stream_id, result.resp, hdr_request.method == .HEAD);
}
