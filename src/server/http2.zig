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
const metrics_mw = @import("../middleware/metrics_mw.zig");
const router = @import("../router/router.zig");
const clock = @import("../runtime/clock.zig");
const buffer_pool = @import("../runtime/buffer_pool.zig");
const write_queue = @import("write_queue.zig");
const build_options = @import("build_options");
const proxy_mod = @import("../proxy/proxy.zig");
const wasm_filter_mod = if (build_options.enable_wasm) @import("../wasm/filter.zig") else struct {};

// The WASM host-call (park) deadline for an H2 stream is configurable per-server
// via `Server.wasm_host_call_deadline_ms` (default 30s), mirroring the H1 path.
// A parked stream past this wall-clock deadline is failed closed by the
// housekeeping tick.

/// Transport start hook (router/proxy WasmBinding.start_fn) for H2 parks. Routes
/// a freshly parked filter's host call to the Server's transport. `ctx` is the
/// Server. Mirrors dispatch.wasmStartThunk; kept local so http2.zig owns its
/// binding wiring without reaching into dispatch.zig privates.
fn wasmStartThunkH2(ctx: *anyopaque, token: u32, req_bytes: []const u8) void {
    const server: *Server = @ptrCast(@alignCast(ctx));
    server.wasmStartHostCall(token, req_bytes);
}

pub fn matchesHttp2Preface(candidate: []const u8) bool {
    if (candidate.len == 0) return false;
    const n = @min(candidate.len, http2.Preface.len);
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

/// Send an HTTP/2 control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE, GOAWAY).
/// Tries to append to the last write-queue entry to avoid acquiring a new
/// 64KB pool buffer for ~100 bytes of control data.
fn sendHttp2ControlFrame(server: *Server, conn: *connection.Connection, frame_data: []const u8) void {
    if (conn.peekLastWrite()) |last| {
        if (last.len + frame_data.len <= last.handle.bytes.len) {
            @memcpy(last.handle.bytes[last.len..][0..frame_data.len], frame_data);
            last.len += frame_data.len;
            server.io.onWriteBuffered(conn, frame_data.len);
            return;
        }
    }
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
    const min_write_slots: u8 = 8;
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
            // RFC 9113 §5.4.1: Send GOAWAY before closing on connection error,
            // carrying the actual error code (e.g. ENHANCE_YOUR_CALM for the
            // rapid-reset mitigation) so the peer learns why. Map internal
            // sentinel codes that aren't valid on the wire to PROTOCOL_ERROR.
            const wire_code: u32 = switch (ingest.error_code) {
                .header_list_too_large, .invalid_preface => 0x01,
                else => @intFromEnum(ingest.error_code),
            };
            var goaway_buf: [17]u8 = undefined;
            const goaway_len = http2.writeGoaway(&goaway_buf, stack.last_stream_id, wire_code) catch 0;
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
                        // GET/HEAD/DELETE or any no-body request.
                        if (server.cfg.static_root.len > 0 and std.mem.startsWith(u8, hdr.request.path, "/static/")) {
                            // Static file serving over h2 — same
                            // open+read path as h1 but the response
                            // goes through queueHttp2Response.
                            const file_path = hdr.request.path[8..];
                            const content_type = Server.guessContentType(file_path);
                            const accept_encoding = hdr.request.getHeader("accept-encoding") orelse "";
                            if (server.staticCacheGetOrLoad(file_path, content_type, accept_encoding)) |entry| {
                                var hdrs: [3]response_mod.Header = undefined;
                                const is_head = hdr.request.method == .HEAD;
                                try queueHttp2Response(server, conn, hdr.stream_id, Server.staticCacheResponse(entry, &hdrs), is_head);
                            } else {
                                queueFileResponseH2(server, conn, hdr.stream_id, server.cfg.static_root, file_path, content_type, accept_encoding) catch {
                                    try queueHttp2Response(server, conn, hdr.stream_id, Server.notFoundResponse(), false);
                                };
                            }
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
                                    if (slot.body_handle) |bh| {
                                        if (slot.body_is_body_pool) server.io.releaseBodyBuffer(bh) else server.io.releaseBuffer(bh);
                                    }
                                    slot.clear();
                                } else {
                                    accumulateH2Body(server, conn, data_ev);
                                }
                                break;
                            }
                        }
                        if (!found_persistent) {
                            // Orphaned DATA frame — stream will time out on the client side.
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
                .window_opened => {
                    drainPendingH2Streams(server, conn);
                },
                .err => |err_event| {
                    if (err_event.stream_id != 0) {
                        sendRstStream(server, conn, err_event.stream_id, @intFromEnum(err_event.code));
                        // Server-initiated stream RST: release any WASM filter
                        // parked on it (E2a), same as a peer RST_STREAM, so a
                        // later completion does not queue frames on a reset
                        // stream and the pinned instance returns to its pool.
                        if (build_options.enable_wasm) {
                            server.wasmCancelForStream(conn.index, conn.id, err_event.stream_id);
                        }
                    }
                },
                .stream_reset => |rst_event| {
                    // Peer RST_STREAM: release any WASM filter parked on this
                    // stream (E2a) so the pinned instance returns to its pool.
                    // No-op (generation-checked) when nothing is parked. Also
                    // drop any half-built pending request body for the stream.
                    if (build_options.enable_wasm) {
                        server.wasmCancelForStream(conn.index, conn.id, rst_event.stream_id);
                    }
                    for (h2_pending) |*slot| {
                        if (slot.active and slot.stream_id == rst_event.stream_id) {
                            if (slot.body_handle) |bh| {
                                if (slot.body_is_body_pool) server.io.releaseBodyBuffer(bh) else server.io.releaseBuffer(bh);
                            }
                            slot.clear();
                            break;
                        }
                    }
                },
            }
        }
        if (ctrl_len > 0) {
            sendHttp2ControlFrame(server, conn, ctrl_buf[0..ctrl_len]);
        }
        if (conn.read_buffered_bytes == 0) break;
    }
}

/// Lazy-streaming static file serving for HTTP/2.
/// Sends HEADERS + first DATA chunk immediately. If the file is larger
/// than one frame, the fd is kept open in a PendingH2File slot and
/// subsequent chunks are pumped by drainPendingH2Streams from the write handler.
fn queueFileResponseH2(
    server: *Server,
    conn: *connection.Connection,
    stream_id: u32,
    static_root: []const u8,
    file_path: []const u8,
    content_type: []const u8,
    accept_encoding: []const u8,
) !void {
    _ = static_root;
    if (std.mem.indexOfScalar(u8, file_path, '%') != null) return error.NotFound;
    if (std.mem.indexOf(u8, file_path, "..") != null) return error.NotFound;
    if (std.mem.indexOfScalar(u8, file_path, 0) != null) return error.NotFound;
    if (file_path.len > 0 and file_path[0] == '/') return error.NotFound;

    const root_fd = server.static_root_fd orelse return error.NotFound;

    const variant = Server.resolveStaticVariant(root_fd, file_path, accept_encoding) orelse return error.NotFound;
    const file_fd = variant.fd;

    const end_pos = std.c.lseek(file_fd, 0, std.posix.SEEK.END);
    if (end_pos < 0) {
        clock.closeFd(file_fd);
        return error.NotFound;
    }
    _ = std.c.lseek(file_fd, 0, std.posix.SEEK.SET);
    const file_size: u64 = @intCast(end_pos);

    const buf = server.io.acquireBuffer() orelse {
        clock.closeFd(file_fd);
        sendRstStream(server, conn, stream_id, 0x7);
        return;
    };
    const max_frame_size: usize = if (conn.http2_stack) |stack| @intCast(stack.peer_max_frame_size) else 16384;

    // Encode HEADERS frame
    const hpack_start: usize = 9;
    const date_str = server.getCachedDate();
    // Content-Type from the original path; advertise a chosen precompressed
    // sibling via Content-Encoding + Vary (Content-Length is `file_size`).
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
    const header_block_len = http2.encodeResponseHeaders(buf.bytes[hpack_start..], 200, hdrs_buf[0..nh], file_size, date_str) catch {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        sendRstStream(server, conn, stream_id, 0x2);
        return;
    };
    const headers_flags: u8 = if (file_size == 0) 0x5 else 0x4; // END_HEADERS + maybe END_STREAM
    http2.writeFrameHeader(buf.bytes, .headers, headers_flags, stream_id, header_block_len) catch {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        return;
    };
    var total_len: usize = 9 + header_block_len;

    if (file_size == 0) {
        clock.closeFd(file_fd);
        if (!conn.enqueueWrite(buf, total_len)) {
            server.io.releaseBuffer(buf);
            return;
        }
        server.io.onWriteBuffered(conn, total_len);
        server.io.setTimeoutPhase(conn, .write);
        if (conn.http2_stack) |stack| stack.closeStream(stream_id);
        return;
    }

    // Pack as many DATA frames as fit into the buffer after HEADERS.
    // Each frame carries its own 9-byte header + up to max_frame_size
    // payload, so a 64KB buffer holds ~3-4 frames at the default 16KB
    // max_frame_size — cutting buffer-pool pressure proportionally.
    var file_offset: u64 = 0;
    var buf_pos = total_len;
    var total_data_sent: usize = 0;
    var read_error = false;

    const stack_ref = conn.http2_stack orelse {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        return;
    };

    while (file_offset < file_size) {
        const space_left = buf.bytes.len - buf_pos;
        if (space_left <= 9) break;
        const payload_space = space_left - 9;
        const payload_max = @min(payload_space, max_frame_size);
        const file_want: usize = @intCast(@min(file_size - file_offset, payload_max));
        const allowed = stack_ref.canSend(stream_id, file_want);
        if (allowed == 0) break;

        const payload_start = buf_pos + 9;
        var chunk_read: usize = 0;
        while (chunk_read < allowed) {
            const result = std.c.pread(file_fd, buf.bytes[payload_start + chunk_read ..].ptr, allowed - chunk_read, @intCast(file_offset + chunk_read));
            if (result < 0) {
                switch (std.posix.errno(result)) {
                    .INTR => continue,
                    else => {
                        read_error = true;
                        break;
                    },
                }
            }
            const n: usize = @intCast(result);
            if (n == 0) break;
            chunk_read += n;
        }
        if (read_error or chunk_read == 0) break;

        file_offset += chunk_read;
        total_data_sent += chunk_read;
        const is_last = file_offset >= file_size;
        const data_flags: u8 = if (is_last) 0x1 else 0x0;
        http2.writeFrameHeader(buf.bytes[buf_pos..], .data, data_flags, stream_id, chunk_read) catch break;
        buf_pos += 9 + chunk_read;
        stack_ref.consumeSendWindow(stream_id, chunk_read);
        if (is_last) break;
    }
    total_len = buf_pos;

    if (read_error and total_data_sent == 0) {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        sendRstStream(server, conn, stream_id, 0x2);
        return;
    }

    if (!conn.enqueueWrite(buf, total_len)) {
        server.io.releaseBuffer(buf);
        clock.closeFd(file_fd);
        return;
    }
    server.io.onWriteBuffered(conn, total_len);
    server.io.setTimeoutPhase(conn, .write);

    if (file_offset >= file_size) {
        clock.closeFd(file_fd);
        if (conn.http2_stack) |stack| stack.closeStream(stream_id);
        return;
    }

    // File too large for one buffer — stash fd for lazy draining
    const files = conn.h2_pending_files orelse blk: {
        const alloc = server.allocator.create([connection.MAX_PENDING_H2_FILES]connection.PendingH2File) catch {
            clock.closeFd(file_fd);
            sendRstStream(server, conn, stream_id, 0x7);
            return;
        };
        alloc.* = [_]connection.PendingH2File{.{}} ** connection.MAX_PENDING_H2_FILES;
        conn.h2_pending_files = alloc;
        break :blk alloc;
    };

    for (files) |*slot| {
        if (!slot.active) {
            slot.* = .{
                .active = true,
                .stream_id = stream_id,
                .file_fd = file_fd,
                .offset = file_offset,
                .remaining = file_size - file_offset,
                .headers_sent = true,
            };
            const ct_len = @min(content_type.len, slot.content_type.len);
            @memcpy(slot.content_type[0..ct_len], content_type[0..ct_len]);
            slot.content_type_len = @intCast(ct_len);
            return;
        }
    }
    // No free slot — RST this stream
    clock.closeFd(file_fd);
    sendRstStream(server, conn, stream_id, 0x7);
}

/// Pump pending H2 file responses: for each active slot with write-queue
/// space, pread the next chunk, frame as DATA, and enqueue. Called from
/// the write handler after buffers drain.
fn drainPendingH2Files(server: *Server, conn: *connection.Connection) void {
    const files = conn.h2_pending_files orelse return;
    const stack = conn.http2_stack orelse return;
    const max_frame_size: usize = @intCast(stack.peer_max_frame_size);
    const buf_size = server.io.cfg.buffer_pool.buffer_size;

    for (files) |*slot| {
        if (!slot.active) continue;
        if (conn.writeQueueAvailable() < 2) return;

        const data_buf = server.io.acquireBuffer() orelse return;
        var buf_pos: usize = 0;
        var total_sent: usize = 0;
        var read_error = false;

        while (slot.remaining > 0) {
            const space_left = buf_size - buf_pos;
            if (space_left <= 9) break;
            const payload_max = @min(space_left - 9, max_frame_size);
            const file_want: usize = @intCast(@min(slot.remaining, @as(u64, payload_max)));
            const allowed = stack.canSend(slot.stream_id, file_want);
            if (allowed == 0) break;

            const payload_start = buf_pos + 9;
            var chunk_read: usize = 0;
            while (chunk_read < allowed) {
                const result = std.c.pread(slot.file_fd, data_buf.bytes[payload_start + chunk_read ..].ptr, allowed - chunk_read, @intCast(slot.offset + chunk_read));
                if (result < 0) {
                    switch (std.posix.errno(result)) {
                        .INTR => continue,
                        else => {
                            read_error = true;
                            break;
                        },
                    }
                }
                const n: usize = @intCast(result);
                if (n == 0) break;
                chunk_read += n;
            }
            if (read_error or chunk_read == 0) break;

            slot.offset += chunk_read;
            slot.remaining -= chunk_read;
            total_sent += chunk_read;
            const is_last = slot.remaining == 0;
            const flags: u8 = if (is_last) 0x1 else 0x0;
            http2.writeFrameHeader(data_buf.bytes[buf_pos..], .data, flags, slot.stream_id, chunk_read) catch {
                read_error = true;
                break;
            };
            buf_pos += 9 + chunk_read;
            stack.consumeSendWindow(slot.stream_id, chunk_read);
            if (is_last) break;
        }

        if (total_sent == 0) {
            server.io.releaseBuffer(data_buf);
            if (read_error) {
                slot.cleanup();
                sendRstStream(server, conn, slot.stream_id, 0x2);
            }
            continue;
        }

        if (!conn.enqueueWrite(data_buf, buf_pos)) {
            server.io.releaseBuffer(data_buf);
            slot.cleanup();
            sendRstStream(server, conn, slot.stream_id, 0x7);
            continue;
        }
        server.io.onWriteBuffered(conn, buf_pos);

        if (slot.remaining == 0) {
            slot.cleanup();
            stack.closeStream(slot.stream_id);
        }
    }
}

fn drainPendingH2Responses(server: *Server, conn: *connection.Connection) void {
    const resps = conn.h2_pending_responses orelse return;
    const stack = conn.http2_stack orelse return;
    const max_frame_size: usize = @intCast(stack.peer_max_frame_size);
    const buf_size = server.io.cfg.buffer_pool.buffer_size;

    for (resps) |*slot| {
        if (!slot.active) continue;
        if (conn.writeQueueAvailable() < 2) return;

        const data_buf = server.io.acquireBuffer() orelse return;
        var buf_pos: usize = 0;
        var total_sent: usize = 0;

        while (slot.offset < slot.len) {
            const space_left = buf_size - buf_pos;
            if (space_left <= 9) break;
            const remaining = slot.len - slot.offset;
            const payload_max = @min(space_left - 9, max_frame_size);
            const want = @min(remaining, payload_max);
            const allowed = stack.canSend(slot.stream_id, want);
            if (allowed == 0) break;

            const chunk_len = @min(allowed, payload_max);
            @memcpy(data_buf.bytes[buf_pos + 9 ..][0..chunk_len], slot.handle.bytes[slot.offset..][0..chunk_len]);
            slot.offset += chunk_len;
            total_sent += chunk_len;

            const is_last = slot.offset >= slot.len;
            const flags: u8 = if (is_last) 0x1 else 0x0;
            http2.writeFrameHeader(data_buf.bytes[buf_pos..], .data, flags, slot.stream_id, chunk_len) catch break;
            buf_pos += 9 + chunk_len;
            stack.consumeSendWindow(slot.stream_id, chunk_len);
            if (is_last) break;
        }

        if (total_sent == 0) {
            server.io.releaseBuffer(data_buf);
            continue;
        }

        if (!conn.enqueueWrite(data_buf, buf_pos)) {
            server.io.releaseBuffer(data_buf);
            slot.cleanup(&server.io);
            sendRstStream(server, conn, slot.stream_id, 0x7);
            continue;
        }
        server.io.onWriteBuffered(conn, buf_pos);

        if (slot.offset >= slot.len) {
            slot.cleanup(&server.io);
            stack.closeStream(slot.stream_id);
        }
    }
}

pub fn drainPendingH2Streams(server: *Server, conn: *connection.Connection) void {
    drainPendingH2Files(server, conn);
    drainPendingH2Responses(server, conn);
}

pub fn queueHttp2Response(server: *Server, conn: *connection.Connection, stream_id: u32, resp: response_mod.Response, is_head: bool) !void {
    const body_len = resp.bodyLen();
    const body_bytes = resp.bodyBytes();
    var managed_body: ?response_mod.ManagedBody = switch (resp.body) {
        .managed => |managed| managed,
        else => null,
    };
    defer if (managed_body) |managed| server.io.releaseBuffer(managed.handle);
    const buf = server.io.acquireBuffer() orelse {
        sendRstStream(server, conn, stream_id, 0x7);
        return;
    };
    const max_frame_size: usize = if (conn.http2_stack) |stack| @intCast(stack.peer_max_frame_size) else 16384;
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

    // Small body: pack HEADERS + DATA into the same buffer when the
    // send window allows it. This halves buffer acquisitions and
    // write-queue slots for the common case (bodies < max_frame_size).
    if (body_len <= max_frame_size and total_len + 9 + body_len <= buf.bytes.len) {
        const send_allowed = if (conn.http2_stack) |stack| stack.canSend(stream_id, body_len) else 0;
        if (send_allowed >= body_len) {
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
            if (conn.http2_stack) |stack| {
                stack.consumeSendWindow(stream_id, body_len);
                stack.closeStream(stream_id);
            }
            return;
        }
        // Window too small — fall through to large-body path
    }

    const stack = conn.http2_stack orelse {
        server.io.releaseBuffer(buf);
        server.closeConnection(conn);
        return;
    };

    // Large body: enqueue HEADERS + one DATA frame for fair scheduling,
    // stash remainder as PendingH2Response for the drain pump.
    if (!conn.enqueueWrite(buf, total_len)) {
        server.io.releaseBuffer(buf);
        server.closeConnection(conn);
        return;
    }
    server.io.onWriteBuffered(conn, total_len);
    server.io.setTimeoutPhase(conn, .write);

    const allowed = stack.canSend(stream_id, body_len);
    var sent: usize = 0;
    if (allowed > 0) {
        const data_buf = server.io.acquireBuffer() orelse {
            sendRstStream(server, conn, stream_id, 0x7);
            return;
        };
        const max_payload = @min(data_buf.bytes.len - 9, max_frame_size);
        const chunk_len = @min(allowed, max_payload);
        @memcpy(data_buf.bytes[9 .. 9 + chunk_len], body_bytes[0..chunk_len]);
        const is_last = chunk_len == body_len;
        const flags: u8 = if (is_last) 0x1 else 0x0;
        http2.writeFrameHeader(data_buf.bytes, .data, flags, stream_id, chunk_len) catch {
            server.io.releaseBuffer(data_buf);
            sendRstStream(server, conn, stream_id, 0x2);
            return;
        };
        const frame_len = 9 + chunk_len;
        if (!conn.enqueueWrite(data_buf, frame_len)) {
            server.io.releaseBuffer(data_buf);
            sendRstStream(server, conn, stream_id, 0x7);
            return;
        }
        server.io.onWriteBuffered(conn, frame_len);
        stack.consumeSendWindow(stream_id, chunk_len);
        if (is_last) {
            stack.closeStream(stream_id);
            return;
        }
        sent = chunk_len;
    }

    // Stash remaining body for the drain pump (fair round-robin with files).
    const remaining_len = body_len - sent;
    var stash_handle: buffer_pool.BufferHandle = undefined;
    var stash_offset: usize = undefined;
    var stash_len: usize = undefined;
    if (managed_body) |managed| {
        stash_handle = managed.handle;
        stash_offset = sent;
        stash_len = body_len;
        managed_body = null;
    } else {
        const h = server.io.acquireBuffer() orelse {
            sendRstStream(server, conn, stream_id, 0x7);
            return;
        };
        if (h.bytes.len < remaining_len) {
            server.io.releaseBuffer(h);
            sendRstStream(server, conn, stream_id, 0x7);
            return;
        }
        @memcpy(h.bytes[0..remaining_len], body_bytes[sent..][0..remaining_len]);
        stash_handle = h;
        stash_offset = 0;
        stash_len = remaining_len;
    }

    const resps = conn.h2_pending_responses orelse blk: {
        const alloc = server.allocator.create([connection.MAX_PENDING_H2_RESPONSES]connection.PendingH2Response) catch {
            server.io.releaseBuffer(stash_handle);
            sendRstStream(server, conn, stream_id, 0x7);
            return;
        };
        alloc.* = [_]connection.PendingH2Response{.{}} ** connection.MAX_PENDING_H2_RESPONSES;
        conn.h2_pending_responses = alloc;
        break :blk alloc;
    };

    for (resps) |*slot| {
        if (!slot.active) {
            slot.* = .{
                .active = true,
                .stream_id = stream_id,
                .handle = stash_handle,
                .offset = stash_offset,
                .len = stash_len,
            };
            return;
        }
    }
    server.io.releaseBuffer(stash_handle);
    sendRstStream(server, conn, stream_id, 0x7);
}

/// Send RST_STREAM for a single stream without killing the connection.
/// Used when buffer exhaustion prevents serving a particular stream.
fn sendRstStream(server: *Server, conn: *connection.Connection, stream_id: u32, error_code: u32) void {
    var rst_buf: [13]u8 = undefined;
    const rst_len = http2.writeRstStream(&rst_buf, stream_id, error_code) catch return;
    sendHttp2ControlFrame(server, conn, rst_buf[0..rst_len]);
    if (conn.http2_stack) |stack| stack.closeStream(stream_id);
}

fn accumulateH2Body(server: *Server, conn: *connection.Connection, data_ev: http2.DataEvent) void {
    const pending = conn.h2_pending orelse return;
    for (pending) |*slot| {
        if (slot.active and slot.stream_id == data_ev.stream_id) {
            if (slot.body_handle == null) {
                slot.body_handle = server.io.acquireBodyBuffer() orelse {
                    sendRstStream(server, conn, data_ev.stream_id, 0x7);
                    slot.active = false;
                    return;
                };
                slot.body_len = 0;
                slot.body_is_body_pool = true;
            }
            const buf = slot.body_handle.?.bytes;
            const avail = buf.len - slot.body_len;
            if (data_ev.data.len > avail) {
                sendRstStream(server, conn, data_ev.stream_id, 0x3);
                slot.active = false;
                if (slot.body_handle) |bh| {
                    if (slot.body_is_body_pool) server.io.releaseBodyBuffer(bh) else server.io.releaseBuffer(bh);
                    slot.body_handle = null;
                }
                return;
            }
            @memcpy(buf[slot.body_len .. slot.body_len + data_ev.data.len], data_ev.data);
            slot.body_len += data_ev.data.len;
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
    // Admin-gated (see dispatch.zig H1 counterpart): off = one dead branch.
    if (server.cfg.admin.enabled) metrics_mw.getStore().recordRequest(.http2);
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

    // Reverse-proxy routing over HTTP/2: if a configured proxy route matches,
    // forward to the upstream and emit the response on this stream — mirrors
    // the H1 proxy path in dispatch.zig so swerver works as an h2 edge gateway.
    // Guarded by `server.proxy`, so non-proxy servers pay nothing. (Response
    // cache / x402 / OTel remain H1-only for now.)
    if (server.proxy) |proxy| {
        if (proxy.matchRoute(&request_with_body)) |_| {
            var ip_buf: [64]u8 = undefined;
            var client_ip_str: ?[]const u8 = null;
            if (conn.cached_peer_ip) |ip4| {
                const l = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                if (l.len > 0) client_ip_str = ip_buf[0..l.len];
            }
            // Real per-stream park binding (E2a): a parking proxy filter suspends
            // THIS stream and resumes via wasmResume's .http2 arm. The connection
            // keeps multiplexing its other streams while this one waits.
            const proxy_binding: proxy_mod.WasmBinding = if (build_options.enable_wasm) .{
                .table = @ptrCast(&server.wasm_host_calls),
                .conn_index = conn.index,
                .conn_id = conn.id,
                .stream_id = stream_id,
                .protocol = .http2,
                .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
                .start_fn = wasmStartThunkH2,
                .start_ctx = @ptrCast(server),
            } else .{};
            var proxy_result = proxy.handle(
                request_with_body,
                &mw_ctx,
                client_ip_str,
                conn.tls_session != null,
                server.now_ms,
                null,
                null,
                proxy_binding,
            );
            defer proxy_result.release();
            // Park sentinel: the filter parked on a host_call. Leave the stream
            // suspended (no frames queued, stream stays open); wasmResume delivers
            // the response on this stream once the host call completes.
            if (build_options.enable_wasm and proxy_result.resp.isParked()) {
                if (server.wasmHasParkForStream(conn.index, conn.id, stream_id)) return;
                // Sentinel without a live park (programmer error / orphaned park):
                // release any orphan and fail closed, mirroring the router orphan
                // branch below (500, with the cancel to avoid an instance leak).
                server.wasmCancelForStream(conn.index, conn.id, stream_id);
                try queueHttp2Response(server, conn, stream_id, .{
                    .status = 500,
                    .headers = &.{},
                    .body = .{ .bytes = "Internal Server Error" },
                }, hdr_request.method == .HEAD);
                return;
            }
            // Pool/park-table exhaustion: serve the 503 AND pause reads briefly
            // so a flood self-throttles (G2), mirroring the router-result path.
            if (proxy_result.pause_reads_ms) |pause_ms| {
                conn.setRateLimitPause(server.now_ms, pause_ms);
            }
            try queueHttp2Response(server, conn, stream_id, proxy_result.resp, hdr_request.method == .HEAD);
            return;
        }
    }

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
    // Real per-stream park binding (E2a): a parking WASM filter suspends THIS
    // stream (recorded in the host_call table, keyed by stream_id) and resumes
    // via wasmResume's .http2 arm. The connection keeps multiplexing its other
    // streams while this one waits.
    if (build_options.enable_wasm) {
        scratch.wasm = .{
            .table = @ptrCast(&server.wasm_host_calls),
            .conn_index = conn.index,
            .conn_id = conn.id,
            .stream_id = stream_id,
            .protocol = .http2,
            .deadline_ms = server.now_ms + server.wasm_host_call_deadline_ms,
            .start_fn = wasmStartThunkH2,
            .start_ctx = @ptrCast(server),
        };
    }
    const result = server.app_router.handle(request_with_body, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    // Park sentinel: a filter parked on a host_call. Leave the stream suspended
    // (no frames queued, stream stays open); wasmResume delivers the response on
    // this stream once the host call completes. Checked before queueHttp2Response
    // so the park sentinel is never serialized.
    if (build_options.enable_wasm and result.resp.isParked()) {
        if (server.wasmHasParkForStream(conn.index, conn.id, stream_id)) return;
        // Sentinel without a live park (programmer error / orphaned park): fail
        // closed on this stream and release any orphaned park to avoid a leak.
        server.wasmCancelForStream(conn.index, conn.id, stream_id);
        try queueHttp2Response(server, conn, stream_id, .{
            .status = 500,
            .headers = &.{},
            .body = .{ .bytes = "Internal Server Error" },
        }, hdr_request.method == .HEAD);
        return;
    }
    if (result.pause_reads_ms) |pause_ms| {
        conn.setRateLimitPause(server.now_ms, pause_ms);
    }
    try queueHttp2Response(server, conn, stream_id, result.resp, hdr_request.method == .HEAD);
}

// ---------------------------------------------------------------------------
// Tests (E2a: HTTP/2 per-stream WASM filter park). Run with:
//   zig build test -Denable-http2=true -Denable-wasm=true
// Skipped (SkipZigTest) when either flag is off, since the path is gated on both.
// ---------------------------------------------------------------------------

const testing = std.testing;
const config = @import("../config.zig");

/// Scan the connection's write queue (without consuming it) for a frame of
/// `want_type` on `want_stream`, returning the frame payload if found. Used by
/// the H2 park/resume tests to confirm a response landed on the right stream.
fn findH2Frame(conn: *connection.Connection, want_type: http2.FrameType, want_stream: u32) ?[]const u8 {
    const cap = conn.write_queue.len;
    var c: usize = 0;
    var idx: usize = conn.write_head;
    while (c < conn.write_count) : ({
        c += 1;
        idx = (idx + 1) % cap;
    }) {
        const entry = conn.write_queue[idx];
        var off: usize = 0;
        while (off + 9 <= entry.len) {
            const flen = (@as(usize, entry.handle.bytes[off]) << 16) |
                (@as(usize, entry.handle.bytes[off + 1]) << 8) |
                @as(usize, entry.handle.bytes[off + 2]);
            const ftype = entry.handle.bytes[off + 3];
            const sid = ((@as(u32, entry.handle.bytes[off + 5]) & 0x7f) << 24) |
                (@as(u32, entry.handle.bytes[off + 6]) << 16) |
                (@as(u32, entry.handle.bytes[off + 7]) << 8) |
                @as(u32, entry.handle.bytes[off + 8]);
            if (ftype == @intFromEnum(want_type) and sid == want_stream) {
                if (off + 9 + flen <= entry.len) return entry.handle.bytes[off + 9 .. off + 9 + flen];
                return entry.handle.bytes[off + 9 .. entry.len];
            }
            off += 9 + flen;
        }
    }
    return null;
}

fn drainH2WriteQueue(server: *Server, conn: *connection.Connection) void {
    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        server.io.releaseBuffer(entry.handle);
        conn.popWrite();
    }
}

fn h2EnrichHandler(_: *router.HandlerContext) response_mod.Response {
    return .{ .status = 200, .headers = &.{}, .body = .{ .bytes = "enriched" } };
}

fn h2PlainHandler(_: *router.HandlerContext) response_mod.Response {
    return .{ .status = 200, .headers = &.{}, .body = .{ .bytes = "plain-ok" } };
}

test "wasm h2: stream park then resume delivers on its stream; sibling flows while parked" {
    if (build_options.enable_http2 and build_options.enable_wasm) {
        const dispatch = @import("dispatch.zig");
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");

        var gpa = std.heap.DebugAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var pool = try wasm_filter_mod.Pool.init(allocator, FILTER, .{ .instances = 2 });
        defer pool.deinit();

        var cfg = config.ServerConfig.default();
        cfg.max_connections = 1;
        cfg.buffer_pool = .{ .buffer_size = 16 * 1024, .buffer_count = 8 };

        var app_router = router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
        try app_router.get("/enrich", h2EnrichHandler);
        try app_router.get("/plain", h2PlainHandler);
        _ = app_router.attachWasmFilter("/enrich", &pool, wasm_filter_mod.DEFAULT_FUEL);

        var server = try Server.initWithRouter(allocator, cfg, app_router);
        defer server.deinit();
        server.wasm_mock_enabled = true;
        server.wasm_mock_reply = "ok"; // probe resumes /enrich to .allow

        const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
        defer if (conn.state != .closed) server.io.releaseConnection(conn);
        conn.protocol = .http2;
        var stack = http2.Stack.init();
        _ = stack.openTestStream(1);
        _ = stack.openTestStream(3);
        conn.http2_stack = &stack;

        // Stream 1 -> /enrich: the filter stages a host_call and PARKS. No frames
        // are queued for it yet; the stream stays suspended.
        const req1 = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
        try dispatchHttp2Request(&server, conn, 1, req1, "");
        try testing.expectEqual(@as(usize, 1), server.wasm_host_calls.liveCount());
        try testing.expect(server.wasmHasParkForStream(conn.index, conn.id, 1));
        try testing.expect(findH2Frame(conn, .headers, 1) == null);
        try testing.expectEqual(@as(usize, 1), server.wasm_mock_count);

        // Stream 3 -> /plain: a SIBLING stream completes immediately while stream
        // 1 is still parked. The connection kept multiplexing.
        const req3 = request.RequestView{ .method = .GET, .path = "/plain", .headers = &.{} };
        try dispatchHttp2Request(&server, conn, 3, req3, "");
        const sib_body = findH2Frame(conn, .data, 3) orelse return error.SiblingNotDelivered;
        try testing.expectEqualStrings("plain-ok", sib_body);
        // Stream 1 still parked, still no response.
        try testing.expect(findH2Frame(conn, .headers, 1) == null);
        try testing.expectEqual(@as(usize, 1), server.wasm_host_calls.liveCount());

        // Complete the parked host call (mock): resumes stream 1 -> allow ->
        // re-dispatch the handler -> deliver "enriched" on stream 1.
        const n = server.wasm_mock_count;
        var k: usize = 0;
        while (k < n) : (k += 1) dispatch.wasmComplete(&server, server.wasm_mock_pending[k], "ok");
        server.wasm_mock_count = 0;

        try testing.expectEqual(@as(usize, 0), server.wasm_host_calls.liveCount()); // released
        const enriched = findH2Frame(conn, .data, 1) orelse return error.ResumeNotDelivered;
        try testing.expectEqualStrings("enriched", enriched);
        // HEADERS for stream 1 present too.
        try testing.expect(findH2Frame(conn, .headers, 1) != null);

        drainH2WriteQueue(&server, conn);
    } else return error.SkipZigTest;
}

test "wasm h2: RST_STREAM during park releases the pinned instance (no leak)" {
    if (build_options.enable_http2 and build_options.enable_wasm) {
        const FILTER = @embedFile("../wasm/testdata/filter_probe.wasm");

        var gpa = std.heap.DebugAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var pool = try wasm_filter_mod.Pool.init(allocator, FILTER, .{ .instances = 1 });
        defer pool.deinit();

        var cfg = config.ServerConfig.default();
        cfg.max_connections = 1;
        cfg.buffer_pool = .{ .buffer_size = 16 * 1024, .buffer_count = 8 };

        var app_router = router.Router.init(.{ .require_payment = false, .payment_required_b64 = "" });
        try app_router.get("/enrich", h2EnrichHandler);
        _ = app_router.attachWasmFilter("/enrich", &pool, wasm_filter_mod.DEFAULT_FUEL);

        var server = try Server.initWithRouter(allocator, cfg, app_router);
        defer server.deinit();
        server.wasm_mock_enabled = true;
        server.wasm_mock_reply = "ok";

        const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
        defer if (conn.state != .closed) server.io.releaseConnection(conn);
        conn.protocol = .http2;
        var stack = http2.Stack.init();
        _ = stack.openTestStream(1);
        conn.http2_stack = &stack;
        conn.h2_pending = try allocator.create([connection.MAX_PENDING_H2_BODIES]connection.PendingH2Body);
        defer allocator.destroy(conn.h2_pending.?);
        conn.h2_pending.?.* = [_]connection.PendingH2Body{.{}} ** connection.MAX_PENDING_H2_BODIES;

        // Park stream 1. The single pool instance is now pinned.
        const req1 = request.RequestView{ .method = .GET, .path = "/enrich", .headers = &.{} };
        try dispatchHttp2Request(&server, conn, 1, req1, "");
        try testing.expectEqual(@as(usize, 1), server.wasm_host_calls.liveCount());

        // Feed an RST_STREAM frame for stream 1 through the real read path. The
        // stack emits a stream_reset event; handleHttp2Read calls cancelForStream,
        // releasing the pinned instance back to the pool (no leak).
        const rbuf = server.io.acquireBuffer() orelse return error.OutOfMemory;
        conn.read_buffer = rbuf;
        // The stack's ingest consumes the client connection preface before any
        // frame, so prepend it ahead of the RST_STREAM.
        @memcpy(rbuf.bytes[0..http2.Preface.len], http2.Preface);
        var rst: [13]u8 = undefined;
        const rst_len = try http2.writeRstStream(&rst, 1, 0x8); // CANCEL
        @memcpy(rbuf.bytes[http2.Preface.len..][0..rst_len], rst[0..rst_len]);
        conn.read_offset = 0;
        conn.read_buffered_bytes = http2.Preface.len + rst_len;

        try handleHttp2Read(&server, conn);

        try testing.expectEqual(@as(usize, 0), server.wasm_host_calls.liveCount()); // released
        // The freed instance is reacquirable from the single-instance pool.
        try testing.expect(pool.acquire() != null);

        drainH2WriteQueue(&server, conn);
        server.io.releaseBuffer(rbuf);
        conn.read_buffer = null;
    } else return error.SkipZigTest;
}
