const std = @import("std");

const config = @import("config.zig");
const runtime = @import("runtime/io.zig");
const connection = @import("runtime/connection.zig");
const router = @import("router/router.zig");
const net = @import("runtime/net.zig");
const http1 = @import("protocol/http1.zig");
const response_mod = @import("response/response.zig");
const http2 = @import("protocol/http2.zig");
const http3 = @import("protocol/http3.zig");
const tls = @import("tls/provider.zig");
const build_options = @import("build_options");
const quic_handler = @import("quic/handler.zig");
const quic_connection = @import("quic/connection.zig");
const middleware = @import("middleware/middleware.zig");
const request = @import("protocol/request.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    cfg: config.ServerConfig,
    io: runtime.IoRuntime,
    app_router: router.Router,
    listener_fd: ?std.posix.fd_t,
    udp_fd: ?std.posix.fd_t,
    tls_provider: ?tls.Provider,
    http2_stack: ?http2.Stack,
    http3_stack: ?http3.Stack,
    quic: ?quic_handler.Handler,
    /// Buffer for receiving UDP datagrams
    udp_recv_buf: [2048]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, cfg: config.ServerConfig) !Server {
        if (cfg.limits.max_header_count > connection.HeaderCapacity) return error.InvalidHeaderTable;
        const io_runtime = try runtime.IoRuntime.init(allocator, cfg);
        const app_router = router.Router.init(.{
            .require_payment = cfg.x402.enabled,
            .payment_required_b64 = cfg.x402.payment_required_b64,
        });
        const tls_provider: ?tls.Provider = if (build_options.enable_tls) tls.Provider.init() else null;
        const http2_stack: ?http2.Stack = if (build_options.enable_http2) http2.Stack.init() else null;
        const http3_stack: ?http3.Stack = if (build_options.enable_http3) http3.Stack.init() else null;
        const quic: ?quic_handler.Handler = if (build_options.enable_http3 and cfg.quic.enabled)
            quic_handler.Handler.init(allocator, true, cfg.quic.max_connections)
        else
            null;

        return .{
            .allocator = allocator,
            .cfg = cfg,
            .io = io_runtime,
            .app_router = app_router,
            .listener_fd = null,
            .udp_fd = null,
            .tls_provider = tls_provider,
            .http2_stack = http2_stack,
            .http3_stack = http3_stack,
            .quic = quic,
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener_fd) |fd| std.posix.close(fd);
        if (self.udp_fd) |fd| std.posix.close(fd);
        if (self.quic) |*q| q.deinit();
        self.io.deinit();
    }

    pub fn run(self: *Server, run_for_ms: ?u64) !void {
        try self.io.start();
        if (self.listener_fd == null) {
            const fd = try net.listen(self.cfg.address, self.cfg.port, 1024);
            self.listener_fd = fd;
            try self.io.registerListener(fd);
        }
        // Initialize UDP listener for QUIC if enabled
        if (self.quic != null and self.udp_fd == null) {
            const quic_port = self.cfg.quic.port;
            if (quic_port > 0) {
                const udp_fd = net.bindUdp(self.cfg.address, quic_port) catch |err| {
                    std.log.warn("Failed to bind UDP port {}: {}", .{ quic_port, err });
                    return err;
                };
                self.udp_fd = udp_fd;
                self.io.registerUdpSocket(udp_fd) catch |err| {
                    std.log.warn("Failed to register UDP socket: {}", .{err});
                    std.posix.close(udp_fd);
                    self.udp_fd = null;
                };
            }
        }
        const deadline = if (run_for_ms) |ms| self.io.nowMs() + ms else null;
        while (true) {
            if (deadline) |limit| {
                if (self.io.nowMs() >= limit) return;
            }
            const now_ms = self.io.nowMs();
            const timeout_ms = self.io.nextPollTimeoutMs(now_ms);
            const events = try self.io.pollWithTimeout(timeout_ms);
            self.io.enforceTimeouts(self.io.nowMs());
            // Periodic QUIC cleanup
            if (self.quic) |*q| {
                q.cleanup();
            }
            if (events.len == 0) continue;
            for (events) |event| {
                switch (event.kind) {
                    .accept => {
                        // Use event.handle if provided (kqueue), otherwise use listener_fd (epoll)
                        const fd = event.handle orelse self.listener_fd orelse continue;
                        try self.handleAccept(fd);
                    },
                    .datagram => {
                        // UDP datagram received - QUIC packet handling
                        try self.handleDatagram();
                    },
                    .read, .write, .err => {
                        // Validate conn_id fits in u32 before casting
                        if (event.conn_id > std.math.maxInt(u32)) continue;
                        const index: u32 = @intCast(event.conn_id);
                        switch (event.kind) {
                            .read => try self.handleRead(index),
                            .write => try self.handleWrite(index),
                            .err => try self.handleError(index),
                            .accept, .datagram => unreachable,
                        }
                    },
                }
            }
        }
    }

    fn handleAccept(self: *Server, listener_fd: std.posix.fd_t) !void {
        const client_fd = net.accept(listener_fd) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        errdefer std.posix.close(client_fd);
        const now_ms = self.io.nowMs();
        const conn = self.io.acquireConnection(now_ms) orelse {
            std.posix.close(client_fd);
            return;
        };
        if (self.io.acquireBuffer()) |buf| {
            conn.read_buffer = buf;
        } else {
            self.io.releaseConnection(conn);
            std.posix.close(client_fd);
            return;
        }
        conn.fd = client_fd;
        conn.transition(.active, now_ms) catch {
            // Invalid state transition - close connection
            if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
            self.io.releaseConnection(conn);
            std.posix.close(client_fd);
            return;
        };
        self.io.setTimeoutPhase(conn, .header);
        self.io.registerConnection(conn.index, client_fd) catch |err| {
            if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
            self.io.releaseConnection(conn);
            std.posix.close(client_fd);
            return err;
        };
    }

    fn handleDatagram(self: *Server) !void {
        const udp_fd = self.udp_fd orelse return;
        var quic = &(self.quic orelse return);

        // Receive datagram
        const recv_result = net.recvfrom(udp_fd, &self.udp_recv_buf) catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => return,
            }
        };

        if (recv_result.bytes_read == 0) return;

        // Convert peer address to our internal format (zero-init to avoid undefined bytes)
        var peer_addr: quic_handler.connection_pool.SockAddrStorage = undefined;
        @memset(std.mem.asBytes(&peer_addr), 0);
        @memcpy(std.mem.asBytes(&peer_addr)[0..@sizeOf(@TypeOf(recv_result.peer_addr))], std.mem.asBytes(&recv_result.peer_addr));

        // Process the QUIC packet
        const result = quic.processPacket(self.udp_recv_buf[0..recv_result.bytes_read], peer_addr) catch |err| {
            // Log error but don't crash
            std.log.debug("QUIC packet error: {}", .{err});
            return;
        };

        // Send response if any (handshake responses)
        if (result.response) |resp| {
            _ = net.sendto(udp_fd, resp, recv_result.peer_addr) catch |err| {
                std.log.debug("Failed to send QUIC response: {}", .{err});
            };
        }

        // Process HTTP/3 events (headers, data, end_stream)
        if (result.conn) |conn| {
            for (result.http3_events) |event| {
                switch (event) {
                    .headers => |hdrs| {
                        // Process HTTP/3 request headers
                        self.handleHttp3Request(udp_fd, conn, hdrs, recv_result.peer_addr);
                    },
                    .data => {
                        // Data events are handled after headers complete
                        // Body data would be accumulated in stream buffer
                    },
                    .end_stream => {
                        // Request complete - response should already be sent
                    },
                    else => {},
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

    /// Handle an HTTP/3 request and send response
    fn handleHttp3Request(
        self: *Server,
        udp_fd: std.posix.fd_t,
        conn: *quic_connection.Connection,
        headers_event: http3.HeadersEvent,
        peer_addr: net.SockAddrStorage,
    ) void {
        // Extract pseudo-headers (:method, :path, :scheme, :authority)
        var method: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var regular_headers: [64]http3.Header = undefined;
        var regular_count: usize = 0;

        for (headers_event.headers) |hdr| {
            if (std.mem.eql(u8, hdr.name, ":method")) {
                method = hdr.value;
            } else if (std.mem.eql(u8, hdr.name, ":path")) {
                path = hdr.value;
            } else if (hdr.name.len > 0 and hdr.name[0] != ':') {
                // Regular header (not pseudo-header)
                if (regular_count < regular_headers.len) {
                    regular_headers[regular_count] = hdr;
                    regular_count += 1;
                }
            }
        }

        // Validate required pseudo-headers
        const method_str = method orelse return;
        const path_str = path orelse return;

        const parsed_method = request.Method.fromString(method_str) orelse return;

        // Convert HTTP/3 headers to request headers
        var req_headers: [64]request.Header = undefined;
        for (regular_headers[0..regular_count], 0..) |hdr, i| {
            req_headers[i] = .{ .name = hdr.name, .value = hdr.value };
        }

        // Build RequestView
        const req_view = request.RequestView{
            .method = parsed_method,
            .path = path_str,
            .headers = req_headers[0..regular_count],
            .body = "", // Body comes in DATA frames
        };

        // Route the request
        var mw_ctx = middleware.Context{ .protocol = .http3 };
        const resp = self.app_router.handle(req_view, &mw_ctx);

        // Encode HTTP/3 response
        var response_buf: [16384]u8 = undefined;
        const resp_len = conn.encodeHttp3Response(
            &response_buf,
            resp.status,
            @ptrCast(resp.headers),
            if (resp.body.len > 0) resp.body else null,
        ) catch return;

        // Build QUIC packet with STREAM frame containing response
        var packet_buf: [2048]u8 = undefined;
        const packet_len = self.buildStreamPacket(
            conn,
            headers_event.stream_id,
            response_buf[0..resp_len],
            true, // FIN - end of response
            &packet_buf,
        ) catch return;

        // Send the response packet
        _ = net.sendto(udp_fd, packet_buf[0..packet_len], peer_addr) catch {};
    }

    /// Build a QUIC short header packet containing a STREAM frame
    fn buildStreamPacket(
        self: *Server,
        conn: *quic_connection.Connection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
        out: []u8,
    ) !usize {
        _ = self;
        const crypto = @import("quic/crypto.zig");
        const varint = @import("quic/varint.zig");

        // Get application keys
        const keys_opt: ?crypto.Keys = if (conn.is_server)
            conn.crypto_ctx.application.server
        else
            conn.crypto_ctx.application.client;
        const keys = keys_opt orelse return error.NoKeys;

        var offset: usize = 0;

        // Short header
        // First byte: Fixed bit (0x40) + Spin bit (0) + Reserved (0) + Key Phase (0) + PN Length (0 = 1 byte)
        out[offset] = 0x40;
        offset += 1;

        // Destination Connection ID (peer's CID)
        @memcpy(out[offset .. offset + conn.peer_cid.len], conn.peer_cid.slice());
        offset += conn.peer_cid.len;

        // Packet number offset
        const pn_offset = offset;

        // Packet number (1 byte for simplicity)
        const pn = conn.application_space.allocatePacketNumber();
        out[offset] = @truncate(pn);
        offset += 1;

        const header_len = offset;

        // Build STREAM frame
        // Frame type: 0x08 + OFF (0x04) + LEN (0x02) + FIN (0x01)
        var frame_type: u8 = 0x08;
        frame_type |= 0x02; // Has length
        if (fin) frame_type |= 0x01;

        out[offset] = frame_type;
        offset += 1;

        // Stream ID (varint)
        offset += varint.encode(out[offset..], stream_id) catch return error.BufferTooSmall;

        // Length (varint)
        offset += varint.encode(out[offset..], data.len) catch return error.BufferTooSmall;

        // Stream data
        @memcpy(out[offset .. offset + data.len], data);
        offset += data.len;

        const plaintext_len = offset - header_len;

        // Encrypt payload
        var ciphertext_buf: [16384]u8 = undefined;
        const ciphertext_len = crypto.protectPayload(
            &keys,
            pn,
            out[0..header_len],
            out[header_len..offset],
            &ciphertext_buf,
        ) catch return error.EncryptionFailed;

        // Copy ciphertext back
        @memcpy(out[header_len .. header_len + ciphertext_len], ciphertext_buf[0..ciphertext_len]);
        offset = header_len + ciphertext_len;

        // Apply header protection
        const sample_offset = pn_offset + 4;
        if (sample_offset + 16 <= offset) {
            const sample: *const [16]u8 = @ptrCast(out[sample_offset .. sample_offset + 16]);
            crypto.applyHeaderProtection(
                keys.hp[0..keys.hp_len],
                sample,
                &out[0],
                out[pn_offset .. pn_offset + 1],
            );
        }

        _ = plaintext_len;

        return offset;
    }

    fn handleRead(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        const fd = conn.fd orelse return;
        if (!self.io.canRead(conn)) return;
        if (conn.timeout_phase == .idle) self.io.setTimeoutPhase(conn, .header);
        const buffer_handle = conn.read_buffer orelse return;
        const offset = conn.read_offset + conn.read_buffered_bytes;
        if (offset >= buffer_handle.bytes.len) return;
        const slice = buffer_handle.bytes[offset..];
        const bytes_read = std.posix.system.read(fd, slice.ptr, slice.len);
        if (bytes_read == 0) {
            self.closeConnection(conn);
            return;
        }
        if (bytes_read < 0) {
            switch (std.posix.errno(bytes_read)) {
                .AGAIN => return,
                else => {
                    self.closeConnection(conn);
                    return;
                },
            }
        }
        const count: usize = @intCast(bytes_read);
        self.io.onReadBuffered(conn, count);
        conn.markActive(self.io.nowMs());

        if (build_options.enable_http2 and conn.protocol == .http1 and conn.read_offset == 0) {
            const end = conn.read_offset + conn.read_buffered_bytes;
            if (end <= buffer_handle.bytes.len) {
                const candidate = buffer_handle.bytes[0..end];
                if (matchesHttp2Preface(candidate)) {
                    if (candidate.len < http2.Preface.len) return;
                    if (conn.http2_stack == null) {
                        const stack_ptr = try self.allocator.create(http2.Stack);
                        stack_ptr.* = http2.Stack.init();
                        conn.http2_stack = stack_ptr;
                    }
                    conn.protocol = .http2;
                }
            }
        }

        if (conn.protocol == .http2) {
            try self.handleHttp2Read(conn);
            return;
        }

        while (conn.read_buffered_bytes > 0 and conn.canEnqueueWrite()) {
            const start = conn.read_offset;
            const end = start + conn.read_buffered_bytes;
            if (end > buffer_handle.bytes.len) break;
            const parse = http1.parse(buffer_handle.bytes[start..end], .{
                .max_header_bytes = self.cfg.limits.max_header_bytes,
                .max_body_bytes = self.cfg.limits.max_body_bytes,
                .max_header_count = self.cfg.limits.max_header_count,
                .headers_storage = conn.headers[0..],
            });
            if (parse.state == .partial) {
                if (parse.expect_continue and !conn.sent_continue) {
                    conn.sent_continue = true;
                    try self.queueResponse(conn, continueResponse());
                }
                return;
            }
            if (parse.state == .err) {
                conn.close_after_write = true;
                self.io.onReadConsumed(conn, conn.read_buffered_bytes);
                try self.queueResponse(conn, errorResponseFor(parse.error_code));
                return;
            }
            conn.header_count = parse.view.headers.len;
            if (!parse.keep_alive) conn.close_after_write = true;
            var mw_ctx = middleware.Context{ .protocol = .http1 };
            const resp = self.app_router.handle(parse.view, &mw_ctx);
            self.io.onReadConsumed(conn, parse.consumed_bytes);
            try self.queueResponse(conn, resp);
            if (conn.read_buffered_bytes == 0) break;
        }
    }

    fn handleHttp2Read(self: *Server, conn: *connection.Connection) !void {
        const buffer_handle = conn.read_buffer orelse return;
        const stack = conn.http2_stack orelse return;
        while (conn.read_buffered_bytes > 0 and conn.canEnqueueWrite()) {
            const start = conn.read_offset;
            const end = start + conn.read_buffered_bytes;
            if (end > buffer_handle.bytes.len) break;
            const slice = buffer_handle.bytes[start..end];
            var frames: [16]http2.Frame = undefined;
            var events: [16]http2.Event = undefined;
            const ingest = stack.ingest(slice, frames[0..], events[0..]);
            if (ingest.state == .partial) return;
            if (ingest.state == .err) {
                self.closeConnection(conn);
                return;
            }
            self.io.onReadConsumed(conn, ingest.consumed_bytes);
            for (events[0..ingest.event_count]) |event| {
                switch (event) {
                    .headers => |hdr| {
                        var mw_ctx = middleware.Context{ .protocol = .http2, .stream_id = hdr.stream_id };
                        const resp = if (hdr.end_stream) self.app_router.handle(hdr.request, &mw_ctx) else response_mod.Response{
                            .status = 501,
                            .headers = &[_]response_mod.Header{},
                            .body = "Not Implemented\n",
                        };
                        try self.queueHttp2Response(conn, hdr.stream_id, resp);
                    },
                    .data => |data| {
                        _ = data;
                    },
                    .settings => |_| {},
                    .err => |_| {},
                }
            }
            if (conn.read_buffered_bytes == 0) break;
        }
    }

    fn handleWrite(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        const fd = conn.fd orelse return;
        const entry = conn.peekWrite() orelse return;
        const slice = entry.handle.bytes[entry.offset..entry.len];
        const bytes_written = std.posix.system.write(fd, slice.ptr, slice.len);
        if (bytes_written < 0) {
            switch (std.posix.errno(bytes_written)) {
                .AGAIN => return,
                else => {
                    self.closeConnection(conn);
                    return;
                },
            }
        }
        if (bytes_written == 0) return;
        const count: usize = @intCast(bytes_written);
        entry.offset += count;
        self.io.onWriteCompleted(conn, count);
        conn.markActive(self.io.nowMs());
        if (entry.offset >= entry.len) {
            self.io.releaseBuffer(entry.handle);
            conn.popWrite();
        }
        if (conn.write_count == 0) {
            self.io.setTimeoutPhase(conn, .idle);
            if (conn.close_after_write) self.closeConnection(conn);
        }
    }

    fn handleError(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        self.closeConnection(conn);
    }

    fn queueResponse(self: *Server, conn: *connection.Connection, resp: response_mod.Response) !void {
        const buf = self.io.acquireBuffer() orelse {
            // Cannot acquire buffer to send response - close connection
            self.closeConnection(conn);
            return;
        };
        const written = encodeResponse(buf.bytes, resp) catch {
            // Cannot encode response - close connection
            self.io.releaseBuffer(buf);
            self.closeConnection(conn);
            return;
        };
        if (!conn.enqueueWrite(buf, written)) {
            self.io.releaseBuffer(buf);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, written);
        self.io.setTimeoutPhase(conn, .write);
    }

    fn queueHttp2Response(self: *Server, conn: *connection.Connection, stream_id: u32, resp: response_mod.Response) !void {
        _ = stream_id;
        const header_buf = self.io.acquireBuffer() orelse {
            self.closeConnection(conn);
            return;
        };
        const header_block_len = http2.encodeResponseHeaders(header_buf.bytes[9..], resp.status, resp.headers, resp.body.len) catch {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        };
        const max_frame_size: usize = if (conn.http2_stack) |stack| @intCast(stack.max_frame_size) else 16384;
        if (header_block_len > max_frame_size) {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        }
        const headers_flags: u8 = if (resp.body.len == 0) 0x5 else 0x4;
        const resp_stream_id: u32 = if (conn.http2_stack) |stack| stack.last_stream_id else 1;
        http2.writeFrameHeader(header_buf.bytes, .headers, headers_flags, resp_stream_id, header_block_len) catch {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        };
        const header_frame_len = 9 + header_block_len;
        if (!conn.enqueueWrite(header_buf, header_frame_len)) {
            self.io.releaseBuffer(header_buf);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, header_frame_len);
        self.io.setTimeoutPhase(conn, .write);

        if (resp.body.len == 0) return;
        var remaining = resp.body;
        while (remaining.len > 0) {
            const data_buf = self.io.acquireBuffer() orelse {
                // Cannot complete response - close connection
                self.closeConnection(conn);
                return;
            };
            const max_payload = @min(data_buf.bytes.len - 9, max_frame_size);
            const chunk_len = if (remaining.len < max_payload) remaining.len else max_payload;
            @memcpy(data_buf.bytes[9 .. 9 + chunk_len], remaining[0..chunk_len]);
            const flags: u8 = if (remaining.len == chunk_len) 0x1 else 0x0;
            http2.writeFrameHeader(data_buf.bytes, .data, flags, resp_stream_id, chunk_len) catch {
                self.io.releaseBuffer(data_buf);
                self.closeConnection(conn);
                return;
            };
            const frame_len = 9 + chunk_len;
            if (!conn.enqueueWrite(data_buf, frame_len)) {
                self.io.releaseBuffer(data_buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, frame_len);
            remaining = remaining[chunk_len..];
        }
    }

    fn encodeResponse(buf: []u8, resp: response_mod.Response) !usize {
        var index: usize = 0;
        const reason = reasonPhrase(resp.status);
        const status_line = try std.fmt.bufPrint(buf[index..], "HTTP/1.1 {d} {s}\r\n", .{ resp.status, reason });
        index += status_line.len;
        for (resp.headers) |header| {
            const header_line = try std.fmt.bufPrint(buf[index..], "{s}: {s}\r\n", .{ header.name, header.value });
            index += header_line.len;
        }
        if (resp.status == 100) {
            if (index + 2 > buf.len) return error.NoSpaceLeft;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            index += 2;
            return index;
        }
        const length_line = try std.fmt.bufPrint(buf[index..], "Content-Length: {d}\r\n\r\n", .{resp.body.len});
        index += length_line.len;
        if (index + resp.body.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[index .. index + resp.body.len], resp.body);
        index += resp.body.len;
        return index;
    }

    fn reasonPhrase(status: u16) []const u8 {
        return switch (status) {
            100 => "Continue",
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            413 => "Payload Too Large",
            431 => "Request Header Fields Too Large",
            408 => "Request Timeout",
            501 => "Not Implemented",
            500 => "Internal Server Error",
            else => "OK",
        };
    }

    fn continueResponse() response_mod.Response {
        return .{
            .status = 100,
            .headers = &[_]response_mod.Header{},
            .body = "",
        };
    }

    fn errorResponseFor(code: http1.ErrorCode) response_mod.Response {
        return switch (code) {
            .body_too_large => .{
                .status = 413,
                .headers = &[_]response_mod.Header{},
                .body = "Payload Too Large\n",
            },
            .header_too_large => .{
                .status = 431,
                .headers = &[_]response_mod.Header{},
                .body = "Request Header Fields Too Large\n",
            },
            else => .{
                .status = 400,
                .headers = &[_]response_mod.Header{},
                .body = "Bad Request\n",
            },
        };
    }

    fn closeConnection(self: *Server, conn: *connection.Connection) void {
        if (conn.fd) |fd| {
            _ = self.io.unregister(fd) catch {};
            std.posix.close(fd);
        }
        if (conn.http2_stack) |stack| {
            self.allocator.destroy(stack);
            conn.http2_stack = null;
        }
        if (conn.read_buffer) |buf| self.io.releaseBuffer(buf);
        while (conn.peekWrite()) |entry| {
            self.io.releaseBuffer(entry.handle);
            conn.popWrite();
        }
        self.io.releaseConnection(conn);
    }

    fn matchesHttp2Preface(candidate: []const u8) bool {
        const n = if (candidate.len < http2.Preface.len) candidate.len else http2.Preface.len;
        return std.mem.eql(u8, candidate[0..n], http2.Preface[0..n]);
    }
};
