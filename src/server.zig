const std = @import("std");

const config = @import("config.zig");
const runtime = @import("runtime/io.zig");
const connection = @import("runtime/connection.zig");
const buffer_pool = @import("runtime/buffer_pool.zig");
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
const metrics_mw = @import("middleware/metrics_mw.zig");
const proxy_mod = @import("proxy/proxy.zig");

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
    /// Reverse proxy handler (null if proxy not configured)
    proxy: ?*proxy_mod.Proxy = null,
    /// Config file path for hot reload (null if not using config file)
    config_path: ?[]const u8 = null,
    /// Buffer for receiving UDP datagrams
    udp_recv_buf: [2048]u8 = undefined,
    /// Pre-computed Alt-Svc header value for HTTP/3 advertisement
    alt_svc_value: [64]u8 = undefined,
    alt_svc_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, cfg: config.ServerConfig) !Server {
        var app_router = router.Router.init(.{
            .require_payment = cfg.x402.enabled,
            .payment_required_b64 = cfg.x402.payment_required_b64,
        });
        try registerDefaultRoutes(&app_router);
        return initWithRouter(allocator, cfg, app_router);
    }

    pub fn initWithRouter(allocator: std.mem.Allocator, cfg: config.ServerConfig, app_router: router.Router) !Server {
        var srv: Server = undefined;
        try srv.initInPlace(allocator, cfg, app_router);
        return srv;
    }

    /// Initialize a Server in-place at the given pointer. Use this to avoid
    /// constructing the large Server struct on the stack.
    pub fn initInPlace(self: *Server, allocator: std.mem.Allocator, cfg: config.ServerConfig, app_router: router.Router) !void {
        if (cfg.limits.max_header_count > connection.HeaderCapacity) return error.InvalidHeaderTable;
        const io_runtime = try runtime.IoRuntime.init(allocator, cfg);
        const tls_provider: ?tls.Provider = if (build_options.enable_tls and cfg.quic.enabled)
            try tls.Provider.init(allocator, cfg.quic.cert_path, cfg.quic.key_path)
        else
            null;
        const http2_stack: ?http2.Stack = if (build_options.enable_http2) http2.Stack.initWithConfig(.{
            .max_streams = cfg.http2.max_streams,
            .max_header_list_size = cfg.http2.max_header_list_size,
            .initial_window_size = cfg.http2.initial_window_size,
            .max_frame_size = cfg.http2.max_frame_size,
            .max_dynamic_table_size = cfg.http2.max_dynamic_table_size,
        }) else null;
        const http3_stack: ?http3.Stack = if (build_options.enable_http3) http3.Stack.init(allocator, true) else null;
        const quic_inst: ?quic_handler.Handler = if (build_options.enable_http3 and cfg.quic.enabled)
            quic_handler.Handler.init(allocator, true, cfg.max_connections)
        else
            null;

        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .io = io_runtime,
            .app_router = app_router,
            .listener_fd = null,
            .udp_fd = null,
            .tls_provider = tls_provider,
            .http2_stack = http2_stack,
            .http3_stack = http3_stack,
            .quic = quic_inst,
            .alt_svc_value = undefined,
            .alt_svc_len = 0,
        };

        // Pre-compute Alt-Svc header if QUIC is enabled
        if (cfg.quic.enabled) {
            const alt_svc = cfg.quic.buildAltSvcHeader(&self.alt_svc_value) catch "";
            self.alt_svc_len = alt_svc.len;
        }
    }

    pub fn deinit(self: *Server) void {
        if (self.listener_fd) |fd| std.posix.close(fd);
        if (self.udp_fd) |fd| std.posix.close(fd);
        if (self.quic) |*q| q.deinit();
        self.io.deinit();
    }

    /// Request a graceful shutdown. The event loop will stop accepting new connections
    /// and exit after draining in-flight responses.
    pub fn shutdown(_: *Server) void {
        shutdown_requested.store(true, .release);
    }

    /// Apply hot reload from config file.
    /// Safe-to-change fields (value types only): timeouts, limits.
    /// Requires restart: address, port, max_connections, buffer pool, allowed_hosts.
    fn applyReload(self: *Server) void {
        const path = self.config_path orelse {
            std.log.info("SIGHUP received but no config file path set, ignoring", .{});
            return;
        };
        const config_file = @import("config_file.zig");
        var loaded = config_file.loadConfigFile(self.allocator, path) catch |err| {
            std.log.err("Config reload failed: {}", .{err});
            return;
        };
        defer loaded.deinit();

        // Validate the new config before applying
        loaded.server_config.validate() catch |err| {
            std.log.err("Config reload validation failed: {}", .{err});
            return;
        };

        const new = loaded.server_config;
        // Hot-reload value-type fields (no pointer/slice ownership issues)
        self.cfg.timeouts = new.timeouts;
        self.cfg.limits = new.limits;
        std.log.info("Config reloaded from {s}", .{path});
    }

    pub fn run(self: *Server, run_for_ms: ?u64) !void {
        // Install signal handlers for graceful shutdown
        const sa = std.posix.Sigaction{
            .handler = .{ .handler = handleShutdownSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
        std.posix.sigaction(std.posix.SIG.INT, &sa, null);
        // Install SIGHUP handler for config hot reload
        const reload_sa = std.posix.Sigaction{
            .handler = .{ .handler = handleReloadSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.HUP, &reload_sa, null);

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
            if (shutdown_requested.load(.acquire)) {
                std.log.info("Shutdown requested, stopping server", .{});
                return;
            }
            if (reload_requested.swap(false, .acq_rel)) {
                self.applyReload();
            }
            if (deadline) |limit| {
                if (self.io.nowMs() >= limit) return;
            }
            const now_ms = self.io.nowMs();
            const timeout_ms = self.io.nextPollTimeoutMs(now_ms);
            const events = try self.io.pollWithTimeout(timeout_ms);
            // Enforce timeouts and close timed-out connections
            const timeout_result = self.io.enforceTimeouts(self.io.nowMs());
            for (timeout_result.to_close[0..timeout_result.count]) |conn_index| {
                if (self.io.getConnection(conn_index)) |conn| {
                    self.closeConnection(conn);
                }
            }
            // Periodic QUIC cleanup
            if (self.quic) |*q| {
                q.cleanup();
            }
            // Periodic proxy maintenance (pool eviction + health checks)
            if (self.proxy) |proxy| {
                proxy.runMaintenance(self.io.nowMs());
            }
            if (events.len == 0) continue;
            for (events) |event| {
                switch (event.kind) {
                    .accept => {
                        // Use event.handle if provided (kqueue), otherwise use listener_fd (epoll)
                        const fd = event.handle orelse self.listener_fd orelse continue;
                        self.handleAccept(fd) catch |err| {
                            // Log accept errors but don't crash the server
                            std.log.warn("Accept failed: {}", .{err});
                        };
                    },
                    .datagram => {
                        // UDP datagram received - QUIC packet handling
                        try self.handleDatagram();
                    },
                    .read, .write, .err => {
                        // Validate conn_id fits in u32 before casting
                        if (event.conn_id > std.math.maxInt(u32)) continue;
                        const index: u32 = @intCast(event.conn_id);
                        // Guard against stale events: if the connection slot was freed
                        // and reused between event generation and dispatch, the fd will
                        // be null (freed) or the connection state will be closed/accept.
                        const conn = self.io.getConnection(index) orelse continue;
                        if (conn.fd == null or conn.state == .closed or conn.state == .accept) continue;
                        switch (event.kind) {
                            .read => self.handleRead(index) catch |err| {
                                std.log.debug("handleRead conn={} failed: {}", .{ index, err });
                            },
                            .write => self.handleWrite(index) catch |err| {
                                std.log.debug("handleWrite conn={} failed: {}", .{ index, err });
                            },
                            .err => self.handleError(index) catch |err| {
                                std.log.debug("handleError conn={} failed: {}", .{ index, err });
                            },
                            .accept, .datagram => unreachable,
                        }
                    },
                }
            }
        }
    }

    pub fn runFor(self: *Server, run_for_ms: u64) !void {
        try self.run(run_for_ms);
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
        // With edge-triggered epoll, we must try to read immediately after accept
        // because data may have arrived before we registered the socket.
        // If we don't do this, we'll miss the EPOLLIN notification.
        try self.handleRead(conn.index);
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
        var mw_ctx = middleware.Context{
            .protocol = .http3,
            .buffer_ops = .{
                .ctx = &self.io,
                .acquire = acquireBufferOpaque,
                .release = releaseBufferOpaque,
            },
        };
        var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
        var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
        const arena_handle = self.io.acquireBuffer();
        var empty_arena: [0]u8 = undefined;
        const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
        var scratch = router.HandlerScratch{
            .response_buf = response_buf[0..],
            .response_headers = response_headers[0..],
            .arena_buf = arena_buf,
            .arena_handle = arena_handle,
            .buffer_ops = mw_ctx.buffer_ops,
        };
        const result = self.app_router.handle(req_view, &mw_ctx, &scratch);
        if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
        const body_bytes = result.resp.bodyBytes();
        const body_len = result.resp.bodyLen();
        const managed_body = switch (result.resp.body) {
            .managed => |managed| managed,
            else => null,
        };
        if (managed_body) |managed| {
            defer self.io.releaseBuffer(managed.handle);
        }
        // Note: QUIC backpressure is handled at the transport layer via flow control,
        // not by pausing reads like TCP. The 429 response is sufficient.

        // Encode HTTP/3 response
        var encoded_response_buf: [16384]u8 = undefined;
        const resp_len = conn.encodeHttp3Response(
            &encoded_response_buf,
            result.resp.status,
            @ptrCast(result.resp.headers),
            if (body_len > 0) body_bytes else null,
        ) catch return;

        // Build QUIC packet with STREAM frame containing response
        var packet_buf: [2048]u8 = undefined;
        const packet_len = self.buildStreamPacket(
            conn,
            headers_event.stream_id,
            encoded_response_buf[0..resp_len],
            true, // FIN - end of response
            &packet_buf,
        ) catch return;

        // Send the response packet
        _ = net.sendto(udp_fd, packet_buf[0..packet_len], peer_addr) catch |err| {
            std.log.debug("Failed to send HTTP/3 response: {}", .{err});
        };
    }

    /// Build a QUIC short header packet containing a STREAM frame
    fn buildStreamPacket(
        _: *Server,
        conn: *quic_connection.Connection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
        out: []u8,
    ) !usize {
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
                .AGAIN, .INTR => return, // Not ready or interrupted, retry on next event
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
                        stack_ptr.* = http2.Stack.initWithConfig(.{
                            .max_streams = self.cfg.http2.max_streams,
                            .max_header_list_size = self.cfg.http2.max_header_list_size,
                            .initial_window_size = self.cfg.http2.initial_window_size,
                            .max_frame_size = self.cfg.http2.max_frame_size,
                            .max_dynamic_table_size = self.cfg.http2.max_dynamic_table_size,
                        });
                        conn.http2_stack = stack_ptr;
                    }
                    conn.protocol = .http2;
                    // RFC 9113 §3.4: Server MUST send SETTINGS as first frame
                    self.sendHttp2ServerPreface(conn) catch {
                        self.closeConnection(conn);
                        return;
                    };
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
            conn.is_head_request = (parse.view.method == .HEAD);
            // Reset sent_continue for each new request in pipelined connections
            conn.sent_continue = false;
            if (!parse.keep_alive) conn.close_after_write = true;
            self.io.onReadConsumed(conn, parse.consumed_bytes);

            // Validate Host header against allowed_hosts if configured
            if (self.cfg.allowed_hosts.len > 0) {
                const host_value = parse.view.getHeader("Host") orelse "";
                // Strip port from host for comparison
                const host_name = if (std.mem.indexOfScalar(u8, host_value, ':')) |colon|
                    host_value[0..colon]
                else
                    host_value;
                var host_allowed = false;
                for (self.cfg.allowed_hosts) |allowed| {
                    if (std.ascii.eqlIgnoreCase(host_name, allowed)) {
                        host_allowed = true;
                        break;
                    }
                }
                if (!host_allowed) {
                    conn.close_after_write = true;
                    try self.queueResponse(conn, badRequestResponse());
                    return;
                }
            }

            // Check for static file requests - use sendfile for zero-copy
            if (self.cfg.static_root.len > 0 and std.mem.startsWith(u8, parse.view.path, "/static/")) {
                const file_path = parse.view.path[8..]; // Skip "/static/"
                const content_type = guessContentType(file_path);
                try self.queueFileResponse(conn, self.cfg.static_root, file_path, content_type);
                if (conn.read_buffered_bytes == 0) break;
                continue;
            }

            // Check proxy routes before router dispatch
            if (self.proxy) |proxy| {
                if (proxy.matchRoute(&parse.view) != null) {
                    var mw_ctx = middleware.Context{
                        .protocol = .http1,
                        .buffer_ops = .{
                            .ctx = &self.io,
                            .acquire = acquireBufferOpaque,
                            .release = releaseBufferOpaque,
                        },
                    };
                    // Extract client IP string for proxy headers
                    var ip_buf: [64]u8 = undefined;
                    var client_ip_str: ?[]const u8 = null;
                    if (net.getPeerAddress(fd)) |peer| {
                        if (peer.getIp4Bytes()) |ip4| {
                            const ip_len = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch "";
                            if (ip_len.len > 0) client_ip_str = ip_buf[0..ip_len.len];
                        }
                    }
                    var proxy_result = proxy.handle(
                        parse.view,
                        &mw_ctx,
                        client_ip_str,
                        false, // TODO: detect TLS
                        self.io.nowMs(),
                    );
                    defer proxy_result.release();

                    try self.queueResponse(conn, proxy_result.resp);
                    if (conn.read_buffered_bytes == 0) break;
                    continue;
                }
            }

            var mw_ctx = middleware.Context{
                .protocol = .http1,
                .buffer_ops = .{
                    .ctx = &self.io,
                    .acquire = acquireBufferOpaque,
                    .release = releaseBufferOpaque,
                },
            };
            // Extract client IP from socket for rate limiting and logging
            if (net.getPeerAddress(fd)) |peer| {
                if (peer.getIp4Bytes()) |ip4| {
                    mw_ctx.client_ip = ip4;
                } else if (peer.getIp6Bytes()) |ip6| {
                    mw_ctx.client_ip6 = ip6;
                }
            }
            var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
            var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
            const arena_handle = self.io.acquireBuffer();
            var empty_arena: [0]u8 = undefined;
            const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
            var scratch = router.HandlerScratch{
                .response_buf = response_buf[0..],
                .response_headers = response_headers[0..],
                .arena_buf = arena_buf,
                .arena_handle = arena_handle,
                .buffer_ops = mw_ctx.buffer_ops,
            };
            const result = self.app_router.handle(parse.view, &mw_ctx, &scratch);
            if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
            // Apply rate limit backpressure if signaled
            if (result.pause_reads_ms) |pause_ms| {
                conn.setRateLimitPause(self.io.nowMs(), pause_ms);
            }
            try self.queueResponse(conn, result.resp);
            if (conn.read_buffered_bytes == 0) break;
        }
    }

    /// Send the HTTP/2 server connection preface (SETTINGS frame)
    fn sendHttp2ServerPreface(self: *Server, conn: *connection.Connection) !void {
        const buf = self.io.acquireBuffer() orelse return error.OutOfMemory;
        const len = http2.writeServerSettings(buf.bytes, .{
            .max_streams = self.cfg.http2.max_streams,
            .max_header_list_size = self.cfg.http2.max_header_list_size,
            .initial_window_size = self.cfg.http2.initial_window_size,
            .max_frame_size = self.cfg.http2.max_frame_size,
            .max_dynamic_table_size = self.cfg.http2.max_dynamic_table_size,
        }) catch {
            self.io.releaseBuffer(buf);
            return error.OutOfMemory;
        };
        if (!conn.enqueueWrite(buf, len)) {
            self.io.releaseBuffer(buf);
            return error.OutOfMemory;
        }
        self.io.onWriteBuffered(conn, len);
    }

    /// Send an HTTP/2 control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE, GOAWAY)
    fn sendHttp2ControlFrame(self: *Server, conn: *connection.Connection, frame_data: []const u8) void {
        const buf = self.io.acquireBuffer() orelse return;
        if (frame_data.len > buf.bytes.len) {
            self.io.releaseBuffer(buf);
            return;
        }
        @memcpy(buf.bytes[0..frame_data.len], frame_data);
        if (!conn.enqueueWrite(buf, frame_data.len)) {
            self.io.releaseBuffer(buf);
            return;
        }
        self.io.onWriteBuffered(conn, frame_data.len);
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
                // RFC 9113 §5.4.1: Send GOAWAY before closing on connection error
                var goaway_buf: [17]u8 = undefined;
                const goaway_len = http2.writeGoaway(&goaway_buf, stack.last_stream_id, 0x01) catch 0;
                if (goaway_len > 0) {
                    self.sendHttp2ControlFrame(conn, goaway_buf[0..goaway_len]);
                }
                self.closeConnection(conn);
                return;
            }
            self.io.onReadConsumed(conn, ingest.consumed_bytes);
            for (events[0..ingest.event_count]) |event| {
                switch (event) {
                    .headers => |hdr| {
                        var mw_ctx = middleware.Context{
                            .protocol = .http2,
                            .stream_id = hdr.stream_id,
                            .buffer_ops = .{
                                .ctx = &self.io,
                                .acquire = acquireBufferOpaque,
                                .release = releaseBufferOpaque,
                            },
                        };
                        // Extract client IP from socket for rate limiting and logging
                        if (conn.fd) |conn_fd| {
                            if (net.getPeerAddress(conn_fd)) |peer| {
                                if (peer.getIp4Bytes()) |ip4| {
                                    mw_ctx.client_ip = ip4;
                                } else if (peer.getIp6Bytes()) |ip6| {
                                    mw_ctx.client_ip6 = ip6;
                                }
                            }
                        }
                        var response_buf: [router.RESPONSE_BUF_SIZE]u8 = undefined;
                        var response_headers: [router.MAX_RESPONSE_HEADERS]response_mod.Header = undefined;
                        const arena_handle = self.io.acquireBuffer();
                        var empty_arena: [0]u8 = undefined;
                        const arena_buf = if (arena_handle) |handle| handle.bytes else empty_arena[0..];
                        var scratch = router.HandlerScratch{
                            .response_buf = response_buf[0..],
                            .response_headers = response_headers[0..],
                            .arena_buf = arena_buf,
                            .arena_handle = arena_handle,
                            .buffer_ops = mw_ctx.buffer_ops,
                        };
                        const resp = if (hdr.end_stream) blk: {
                            const result = self.app_router.handle(hdr.request, &mw_ctx, &scratch);
                            // Apply rate limit backpressure if signaled
                            if (result.pause_reads_ms) |pause_ms| {
                                conn.setRateLimitPause(self.io.nowMs(), pause_ms);
                            }
                            break :blk result.resp;
                        } else response_mod.Response{
                            .status = 501,
                            .headers = &[_]response_mod.Header{},
                            .body = .{ .bytes = "Not Implemented\n" },
                        };
                        if (scratch.arena_handle) |handle| self.io.releaseBuffer(handle);
                        try self.queueHttp2Response(conn, hdr.stream_id, resp);
                    },
                    .data => |data| {
                        _ = data;
                    },
                    .settings => |settings_event| {
                        if (!settings_event.ack) {
                            // RFC 9113 §6.5.3: MUST send SETTINGS ACK
                            var ack_buf: [9]u8 = undefined;
                            const ack_len = http2.writeSettingsAck(&ack_buf) catch 0;
                            if (ack_len > 0) {
                                self.sendHttp2ControlFrame(conn, ack_buf[0..ack_len]);
                            }
                        }
                    },
                    .ping => |ping_event| {
                        // RFC 9113 §6.7: MUST respond with PING ACK
                        var ping_buf: [17]u8 = undefined;
                        const ping_len = http2.writePingAck(&ping_buf, ping_event.opaque_data) catch 0;
                        if (ping_len > 0) {
                            self.sendHttp2ControlFrame(conn, ping_buf[0..ping_len]);
                        }
                    },
                    .window_update_needed => |wu| {
                        // RFC 9113 §6.9: Send WINDOW_UPDATE
                        var wu_buf: [13]u8 = undefined;
                        const wu_len = http2.writeWindowUpdate(&wu_buf, wu.stream_id, wu.increment) catch 0;
                        if (wu_len > 0) {
                            self.sendHttp2ControlFrame(conn, wu_buf[0..wu_len]);
                        }
                    },
                    .err => |_| {},
                }
            }
            if (conn.read_buffered_bytes == 0) break;
        }
    }

    fn handleWrite(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        const socket_fd = conn.fd orelse return;

        // Process buffer writes in a loop (edge-triggered epoll requires draining until EAGAIN)
        while (conn.peekWrite()) |entry| {
            const slice = entry.handle.bytes[entry.offset..entry.len];
            const bytes_written = std.posix.system.write(socket_fd, slice.ptr, slice.len);
            if (bytes_written < 0) {
                switch (std.posix.errno(bytes_written)) {
                    .AGAIN => return, // Socket not ready, wait for next event
                    .INTR => continue, // Interrupted by signal, retry
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

                // Continue streaming pending body if there's more data
                if (conn.hasPendingBody()) {
                    self.streamBodyChunks(conn, conn.pending_body);
                }
            }
        }

        // All buffer writes done, try sendfile if file is pending
        if (conn.hasPendingFile()) {
            // Use sendfile for file transfer
            const file_fd = conn.pending_file_fd.?;
            const result = net.sendfile(socket_fd, file_fd, &conn.pending_file_offset, conn.pending_file_remaining) catch |err| {
                switch (err) {
                    error.WouldBlock => return,
                    error.Closed, error.Failed => {
                        conn.cleanupPendingFile();
                        self.closeConnection(conn);
                        return;
                    },
                }
            };
            conn.pending_file_remaining -= result.bytes_sent;
            conn.markActive(self.io.nowMs());

            // Check if file transfer is complete
            if (conn.pending_file_remaining == 0) {
                conn.cleanupPendingFile();
            }
        }

        // Check if all writes are complete
        if (conn.write_count == 0 and !conn.hasPendingBody() and !conn.hasPendingFile()) {
            self.io.setTimeoutPhase(conn, .idle);
            if (conn.close_after_write) self.closeConnection(conn);
        }
    }

    fn handleError(self: *Server, index: u32) !void {
        const conn = self.io.getConnection(index) orelse return;
        self.closeConnection(conn);
    }

    fn queueResponse(self: *Server, conn: *connection.Connection, resp: response_mod.Response) !void {
        const body_len = resp.bodyLen();
        const body_bytes = resp.bodyBytes();
        const managed_body = switch (resp.body) {
            .managed => |managed| managed,
            else => null,
        };
        // RFC 9110 §9.3.2: HEAD response MUST NOT contain a message body
        const suppress_body = conn.is_head_request;
        const buf = self.io.acquireBuffer() orelse {
            // Cannot acquire buffer to send response - close connection
            if (managed_body) |managed| self.io.releaseBuffer(managed.handle);
            self.closeConnection(conn);
            return;
        };
        // Include Alt-Svc header to advertise HTTP/3 when QUIC is enabled
        const alt_svc: ?[]const u8 = if (self.alt_svc_len > 0)
            self.alt_svc_value[0..self.alt_svc_len]
        else
            null;

        if (managed_body) |managed| {
            if (body_len > managed.handle.bytes.len) {
                self.io.releaseBuffer(managed.handle);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write) catch {
                self.io.releaseBuffer(managed.handle);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            };
            if (!conn.enqueueWrite(buf, header_len)) {
                self.io.releaseBuffer(managed.handle);
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, header_len);

            if (body_len == 0 or suppress_body) {
                self.io.releaseBuffer(managed.handle);
                self.io.setTimeoutPhase(conn, .write);
                return;
            }
            if (!conn.enqueueWrite(managed.handle, body_len)) {
                self.io.releaseBuffer(managed.handle);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, body_len);
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        if (suppress_body) {
            // HEAD: send headers with Content-Length but no body
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write) catch {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            };
            if (!conn.enqueueWrite(buf, header_len)) {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, header_len);
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        // For large bodies that don't fit in a single buffer, write headers first then chunk body
        const header_space = 512; // Reserve space for headers
        if (body_len > buf.bytes.len - header_space) {
            // Write headers only first
            const header_len = encodeResponseHeaders(buf.bytes, resp, alt_svc, conn.close_after_write) catch {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            };
            if (!conn.enqueueWrite(buf, header_len)) {
                self.io.releaseBuffer(buf);
                self.closeConnection(conn);
                return;
            }
            self.io.onWriteBuffered(conn, header_len);

            // Stream body in chunks - only enqueue what fits, store rest for later
            self.streamBodyChunks(conn, body_bytes);
            self.io.setTimeoutPhase(conn, .write);
            return;
        }

        // Small response - write everything in one buffer
        const written = encodeResponse(buf.bytes, resp, alt_svc, conn.close_after_write) catch {
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

    /// Stream body data in chunks, enqueueing up to available queue slots.
    /// Remaining data is stored in conn.pending_body for later streaming.
    ///
    /// LIFETIME CONTRACT: `body` (and thus `conn.pending_body`) must point to
    /// memory that outlives the connection — typically compile-time string literals
    /// from handler responses (e.g., `body = .{ .bytes = "Hello" }`). The slice is
    /// never freed by the server; it is only read and copied into write buffers.
    /// Managed bodies (.managed) are written inline in queueResponse and never
    /// stored in pending_body.
    fn streamBodyChunks(self: *Server, conn: *connection.Connection, body: []const u8) void {
        var remaining = body;

        // Enqueue chunks while we have queue space (leave 1 slot for new requests)
        while (remaining.len > 0 and conn.writeQueueAvailable() > 1) {
            const body_buf = self.io.acquireBuffer() orelse {
                // No buffers available - store remaining and wait
                conn.pending_body = remaining;
                return;
            };
            const chunk_len = @min(remaining.len, body_buf.bytes.len);
            @memcpy(body_buf.bytes[0..chunk_len], remaining[0..chunk_len]);
            if (!conn.enqueueWrite(body_buf, chunk_len)) {
                self.io.releaseBuffer(body_buf);
                conn.pending_body = remaining;
                return;
            }
            self.io.onWriteBuffered(conn, chunk_len);
            remaining = remaining[chunk_len..];
        }

        // Store any remaining data for continuation in handleWrite
        conn.pending_body = remaining;
    }

    /// Queue a file response using sendfile for zero-copy transfer.
    /// Sends HTTP headers first, then sets up the connection for sendfile.
    fn queueFileResponse(self: *Server, conn: *connection.Connection, static_root: []const u8, file_path: []const u8, content_type: []const u8) !void {
        // Reject paths containing percent-encoded sequences to prevent URL-encoded
        // path traversal (e.g., %2e%2e bypassing the ".." check below)
        if (std.mem.indexOfScalar(u8, file_path, '%') != null) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        // Prevent path traversal attacks — reject ".." components
        if (std.mem.indexOf(u8, file_path, "..") != null) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        // Reject paths with null bytes
        if (std.mem.indexOfScalar(u8, file_path, 0) != null) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }

        // Build full path: static_root + "/" + file_path
        var path_buf: [4096]u8 = undefined;
        const full_path_len = static_root.len + 1 + file_path.len;
        if (full_path_len >= path_buf.len) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        @memcpy(path_buf[0..static_root.len], static_root);
        path_buf[static_root.len] = '/';
        @memcpy(path_buf[static_root.len + 1 ..][0..file_path.len], file_path);
        path_buf[full_path_len] = 0;
        const path_z: [*:0]const u8 = @ptrCast(&path_buf);

        // Open file using C library for portability — use O_NOFOLLOW to prevent symlink traversal
        const c = @cImport({
            @cInclude("fcntl.h");
            @cInclude("sys/stat.h");
        });
        const file_fd_c = c.open(path_z, c.O_RDONLY | c.O_NOFOLLOW);
        if (file_fd_c < 0) {
            try self.queueResponse(conn, notFoundResponse());
            return;
        }
        const file_fd: std.posix.fd_t = @intCast(file_fd_c);

        // Verify the resolved file is still under static_root using fstat to check it's a regular file
        var stat_buf_check: c.struct_stat = undefined;
        if (c.fstat(file_fd_c, &stat_buf_check) != 0 or (stat_buf_check.st_mode & c.S_IFMT) != c.S_IFREG) {
            std.posix.close(file_fd);
            try self.queueResponse(conn, notFoundResponse());
            return;
        }

        const file_size: u64 = @intCast(stat_buf_check.st_size);

        // Build and send headers
        const buf = self.io.acquireBuffer() orelse {
            std.posix.close(file_fd);
            self.closeConnection(conn);
            return;
        };

        var size_buf: [20]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{file_size}) catch {
            self.io.releaseBuffer(buf);
            std.posix.close(file_fd);
            self.closeConnection(conn);
            return;
        };

        const headers = [_]response_mod.Header{
            .{ .name = "Content-Type", .value = content_type },
            .{ .name = "Content-Length", .value = size_str },
        };

        const header_len = encodeFileHeaders(buf.bytes, 200, &headers) catch {
            self.io.releaseBuffer(buf);
            std.posix.close(file_fd);
            self.closeConnection(conn);
            return;
        };

        if (!conn.enqueueWrite(buf, header_len)) {
            self.io.releaseBuffer(buf);
            std.posix.close(file_fd);
            self.closeConnection(conn);
            return;
        }
        self.io.onWriteBuffered(conn, header_len);

        // Set up sendfile - file body will be sent after headers
        conn.pending_file_fd = file_fd;
        conn.pending_file_offset = 0;
        conn.pending_file_remaining = file_size;

        self.io.setTimeoutPhase(conn, .write);
    }

    fn queueHttp2Response(self: *Server, conn: *connection.Connection, stream_id: u32, resp: response_mod.Response) !void {
        const body_len = resp.bodyLen();
        const body_bytes = resp.bodyBytes();
        const managed_body = switch (resp.body) {
            .managed => |managed| managed,
            else => null,
        };
        defer if (managed_body) |managed| self.io.releaseBuffer(managed.handle);
        const header_buf = self.io.acquireBuffer() orelse {
            self.closeConnection(conn);
            return;
        };
        // Build headers array with Alt-Svc if enabled
        var headers_with_alt_svc: [65]response_mod.Header = undefined;
        var header_count = resp.headers.len;
        for (resp.headers, 0..) |h, i| {
            headers_with_alt_svc[i] = h;
        }
        // Add Alt-Svc header to advertise HTTP/3
        if (self.alt_svc_len > 0 and header_count < headers_with_alt_svc.len) {
            headers_with_alt_svc[header_count] = .{
                .name = "alt-svc",
                .value = self.alt_svc_value[0..self.alt_svc_len],
            };
            header_count += 1;
        }
        const header_block_len = http2.encodeResponseHeaders(header_buf.bytes[9..], resp.status, headers_with_alt_svc[0..header_count], body_len) catch {
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
        const headers_flags: u8 = if (body_len == 0) 0x5 else 0x4;
        // RFC 9113 §8.1: Response MUST be on the stream that carried the request
        const resp_stream_id: u32 = stream_id;
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

        if (body_len == 0) {
            // END_STREAM was set on HEADERS frame — stream is fully closed
            if (conn.http2_stack) |stack| stack.closeStream(resp_stream_id);
            return;
        }
        var remaining = body_bytes;
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
        // END_STREAM was set on last DATA frame — stream is fully closed
        if (conn.http2_stack) |stack| stack.closeStream(resp_stream_id);
    }

    fn encodeResponse(buf: []u8, resp: response_mod.Response, alt_svc: ?[]const u8, connection_close: bool) !usize {
        var index: usize = 0;
        const reason = reasonPhrase(resp.status);
        const status_line = try std.fmt.bufPrint(buf[index..], "HTTP/1.1 {d} {s}\r\n", .{ resp.status, reason });
        index += status_line.len;
        const body_bytes = resp.bodyBytes();

        // RFC 9110 §15.2: 1xx responses have no body, no Date, no Content-Length
        if (resp.status >= 100 and resp.status < 200) {
            if (index + 2 > buf.len) return error.NoSpaceLeft;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            index += 2;
            return index;
        }

        for (resp.headers) |header| {
            const header_line = try std.fmt.bufPrint(buf[index..], "{s}: {s}\r\n", .{ header.name, header.value });
            index += header_line.len;
        }
        // RFC 9110 §6.6.1: Origin servers MUST send Date header in responses
        // RFC 9110 §5.6.7: Date must be in IMF-fixdate format
        var date_buf: [29]u8 = undefined;
        const date_str = formatImfDate(&date_buf);
        const date_line = try std.fmt.bufPrint(buf[index..], "Date: {s}\r\n", .{date_str});
        index += date_line.len;
        // Add Alt-Svc header to advertise HTTP/3 availability
        if (alt_svc) |svc| {
            if (svc.len > 0) {
                const alt_svc_line = try std.fmt.bufPrint(buf[index..], "Alt-Svc: {s}\r\n", .{svc});
                index += alt_svc_line.len;
            }
        }
        // RFC 9112 §9.6: Signal connection close to the client
        if (connection_close) {
            const close_line = try std.fmt.bufPrint(buf[index..], "Connection: close\r\n", .{});
            index += close_line.len;
        }
        // RFC 9110 §8.6: MUST NOT send Content-Length in 204 or 304 responses
        if (resp.status == 204 or resp.status == 304) {
            if (index + 2 > buf.len) return error.NoSpaceLeft;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            index += 2;
            return index;
        }
        const length_line = try std.fmt.bufPrint(buf[index..], "Content-Length: {d}\r\n\r\n", .{body_bytes.len});
        index += length_line.len;
        if (index + body_bytes.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[index .. index + body_bytes.len], body_bytes);
        index += body_bytes.len;
        return index;
    }

    /// Encode response headers only (for large body responses that need chunking)
    fn encodeResponseHeaders(buf: []u8, resp: response_mod.Response, alt_svc: ?[]const u8, connection_close: bool) !usize {
        var index: usize = 0;
        const reason = reasonPhrase(resp.status);
        const status_line = try std.fmt.bufPrint(buf[index..], "HTTP/1.1 {d} {s}\r\n", .{ resp.status, reason });
        index += status_line.len;
        const body_len = resp.bodyLen();
        for (resp.headers) |header| {
            const header_line = try std.fmt.bufPrint(buf[index..], "{s}: {s}\r\n", .{ header.name, header.value });
            index += header_line.len;
        }
        // RFC 9110 §15.2: 1xx responses have no body, no Date, no Content-Length
        if (resp.status >= 100 and resp.status < 200) {
            if (index + 2 > buf.len) return error.NoSpaceLeft;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            index += 2;
            return index;
        }
        // RFC 9110 §6.6.1: Origin servers MUST send Date header
        var date_buf: [29]u8 = undefined;
        const date_str = formatImfDate(&date_buf);
        const date_line = try std.fmt.bufPrint(buf[index..], "Date: {s}\r\n", .{date_str});
        index += date_line.len;
        if (alt_svc) |svc| {
            if (svc.len > 0) {
                const alt_svc_line = try std.fmt.bufPrint(buf[index..], "Alt-Svc: {s}\r\n", .{svc});
                index += alt_svc_line.len;
            }
        }
        // RFC 9112 §9.6: Signal connection close to the client
        if (connection_close) {
            const close_line = try std.fmt.bufPrint(buf[index..], "Connection: close\r\n", .{});
            index += close_line.len;
        }
        // RFC 9110 §8.6: MUST NOT send Content-Length in 204 or 304 responses
        if (resp.status == 204 or resp.status == 304) {
            if (index + 2 > buf.len) return error.NoSpaceLeft;
            buf[index] = '\r';
            buf[index + 1] = '\n';
            index += 2;
            return index;
        }
        const length_line = try std.fmt.bufPrint(buf[index..], "Content-Length: {d}\r\n\r\n", .{body_len});
        index += length_line.len;
        return index;
    }

    /// Encode HTTP/1.1 response headers for file responses (doesn't add Content-Length)
    fn encodeFileHeaders(buf: []u8, status: u16, headers: []const response_mod.Header) !usize {
        var index: usize = 0;
        const reason = reasonPhrase(status);
        const status_line = try std.fmt.bufPrint(buf[index..], "HTTP/1.1 {d} {s}\r\n", .{ status, reason });
        index += status_line.len;
        for (headers) |header| {
            const header_line = try std.fmt.bufPrint(buf[index..], "{s}: {s}\r\n", .{ header.name, header.value });
            index += header_line.len;
        }
        // RFC 9110 §6.6.1: Origin servers MUST send Date header
        var date_buf: [29]u8 = undefined;
        const date_str = formatImfDate(&date_buf);
        const file_date_line = try std.fmt.bufPrint(buf[index..], "Date: {s}\r\n", .{date_str});
        index += file_date_line.len;
        // End headers
        if (index + 2 > buf.len) return error.NoSpaceLeft;
        buf[index] = '\r';
        buf[index + 1] = '\n';
        index += 2;
        return index;
    }

    fn reasonPhrase(status: u16) []const u8 {
        return response_mod.statusPhrase(status);
    }

    /// Format current time as IMF-fixdate (RFC 9110 §5.6.7)
    /// e.g., "Sun, 06 Nov 1994 08:49:37 GMT"
    fn formatImfDate(buf: *[29]u8) []const u8 {
        const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
        const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        const ts = std.posix.clock_gettime(.REALTIME) catch return "Thu, 01 Jan 1970 00:00:00 GMT";
        const epoch_secs: u64 = @intCast(ts.sec);

        // Calculate date components from Unix timestamp
        const secs_per_day: u64 = 86400;
        var days = epoch_secs / secs_per_day;
        const day_secs = epoch_secs % secs_per_day;
        const hour = day_secs / 3600;
        const minute = (day_secs % 3600) / 60;
        const second = day_secs % 60;

        // Day of week (Jan 1 1970 = Thursday = index 0)
        const wday = days % 7;

        // Year/month/day from days since epoch
        var year: u64 = 1970;
        while (true) {
            const days_in_year: u64 = if (isLeapYear(year)) 366 else 365;
            if (days < days_in_year) break;
            days -= days_in_year;
            year += 1;
        }
        const leap = isLeapYear(year);
        const month_days = if (leap)
            [_]u64{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
        else
            [_]u64{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        var month: usize = 0;
        while (month < 11) : (month += 1) {
            if (days < month_days[month]) break;
            days -= month_days[month];
        }
        const day = days + 1;

        // Format: "Sun, 06 Nov 1994 08:49:37 GMT"
        _ = std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
            day_names[wday],
            day,
            month_names[month],
            year,
            hour,
            minute,
            second,
        }) catch return "Thu, 01 Jan 1970 00:00:00 GMT";
        return buf[0..29];
    }

    fn isLeapYear(year: u64) bool {
        return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
    }

    fn continueResponse() response_mod.Response {
        return .{
            .status = 100,
            .headers = &[_]response_mod.Header{},
            .body = .none,
        };
    }

    fn notFoundResponse() response_mod.Response {
        return .{
            .status = 404,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Not Found\n" },
        };
    }

    fn badRequestResponse() response_mod.Response {
        return .{
            .status = 400,
            .headers = &[_]response_mod.Header{},
            .body = .{ .bytes = "Bad Request\n" },
        };
    }

    /// Guess Content-Type from file extension
    fn guessContentType(path: []const u8) []const u8 {
        if (std.mem.endsWith(u8, path, ".html") or std.mem.endsWith(u8, path, ".htm")) {
            return "text/html";
        } else if (std.mem.endsWith(u8, path, ".css")) {
            return "text/css";
        } else if (std.mem.endsWith(u8, path, ".js")) {
            return "application/javascript";
        } else if (std.mem.endsWith(u8, path, ".json")) {
            return "application/json";
        } else if (std.mem.endsWith(u8, path, ".png")) {
            return "image/png";
        } else if (std.mem.endsWith(u8, path, ".jpg") or std.mem.endsWith(u8, path, ".jpeg")) {
            return "image/jpeg";
        } else if (std.mem.endsWith(u8, path, ".gif")) {
            return "image/gif";
        } else if (std.mem.endsWith(u8, path, ".svg")) {
            return "image/svg+xml";
        } else if (std.mem.endsWith(u8, path, ".txt")) {
            return "text/plain";
        } else if (std.mem.endsWith(u8, path, ".pdf")) {
            return "application/pdf";
        } else if (std.mem.endsWith(u8, path, ".wasm")) {
            return "application/wasm";
        } else {
            return "application/octet-stream";
        }
    }

    fn errorResponseFor(code: http1.ErrorCode) response_mod.Response {
        return switch (code) {
            .body_too_large => .{
                .status = 413,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Payload Too Large\n" },
            },
            .header_too_large => .{
                .status = 431,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Request Header Fields Too Large\n" },
            },
            .expectation_failed => .{
                .status = 417,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Expectation Failed\n" },
            },
            else => .{
                .status = 400,
                .headers = &[_]response_mod.Header{},
                .body = .{ .bytes = "Bad Request\n" },
            },
        };
    }

    fn closeConnection(self: *Server, conn: *connection.Connection) void {
        if (conn.fd) |fd| {
            _ = self.io.unregister(fd) catch {};
            std.posix.close(fd);
            conn.fd = null;
        }
        if (conn.http2_stack) |stack| {
            self.allocator.destroy(stack);
            conn.http2_stack = null;
        }
        // Drain write queue before releasing read buffer to avoid double-free
        // if a buffer handle appears in both places
        while (conn.peekWrite()) |entry| {
            self.io.releaseBuffer(entry.handle);
            conn.popWrite();
        }
        if (conn.read_buffer) |buf| {
            self.io.releaseBuffer(buf);
            conn.read_buffer = null;
        }
        // Clean up pending file descriptor and body reference
        conn.cleanupPendingFile();
        conn.pending_body = &[_]u8{};
        self.io.releaseConnection(conn);
    }

    fn matchesHttp2Preface(candidate: []const u8) bool {
        const n = if (candidate.len < http2.Preface.len) candidate.len else http2.Preface.len;
        return std.mem.eql(u8, candidate[0..n], http2.Preface[0..n]);
    }
};

test "metrics middleware response queued for http1" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    const req = request.RequestView{
        .method = .GET,
        .path = "/metrics",
        .headers = &[_]request.Header{},
        .body = "",
    };

    var mw_ctx = middleware.Context{
        .protocol = .http1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
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

    const result = server.app_router.handle(req, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const managed = switch (result.resp.body) {
        .managed => |m| m,
        else => return error.UnexpectedBody,
    };

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    try server.queueResponse(conn, result.resp);
    try std.testing.expectEqual(@as(u8, 2), conn.write_count);

    const header_entry = conn.peekWrite().?.*;
    conn.popWrite();
    const body_entry = conn.peekWrite().?.*;
    conn.popWrite();

    try std.testing.expectEqual(managed.handle.index, body_entry.handle.index);
    try std.testing.expectEqualStrings(result.resp.bodyBytes(), body_entry.handle.bytes[0..body_entry.len]);

    server.io.releaseBuffer(header_entry.handle);
    server.io.releaseBuffer(body_entry.handle);
}

test "metrics middleware response queued for http2" {
    if (!build_options.enable_http2) return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    const req = request.RequestView{
        .method = .GET,
        .path = "/metrics",
        .headers = &[_]request.Header{},
        .body = "",
    };

    var mw_ctx = middleware.Context{
        .protocol = .http2,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
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

    const result = server.app_router.handle(req, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const managed = switch (result.resp.body) {
        .managed => |m| m,
        else => return error.UnexpectedBody,
    };

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);
    conn.protocol = .http2;

    try server.queueHttp2Response(conn, 1, result.resp);
    try std.testing.expect(conn.write_count >= 2);

    const expected = result.resp.bodyBytes();
    var found_data = false;
    var saw_managed_handle = false;

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        const frame_type = entry.handle.bytes[3];
        if (entry.handle.index == managed.handle.index) {
            saw_managed_handle = true;
        }
        if (frame_type == @intFromEnum(http2.FrameType.data)) {
            const len = (@as(usize, entry.handle.bytes[0]) << 16) |
                (@as(usize, entry.handle.bytes[1]) << 8) |
                @as(usize, entry.handle.bytes[2]);
            try std.testing.expectEqualStrings(expected, entry.handle.bytes[9 .. 9 + len]);
            found_data = true;
        }
        server.io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    try std.testing.expect(found_data);
    try std.testing.expect(!saw_managed_handle);
}

test "metrics middleware end-to-end http1" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    const raw = "GET /metrics HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var headers: [8]request.Header = undefined;
    var buf: [128]u8 = undefined;
    @memcpy(buf[0..raw.len], raw);
    const parse = http1.parse(buf[0..raw.len], .{
        .max_header_bytes = 256,
        .max_body_bytes = 1024,
        .max_header_count = headers.len,
        .headers_storage = headers[0..],
    });
    try std.testing.expectEqual(http1.ParseState.complete, parse.state);

    var mw_ctx = middleware.Context{
        .protocol = .http1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
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

    const result = server.app_router.handle(parse.view, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const managed = switch (result.resp.body) {
        .managed => |m| m,
        else => return error.UnexpectedBody,
    };

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    try server.queueResponse(conn, result.resp);
    try std.testing.expectEqual(@as(u8, 2), conn.write_count);

    const header_entry = conn.peekWrite().?.*;
    conn.popWrite();
    const body_entry = conn.peekWrite().?.*;
    conn.popWrite();

    try std.testing.expectEqual(managed.handle.index, body_entry.handle.index);
    try std.testing.expectEqualStrings(result.resp.bodyBytes(), body_entry.handle.bytes[0..body_entry.len]);

    server.io.releaseBuffer(header_entry.handle);
    server.io.releaseBuffer(body_entry.handle);
}

test "metrics middleware end-to-end http2" {
    if (!build_options.enable_http2) return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    var app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    const chain = middleware.Chain.init(&.{metrics_mw.evaluate}, &.{});
    app_router.setMiddleware(chain);

    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    metrics_mw.getStore().* = .{};

    var stack = http2.Stack.init();
    var frames: [8]http2.Frame = undefined;
    var events: [8]http2.Event = undefined;
    var header_block_buf: [128]u8 = undefined;
    const header_block = buildHeaderBlockAuthority(&header_block_buf, "example.com");

    var input_buf: [256]u8 = undefined;
    var idx: usize = 0;
    @memcpy(input_buf[idx .. idx + http2.Preface.len], http2.Preface);
    idx += http2.Preface.len;
    http2.writeFrameHeader(input_buf[idx..], .headers, 0x5, 1, header_block.len) catch return error.BufferTooSmall;
    idx += 9;
    @memcpy(input_buf[idx .. idx + header_block.len], header_block);
    idx += header_block.len;

    const ingest = stack.ingest(input_buf[0..idx], frames[0..], events[0..]);
    try std.testing.expectEqual(http2.ParseState.complete, ingest.state);
    try std.testing.expect(ingest.event_count > 0);

    var req_view: ?request.RequestView = null;
    for (events[0..ingest.event_count]) |event| {
        if (event == .headers) {
            req_view = event.headers.request;
        }
    }
    const view = req_view orelse return error.UnexpectedDecision;

    var mw_ctx = middleware.Context{
        .protocol = .http2,
        .stream_id = 1,
        .buffer_ops = .{
            .ctx = &server.io,
            .acquire = acquireBufferOpaque,
            .release = releaseBufferOpaque,
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

    const result = server.app_router.handle(view, &mw_ctx, &scratch);
    if (scratch.arena_handle) |handle| server.io.releaseBuffer(handle);
    try std.testing.expect(result.resp.bodyLen() > 0);

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);
    conn.protocol = .http2;
    conn.http2_stack = &stack;

    try server.queueHttp2Response(conn, 1, result.resp);
    try std.testing.expect(conn.write_count >= 2);

    const expected = result.resp.bodyBytes();
    var collected = try std.testing.allocator.alloc(u8, expected.len);
    defer std.testing.allocator.free(collected);
    var collected_len: usize = 0;

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        const frame_type = entry.handle.bytes[3];
        if (frame_type == @intFromEnum(http2.FrameType.data)) {
            const len = (@as(usize, entry.handle.bytes[0]) << 16) |
                (@as(usize, entry.handle.bytes[1]) << 8) |
                @as(usize, entry.handle.bytes[2]);
            @memcpy(collected[collected_len .. collected_len + len], entry.handle.bytes[9 .. 9 + len]);
            collected_len += len;
        }
        server.io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    try std.testing.expectEqual(expected.len, collected_len);
    try std.testing.expectEqualStrings(expected, collected[0..collected_len]);
}

fn buildHeaderBlockAuthority(buffer: []u8, authority: []const u8) []u8 {
    var idx: usize = 0;
    buffer[idx] = 0x82; // :method GET (static index 2)
    idx += 1;
    buffer[idx] = 0x84; // :path / (static index 4)
    idx += 1;
    buffer[idx] = 0x86; // :scheme http (static index 6)
    idx += 1;
    buffer[idx] = 0x01; // literal without indexing, indexed name :authority (index 1)
    idx += 1;
    buffer[idx] = @intCast(authority.len);
    idx += 1;
    @memcpy(buffer[idx .. idx + authority.len], authority);
    idx += authority.len;
    return buffer[0..idx];
}

test "http1 response bytes from write queue" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    const app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    const resp = response_mod.Response{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .bytes = "hi" },
    };

    try server.queueResponse(conn, resp);
    const bytes = try drainWriteQueue(&server.io, conn, allocator);
    defer allocator.free(bytes);

    // Verify structural correctness (Date header is dynamic so check components)
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Date: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 2\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhi"));
}

test "http1 managed response bytes from write queue" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.ServerConfig.default();
    cfg.max_connections = 1;

    cfg.buffer_pool = .{
        .buffer_size = 16 * 1024,
        .buffer_count = 4,
    };

    const app_router = router.Router.init(.{
        .require_payment = false,
        .payment_required_b64 = "",
    });
    var server = try Server.initWithRouter(allocator, cfg, app_router);
    defer server.deinit();

    const handle = server.io.acquireBuffer() orelse return error.OutOfMemory;
    const body = "hello";
    @memcpy(handle.bytes[0..body.len], body);

    const resp = response_mod.Response{
        .status = 200,
        .headers = &[_]response_mod.Header{
            .{ .name = "Content-Type", .value = "text/plain" },
        },
        .body = .{ .managed = .{ .handle = handle, .len = body.len } },
    };

    const conn = server.io.acquireConnection(server.io.nowMs()) orelse return error.OutOfMemory;
    defer if (conn.state != .closed) server.io.releaseConnection(conn);

    try server.queueResponse(conn, resp);
    const bytes = try drainWriteQueue(&server.io, conn, allocator);
    defer allocator.free(bytes);

    // Verify structural correctness (Date header is dynamic so check components)
    try std.testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Date: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nhello"));
}

fn drainWriteQueue(io: *runtime.IoRuntime, conn: *connection.Connection, allocator: std.mem.Allocator) ![]u8 {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);

    while (conn.peekWrite()) |entry_ptr| {
        const entry = entry_ptr.*;
        try list.appendSlice(allocator, entry.handle.bytes[entry.offset..entry.len]);
        io.releaseBuffer(entry.handle);
        conn.popWrite();
    }

    return list.toOwnedSlice(allocator);
}

fn acquireBufferOpaque(ctx: *anyopaque) ?buffer_pool.BufferHandle {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    return io.acquireBuffer();
}

fn releaseBufferOpaque(ctx: *anyopaque, handle: buffer_pool.BufferHandle) void {
    const io: *runtime.IoRuntime = @ptrCast(@alignCast(ctx));
    io.releaseBuffer(handle);
}

pub fn registerDefaultRoutes(app_router: *router.Router) !void {
    // Register built-in benchmark endpoints
    try app_router.get("/health", handleBenchHealth);
    try app_router.get("/echo", handleBenchEchoGet);
    try app_router.post("/echo", handleBenchEchoPost);
    try app_router.get("/blob", handleBenchBlob);
    // TechEmpower Framework Benchmark endpoints
    try app_router.get("/plaintext", handleTfbPlaintext);
    try app_router.get("/json", handleTfbJson);
}

// ============================================================
// Benchmark Handlers
// Built-in endpoints for performance testing
// ============================================================

/// 1MB static blob for large response benchmarks
/// Tests streaming response capability
const benchmark_blob: [1024 * 1024]u8 = [_]u8{0} ** (1024 * 1024);

/// GET /health - minimal health check for benchmarks
    fn handleBenchHealth(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{},
            .body = .none,
        };
    }

/// GET /echo - return static JSON response
    fn handleBenchEchoGet(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = "{\"status\":\"ok\"}" },
        };
    }

/// POST /echo - echo back request body
fn handleBenchEchoPost(ctx: *router.HandlerContext) response_mod.Response {
    const body = ctx.request.body;
    if (body.len == 0) {
        return handleBenchEchoGet(ctx);
    }
    var builder = ctx.respond() catch return .{
        .status = 503,
        .headers = &[_]response_mod.Header{},
        .body = .{ .bytes = "No buffers available\n" },
    };
    defer ctx.releaseBuilder(&builder);
    return builder.json(200, body) catch .{
        .status = 413,
        .headers = &[_]response_mod.Header{},
        .body = .{ .bytes = "Payload Too Large\n" },
    };
}

/// GET /blob - return 1MB response for throughput testing
    fn handleBenchBlob(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/octet-stream" },
            },
            .body = .{ .bytes = &benchmark_blob },
        };
    }

// ============================================================
// TechEmpower Framework Benchmark Handlers
// https://www.techempower.com/benchmarks/
// ============================================================

/// GET /plaintext - TechEmpower plaintext test
    fn handleTfbPlaintext(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
            },
            .body = .{ .bytes = "Hello, World!" },
        };
    }

/// GET /json - TechEmpower JSON serialization test
    fn handleTfbJson(_: *router.HandlerContext) response_mod.Response {
        return .{
            .status = 200,
            .headers = &[_]response_mod.Header{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = .{ .bytes = "{\"message\":\"Hello, World!\"}" },
        };
    }
