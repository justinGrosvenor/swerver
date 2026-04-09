const std = @import("std");
const types = @import("types.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const connection = @import("connection.zig");
pub const connection_pool = @import("connection_pool.zig");
const stream = @import("stream.zig");
const recovery = @import("recovery.zig");
const congestion = @import("congestion.zig");
const crypto = @import("crypto.zig");
const http3 = @import("../protocol/http3.zig");
const metrics_mw = @import("../middleware/metrics_mw.zig");
const build_options = @import("build_options");
const test_utils = @import("test_utils.zig");

/// QUIC packet handler
///
/// Processes incoming QUIC datagrams and produces responses.

pub const Error = error{
    InvalidPacket,
    ConnectionNotFound,
    HandshakeFailed,
    ProtocolError,
    OutOfMemory,
    DecryptionFailed,
};

/// Result of processing a packet
pub const ProcessResult = struct {
    /// Response data to send (if any)
    response: ?[]const u8 = null,
    /// Connection that handled the packet
    conn: ?*connection.Connection = null,
    /// New connection was created
    new_connection: bool = false,
    /// Connection should be closed
    close_connection: bool = false,
    /// HTTP/3 events generated (headers received, data received, etc.)
    http3_events: []http3.Event = &.{},
};

/// Server-wide QUIC metrics
pub const metrics = @import("metrics.zig");

/// QUIC Handler for processing packets
pub const Handler = struct {
    allocator: std.mem.Allocator,
    pool: connection_pool.ConnectionPool,
    /// Buffer for building response packets
    response_buffer: [2048]u8 = undefined,
    /// Is this a server handler?
    is_server: bool,
    /// Server-wide metrics
    server_metrics: metrics.ServerMetrics = .{},

    pub fn init(allocator: std.mem.Allocator, is_server: bool, max_connections: usize) Handler {
        return .{
            .allocator = allocator,
            .pool = connection_pool.ConnectionPool.init(allocator, is_server, max_connections),
            .is_server = is_server,
        };
    }

    /// Get server-wide metrics
    pub fn getMetrics(self: *const Handler) *const metrics.ServerMetrics {
        return &self.server_metrics;
    }

    pub fn deinit(self: *Handler) void {
        self.pool.deinit();
    }

    /// Process an incoming QUIC datagram
    pub fn processPacket(
        self: *Handler,
        data: []const u8,
        peer_addr: connection_pool.SockAddrStorage,
    ) Error!ProcessResult {
        var result = ProcessResult{};

        // Parse packet header
        const parse_result = packet.parseHeader(data, 8); // Assume 8-byte CIDs
        if (parse_result.state != .complete) {
            return Error.InvalidPacket;
        }

        const header = parse_result.header orelse return Error.InvalidPacket;

        // Find or create connection
        var conn: *connection.Connection = undefined;

        switch (header) {
            .long => |long| {
                // Try to find by DCID first
                if (self.pool.findByCid(long.dcid)) |c| {
                    conn = c;
                } else if (long.packet_type == .initial and self.is_server) {
                    // Create new connection for Initial packet
                    conn = self.pool.createConnection(long.dcid, peer_addr) catch |err| {
                        return switch (err) {
                            connection_pool.Error.OutOfMemory => Error.OutOfMemory,
                            else => Error.ConnectionNotFound,
                        };
                    };
                    result.new_connection = true;
                    // Record new QUIC connection attempt
                    metrics_mw.getStore().recordQuicConnectionAttempt();
                } else {
                    return Error.ConnectionNotFound;
                }

                // Process based on packet type
                switch (long.packet_type) {
                    .initial => {
                        try self.handleInitialPacket(conn, long, data);
                        result.response = try self.buildInitialResponse(conn);
                    },
                    .handshake => {
                        try self.handleHandshakePacket(conn, long, data);
                    },
                    .zero_rtt => {
                        // 0-RTT early data
                        if (conn.crypto_ctx.canAcceptEarlyData()) {
                            try self.handleZeroRttPacket(conn, long, data);
                            result.http3_events = getHttp3Events(conn);
                        }
                        // If early data not accepted, packet is silently dropped
                    },
                    .retry => {
                        // Retry handling (client-side)
                    },
                }
            },
            .short => |short| {
                // Find connection by DCID
                conn = self.pool.findByCid(short.dcid) orelse {
                    return Error.ConnectionNotFound;
                };

                try self.handleShortPacket(conn, short, data);

                // Collect HTTP/3 events after processing
                result.http3_events = getHttp3Events(conn);
            },
        }

        result.conn = conn;
        result.close_connection = !conn.isAlive();

        // Record packet received
        metrics_mw.getStore().recordQuicPackets(0, 1, 0);

        return result;
    }

    fn handleInitialPacket(
        self: *Handler,
        conn: *connection.Connection,
        header: packet.LongHeader,
        data: []const u8,
    ) Error!void {
        _ = self;

        // Update peer's connection ID
        if (header.scid.len > 0) {
            conn.peer_cid = header.scid;
        }

        // Get Initial keys for decryption
        const keys_opt: ?crypto.Keys = if (conn.is_server)
            conn.crypto_ctx.initial.client // Decrypt with client's key
        else
            conn.crypto_ctx.initial.server; // Decrypt with server's key
        const keys = keys_opt orelse return Error.HandshakeFailed;

        // Decrypt and process Initial packet
        try processEncryptedPacket(conn, &keys, header, data, types.PacketNumberSpace.initial);

        // Transition state
        if (conn.state == .initial) {
            conn.state = .handshaking;
        }

        // Advance TLS handshake if session exists
        if (conn.tls_session != null) {
            const handshake_complete = conn.advanceTlsHandshake() catch false;
            if (handshake_complete) {
                conn.onHandshakeComplete();
                // Record handshake completion in global metrics
                metrics_mw.getStore().recordQuicHandshakeComplete(conn.conn_metrics.handshakeLatencyMs());
            }
        }
    }

    fn handleHandshakePacket(
        self: *Handler,
        conn: *connection.Connection,
        header: packet.LongHeader,
        data: []const u8,
    ) Error!void {
        _ = self;

        // Get Handshake keys for decryption
        const keys_opt: ?crypto.Keys = if (conn.is_server)
            conn.crypto_ctx.handshake.client
        else
            conn.crypto_ctx.handshake.server;
        const keys = keys_opt orelse {
            // No handshake keys yet - this is expected early in handshake
            return Error.HandshakeFailed;
        };

        // Decrypt and process Handshake packet
        try processEncryptedPacket(conn, &keys, header, data, types.PacketNumberSpace.handshake);

        // Advance TLS handshake
        if (conn.tls_session != null) {
            const handshake_complete = conn.advanceTlsHandshake() catch false;
            if (handshake_complete and conn.state == .handshaking) {
                conn.onHandshakeComplete();
                // Record handshake completion in global metrics
                metrics_mw.getStore().recordQuicHandshakeComplete(conn.conn_metrics.handshakeLatencyMs());
            }
        }
    }

    /// Handle 0-RTT packet (early data)
    fn handleZeroRttPacket(
        self: *Handler,
        conn: *connection.Connection,
        header: packet.LongHeader,
        data: []const u8,
    ) Error!void {
        _ = self;

        // 0-RTT packets are only sent by clients, so server decrypts with client key
        const keys = conn.crypto_ctx.early_data.client orelse {
            return Error.DecryptionFailed;
        };

        // Decrypt and process 0-RTT packet
        // 0-RTT uses the same packet number space as application data
        try processEncryptedPacket(conn, &keys, header, data, types.PacketNumberSpace.application);

        // Mark that we've accepted early data
        conn.early_data_received = true;
    }

    /// Process an encrypted long header packet (Initial or Handshake)
    fn processEncryptedPacket(
        conn: *connection.Connection,
        keys: *const crypto.Keys,
        header: packet.LongHeader,
        data: []const u8,
        pn_space: types.PacketNumberSpace,
    ) Error!void {
        const pn_offset = header.packet_number_offset;
        // RFC 9000 §17.2: Length field covers (Packet Number + Payload).
        // The full Initial/Handshake packet ends at pn_offset + payload_length.
        // Any bytes beyond are coalesced packets or trailing data, NOT part of
        // this packet's AEAD-protected ciphertext.
        const packet_len = pn_offset + header.payload_length;
        if (packet_len > data.len) return Error.InvalidPacket;

        // Copy packet to mutable buffer for decryption
        var decrypt_buf: [65536]u8 = undefined;
        if (packet_len > decrypt_buf.len) return Error.InvalidPacket;
        @memcpy(decrypt_buf[0..packet_len], data[0..packet_len]);

        // Get largest PN for this space
        const space = conn.getPacketSpace(pn_space);
        const largest_pn = space.largest_received orelse 0;

        // Unprotect the packet
        const unprotect_result = crypto.unprotectPacket(
            keys,
            largest_pn,
            pn_offset,
            &decrypt_buf,
            packet_len,
        ) catch return Error.InvalidPacket;

        // Record packet received
        space.onPacketReceived(unprotect_result.pn);

        // Parse and process frames from decrypted payload
        const payload = decrypt_buf[unprotect_result.header_len .. unprotect_result.header_len + unprotect_result.payload_len];
        try processCryptoFrames(conn, payload, pn_space);
    }

    /// Process CRYPTO frames from Initial/Handshake packets
    fn processCryptoFrames(conn: *connection.Connection, payload: []const u8, space: types.PacketNumberSpace) Error!void {
        var offset: usize = 0;

        while (offset < payload.len) {
            const result = frame.parseFrame(payload[offset..]) catch return Error.InvalidPacket;
            offset += result.consumed;

            switch (result.frame) {
                .padding => {}, // Ignore padding
                .ping => {}, // PING just triggers ACK
                .ack => |ack| {
                    conn.processAckFrame(ack, space);
                },
                .crypto => |crypto_frame| {
                    // Feed CRYPTO data to TLS session
                    conn.feedCryptoData(crypto_frame.data) catch |err| {
                        std.log.debug("QUIC crypto data processing failed: {}", .{err});
                    };
                },
                else => {}, // Ignore other frame types in Initial/Handshake
            }
        }
    }

    fn handleShortPacket(
        self: *Handler,
        conn: *connection.Connection,
        header: packet.ShortHeader,
        data: []const u8,
    ) Error!void {
        _ = self;

        // Connection must be in connected state
        if (conn.state != .connected) {
            return Error.ProtocolError;
        }

        // Get application keys for decryption
        const keys_opt: ?crypto.Keys = if (conn.is_server)
            conn.crypto_ctx.application.client // Decrypt with client's key
        else
            conn.crypto_ctx.application.server; // Decrypt with server's key
        const keys = keys_opt orelse return Error.HandshakeFailed;

        // Calculate packet number offset
        // Short header: flags (1) + DCID (variable)
        const pn_offset = 1 + header.dcid.len;

        // Copy packet to mutable buffer for decryption
        var decrypt_buf: [65536]u8 = undefined;
        if (data.len > decrypt_buf.len) return Error.InvalidPacket;
        @memcpy(decrypt_buf[0..data.len], data);

        // Unprotect the packet (removes header protection and decrypts)
        const largest_pn = conn.application_space.largest_received orelse 0;
        const unprotect_result = crypto.unprotectPacket(
            &keys,
            largest_pn,
            pn_offset,
            &decrypt_buf,
            data.len,
        ) catch return Error.InvalidPacket;

        // Record packet received
        conn.application_space.onPacketReceived(unprotect_result.pn);

        // Parse and process frames from decrypted payload
        const payload = decrypt_buf[unprotect_result.header_len .. unprotect_result.header_len + unprotect_result.payload_len];
        try processFrames(conn, payload);
    }

    /// Process all frames in a decrypted packet payload
    fn processFrames(conn: *connection.Connection, payload: []const u8) Error!void {
        var offset: usize = 0;

        while (offset < payload.len) {
            const result = frame.parseFrame(payload[offset..]) catch return Error.InvalidPacket;
            offset += result.consumed;

            switch (result.frame) {
                .padding => {}, // Ignore padding
                .ping => {}, // PING just triggers ACK
                .ack => |ack| {
                    conn.processAckFrame(ack, types.PacketNumberSpace.application);
                },
                .stream => |stream_frame| {
                    try processStreamFrame(conn, stream_frame);
                },
                .max_data => |max_data| {
                    conn.processMaxDataFrame(max_data.maximum_data);
                },
                .max_stream_data => |max_stream_data| {
                    if (conn.getStream(max_stream_data.stream_id)) |s| {
                        s.updateSendLimit(max_stream_data.maximum_stream_data);
                    }
                },
                .max_streams => |max_streams| {
                    // Update stream limits
                    if (conn.stream_manager) |*mgr| {
                        if (max_streams.bidirectional) {
                            mgr.max_streams_bidi_local = max_streams.maximum_streams;
                        } else {
                            mgr.max_streams_uni_local = max_streams.maximum_streams;
                        }
                    }
                },
                .connection_close => |close_frame| {
                    conn.processConnectionClose(close_frame.error_code, close_frame.reason_phrase);
                },
                .handshake_done => {
                    // Server confirms handshake complete
                    if (!conn.is_server) {
                        conn.onHandshakeComplete();
                    }
                },
                .reset_stream => |reset| {
                    if (conn.getStream(reset.stream_id)) |s| {
                        s.onReset(reset.final_size) catch |err| {
                            std.log.debug("QUIC stream reset failed: {}", .{err});
                        };
                    }
                },
                .stop_sending => |stop| {
                    if (conn.getStream(stop.stream_id)) |s| {
                        s.reset(stop.application_error_code);
                    }
                },
                .path_challenge => |challenge| {
                    // Queue PATH_RESPONSE with same data
                    conn.queuePathResponse(challenge.data);
                },
                .path_response => |response_frame| {
                    // Validate path response against pending challenge
                    conn.validatePathResponse(response_frame.data);
                },
                .new_connection_id => |new_cid| {
                    conn.addPeerConnectionId(new_cid);
                },
                .retire_connection_id => |retire| {
                    conn.retireConnectionId(retire.sequence_number);
                },
                else => {}, // Ignore other frame types for now
            }
        }
    }

    /// Process a STREAM frame
    fn processStreamFrame(conn: *connection.Connection, stream_frame: frame.StreamFrame) Error!void {
        // Get or create the stream
        const s = conn.getOrCreateStream(stream_frame.stream_id) catch |err| {
            return switch (err) {
                error.OutOfMemory => Error.OutOfMemory,
                error.StreamLimitExceeded => Error.ProtocolError,
                error.InvalidState, error.ConnectionClosed => Error.ProtocolError,
                else => Error.ProtocolError,
            };
        };

        // Deliver data to stream
        s.receive(stream_frame.offset, stream_frame.data, stream_frame.fin) catch |err| switch (err) {
            stream.Error.FlowControlError => return Error.ProtocolError,
            stream.Error.FinalSizeError => return Error.ProtocolError,
            stream.Error.InvalidStreamState => return Error.ProtocolError,
            stream.Error.OutOfMemory => return Error.OutOfMemory,
            else => return Error.ProtocolError,
        };

        // Update connection-level flow control
        conn.flow_control.onDataReceived(stream_frame.data.len) catch {
            return Error.ProtocolError;
        };

        // Process through HTTP/3 stack
        // The HTTP/3 events are stored in the stack and will be returned via getHttp3Events
        _ = conn.processHttp3Stream(stream_frame.stream_id, stream_frame.data, stream_frame.fin) catch |err| {
            std.log.debug("HTTP/3 stream processing failed: stream={} err={}", .{ stream_frame.stream_id, err });
        };
    }

    /// Get pending HTTP/3 events from the connection
    fn getHttp3Events(conn: *connection.Connection) []http3.Event {
        if (conn.http3_stack) |*stack| {
            return stack.events.items;
        }
        return &.{};
    }

    fn buildInitialResponse(self: *Handler, conn: *connection.Connection) Error![]const u8 {
        // Get server Initial keys
        const keys = conn.crypto_ctx.initial.server orelse return error.HandshakeFailed;

        var offset: usize = 0;

        // Build Initial packet header
        // First byte: Long header (0x80) | Fixed (0x40) | Initial type (0x00) | PN length (0x00 = 1 byte)
        self.response_buffer[offset] = 0xc0;
        offset += 1;

        // Version (QUIC v1)
        self.response_buffer[offset] = 0x00;
        self.response_buffer[offset + 1] = 0x00;
        self.response_buffer[offset + 2] = 0x00;
        self.response_buffer[offset + 3] = 0x01;
        offset += 4;

        // DCID length and value (peer's CID)
        self.response_buffer[offset] = conn.peer_cid.len;
        offset += 1;
        if (conn.peer_cid.len > 0) {
            @memcpy(self.response_buffer[offset .. offset + conn.peer_cid.len], conn.peer_cid.slice());
            offset += conn.peer_cid.len;
        }

        // SCID length and value (our CID)
        self.response_buffer[offset] = conn.our_cid.len;
        offset += 1;
        if (conn.our_cid.len > 0) {
            @memcpy(self.response_buffer[offset .. offset + conn.our_cid.len], conn.our_cid.slice());
            offset += conn.our_cid.len;
        }

        // Token length (0 for server Initial)
        self.response_buffer[offset] = 0x00;
        offset += 1;

        // Length field placeholder (will be filled after encryption)
        const length_offset = offset;
        offset += 2; // 2-byte varint for length

        // Packet number offset (for header protection)
        const pn_offset = offset;

        // Packet number (1 byte)
        const pn = conn.initial_space.allocatePacketNumber();
        self.response_buffer[offset] = @truncate(pn);
        offset += 1;

        const header_len = offset;

        // Build plaintext payload
        // ACK frame for packet 0
        self.response_buffer[offset] = 0x02; // ACK frame type
        offset += 1;
        self.response_buffer[offset] = 0x00; // Largest Acknowledged (0)
        offset += 1;
        self.response_buffer[offset] = 0x00; // ACK Delay (0)
        offset += 1;
        self.response_buffer[offset] = 0x00; // ACK Range Count (0)
        offset += 1;
        self.response_buffer[offset] = 0x00; // First ACK Range (0)
        offset += 1;

        // Calculate padding needed for minimum 1200 bytes after encryption
        // Need: header_len + plaintext + 16 (tag) >= 1200
        const min_plaintext = 1200 - header_len - crypto.AEAD_TAG_LEN;
        const current_plaintext = offset - header_len;

        while (offset - header_len < min_plaintext) {
            self.response_buffer[offset] = 0x00; // PADDING frame
            offset += 1;
        }

        const plaintext_len = offset - header_len;

        // Encrypt payload
        var ciphertext_buf: [2048]u8 = undefined;
        const ciphertext_len = crypto.protectPayload(
            &keys,
            pn,
            self.response_buffer[0..header_len],
            self.response_buffer[header_len..offset],
            &ciphertext_buf,
        ) catch return error.HandshakeFailed;

        // Copy ciphertext back
        @memcpy(self.response_buffer[header_len .. header_len + ciphertext_len], ciphertext_buf[0..ciphertext_len]);
        offset = header_len + ciphertext_len;

        // Fill in length field (includes PN length + ciphertext)
        const length_value = 1 + ciphertext_len; // 1 byte PN + ciphertext
        self.response_buffer[length_offset] = @intCast(0x40 | ((length_value >> 8) & 0x3f));
        self.response_buffer[length_offset + 1] = @intCast(length_value & 0xff);

        // Apply header protection (required for Initial packets per RFC 9001)
        // Sample starts 4 bytes after packet number and needs 16 bytes
        const sample_offset = pn_offset + 4;
        if (sample_offset + 16 > offset) {
            // Packet too small for header protection - this should never happen
            // with proper padding to 1200 bytes
            return error.HandshakeFailed;
        }

        const sample: *const [16]u8 = @ptrCast(self.response_buffer[sample_offset .. sample_offset + 16]);
        crypto.applyHeaderProtection(
            keys.hp[0..keys.hp_len],
            sample,
            &self.response_buffer[0],
            self.response_buffer[pn_offset .. pn_offset + 1],
        );

        _ = plaintext_len;
        _ = current_plaintext;

        return self.response_buffer[0..offset];
    }

    /// Get count of active connections
    pub fn connectionCount(self: *const Handler) usize {
        return self.pool.count();
    }

    /// Clean up closed connections
    pub fn cleanup(self: *Handler) void {
        // Track how many connections we're closing
        var it = self.pool.iterator();
        while (it.next()) |conn| {
            if (!conn.isAlive() or conn.isIdleTimedOut()) {
                const is_error = conn.close_error != null and conn.close_error.? != .no_error;
                const is_timeout = conn.isIdleTimedOut();
                metrics_mw.getStore().recordQuicConnectionClose(is_error, is_timeout);
            }
        }
        self.pool.cleanup();
    }

    /// Record RTT sample from ACK processing
    pub fn recordRttSample(rtt_us: u64) void {
        metrics_mw.getStore().recordQuicRtt(rtt_us);
    }

    /// Record packet sent
    pub fn recordPacketSent() void {
        metrics_mw.getStore().recordQuicPackets(1, 0, 0);
    }

    /// Record packet lost
    pub fn recordPacketLost() void {
        metrics_mw.getStore().recordQuicPackets(0, 0, 1);
    }
};

// Tests
test "handler initialization" {
    if (!build_options.enable_http3) return;
    const allocator = std.testing.allocator;
    var handler = Handler.init(allocator, true, 100);
    defer handler.deinit();

    try std.testing.expectEqual(@as(usize, 0), handler.connectionCount());
}

test "handler processes Initial packet" {
    if (!build_options.enable_http3) return;
    const allocator = std.testing.allocator;
    var server_handler = Handler.init(allocator, true, 100);
    defer server_handler.deinit();

    const dcid_bytes = [_]u8{0xaa} ** 8;
    const scid_bytes = [_]u8{0xbb} ** 4;
    var pkt_buf: [types.Constants.min_initial_packet_size]u8 = undefined;
    const packet_bytes = try test_utils.buildClientInitialPacket(&pkt_buf, &dcid_bytes, &scid_bytes, 256);

    var peer_addr: connection_pool.SockAddrStorage = undefined;
    @memset(std.mem.asBytes(&peer_addr), 0);

    const result = try server_handler.processPacket(packet_bytes, peer_addr);
    try std.testing.expect(result.new_connection);
    try std.testing.expect(result.conn != null);
    try std.testing.expect(result.response != null);
    try std.testing.expectEqual(@as(usize, 1), server_handler.connectionCount());
}
