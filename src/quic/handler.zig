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
const tls = @import("../tls/provider.zig");

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
    /// Buffer for building outgoing UDP datagrams. Sized to fit a coalesced
    /// Initial + Handshake flight with a typical TLS 1.3 cert chain
    /// (ServerHello ~120B, EE+Cert+CertVerify+Finished ~2-3 KiB).
    response_buffer: [16 * 1024]u8 = undefined,
    /// Is this a server handler?
    is_server: bool,
    /// Server-wide metrics
    server_metrics: metrics.ServerMetrics = .{},
    /// TLS provider used to bootstrap a TLS session for each new QUIC
    /// connection (server: handshake processing, key derivation). Null
    /// when TLS is disabled at build time or no cert was configured.
    tls_provider: ?*tls.Provider = null,

    pub fn init(allocator: std.mem.Allocator, is_server: bool, max_connections: usize) Handler {
        return .{
            .allocator = allocator,
            .pool = connection_pool.ConnectionPool.init(allocator, is_server, max_connections),
            .is_server = is_server,
        };
    }

    /// Wire a TLS provider into the handler. Must be called before the
    /// first incoming Initial packet for h3 to work — otherwise
    /// connection.tls_session stays null and no TLS handshake runs.
    pub fn setTlsProvider(self: *Handler, provider: *tls.Provider) void {
        self.tls_provider = provider;
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
                    // Bootstrap the TLS session so the QUIC TLS handshake
                    // can produce a server flight. Without this the
                    // connection would have no tls_session and TLS would
                    // never run, so the server would only ever ack.
                    if (self.tls_provider) |provider| {
                        conn.initTls(provider) catch |err| {
                            std.log.warn("h3: initTls failed: {}", .{err});
                            return Error.HandshakeFailed;
                        };
                    }
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
            // No handshake keys yet — expected very early in handshake
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

    /// Process CRYPTO frames from Initial/Handshake packets.
    ///
    /// CRYPTO frames within a packet may arrive out of offset order
    /// (curl/ngtcp2 deliberately fragments and reorders for interop testing).
    /// We feed them through the connection's per-level reassembly buffer,
    /// which only emits contiguous prefixes to TLS — that lets OpenSSL parse
    /// the handshake messages correctly.
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
                    // Hand the (offset, bytes) tuple to the connection's
                    // per-level reassembly buffer; it will feed any new
                    // contiguous prefix to TLS via feedCryptoData.
                    conn.ingestCryptoFrame(space, crypto_frame.offset, crypto_frame.data) catch |err| {
                        std.log.debug("QUIC crypto reassembly failed: {}", .{err});
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

        // Connection must be in connected state — clients can race their
        // 1-RTT data ahead of our handshake completion. Drop silently so
        // they retransmit; we'll process it once handshake_complete fires.
        if (conn.state != .connected) {
            return;
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

    /// Build a coalesced response datagram for a server-side connection in
    /// the handshake phase. Drains any pending CRYPTO bytes from the TLS
    /// adapter at the Initial and Handshake encryption levels and emits
    /// the corresponding QUIC packets back-to-back in a single datagram
    /// (RFC 9000 §12.2 packet coalescing).
    ///
    /// Layout:
    ///   [Initial packet] [Handshake packet?]
    ///
    /// The Initial packet is always padded to make the *datagram* at least
    /// 1200 bytes (RFC 9000 §14.1). When a Handshake packet is also being
    /// sent, the padding requirement applies to the combined size.
    fn buildInitialResponse(self: *Handler, conn: *connection.Connection) Error![]const u8 {
        var offset: usize = 0;

        // ---- Initial packet (always emitted in the response to a client Initial) ----
        const initial_keys = conn.crypto_ctx.initial.server orelse return Error.HandshakeFailed;
        const initial_crypto = conn.getPendingCryptoData(types.PacketNumberSpace.initial);

        // We need to know whether a Handshake packet will follow so we can
        // decide how much PADDING to put inside the Initial. To make that
        // decision we have to peek at the Handshake outbound queue.
        const handshake_crypto = conn.getPendingCryptoData(types.PacketNumberSpace.handshake);
        const will_emit_handshake = handshake_crypto.len > 0 and conn.crypto_ctx.handshake.server != null;

        // Build the Initial packet header into response_buffer[offset..]
        const initial_built = try buildHandshakePacket(
            self.response_buffer[offset..],
            .{
                .packet_type = .initial,
                .conn = conn,
                .crypto_data = initial_crypto,
                .keys = &initial_keys,
                .pad_datagram_to = if (will_emit_handshake) 0 else 1200,
                .datagram_bytes_so_far = offset,
                .ack_largest = if (conn.initial_space.ack_needed) conn.initial_space.largest_received else null,
            },
        );
        offset += initial_built.bytes_written;
        if (initial_crypto.len > 0) {
            conn.consumePendingCryptoData(types.PacketNumberSpace.initial, initial_crypto.len);
        }
        if (conn.initial_space.ack_needed) conn.initial_space.ack_needed = false;

        // ---- Handshake packet (only if there's pending Handshake CRYPTO data) ----
        if (will_emit_handshake) {
            const handshake_keys = conn.crypto_ctx.handshake.server.?;
            const handshake_built = try buildHandshakePacket(
                self.response_buffer[offset..],
                .{
                    .packet_type = .handshake,
                    .conn = conn,
                    .crypto_data = handshake_crypto,
                    .keys = &handshake_keys,
                    .pad_datagram_to = 1200,
                    .datagram_bytes_so_far = offset,
                    .ack_largest = if (conn.handshake_space.ack_needed) conn.handshake_space.largest_received else null,
                },
            );
            offset += handshake_built.bytes_written;
            conn.consumePendingCryptoData(types.PacketNumberSpace.handshake, handshake_crypto.len);
            if (conn.handshake_space.ack_needed) conn.handshake_space.ack_needed = false;
        }

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

/// Build a single QUIC long-header packet (Initial or Handshake) into `out`.
/// Lays down the header, an optional ACK frame, a CRYPTO frame carrying the
/// caller-supplied handshake bytes, optional PADDING to satisfy the RFC 9000
/// §14.1 1200-byte minimum on the *datagram*, then runs AEAD packet
/// protection + header protection over the result.
const BuildPacketOptions = struct {
    packet_type: types.PacketType,
    conn: *connection.Connection,
    crypto_data: []const u8,
    keys: *const crypto.Keys,
    /// If non-zero, pad so the total datagram (this packet + everything
    /// already in the buffer up to `datagram_bytes_so_far`) reaches at least
    /// this many bytes.
    pad_datagram_to: usize,
    datagram_bytes_so_far: usize,
    /// If non-null, emit an ACK frame acking this largest_received packet
    /// number in the matching number space.
    ack_largest: ?u64,
};

const BuildPacketResult = struct {
    bytes_written: usize,
};

fn buildHandshakePacket(out: []u8, opts: BuildPacketOptions) Error!BuildPacketResult {
    const conn_ref = opts.conn;

    // ---- Header ----
    var off: usize = 0;

    // First byte: long header (0x80) | fixed (0x40) | type (00=Initial, 10=Handshake)
    // | reserved 00 | PN length 00 (1 byte)
    const type_bits: u8 = switch (opts.packet_type) {
        .initial => 0x00,
        .handshake => 0x20,
        else => return Error.InvalidPacket,
    };
    if (off >= out.len) return Error.HandshakeFailed;
    out[off] = 0xc0 | type_bits;
    off += 1;

    // Version (QUIC v1)
    if (off + 4 > out.len) return Error.HandshakeFailed;
    out[off] = 0x00;
    out[off + 1] = 0x00;
    out[off + 2] = 0x00;
    out[off + 3] = 0x01;
    off += 4;

    // DCID length + DCID
    if (off + 1 + conn_ref.peer_cid.len > out.len) return Error.HandshakeFailed;
    out[off] = conn_ref.peer_cid.len;
    off += 1;
    if (conn_ref.peer_cid.len > 0) {
        @memcpy(out[off .. off + conn_ref.peer_cid.len], conn_ref.peer_cid.slice());
        off += conn_ref.peer_cid.len;
    }

    // SCID length + SCID
    if (off + 1 + conn_ref.our_cid.len > out.len) return Error.HandshakeFailed;
    out[off] = conn_ref.our_cid.len;
    off += 1;
    if (conn_ref.our_cid.len > 0) {
        @memcpy(out[off .. off + conn_ref.our_cid.len], conn_ref.our_cid.slice());
        off += conn_ref.our_cid.len;
    }

    // Token length (Initial only, always 0 for server-side response)
    if (opts.packet_type == .initial) {
        if (off >= out.len) return Error.HandshakeFailed;
        out[off] = 0x00;
        off += 1;
    }

    // Length field placeholder — encoded as a 2-byte varint (0x4000 | value).
    // We'll fill it in once we know the payload+tag size.
    if (off + 2 > out.len) return Error.HandshakeFailed;
    const length_offset = off;
    off += 2;

    // Packet number — 1 byte for now (sufficient for low PN values during handshake)
    const pn_offset = off;
    const pn_len: u8 = 1;
    const space_kind: types.PacketNumberSpace = switch (opts.packet_type) {
        .initial => .initial,
        .handshake => .handshake,
        else => return Error.InvalidPacket,
    };
    const space = conn_ref.getPacketSpace(space_kind);
    const pn = space.allocatePacketNumber();
    if (off >= out.len) return Error.HandshakeFailed;
    out[off] = @truncate(pn);
    off += 1;

    const header_len = off;

    // ---- Plaintext payload ----
    // Optional ACK frame
    if (opts.ack_largest) |largest| {
        const acked = frame.writeAck(out[off..], largest, 0) catch return Error.HandshakeFailed;
        off += acked;
    }

    // CRYPTO frame carrying the TLS handshake bytes (if any)
    if (opts.crypto_data.len > 0) {
        // CRYPTO offset is per-encryption-level, monotonically increasing.
        // For now we always emit at offset 0 because we drain the entire
        // queue in one go and only ever build one packet per level per
        // server flight. (Multi-packet handshake flights would need an
        // out-of-line offset cursor.)
        const written = frame.writeCrypto(out[off..], 0, opts.crypto_data) catch return Error.HandshakeFailed;
        off += written;
    }

    // PADDING to satisfy the datagram minimum (RFC 9000 §14.1)
    if (opts.pad_datagram_to > 0) {
        // Required total datagram size minus what's already in the buffer
        // before this packet. The current packet contributes `off` plain
        // bytes plus AEAD_TAG_LEN once protected.
        const target = opts.pad_datagram_to;
        const bytes_before = opts.datagram_bytes_so_far;
        const min_packet_size = if (target > bytes_before) target - bytes_before else 0;
        // Account for the AEAD tag that protectPacket will append.
        while (off + crypto.AEAD_TAG_LEN < min_packet_size) {
            if (off >= out.len) return Error.HandshakeFailed;
            out[off] = 0x00; // PADDING frame (frame type 0x00)
            off += 1;
        }
    }

    // ---- Length field fixup ----
    const payload_len = off - header_len;
    const length_value: u64 = pn_len + payload_len + crypto.AEAD_TAG_LEN;
    // 2-byte varint: 0x40 | high6 || low8
    if (length_value > 0x3fff) return Error.HandshakeFailed;
    out[length_offset] = @intCast(0x40 | ((length_value >> 8) & 0x3f));
    out[length_offset + 1] = @intCast(length_value & 0xff);

    // ---- AEAD packet protection + header protection ----
    const protected_len = crypto.protectPacket(
        opts.keys,
        pn,
        header_len,
        pn_offset,
        pn_len,
        out,
        off,
    ) catch return Error.HandshakeFailed;

    return .{ .bytes_written = protected_len };
}

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
