const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const varint = @import("varint.zig");
pub const metrics = @import("metrics.zig");
const tls = @import("../tls/provider.zig");
const stream = @import("stream.zig");
const http3 = @import("../protocol/http3.zig");

/// QUIC Connection State Machine per RFC 9000.
///
/// Manages:
/// - Connection lifecycle (states, handshake)
/// - Packet number spaces
/// - Connection-level flow control
/// - Transport parameters

pub const Error = error{
    InvalidState,
    ConnectionClosed,
    FlowControlError,
    StreamLimitExceeded,
    ProtocolViolation,
    HandshakeFailed,
    InvalidPacket,
    CryptoError,
    OutOfMemory,
    TlsError,
};

/// Connection states per RFC 9000 Section 10
pub const State = enum {
    /// Initial state, waiting for or sending Initial packets
    initial,
    /// Handshake in progress
    handshaking,
    /// Connection established, can send application data
    connected,
    /// Initiated connection close, waiting for peer acknowledgment
    closing,
    /// Received connection close, waiting for timeout
    draining,
    /// Connection fully closed
    closed,
};

/// Packet number space tracking
pub const PacketNumberSpace = struct {
    /// Next packet number to send
    next_pn: u64 = 0,
    /// Largest acknowledged packet number (-1 means none acked yet)
    largest_acked: ?u64 = null,
    /// Largest received packet number
    largest_received: ?u64 = null,
    /// Timestamp when largest packet was received (microseconds since epoch)
    largest_received_time: ?u64 = null,
    /// ACK ranges to send (simple: just track largest for now)
    ack_needed: bool = false,
    /// Crypto keys for this space
    keys: ?crypto.Keys = null,

    /// Get the next packet number and increment
    pub fn allocatePacketNumber(self: *PacketNumberSpace) u64 {
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }

    /// Record that a packet was received
    pub fn onPacketReceived(self: *PacketNumberSpace, pn: u64) void {
        self.onPacketReceivedAt(pn, getCurrentTimeMicros());
    }

    /// Record that a packet was received at a specific time
    pub fn onPacketReceivedAt(self: *PacketNumberSpace, pn: u64, time_us: u64) void {
        if (self.largest_received) |largest| {
            if (pn > largest) {
                self.largest_received = pn;
                self.largest_received_time = time_us;
            }
        } else {
            self.largest_received = pn;
            self.largest_received_time = time_us;
        }
        self.ack_needed = true;
    }

    /// Record that an ACK was received
    pub fn onAckReceived(self: *PacketNumberSpace, largest_acked: u64) void {
        if (self.largest_acked) |current| {
            if (largest_acked > current) {
                self.largest_acked = largest_acked;
            }
        } else {
            self.largest_acked = largest_acked;
        }
    }

    /// Calculate ACK delay from when largest packet was received to now
    /// Returns delay in microseconds
    pub fn calculateAckDelay(self: *const PacketNumberSpace) u64 {
        const recv_time = self.largest_received_time orelse return 0;
        const now = getCurrentTimeMicros();
        if (now > recv_time) {
            return now - recv_time;
        }
        return 0;
    }
};

// Starting instant for relative time calculation
var start_instant: ?std.time.Instant = null;

/// Get current time in microseconds (relative to first call)
fn getCurrentTimeMicros() u64 {
    const now = std.time.Instant.now() catch return 0;

    if (start_instant == null) {
        start_instant = now;
        return 0;
    }

    // Return nanoseconds since start, converted to microseconds
    const ns = now.since(start_instant.?);
    return ns / 1000;
}

/// Transport parameters negotiated with peer
pub const TransportParams = struct {
    max_idle_timeout: u64 = 0,
    max_udp_payload_size: u64 = types.TransportParamDefaults.max_udp_payload_size,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u8 = types.TransportParamDefaults.ack_delay_exponent,
    max_ack_delay: u64 = types.TransportParamDefaults.max_ack_delay,
    active_connection_id_limit: u64 = types.TransportParamDefaults.active_connection_id_limit,
    disable_active_migration: bool = false,
};

/// Flow control state
pub const FlowControl = struct {
    /// Maximum data we can send (peer's limit)
    max_data_send: u64 = 0,
    /// Data we've sent so far
    data_sent: u64 = 0,
    /// Maximum data peer can send (our limit)
    max_data_recv: u64 = 0,
    /// Data we've received so far
    data_received: u64 = 0,
    /// Need to send MAX_DATA update
    send_max_data: bool = false,

    /// Check if we can send data
    pub fn canSend(self: *const FlowControl, len: u64) bool {
        return self.data_sent + len <= self.max_data_send;
    }

    /// Record that we sent data
    pub fn onDataSent(self: *FlowControl, len: u64) void {
        self.data_sent += len;
    }

    /// Record that we received data
    pub fn onDataReceived(self: *FlowControl, len: u64) Error!void {
        self.data_received += len;
        if (self.data_received > self.max_data_recv) {
            return Error.FlowControlError;
        }
        // Check if we should send MAX_DATA (when 50% consumed)
        if (self.data_received > self.max_data_recv / 2) {
            self.send_max_data = true;
        }
    }

    /// Update our receive limit
    pub fn updateMaxRecv(self: *FlowControl, new_max: u64) void {
        if (new_max > self.max_data_recv) {
            self.max_data_recv = new_max;
            self.send_max_data = false;
        }
    }

    /// Update peer's send limit (from MAX_DATA frame)
    pub fn updateMaxSend(self: *FlowControl, new_max: u64) void {
        if (new_max > self.max_data_send) {
            self.max_data_send = new_max;
        }
    }
};

/// Peer connection ID with associated metadata
pub const PeerConnectionId = struct {
    cid: types.ConnectionId,
    sequence_number: u64,
    stateless_reset_token: ?[16]u8 = null,
    retired: bool = false,
};

/// QUIC Connection
pub const Connection = struct {
    allocator: std.mem.Allocator,
    /// Current connection state
    state: State = .initial,
    /// Is this a server-side connection?
    is_server: bool,
    /// Original destination connection ID (for Initial packet validation)
    original_dcid: types.ConnectionId,
    /// Our connection ID
    our_cid: types.ConnectionId,
    /// Peer's connection ID
    peer_cid: types.ConnectionId,
    /// QUIC version in use
    version: u32 = @intFromEnum(types.Version.quic_v1),
    /// Cryptographic context
    crypto_ctx: crypto.CryptoContext,
    /// Packet number spaces
    initial_space: PacketNumberSpace = .{},
    handshake_space: PacketNumberSpace = .{},
    application_space: PacketNumberSpace = .{},
    /// Our transport parameters
    local_params: TransportParams = .{},
    /// Peer's transport parameters
    peer_params: TransportParams = .{},
    /// Connection-level flow control
    flow_control: FlowControl = .{},
    /// Crypto data buffer (for assembling CRYPTO frames)
    crypto_buffer: std.ArrayList(u8) = .empty,
    /// Pending crypto data offset
    crypto_offset: u64 = 0,
    /// Close error code (if closing/draining)
    close_error: ?types.TransportError = null,
    /// Close reason phrase
    close_reason: ?[]const u8 = null,
    /// Timer for idle timeout (in nanoseconds)
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// Last activity instant
    last_activity: ?std.time.Instant = null,
    /// Connection metrics
    conn_metrics: metrics.ConnectionMetrics = .{ .created_at = null },
    /// TLS session for handshake and key derivation
    tls_session: ?tls.Session = null,
    /// Buffer for outgoing CRYPTO data
    tls_out_buffer: [4096]u8 = undefined,
    /// Amount of data in tls_out_buffer
    tls_out_len: usize = 0,
    /// Stream manager for this connection
    stream_manager: ?stream.StreamManager = null,
    /// HTTP/3 protocol stack
    http3_stack: ?http3.Stack = null,
    /// Whether 0-RTT early data was received on this connection
    early_data_received: bool = false,
    /// Pending PATH_RESPONSE data to send
    pending_path_response: ?[8]u8 = null,
    /// Pending PATH_CHALLENGE data we're waiting to validate
    pending_path_challenge: ?[8]u8 = null,
    /// Peer's connection IDs (for connection ID rotation)
    peer_cids: [8]?PeerConnectionId = .{null} ** 8,
    /// Number of valid peer connection IDs
    peer_cid_count: usize = 0,
    /// Next sequence number for our connection IDs
    our_cid_seq: u64 = 0,
    /// Timestamp when draining started (microseconds)
    draining_started_us: ?u64 = null,
    /// Draining duration (3 × PTO, in microseconds)
    draining_duration_us: u64 = 3 * 1000 * 1000, // Default 3 seconds

    pub fn init(allocator: std.mem.Allocator, is_server: bool, dcid: types.ConnectionId) Connection {
        var conn = Connection{
            .allocator = allocator,
            .is_server = is_server,
            .original_dcid = dcid,
            .our_cid = types.ConnectionId{},
            .peer_cid = dcid,
            .crypto_ctx = crypto.CryptoContext.init(),
            .last_activity = std.time.Instant.now() catch null,
            .conn_metrics = metrics.ConnectionMetrics.init(),
        };

        // Generate our connection ID (8 bytes) from hash of DCID
        // Note: In production, use cryptographically secure random bytes
        const hash = std.hash.Wyhash.hash(0, dcid.slice());
        const hash_bytes = std.mem.toBytes(hash);
        @memcpy(conn.our_cid.bytes[0..8], &hash_bytes);
        conn.our_cid.len = 8;

        // Derive initial keys from DCID
        conn.crypto_ctx.deriveInitialKeys(dcid.slice(), conn.version);

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        self.crypto_buffer.deinit(self.allocator);
        if (self.tls_session) |*session| {
            session.deinit();
        }
        if (self.stream_manager) |*mgr| {
            mgr.deinit();
        }
        if (self.http3_stack) |*stack| {
            stack.deinit();
        }
    }

    /// Initialize the stream manager for this connection.
    pub fn initStreamManager(self: *Connection) void {
        if (self.stream_manager == null) {
            var mgr = stream.StreamManager.init(self.allocator, self.is_server);
            // Set initial limits from local transport parameters
            mgr.setLimits(
                self.local_params.initial_max_streams_bidi,
                self.peer_params.initial_max_streams_bidi,
                self.local_params.initial_max_streams_uni,
                self.peer_params.initial_max_streams_uni,
            );
            mgr.initial_max_stream_data = self.local_params.initial_max_stream_data_bidi_remote;
            self.stream_manager = mgr;
        }

        // Initialize HTTP/3 stack
        if (self.http3_stack == null) {
            self.http3_stack = http3.Stack.init(self.allocator, self.is_server);
        }
    }

    /// Process stream data through HTTP/3 stack.
    /// Returns events produced by parsing HTTP/3 frames.
    pub fn processHttp3Stream(self: *Connection, stream_id: u64, data: []const u8, end_stream: bool) Error![]http3.Event {
        if (self.http3_stack) |*stack| {
            const result = stack.ingest(stream_id, data, end_stream) catch return Error.ProtocolViolation;
            return result.events;
        }
        return Error.InvalidState;
    }

    /// Initialize HTTP/3 control streams.
    /// Creates control stream and queues SETTINGS frame.
    fn initHttp3ControlStreams(self: *Connection) void {
        // Server uses stream ID 3 for control, client uses stream ID 2
        // (Unidirectional streams: client=2,6,10..., server=3,7,11...)
        const control_stream_id: u64 = if (self.is_server) 3 else 2;

        // Create the control stream
        if (self.stream_manager) |*mgr| {
            const ctrl_stream = mgr.getOrCreateStream(control_stream_id) catch return;
            ctrl_stream.send_max_offset = 65536; // Allow sending
        }

        // Set control stream in HTTP/3 stack and build SETTINGS
        if (self.http3_stack) |*stack| {
            stack.our_control_stream = control_stream_id;

            // Build SETTINGS frame data to queue for sending
            var settings_buf: [256]u8 = undefined;

            // Control stream type byte (0x00 for control)
            settings_buf[0] = 0x00;
            var offset: usize = 1;

            // Build SETTINGS frame
            const settings_len = stack.buildSettings(settings_buf[offset..]) catch return;
            offset += settings_len;

            // Queue the control stream data
            if (self.stream_manager) |*mgr| {
                if (mgr.getStream(control_stream_id)) |ctrl_stream| {
                    ctrl_stream.send(settings_buf[0..offset], false) catch {};
                }
            }
        }
    }

    /// Get pending control stream data to send
    pub fn getPendingControlStreamData(self: *Connection) ?struct { stream_id: u64, data: []const u8 } {
        if (self.http3_stack) |*stack| {
            if (stack.our_control_stream) |ctrl_id| {
                if (self.stream_manager) |*mgr| {
                    if (mgr.getStream(ctrl_id)) |ctrl_stream| {
                        const data = ctrl_stream.send_buffer.items;
                        if (data.len > 0) {
                            return .{ .stream_id = ctrl_id, .data = data };
                        }
                    }
                }
            }
        }
        return null;
    }

    /// Clear pending control stream data after it has been sent
    pub fn clearPendingControlStreamData(self: *Connection) void {
        if (self.http3_stack) |*stack| {
            if (stack.our_control_stream) |ctrl_id| {
                if (self.stream_manager) |*mgr| {
                    if (mgr.getStream(ctrl_id)) |ctrl_stream| {
                        ctrl_stream.send_buffer.clearRetainingCapacity();
                    }
                }
            }
        }
    }

    /// Encode an HTTP/3 response for a stream.
    pub fn encodeHttp3Response(
        self: *Connection,
        buf: []u8,
        status: u16,
        headers: []const http3.Header,
        body: ?[]const u8,
    ) Error!usize {
        if (self.http3_stack) |*stack| {
            return stack.encodeResponse(buf, status, headers, body) catch Error.ProtocolViolation;
        }
        return Error.InvalidState;
    }

    /// Get or create a stream by ID.
    pub fn getOrCreateStream(self: *Connection, stream_id: u64) Error!*stream.Stream {
        if (self.stream_manager) |*mgr| {
            return mgr.getOrCreateStream(stream_id) catch |err| switch (err) {
                stream.Error.OutOfMemory => Error.OutOfMemory,
                stream.Error.StreamLimitExceeded => Error.StreamLimitExceeded,
                else => Error.ProtocolViolation,
            };
        }
        return Error.InvalidState;
    }

    /// Get an existing stream by ID.
    pub fn getStream(self: *Connection, stream_id: u64) ?*stream.Stream {
        if (self.stream_manager) |*mgr| {
            return mgr.getStream(stream_id);
        }
        return null;
    }

    /// Initialize TLS session for this connection.
    /// Must be called after init() to enable TLS 1.3 handshake.
    pub fn initTls(self: *Connection, provider: *tls.Provider) Error!void {
        self.tls_session = provider.createSession(self.is_server) catch return Error.TlsError;
    }

    /// Feed incoming CRYPTO frame data to TLS.
    /// This data comes from CRYPTO frames in Initial/Handshake packets.
    pub fn feedCryptoData(self: *Connection, data: []const u8) Error!void {
        if (self.tls_session) |*session| {
            _ = session.feedCryptoData(data) catch return Error.TlsError;
        }
    }

    /// Advance the TLS handshake and collect outgoing CRYPTO data.
    /// Returns true if handshake is complete.
    pub fn advanceTlsHandshake(self: *Connection) Error!bool {
        if (self.tls_session) |*session| {
            // Try to advance the handshake
            const result = session.doHandshake();

            // Read any outgoing crypto data
            const read_len = session.readCryptoData(&self.tls_out_buffer) catch |err| switch (err) {
                error.NoBio => 0,
                else => return Error.TlsError,
            };
            self.tls_out_len = read_len;

            return switch (result) {
                .complete => blk: {
                    // Handshake complete - derive keys from TLS
                    try self.deriveHandshakeKeys();
                    try self.deriveApplicationKeys();
                    break :blk true;
                },
                .in_progress => false,
                .failed => Error.HandshakeFailed,
            };
        }
        return Error.TlsError;
    }

    /// Get pending outgoing CRYPTO data to send in CRYPTO frames.
    pub fn getPendingCryptoData(self: *Connection) ?[]const u8 {
        if (self.tls_out_len > 0) {
            return self.tls_out_buffer[0..self.tls_out_len];
        }
        return null;
    }

    /// Clear pending CRYPTO data after it has been sent.
    pub fn clearPendingCryptoData(self: *Connection) void {
        self.tls_out_len = 0;
    }

    /// Derive handshake keys from TLS session.
    fn deriveHandshakeKeys(self: *Connection) Error!void {
        if (self.tls_session) |*session| {
            var client_secret: [32]u8 = undefined;
            var server_secret: [32]u8 = undefined;

            session.exportKeyingMaterial(&client_secret, tls.QuicKeyLabels.client_handshake, null) catch return Error.CryptoError;
            session.exportKeyingMaterial(&server_secret, tls.QuicKeyLabels.server_handshake, null) catch return Error.CryptoError;

            // Derive keys from secrets
            self.crypto_ctx.handshake.client = deriveKeysFromTlsSecret(&client_secret);
            self.crypto_ctx.handshake.server = deriveKeysFromTlsSecret(&server_secret);
        }
    }

    /// Derive application (1-RTT) keys from TLS session.
    fn deriveApplicationKeys(self: *Connection) Error!void {
        if (self.tls_session) |*session| {
            var client_secret: [32]u8 = undefined;
            var server_secret: [32]u8 = undefined;

            session.exportKeyingMaterial(&client_secret, tls.QuicKeyLabels.client_application, null) catch return Error.CryptoError;
            session.exportKeyingMaterial(&server_secret, tls.QuicKeyLabels.server_application, null) catch return Error.CryptoError;

            // Derive keys from secrets
            self.crypto_ctx.application.client = deriveKeysFromTlsSecret(&client_secret);
            self.crypto_ctx.application.server = deriveKeysFromTlsSecret(&server_secret);
        }
    }

    /// Get the packet number space for a given type
    pub fn getPacketSpace(self: *Connection, space: types.PacketNumberSpace) *PacketNumberSpace {
        return switch (space) {
            .initial => &self.initial_space,
            .handshake => &self.handshake_space,
            .application => &self.application_space,
        };
    }

    /// Process an incoming packet
    pub fn processPacket(self: *Connection, data: []const u8) Error!void {
        self.last_activity = std.time.Instant.now() catch self.last_activity;

        // Parse header
        const result = packet.parseHeader(data, self.our_cid.len);
        if (result.state != .complete) {
            return Error.InvalidPacket;
        }

        const header = result.header orelse return Error.InvalidPacket;

        switch (header) {
            .long => |long| {
                try self.processLongHeaderPacket(long, data);
            },
            .short => |short| {
                try self.processShortHeaderPacket(short, data);
            },
        }
    }

    fn processLongHeaderPacket(self: *Connection, header: packet.LongHeader, data: []const u8) Error!void {
        _ = data;

        switch (header.packet_type) {
            .initial => {
                if (self.state != .initial and self.state != .handshaking) {
                    return Error.InvalidState;
                }
                // Process Initial packet
                try self.handleInitialPacket(header);
            },
            .handshake => {
                if (self.state != .handshaking and self.state != .connected) {
                    return Error.InvalidState;
                }
                try self.handleHandshakePacket(header);
            },
            .zero_rtt => {
                // 0-RTT not supported yet
                return Error.InvalidState;
            },
            .retry => {
                if (!self.is_server and self.state == .initial) {
                    try self.handleRetryPacket(header);
                }
            },
        }
    }

    fn processShortHeaderPacket(self: *Connection, header: packet.ShortHeader, data: []const u8) Error!void {
        _ = data;
        _ = header;

        if (self.state != .connected) {
            return Error.InvalidState;
        }

        // Process 1-RTT packet
        // TODO: Decrypt and process frames
    }

    fn handleInitialPacket(self: *Connection, header: packet.LongHeader) Error!void {
        // Update peer's connection ID if needed
        if (header.scid.len > 0) {
            self.peer_cid = header.scid;
        }

        // Process CRYPTO frames from Initial packet
        // The handshake data would be extracted here
        if (self.state == .initial) {
            self.state = .handshaking;
        }
    }

    fn handleHandshakePacket(self: *Connection, header: packet.LongHeader) Error!void {
        _ = self;
        _ = header;

        // Process Handshake CRYPTO frames
        // When complete, transition to connected
        // This would be done after TLS handshake completes
    }

    fn handleRetryPacket(self: *Connection, header: packet.LongHeader) Error!void {
        _ = self;
        _ = header;
        // Validate Retry token integrity
        // Update connection ID and token
        // Re-send Initial packet with token
    }

    /// Transition to connected state
    pub fn onHandshakeComplete(self: *Connection) void {
        self.state = .connected;

        // Record handshake completion in metrics
        self.conn_metrics.handshakeComplete();

        // Apply peer's transport parameters to flow control
        self.flow_control.max_data_send = self.peer_params.initial_max_data;
        self.flow_control.max_data_recv = self.local_params.initial_max_data;

        // Initialize stream manager now that transport params are set
        self.initStreamManager();

        // Initialize HTTP/3 control streams
        self.initHttp3ControlStreams();

        // Discard Initial and Handshake keys
        self.initial_space.keys = null;
        self.handshake_space.keys = null;
    }

    /// Initiate connection close
    pub fn close(self: *Connection, error_code: types.TransportError, reason: ?[]const u8) void {
        if (self.state == .closed or self.state == .draining) {
            return;
        }

        self.close_error = error_code;
        self.close_reason = reason;
        self.state = .closing;
    }

    /// Build a CONNECTION_CLOSE frame for the current close state
    /// Returns bytes written to buffer
    pub fn buildConnectionCloseFrame(self: *const Connection, buf: []u8) !usize {
        const error_code = if (self.close_error) |err|
            @intFromEnum(err)
        else
            @intFromEnum(types.TransportError.no_error);

        const reason = self.close_reason orelse "";

        return frame.writeConnectionClose(buf, error_code, null, reason);
    }

    /// Build a CONNECTION_CLOSE frame for a specific error
    /// Useful when closing due to a specific protocol error
    pub fn buildConnectionCloseForError(buf: []u8, error_code: types.TransportError, triggering_frame: ?u64, reason: []const u8) !usize {
        return frame.writeConnectionClose(buf, @intFromEnum(error_code), triggering_frame, reason);
    }

    /// Check if connection needs to send CONNECTION_CLOSE
    pub fn needsConnectionClose(self: *const Connection) bool {
        return self.state == .closing;
    }

    /// Enter draining state (received CONNECTION_CLOSE from peer)
    /// RFC 9000: After sending CONNECTION_CLOSE, endpoint enters draining period
    /// and should remain in that state for 3 × PTO before fully closing
    pub fn drain(self: *Connection) void {
        if (self.state == .closed or self.state == .draining) return;
        self.state = .draining;
        self.draining_started_us = getCurrentTimeMicros();

        // Calculate draining duration based on PTO
        // PTO = smoothed_rtt + max(4 * rttvar, granularity) + max_ack_delay
        // Default to 3 seconds if no RTT data
        const rtt_us = self.conn_metrics.rtt_us;
        const rtt_var = self.conn_metrics.rtt_var_us;
        const max_ack_delay = self.peer_params.max_ack_delay * 1000; // Convert ms to us
        if (rtt_us > 0) {
            const pto = rtt_us + @max(4 * rtt_var, 1000) + max_ack_delay;
            self.draining_duration_us = 3 * pto;
        }
    }

    /// Check if draining period has completed
    pub fn isDrainingComplete(self: *const Connection) bool {
        if (self.state != .draining) return false;

        const started = self.draining_started_us orelse return true;
        const now = getCurrentTimeMicros();
        return now >= started + self.draining_duration_us;
    }

    /// Complete connection close (call when draining complete or forced close)
    pub fn onClosed(self: *Connection) void {
        self.state = .closed;
    }

    /// Check and transition from draining to closed if draining period expired
    pub fn checkDrainingComplete(self: *Connection) bool {
        if (self.isDrainingComplete()) {
            self.onClosed();
            return true;
        }
        return false;
    }

    /// Check if connection is still alive (not closed or draining)
    pub fn isAlive(self: *const Connection) bool {
        return self.state != .closed and self.state != .draining;
    }

    /// Check if connection is in a terminal state (closed)
    pub fn isClosed(self: *const Connection) bool {
        return self.state == .closed;
    }

    /// Check if connection is draining
    pub fn isDraining(self: *const Connection) bool {
        return self.state == .draining;
    }

    /// Check if connection can send application data
    pub fn canSendAppData(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Check if idle timeout has expired
    pub fn isIdleTimedOut(self: *const Connection) bool {
        const last = self.last_activity orelse return false;
        const now = std.time.Instant.now() catch return false;
        const elapsed = now.since(last);
        return elapsed > self.idle_timeout_ns;
    }

    /// Process a received ACK frame, marking packets as acknowledged.
    /// ACK frame format:
    /// - First range: [largest_ack - first_ack_range, largest_ack]
    /// - Additional ranges: gap indicates unacked packets before next range
    pub fn processAckFrame(self: *Connection, ack: frame.AckFrame, space: types.PacketNumberSpace) void {
        const pn_space = self.getPacketSpace(space);
        pn_space.onAckReceived(ack.largest_acked);

        // Process first ACK range: [largest - first_range, largest]
        var current_largest = ack.largest_acked;
        var current_smallest = ack.largest_acked -| ack.first_ack_range;

        // Mark packets in first range as acknowledged
        self.markPacketsAcked(space, current_smallest, current_largest);

        // Process additional ACK ranges
        for (ack.ranges) |range| {
            // Gap of 'gap' unacknowledged packets before next range
            // Next range starts at: current_smallest - gap - 2
            if (current_smallest < range.gap + 2) break; // Underflow protection
            current_largest = current_smallest - range.gap - 2;
            current_smallest = current_largest -| range.length;

            self.markPacketsAcked(space, current_smallest, current_largest);
        }
    }

    /// Mark a range of packets as acknowledged
    fn markPacketsAcked(self: *Connection, space: types.PacketNumberSpace, smallest: u64, largest: u64) void {
        // In a full implementation, we would:
        // 1. Look up sent packets in this range
        // 2. Mark them as acknowledged
        // 3. Stop retransmission timers
        // 4. Update RTT estimates based on ack timing
        // 5. Trigger congestion control on_ack events

        // For now, update metrics
        self.conn_metrics.packets_acked += (largest - smallest + 1);

        // Space-specific tracking could be added here
        _ = space;
    }

    /// Process a received MAX_DATA frame
    pub fn processMaxDataFrame(self: *Connection, max_data: u64) void {
        self.flow_control.updateMaxSend(max_data);
    }

    /// Process a received MAX_STREAM_DATA frame
    pub fn processMaxStreamDataFrame(self: *Connection, stream_id: u64, max_data: u64) void {
        if (self.stream_manager) |*mgr| {
            if (mgr.getStream(stream_id)) |strm| {
                strm.updateSendLimit(max_data);
            }
        }
    }

    /// Process a received CONNECTION_CLOSE frame
    pub fn processConnectionClose(self: *Connection, error_code: u64, reason: []const u8) void {
        _ = reason;
        self.close_error = @enumFromInt(error_code);
        self.drain();
    }

    // ---- FLOW CONTROL ----

    /// Check if connection needs to send MAX_DATA
    pub fn needsMaxData(self: *const Connection) bool {
        return self.flow_control.send_max_data;
    }

    /// Build a MAX_DATA frame
    /// Returns bytes written, or 0 if no update needed
    pub fn buildMaxDataFrame(self: *Connection, buf: []u8) !usize {
        if (!self.flow_control.send_max_data) {
            return 0;
        }

        // Increase our receive limit by the current max (double it)
        const new_max = self.flow_control.max_data_recv * 2;
        self.flow_control.updateMaxRecv(new_max);

        return frame.writeMaxData(buf, new_max);
    }

    /// Get a stream that needs MAX_STREAM_DATA to be sent
    /// Returns the stream ID, or null if none needed
    pub fn getStreamNeedingFlowControl(self: *Connection) ?u64 {
        if (self.stream_manager) |*mgr| {
            var it = mgr.streams.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.*.send_max_stream_data) {
                    return entry.key_ptr.*;
                }
            }
        }
        return null;
    }

    /// Build a MAX_STREAM_DATA frame for a stream
    /// Returns bytes written
    pub fn buildMaxStreamDataFrame(self: *Connection, buf: []u8, stream_id: u64) !usize {
        if (self.stream_manager) |*mgr| {
            if (mgr.getStream(stream_id)) |strm| {
                if (strm.send_max_stream_data) {
                    // Double the stream's receive limit
                    const new_max = strm.recv_max_offset * 2;
                    strm.updateRecvLimit(new_max);

                    return frame.writeMaxStreamData(buf, stream_id, new_max);
                }
            }
        }
        return 0;
    }

    /// Update flow control when stream data is received
    /// Call this after processing a STREAM frame
    pub fn onStreamDataReceived(self: *Connection, len: u64) Error!void {
        try self.flow_control.onDataReceived(len);
    }

    /// Check if we can send data of the given length (connection-level)
    pub fn canSendData(self: *const Connection, len: u64) bool {
        return self.flow_control.canSend(len);
    }

    /// Record that we sent data (connection-level)
    pub fn onDataSent(self: *Connection, len: u64) void {
        self.flow_control.onDataSent(len);
    }

    // ---- PATH_CHALLENGE / PATH_RESPONSE ----

    /// Queue a PATH_RESPONSE to be sent (in response to PATH_CHALLENGE)
    pub fn queuePathResponse(self: *Connection, data: [8]u8) void {
        self.pending_path_response = data;
    }

    /// Check if we have a pending PATH_RESPONSE to send
    pub fn hasPendingPathResponse(self: *const Connection) bool {
        return self.pending_path_response != null;
    }

    /// Get and clear pending PATH_RESPONSE data
    pub fn takePendingPathResponse(self: *Connection) ?[8]u8 {
        const data = self.pending_path_response;
        self.pending_path_response = null;
        return data;
    }

    /// Start a path validation by sending PATH_CHALLENGE
    pub fn startPathValidation(self: *Connection) [8]u8 {
        // Generate 8 random bytes for challenge
        var data: [8]u8 = undefined;
        std.crypto.random.bytes(&data);
        self.pending_path_challenge = data;
        return data;
    }

    /// Validate a received PATH_RESPONSE
    pub fn validatePathResponse(self: *Connection, data: [8]u8) void {
        if (self.pending_path_challenge) |expected| {
            if (std.mem.eql(u8, &data, &expected)) {
                // Path validated successfully
                self.pending_path_challenge = null;
                // Could update path state here for connection migration
            }
        }
    }

    /// Check if path validation is pending
    pub fn isPathValidationPending(self: *const Connection) bool {
        return self.pending_path_challenge != null;
    }

    // ---- NEW_CONNECTION_ID / RETIRE_CONNECTION_ID ----

    /// Add a new peer connection ID from NEW_CONNECTION_ID frame
    pub fn addPeerConnectionId(self: *Connection, new_cid_frame: frame.NewConnectionIdFrame) void {
        // Find an empty slot or replace retired one
        for (&self.peer_cids) |*slot| {
            if (slot.* == null or (slot.*.?.retired and slot.*.?.sequence_number < new_cid_frame.sequence_number)) {
                slot.* = PeerConnectionId{
                    .cid = new_cid_frame.connection_id,
                    .sequence_number = new_cid_frame.sequence_number,
                    .stateless_reset_token = new_cid_frame.stateless_reset_token,
                    .retired = false,
                };
                self.peer_cid_count = @min(self.peer_cid_count + 1, self.peer_cids.len);
                return;
            }
        }
        // All slots full - could trigger RETIRE_CONNECTION_ID for oldest
    }

    /// Retire a connection ID (from RETIRE_CONNECTION_ID frame)
    pub fn retireConnectionId(self: *Connection, sequence_number: u64) void {
        for (&self.peer_cids) |*slot| {
            if (slot.*) |*pcid| {
                if (pcid.sequence_number == sequence_number) {
                    pcid.retired = true;
                    return;
                }
            }
        }
    }

    /// Get the active peer connection ID to use
    pub fn getActivePeerCid(self: *const Connection) types.ConnectionId {
        // Return first non-retired peer CID, or fall back to peer_cid
        for (self.peer_cids) |slot| {
            if (slot) |pcid| {
                if (!pcid.retired) {
                    return pcid.cid;
                }
            }
        }
        return self.peer_cid;
    }

    /// Generate an ACK frame for a packet number space
    pub fn generateAckFrame(self: *Connection, space: types.PacketNumberSpace) ?frame.AckFrame {
        const pn_space = self.getPacketSpace(space);

        if (!pn_space.ack_needed) return null;

        const largest = pn_space.largest_received orelse return null;

        pn_space.ack_needed = false;

        // Calculate ACK delay in microseconds, then encode with exponent
        // ACK delay encoding: delay_us / (2^ack_delay_exponent)
        const delay_us = pn_space.calculateAckDelay();
        const exponent = self.local_params.ack_delay_exponent;
        const encoded_delay = delay_us >> @intCast(exponent);

        return frame.AckFrame{
            .largest_ack = largest,
            .ack_delay = encoded_delay,
            .first_ack_range = largest, // Simple: ACK only largest
            .ack_ranges = &[_]frame.AckRange{},
            .ecn = null,
        };
    }
};

/// Derive QUIC keys from a TLS traffic secret.
/// Uses HKDF-Expand-Label with "quic key", "quic iv", "quic hp" labels.
fn deriveKeysFromTlsSecret(secret: *const [32]u8) crypto.Keys {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

    // HKDF-Expand-Label helper (inline since crypto module's is private)
    const hkdfExpandLabel = struct {
        fn expand(prk: *const [32]u8, label: []const u8, out: []u8) void {
            // Build HkdfLabel: length || "tls13 " || label || context(empty)
            var info: [64]u8 = undefined;
            var info_len: usize = 0;

            // Length (2 bytes, big-endian)
            info[0] = @intCast((out.len >> 8) & 0xff);
            info[1] = @intCast(out.len & 0xff);
            info_len = 2;

            // Label: length + "tls13 " + label
            const prefix = "tls13 ";
            const full_len = prefix.len + label.len;
            info[info_len] = @intCast(full_len);
            info_len += 1;
            @memcpy(info[info_len .. info_len + prefix.len], prefix);
            info_len += prefix.len;
            @memcpy(info[info_len .. info_len + label.len], label);
            info_len += label.len;

            // Context length (0)
            info[info_len] = 0;
            info_len += 1;

            // HKDF-Expand
            var hmac = HmacSha256.init(prk);
            hmac.update(info[0..info_len]);
            hmac.update(&[_]u8{1});
            var result: [32]u8 = undefined;
            hmac.final(&result);
            @memcpy(out, result[0..out.len]);
        }
    }.expand;

    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;

    hkdfExpandLabel(secret, "quic key", &key);
    hkdfExpandLabel(secret, "quic iv", &iv);
    hkdfExpandLabel(secret, "quic hp", &hp);

    return crypto.Keys.init128(key, iv, hp);
}

// Tests
test "connection initialization" {
    const allocator = std.testing.allocator;
    const dcid = types.ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    var conn = Connection.init(allocator, true, dcid);
    defer conn.deinit();

    try std.testing.expectEqual(State.initial, conn.state);
    try std.testing.expect(conn.is_server);
    try std.testing.expectEqual(@as(u8, 8), conn.our_cid.len);
    try std.testing.expect(conn.crypto_ctx.initial.client != null);
    try std.testing.expect(conn.crypto_ctx.initial.server != null);
}

test "connection state transitions" {
    const allocator = std.testing.allocator;
    const dcid = types.ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    var conn = Connection.init(allocator, true, dcid);
    defer conn.deinit();

    try std.testing.expectEqual(State.initial, conn.state);

    // Simulate handshake start
    conn.state = .handshaking;
    try std.testing.expectEqual(State.handshaking, conn.state);

    // Simulate handshake complete
    conn.onHandshakeComplete();
    try std.testing.expectEqual(State.connected, conn.state);
    try std.testing.expect(conn.canSendAppData());

    // Close connection
    conn.close(.no_error, null);
    try std.testing.expectEqual(State.closing, conn.state);
}

test "packet number space" {
    var space = PacketNumberSpace{};

    // Allocate packet numbers
    try std.testing.expectEqual(@as(u64, 0), space.allocatePacketNumber());
    try std.testing.expectEqual(@as(u64, 1), space.allocatePacketNumber());
    try std.testing.expectEqual(@as(u64, 2), space.allocatePacketNumber());

    // Receive packets
    space.onPacketReceived(10);
    try std.testing.expectEqual(@as(u64, 10), space.largest_received.?);
    try std.testing.expect(space.ack_needed);

    // Receive ACK
    space.onAckReceived(1);
    try std.testing.expectEqual(@as(u64, 1), space.largest_acked.?);
}

test "ack delay calculation" {
    var space = PacketNumberSpace{};

    // No packets received - delay should be 0
    try std.testing.expectEqual(@as(u64, 0), space.calculateAckDelay());

    // Receive a packet with a specific timestamp (1000us ago)
    const now = getCurrentTimeMicros();
    const past = if (now > 1000) now - 1000 else 0;
    space.onPacketReceivedAt(1, past);

    // Delay should be approximately 1000us (allow some tolerance for test execution time)
    const delay = space.calculateAckDelay();
    // Since getCurrentTimeMicros may return 0 on some platforms, only check if time is working
    if (now > 0 and past > 0) {
        try std.testing.expect(delay >= 1000);
        try std.testing.expect(delay < 100_000); // Less than 100ms (reasonable upper bound)
    }
}

test "flow control" {
    var fc = FlowControl{};

    // Initially can't send (no limit)
    try std.testing.expect(!fc.canSend(100));

    // Set limits
    fc.max_data_send = 1000;
    fc.max_data_recv = 1000;

    try std.testing.expect(fc.canSend(100));

    // Send some data
    fc.onDataSent(500);
    try std.testing.expect(fc.canSend(500));
    try std.testing.expect(!fc.canSend(501));

    // Receive some data (more than half triggers MAX_DATA update)
    try fc.onDataReceived(501);
    try std.testing.expect(fc.send_max_data); // Should trigger MAX_DATA

    // Try to receive too much
    try std.testing.expectError(Error.FlowControlError, fc.onDataReceived(500));
}

test "derive keys from TLS secret" {
    // Test that key derivation produces valid keys
    const secret = [_]u8{0x42} ** 32;
    const keys = deriveKeysFromTlsSecret(&secret);

    // Keys should be deterministic
    try std.testing.expectEqual(@as(u8, 16), keys.key_len);
    try std.testing.expectEqual(@as(u8, 16), keys.hp_len);

    // Different secret should produce different keys
    const secret2 = [_]u8{0x43} ** 32;
    const keys2 = deriveKeysFromTlsSecret(&secret2);
    try std.testing.expect(!std.mem.eql(u8, keys.key[0..16], keys2.key[0..16]));
}
