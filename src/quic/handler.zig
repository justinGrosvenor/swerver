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

/// QUIC packet handler
///
/// Processes incoming QUIC datagrams and produces responses.

pub const Error = error{
    InvalidPacket,
    ConnectionNotFound,
    HandshakeFailed,
    ProtocolError,
    OutOfMemory,
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
                        // 0-RTT not supported yet
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
            },
        }

        result.conn = conn;
        result.close_connection = !conn.isAlive();

        return result;
    }

    fn handleInitialPacket(
        self: *Handler,
        conn: *connection.Connection,
        header: packet.LongHeader,
        data: []const u8,
    ) Error!void {
        _ = self;
        _ = data;

        // Update peer's connection ID
        if (header.scid.len > 0) {
            conn.peer_cid = header.scid;
        }

        // Process CRYPTO frames (would contain ClientHello)
        // For now, just transition state
        if (conn.state == .initial) {
            conn.state = .handshaking;
        }
    }

    fn handleHandshakePacket(
        self: *Handler,
        conn: *connection.Connection,
        header: packet.LongHeader,
        data: []const u8,
    ) Error!void {
        _ = self;
        _ = header;
        _ = data;

        // Process Handshake CRYPTO frames
        // When complete, transition to connected
        if (conn.state == .handshaking) {
            // In a real implementation, this would happen after TLS handshake completes
            // For now, simulate immediate completion
            conn.onHandshakeComplete();
        }
    }

    fn handleShortPacket(
        self: *Handler,
        conn: *connection.Connection,
        header: packet.ShortHeader,
        data: []const u8,
    ) Error!void {
        _ = self;
        _ = header;
        _ = data;

        // Process 1-RTT packet with application data
        // Would decrypt payload, parse frames, handle STREAM data
        _ = conn;
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
        self.pool.cleanup();
    }
};

// Tests
test "handler initialization" {
    const allocator = std.testing.allocator;
    var handler = Handler.init(allocator, true, 100);
    defer handler.deinit();

    try std.testing.expectEqual(@as(usize, 0), handler.connectionCount());
}

test "handler processes Initial packet" {
    const allocator = std.testing.allocator;
    var handler = Handler.init(allocator, true, 100);
    defer handler.deinit();

    // Build a minimal Initial packet
    var pkt: [1200]u8 = undefined;
    var offset: usize = 0;

    // First byte: Long header | Fixed | Initial
    pkt[offset] = 0xc0;
    offset += 1;

    // Version (QUIC v1)
    pkt[offset] = 0x00;
    pkt[offset + 1] = 0x00;
    pkt[offset + 2] = 0x00;
    pkt[offset + 3] = 0x01;
    offset += 4;

    // DCID length = 8
    pkt[offset] = 0x08;
    offset += 1;
    @memset(pkt[offset .. offset + 8], 0xaa);
    offset += 8;

    // SCID length = 4
    pkt[offset] = 0x04;
    offset += 1;
    @memset(pkt[offset .. offset + 4], 0xbb);
    offset += 4;

    // Token length = 0
    pkt[offset] = 0x00;
    offset += 1;

    // Length = remaining (varint)
    const remaining = 1200 - offset - 2;
    pkt[offset] = @intCast(0x40 | ((remaining >> 8) & 0x3f));
    pkt[offset + 1] = @intCast(remaining & 0xff);
    offset += 2;

    // Fill rest with padding
    @memset(pkt[offset..], 0x00);

    var peer_addr: connection_pool.SockAddrStorage = undefined;
    @memset(std.mem.asBytes(&peer_addr), 0);

    const result = try handler.processPacket(&pkt, peer_addr);

    try std.testing.expect(result.new_connection);
    try std.testing.expect(result.conn != null);
    try std.testing.expect(result.response != null);
    try std.testing.expectEqual(@as(usize, 1), handler.connectionCount());
}
