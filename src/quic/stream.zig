const std = @import("std");
const types = @import("types.zig");

/// QUIC Stream Management per RFC 9000 Section 2-3.
///
/// Handles:
/// - Stream lifecycle management
/// - Stream-level flow control
/// - Send and receive buffers

pub const Error = error{
    StreamNotFound,
    StreamClosed,
    FlowControlError,
    StreamLimitExceeded,
    InvalidStreamState,
    FinalSizeError,
    OutOfMemory,
};

/// Stream states per RFC 9000 Section 3
pub const State = enum {
    /// Stream has not been created yet
    idle,
    /// Stream is open for sending and receiving
    open,
    /// Local side has sent FIN, waiting for peer data
    half_closed_local,
    /// Peer has sent FIN, can still send
    half_closed_remote,
    /// Both sides have sent FIN
    closed,
    /// Stream was reset
    reset_sent,
    /// Peer reset the stream
    reset_received,
};

/// Stream data chunk for reassembly
const DataChunk = struct {
    offset: u64,
    /// Owned copy of data (must be freed)
    data: []u8,
    fin: bool,
};

/// QUIC Stream
pub const Stream = struct {
    allocator: std.mem.Allocator,
    /// Stream ID (encodes direction and initiator)
    id: u64,
    /// Current state
    state: State = .idle,
    /// Stream type (derived from ID)
    stream_type: types.StreamType,

    // Send side
    /// Next offset to send
    send_offset: u64 = 0,
    /// Maximum offset we can send to (peer's flow control)
    send_max_offset: u64 = 0,
    /// Final size if FIN sent
    send_fin_offset: ?u64 = null,
    /// Pending send data
    send_buffer: std.ArrayList(u8) = .empty,

    // Receive side
    /// Next expected offset (for in-order delivery)
    recv_offset: u64 = 0,
    /// Maximum offset we allow (our flow control)
    recv_max_offset: u64 = 0,
    /// Final size if FIN received
    recv_fin_offset: ?u64 = null,
    /// Received data buffer
    recv_buffer: std.ArrayList(u8) = .empty,
    /// Out-of-order chunks (for reassembly)
    pending_chunks: std.ArrayList(DataChunk) = .empty,

    // Flow control
    /// Need to send MAX_STREAM_DATA
    send_max_stream_data: bool = false,
    /// Need to send STREAM_DATA_BLOCKED
    send_blocked: bool = false,

    pub fn init(allocator: std.mem.Allocator, id: u64, initial_max_recv: u64) Stream {
        return Stream{
            .allocator = allocator,
            .id = id,
            .stream_type = types.StreamIdHelpers.getType(id),
            .recv_max_offset = initial_max_recv,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.send_buffer.deinit(self.allocator);
        self.recv_buffer.deinit(self.allocator);

        // Free any remaining pending chunk data
        for (self.pending_chunks.items) |chunk| {
            self.allocator.free(chunk.data);
        }
        self.pending_chunks.deinit(self.allocator);
    }

    /// Check if this is a bidirectional stream
    pub fn isBidirectional(self: *const Stream) bool {
        return types.StreamIdHelpers.isBidirectional(self.id);
    }

    /// Check if this is a client-initiated stream
    pub fn isClientInitiated(self: *const Stream) bool {
        return types.StreamIdHelpers.isClientInitiated(self.id);
    }

    /// Open the stream
    pub fn open(self: *Stream) void {
        if (self.state == .idle) {
            self.state = .open;
        }
    }

    /// Queue data for sending
    pub fn send(self: *Stream, data: []const u8, fin: bool) Error!void {
        if (self.state == .half_closed_local or
            self.state == .closed or
            self.state == .reset_sent)
        {
            return Error.InvalidStreamState;
        }

        // Check flow control
        const new_offset = self.send_offset + data.len;
        if (new_offset > self.send_max_offset) {
            self.send_blocked = true;
            return Error.FlowControlError;
        }

        // Append to send buffer
        self.send_buffer.appendSlice(self.allocator, data) catch return Error.OutOfMemory;
        self.send_offset = new_offset;

        if (fin) {
            self.send_fin_offset = new_offset;
            if (self.state == .open) {
                self.state = .half_closed_local;
            } else if (self.state == .half_closed_remote) {
                self.state = .closed;
            }
        }
    }

    /// Receive stream data
    pub fn receive(self: *Stream, offset: u64, data: []const u8, fin: bool) Error!void {
        if (self.state == .half_closed_remote or
            self.state == .closed or
            self.state == .reset_received)
        {
            return Error.InvalidStreamState;
        }

        // Check flow control
        const end_offset = offset + data.len;
        if (end_offset > self.recv_max_offset) {
            return Error.FlowControlError;
        }

        // Check final size consistency
        if (fin) {
            if (self.recv_fin_offset) |existing_fin| {
                if (existing_fin != end_offset) {
                    return Error.FinalSizeError;
                }
            } else {
                self.recv_fin_offset = end_offset;
            }
        } else if (self.recv_fin_offset) |existing_fin| {
            if (end_offset > existing_fin) {
                return Error.FinalSizeError;
            }
        }

        // Handle in-order data
        if (offset == self.recv_offset) {
            self.recv_buffer.appendSlice(self.allocator, data) catch return Error.OutOfMemory;
            self.recv_offset = end_offset;

            // Try to process any pending chunks
            try self.processPendingChunks();

            // Check if stream is now fully received
            if (fin or (self.recv_fin_offset != null and self.recv_offset >= self.recv_fin_offset.?)) {
                if (self.state == .open) {
                    self.state = .half_closed_remote;
                } else if (self.state == .half_closed_local) {
                    self.state = .closed;
                }
            }
        } else if (offset > self.recv_offset) {
            // Out-of-order, queue for later (must copy data as caller's buffer may be reused)
            const data_copy = self.allocator.alloc(u8, data.len) catch return Error.OutOfMemory;
            @memcpy(data_copy, data);

            self.pending_chunks.append(self.allocator, .{
                .offset = offset,
                .data = data_copy,
                .fin = fin,
            }) catch {
                self.allocator.free(data_copy);
                return Error.OutOfMemory;
            };
        }
        // Ignore duplicate/old data

        // Check if we should send MAX_STREAM_DATA
        if (self.recv_offset > self.recv_max_offset / 2) {
            self.send_max_stream_data = true;
        }
    }

    fn processPendingChunks(self: *Stream) Error!void {
        var made_progress = true;
        while (made_progress) {
            made_progress = false;
            var i: usize = 0;
            while (i < self.pending_chunks.items.len) {
                const chunk = self.pending_chunks.items[i];
                if (chunk.offset == self.recv_offset) {
                    self.recv_buffer.appendSlice(self.allocator, chunk.data) catch return Error.OutOfMemory;
                    self.recv_offset = chunk.offset + chunk.data.len;

                    // Free the owned data copy
                    self.allocator.free(chunk.data);

                    _ = self.pending_chunks.orderedRemove(i);
                    made_progress = true;
                } else {
                    i += 1;
                }
            }
        }
    }

    /// Get data ready to read (in-order)
    pub fn read(self: *Stream) []const u8 {
        return self.recv_buffer.items;
    }

    /// Consume read data
    pub fn consumeRead(self: *Stream, len: usize) void {
        if (len >= self.recv_buffer.items.len) {
            self.recv_buffer.clearRetainingCapacity();
        } else {
            // Shift remaining data
            const remaining = self.recv_buffer.items.len - len;
            std.mem.copyForwards(u8, self.recv_buffer.items[0..remaining], self.recv_buffer.items[len..]);
            self.recv_buffer.items.len = remaining;
        }
    }

    /// Reset the stream (send RESET_STREAM)
    pub fn reset(self: *Stream, error_code: u64) void {
        _ = error_code;
        self.state = .reset_sent;
    }

    /// Handle peer reset (received RESET_STREAM)
    pub fn onReset(self: *Stream, final_size: u64) Error!void {
        // Validate final size
        if (self.recv_fin_offset) |fin| {
            if (final_size != fin) {
                return Error.FinalSizeError;
            }
        }
        self.recv_fin_offset = final_size;
        self.state = .reset_received;
    }

    /// Update peer's flow control limit
    pub fn updateSendLimit(self: *Stream, max_offset: u64) void {
        if (max_offset > self.send_max_offset) {
            self.send_max_offset = max_offset;
            self.send_blocked = false;
        }
    }

    /// Update our flow control limit
    pub fn updateRecvLimit(self: *Stream, new_max: u64) void {
        if (new_max > self.recv_max_offset) {
            self.recv_max_offset = new_max;
            self.send_max_stream_data = false;
        }
    }

    /// Check if stream is finished (no more data expected)
    pub fn isFinished(self: *const Stream) bool {
        return self.state == .closed or
            self.state == .reset_sent or
            self.state == .reset_received;
    }

    /// Check if stream can receive data
    pub fn canReceive(self: *const Stream) bool {
        return self.state == .idle or
            self.state == .open or
            self.state == .half_closed_local;
    }

    /// Check if stream can send data
    pub fn canSend(self: *const Stream) bool {
        return self.state == .open or
            self.state == .half_closed_remote;
    }
};

/// Manages all streams for a connection
pub const StreamManager = struct {
    allocator: std.mem.Allocator,
    /// Is this a server connection?
    is_server: bool,
    /// All active streams
    streams: std.AutoHashMap(u64, *Stream),
    /// Next stream IDs to use (by type)
    next_client_bidi: u64 = 0,
    next_server_bidi: u64 = 1,
    next_client_uni: u64 = 2,
    next_server_uni: u64 = 3,
    /// Stream limits (from transport parameters)
    max_streams_bidi_local: u64 = 0,
    max_streams_bidi_remote: u64 = 0,
    max_streams_uni_local: u64 = 0,
    max_streams_uni_remote: u64 = 0,
    /// Current stream counts
    open_streams_bidi: u64 = 0,
    open_streams_uni: u64 = 0,
    /// Default flow control for new streams
    initial_max_stream_data: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, is_server: bool) StreamManager {
        return StreamManager{
            .allocator = allocator,
            .is_server = is_server,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
        };
    }

    pub fn deinit(self: *StreamManager) void {
        var it = self.streams.valueIterator();
        while (it.next()) |stream_ptr| {
            stream_ptr.*.deinit();
            self.allocator.destroy(stream_ptr.*);
        }
        self.streams.deinit();
    }

    /// Get or create a stream
    pub fn getOrCreateStream(self: *StreamManager, id: u64) Error!*Stream {
        if (self.streams.get(id)) |stream| {
            return stream;
        }

        // Create new stream
        return try self.createStream(id);
    }

    /// Create a new local stream
    pub fn createLocalStream(self: *StreamManager, bidirectional: bool) Error!*Stream {
        const id = if (self.is_server)
            if (bidirectional) blk: {
                const id = self.next_server_bidi;
                self.next_server_bidi += 4;
                break :blk id;
            } else blk: {
                const id = self.next_server_uni;
                self.next_server_uni += 4;
                break :blk id;
            }
        else if (bidirectional) blk: {
            const id = self.next_client_bidi;
            self.next_client_bidi += 4;
            break :blk id;
        } else blk: {
            const id = self.next_client_uni;
            self.next_client_uni += 4;
            break :blk id;
        };

        // Check stream limits
        if (bidirectional) {
            if (self.open_streams_bidi >= self.max_streams_bidi_local) {
                return Error.StreamLimitExceeded;
            }
            self.open_streams_bidi += 1;
        } else {
            if (self.open_streams_uni >= self.max_streams_uni_local) {
                return Error.StreamLimitExceeded;
            }
            self.open_streams_uni += 1;
        }

        return try self.createStream(id);
    }

    fn createStream(self: *StreamManager, id: u64) Error!*Stream {
        const stream = self.allocator.create(Stream) catch return Error.OutOfMemory;
        stream.* = Stream.init(self.allocator, id, self.initial_max_stream_data);
        stream.open();

        self.streams.put(id, stream) catch {
            self.allocator.destroy(stream);
            return Error.OutOfMemory;
        };

        return stream;
    }

    /// Get an existing stream
    pub fn getStream(self: *StreamManager, id: u64) ?*Stream {
        return self.streams.get(id);
    }

    /// Remove a finished stream
    pub fn removeStream(self: *StreamManager, id: u64) void {
        if (self.streams.fetchRemove(id)) |entry| {
            const stream = entry.value;

            // Update stream counts
            if (stream.isBidirectional()) {
                if (self.open_streams_bidi > 0) {
                    self.open_streams_bidi -= 1;
                }
            } else {
                if (self.open_streams_uni > 0) {
                    self.open_streams_uni -= 1;
                }
            }

            stream.deinit();
            self.allocator.destroy(stream);
        }
    }

    /// Update stream limits from transport parameters
    pub fn setLimits(
        self: *StreamManager,
        max_bidi_local: u64,
        max_bidi_remote: u64,
        max_uni_local: u64,
        max_uni_remote: u64,
    ) void {
        self.max_streams_bidi_local = max_bidi_local;
        self.max_streams_bidi_remote = max_bidi_remote;
        self.max_streams_uni_local = max_uni_local;
        self.max_streams_uni_remote = max_uni_remote;
    }

    /// Get count of active streams
    pub fn activeStreamCount(self: *const StreamManager) usize {
        return self.streams.count();
    }
};

// Tests
test "stream initialization" {
    const allocator = std.testing.allocator;

    // Client-initiated bidirectional stream
    var stream = Stream.init(allocator, 0, 1000);
    defer stream.deinit();

    try std.testing.expectEqual(@as(u64, 0), stream.id);
    try std.testing.expectEqual(types.StreamType.client_bidi, stream.stream_type);
    try std.testing.expect(stream.isBidirectional());
    try std.testing.expect(stream.isClientInitiated());
    try std.testing.expectEqual(State.idle, stream.state);
}

test "stream type detection" {
    const allocator = std.testing.allocator;

    // Client bidi: id % 4 == 0
    {
        var s = Stream.init(allocator, 0, 1000);
        defer s.deinit();
        try std.testing.expectEqual(types.StreamType.client_bidi, s.stream_type);
    }

    // Server bidi: id % 4 == 1
    {
        var s = Stream.init(allocator, 1, 1000);
        defer s.deinit();
        try std.testing.expectEqual(types.StreamType.server_bidi, s.stream_type);
    }

    // Client uni: id % 4 == 2
    {
        var s = Stream.init(allocator, 2, 1000);
        defer s.deinit();
        try std.testing.expectEqual(types.StreamType.client_uni, s.stream_type);
    }

    // Server uni: id % 4 == 3
    {
        var s = Stream.init(allocator, 3, 1000);
        defer s.deinit();
        try std.testing.expectEqual(types.StreamType.server_uni, s.stream_type);
    }
}

test "stream state transitions" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator, 0, 10000);
    defer stream.deinit();

    // Open stream
    stream.open();
    try std.testing.expectEqual(State.open, stream.state);

    // Send with FIN
    stream.send_max_offset = 10000;
    try stream.send("hello", true);
    try std.testing.expectEqual(State.half_closed_local, stream.state);

    // Receive with FIN
    try stream.receive(0, "world", true);
    try std.testing.expectEqual(State.closed, stream.state);
}

test "stream flow control" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator, 0, 100);
    defer stream.deinit();

    stream.open();
    stream.send_max_offset = 100;

    // Send within limit
    try stream.send("hello", false);
    try std.testing.expectEqual(@as(u64, 5), stream.send_offset);

    // Try to exceed limit
    const large_data = [_]u8{0} ** 200;
    try std.testing.expectError(Error.FlowControlError, stream.send(&large_data, false));
    try std.testing.expect(stream.send_blocked);

    // Update limit
    stream.updateSendLimit(500);
    try std.testing.expect(!stream.send_blocked);
}

test "stream manager" {
    const allocator = std.testing.allocator;
    var mgr = StreamManager.init(allocator, true);
    defer mgr.deinit();

    // Set limits
    mgr.setLimits(10, 10, 10, 10);
    mgr.initial_max_stream_data = 1000;

    // Create local stream
    const stream = try mgr.createLocalStream(true);
    try std.testing.expectEqual(@as(u64, 1), stream.id); // Server bidi starts at 1

    // Get existing stream
    const same = mgr.getStream(1);
    try std.testing.expect(same != null);
    try std.testing.expect(same.? == stream);

    // Create another
    const stream2 = try mgr.createLocalStream(true);
    try std.testing.expectEqual(@as(u64, 5), stream2.id); // Next server bidi

    try std.testing.expectEqual(@as(usize, 2), mgr.activeStreamCount());

    // Remove stream
    mgr.removeStream(1);
    try std.testing.expectEqual(@as(usize, 1), mgr.activeStreamCount());
}

test "stream receive with reassembly" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator, 0, 10000);
    defer stream.deinit();

    stream.open();

    // Receive out of order
    try stream.receive(5, "world", false); // offset 5, pending
    try stream.receive(0, "hello", false); // offset 0, triggers reassembly

    // Both should now be in recv_buffer
    try std.testing.expectEqual(@as(u64, 10), stream.recv_offset);
    try std.testing.expectEqualStrings("helloworld", stream.read());
}

test "stream triggers MAX_STREAM_DATA when half consumed" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator, 0, 1000);
    defer stream.deinit();

    stream.open();

    // Initially no MAX_STREAM_DATA needed
    try std.testing.expect(!stream.send_max_stream_data);

    // Receive less than half - no trigger
    try stream.receive(0, &[_]u8{0} ** 400, false);
    try std.testing.expect(!stream.send_max_stream_data);

    // Receive past half - should trigger
    try stream.receive(400, &[_]u8{0} ** 200, false);
    try std.testing.expect(stream.send_max_stream_data);

    // Update limit clears the flag
    stream.updateRecvLimit(2000);
    try std.testing.expect(!stream.send_max_stream_data);
}

test "stream manager flow control integration" {
    const allocator = std.testing.allocator;
    var mgr = StreamManager.init(allocator, false); // Client
    defer mgr.deinit();

    mgr.setLimits(10, 10, 10, 10);
    mgr.initial_max_stream_data = 1000;

    // Create a stream
    const stream = try mgr.createLocalStream(true);
    stream.open();

    // Receive data past half - triggers MAX_STREAM_DATA
    try stream.receive(0, &[_]u8{0} ** 600, false);
    try std.testing.expect(stream.send_max_stream_data);

    // Verify we can find the stream
    const found = mgr.getStream(stream.id);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.send_max_stream_data);
}
