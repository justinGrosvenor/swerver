const std = @import("std");
const ffi = @import("ffi.zig");
const build_options = @import("build_options");

/// QUIC TLS adapter that drives OpenSSL 3.5+ via SSL_set_quic_tls_cbs.
///
/// Replaces the memory-BIO path used for TCP TLS with a callback-based
/// integration where:
///   - incoming CRYPTO frame bytes are fed in per-encryption-level via
///     feedCryptoData()
///   - outgoing CRYPTO frame bytes are queued by OpenSSL via the
///     crypto_send callback into per-encryption-level outbound queues
///   - traffic secrets are reported via the yield_secret callback as the
///     handshake progresses through Initial → Handshake → Application
///   - QUIC transport parameters are exchanged as a TLS extension via
///     SSL_set_quic_tls_transport_params and got_transport_params
///
/// The QuicState struct is heap-allocated by the Provider and pinned for
/// the SSL session's lifetime — OpenSSL keeps a pointer to the dispatch
/// table inside it.

/// QUIC encryption level. Mirrors RFC 9001 §2.1 / RFC 9000 §12.3 spaces.
pub const Level = enum(u3) {
    initial = 0,
    early_data = 1,
    handshake = 2,
    application = 3,

    pub fn fromOsslProtLevel(prot: u32) ?Level {
        return switch (prot) {
            ffi.OSSL_RECORD_PROTECTION_LEVEL_NONE => .initial,
            ffi.OSSL_RECORD_PROTECTION_LEVEL_EARLY => .early_data,
            ffi.OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE => .handshake,
            ffi.OSSL_RECORD_PROTECTION_LEVEL_APPLICATION => .application,
            else => null,
        };
    }

    pub fn index(self: Level) usize {
        return @intFromEnum(self);
    }
};

pub const Direction = enum(u1) {
    read = 0,
    write = 1,

    pub fn fromOsslDirection(dir: c_int) ?Direction {
        return switch (dir) {
            ffi.OSSL_QUIC_DIRECTION_READ => .read,
            ffi.OSSL_QUIC_DIRECTION_WRITE => .write,
            else => null,
        };
    }
};

/// Holds a TLS traffic secret (max SHA-384 = 48 bytes; we use 64 for headroom).
pub const Secret = struct {
    bytes: [64]u8 = [_]u8{0} ** 64,
    len: u8 = 0,

    pub fn set(self: *Secret, data: []const u8) void {
        std.debug.assert(data.len <= self.bytes.len);
        @memcpy(self.bytes[0..data.len], data);
        self.len = @intCast(data.len);
    }

    pub fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Single-producer / single-consumer FIFO byte queue. Producer is OpenSSL
/// (crypto_send) for outbound queues, the QUIC stack (feedCryptoData) for
/// inbound queues. Consumer is the QUIC stack (drain/consume) for outbound,
/// OpenSSL (crypto_recv_rcd / crypto_release_rcd) for inbound.
///
/// 16 KB is sized to hold a full TLS 1.3 handshake flight at the Handshake
/// level (EncryptedExtensions + Certificate + CertVerify + Finished) for
/// typical cert chains. Initial / Application flights are much smaller.
pub const Queue = struct {
    pub const capacity: usize = 16 * 1024;

    buf: [capacity]u8 = undefined,
    head: usize = 0,
    tail: usize = 0,

    pub fn reset(self: *Queue) void {
        self.head = 0;
        self.tail = 0;
    }

    pub fn pending(self: *const Queue) []const u8 {
        return self.buf[self.head..self.tail];
    }

    pub fn pendingLen(self: *const Queue) usize {
        return self.tail - self.head;
    }

    pub fn isEmpty(self: *const Queue) bool {
        return self.head == self.tail;
    }

    pub fn freeSpace(self: *const Queue) usize {
        return capacity - self.tail;
    }

    /// Append bytes to the tail. Returns error.QueueFull if no room.
    /// Compacts (shifts head→0) before failing if compaction would help.
    pub fn append(self: *Queue, data: []const u8) error{QueueFull}!void {
        if (self.freeSpace() < data.len) {
            self.compact();
            if (self.freeSpace() < data.len) return error.QueueFull;
        }
        @memcpy(self.buf[self.tail..][0..data.len], data);
        self.tail += data.len;
    }

    /// Mark `n` bytes from the head as consumed.
    pub fn consume(self: *Queue, n: usize) void {
        std.debug.assert(n <= self.pendingLen());
        self.head += n;
        if (self.head == self.tail) self.reset();
    }

    /// Slide pending bytes back to offset 0 to recover free space at the tail.
    fn compact(self: *Queue) void {
        if (self.head == 0) return;
        const len = self.pendingLen();
        if (len > 0) {
            std.mem.copyForwards(u8, self.buf[0..len], self.buf[self.head..self.tail]);
        }
        self.head = 0;
        self.tail = len;
    }
};

/// Per-connection QUIC TLS adapter state. One instance per QUIC connection;
/// owned by the Provider, freed when the Session is deinit'd.
pub const QuicState = struct {
    /// Outgoing CRYPTO bytes per encryption level (filled by crypto_send,
    /// drained by the QUIC stack into CRYPTO frames).
    out_initial: Queue = .{},
    out_handshake: Queue = .{},
    out_application: Queue = .{},

    /// Incoming CRYPTO bytes per encryption level (filled by the QUIC stack
    /// from CRYPTO frames, drained by OpenSSL via crypto_recv_rcd).
    in_initial: Queue = .{},
    in_handshake: Queue = .{},
    in_application: Queue = .{},

    /// Installed traffic secrets per (direction, level). yield_secret writes,
    /// the QUIC stack reads to derive packet protection keys (key/iv/hp via
    /// HKDF-Expand-Label per RFC 9001 §5.1).
    read_secrets: [4]Secret = [_]Secret{.{}} ** 4,
    write_secrets: [4]Secret = [_]Secret{.{}} ** 4,

    /// Bit per Level — set when the QUIC stack hasn't yet observed the
    /// secret installation. Lets the upper layer poll for "did handshake
    /// keys appear?" without callbacks.
    read_secret_pending: u8 = 0,
    write_secret_pending: u8 = 0,

    /// Most-recently installed write level. crypto_send appends to the queue
    /// at this level. Defaults to Initial because OpenSSL can call crypto_send
    /// for the ServerHello before yield_secret(direction=WRITE) ever fires —
    /// the Initial keys come from the DCID, not from TLS.
    current_write_level: Level = .initial,

    /// Most-recently installed read level. crypto_recv_rcd reads from the
    /// queue at this level. Defaults to Initial for the same reason.
    current_read_level: Level = .initial,

    /// Tracking for the recv_rcd → release_rcd handshake: we hand OpenSSL a
    /// borrow of the queue's pending slice, and on release we mark it consumed.
    pending_recv_level: ?Level = null,
    pending_recv_len: usize = 0,

    /// Peer's QUIC transport parameters TLV blob, copied out of the
    /// got_transport_params callback. The QUIC stack parses this once.
    peer_transport_params_buf: [1024]u8 = undefined,
    peer_transport_params_len: usize = 0,

    /// Local QUIC transport parameters TLV blob. Allocated and owned by the
    /// QuicState; pointer-stable so OpenSSL can keep a reference.
    local_transport_params_buf: [1024]u8 = undefined,
    local_transport_params_len: usize = 0,

    /// OSSL_DISPATCH table storage. OpenSSL keeps a pointer to this, so it
    /// must outlive the SSL session — which is why QuicState is heap-pinned.
    dispatch_table: [ffi.QUIC_DISPATCH_MAX_ENTRIES]ffi.OSSL_DISPATCH = undefined,

    /// Latest TLS alert code from the alert callback (null if none).
    last_alert: ?u8 = null,

    /// Set to true if any callback returned a hard failure — used to short
    /// out subsequent SSL_do_handshake calls cleanly.
    callback_failed: bool = false,

    pub fn init(allocator: std.mem.Allocator) !*QuicState {
        const self = try allocator.create(QuicState);
        self.* = .{};
        return self;
    }

    pub fn deinit(self: *QuicState, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    /// Install QUIC TLS callbacks on `ssl`. Must be called once, before
    /// SSL_do_handshake. The dispatch table inside `self` is wired up here.
    pub fn install(self: *QuicState, ssl: *ffi.SSL) !void {
        ffi.buildQuicDispatchTable(&self.dispatch_table, .{
            .crypto_send = cryptoSend,
            .crypto_recv_rcd = cryptoRecvRcd,
            .crypto_release_rcd = cryptoReleaseRcd,
            .yield_secret = yieldSecret,
            .got_transport_params = gotTransportParams,
            .alert = alertCb,
        });
        try ffi.setQuicTlsCallbacks(ssl, &self.dispatch_table, @ptrCast(self));
    }

    /// Set local QUIC transport parameters. Bytes are copied into the
    /// pinned buffer; OpenSSL is then handed the buffer pointer.
    pub fn setLocalTransportParams(self: *QuicState, ssl: *ffi.SSL, params: []const u8) !void {
        if (params.len > self.local_transport_params_buf.len) return error.TransportParamsTooLarge;
        @memcpy(self.local_transport_params_buf[0..params.len], params);
        self.local_transport_params_len = params.len;
        try ffi.setQuicTlsTransportParams(
            ssl,
            self.local_transport_params_buf[0..self.local_transport_params_len],
        );
    }

    pub fn outboundQueue(self: *QuicState, level: Level) *Queue {
        return switch (level) {
            .initial => &self.out_initial,
            .handshake => &self.out_handshake,
            .application => &self.out_application,
            // 0-RTT outbound is server-side ticket data; we share the application queue.
            .early_data => &self.out_application,
        };
    }

    pub fn inboundQueue(self: *QuicState, level: Level) *Queue {
        return switch (level) {
            .initial => &self.in_initial,
            .handshake => &self.in_handshake,
            .application => &self.in_application,
            .early_data => &self.in_application,
        };
    }

    /// Feed received CRYPTO frame bytes at the given encryption level.
    /// The QUIC stack calls this whenever a CRYPTO frame is decoded out of
    /// an incoming packet, before invoking SSL_do_handshake.
    pub fn feedCryptoData(self: *QuicState, level: Level, data: []const u8) !void {
        try self.inboundQueue(level).append(data);
    }

    /// Get the read-only pending bytes at an outbound level. The QUIC stack
    /// calls this when assembling an outgoing packet — copy bytes into a
    /// CRYPTO frame, then call consumeOutgoing(level, n) to mark them sent.
    pub fn pendingOutgoing(self: *QuicState, level: Level) []const u8 {
        return self.outboundQueue(level).pending();
    }

    pub fn consumeOutgoing(self: *QuicState, level: Level, n: usize) void {
        self.outboundQueue(level).consume(n);
    }

    /// Get a slice of the installed secret for (direction, level), or null
    /// if not yet installed. Used by connection.zig to derive packet keys.
    pub fn getSecret(self: *QuicState, dir: Direction, level: Level) ?[]const u8 {
        const arr: *const [4]Secret = switch (dir) {
            .read => &self.read_secrets,
            .write => &self.write_secrets,
        };
        const s = &arr[level.index()];
        if (s.len == 0) return null;
        return s.slice();
    }

    /// Did a callback install a new secret since the last takePending call?
    /// Returns the (direction, level) tuples that became ready, then clears
    /// the pending bits. Lets the upper layer poll for "new keys to derive".
    pub const SecretReady = struct { dir: Direction, level: Level };

    pub fn takePendingSecrets(self: *QuicState, out: *[8]SecretReady) usize {
        var count: usize = 0;
        var i: u3 = 0;
        while (i < 4) : (i += 1) {
            const lvl: Level = @enumFromInt(i);
            if ((self.read_secret_pending & (@as(u8, 1) << i)) != 0) {
                if (count < out.len) out[count] = .{ .dir = .read, .level = lvl };
                count += 1;
            }
            if ((self.write_secret_pending & (@as(u8, 1) << i)) != 0) {
                if (count < out.len) out[count] = .{ .dir = .write, .level = lvl };
                count += 1;
            }
        }
        self.read_secret_pending = 0;
        self.write_secret_pending = 0;
        return count;
    }

    pub fn peerTransportParams(self: *const QuicState) ?[]const u8 {
        if (self.peer_transport_params_len == 0) return null;
        return self.peer_transport_params_buf[0..self.peer_transport_params_len];
    }

    // ============================================================
    // OpenSSL OSSL_DISPATCH callbacks
    // ============================================================
    //
    // All callbacks return 1 on success, 0 on failure (failure is fatal to
    // the TLS connection). They live as `callconv(.c)` functions so OpenSSL
    // can call them through the dispatch table.

    fn ctxFromArg(arg: ?*anyopaque) ?*QuicState {
        return @ptrCast(@alignCast(arg orelse return null));
    }

    fn cryptoSend(
        _: *ffi.SSL,
        buf: [*]const u8,
        buf_len: usize,
        consumed: *usize,
        arg: ?*anyopaque,
    ) callconv(.c) c_int {
        const self = ctxFromArg(arg) orelse {
            consumed.* = 0;
            return 0;
        };
        const slice = buf[0..buf_len];
        const queue = self.outboundQueue(self.current_write_level);
        queue.append(slice) catch {
            self.callback_failed = true;
            consumed.* = 0;
            return 0;
        };
        consumed.* = buf_len;
        return 1;
    }

    fn cryptoRecvRcd(
        _: *ffi.SSL,
        buf: *[*]const u8,
        bytes_read: *usize,
        arg: ?*anyopaque,
    ) callconv(.c) c_int {
        const self = ctxFromArg(arg) orelse return 0;
        const queue = self.inboundQueue(self.current_read_level);
        const pending = queue.pending();
        if (pending.len == 0) {
            // No CRYPTO data buffered at the current read level. Returning
            // 0 here indicates failure; instead, hand back an empty record
            // (buf=valid pointer, bytes_read=0) so OpenSSL knows there is
            // nothing to read right now without erroring out.
            buf.* = self.in_initial.buf[0..].ptr;
            bytes_read.* = 0;
            self.pending_recv_level = self.current_read_level;
            self.pending_recv_len = 0;
            return 1;
        }
        buf.* = pending.ptr;
        bytes_read.* = pending.len;
        self.pending_recv_level = self.current_read_level;
        self.pending_recv_len = pending.len;
        return 1;
    }

    fn cryptoReleaseRcd(
        _: *ffi.SSL,
        bytes_read: usize,
        arg: ?*anyopaque,
    ) callconv(.c) c_int {
        const self = ctxFromArg(arg) orelse return 0;
        const lvl = self.pending_recv_level orelse return 0;
        // OpenSSL contract: bytes_read here always equals the bytes_read we
        // returned from cryptoRecvRcd.
        std.debug.assert(bytes_read == self.pending_recv_len);
        if (bytes_read > 0) self.inboundQueue(lvl).consume(bytes_read);
        self.pending_recv_level = null;
        self.pending_recv_len = 0;
        return 1;
    }

    fn yieldSecret(
        _: *ffi.SSL,
        prot_level: u32,
        direction: c_int,
        secret: [*]const u8,
        secret_len: usize,
        arg: ?*anyopaque,
    ) callconv(.c) c_int {
        const self = ctxFromArg(arg) orelse return 0;
        const lvl = Level.fromOsslProtLevel(prot_level) orelse {
            self.callback_failed = true;
            return 0;
        };
        const dir = Direction.fromOsslDirection(direction) orelse {
            self.callback_failed = true;
            return 0;
        };
        const slice = secret[0..secret_len];
        switch (dir) {
            .read => {
                self.read_secrets[lvl.index()].set(slice);
                self.read_secret_pending |= @as(u8, 1) << @intFromEnum(lvl);
                self.current_read_level = lvl;
            },
            .write => {
                self.write_secrets[lvl.index()].set(slice);
                self.write_secret_pending |= @as(u8, 1) << @intFromEnum(lvl);
                self.current_write_level = lvl;
            },
        }
        return 1;
    }

    fn gotTransportParams(
        _: *ffi.SSL,
        params: [*]const u8,
        params_len: usize,
        arg: ?*anyopaque,
    ) callconv(.c) c_int {
        const self = ctxFromArg(arg) orelse return 0;
        if (params_len > self.peer_transport_params_buf.len) {
            self.callback_failed = true;
            return 0;
        }
        @memcpy(self.peer_transport_params_buf[0..params_len], params[0..params_len]);
        self.peer_transport_params_len = params_len;
        return 1;
    }

    fn alertCb(
        _: *ffi.SSL,
        alert_code: u8,
        arg: ?*anyopaque,
    ) callconv(.c) c_int {
        const self = ctxFromArg(arg) orelse return 0;
        self.last_alert = alert_code;
        return 1;
    }
};

// ============================================================
// Tests
// ============================================================

test "Queue: append, pending, consume, compact" {
    var q: Queue = .{};
    try std.testing.expect(q.isEmpty());
    try q.append("hello");
    try std.testing.expectEqualStrings("hello", q.pending());
    try q.append(" world");
    try std.testing.expectEqualStrings("hello world", q.pending());
    q.consume(6);
    try std.testing.expectEqualStrings("world", q.pending());
    // Force a compaction by appending data near the tail boundary.
    var big: [Queue.capacity - 5]u8 = undefined;
    @memset(&big, 'x');
    try q.append(&big);
    try std.testing.expectEqual(@as(usize, Queue.capacity), q.pendingLen());
}

test "Queue: full returns error" {
    var q: Queue = .{};
    var buf: [Queue.capacity]u8 = undefined;
    @memset(&buf, 'a');
    try q.append(&buf);
    try std.testing.expectError(error.QueueFull, q.append("x"));
}

test "Level: round-trip OpenSSL constants" {
    try std.testing.expectEqual(Level.initial, Level.fromOsslProtLevel(ffi.OSSL_RECORD_PROTECTION_LEVEL_NONE).?);
    try std.testing.expectEqual(Level.early_data, Level.fromOsslProtLevel(ffi.OSSL_RECORD_PROTECTION_LEVEL_EARLY).?);
    try std.testing.expectEqual(Level.handshake, Level.fromOsslProtLevel(ffi.OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE).?);
    try std.testing.expectEqual(Level.application, Level.fromOsslProtLevel(ffi.OSSL_RECORD_PROTECTION_LEVEL_APPLICATION).?);
    try std.testing.expectEqual(@as(?Level, null), Level.fromOsslProtLevel(99));
}

test "QuicState: feed and read inbound queue" {
    if (!build_options.enable_tls) return;
    const allocator = std.testing.allocator;
    var state = try QuicState.init(allocator);
    defer state.deinit(allocator);

    try state.feedCryptoData(.initial, "ClientHello bytes");
    try std.testing.expectEqualStrings("ClientHello bytes", state.in_initial.pending());

    try state.feedCryptoData(.handshake, "handshake msg");
    try std.testing.expectEqualStrings("handshake msg", state.in_handshake.pending());
}

test "QuicState: yield_secret installs and pending tracking" {
    if (!build_options.enable_tls) return;
    const allocator = std.testing.allocator;
    var state = try QuicState.init(allocator);
    defer state.deinit(allocator);

    const fake_secret = [_]u8{0xab} ** 32;
    // Direct call to the callback (simulating OpenSSL).
    const rc = QuicState.yieldSecret(
        undefined,
        ffi.OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE,
        ffi.OSSL_QUIC_DIRECTION_WRITE,
        &fake_secret,
        fake_secret.len,
        @ptrCast(state),
    );
    try std.testing.expectEqual(@as(c_int, 1), rc);
    try std.testing.expectEqualSlices(u8, &fake_secret, state.getSecret(.write, .handshake).?);
    try std.testing.expectEqual(Level.handshake, state.current_write_level);

    var pending: [8]QuicState.SecretReady = undefined;
    const n = state.takePendingSecrets(&pending);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(Direction.write, pending[0].dir);
    try std.testing.expectEqual(Level.handshake, pending[0].level);
    // After taking, pending should be cleared.
    try std.testing.expectEqual(@as(usize, 0), state.takePendingSecrets(&pending));
}
