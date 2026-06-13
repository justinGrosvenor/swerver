//! Native PostgreSQL client — module root.
//!
//! This module is the pure-protocol layer: wire codec, SCRAM-SHA-256,
//! binary type decoders, and a socket-free `Handshake` state machine.
//! The reactor integration drives `Handshake` from the event loop:
//! call `takeSend` whenever the socket is writable and a message is
//! pending, `feed` with whatever bytes arrived, repeat until `isReady`.

const std = @import("std");

pub const protocol = @import("protocol.zig");
pub const scram = @import("scram.zig");
pub const types = @import("types.zig");
/// Handler-facing park-and-resume types (ResumeContext, Result, Row…).
pub const handler_api = @import("handler_api.zig");
/// Per-worker reactor connection driver + query/park machinery.
pub const client = @import("client.zig");

/// The only SASL mechanism implemented (no channel binding in v1).
pub const SASL_MECHANISM = "SCRAM-SHA-256";

pub const HandshakeError = error{
    /// Authentication method requested by the server is not supported
    /// (md5, Kerberos, GSS, or a SASL list without SCRAM-SHA-256).
    UnsupportedAuth,
    /// Server sent ErrorResponse; details in `lastError()`.
    ServerError,
    /// Backend message that has no business arriving mid-handshake.
    UnexpectedMessage,
    /// Handshake already failed; feed/takeSend are no longer valid.
    Failed,
} || protocol.ParseError || protocol.WriteError || scram.Error;

/// Startup → auth → ready as a pure feed/emit state machine. No socket,
/// no allocation: outbound messages serialize into caller buffers and
/// inbound parsing borrows from the caller's receive buffer.
///
/// Driving contract:
///   1. `takeSend(buf)` — returns the next message to transmit, or null.
///   2. `feed(bytes)` — consume backend bytes; returns how many were
///      used. The unconsumed tail holds a partial frame and must be
///      re-presented (prepended) on the next call.
///   3. Repeat until `isReady()`; after that, leftover bytes belong to
///      the query phase.
pub const Handshake = struct {
    pub const Options = struct {
        user: []const u8,
        /// Borrowed; must remain valid until the handshake completes.
        password: []const u8 = "",
        database: ?[]const u8 = null,
        application_name: ?[]const u8 = null,
        /// Caller-generated SCRAM nonce (printable ASCII, no commas).
        /// The reactor sources this from its CSPRNG; tests pin it.
        client_nonce: []const u8,
    };

    pub const State = enum {
        /// Startup message not sent yet.
        start,
        /// Awaiting the server's Authentication request (or Ok).
        auth,
        /// SASL initial response queued/sent; awaiting server-first.
        sasl_continue_wait,
        /// Client-final queued/sent; awaiting server-final.
        sasl_final_wait,
        /// Authenticated; draining ParameterStatus/BackendKeyData until
        /// ReadyForQuery.
        params,
        ready,
        failed,
    };

    const PendingSend = enum { startup, sasl_initial, sasl_response, password, none };

    /// Stored copy of the salient ErrorResponse fields (the frame's
    /// backing buffer does not outlive `feed`).
    pub const StoredError = struct {
        code_buf: [5]u8 = .{0} ** 5,
        code_len: usize = 0,
        message_buf: [256]u8 = .{0} ** 256,
        message_len: usize = 0,

        pub fn code(self: *const StoredError) []const u8 {
            return self.code_buf[0..self.code_len];
        }

        pub fn message(self: *const StoredError) []const u8 {
            return self.message_buf[0..self.message_len];
        }
    };

    opts: Options,
    state: State = .start,
    pending_send: PendingSend = .startup,
    scram_client: scram.Client = undefined,
    backend_pid: u32 = 0,
    backend_secret: u32 = 0,
    txn_status: protocol.TxnStatus = .idle,
    server_error: ?StoredError = null,

    pub fn init(opts: Options) Handshake {
        return .{ .opts = opts };
    }

    pub fn isReady(self: *const Handshake) bool {
        return self.state == .ready;
    }

    /// ErrorResponse details after `feed` returned `error.ServerError`.
    pub fn lastError(self: *const Handshake) ?*const StoredError {
        return if (self.server_error) |*e| e else null;
    }

    /// Serialize the next outbound message into `buf`, or return null
    /// when nothing is pending. On `error.BufferTooSmall` the message
    /// stays pending and the call may be retried with a larger buffer.
    pub fn takeSend(self: *Handshake, buf: []u8) HandshakeError!?[]u8 {
        if (self.state == .failed) return error.Failed;
        switch (self.pending_send) {
            .none => return null,
            .startup => {
                const out = try protocol.writeStartup(
                    buf,
                    self.opts.user,
                    self.opts.database,
                    self.opts.application_name,
                );
                self.pending_send = .none;
                self.state = .auth;
                return out;
            },
            .sasl_initial => {
                var scratch: [scram.CLIENT_FIRST_MAX]u8 = undefined;
                const first = try self.scram_client.clientFirst(&scratch);
                const out = try protocol.writeSaslInitialResponse(buf, SASL_MECHANISM, first);
                self.pending_send = .none;
                return out;
            },
            .sasl_response => {
                var scratch: [scram.CLIENT_FINAL_MAX]u8 = undefined;
                const final = try self.scram_client.clientFinal(&scratch);
                const out = try protocol.writeSaslResponse(buf, final);
                self.pending_send = .none;
                return out;
            },
            .password => {
                const out = try protocol.writePassword(buf, self.opts.password);
                self.pending_send = .none;
                return out;
            },
        }
    }

    /// Consume backend bytes. Returns the number of bytes used (complete
    /// frames only); the caller keeps the tail. Stops consuming once
    /// ready — remaining bytes are query-phase traffic.
    pub fn feed(self: *Handshake, bytes: []const u8) HandshakeError!usize {
        if (self.state == .failed) return error.Failed;
        var iter = protocol.FrameIter.init(bytes);
        while (self.state != .ready) {
            const frame = (try iter.next()) orelse break;
            self.handleFrame(frame) catch |err| {
                self.state = .failed;
                return err;
            };
        }
        return iter.consumed();
    }

    fn handleFrame(self: *Handshake, frame: protocol.Frame) HandshakeError!void {
        switch (@as(protocol.BackendType, @enumFromInt(frame.typ))) {
            .authentication => try self.handleAuth(frame.payload),
            .parameter_status => {
                // Server runtime parameters (server_version, TimeZone, ...)
                // are parsed but not currently recorded.
                _ = try protocol.parseParameterStatus(frame.payload);
            },
            .backend_key_data => {
                const kd = try protocol.parseBackendKeyData(frame.payload);
                self.backend_pid = kd.pid;
                self.backend_secret = kd.secret;
            },
            .ready_for_query => {
                self.txn_status = try protocol.parseReadyForQuery(frame.payload);
                self.state = .ready;
            },
            .error_response => {
                const info = try protocol.parseErrorResponse(frame.payload);
                var stored = StoredError{};
                stored.code_len = @min(info.code.len, stored.code_buf.len);
                @memcpy(stored.code_buf[0..stored.code_len], info.code[0..stored.code_len]);
                stored.message_len = @min(info.message.len, stored.message_buf.len);
                @memcpy(stored.message_buf[0..stored.message_len], info.message[0..stored.message_len]);
                self.server_error = stored;
                return error.ServerError;
            },
            .notice_response => {}, // informational; ignore
            .negotiate_protocol_version => return error.UnsupportedAuth,
            else => return error.UnexpectedMessage,
        }
    }

    fn handleAuth(self: *Handshake, payload: []const u8) HandshakeError!void {
        switch (try protocol.parseAuth(payload)) {
            .ok => self.state = .params,
            .cleartext_password => {
                // Policy (cleartext only over TLS) is enforced by the
                // phase-2/3 connection layer; the state machine just
                // answers the request.
                if (self.state != .auth) return error.UnexpectedMessage;
                self.pending_send = .password;
            },
            .sasl => |mechanisms| {
                if (self.state != .auth) return error.UnexpectedMessage;
                if (!protocol.saslMechanismsContain(mechanisms, SASL_MECHANISM)) {
                    return error.UnsupportedAuth;
                }
                self.scram_client = try scram.Client.init(
                    self.opts.user,
                    self.opts.password,
                    self.opts.client_nonce,
                );
                self.pending_send = .sasl_initial;
                self.state = .sasl_continue_wait;
            },
            .sasl_continue => |server_first| {
                if (self.state != .sasl_continue_wait) return error.UnexpectedMessage;
                try self.scram_client.handleServerFirst(server_first);
                self.pending_send = .sasl_response;
                self.state = .sasl_final_wait;
            },
            .sasl_final => |server_final| {
                if (self.state != .sasl_final_wait) return error.UnexpectedMessage;
                // MUST verify the server signature — fail closed.
                try self.scram_client.verifyServerFinal(server_final);
                self.state = .auth; // AuthenticationOk follows
            },
            .md5_password, .unsupported => return error.UnsupportedAuth,
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Append a backend frame to `buf` at `off`; returns the new offset.
fn putFrame(buf: []u8, off: usize, typ: u8, payload: []const u8) usize {
    buf[off] = typ;
    std.mem.writeInt(u32, buf[off + 1 ..][0..4], @intCast(4 + payload.len), .big);
    @memcpy(buf[off + 5 .. off + 5 + payload.len], payload);
    return off + 5 + payload.len;
}

fn putAuthFrame(buf: []u8, off: usize, auth_code: u32, data: []const u8) usize {
    buf[off] = 'R';
    std.mem.writeInt(u32, buf[off + 1 ..][0..4], @intCast(8 + data.len), .big);
    std.mem.writeInt(u32, buf[off + 5 ..][0..4], auth_code, .big);
    @memcpy(buf[off + 9 .. off + 9 + data.len], data);
    return off + 9 + data.len;
}

// RFC 7677 §3 vector — user "user", password "pencil". The Handshake
// passes the user through to SCRAM, so the full exchange (client-final
// bytes and server-final verification) matches the RFC exactly.
const RFC_NONCE = "rOprNGfwEbeRWgbNEkqO";
const RFC_SERVER_FIRST = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const RFC_CLIENT_FINAL = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const RFC_SERVER_FINAL = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

test "handshake: full SCRAM exchange against RFC 7677 vector" {
    var hs = Handshake.init(.{
        .user = "user",
        .password = "pencil",
        .database = "appdb",
        .application_name = "swerver",
        .client_nonce = RFC_NONCE,
    });
    var send_buf: [512]u8 = undefined;

    // 1. Startup message.
    const startup = (try hs.takeSend(&send_buf)).?;
    try testing.expectEqual(
        protocol.PROTOCOL_VERSION,
        std.mem.readInt(u32, startup[4..8], .big),
    );
    try testing.expect(std.mem.indexOf(u8, startup, "user\x00user\x00") != null);
    try testing.expect(std.mem.indexOf(u8, startup, "database\x00appdb\x00") != null);
    try testing.expectEqual(@as(?[]u8, null), try hs.takeSend(&send_buf));
    try testing.expectEqual(Handshake.State.auth, hs.state);

    // 2. Server requests SASL with SCRAM-SHA-256.
    var rx: [512]u8 = undefined;
    var off = putAuthFrame(&rx, 0, 10, "SCRAM-SHA-256\x00\x00");
    try testing.expectEqual(off, try hs.feed(rx[0..off]));

    // 3. Client sends SASLInitialResponse with the RFC client-first.
    const initial = (try hs.takeSend(&send_buf)).?;
    try testing.expectEqual(@as(u8, 'p'), initial[0]);
    try testing.expect(std.mem.indexOf(u8, initial, "SCRAM-SHA-256\x00") != null);
    try testing.expect(std.mem.indexOf(u8, initial, "n,,n=user,r=" ++ RFC_NONCE) != null);

    // 4. Server-first → client-final must reproduce the RFC bytes.
    off = putAuthFrame(&rx, 0, 11, RFC_SERVER_FIRST);
    try testing.expectEqual(off, try hs.feed(rx[0..off]));
    const final = (try hs.takeSend(&send_buf)).?;
    try testing.expectEqual(@as(u8, 'p'), final[0]);
    try testing.expectEqualStrings(RFC_CLIENT_FINAL, final[5..]);

    // 5. Server-final + AuthenticationOk + session setup + ReadyForQuery.
    off = putAuthFrame(&rx, 0, 12, RFC_SERVER_FINAL);
    off = putAuthFrame(&rx, off, 0, "");
    off = putFrame(&rx, off, 'S', "server_version\x0016.3\x00");
    off = putFrame(&rx, off, 'K', "\x00\x00\x30\x39\x00\x00\x00\x07");
    off = putFrame(&rx, off, 'Z', "I");
    try testing.expectEqual(off, try hs.feed(rx[0..off]));

    try testing.expect(hs.isReady());
    try testing.expectEqual(@as(u32, 12345), hs.backend_pid);
    try testing.expectEqual(@as(u32, 7), hs.backend_secret);
    try testing.expectEqual(protocol.TxnStatus.idle, hs.txn_status);
    try testing.expectEqual(@as(?[]u8, null), try hs.takeSend(&send_buf));
}

test "handshake: tampered server-final signature fails closed" {
    var hs = Handshake.init(.{ .user = "user", .password = "pencil", .client_nonce = RFC_NONCE });
    var send_buf: [512]u8 = undefined;
    _ = (try hs.takeSend(&send_buf)).?;

    var rx: [512]u8 = undefined;
    var off = putAuthFrame(&rx, 0, 10, "SCRAM-SHA-256\x00\x00");
    _ = try hs.feed(rx[0..off]);
    _ = (try hs.takeSend(&send_buf)).?;
    off = putAuthFrame(&rx, 0, 11, RFC_SERVER_FIRST);
    _ = try hs.feed(rx[0..off]);
    _ = (try hs.takeSend(&send_buf)).?;

    var tampered: [RFC_SERVER_FINAL.len]u8 = RFC_SERVER_FINAL.*;
    tampered[2] = 'X';
    off = putAuthFrame(&rx, 0, 12, &tampered);
    try testing.expectError(error.ServerSignatureMismatch, hs.feed(rx[0..off]));
    try testing.expectEqual(Handshake.State.failed, hs.state);
    try testing.expectError(error.Failed, hs.feed(rx[0..off]));
    try testing.expectError(error.Failed, hs.takeSend(&send_buf));
}

test "handshake: server ErrorResponse surfaces code and message" {
    var hs = Handshake.init(.{ .user = "alice", .password = "wrong", .client_nonce = RFC_NONCE });
    var send_buf: [512]u8 = undefined;
    _ = (try hs.takeSend(&send_buf)).?;

    var rx: [256]u8 = undefined;
    const off = putFrame(&rx, 0, 'E', "SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00");
    try testing.expectError(error.ServerError, hs.feed(rx[0..off]));
    try testing.expectEqual(Handshake.State.failed, hs.state);
    const stored = hs.lastError().?;
    try testing.expectEqualStrings("28P01", stored.code());
    try testing.expectEqualStrings("password authentication failed", stored.message());
}

test "handshake: cleartext password request" {
    var hs = Handshake.init(.{ .user = "bob", .password = "hunter2", .client_nonce = RFC_NONCE });
    var send_buf: [256]u8 = undefined;
    _ = (try hs.takeSend(&send_buf)).?;

    var rx: [128]u8 = undefined;
    var off = putAuthFrame(&rx, 0, 3, "");
    try testing.expectEqual(off, try hs.feed(rx[0..off]));
    const pw = (try hs.takeSend(&send_buf)).?;
    try testing.expectEqualSlices(u8, "p\x00\x00\x00\x0chunter2\x00", pw);

    off = putAuthFrame(&rx, 0, 0, "");
    off = putFrame(&rx, off, 'Z', "I");
    try testing.expectEqual(off, try hs.feed(rx[0..off]));
    try testing.expect(hs.isReady());
}

test "handshake: unsupported auth methods are rejected" {
    // md5
    {
        var hs = Handshake.init(.{ .user = "u", .password = "p", .client_nonce = RFC_NONCE });
        var send_buf: [256]u8 = undefined;
        _ = (try hs.takeSend(&send_buf)).?;
        var rx: [64]u8 = undefined;
        const off = putAuthFrame(&rx, 0, 5, "salt");
        try testing.expectError(error.UnsupportedAuth, hs.feed(rx[0..off]));
    }
    // SASL list without SCRAM-SHA-256
    {
        var hs = Handshake.init(.{ .user = "u", .password = "p", .client_nonce = RFC_NONCE });
        var send_buf: [256]u8 = undefined;
        _ = (try hs.takeSend(&send_buf)).?;
        var rx: [64]u8 = undefined;
        const off = putAuthFrame(&rx, 0, 10, "SCRAM-SHA-256-PLUS\x00\x00");
        try testing.expectError(error.UnsupportedAuth, hs.feed(rx[0..off]));
    }
}

test "handshake: partial frames are retained across feeds" {
    var hs = Handshake.init(.{ .user = "u", .password = "p", .client_nonce = RFC_NONCE });
    var send_buf: [256]u8 = undefined;
    _ = (try hs.takeSend(&send_buf)).?;

    var rx: [128]u8 = undefined;
    var off = putAuthFrame(&rx, 0, 0, "");
    const first_len = off;
    off = putFrame(&rx, off, 'Z', "I");

    // Feed everything but the final byte: only the auth frame consumes.
    const consumed = try hs.feed(rx[0 .. off - 1]);
    try testing.expectEqual(first_len, consumed);
    try testing.expectEqual(Handshake.State.params, hs.state);
    // Re-present the tail: handshake completes.
    const consumed2 = try hs.feed(rx[consumed..off]);
    try testing.expectEqual(off - consumed, consumed2);
    try testing.expect(hs.isReady());
}

test "handshake: stops consuming at ReadyForQuery" {
    var hs = Handshake.init(.{ .user = "u", .password = "p", .client_nonce = RFC_NONCE });
    var send_buf: [256]u8 = undefined;
    _ = (try hs.takeSend(&send_buf)).?;

    var rx: [128]u8 = undefined;
    var off = putAuthFrame(&rx, 0, 0, "");
    off = putFrame(&rx, off, 'Z', "I");
    const handshake_len = off;
    // A query-phase frame the handshake must not eat.
    off = putFrame(&rx, off, 'C', "SELECT 1\x00");

    try testing.expectEqual(handshake_len, try hs.feed(rx[0..off]));
    try testing.expect(hs.isReady());
}

test "handshake: query-phase message mid-auth is unexpected" {
    var hs = Handshake.init(.{ .user = "u", .password = "p", .client_nonce = RFC_NONCE });
    var send_buf: [256]u8 = undefined;
    _ = (try hs.takeSend(&send_buf)).?;
    var rx: [64]u8 = undefined;
    const off = putFrame(&rx, 0, 'D', "\x00\x00");
    try testing.expectError(error.UnexpectedMessage, hs.feed(rx[0..off]));
}

// ---------------------------------------------------------------------------
// Optional integration test against a live server. Set PG_TEST_DSN to a
// URL of the form postgres://user:password@host:port/database to enable.
// Test-only blocking I/O — the codec module itself never opens sockets.
// ---------------------------------------------------------------------------

const TestDsn = struct {
    user: []const u8,
    password: []const u8,
    host: []const u8,
    port: u16,
    database: []const u8,
};

fn parseTestDsn(dsn: []const u8) !TestDsn {
    const prefix = "postgres://";
    if (!std.mem.startsWith(u8, dsn, prefix)) return error.BadDsn;
    const rest = dsn[prefix.len..];
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.BadDsn;
    const userinfo = rest[0..at];
    const hostpart = rest[at + 1 ..];
    const colon = std.mem.indexOfScalar(u8, userinfo, ':') orelse return error.BadDsn;
    const slash = std.mem.indexOfScalar(u8, hostpart, '/') orelse return error.BadDsn;
    const hostport = hostpart[0..slash];
    const port_colon = std.mem.lastIndexOfScalar(u8, hostport, ':') orelse return error.BadDsn;
    return .{
        .user = userinfo[0..colon],
        .password = userinfo[colon + 1 ..],
        .host = hostport[0..port_colon],
        .port = try std.fmt.parseInt(u16, hostport[port_colon + 1 ..], 10),
        .database = hostpart[slash + 1 ..],
    };
}

test "integration: live handshake and extended query (PG_TEST_DSN)" {
    const dsn_z = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn = try parseTestDsn(std.mem.sliceTo(dsn_z, 0));

    const net = @import("../../runtime/net.zig");
    const clock = @import("../../runtime/clock.zig");

    const fd = try net.connectBlocking(dsn.host, dsn.port, 5000);
    defer clock.closeFd(fd);
    net.setSocketTimeouts(fd, 5000, 5000);

    var hs = Handshake.init(.{
        .user = dsn.user,
        .password = dsn.password,
        .database = dsn.database,
        .application_name = "swerver-pg-test",
        .client_nonce = "swerverIntegrationNonce0", // fixed: test-only
    });

    var send_buf: [1024]u8 = undefined;
    var rx: [16384]u8 = undefined;
    var rx_len: usize = 0;
    while (!hs.isReady()) {
        if (try hs.takeSend(&send_buf)) |out| try net.sendAll(fd, out);
        if (hs.isReady()) break;
        const n = try net.recvBlocking(fd, rx[rx_len..]);
        if (n == 0) return error.UnexpectedEof;
        rx_len += n;
        const consumed = try hs.feed(rx[0..rx_len]);
        std.mem.copyForwards(u8, rx[0 .. rx_len - consumed], rx[consumed..rx_len]);
        rx_len -= consumed;
    }

    // Extended query: Parse/Bind/Describe/Execute/Sync in one batch.
    var q: [512]u8 = undefined;
    var q_len: usize = 0;
    q_len += (try protocol.writeParse(q[q_len..], "", "select 41 + $1::int4, 'hi'::text, null::int4", &.{})).len;
    const params = [_]?[]const u8{"1"};
    q_len += (try protocol.writeBind(q[q_len..], "", "", &params)).len;
    q_len += (try protocol.writeDescribePortal(q[q_len..], "")).len;
    q_len += (try protocol.writeExecute(q[q_len..], "", 0)).len;
    q_len += (try protocol.writeSync(q[q_len..])).len;
    try net.sendAll(fd, q[0..q_len]);

    var saw_row = false;
    var done = false;
    while (!done) {
        const n = try net.recvBlocking(fd, rx[rx_len..]);
        if (n == 0) return error.UnexpectedEof;
        rx_len += n;
        var iter = protocol.FrameIter.init(rx[0..rx_len]);
        while (try iter.next()) |frame| {
            switch (@as(protocol.BackendType, @enumFromInt(frame.typ))) {
                .data_row => {
                    var row = try protocol.DataRowIter.init(frame.payload);
                    try testing.expectEqual(@as(u16, 3), row.column_count);
                    const c1 = (try row.next()).?;
                    try testing.expectEqual(@as(i32, 42), try types.decodeInt4(c1.?));
                    const c2 = (try row.next()).?;
                    try testing.expectEqualStrings("hi", types.decodeText(c2.?));
                    const c3 = (try row.next()).?;
                    try testing.expectEqual(@as(protocol.DataValue, null), c3);
                    saw_row = true;
                },
                .error_response => {
                    const info = try protocol.parseErrorResponse(frame.payload);
                    std.debug.print("server error {s}: {s}\n", .{ info.code, info.message });
                    return error.ServerError;
                },
                .ready_for_query => done = true,
                else => {},
            }
        }
        const consumed = iter.consumed();
        std.mem.copyForwards(u8, rx[0 .. rx_len - consumed], rx[consumed..rx_len]);
        rx_len -= consumed;
    }
    try testing.expect(saw_row);

    var term_buf: [8]u8 = undefined;
    try net.sendAll(fd, try protocol.writeTerminate(&term_buf));
}
