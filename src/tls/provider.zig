const std = @import("std");
const ffi = @import("ffi.zig");
const build_options = @import("build_options");
pub const quic_session = @import("quic_session.zig");
pub const QuicState = quic_session.QuicState;
pub const QuicLevel = quic_session.Level;
pub const QuicDirection = quic_session.Direction;

pub const MAX_SNI_ENTRIES = 64;

pub const SniEntry = struct {
    hostname: [:0]const u8,
    ctx: *ffi.SSL_CTX,
    is_wildcard: bool,
};

pub const CertStore = struct {
    entries: [MAX_SNI_ENTRIES]SniEntry,
    count: usize,
    default_ctx: *ffi.SSL_CTX,

    pub fn lookup(self: *const CertStore, hostname: []const u8) *ffi.SSL_CTX {
        for (self.entries[0..self.count]) |entry| {
            if (entry.is_wildcard) {
                if (matchWildcard(entry.hostname, hostname)) return entry.ctx;
            } else {
                if (std.ascii.eqlIgnoreCase(entry.hostname, hostname)) return entry.ctx;
            }
        }
        return self.default_ctx;
    }

    fn matchWildcard(pattern: [:0]const u8, hostname: []const u8) bool {
        if (!std.mem.startsWith(u8, pattern, "*.")) return false;
        const suffix = pattern[1..]; // ".example.com"
        if (hostname.len <= suffix.len) return false;
        const host_suffix = hostname[hostname.len - suffix.len ..];
        if (!std.ascii.eqlIgnoreCase(host_suffix, suffix)) return false;
        const prefix = hostname[0 .. hostname.len - suffix.len];
        return std.mem.indexOfScalar(u8, prefix, '.') == null;
    }
};

fn sniCallback(ssl: *ffi.SSL, _: *c_int, arg: ?*anyopaque) callconv(.c) c_int {
    const store: *const CertStore = @ptrCast(@alignCast(arg orelse return ffi.SSL_TLSEXT_ERR_OK_NOACK));
    const hostname = ffi.getServername(ssl) orelse return ffi.SSL_TLSEXT_ERR_OK_NOACK;
    const ctx = store.lookup(hostname);
    ffi.setSslCtx(ssl, ctx);
    return ffi.SSL_TLSEXT_ERR_OK_NOACK;
}

/// TLS provider for QUIC handshake and key derivation, and TCP TLS.
/// Uses OpenSSL/BoringSSL via C FFI.
pub const Provider = struct {
    ctx: *ffi.SSL_CTX,
    allocator: std.mem.Allocator,
    cert_store: ?*CertStore = null,

    pub const Error = error{
        ContextCreationFailed,
        CertificateLoadFailed,
        PrivateKeyLoadFailed,
        PrivateKeyMismatch,
        SessionCreationFailed,
        BioCreationFailed,
        TlsNotAvailable,
    };

    /// Initialize a TLS provider with server certificates.
    pub fn init(allocator: std.mem.Allocator, cert_path: [:0]const u8, key_path: [:0]const u8) Error!Provider {
        const ctx = ffi.createContext(true) catch return error.ContextCreationFailed;
        errdefer ffi.freeContext(ctx);

        ffi.loadCertificateChain(ctx, cert_path) catch return error.CertificateLoadFailed;
        ffi.loadPrivateKey(ctx, key_path) catch return error.PrivateKeyLoadFailed;

        return .{
            .ctx = ctx,
            .allocator = allocator,
        };
    }

    /// Initialize a TLS provider for QUIC: TLS 1.3 only, AES-128-GCM
    /// ciphersuite, h3 ALPN. Use this instead of init() when the resulting
    /// Provider will create QUIC sessions via createQuicSession().
    pub fn initQuic(allocator: std.mem.Allocator, cert_path: [:0]const u8, key_path: [:0]const u8) Error!Provider {
        const ctx = ffi.createQuicContext(true) catch return error.ContextCreationFailed;
        errdefer ffi.freeContext(ctx);

        ffi.loadCertificateChain(ctx, cert_path) catch return error.CertificateLoadFailed;
        ffi.loadPrivateKey(ctx, key_path) catch return error.PrivateKeyLoadFailed;

        return .{
            .ctx = ctx,
            .allocator = allocator,
        };
    }

    /// Initialize a TLS provider for TCP connections (TLS 1.2+, ALPN h2/http1.1).
    pub fn initTcp(allocator: std.mem.Allocator, cert_path: [:0]const u8, key_path: [:0]const u8) Error!Provider {
        const ctx = ffi.createTcpContext(true) catch return error.ContextCreationFailed;
        errdefer ffi.freeContext(ctx);

        ffi.loadCertificateChain(ctx, cert_path) catch return error.CertificateLoadFailed;
        ffi.loadPrivateKey(ctx, key_path) catch return error.PrivateKeyLoadFailed;

        return .{
            .ctx = ctx,
            .allocator = allocator,
        };
    }

    pub const CertEntry = struct {
        hostnames: []const [:0]const u8,
        cert_path: [:0]const u8,
        key_path: [:0]const u8,
    };

    pub const MtlsConfig = struct {
        ca_path: [:0]const u8 = "",
        require: bool = true,
    };

    /// Initialize a TLS provider with SNI support for multiple certificates.
    /// The first cert_path/key_path is the default (used when no SNI match).
    /// Additional certificates are routed via SNI hostname matching.
    /// Optional mTLS configuration enables client certificate verification.
    pub fn initTcpSni(
        allocator: std.mem.Allocator,
        default_cert: [:0]const u8,
        default_key: [:0]const u8,
        extra_certs: []const CertEntry,
    ) Error!Provider {
        return initTcpSniMtls(allocator, default_cert, default_key, extra_certs, null);
    }

    pub fn initTcpSniMtls(
        allocator: std.mem.Allocator,
        default_cert: [:0]const u8,
        default_key: [:0]const u8,
        extra_certs: []const CertEntry,
        mtls: ?MtlsConfig,
    ) Error!Provider {
        const default_ctx = ffi.createTcpContext(true) catch return error.ContextCreationFailed;
        errdefer ffi.freeContext(default_ctx);

        ffi.loadCertificateChain(default_ctx, default_cert) catch return error.CertificateLoadFailed;
        ffi.loadPrivateKey(default_ctx, default_key) catch return error.PrivateKeyLoadFailed;

        if (mtls) |m| {
            if (m.ca_path.len > 0) {
                ffi.loadCaCert(default_ctx, m.ca_path) catch return error.CertificateLoadFailed;
                ffi.setVerifyPeer(default_ctx, m.require);
            }
        }

        if (extra_certs.len == 0) {
            return .{ .ctx = default_ctx, .allocator = allocator };
        }

        const store = allocator.create(CertStore) catch return error.ContextCreationFailed;
        store.* = .{
            .entries = undefined,
            .count = 0,
            .default_ctx = default_ctx,
        };
        errdefer {
            for (store.entries[0..store.count]) |entry| ffi.freeContext(entry.ctx);
            allocator.destroy(store);
        }

        for (extra_certs) |cert| {
            const ctx = ffi.createTcpContext(true) catch return error.ContextCreationFailed;
            errdefer ffi.freeContext(ctx);

            ffi.loadCertificateChain(ctx, cert.cert_path) catch return error.CertificateLoadFailed;
            ffi.loadPrivateKey(ctx, cert.key_path) catch return error.PrivateKeyLoadFailed;

            if (mtls) |m| {
                if (m.ca_path.len > 0) {
                    ffi.loadCaCert(ctx, m.ca_path) catch return error.CertificateLoadFailed;
                    ffi.setVerifyPeer(ctx, m.require);
                }
            }

            for (cert.hostnames) |hostname| {
                if (store.count >= MAX_SNI_ENTRIES) break;
                store.entries[store.count] = .{
                    .hostname = hostname,
                    .ctx = ctx,
                    .is_wildcard = std.mem.startsWith(u8, hostname, "*."),
                };
                store.count += 1;
            }
        }

        ffi.setSniCallback(default_ctx, sniCallback, @ptrCast(store));

        return .{
            .ctx = default_ctx,
            .allocator = allocator,
            .cert_store = store,
        };
    }

    /// Initialize a TLS provider for client connections (no certificates needed).
    pub fn initClient(allocator: std.mem.Allocator) Error!Provider {
        const ctx = ffi.createContext(false) catch return error.ContextCreationFailed;
        ffi.loadDefaultVerifyPaths(ctx) catch {
            ffi.freeContext(ctx);
            return error.ContextCreationFailed;
        };
        ffi.setVerifyPeer(ctx, false);

        return .{
            .ctx = ctx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Provider) void {
        if (self.cert_store) |store| {
            var freed: [MAX_SNI_ENTRIES]*ffi.SSL_CTX = undefined;
            var freed_count: usize = 0;
            for (store.entries[0..store.count]) |entry| {
                if (entry.ctx == self.ctx) continue;
                var already_freed = false;
                for (freed[0..freed_count]) |f| {
                    if (f == entry.ctx) { already_freed = true; break; }
                }
                if (!already_freed) {
                    ffi.freeContext(entry.ctx);
                    if (freed_count < freed.len) {
                        freed[freed_count] = entry.ctx;
                        freed_count += 1;
                    }
                }
            }
            self.allocator.destroy(store);
            self.cert_store = null;
        }
        ffi.freeContext(self.ctx);
    }

    /// Create a new TLS session for a connection (memory BIO — legacy path).
    /// New QUIC code should use createQuicSession instead, which uses the
    /// SSL_set_quic_tls_cbs callback API rather than memory BIOs.
    pub fn createSession(self: *Provider, is_server: bool) Error!Session {
        const ssl = ffi.createSession(self.ctx, is_server) catch return error.SessionCreationFailed;
        return Session{ .ssl = ssl, .is_socket = false };
    }

    /// Create a new TLS session bound to a QuicState callback adapter.
    /// Allocates and pins a QuicState (the dispatch table inside it must
    /// outlive the SSL), installs the QUIC TLS callbacks, and returns a
    /// Session in `quic` mode.
    ///
    /// Caller must call deinit on the returned Session, which frees the
    /// QuicState.
    pub fn createQuicSession(self: *Provider, is_server: bool) Error!Session {
        const ssl = ffi.createBareSession(self.ctx, is_server) catch return error.SessionCreationFailed;
        errdefer ffi.freeSession(ssl);

        const state = QuicState.init(self.allocator) catch return error.SessionCreationFailed;
        errdefer state.deinit(self.allocator);

        state.install(ssl) catch return error.SessionCreationFailed;

        return Session{
            .ssl = ssl,
            .is_socket = false,
            .quic = state,
            .quic_allocator = self.allocator,
        };
    }

    /// Create a new TLS session for a TCP socket connection.
    pub fn createSocketSession(self: *Provider, fd: std.posix.fd_t) Error!Session {
        const ssl = ffi.createSocketSession(self.ctx, fd, true) catch return error.SessionCreationFailed;
        return Session{ .ssl = ssl, .is_socket = true };
    }

    /// Create a new TLS session for a TCP connection using memory BIOs
    /// instead of a socket BIO. The caller is responsible for feeding
    /// incoming ciphertext to rbio via `Session.feedCryptoData` and draining
    /// outgoing ciphertext from wbio via `Session.readCryptoData`.
    ///
    /// This is required to run TLS over the native io_uring backend, where
    /// multishot recv has already drained the socket's bytes into a kernel
    /// provided buffer — a socket BIO's internal `recv(fd)` would see EAGAIN.
    pub fn createTcpMemSession(self: *Provider) Error!Session {
        const ssl = ffi.createSession(self.ctx, true) catch return error.SessionCreationFailed;
        // is_socket=false — we don't want Session.deinit to call SSL_shutdown
        // (the shutdown alert would write to wbio and we'd have to pump it).
        // Close_notify is skipped; TCP RST on connection teardown is fine.
        return Session{ .ssl = ssl, .is_socket = false };
    }
};

/// Represents a TLS session for a single connection.
/// For QUIC, this handles the TLS 1.3 handshake and key derivation.
/// For TCP, this wraps socket read/write with encryption.
pub const Session = struct {
    ssl: *ffi.SSL,
    is_socket: bool = false,
    handshake_complete: bool = false,
    /// Set when the session was created via createQuicSession (callback mode).
    /// The QuicState is heap-pinned and owned by this Session.
    quic: ?*QuicState = null,
    quic_allocator: ?std.mem.Allocator = null,

    pub const Error = error{
        HandshakeFailed,
        KeyExportFailed,
        BioWriteFailed,
        BioReadFailed,
        NoBio,
        WouldBlock,
        ConnectionClosed,
        TlsError,
        TransportParamsTooLarge,
    };

    pub const HandshakeState = enum {
        in_progress,
        complete,
        failed,
    };

    pub fn deinit(self: *Session) void {
        if (self.is_socket) {
            ffi.sslShutdown(self.ssl);
        }
        ffi.freeSession(self.ssl);
        if (self.quic) |state| {
            if (self.quic_allocator) |alloc| state.deinit(alloc);
        }
    }

    /// Set the local QUIC transport parameters blob. Must be called before
    /// the first SSL_do_handshake. Only valid in QUIC mode.
    pub fn setQuicTransportParams(self: *Session, params: []const u8) Error!void {
        const state = self.quic orelse return error.TlsError;
        state.setLocalTransportParams(self.ssl, params) catch return error.TransportParamsTooLarge;
    }

    /// Feed CRYPTO frame bytes received at the given encryption level into
    /// the TLS state machine. The QUIC stack calls this before doHandshake.
    pub fn feedQuicCryptoData(self: *Session, level: QuicLevel, data: []const u8) Error!void {
        const state = self.quic orelse return error.TlsError;
        state.feedCryptoData(level, data) catch return error.BioWriteFailed;
    }

    /// Drain pending outgoing CRYPTO bytes at the given encryption level.
    /// Returns a slice valid until consumeQuicOutgoing is called.
    pub fn pendingQuicOutgoing(self: *Session, level: QuicLevel) []const u8 {
        const state = self.quic orelse return &.{};
        return state.pendingOutgoing(level);
    }

    pub fn consumeQuicOutgoing(self: *Session, level: QuicLevel, n: usize) void {
        const state = self.quic orelse return;
        state.consumeOutgoing(level, n);
    }

    /// Get the installed traffic secret at (direction, level), or null if
    /// not yet derived. Used by QUIC to compute packet protection keys.
    pub fn getQuicSecret(self: *Session, dir: QuicDirection, level: QuicLevel) ?[]const u8 {
        const state = self.quic orelse return null;
        return state.getSecret(dir, level);
    }

    /// Drain the list of (direction, level) tuples for which a secret was
    /// installed since the last call. Returns count written to `out`.
    pub fn takePendingQuicSecrets(self: *Session, out: *[8]quic_session.QuicState.SecretReady) usize {
        const state = self.quic orelse return 0;
        return state.takePendingSecrets(out);
    }

    /// The peer's QUIC transport parameters TLV blob (or null if not yet
    /// received).
    pub fn peerQuicTransportParams(self: *Session) ?[]const u8 {
        const state = self.quic orelse return null;
        return state.peerTransportParams();
    }

    /// Accept TLS handshake on a socket connection (server-side).
    /// Returns true if handshake complete, false if more I/O needed.
    pub fn accept(self: *Session) Error!bool {
        if (self.handshake_complete) return true;

        switch (ffi.sslAccept(self.ssl)) {
            .complete => {
                self.handshake_complete = true;
                return true;
            },
            .want_read, .want_write => return false,
            .err => return error.HandshakeFailed,
        }
    }

    /// Read decrypted data from TLS socket connection.
    pub fn read(self: *Session, buf: []u8) Error!usize {
        if (comptime build_options.enable_tls) {
            return ffi.sslRead(self.ssl, buf) catch |err| switch (err) {
                error.WouldBlock => error.WouldBlock,
                error.ConnectionClosed => error.ConnectionClosed,
                error.TlsError => error.TlsError,
            };
        }
        return error.TlsError;
    }

    /// Write data to TLS socket connection (encrypts automatically).
    pub fn write(self: *Session, data: []const u8) Error!usize {
        if (comptime build_options.enable_tls) {
            return ffi.sslWrite(self.ssl, data) catch |err| switch (err) {
                error.WouldBlock => error.WouldBlock,
                error.TlsError => error.TlsError,
            };
        }
        return error.TlsError;
    }

    /// Feed incoming TLS handshake data (from CRYPTO frames).
    pub fn feedCryptoData(self: *Session, data: []const u8) Error!usize {
        if (!build_options.enable_tls) return error.TlsError;
        return ffi.feedCryptoData(self.ssl, data) catch |err| switch (err) {
            error.NoBio => error.NoBio,
            error.BioWriteFailed => error.BioWriteFailed,
        };
    }

    /// Read outgoing TLS handshake data (for CRYPTO frames).
    pub fn readCryptoData(self: *Session, buf: []u8) Error!usize {
        if (!build_options.enable_tls) return error.TlsError;
        return ffi.readCryptoData(self.ssl, buf) catch |err| switch (err) {
            error.NoBio => error.NoBio,
            error.BioReadFailed => error.BioReadFailed,
        };
    }

    /// Advance the TLS handshake.
    pub fn doHandshake(self: *Session) HandshakeState {
        return switch (ffi.doHandshake(self.ssl)) {
            .complete => .complete,
            .want_read, .want_write => .in_progress,
            .err => .failed,
        };
    }

    /// Check if the handshake is complete.
    pub fn isHandshakeComplete(self: *const Session) bool {
        return ffi.isHandshakeComplete(self.ssl);
    }

    /// Get the negotiated ALPN protocol (should be "h3" for HTTP/3).
    pub fn getAlpn(self: *const Session) ?[]const u8 {
        return ffi.getSelectedAlpn(self.ssl);
    }

    pub fn getPeerCertSubject(self: *const Session, buf: []u8) ?[]const u8 {
        return ffi.getPeerCertSubject(self.ssl, buf);
    }

    /// Export keying material for QUIC packet protection.
    /// Used to derive Initial, Handshake, and Application keys.
    pub fn exportKeyingMaterial(self: *Session, out: []u8, label: []const u8, context: ?[]const u8) Error!void {
        ffi.exportKeyingMaterial(self.ssl, out, label, context) catch return error.KeyExportFailed;
    }

    /// Derive QUIC Initial keys from the Destination Connection ID.
    /// Per RFC 9001, Initial keys are derived without TLS using a fixed salt.
    pub fn deriveInitialSecret(dcid: []const u8, out: []u8) void {
        // RFC 9001 Section 5.2: Initial keys use HKDF with a version-specific salt
        // Salt for QUIC v1: 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
        const salt = [_]u8{
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        };

        // HKDF-Extract(salt, dcid)
        var hmac = std.crypto.auth.hmac.sha256.init(salt[0..]);
        hmac.update(dcid);
        const extract = hmac.finalResult();

        // Copy to output (truncate or pad as needed)
        const copy_len = @min(out.len, extract.len);
        @memcpy(out[0..copy_len], extract[0..copy_len]);
    }
};

/// QUIC-specific key labels for TLS key export.
pub const QuicKeyLabels = struct {
    pub const client_initial = ffi.QUIC_CLIENT_INITIAL_LABEL;
    pub const server_initial = ffi.QUIC_SERVER_INITIAL_LABEL;
    pub const client_handshake = ffi.QUIC_CLIENT_HANDSHAKE_LABEL;
    pub const server_handshake = ffi.QUIC_SERVER_HANDSHAKE_LABEL;
    pub const client_application = ffi.QUIC_CLIENT_APPLICATION_LABEL;
    pub const server_application = ffi.QUIC_SERVER_APPLICATION_LABEL;
};

test "wildcard matching" {
    try std.testing.expect(CertStore.matchWildcard("*.example.com", "api.example.com"));
    try std.testing.expect(CertStore.matchWildcard("*.example.com", "www.example.com"));
    try std.testing.expect(!CertStore.matchWildcard("*.example.com", "example.com"));
    try std.testing.expect(!CertStore.matchWildcard("*.example.com", "sub.api.example.com"));
    try std.testing.expect(!CertStore.matchWildcard("*.example.com", "other.com"));
    try std.testing.expect(!CertStore.matchWildcard("api.example.com", "api.example.com"));
}

test "config parsing with certificates" {
    const config_mod = @import("../config.zig");
    const cert = config_mod.TlsCertificate{
        .hostnames = &.{},
        .cert_path = "test.pem",
        .key_path = "test.key",
    };
    try std.testing.expectEqual(@as(usize, 0), cert.hostnames.len);
    try std.testing.expectEqualStrings("test.pem", cert.cert_path);
}
