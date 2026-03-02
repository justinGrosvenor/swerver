const std = @import("std");
const ffi = @import("ffi.zig");
const build_options = @import("build_options");

/// TLS 1.3 provider for QUIC handshake and key derivation.
/// Uses OpenSSL/BoringSSL via C FFI.
pub const Provider = struct {
    ctx: *ffi.SSL_CTX,
    allocator: std.mem.Allocator,

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

    /// Initialize a TLS provider for client connections (no certificates needed).
    pub fn initClient(allocator: std.mem.Allocator) Error!Provider {
        const ctx = ffi.createContext(false) catch return error.ContextCreationFailed;

        return .{
            .ctx = ctx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Provider) void {
        ffi.freeContext(self.ctx);
    }

    /// Create a new TLS session for a connection (memory BIO for QUIC).
    pub fn createSession(self: *Provider, is_server: bool) Error!Session {
        const ssl = ffi.createSession(self.ctx, is_server) catch return error.SessionCreationFailed;
        return Session{ .ssl = ssl, .is_socket = false };
    }

    /// Create a new TLS session for a TCP socket connection.
    pub fn createSocketSession(self: *Provider, fd: std.posix.fd_t) Error!Session {
        const ssl = ffi.createSocketSession(self.ctx, fd, true) catch return error.SessionCreationFailed;
        return Session{ .ssl = ssl, .is_socket = true };
    }
};

/// Represents a TLS session for a single connection.
/// For QUIC, this handles the TLS 1.3 handshake and key derivation.
/// For TCP, this wraps socket read/write with encryption.
pub const Session = struct {
    ssl: *ffi.SSL,
    is_socket: bool = false,
    handshake_complete: bool = false,

    pub const Error = error{
        HandshakeFailed,
        KeyExportFailed,
        BioWriteFailed,
        BioReadFailed,
        NoBio,
        WouldBlock,
        ConnectionClosed,
        TlsError,
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
        return ffi.sslRead(self.ssl, buf) catch |err| switch (err) {
            error.WouldBlock => error.WouldBlock,
            error.ConnectionClosed => error.ConnectionClosed,
            error.TlsError => error.TlsError,
        };
    }

    /// Write data to TLS socket connection (encrypts automatically).
    pub fn write(self: *Session, data: []const u8) Error!usize {
        return ffi.sslWrite(self.ssl, data) catch |err| switch (err) {
            error.WouldBlock => error.WouldBlock,
            error.TlsError => error.TlsError,
        };
    }

    /// Feed incoming TLS handshake data (from CRYPTO frames).
    pub fn feedCryptoData(self: *Session, data: []const u8) Error!usize {
        if (!build_options.enable_tls) return error.TlsError;
        return ffi.feedCryptoData(self.ssl, data) catch |err| switch (err) {
            error.NoBio => error.NoBio,
            error.BioWriteFailed => error.BioWriteFailed,
            else => error.TlsError,
        };
    }

    /// Read outgoing TLS handshake data (for CRYPTO frames).
    pub fn readCryptoData(self: *Session, buf: []u8) Error!usize {
        if (!build_options.enable_tls) return error.TlsError;
        return ffi.readCryptoData(self.ssl, buf) catch |err| switch (err) {
            error.NoBio => error.NoBio,
            error.BioReadFailed => error.BioReadFailed,
            else => error.TlsError,
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
