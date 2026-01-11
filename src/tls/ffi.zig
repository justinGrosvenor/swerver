const std = @import("std");
const builtin = @import("builtin");

/// C FFI bindings for OpenSSL/BoringSSL TLS 1.3 operations.
/// Used by QUIC for handshake and key derivation.

// Opaque C types
pub const SSL_CTX = opaque {};
pub const SSL = opaque {};
pub const SSL_METHOD = opaque {};
pub const X509 = opaque {};
pub const EVP_PKEY = opaque {};
pub const BIO = opaque {};
pub const BIO_METHOD = opaque {};

// Error codes
pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_ERROR_WANT_CONNECT: c_int = 7;
pub const SSL_ERROR_WANT_ACCEPT: c_int = 8;

// SSL/TLS version constants
pub const TLS1_3_VERSION: c_int = 0x0304;

// SSL mode flags
pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_long = 0x00000001;
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 0x00000002;

// SSL control options
pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;

// ALPN callback return values
pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

// Key export labels for QUIC
pub const QUIC_CLIENT_INITIAL_LABEL = "client in";
pub const QUIC_SERVER_INITIAL_LABEL = "server in";
pub const QUIC_CLIENT_HANDSHAKE_LABEL = "c hs traffic";
pub const QUIC_SERVER_HANDSHAKE_LABEL = "s hs traffic";
pub const QUIC_CLIENT_APPLICATION_LABEL = "c ap traffic";
pub const QUIC_SERVER_APPLICATION_LABEL = "s ap traffic";

// QUIC encryption levels (for key export)
pub const QuicEncryptionLevel = enum(c_int) {
    initial = 0,
    early_data = 1,
    handshake = 2,
    application = 3,
};

// Function pointer types for callbacks
pub const AlpnSelectCallback = *const fn (
    ssl: *SSL,
    out: *[*]const u8,
    outlen: *u8,
    in: [*]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.C) c_int;

// External C functions - these are resolved at link time
extern fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern fn SSL_CTX_free(ctx: *SSL_CTX) void;
extern fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, file: [*:0]const u8) c_int;
extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, typ: c_int) c_int;
extern fn SSL_CTX_check_private_key(ctx: *SSL_CTX) c_int;
extern fn SSL_CTX_set_alpn_select_cb(ctx: *SSL_CTX, cb: AlpnSelectCallback, arg: ?*anyopaque) void;
extern fn SSL_CTX_ctrl(ctx: *SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;

extern fn SSL_new(ctx: *SSL_CTX) ?*SSL;
extern fn SSL_free(ssl: *SSL) void;
extern fn SSL_set_accept_state(ssl: *SSL) void;
extern fn SSL_set_connect_state(ssl: *SSL) void;
extern fn SSL_do_handshake(ssl: *SSL) c_int;
extern fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
extern fn SSL_is_init_finished(ssl: *const SSL) c_int;
extern fn SSL_read(ssl: *SSL, buf: [*]u8, num: c_int) c_int;
extern fn SSL_write(ssl: *SSL, buf: [*]const u8, num: c_int) c_int;
extern fn SSL_get0_alpn_selected(ssl: *const SSL, data: *[*]const u8, len: *c_uint) void;
extern fn SSL_export_keying_material(
    ssl: *SSL,
    out: [*]u8,
    olen: usize,
    label: [*]const u8,
    llen: usize,
    context: ?[*]const u8,
    contextlen: usize,
    use_context: c_int,
) c_int;

extern fn TLS_server_method() *const SSL_METHOD;
extern fn TLS_client_method() *const SSL_METHOD;

extern fn BIO_new(typ: *const BIO_METHOD) ?*BIO;
extern fn BIO_free(bio: *BIO) c_int;
extern fn BIO_s_mem() *const BIO_METHOD;
extern fn BIO_read(bio: *BIO, data: [*]u8, dlen: c_int) c_int;
extern fn BIO_write(bio: *BIO, data: [*]const u8, dlen: c_int) c_int;
extern fn BIO_ctrl_pending(bio: *BIO) usize;

extern fn SSL_set_bio(ssl: *SSL, rbio: ?*BIO, wbio: ?*BIO) void;
extern fn SSL_get_rbio(ssl: *const SSL) ?*BIO;
extern fn SSL_get_wbio(ssl: *const SSL) ?*BIO;
extern fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
extern fn SSL_accept(ssl: *SSL) c_int;
extern fn SSL_connect(ssl: *SSL) c_int;
extern fn SSL_shutdown(ssl: *SSL) c_int;

extern fn ERR_get_error() c_ulong;
extern fn ERR_error_string_n(e: c_ulong, buf: [*]u8, len: usize) void;

// File type constants for SSL_CTX_use_PrivateKey_file
pub const SSL_FILETYPE_PEM: c_int = 1;
pub const SSL_FILETYPE_ASN1: c_int = 2;

// Zig wrapper functions for safer usage

pub fn createContext(is_server: bool) !*SSL_CTX {
    const method = if (is_server) TLS_server_method() else TLS_client_method();
    const ctx = SSL_CTX_new(method) orelse return error.ContextCreationFailed;

    // Set minimum TLS version to 1.3 for QUIC
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, null);
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, null);

    return ctx;
}

pub fn freeContext(ctx: *SSL_CTX) void {
    SSL_CTX_free(ctx);
}

pub fn loadCertificateChain(ctx: *SSL_CTX, path: [:0]const u8) !void {
    if (SSL_CTX_use_certificate_chain_file(ctx, path.ptr) != 1) {
        return error.CertificateLoadFailed;
    }
}

pub fn loadPrivateKey(ctx: *SSL_CTX, path: [:0]const u8) !void {
    if (SSL_CTX_use_PrivateKey_file(ctx, path.ptr, SSL_FILETYPE_PEM) != 1) {
        return error.PrivateKeyLoadFailed;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        return error.PrivateKeyMismatch;
    }
}

pub fn createSession(ctx: *SSL_CTX, is_server: bool) !*SSL {
    const ssl = SSL_new(ctx) orelse return error.SessionCreationFailed;
    if (is_server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }

    // Set up memory BIOs for QUIC integration
    const rbio = BIO_new(BIO_s_mem()) orelse {
        SSL_free(ssl);
        return error.BioCreationFailed;
    };
    const wbio = BIO_new(BIO_s_mem()) orelse {
        _ = BIO_free(rbio);
        SSL_free(ssl);
        return error.BioCreationFailed;
    };

    SSL_set_bio(ssl, rbio, wbio);
    return ssl;
}

pub fn freeSession(ssl: *SSL) void {
    SSL_free(ssl);
}

/// Create a session for socket-based TLS (not memory BIO)
pub fn createSocketSession(ctx: *SSL_CTX, fd: c_int, is_server: bool) !*SSL {
    const ssl = SSL_new(ctx) orelse return error.SessionCreationFailed;
    errdefer SSL_free(ssl);

    if (SSL_set_fd(ssl, fd) != 1) {
        return error.SessionCreationFailed;
    }

    if (is_server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }

    return ssl;
}

/// Perform TLS accept handshake (for server)
pub fn sslAccept(ssl: *SSL) HandshakeResult {
    const ret = SSL_accept(ssl);
    if (ret == 1) return .complete;

    const err = SSL_get_error(ssl, ret);
    return switch (err) {
        SSL_ERROR_WANT_READ => .want_read,
        SSL_ERROR_WANT_WRITE => .want_write,
        else => .err,
    };
}

/// Read decrypted data from TLS connection
pub fn sslRead(ssl: *SSL, buf: []u8) !usize {
    const ret = SSL_read(ssl, buf.ptr, @intCast(buf.len));
    if (ret > 0) return @intCast(ret);
    if (ret == 0) return 0; // Connection closed

    const err = SSL_get_error(ssl, ret);
    return switch (err) {
        SSL_ERROR_WANT_READ => error.WouldBlock,
        SSL_ERROR_WANT_WRITE => error.WouldBlock,
        SSL_ERROR_ZERO_RETURN => error.ConnectionClosed,
        else => error.TlsError,
    };
}

/// Write data to TLS connection (encrypts automatically)
pub fn sslWrite(ssl: *SSL, data: []const u8) !usize {
    const ret = SSL_write(ssl, data.ptr, @intCast(data.len));
    if (ret > 0) return @intCast(ret);

    const err = SSL_get_error(ssl, ret);
    return switch (err) {
        SSL_ERROR_WANT_READ => error.WouldBlock,
        SSL_ERROR_WANT_WRITE => error.WouldBlock,
        else => error.TlsError,
    };
}

/// Shutdown TLS connection
pub fn sslShutdown(ssl: *SSL) void {
    _ = SSL_shutdown(ssl);
}

pub const HandshakeResult = enum {
    complete,
    want_read,
    want_write,
    err,
};

pub fn doHandshake(ssl: *SSL) HandshakeResult {
    const ret = SSL_do_handshake(ssl);
    if (ret == 1) return .complete;

    const err = SSL_get_error(ssl, ret);
    return switch (err) {
        SSL_ERROR_WANT_READ => .want_read,
        SSL_ERROR_WANT_WRITE => .want_write,
        else => .err,
    };
}

pub fn isHandshakeComplete(ssl: *const SSL) bool {
    return SSL_is_init_finished(ssl) != 0;
}

pub fn feedCryptoData(ssl: *SSL, data: []const u8) !usize {
    const rbio = SSL_get_rbio(ssl) orelse return error.NoBio;
    const written = BIO_write(rbio, data.ptr, @intCast(data.len));
    if (written < 0) return error.BioWriteFailed;
    return @intCast(written);
}

pub fn readCryptoData(ssl: *SSL, buf: []u8) !usize {
    const wbio = SSL_get_wbio(ssl) orelse return error.NoBio;
    const pending = BIO_ctrl_pending(wbio);
    if (pending == 0) return 0;

    const to_read: c_int = @intCast(@min(buf.len, pending));
    const read = BIO_read(wbio, buf.ptr, to_read);
    if (read < 0) return error.BioReadFailed;
    return @intCast(read);
}

pub fn exportKeyingMaterial(
    ssl: *SSL,
    out: []u8,
    label: []const u8,
    context: ?[]const u8,
) !void {
    const ctx_ptr = if (context) |c| c.ptr else null;
    const ctx_len = if (context) |c| c.len else 0;
    const use_ctx: c_int = if (context != null) 1 else 0;

    const ret = SSL_export_keying_material(
        ssl,
        out.ptr,
        out.len,
        label.ptr,
        label.len,
        ctx_ptr,
        ctx_len,
        use_ctx,
    );
    if (ret != 1) return error.KeyExportFailed;
}

pub fn getSelectedAlpn(ssl: *const SSL) ?[]const u8 {
    var data: [*]const u8 = undefined;
    var len: c_uint = 0;
    SSL_get0_alpn_selected(ssl, &data, &len);
    if (len == 0) return null;
    return data[0..len];
}

pub fn getLastError() [256]u8 {
    var buf: [256]u8 = undefined;
    const err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, &buf, buf.len);
    } else {
        @memset(&buf, 0);
    }
    return buf;
}
