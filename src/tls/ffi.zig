const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const tls_enabled = build_options.enable_tls;
const http3_enabled = build_options.enable_http3;

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

// TLS 1.2 version
pub const TLS1_2_VERSION: c_int = 0x0303;

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
    ssl_p: *SSL,
    out: *[*]const u8,
    outlen: *u8,
    in: [*]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int;

// File type constants for SSL_CTX_use_PrivateKey_file
pub const SSL_FILETYPE_PEM: c_int = 1;
pub const SSL_FILETYPE_ASN1: c_int = 2;

pub const HandshakeResult = enum {
    complete,
    want_read,
    want_write,
    err,
};

// External C functions - these are resolved at link time
extern fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern fn SSL_CTX_free(ctx: *SSL_CTX) void;
extern fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, file: [*:0]const u8) c_int;
extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, typ: c_int) c_int;
extern fn SSL_CTX_check_private_key(ctx: *SSL_CTX) c_int;
extern fn SSL_CTX_set_alpn_select_cb(ctx: *SSL_CTX, cb: AlpnSelectCallback, arg: ?*anyopaque) void;
extern fn SSL_CTX_ctrl(ctx: *SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
extern fn SSL_CTX_set_ciphersuites(ctx: *SSL_CTX, str: [*:0]const u8) c_int;
extern fn SSL_CTX_set_alpn_protos(ctx: *SSL_CTX, protos: [*]const u8, protos_len: c_uint) c_int;

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

// ============================================================
// QUIC TLS callback API (OpenSSL 3.5+, BoringSSL-compatible)
// ============================================================
//
// Lets a third-party QUIC stack drive OpenSSL's TLS 1.3 state machine.
// Instead of TLS records over a BIO, the QUIC stack feeds raw handshake
// bytes via crypto_recv_rcd and reads outgoing handshake bytes via
// crypto_send. Traffic secrets at each protection level are reported
// via yield_secret. Peer's QUIC transport parameters arrive via
// got_transport_params (and we set ours via SSL_set_quic_tls_transport_params
// before SSL_do_handshake).
//
// See `man 3ssl SSL_set_quic_tls_cbs` (OpenSSL 3.5+) for the contract.

/// OSSL_DISPATCH function id constants from <openssl/core_dispatch.h>
pub const OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND: c_int = 2001;
pub const OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD: c_int = 2002;
pub const OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD: c_int = 2003;
pub const OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET: c_int = 2004;
pub const OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS: c_int = 2005;
pub const OSSL_FUNC_SSL_QUIC_TLS_ALERT: c_int = 2006;

/// TLS protection level constants reported by yield_secret.
/// These match RFC 9001 encryption levels (Initial / 0-RTT / Handshake / Application).
pub const OSSL_RECORD_PROTECTION_LEVEL_NONE: u32 = 0;
pub const OSSL_RECORD_PROTECTION_LEVEL_EARLY: u32 = 1;
pub const OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE: u32 = 2;
pub const OSSL_RECORD_PROTECTION_LEVEL_APPLICATION: u32 = 3;

/// Direction passed to yield_secret: 0 = read (decrypt), 1 = write (encrypt).
pub const OSSL_QUIC_DIRECTION_READ: c_int = 0;
pub const OSSL_QUIC_DIRECTION_WRITE: c_int = 1;

/// OSSL_DISPATCH entry: a {function_id, function pointer} pair, NULL-terminated.
pub const OSSL_DISPATCH = extern struct {
    function_id: c_int,
    function: ?*const fn () callconv(.c) void,
};

// Callback function pointer types. All callbacks return 1 on success, 0 on
// failure. A failure response is fatal to the connection.

pub const QuicTlsCryptoSendFn = *const fn (
    ssl: *SSL,
    buf: [*]const u8,
    buf_len: usize,
    consumed: *usize,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub const QuicTlsCryptoRecvRcdFn = *const fn (
    ssl: *SSL,
    buf: *[*]const u8,
    bytes_read: *usize,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub const QuicTlsCryptoReleaseRcdFn = *const fn (
    ssl: *SSL,
    bytes_read: usize,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub const QuicTlsYieldSecretFn = *const fn (
    ssl: *SSL,
    prot_level: u32,
    direction: c_int,
    secret: [*]const u8,
    secret_len: usize,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub const QuicTlsGotTransportParamsFn = *const fn (
    ssl: *SSL,
    params: [*]const u8,
    params_len: usize,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub const QuicTlsAlertFn = *const fn (
    ssl: *SSL,
    alert_code: u8,
    arg: ?*anyopaque,
) callconv(.c) c_int;

/// A bundle of optional callbacks; pass into buildQuicDispatchTable to get
/// a NULL-terminated OSSL_DISPATCH array suitable for SSL_set_quic_tls_cbs.
pub const QuicTlsCallbacks = struct {
    crypto_send: ?QuicTlsCryptoSendFn = null,
    crypto_recv_rcd: ?QuicTlsCryptoRecvRcdFn = null,
    crypto_release_rcd: ?QuicTlsCryptoReleaseRcdFn = null,
    yield_secret: ?QuicTlsYieldSecretFn = null,
    got_transport_params: ?QuicTlsGotTransportParamsFn = null,
    alert: ?QuicTlsAlertFn = null,
};

/// Maximum number of OSSL_DISPATCH entries (6 callbacks + terminator).
pub const QUIC_DISPATCH_MAX_ENTRIES: usize = 7;

extern fn SSL_set_quic_tls_cbs(
    ssl: *SSL,
    qtdis: [*]const OSSL_DISPATCH,
    arg: ?*anyopaque,
) c_int;

extern fn SSL_set_quic_tls_transport_params(
    ssl: *SSL,
    params: [*]const u8,
    params_len: usize,
) c_int;

extern fn SSL_set_quic_tls_early_data_enabled(
    ssl: *SSL,
    enabled: c_int,
) c_int;

/// Populate a NULL-terminated OSSL_DISPATCH table from a QuicTlsCallbacks struct.
/// `table` must have room for QUIC_DISPATCH_MAX_ENTRIES entries; the storage must
/// remain valid for the SSL's lifetime (OpenSSL keeps a pointer to it).
pub fn buildQuicDispatchTable(
    table: *[QUIC_DISPATCH_MAX_ENTRIES]OSSL_DISPATCH,
    cbs: QuicTlsCallbacks,
) void {
    var idx: usize = 0;
    if (cbs.crypto_send) |fn_ptr| {
        table[idx] = .{
            .function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
            .function = @ptrCast(fn_ptr),
        };
        idx += 1;
    }
    if (cbs.crypto_recv_rcd) |fn_ptr| {
        table[idx] = .{
            .function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
            .function = @ptrCast(fn_ptr),
        };
        idx += 1;
    }
    if (cbs.crypto_release_rcd) |fn_ptr| {
        table[idx] = .{
            .function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
            .function = @ptrCast(fn_ptr),
        };
        idx += 1;
    }
    if (cbs.yield_secret) |fn_ptr| {
        table[idx] = .{
            .function_id = OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
            .function = @ptrCast(fn_ptr),
        };
        idx += 1;
    }
    if (cbs.got_transport_params) |fn_ptr| {
        table[idx] = .{
            .function_id = OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
            .function = @ptrCast(fn_ptr),
        };
        idx += 1;
    }
    if (cbs.alert) |fn_ptr| {
        table[idx] = .{
            .function_id = OSSL_FUNC_SSL_QUIC_TLS_ALERT,
            .function = @ptrCast(fn_ptr),
        };
        idx += 1;
    }
    // NULL terminator
    table[idx] = .{ .function_id = 0, .function = null };
}

/// Install QUIC TLS callbacks on an SSL session. The dispatch table and arg
/// must remain valid for the SSL's lifetime — OpenSSL keeps the pointers.
/// Switches the SSL to TLS 1.3 record-layer-bypass mode.
///
/// Compile-time gated on `enable_http3` so the SSL_set_quic_tls_cbs symbol
/// (added in OpenSSL 3.5+) isn't pulled in by non-h3 builds linking
/// against older OpenSSL — Debian Bookworm ships OpenSSL 3.0.x which
/// doesn't have it.
pub fn setQuicTlsCallbacks(
    ssl: *SSL,
    dispatch: [*]const OSSL_DISPATCH,
    arg: ?*anyopaque,
) !void {
    if (!tls_enabled or !http3_enabled) return error.QuicTlsNotAvailable;
    if (SSL_set_quic_tls_cbs(ssl, dispatch, arg) != 1) {
        return error.QuicTlsCallbackInstallFailed;
    }
}

/// Set the local QUIC transport parameters blob. The bytes must remain valid
/// until they are sent (i.e. until SSL_do_handshake produces the ClientHello
/// or ServerHello flight). For a server, this can also be set inside the
/// got_transport_params callback before the response flight is built.
///
/// Compile-time gated on `enable_http3` (see setQuicTlsCallbacks).
pub fn setQuicTlsTransportParams(ssl: *SSL, params: []const u8) !void {
    if (!tls_enabled or !http3_enabled) return error.QuicTlsNotAvailable;
    if (SSL_set_quic_tls_transport_params(ssl, params.ptr, params.len) != 1) {
        return error.QuicTlsTransportParamsFailed;
    }
}

/// Enable or disable TLS 0-RTT (early data) for QUIC.
///
/// Compile-time gated on `enable_http3` (see setQuicTlsCallbacks).
pub fn setQuicTlsEarlyDataEnabled(ssl: *SSL, enabled: bool) !void {
    if (!tls_enabled or !http3_enabled) return error.QuicTlsNotAvailable;
    if (SSL_set_quic_tls_early_data_enabled(ssl, if (enabled) 1 else 0) != 1) {
        return error.QuicTlsEarlyDataFailed;
    }
}

// Zig wrapper functions for safer usage

pub fn createContext(is_server: bool) !*SSL_CTX {
    if (!tls_enabled) return error.TlsNotAvailable;
    const method = if (is_server) TLS_server_method() else TLS_client_method();
    const ctx = SSL_CTX_new(method) orelse return error.ContextCreationFailed;

    // Set minimum TLS version to 1.3 for QUIC
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, null);
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, null);

    return ctx;
}

/// Create a TLS context for QUIC: TLS 1.3 only, AES-128-GCM ciphersuite,
/// h3 ALPN preference. The QUIC packet protection layer currently only
/// supports AES-128-GCM, so we restrict negotiation to TLS_AES_128_GCM_SHA256.
pub fn createQuicContext(is_server: bool) !*SSL_CTX {
    if (!tls_enabled) return error.TlsNotAvailable;
    const method = if (is_server) TLS_server_method() else TLS_client_method();
    const ctx = SSL_CTX_new(method) orelse return error.ContextCreationFailed;
    errdefer SSL_CTX_free(ctx);

    // Force TLS 1.3 (QUIC requires it).
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, null);
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, null);

    // Restrict to AES-128-GCM until we wire up SHA-384 / AES-256-GCM secret sizes.
    try setCiphersuites(ctx, "TLS_AES_128_GCM_SHA256");

    // ALPN: server prefers h3, client advertises h3.
    if (is_server) {
        SSL_CTX_set_alpn_select_cb(ctx, quicAlpnSelectCallback, null);
    } else {
        // Client side: advertise h3 as the only protocol.
        // Wire format: <1-byte len><proto bytes>.
        const h3_protos = [_]u8{ 2, 'h', '3' };
        try setAlpnProtocols(ctx, &h3_protos);
    }

    return ctx;
}

/// ALPN selection callback for QUIC TLS: only accept h3.
fn quicAlpnSelectCallback(
    _: *SSL,
    out: *[*]const u8,
    outlen: *u8,
    in_data: [*]const u8,
    inlen: c_uint,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const client_list = in_data[0..inlen];
    var i: usize = 0;
    while (i < client_list.len) {
        const proto_len = client_list[i];
        i += 1;
        if (i + proto_len > client_list.len) break;
        const proto = client_list[i .. i + proto_len];
        if (std.mem.eql(u8, proto, "h3")) {
            out.* = @ptrCast(client_list[i..].ptr);
            outlen.* = proto_len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += proto_len;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/// Create a TLS context for TCP connections (TLS 1.2+, sets ALPN for h2/http1.1).
/// Unlike createContext() which forces TLS 1.3 for QUIC, this uses library defaults
/// which support TLS 1.2+ on both OpenSSL and LibreSSL.
pub fn createTcpContext(is_server: bool) !*SSL_CTX {
    if (!tls_enabled) return error.TlsNotAvailable;
    const method = if (is_server) TLS_server_method() else TLS_client_method();
    const ctx = SSL_CTX_new(method) orelse return error.ContextCreationFailed;

    // Library defaults allow TLS 1.2+ which is correct for TCP.
    // No explicit version pinning needed (unlike QUIC which requires 1.3).

    // Set ALPN callback for server to negotiate h2 or http/1.1
    if (is_server) {
        SSL_CTX_set_alpn_select_cb(ctx, tcpAlpnSelectCallback, null);
    }

    return ctx;
}

/// ALPN selection callback for TCP TLS: prefer h2, fall back to http/1.1
fn tcpAlpnSelectCallback(
    _: *SSL,
    out: *[*]const u8,
    outlen: *u8,
    in_data: [*]const u8,
    inlen: c_uint,
    _: ?*anyopaque,
) callconv(.c) c_int {
    // Wire format: each protocol is length-prefixed (1 byte length + protocol bytes)
    const client_list = in_data[0..inlen];
    // First pass: look for "h2"
    var i: usize = 0;
    while (i < client_list.len) {
        const proto_len = client_list[i];
        i += 1;
        if (i + proto_len > client_list.len) break;
        const proto = client_list[i .. i + proto_len];
        if (std.mem.eql(u8, proto, "h2")) {
            out.* = @ptrCast(client_list[i..].ptr);
            outlen.* = proto_len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += proto_len;
    }
    // Second pass: look for "http/1.1"
    i = 0;
    while (i < client_list.len) {
        const proto_len = client_list[i];
        i += 1;
        if (i + proto_len > client_list.len) break;
        const proto = client_list[i .. i + proto_len];
        if (std.mem.eql(u8, proto, "http/1.1")) {
            out.* = @ptrCast(client_list[i..].ptr);
            outlen.* = proto_len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += proto_len;
    }
    // No matching protocol — accept anyway (will default to HTTP/1.1)
    return SSL_TLSEXT_ERR_NOACK;
}

pub fn freeContext(ctx: *SSL_CTX) void {
    if (!tls_enabled) return;
    SSL_CTX_free(ctx);
}

pub fn loadCertificateChain(ctx: *SSL_CTX, path: [:0]const u8) !void {
    if (!tls_enabled) return error.TlsNotAvailable;
    if (SSL_CTX_use_certificate_chain_file(ctx, path.ptr) != 1) {
        return error.CertificateLoadFailed;
    }
}

pub fn loadPrivateKey(ctx: *SSL_CTX, path: [:0]const u8) !void {
    if (!tls_enabled) return error.TlsNotAvailable;
    if (SSL_CTX_use_PrivateKey_file(ctx, path.ptr, SSL_FILETYPE_PEM) != 1) {
        return error.PrivateKeyLoadFailed;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        return error.PrivateKeyMismatch;
    }
}

pub fn createSession(ctx: *SSL_CTX, is_server: bool) !*SSL {
    if (!tls_enabled) return error.TlsNotAvailable;
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

/// Create a bare SSL session for QUIC callback mode — no BIOs are set up.
/// The caller must follow up with SSL_set_quic_tls_cbs (via setQuicTlsCallbacks)
/// before calling SSL_do_handshake.
pub fn createBareSession(ctx: *SSL_CTX, is_server: bool) !*SSL {
    if (!tls_enabled) return error.TlsNotAvailable;
    const ssl = SSL_new(ctx) orelse return error.SessionCreationFailed;
    if (is_server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }
    return ssl;
}

/// Restrict the TLS 1.3 ciphersuites this context will negotiate. Pass a
/// colon-separated list (e.g. "TLS_AES_128_GCM_SHA256"). Used by the QUIC
/// path so we only see SHA-256 32-byte traffic secrets matching our
/// AES-128-GCM packet protection — until we wire up SHA-384 support.
pub fn setCiphersuites(ctx: *SSL_CTX, ciphers: [:0]const u8) !void {
    if (!tls_enabled) return error.TlsNotAvailable;
    if (SSL_CTX_set_ciphersuites(ctx, ciphers.ptr) != 1) {
        return error.CipherSuiteSetFailed;
    }
}

/// Set the ALPN protocol list this context will advertise (server-side
/// override of the default ALPN selection callback). `protos` is the
/// length-prefixed wire format: each protocol is 1-byte-len + bytes.
pub fn setAlpnProtocols(ctx: *SSL_CTX, protos: []const u8) !void {
    if (!tls_enabled) return error.TlsNotAvailable;
    if (SSL_CTX_set_alpn_protos(ctx, protos.ptr, @intCast(protos.len)) != 0) {
        // OpenSSL convention: SSL_CTX_set_alpn_protos returns 0 on success.
        return error.AlpnSetFailed;
    }
}

pub fn freeSession(ssl: *SSL) void {
    if (!tls_enabled) return;
    SSL_free(ssl);
}

/// Create a session for socket-based TLS (not memory BIO)
pub fn createSocketSession(ctx: *SSL_CTX, fd: c_int, is_server: bool) !*SSL {
    if (!tls_enabled) return error.TlsNotAvailable;
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
    if (!tls_enabled) return .err;
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
    if (!tls_enabled) return error.TlsNotAvailable;
    const ret = SSL_read(ssl, buf.ptr, @intCast(buf.len));
    if (ret > 0) return @intCast(ret);
    // For ret <= 0, MUST check SSL_get_error to distinguish WANT_READ
    // from actual EOF — returning 0 directly treats transient errors as EOF.
    const err = SSL_get_error(ssl, ret);
    return switch (err) {
        SSL_ERROR_WANT_READ => error.WouldBlock,
        SSL_ERROR_WANT_WRITE => error.WouldBlock,
        SSL_ERROR_ZERO_RETURN => error.ConnectionClosed,
        SSL_ERROR_SYSCALL => if (ret == 0) error.ConnectionClosed else error.TlsError,
        else => error.TlsError,
    };
}

/// Write data to TLS connection (encrypts automatically)
pub fn sslWrite(ssl: *SSL, data: []const u8) !usize {
    if (!tls_enabled) return error.TlsNotAvailable;
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
    if (!tls_enabled) return;
    _ = SSL_shutdown(ssl);
}

pub fn doHandshake(ssl: *SSL) HandshakeResult {
    if (!tls_enabled) return .err;
    const ret = SSL_do_handshake(ssl);
    if (ret == 1) return .complete;

    const err = SSL_get_error(ssl, ret);
    if (err != SSL_ERROR_WANT_READ and err != SSL_ERROR_WANT_WRITE) {
        // Drain the OpenSSL error queue for diagnostics — these errors are
        // fatal for the connection (handshake failed for a non-recoverable
        // reason like a malformed message or protocol violation).
        var buf: [256]u8 = undefined;
        @memset(&buf, 0);
        const e = ERR_get_error();
        if (e != 0) {
            ERR_error_string_n(e, &buf, buf.len);
            const msg_len = std.mem.indexOfScalar(u8, &buf, 0) orelse buf.len;
            std.log.debug("TLS handshake failed: ret={d} ssl_err={d} {s}", .{
                ret, err, buf[0..msg_len],
            });
        }
    }
    return switch (err) {
        SSL_ERROR_WANT_READ => .want_read,
        SSL_ERROR_WANT_WRITE => .want_write,
        else => .err,
    };
}

pub fn isHandshakeComplete(ssl: *const SSL) bool {
    if (!tls_enabled) return false;
    return SSL_is_init_finished(ssl) != 0;
}

pub fn feedCryptoData(ssl: *SSL, data: []const u8) !usize {
    if (!tls_enabled) return error.TlsNotAvailable;
    const rbio = SSL_get_rbio(ssl) orelse return error.NoBio;
    const written = BIO_write(rbio, data.ptr, @intCast(data.len));
    if (written < 0) return error.BioWriteFailed;
    return @intCast(written);
}

pub fn readCryptoData(ssl: *SSL, buf: []u8) !usize {
    if (!tls_enabled) return error.TlsNotAvailable;
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
    if (!tls_enabled) return error.TlsNotAvailable;
    const ctx_ptr = if (context) |ctx| ctx.ptr else null;
    const ctx_len = if (context) |ctx| ctx.len else 0;
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
    if (!tls_enabled) return null;
    var data: [*]const u8 = undefined;
    var len: c_uint = 0;
    SSL_get0_alpn_selected(ssl, &data, &len);
    if (len == 0) return null;
    return data[0..len];
}

pub fn getLastError() [256]u8 {
    if (!tls_enabled) return [_]u8{0} ** 256;
    var buf: [256]u8 = undefined;
    const err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, &buf, buf.len);
    } else {
        @memset(&buf, 0);
    }
    return buf;
}
