//! TLS-to-upstream support for the reverse proxy (issue #36).
//!
//! The proxy's upstream I/O is deliberately blocking, which is exactly the
//! model OpenSSL's fd BIO fits: SSL_connect/SSL_read/SSL_write over a
//! blocking socket honor the fd's SO_RCVTIMEO/SO_SNDTIMEO, so route
//! timeouts bound the handshake and every read the same way they bound
//! plain connections. This module wraps the same ffi surface the config
//! fetcher and x402 facilitator client already use, gated on
//! build_options.enable_tls: with TLS off every call fails closed with
//! error.TlsNotEnabled (config validation rejects `tls: true` upstreams
//! before a server starts, so these paths are unreachable then).
//!
//! Ownership: one SSL_CTX per TLS-enabled upstream (created by Proxy.init,
//! freed by Proxy.deinit); one SSL per pooled connection (created at
//! connect, freed wherever the pool closes the fd). Both are stored as
//! *anyopaque so pool.zig and proxy.zig need no conditional ffi imports.

const std = @import("std");
const build_options = @import("build_options");

const ffi = if (build_options.enable_tls) @import("../tls/ffi.zig") else struct {};

pub const Error = error{
    TlsNotEnabled,
    TlsInitFailed,
    TlsHandshakeFailed,
};

/// Create a client SSL_CTX for one upstream. `verify` controls peer
/// certificate verification against the system trust store (default on;
/// `tls_verify: false` supports self-signed backends).
pub fn createContext(verify: bool) Error!*anyopaque {
    if (!build_options.enable_tls) return error.TlsNotEnabled;
    const ctx = ffi.SSL_CTX_new(ffi.TLS_client_method()) orelse return error.TlsInitFailed;
    errdefer ffi.SSL_CTX_free(ctx);
    if (verify) {
        ffi.loadDefaultVerifyPaths(ctx) catch return error.TlsInitFailed;
    }
    ffi.setClientVerify(ctx, verify);
    return @ptrCast(ctx);
}

pub fn destroyContext(ctx: *anyopaque) void {
    if (!build_options.enable_tls) return;
    ffi.SSL_CTX_free(@ptrCast(@alignCast(ctx)));
}

/// Handshake a client session over a connected (blocking) socket.
/// `sni_host` is sent as SNI and, when `verify_hostname`, checked against
/// the peer certificate. The fd's send/recv timeouts bound the handshake.
pub fn connect(
    ctx: *anyopaque,
    fd: std.posix.fd_t,
    sni_host: []const u8,
    verify_hostname: bool,
) Error!*anyopaque {
    if (!build_options.enable_tls) return error.TlsNotEnabled;
    const ssl_ctx: *ffi.SSL_CTX = @ptrCast(@alignCast(ctx));
    const ssl = ffi.SSL_new(ssl_ctx) orelse return error.TlsInitFailed;
    errdefer ffi.SSL_free(ssl);

    // Null-terminate the host for OpenSSL (DNS names cap at 253).
    var host_z: [253:0]u8 = undefined;
    if (sni_host.len == 0 or sni_host.len >= host_z.len) return error.TlsInitFailed;
    @memcpy(host_z[0..sni_host.len], sni_host);
    host_z[sni_host.len] = 0;
    const host_sentinel: [:0]const u8 = host_z[0..sni_host.len :0];
    if (verify_hostname) {
        if (!ffi.setHostnameVerification(ssl, host_sentinel)) return error.TlsInitFailed;
    }
    if (!ffi.setSniHostname(ssl, host_sentinel)) return error.TlsInitFailed;

    if (ffi.SSL_set_fd(ssl, @intCast(fd)) != 1) return error.TlsInitFailed;
    if (ffi.SSL_connect(ssl) != 1) return error.TlsHandshakeFailed;
    return @ptrCast(ssl);
}

/// Best-effort close_notify + free. Safe on half-broken sessions: the
/// shutdown write inherits the fd's send timeout.
pub fn freeSession(session: *anyopaque) void {
    if (!build_options.enable_tls) return;
    const ssl: *ffi.SSL = @ptrCast(@alignCast(session));
    _ = ffi.SSL_shutdown(ssl);
    ffi.SSL_free(ssl);
}

pub fn send(session: *anyopaque, data: []const u8) error{SendFailed}!void {
    if (!build_options.enable_tls) return error.SendFailed;
    const ssl: *ffi.SSL = @ptrCast(@alignCast(session));
    var sent: usize = 0;
    while (sent < data.len) {
        const n = ffi.SSL_write(ssl, data[sent..].ptr, @intCast(data.len - sent));
        if (n <= 0) return error.SendFailed;
        sent += @intCast(n);
    }
}

/// Returns 0 on orderly close (close_notify or EOF-ish failure), mirroring
/// net.recvBlocking's EOF contract; hard errors surface as RecvFailed.
pub fn recv(session: *anyopaque, buf: []u8) error{RecvFailed}!usize {
    if (!build_options.enable_tls) return error.RecvFailed;
    const ssl: *ffi.SSL = @ptrCast(@alignCast(session));
    const n = ffi.SSL_read(ssl, buf.ptr, @intCast(buf.len));
    if (n > 0) return @intCast(n);
    const err = ffi.SSL_get_error(ssl, n);
    if (err == ffi.SSL_ERROR_ZERO_RETURN) return 0; // orderly close_notify
    return error.RecvFailed;
}

const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");

test "createContext round-trips (verify on and off)" {
    if (!build_options.enable_tls) return error.SkipZigTest;
    const strict = try createContext(true);
    destroyContext(strict);
    const insecure = try createContext(false);
    destroyContext(insecure);
}

test "connect fails cleanly against a non-TLS peer" {
    // The exact failure users hit inverted: swerver speaking TLS to a plain
    // TCP endpoint. The handshake must fail (bounded by the fd's timeouts,
    // here via peer close), not hang and not crash.
    if (!build_options.enable_tls) return error.SkipZigTest;

    const lfd = net.listen("127.0.0.1", 0, 4) catch return error.SkipZigTest;
    defer clock.closeFd(lfd);
    const port = net.getLocalPort(lfd) orelse return error.SkipZigTest;

    const Peer = struct {
        fn run(listen_fd: std.posix.fd_t) void {
            // net.accept is nonblocking; spin briefly, then close the
            // accepted fd immediately so the client's handshake sees EOF.
            var attempts: usize = 0;
            while (attempts < 20000) : (attempts += 1) {
                const cfd = net.accept(listen_fd) catch {
                    std.Thread.yield() catch {};
                    continue;
                };
                clock.closeFd(cfd);
                return;
            }
        }
    };
    const t = try std.Thread.spawn(.{}, Peer.run, .{lfd});

    const fd = net.connectBlocking("127.0.0.1", port, 1000) catch return error.SkipZigTest;
    defer clock.closeFd(fd);
    net.setSocketTimeouts(fd, 1000, 1000);

    const ctx = try createContext(false);
    defer destroyContext(ctx);
    try std.testing.expectError(error.TlsHandshakeFailed, connect(ctx, fd, "localhost", false));
    t.join();
}
