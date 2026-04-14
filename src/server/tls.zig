//! # TLS handshake and ciphertext pump helpers
//!
//! This module owns the TLS-specific parts of the read and write
//! paths for TCP connections. The `Server` still holds the shared
//! ciphertext scratch buffer (`tls_cipher_scratch`), the per-
//! connection carry handles live on `Connection`, and `connRead` /
//! `connWrite` / `seedReadBuffer` stay in `src/server.zig` because
//! they're the shared plain-TCP-and-TLS entry points — they just
//! call into the helpers here when `conn.is_tls` is true.
//!
//! The model:
//!
//!   1. On accept, `handleTlsHandshake` runs SSL_do_handshake in a
//!      loop until accepted. Ciphertext that OpenSSL writes into
//!      wbio during the handshake is drained by `tlsFlushWbio`.
//!   2. `tlsPumpRead` handles the poll/epoll backends — completion
//!      backends already seeded rbio via `seedReadBuffer`, so the
//!      pump is a no-op there.
//!   3. On write, `tlsFlushWbio` pulls ciphertext from wbio into
//!      `tls_cipher_scratch` and writes it to the socket. If the
//!      socket backpressures mid-drain, `tlsStashCarry` parks the
//!      unsent tail in a pool buffer referenced by
//!      `conn.tls_cipher_carry_handle`. The next write event's
//!      `tlsDrainCarry` flushes that carry before any fresh
//!      SSL_write — preserving encryption order on the wire.

const std = @import("std");
const build_options = @import("build_options");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const connection = @import("../runtime/connection.zig");
const tls = @import("../tls/provider.zig");
const http2 = @import("../protocol/http2.zig");
const http2_mod = @import("http2.zig");

/// Max plaintext bytes pushed into SSL_write per `connWrite` call. Caps the
/// ciphertext any single SSL_write can produce at roughly one TLS record,
/// which keeps `TLS_CIPHER_SCRATCH_SIZE` (and any carryover into a pooled
/// buffer) small and predictable.
pub const TLS_PLAINTEXT_WRITE_CAP: usize = 16 * 1024;

/// Scratch buffer size for draining wbio ciphertext to the socket. Large
/// enough to hold the ciphertext produced by a single TLS 1.3 AES-GCM record
/// (16384 bytes plaintext + AEAD tag + header) with comfortable slack so a
/// healthy wbio drains in one BIO_read/writev round-trip.
pub const TLS_CIPHER_SCRATCH_SIZE: usize = 16 * 1024 + 512;

/// Result of `tlsDrainCarry`: whether the stashed ciphertext has been
/// fully flushed to the socket, whether the socket is backpressured
/// (caller should return and wait for the next writable event), or
/// whether a fatal socket error was observed.
pub const CarryFlushResult = enum { done, again, err };

pub fn handleTlsHandshake(server: *Server, conn: *connection.Connection) !void {
    var session = &(conn.tls_session orelse return error.NoTlsSession);
    // Pull any ciphertext the backend hasn't seeded for us (poll/epoll
    // path — completion backends already fed rbio from the event). Safe
    // to call unconditionally; no-op on native.
    _ = tlsPumpRead(server, conn);
    // Before feeding new plaintext to SSL_do_handshake, flush any
    // ciphertext we stashed from a prior partial writev.
    switch (tlsDrainCarry(server, conn)) {
        .done => {},
        .again => return,
        .err => return error.TlsWriteFailed,
    }
    const accepted = session.accept() catch {
        return error.TlsHandshakeFailed;
    };
    // session.accept may have written handshake output (ServerHello,
    // EncryptedExtensions, Certificate, …) into wbio. Drain it now so
    // the client can progress; the handshake is only meaningful once
    // both sides have flushed their crypto bytes.
    try tlsFlushWbio(server, conn);
    if (accepted) {
        // Handshake complete — check ALPN for h2 and transition to active
        conn.transition(.active, server.io.nowMs()) catch return error.InvalidTransition;
        if (build_options.enable_http2) {
            if (session.getAlpn()) |alpn| {
                if (std.mem.eql(u8, alpn, "h2")) {
                    if (conn.http2_stack == null) {
                        const stack_ptr = try server.allocator.create(http2.Stack);
                        stack_ptr.* = http2.Stack.initWithConfig(.{
                            .max_streams = server.cfg.http2.max_streams,
                            .max_header_list_size = server.cfg.http2.max_header_list_size,
                            .initial_window_size = server.cfg.http2.initial_window_size,
                            .max_frame_size = server.cfg.http2.max_frame_size,
                            .max_dynamic_table_size = server.cfg.http2.max_dynamic_table_size,
                        });
                        conn.http2_stack = stack_ptr;
                    }
                    conn.protocol = .http2;
                    http2_mod.sendHttp2ServerPreface(server, conn) catch {
                        return error.Http2PrefaceFailed;
                    };
                }
            }
        }
        // For HTTP/2 over TLS, flush the server preface (SETTINGS) before
        // reading. The client won't send its h2 preface until it receives ours.
        if (conn.protocol == .http2) {
            server.handleWrite(conn.index) catch {};
        }
        // Try to read immediately (data may already be buffered by TLS/kernel)
        server.handleRead(conn.index) catch {
            server.closeConnection(conn);
            return;
        };
        // Flush any response queued by handleRead (the event loop also does
        // this after read events, but we need it here for the initial handshake)
        if (conn.write_count > 0) {
            server.handleWrite(conn.index) catch {};
        }
    }
    // If not accepted, handshake needs more I/O — wait for next event
}

/// For TLS connections running on a non-completion backend (poll / epoll),
/// pull any available ciphertext from the socket with blocking reads and
/// feed it into the memory rbio. No-op on completion backends — the event
/// dispatcher already routed kernel-delivered bytes into rbio via
/// `seedReadBuffer`. Called before each `session.accept` / `SSL_read` so
/// the BIO always has the freshest bytes the kernel has handed us.
/// Returns true if any bytes were fed, false otherwise.
pub fn tlsPumpRead(server: *Server, conn: *connection.Connection) bool {
    if (!conn.is_tls) return false;
    if (server.io.capabilities().delivers_read_data) return false;
    const fd = conn.fd orelse return false;
    var session = &(conn.tls_session orelse return false);
    var scratch: [16 * 1024]u8 = undefined;
    var any: bool = false;
    while (true) {
        const raw = std.posix.system.read(fd, &scratch, scratch.len);
        if (raw == 0) return any; // EOF — let the next SSL_read surface it
        if (raw < 0) {
            // EAGAIN / INTR — we've drained what's available.
            return any;
        }
        const n: usize = @intCast(raw);
        var remaining: []const u8 = scratch[0..n];
        while (remaining.len > 0) {
            const fed = session.feedCryptoData(remaining) catch return any;
            if (fed == 0) return any;
            remaining = remaining[fed..];
        }
        any = true;
        conn.markActive(server.io.nowMs());
    }
}

/// Drain any leftover ciphertext carry from a prior partial writev back to
/// the socket. Returns `.done` when the carry is empty (proceed to
/// encrypt more plaintext), `.again` when the socket is backpressured
/// (caller should return and wait for the next writable event), or
/// `.err` on a fatal socket error.
pub fn tlsDrainCarry(server: *Server, conn: *connection.Connection) CarryFlushResult {
    const handle = conn.tls_cipher_carry_handle orelse return .done;
    const fd = conn.fd orelse return .err;
    while (conn.tls_cipher_carry_offset < conn.tls_cipher_carry_len) {
        const slice = handle.bytes[conn.tls_cipher_carry_offset..conn.tls_cipher_carry_len];
        const raw = std.c.write(fd, slice.ptr, slice.len);
        if (raw < 0) {
            return switch (std.posix.errno(raw)) {
                .AGAIN => .again,
                .INTR => continue,
                else => .err,
            };
        }
        if (raw == 0) return .again;
        conn.tls_cipher_carry_offset += @intCast(raw);
        server.io.onWriteCompleted(conn, @intCast(raw));
        conn.markActive(server.io.nowMs());
    }
    // Carry fully drained — release the buffer.
    server.io.releaseBuffer(handle);
    conn.tls_cipher_carry_handle = null;
    conn.tls_cipher_carry_offset = 0;
    conn.tls_cipher_carry_len = 0;
    return .done;
}

/// Drain whatever ciphertext is currently pending in wbio to the socket.
/// If the socket is backpressured mid-drain, stashes the leftover
/// ciphertext into `conn.tls_cipher_carry_handle` so the next handleWrite
/// event can flush it. Returns normally on EAGAIN (partial + stash) or
/// on successful full drain; returns `error.TlsWriteFailed` on socket
/// errors, or `error.TlsCarryAllocFailed` if the pool is exhausted.
pub fn tlsFlushWbio(server: *Server, conn: *connection.Connection) !void {
    var session = &(conn.tls_session orelse return);
    const fd = conn.fd orelse return error.TlsWriteFailed;
    while (true) {
        const n = session.readCryptoData(&server.tls_cipher_scratch) catch {
            return error.TlsWriteFailed;
        };
        if (n == 0) return;
        var sent: usize = 0;
        while (sent < n) {
            const raw = std.c.write(fd, server.tls_cipher_scratch[sent..].ptr, n - sent);
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => {
                        // Backpressured — stash the unsent tail plus
                        // anything still queued in wbio for next time.
                        if (!tlsStashCarry(server, conn, session, server.tls_cipher_scratch[sent..n])) {
                            return error.TlsCarryAllocFailed;
                        }
                        return;
                    },
                    .INTR => continue,
                    else => return error.TlsWriteFailed,
                }
            }
            if (raw == 0) {
                if (!tlsStashCarry(server, conn, session, server.tls_cipher_scratch[sent..n])) {
                    return error.TlsCarryAllocFailed;
                }
                return;
            }
            sent += @intCast(raw);
            conn.markActive(server.io.nowMs());
        }
    }
}

/// Stash the remaining ciphertext (scratch tail + anything still pending
/// in wbio) into a pool buffer so the next handleWrite call can flush it
/// before encrypting more plaintext. Called from the wbio drain path when
/// the socket returns EAGAIN or a short write.
fn tlsStashCarry(
    server: *Server,
    conn: *connection.Connection,
    session: *tls.Session,
    scratch_tail: []const u8,
) bool {
    // How many more ciphertext bytes are still sitting in wbio?
    var extra_buf: [TLS_CIPHER_SCRATCH_SIZE]u8 = undefined;
    const extra_n = session.readCryptoData(&extra_buf) catch 0;
    const total = scratch_tail.len + extra_n;
    if (total == 0) return true;
    const handle = server.io.acquireBuffer() orelse return false;
    if (handle.bytes.len < total) {
        server.io.releaseBuffer(handle);
        return false;
    }
    @memcpy(handle.bytes[0..scratch_tail.len], scratch_tail);
    if (extra_n > 0) {
        @memcpy(handle.bytes[scratch_tail.len..][0..extra_n], extra_buf[0..extra_n]);
    }
    conn.tls_cipher_carry_handle = handle;
    conn.tls_cipher_carry_offset = 0;
    conn.tls_cipher_carry_len = total;
    server.io.onWriteBuffered(conn, total);
    return true;
}
