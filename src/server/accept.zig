//! # Accept path helpers
//!
//! Everything that runs between "the kernel handed us a connected
//! socket" and "the connection is registered with the backend and
//! ready to read." The split depends on which backend delivered
//! the connection:
//!
//!   - `handleAccept` drives a `accept4`-in-a-loop on edge-triggered
//!     backends (poll / epoll). Called from the event dispatcher
//!     when the listener fd becomes readable.
//!   - `handlePreAccepted` is the entry point for io_uring's
//!     multishot accept — the kernel has already done the accept,
//!     so we go straight to per-connection setup.
//!
//! Both paths funnel into `setupAcceptedConnection`, which acquires
//! the pool slot + read buffer, wires up TLS if configured, and
//! either immediately tries the first `handleRead` (plain TCP) or
//! kicks off the TLS handshake.
//!
//! TCP_NODELAY is set on the listener so accepted sockets inherit
//! it — avoiding a per-accept setsockopt syscall that showed up on
//! the connection-churn benchmarks.

const std = @import("std");

const server_mod = @import("../server.zig");
const Server = server_mod.Server;

const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const server_tls = @import("tls.zig");

pub fn handleAccept(server: *Server, listener_fd: std.posix.fd_t) !void {
    // Edge-triggered epoll: must drain the accept queue in a loop or
    // pending connections will be stranded until the next "transition".
    while (true) {
        acceptOne(server, listener_fd) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
    }
}

/// Called when the io_uring_native backend delivers a multishot
/// accept CQE. The kernel has already accepted the connection and
/// given us the client fd — already non-blocking and close-on-exec
/// because armMultishotAccept passed SOCK_NONBLOCK | SOCK_CLOEXEC
/// as the accept flags. Go straight to the per-connection setup.
pub fn handlePreAccepted(server: *Server, client_fd: std.posix.fd_t) !void {
    try setupAcceptedConnection(server, client_fd);
}

fn acceptOne(server: *Server, listener_fd: std.posix.fd_t) !void {
    const client_fd = net.accept(listener_fd) catch |err| switch (err) {
        error.WouldBlock => return error.WouldBlock,
        else => return err,
    };
    try setupAcceptedConnection(server, client_fd);
}

/// Common per-connection setup after an accept: acquire a pool
/// connection, wire up the read buffer, register with the backend,
/// start TLS if configured.
///
/// TCP_NODELAY is set on the listener so accepted sockets inherit
/// it — we used to call setsockopt per accept, which showed up as
/// ~7% of server syscall time on connection-churn benchmarks.
///
/// Peer address caching via getpeername only fires when reverse
/// proxy is configured (for X-Forwarded-For). Rate-limiting /
/// access-log middleware that needs the peer IP can call
/// `net.getPeerAddress(conn.fd)` directly on the cold path —
/// benchmark configs pay zero getpeername syscalls this way.
fn setupAcceptedConnection(server: *Server, client_fd: std.posix.fd_t) !void {
    const now_ms = server.io.nowMs();
    const conn = server.io.acquireConnection(now_ms) orelse {
        clock.closeFd(client_fd);
        return;
    };
    if (server.io.acquireBuffer()) |buf| {
        conn.read_buffer = buf;
    } else {
        server.io.releaseConnection(conn);
        clock.closeFd(client_fd);
        return;
    }
    conn.fd = client_fd;
    if (server.proxy != null) {
        if (net.getPeerAddress(client_fd)) |peer| {
            if (peer.getIp4Bytes()) |ip4| {
                conn.cached_peer_ip = ip4;
            } else if (peer.getIp6Bytes()) |ip6| {
                conn.cached_peer_ip6 = ip6;
            }
        }
    }
    // If TLS is configured, start handshake before going active
    if (server.tcp_tls_provider) |*provider| {
        conn.tls_session = provider.createTcpMemSession() catch {
            if (conn.read_buffer) |buf| server.io.releaseBuffer(buf);
            server.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return;
        };
        conn.is_tls = true;
        conn.transition(.handshake, now_ms) catch {
            conn.cleanupTls();
            if (conn.read_buffer) |buf| server.io.releaseBuffer(buf);
            server.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return;
        };
        server.io.setTimeoutPhase(conn, .header);
        server.io.registerConnection(conn.index, client_fd) catch |err| {
            conn.cleanupTls();
            if (conn.read_buffer) |buf| server.io.releaseBuffer(buf);
            server.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return err;
        };
        // Try handshake immediately (may complete in one round-trip)
        server_tls.handleTlsHandshake(server, conn) catch {
            server.closeConnection(conn);
            return;
        };
    } else {
        conn.transition(.active, now_ms) catch {
            // Invalid state transition - close connection
            if (conn.read_buffer) |buf| server.io.releaseBuffer(buf);
            server.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return;
        };
        server.io.setTimeoutPhase(conn, .header);
        server.io.registerConnection(conn.index, client_fd) catch |err| {
            if (conn.read_buffer) |buf| server.io.releaseBuffer(buf);
            server.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return err;
        };
        // With edge-triggered epoll, we must try to read immediately after accept
        // because data may have arrived before we registered the socket.
        // If we don't do this, we'll miss the EPOLLIN notification.
        server.handleRead(conn.index) catch {
            server.closeConnection(conn);
            return;
        };
    }
}

