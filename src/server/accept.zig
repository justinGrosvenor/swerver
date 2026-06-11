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

const IP_TRACKER_SLOTS = 4096;
const DEFAULT_PER_IP_LIMIT: u16 = 256;

/// Per-worker IP connection tracker. Each forked worker process has its own instance,
/// so the effective per-IP limit is multiplied by the number of workers.
/// Keys are IP hashes — collisions cause two IPs to share a counter (conservative: may
/// deny earlier than configured, but never allows more than the limit).
pub const IpConnTracker = struct {
    keys: [IP_TRACKER_SLOTS]u64 = [_]u64{0} ** IP_TRACKER_SLOTS,
    counts: [IP_TRACKER_SLOTS]u16 = [_]u16{0} ** IP_TRACKER_SLOTS,

    fn slot(self: *IpConnTracker, hash: u64) ?usize {
        if (hash == 0) return null;
        var idx = hash % IP_TRACKER_SLOTS;
        var probes: usize = 0;
        while (probes < 16) : (probes += 1) {
            if (self.keys[idx] == hash or self.keys[idx] == 0) return idx;
            idx = (idx + 1) % IP_TRACKER_SLOTS;
        }
        return null;
    }

    pub fn increment(self: *IpConnTracker, hash: u64, limit: u16) bool {
        const idx = self.slot(hash) orelse return false;
        if (self.keys[idx] == 0) {
            self.keys[idx] = hash;
            self.counts[idx] = 1;
            return true;
        }
        if (self.counts[idx] >= limit) return false;
        self.counts[idx] += 1;
        return true;
    }

    pub fn decrement(self: *IpConnTracker, hash: u64) void {
        const idx = self.slot(hash) orelse return;
        if (self.keys[idx] != hash) return;
        if (self.counts[idx] > 0) self.counts[idx] -= 1;
        if (self.counts[idx] == 0) self.keys[idx] = 0;
    }
};

pub var ip_tracker: IpConnTracker = .{};

fn hashIp(ip4: ?[4]u8, ip6: ?[16]u8) u64 {
    if (ip4) |bytes| {
        var h: u64 = 0xcbf29ce484222325;
        for (bytes) |b| {
            h ^= b;
            h *%= 0x100000001b3;
        }
        return h | 1;
    }
    if (ip6) |bytes| {
        var h: u64 = 0xcbf29ce484222325;
        for (bytes) |b| {
            h ^= b;
            h *%= 0x100000001b3;
        }
        return h | 1;
    }
    return 0;
}

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
        error.TooManyOpenFiles => {
            if (server.spare_fd) |spare| {
                clock.closeFd(spare);
                server.spare_fd = null;
            }
            if (net.accept(listener_fd)) |doomed_fd| {
                clock.closeFd(doomed_fd);
            } else |_| {}
            server.spare_fd = std.posix.openat(std.posix.AT.FDCWD, "/dev/null", .{}, 0) catch null;
            std.log.warn("EMFILE: fd limit reached, dropped incoming connection", .{});
            return;
        },
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
    const conn = server.io.acquireConnection(server.now_ms) orelse {
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
    // Resolve which listener this connection arrived on (multi-listener model):
    // getsockname gives the local port, which maps to a ListenerConfig. Falls
    // back to the legacy single-port config when the port can't be read or
    // isn't in the listeners array.
    const lcfg = if (net.getLocalPort(client_fd)) |lp|
        server.cfg.listenerForPort(lp)
    else
        server.cfg.listenerForPort(server.cfg.port);
    conn.h2c_only = lcfg.h2c_only;
    if (server.needs_peer_ip or server.cfg.per_ip_limit > 0) {
        if (net.getPeerAddress(client_fd)) |peer| {
            if (peer.getIp4Bytes()) |ip4| {
                conn.cached_peer_ip = ip4;
            } else if (peer.getIp6Bytes()) |ip6| {
                conn.cached_peer_ip6 = ip6;
            }
        }
    }
    if (server.cfg.per_ip_limit > 0) {
        const h = hashIp(conn.cached_peer_ip, conn.cached_peer_ip6);
        if (h != 0 and !ip_tracker.increment(h, server.cfg.per_ip_limit)) {
            if (conn.read_buffer) |buf| server.io.releaseBuffer(buf);
            server.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return;
        }
        conn.ip_hash = h;
    }
    // Start TLS only when this listener wants it AND a provider is built.
    // tcp_tls_provider may exist solely to serve OTHER (TLS) listeners, so a
    // plaintext listener must fall through to the plaintext branch even though
    // the provider is non-null.
    if (lcfg.use_tls and server.tcp_tls_provider != null) {
        const provider = &server.tcp_tls_provider.?;
        conn.tls_session = provider.createTcpMemSession() catch {
            if (conn.read_buffer) |buf| server.io.releaseBuffer(buf);
            server.io.releaseConnection(conn);
            clock.closeFd(client_fd);
            return;
        };
        conn.is_tls = true;
        conn.transition(.handshake, server.now_ms) catch {
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
        conn.transition(.active, server.now_ms) catch {
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
        server.handleRead(conn.index) catch {
            server.closeConnection(conn);
            return;
        };
        // Flush any response queued by handleRead (no write event
        // is registered yet since kqueue only arms EVFILT_WRITE
        // on EAGAIN from writev).
        const rconn = server.io.getConnection(conn.index) orelse return;
        if (rconn.write_count > 0) {
            server.handleWrite(conn.index) catch {};
        }
    }
}
