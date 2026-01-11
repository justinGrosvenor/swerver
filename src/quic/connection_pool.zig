const std = @import("std");
const types = @import("types.zig");
const connection = @import("connection.zig");

/// Socket address storage (platform-independent)
pub const SockAddrStorage = extern struct {
    family: u16 = 0,
    data: [126]u8 = [_]u8{0} ** 126,
};

/// QUIC Connection Pool
///
/// Manages active QUIC connections with lookup by:
/// - Connection ID (for routing packets)
/// - Peer address (for Initial packets without known CID)

pub const Error = error{
    ConnectionNotFound,
    ConnectionLimitReached,
    DuplicateConnectionId,
    OutOfMemory,
};

/// Peer address key for lookups
pub const PeerKey = struct {
    addr: SockAddrStorage,

    pub fn hash(self: PeerKey) u64 {
        const bytes = std.mem.asBytes(&self.addr);
        return std.hash.Wyhash.hash(0, bytes);
    }

    pub fn eql(a: PeerKey, b: PeerKey) bool {
        const a_bytes = std.mem.asBytes(&a.addr);
        const b_bytes = std.mem.asBytes(&b.addr);
        return std.mem.eql(u8, a_bytes, b_bytes);
    }
};

/// Connection ID key for lookups
pub const CidKey = struct {
    cid: types.ConnectionId,

    pub fn hash(self: CidKey) u64 {
        return self.cid.hash();
    }

    pub fn eql(a: CidKey, b: CidKey) bool {
        return a.cid.eql(&b.cid);
    }
};

/// Connection entry in the pool
pub const PoolEntry = struct {
    conn: *connection.Connection,
    peer_addr: SockAddrStorage,
    created_at: i128,
    /// Original DCID (for Initial packet routing)
    original_dcid: types.ConnectionId,
};

/// Connection pool for managing QUIC connections
pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    /// Connections indexed by our Connection ID
    by_cid: std.HashMap(CidKey, *PoolEntry, CidKeyContext, 80),
    /// Connections indexed by peer address (for Initial packets)
    by_peer: std.HashMap(PeerKey, *PoolEntry, PeerKeyContext, 80),
    /// All entries for iteration
    entries: std.ArrayList(*PoolEntry),
    /// Maximum connections allowed
    max_connections: usize,
    /// Is this a server pool?
    is_server: bool,

    const CidKeyContext = struct {
        pub fn hash(_: @This(), key: CidKey) u64 {
            return key.hash();
        }
        pub fn eql(_: @This(), a: CidKey, b: CidKey) bool {
            return a.eql(b);
        }
    };

    const PeerKeyContext = struct {
        pub fn hash(_: @This(), key: PeerKey) u64 {
            return key.hash();
        }
        pub fn eql(_: @This(), a: PeerKey, b: PeerKey) bool {
            return a.eql(b);
        }
    };

    pub fn init(allocator: std.mem.Allocator, is_server: bool, max_connections: usize) ConnectionPool {
        return .{
            .allocator = allocator,
            .by_cid = std.HashMap(CidKey, *PoolEntry, CidKeyContext, 80).init(allocator),
            .by_peer = std.HashMap(PeerKey, *PoolEntry, PeerKeyContext, 80).init(allocator),
            .entries = .empty,
            .max_connections = max_connections,
            .is_server = is_server,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        // Clean up all entries
        for (self.entries.items) |entry| {
            entry.conn.deinit();
            self.allocator.destroy(entry.conn);
            self.allocator.destroy(entry);
        }
        self.entries.deinit(self.allocator);
        self.by_cid.deinit();
        self.by_peer.deinit();
    }

    /// Create a new connection for an incoming Initial packet
    pub fn createConnection(
        self: *ConnectionPool,
        dcid: types.ConnectionId,
        peer_addr: SockAddrStorage,
    ) Error!*connection.Connection {
        if (self.entries.items.len >= self.max_connections) {
            return Error.ConnectionLimitReached;
        }

        // Create connection
        const conn = self.allocator.create(connection.Connection) catch return Error.OutOfMemory;
        conn.* = connection.Connection.init(self.allocator, self.is_server, dcid);

        // Create pool entry
        const entry = self.allocator.create(PoolEntry) catch {
            conn.deinit();
            self.allocator.destroy(conn);
            return Error.OutOfMemory;
        };

        entry.* = .{
            .conn = conn,
            .peer_addr = peer_addr,
            .created_at = 0, // Timestamp set on first use
            .original_dcid = dcid,
        };

        // Index by our CID
        self.by_cid.put(.{ .cid = conn.our_cid }, entry) catch {
            conn.deinit();
            self.allocator.destroy(conn);
            self.allocator.destroy(entry);
            return Error.OutOfMemory;
        };

        // Index by peer address
        self.by_peer.put(.{ .addr = peer_addr }, entry) catch {
            _ = self.by_cid.remove(.{ .cid = conn.our_cid });
            conn.deinit();
            self.allocator.destroy(conn);
            self.allocator.destroy(entry);
            return Error.OutOfMemory;
        };

        // Index by original DCID (for Initial packet routing)
        self.by_cid.put(.{ .cid = dcid }, entry) catch {
            // Non-fatal, we can still route by our CID
        };

        self.entries.append(self.allocator, entry) catch {
            _ = self.by_cid.remove(.{ .cid = conn.our_cid });
            _ = self.by_cid.remove(.{ .cid = dcid });
            _ = self.by_peer.remove(.{ .addr = peer_addr });
            conn.deinit();
            self.allocator.destroy(conn);
            self.allocator.destroy(entry);
            return Error.OutOfMemory;
        };

        return conn;
    }

    /// Find connection by Connection ID
    pub fn findByCid(self: *ConnectionPool, cid: types.ConnectionId) ?*connection.Connection {
        if (self.by_cid.get(.{ .cid = cid })) |entry| {
            return entry.conn;
        }
        return null;
    }

    /// Find connection by peer address
    pub fn findByPeer(self: *ConnectionPool, peer_addr: SockAddrStorage) ?*connection.Connection {
        if (self.by_peer.get(.{ .addr = peer_addr })) |entry| {
            return entry.conn;
        }
        return null;
    }

    /// Get peer address for a connection
    pub fn getPeerAddr(self: *ConnectionPool, conn: *connection.Connection) ?SockAddrStorage {
        // Find the entry for this connection
        for (self.entries.items) |entry| {
            if (entry.conn == conn) {
                return entry.peer_addr;
            }
        }
        return null;
    }

    /// Remove a connection from the pool
    pub fn removeConnection(self: *ConnectionPool, conn: *connection.Connection) void {
        // Find and remove the entry
        var idx: ?usize = null;
        for (self.entries.items, 0..) |entry, i| {
            if (entry.conn == conn) {
                idx = i;

                // Remove from indices
                _ = self.by_cid.remove(.{ .cid = conn.our_cid });
                _ = self.by_cid.remove(.{ .cid = entry.original_dcid });
                _ = self.by_peer.remove(.{ .addr = entry.peer_addr });

                // Clean up
                conn.deinit();
                self.allocator.destroy(conn);
                self.allocator.destroy(entry);
                break;
            }
        }

        if (idx) |i| {
            _ = self.entries.orderedRemove(i);
        }
    }

    /// Clean up closed and timed-out connections
    pub fn cleanup(self: *ConnectionPool) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const entry = self.entries.items[i];
            const conn = entry.conn;

            if (!conn.isAlive() or conn.isIdleTimedOut()) {
                // Remove from indices
                _ = self.by_cid.remove(.{ .cid = conn.our_cid });
                _ = self.by_cid.remove(.{ .cid = entry.original_dcid });
                _ = self.by_peer.remove(.{ .addr = entry.peer_addr });

                // Clean up
                conn.deinit();
                self.allocator.destroy(conn);
                self.allocator.destroy(entry);

                _ = self.entries.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Get count of active connections
    pub fn count(self: *const ConnectionPool) usize {
        return self.entries.items.len;
    }

    /// Iterate over all connections
    pub fn iterator(self: *ConnectionPool) ConnectionIterator {
        return .{ .pool = self, .index = 0 };
    }

    pub const ConnectionIterator = struct {
        pool: *ConnectionPool,
        index: usize,

        pub fn next(self: *ConnectionIterator) ?*connection.Connection {
            if (self.index >= self.pool.entries.items.len) {
                return null;
            }
            const conn = self.pool.entries.items[self.index].conn;
            self.index += 1;
            return conn;
        }
    };
};

// Tests
test "connection pool basic operations" {
    const allocator = std.testing.allocator;
    var pool = ConnectionPool.init(allocator, true, 100);
    defer pool.deinit();

    // Create a connection
    const dcid = types.ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    var peer_addr: SockAddrStorage = undefined;
    @memset(std.mem.asBytes(&peer_addr), 0);

    const conn = try pool.createConnection(dcid, peer_addr);

    try std.testing.expectEqual(@as(usize, 1), pool.count());

    // Find by CID
    const found = pool.findByCid(conn.our_cid);
    try std.testing.expect(found != null);
    try std.testing.expect(found.? == conn);

    // Find by original DCID
    const found2 = pool.findByCid(dcid);
    try std.testing.expect(found2 != null);
    try std.testing.expect(found2.? == conn);

    // Find by peer
    const found3 = pool.findByPeer(peer_addr);
    try std.testing.expect(found3 != null);
    try std.testing.expect(found3.? == conn);

    // Remove connection
    pool.removeConnection(conn);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

test "connection pool limit" {
    const allocator = std.testing.allocator;
    var pool = ConnectionPool.init(allocator, true, 2);
    defer pool.deinit();

    var peer_addr: SockAddrStorage = undefined;

    // Create two connections
    const dcid1 = types.ConnectionId.init(&[_]u8{0x01});
    @memset(std.mem.asBytes(&peer_addr), 1);
    _ = try pool.createConnection(dcid1, peer_addr);

    const dcid2 = types.ConnectionId.init(&[_]u8{0x02});
    @memset(std.mem.asBytes(&peer_addr), 2);
    _ = try pool.createConnection(dcid2, peer_addr);

    // Third should fail
    const dcid3 = types.ConnectionId.init(&[_]u8{0x03});
    @memset(std.mem.asBytes(&peer_addr), 3);
    try std.testing.expectError(Error.ConnectionLimitReached, pool.createConnection(dcid3, peer_addr));
}

test "connection pool iterator" {
    const allocator = std.testing.allocator;
    var pool = ConnectionPool.init(allocator, true, 10);
    defer pool.deinit();

    var peer_addr: SockAddrStorage = undefined;

    // Create connections
    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        const dcid = types.ConnectionId.init(&[_]u8{i});
        @memset(std.mem.asBytes(&peer_addr), i);
        _ = try pool.createConnection(dcid, peer_addr);
    }

    // Iterate
    var it = pool.iterator();
    var count: usize = 0;
    while (it.next()) |_| {
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), count);
}
