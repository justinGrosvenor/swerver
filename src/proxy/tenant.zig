//! Per-worker tenant-to-microVM affinity registry (park-concurrency plan Phase 1).
//!
//! Maps a tenant key (a request header value, e.g. the Host) to the UNIX-domain
//! data socket of the warm Nether microVM serving that tenant. A registry HIT
//! lets the proxy forward straight to the VM (steady state = ordinary proxying,
//! no wasm filter, no park); a MISS runs the filter, which parks for a Tier-2
//! cold start whose reply names the socket (registered here on resume).
//!
//! Owned by the Server (survives config reload, unlike the Proxy), and is
//! PER-WORKER: N workers each learn the same mapping independently via their own
//! cold-start park. The supervisor's ensure is idempotent, so per-worker
//! duplication just costs at most `workers` cold-start parks per tenant, once.
//! Mirrors the fixed-slot, zero-per-request-alloc style of the host_call table
//! and the connection pool.
//!
//! SINGLE-THREADED: the registry is touched only from its worker's reactor
//! thread. `lookup` returns a slice INTO a slot, valid only until the next
//! `register`/`evict`/`evictIdle` on the same worker; callers must consume it
//! within the synchronous forward and never mutate the registry mid-forward.

const std = @import("std");
const net = @import("../runtime/net.zig");

pub const TENANT_KEY_MAX = 128;
pub const PATH_MAX = net.UNIX_PATH_MAX;
pub const CAP = 256;

const Slot = struct {
    active: bool = false,
    key_buf: [TENANT_KEY_MAX]u8 = undefined,
    key_len: u16 = 0,
    path_buf: [PATH_MAX]u8 = undefined,
    path_len: u16 = 0,
    last_used_ms: u64 = 0,
};

pub const TenantRegistry = struct {
    slots: [CAP]Slot = [1]Slot{.{}} ** CAP,
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,

    /// Look up the warm socket path for a tenant key, bumping its LRU stamp.
    /// Returns a slot-interior slice (see the module lifetime note) or null.
    pub fn lookup(self: *TenantRegistry, key: []const u8, now_ms: u64) ?[]const u8 {
        if (key.len == 0 or key.len > TENANT_KEY_MAX) {
            self.misses += 1;
            return null;
        }
        for (&self.slots) |*s| {
            if (s.active and s.key_len == key.len and std.mem.eql(u8, s.key_buf[0..s.key_len], key)) {
                s.last_used_ms = now_ms;
                self.hits += 1;
                return s.path_buf[0..s.path_len];
            }
        }
        self.misses += 1;
        return null;
    }

    /// Insert or update a tenant->path mapping. On a full table the
    /// least-recently-used slot is evicted. Over-long key/path are rejected
    /// (caller validated the path prefix already). Idempotent for a repeated
    /// (key, path).
    pub fn register(self: *TenantRegistry, key: []const u8, path: []const u8, now_ms: u64) void {
        if (key.len == 0 or key.len > TENANT_KEY_MAX) return;
        if (path.len == 0 or path.len > PATH_MAX) return;

        var free: ?*Slot = null;
        var lru: ?*Slot = null;
        for (&self.slots) |*s| {
            if (s.active and s.key_len == key.len and std.mem.eql(u8, s.key_buf[0..s.key_len], key)) {
                writeSlot(s, key, path, now_ms);
                return;
            }
            if (!s.active) {
                if (free == null) free = s;
            } else if (lru == null or s.last_used_ms < lru.?.last_used_ms) {
                lru = s;
            }
        }
        if (free) |s| {
            writeSlot(s, key, path, now_ms);
            return;
        }
        // Full: evict the LRU slot.
        if (lru) |s| {
            self.evictions += 1;
            writeSlot(s, key, path, now_ms);
        }
    }

    fn writeSlot(s: *Slot, key: []const u8, path: []const u8, now_ms: u64) void {
        @memcpy(s.key_buf[0..key.len], key);
        s.key_len = @intCast(key.len);
        @memcpy(s.path_buf[0..path.len], path);
        s.path_len = @intCast(path.len);
        s.last_used_ms = now_ms;
        s.active = true;
    }

    /// Drop a tenant mapping (dead-socket feedback: a forward to it failed).
    pub fn evict(self: *TenantRegistry, key: []const u8) void {
        for (&self.slots) |*s| {
            if (s.active and s.key_len == key.len and std.mem.eql(u8, s.key_buf[0..s.key_len], key)) {
                s.active = false;
                self.evictions += 1;
                return;
            }
        }
    }

    /// Reap mappings unused for at least `ttl_ms` (housekeeping). Returns the
    /// count reaped. Only garbage-collects swerver's view; the supervisor owns
    /// actual VM reclaim (a later miss just re-parks).
    pub fn evictIdle(self: *TenantRegistry, now_ms: u64, ttl_ms: u64) u32 {
        var n: u32 = 0;
        for (&self.slots) |*s| {
            if (s.active and now_ms -% s.last_used_ms >= ttl_ms) {
                s.active = false;
                n += 1;
            }
        }
        self.evictions += n;
        return n;
    }

    pub fn count(self: *const TenantRegistry) usize {
        var n: usize = 0;
        for (&self.slots) |*s| {
            if (s.active) n += 1;
        }
        return n;
    }

    pub const Entry = struct { key: []const u8, path: []const u8, last_used_ms: u64 };

    /// Iterate active entries (admin view). Slices point into the registry;
    /// valid only until the next mutation (same worker, single-threaded).
    pub const Iterator = struct {
        reg: *TenantRegistry,
        idx: usize = 0,
        pub fn next(self: *Iterator) ?Entry {
            while (self.idx < CAP) {
                const s = &self.reg.slots[self.idx];
                self.idx += 1;
                if (s.active) return .{
                    .key = s.key_buf[0..s.key_len],
                    .path = s.path_buf[0..s.path_len],
                    .last_used_ms = s.last_used_ms,
                };
            }
            return null;
        }
    };

    pub fn iterator(self: *TenantRegistry) Iterator {
        return .{ .reg = self };
    }
};

test "register/lookup/upsert/miss" {
    var r = TenantRegistry{};
    try std.testing.expect(r.lookup("t1", 1) == null);
    r.register("t1", "/tmp/vm1.sock", 10);
    try std.testing.expectEqualStrings("/tmp/vm1.sock", r.lookup("t1", 11).?);
    // Upsert: same key, new path.
    r.register("t1", "/tmp/vm1b.sock", 12);
    try std.testing.expectEqualStrings("/tmp/vm1b.sock", r.lookup("t1", 13).?);
    try std.testing.expectEqual(@as(usize, 1), r.count());
    // A distinct key coexists.
    r.register("t2", "/tmp/vm2.sock", 14);
    try std.testing.expectEqual(@as(usize, 2), r.count());
    // Oversized / empty keys never match.
    try std.testing.expect(r.lookup("", 15) == null);
    const long = [_]u8{'a'} ** (TENANT_KEY_MAX + 1);
    try std.testing.expect(r.lookup(&long, 15) == null);
}

test "evict on failure + evictIdle by TTL" {
    var r = TenantRegistry{};
    r.register("t1", "/tmp/a.sock", 100);
    r.register("t2", "/tmp/b.sock", 200);
    r.evict("t1");
    try std.testing.expect(r.lookup("t1", 300) == null);
    try std.testing.expectEqualStrings("/tmp/b.sock", r.lookup("t2", 300).?);
    // t2 last used at 300; TTL 50 at now 400 reaps it.
    try std.testing.expectEqual(@as(u32, 1), r.evictIdle(400, 50));
    try std.testing.expect(r.lookup("t2", 400) == null);
    try std.testing.expectEqual(@as(usize, 0), r.count());
}

test "LRU eviction when full" {
    var r = TenantRegistry{};
    var buf: [16]u8 = undefined;
    // Fill CAP slots, each with an increasing last_used stamp.
    var i: usize = 0;
    while (i < CAP) : (i += 1) {
        const k = std.fmt.bufPrint(&buf, "k{d}", .{i}) catch unreachable;
        r.register(k, "/tmp/x.sock", @intCast(i + 1));
    }
    try std.testing.expectEqual(@as(usize, CAP), r.count());
    // k0 is the LRU (stamp 1). A new key evicts it, not a newer one.
    r.register("new", "/tmp/new.sock", 100000);
    try std.testing.expectEqual(@as(usize, CAP), r.count());
    try std.testing.expect(r.lookup("k0", 100001) == null);
    try std.testing.expectEqualStrings("/tmp/new.sock", r.lookup("new", 100001).?);
}
