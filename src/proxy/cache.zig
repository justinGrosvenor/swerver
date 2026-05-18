const std = @import("std");
const response_mod = @import("../response/response.zig");
const request_mod = @import("../protocol/request.zig");

pub const CacheConfig = struct {
    ttl_s: u32 = 60,
    max_entries: u16 = 1024,
    vary: []const []const u8 = &.{},
};

pub const StoredHeader = struct {
    name: []const u8,
    value: []const u8,
};

const Entry = struct {
    key_hash: u64 = 0,
    path: []const u8 = "",
    vary_hash: u64 = 0,

    status: u16 = 0,
    headers: []StoredHeader = &.{},
    header_storage: []u8 = "",
    body: []u8 = "",

    etag: ?[]const u8 = null,
    last_modified: ?[]const u8 = null,

    created_ms: u64 = 0,
    ttl_ms: u64 = 0,

    prev: ?u16 = null,
    next: ?u16 = null,
    in_use: bool = false,
};

const SENTINEL: u16 = std.math.maxInt(u16);

pub const LookupResult = union(enum) {
    hit: HitInfo,
    not_modified,
    miss,
};

pub const HitInfo = struct {
    status: u16,
    headers: []const StoredHeader,
    body: []const u8,
};

pub const ResponseCache = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    map: std.AutoHashMap(u64, u16),
    lru_head: u16 = SENTINEL,
    lru_tail: u16 = SENTINEL,
    free_head: u16 = 0,
    count: u16 = 0,
    capacity: u16,

    pub fn init(allocator: std.mem.Allocator, max_entries: u16) !ResponseCache {
        const cap = if (max_entries == 0) 256 else max_entries;
        const entries = try allocator.alloc(Entry, cap);
        for (entries, 0..) |*e, i| {
            e.* = .{};
            e.next = if (i + 1 < cap) @intCast(i + 1) else SENTINEL;
        }
        return .{
            .allocator = allocator,
            .entries = entries,
            .map = std.AutoHashMap(u64, u16).init(allocator),
            .capacity = cap,
        };
    }

    pub fn deinit(self: *ResponseCache) void {
        for (self.entries) |*e| {
            if (e.in_use) self.freeEntryData(e);
        }
        self.allocator.free(self.entries);
        self.map.deinit();
    }

    pub fn lookup(
        self: *ResponseCache,
        method: request_mod.Method,
        path: []const u8,
        req_headers: []const request_mod.Header,
        vary_keys: []const []const u8,
        now_ms: u64,
    ) LookupResult {
        if (method != .GET) return .miss;

        const key = computeKey(path, vary_keys, req_headers);
        const idx = self.map.get(key) orelse return .miss;
        const entry = &self.entries[idx];

        if (!entry.in_use or entry.key_hash != key) return .miss;
        if (now_ms > entry.created_ms + entry.ttl_ms) {
            self.evictEntry(idx);
            return .miss;
        }

        // Conditional: If-None-Match
        if (entry.etag) |etag| {
            for (req_headers) |hdr| {
                if (std.ascii.eqlIgnoreCase(hdr.name, "If-None-Match")) {
                    if (std.mem.eql(u8, hdr.value, etag)) {
                        self.promoteToHead(idx);
                        return .not_modified;
                    }
                }
            }
        }

        // Conditional: If-Modified-Since
        if (entry.last_modified) |lm| {
            for (req_headers) |hdr| {
                if (std.ascii.eqlIgnoreCase(hdr.name, "If-Modified-Since")) {
                    if (std.mem.eql(u8, hdr.value, lm)) {
                        self.promoteToHead(idx);
                        return .not_modified;
                    }
                }
            }
        }

        self.promoteToHead(idx);
        return .{ .hit = .{
            .status = entry.status,
            .headers = entry.headers,
            .body = entry.body,
        } };
    }

    pub fn store(
        self: *ResponseCache,
        path: []const u8,
        req_headers: []const request_mod.Header,
        vary_keys: []const []const u8,
        resp_status: u16,
        resp_headers: []const response_mod.Header,
        resp_body: []const u8,
        ttl_ms: u64,
        now_ms: u64,
    ) void {
        if (resp_status != 200) return;
        if (!isCacheable(resp_headers)) return;

        const key = computeKey(path, vary_keys, req_headers);
        const effective_ttl = extractMaxAge(resp_headers) orelse ttl_ms;

        // If entry already exists for this key, evict and replace
        if (self.map.get(key)) |existing| {
            self.evictEntry(existing);
        }

        const idx = self.allocSlot() orelse return;
        const entry = &self.entries[idx];

        // Copy path
        const path_copy = self.allocator.alloc(u8, path.len) catch return;
        @memcpy(path_copy, path);

        // Copy body
        const body_copy = self.allocator.alloc(u8, resp_body.len) catch {
            self.allocator.free(path_copy);
            return;
        };
        @memcpy(body_copy, resp_body);

        // Copy headers: single allocation for StoredHeader array + all name/value bytes
        var total_hdr_bytes: usize = 0;
        var cacheable_count: usize = 0;
        for (resp_headers) |hdr| {
            if (isHopByHopResponse(hdr.name)) continue;
            total_hdr_bytes += hdr.name.len + hdr.value.len;
            cacheable_count += 1;
        }

        const stored_headers = self.allocator.alloc(StoredHeader, cacheable_count) catch {
            self.allocator.free(path_copy);
            self.allocator.free(body_copy);
            return;
        };
        const hdr_storage = self.allocator.alloc(u8, total_hdr_bytes) catch {
            self.allocator.free(path_copy);
            self.allocator.free(body_copy);
            self.allocator.free(stored_headers);
            return;
        };

        var hdr_pos: usize = 0;
        var hdr_idx: usize = 0;
        var etag_slice: ?[]const u8 = null;
        var last_modified_slice: ?[]const u8 = null;

        for (resp_headers) |hdr| {
            if (isHopByHopResponse(hdr.name)) continue;
            const name_start = hdr_pos;
            @memcpy(hdr_storage[hdr_pos .. hdr_pos + hdr.name.len], hdr.name);
            hdr_pos += hdr.name.len;
            const val_start = hdr_pos;
            @memcpy(hdr_storage[hdr_pos .. hdr_pos + hdr.value.len], hdr.value);
            hdr_pos += hdr.value.len;

            const stored_name = hdr_storage[name_start .. name_start + hdr.name.len];
            const stored_value = hdr_storage[val_start .. val_start + hdr.value.len];

            stored_headers[hdr_idx] = .{ .name = stored_name, .value = stored_value };

            if (std.ascii.eqlIgnoreCase(hdr.name, "ETag")) {
                etag_slice = stored_value;
            } else if (std.ascii.eqlIgnoreCase(hdr.name, "Last-Modified")) {
                last_modified_slice = stored_value;
            }

            hdr_idx += 1;
        }

        entry.* = .{
            .key_hash = key,
            .path = path_copy,
            .vary_hash = computeVaryHash(vary_keys, req_headers),
            .status = resp_status,
            .headers = stored_headers,
            .header_storage = hdr_storage,
            .body = body_copy,
            .etag = etag_slice,
            .last_modified = last_modified_slice,
            .created_ms = now_ms,
            .ttl_ms = effective_ttl,
            .in_use = true,
        };

        self.map.put(key, idx) catch {
            self.freeEntryData(entry);
            entry.in_use = false;
            self.returnSlot(idx);
            return;
        };

        self.addToHead(idx);
        self.count += 1;
    }

    pub fn invalidate(self: *ResponseCache, path: []const u8) void {
        var to_remove: [16]u64 = undefined;
        var remove_count: usize = 0;

        var it = self.map.iterator();
        while (it.next()) |kv| {
            const entry = &self.entries[kv.value_ptr.*];
            if (entry.in_use and std.mem.eql(u8, entry.path, path)) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = kv.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |key| {
            if (self.map.get(key)) |idx| {
                self.evictEntry(idx);
            }
        }
    }

    fn allocSlot(self: *ResponseCache) ?u16 {
        if (self.free_head != SENTINEL) {
            const idx = self.free_head;
            self.free_head = self.entries[idx].next orelse SENTINEL;
            return idx;
        }
        // Evict LRU tail
        if (self.lru_tail != SENTINEL) {
            const idx = self.lru_tail;
            self.evictEntry(idx);
            return self.allocSlot();
        }
        return null;
    }

    fn returnSlot(self: *ResponseCache, idx: u16) void {
        self.entries[idx].next = if (self.free_head == SENTINEL) null else self.free_head;
        self.entries[idx].prev = null;
        self.free_head = idx;
    }

    fn evictEntry(self: *ResponseCache, idx: u16) void {
        const entry = &self.entries[idx];
        if (!entry.in_use) return;

        _ = self.map.remove(entry.key_hash);
        self.removeFromLru(idx);
        self.freeEntryData(entry);
        entry.* = .{};
        self.returnSlot(idx);
        self.count -= 1;
    }

    fn freeEntryData(self: *ResponseCache, entry: *Entry) void {
        if (entry.path.len > 0) self.allocator.free(entry.path);
        if (entry.body.len > 0) self.allocator.free(entry.body);
        if (entry.headers.len > 0) self.allocator.free(entry.headers);
        if (entry.header_storage.len > 0) self.allocator.free(entry.header_storage);
    }

    fn promoteToHead(self: *ResponseCache, idx: u16) void {
        if (self.lru_head == idx) return;
        self.removeFromLru(idx);
        self.addToHead(idx);
    }

    fn addToHead(self: *ResponseCache, idx: u16) void {
        self.entries[idx].prev = null;
        self.entries[idx].next = if (self.lru_head == SENTINEL) null else self.lru_head;
        if (self.lru_head != SENTINEL) {
            self.entries[self.lru_head].prev = idx;
        }
        self.lru_head = idx;
        if (self.lru_tail == SENTINEL) {
            self.lru_tail = idx;
        }
    }

    fn removeFromLru(self: *ResponseCache, idx: u16) void {
        const entry = &self.entries[idx];
        const prev = entry.prev;
        const next = entry.next;

        if (prev) |p| {
            self.entries[p].next = next;
        } else {
            self.lru_head = next orelse SENTINEL;
        }

        if (next) |n| {
            self.entries[n].prev = prev;
        } else {
            self.lru_tail = prev orelse SENTINEL;
        }

        entry.prev = null;
        entry.next = null;
    }
};

fn computeKey(
    path: []const u8,
    vary_keys: []const []const u8,
    req_headers: []const request_mod.Header,
) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(path);
    h.update("\x00");
    for (vary_keys) |vk| {
        for (req_headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, vk)) {
                h.update(hdr.value);
                break;
            }
        }
        h.update("\x00");
    }
    return h.final();
}

fn computeVaryHash(
    vary_keys: []const []const u8,
    req_headers: []const request_mod.Header,
) u64 {
    var h = std.hash.Wyhash.init(0x1234);
    for (vary_keys) |vk| {
        for (req_headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, vk)) {
                h.update(hdr.value);
                break;
            }
        }
    }
    return h.final();
}

fn isCacheable(headers: []const response_mod.Header) bool {
    for (headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "Cache-Control")) {
            if (std.mem.indexOf(u8, hdr.value, "no-store") != null) return false;
            if (std.mem.indexOf(u8, hdr.value, "private") != null) return false;
        }
    }
    return true;
}

fn extractMaxAge(headers: []const response_mod.Header) ?u64 {
    for (headers) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "Cache-Control")) {
            if (std.mem.indexOf(u8, hdr.value, "max-age=")) |pos| {
                const start = pos + 8;
                var end = start;
                while (end < hdr.value.len and hdr.value[end] >= '0' and hdr.value[end] <= '9') : (end += 1) {}
                if (end > start) {
                    const secs = std.fmt.parseInt(u32, hdr.value[start..end], 10) catch return null;
                    return @as(u64, secs) * 1000;
                }
            }
        }
    }
    return null;
}

fn isHopByHopResponse(name: []const u8) bool {
    const skip = [_][]const u8{
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    };
    for (skip) |s| {
        if (std.ascii.eqlIgnoreCase(name, s)) return true;
    }
    return false;
}

// ── Tests ──

test "cache miss on empty cache" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const headers = [_]request_mod.Header{};
    const result = cache.lookup(.GET, "/test", &headers, &.{}, 1000);
    try std.testing.expect(result == .miss);
}

test "cache store and hit" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const req_headers = [_]request_mod.Header{};
    const resp_headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "text/plain" },
    };

    cache.store("/test", &req_headers, &.{}, 200, &resp_headers, "hello", 60_000, 1000);
    const result = cache.lookup(.GET, "/test", &req_headers, &.{}, 2000);
    switch (result) {
        .hit => |info| {
            try std.testing.expectEqual(@as(u16, 200), info.status);
            try std.testing.expectEqualStrings("hello", info.body);
            try std.testing.expectEqual(@as(usize, 1), info.headers.len);
            try std.testing.expectEqualStrings("Content-Type", info.headers[0].name);
        },
        else => return error.ExpectedHit,
    }
}

test "cache expires after TTL" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const req_headers = [_]request_mod.Header{};
    const resp_headers = [_]response_mod.Header{};

    cache.store("/ttl", &req_headers, &.{}, 200, &resp_headers, "data", 5_000, 1000);

    const hit = cache.lookup(.GET, "/ttl", &req_headers, &.{}, 5000);
    try std.testing.expect(hit == .hit);

    const miss = cache.lookup(.GET, "/ttl", &req_headers, &.{}, 7000);
    try std.testing.expect(miss == .miss);
}

test "cache respects no-store" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const req_headers = [_]request_mod.Header{};
    const resp_headers = [_]response_mod.Header{
        .{ .name = "Cache-Control", .value = "no-store" },
    };

    cache.store("/private", &req_headers, &.{}, 200, &resp_headers, "secret", 60_000, 1000);
    const result = cache.lookup(.GET, "/private", &req_headers, &.{}, 2000);
    try std.testing.expect(result == .miss);
}

test "cache conditional 304 with ETag" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const req_store_headers = [_]request_mod.Header{};
    const resp_headers = [_]response_mod.Header{
        .{ .name = "ETag", .value = "\"abc123\"" },
        .{ .name = "Content-Type", .value = "text/plain" },
    };

    cache.store("/etag", &req_store_headers, &.{}, 200, &resp_headers, "body", 60_000, 1000);

    const req_headers = [_]request_mod.Header{
        .{ .name = "If-None-Match", .value = "\"abc123\"" },
    };
    const result = cache.lookup(.GET, "/etag", &req_headers, &.{}, 2000);
    try std.testing.expect(result == .not_modified);
}

test "cache LRU eviction" {
    var cache = try ResponseCache.init(std.testing.allocator, 2);
    defer cache.deinit();

    const req_headers = [_]request_mod.Header{};
    const resp_headers = [_]response_mod.Header{};

    cache.store("/a", &req_headers, &.{}, 200, &resp_headers, "a", 60_000, 1000);
    cache.store("/b", &req_headers, &.{}, 200, &resp_headers, "b", 60_000, 1000);
    // This should evict /a (LRU tail)
    cache.store("/c", &req_headers, &.{}, 200, &resp_headers, "c", 60_000, 1000);

    try std.testing.expect(cache.lookup(.GET, "/a", &req_headers, &.{}, 2000) == .miss);
    try std.testing.expect(cache.lookup(.GET, "/b", &req_headers, &.{}, 2000) == .hit);
    try std.testing.expect(cache.lookup(.GET, "/c", &req_headers, &.{}, 2000) == .hit);
}

test "cache invalidate on POST path" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const req_headers = [_]request_mod.Header{};
    const resp_headers = [_]response_mod.Header{};

    cache.store("/resource", &req_headers, &.{}, 200, &resp_headers, "data", 60_000, 1000);
    try std.testing.expect(cache.lookup(.GET, "/resource", &req_headers, &.{}, 2000) == .hit);

    cache.invalidate("/resource");
    try std.testing.expect(cache.lookup(.GET, "/resource", &req_headers, &.{}, 2000) == .miss);
}

test "cache vary header differentiation" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const vary_keys = [_][]const u8{"Accept"};
    const resp_headers = [_]response_mod.Header{
        .{ .name = "Content-Type", .value = "application/json" },
    };

    const req_json = [_]request_mod.Header{
        .{ .name = "Accept", .value = "application/json" },
    };
    cache.store("/api", &req_json, &vary_keys, 200, &resp_headers, "{}", 60_000, 1000);

    const req_xml = [_]request_mod.Header{
        .{ .name = "Accept", .value = "application/xml" },
    };
    // Different Accept value should miss
    try std.testing.expect(cache.lookup(.GET, "/api", &req_xml, &vary_keys, 2000) == .miss);
    // Same Accept value should hit
    try std.testing.expect(cache.lookup(.GET, "/api", &req_json, &vary_keys, 2000) == .hit);
}

test "cache respects max-age directive" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const req_headers = [_]request_mod.Header{};
    const resp_headers = [_]response_mod.Header{
        .{ .name = "Cache-Control", .value = "max-age=2" },
    };

    cache.store("/maxage", &req_headers, &.{}, 200, &resp_headers, "data", 60_000, 1000);

    // Within max-age (2s = 2000ms)
    try std.testing.expect(cache.lookup(.GET, "/maxage", &req_headers, &.{}, 2500) == .hit);
    // Past max-age
    try std.testing.expect(cache.lookup(.GET, "/maxage", &req_headers, &.{}, 4000) == .miss);
}

test "cache skips non-GET methods" {
    var cache = try ResponseCache.init(std.testing.allocator, 16);
    defer cache.deinit();

    const req_headers = [_]request_mod.Header{};
    const result = cache.lookup(.POST, "/test", &req_headers, &.{}, 1000);
    try std.testing.expect(result == .miss);
}
