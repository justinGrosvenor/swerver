const std = @import("std");

const MAX_CONSUMERS = 1024;
const MAX_NAME_LEN = 128;

pub const Entry = struct {
    name: [MAX_NAME_LEN]u8 = undefined,
    name_len: u8 = 0,
    requests: u64 = 0,
    last_seen_ms: u64 = 0,
    active: bool = false,

    pub fn nameSlice(self: *const Entry) []const u8 {
        return self.name[0..self.name_len];
    }
};

var entries: [MAX_CONSUMERS]Entry = .{Entry{}} ** MAX_CONSUMERS;

pub fn record(consumer: []const u8, now_ms: u64) void {
    if (consumer.len == 0) return;
    const clen: u8 = @intCast(@min(consumer.len, MAX_NAME_LEN));

    for (&entries) |*e| {
        if (e.active and e.name_len == clen and
            std.mem.eql(u8, e.name[0..e.name_len], consumer[0..clen]))
        {
            e.requests += 1;
            e.last_seen_ms = now_ms;
            return;
        }
    }

    // Find empty slot or evict LRU
    var target: *Entry = &entries[0];
    var oldest_ms: u64 = std.math.maxInt(u64);
    for (&entries) |*e| {
        if (!e.active) {
            target = e;
            break;
        }
        if (e.last_seen_ms < oldest_ms) {
            oldest_ms = e.last_seen_ms;
            target = e;
        }
    }

    @memcpy(target.name[0..clen], consumer[0..clen]);
    target.name_len = clen;
    target.requests = 1;
    target.last_seen_ms = now_ms;
    target.active = true;
}

pub fn snapshot(buf: []u8) []const u8 {
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"consumers\":[");
    var first = true;
    for (&entries) |*e| {
        if (!e.active or e.requests == 0) continue;
        if (!first) off += copyInto(buf[off..], ",");
        first = false;
        const n = std.fmt.bufPrint(buf[off..], "{{\"name\":\"{s}\",\"requests\":{d},\"last_seen_ms\":{d}}}", .{
            e.nameSlice(), e.requests, e.last_seen_ms,
        }) catch break;
        off += n.len;
    }
    off += copyInto(buf[off..], "]}");
    return buf[0..off];
}

pub fn snapshotAndReset(buf: []u8) []const u8 {
    const result = snapshot(buf);
    for (&entries) |*e| {
        if (e.active) e.requests = 0;
    }
    return result;
}

fn copyInto(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

// ── Tests ──────────────────────────────────────────────────────

test "record and snapshot" {
    @memset(std.mem.asBytes(&entries), 0);

    record("tenant-a", 1000);
    record("tenant-a", 1001);
    record("tenant-b", 1002);
    record("tenant-a", 1003);

    var buf: [4096]u8 = undefined;
    const json = snapshot(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"tenant-a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"requests\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"tenant-b\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"requests\":1") != null);
}

test "snapshotAndReset zeros counts" {
    @memset(std.mem.asBytes(&entries), 0);

    record("client-1", 500);
    record("client-1", 501);

    var buf: [4096]u8 = undefined;
    const json = snapshotAndReset(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"requests\":2") != null);

    const json2 = snapshot(&buf);
    try std.testing.expectEqualStrings("{\"consumers\":[]}", json2);
}

test "empty consumer ignored" {
    @memset(std.mem.asBytes(&entries), 0);

    record("", 100);

    var buf: [4096]u8 = undefined;
    const json = snapshot(&buf);
    try std.testing.expectEqualStrings("{\"consumers\":[]}", json);
}

test "LRU eviction" {
    @memset(std.mem.asBytes(&entries), 0);

    for (0..MAX_CONSUMERS) |i| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "consumer-{d}", .{i}) catch break;
        record(name, @intCast(i * 10));
    }

    // All slots full — next record should evict the oldest (consumer-0)
    record("new-consumer", 99999);

    var buf: [131072]u8 = undefined;
    const json = snapshot(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"new-consumer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"consumer-0\"") == null);
}
