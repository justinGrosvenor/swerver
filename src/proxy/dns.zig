const std = @import("std");
const builtin = @import("builtin");
const upstream_mod = @import("upstream.zig");

pub const DnsConfig = struct {
    hostname: []const u8,
    port: u16 = 80,
    interval_s: u32 = 30,
};

const MAX_RESOLVED: usize = 64;

const ResolvedIp = struct {
    octets: [4]u8,
};

const DiscoveryEntry = struct {
    upstream_name: []const u8,
    config: DnsConfig,
    last_resolved_ms: u64 = 0,
    servers: []upstream_mod.Server = &.{},
    current_ips: []ResolvedIp = &.{},
};

pub const DnsDiscovery = struct {
    allocator: std.mem.Allocator,
    entries: []DiscoveryEntry,
    entry_count: usize,

    pub fn init(allocator: std.mem.Allocator, upstreams: []const upstream_mod.Upstream) !DnsDiscovery {
        var count: usize = 0;
        for (upstreams) |u| {
            if (u.dns_discovery != null) count += 1;
        }
        if (count == 0) {
            return .{
                .allocator = allocator,
                .entries = &.{},
                .entry_count = 0,
            };
        }

        const entries = try allocator.alloc(DiscoveryEntry, count);
        var ei: usize = 0;
        for (upstreams) |u| {
            if (u.dns_discovery) |dns| {
                entries[ei] = .{
                    .upstream_name = u.name,
                    .config = dns,
                };
                ei += 1;
            }
        }

        return .{
            .allocator = allocator,
            .entries = entries,
            .entry_count = count,
        };
    }

    pub fn deinit(self: *DnsDiscovery) void {
        for (self.entries[0..self.entry_count]) |*e| {
            if (e.servers.len > 0) self.allocator.free(e.servers);
            if (e.current_ips.len > 0) self.allocator.free(e.current_ips);
        }
        if (self.entry_count > 0) self.allocator.free(self.entries);
    }

    pub fn tick(self: *DnsDiscovery, now_ms: u64) bool {
        var any_changed = false;
        for (self.entries[0..self.entry_count]) |*entry| {
            const interval_ms: u64 = @as(u64, entry.config.interval_s) * 1000;
            if (now_ms -% entry.last_resolved_ms < interval_ms) continue;
            entry.last_resolved_ms = now_ms;

            if (self.resolveEntry(entry)) {
                any_changed = true;
            }
        }
        return any_changed;
    }

    pub fn resolvedServers(self: *const DnsDiscovery, upstream_name: []const u8) ?[]const upstream_mod.Server {
        for (self.entries[0..self.entry_count]) |*e| {
            if (std.mem.eql(u8, e.upstream_name, upstream_name)) {
                if (e.servers.len > 0) return e.servers;
                return null;
            }
        }
        return null;
    }

    fn resolveEntry(self: *DnsDiscovery, entry: *DiscoveryEntry) bool {
        var resolved: [MAX_RESOLVED]ResolvedIp = undefined;
        const count = dnsResolveAll(entry.config.hostname, &resolved) catch return false;
        if (count == 0) return false;

        // Check if IPs changed
        if (ipsEqual(entry.current_ips, resolved[0..count])) return false;

        // Build new server list
        const new_servers = self.allocator.alloc(upstream_mod.Server, count) catch return false;
        for (resolved[0..count], 0..) |ip, i| {
            new_servers[i] = .{
                .address = ipToStr(self.allocator, ip) catch {
                    for (new_servers[0..i]) |s| self.allocator.free(@constCast(s.address));
                    self.allocator.free(new_servers);
                    return false;
                },
                .port = entry.config.port,
            };
        }

        const new_ips = self.allocator.alloc(ResolvedIp, count) catch {
            for (new_servers) |s| self.allocator.free(@constCast(s.address));
            self.allocator.free(new_servers);
            return false;
        };
        @memcpy(new_ips, resolved[0..count]);

        // Free old data
        for (entry.servers) |s| self.allocator.free(@constCast(s.address));
        if (entry.servers.len > 0) self.allocator.free(entry.servers);
        if (entry.current_ips.len > 0) self.allocator.free(entry.current_ips);

        entry.servers = new_servers;
        entry.current_ips = new_ips;

        std.log.info("DNS discovery: {s} resolved to {d} servers", .{ entry.upstream_name, count });
        return true;
    }
};

fn ipsEqual(a: []const ResolvedIp, b: []const ResolvedIp) bool {
    if (a.len != b.len) return false;
    for (a, b) |ai, bi| {
        if (!std.mem.eql(u8, &ai.octets, &bi.octets)) return false;
    }
    return true;
}

fn ipToStr(allocator: std.mem.Allocator, ip: ResolvedIp) ![]const u8 {
    var buf: [16]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3] }) catch return error.OutOfMemory;
    const result = try allocator.alloc(u8, s.len);
    @memcpy(result, s);
    return result;
}

// Platform-specific DNS resolution

const has_bsd_addrinfo = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

const addrinfo = if (has_bsd_addrinfo)
    extern struct {
        flags: c_int,
        family: c_int,
        socktype: c_int,
        protocol: c_int,
        addrlen: std.posix.socklen_t,
        canonname: ?[*:0]u8,
        addr: ?*std.posix.sockaddr,
        next: ?*@This(),
    }
else
    extern struct {
        flags: c_int,
        family: c_int,
        socktype: c_int,
        protocol: c_int,
        addrlen: std.posix.socklen_t,
        addr: ?*std.posix.sockaddr,
        canonname: ?[*:0]u8,
        next: ?*@This(),
    };

extern "c" fn getaddrinfo(
    node: [*:0]const u8,
    service: ?[*:0]const u8,
    hints: ?*const addrinfo,
    res: *?*addrinfo,
) c_int;

extern "c" fn freeaddrinfo(res: *addrinfo) void;

const SockAddrIn = extern struct {
    len_or_family: if (has_bsd_addrinfo) packed struct(u16) { len: u8, family: u8 } else u16,
    port: u16,
    addr: [4]u8,
    zero: [8]u8 = .{0} ** 8,
};

fn dnsResolveAll(hostname: []const u8, out: *[MAX_RESOLVED]ResolvedIp) !usize {
    var buf: [256]u8 = undefined;
    if (hostname.len >= buf.len) return error.HostnameTooLong;
    @memcpy(buf[0..hostname.len], hostname);
    buf[hostname.len] = 0;

    var hints: addrinfo = std.mem.zeroes(addrinfo);
    hints.family = @intCast(std.posix.AF.INET);
    hints.socktype = @intCast(std.posix.SOCK.STREAM);

    var result: ?*addrinfo = null;
    const rc = getaddrinfo(@ptrCast(buf[0..hostname.len :0]), null, &hints, &result);
    if (rc != 0 or result == null) return error.DnsResolutionFailed;
    defer freeaddrinfo(result.?);

    var count: usize = 0;
    var current: ?*addrinfo = result;
    while (current) |info| {
        if (count >= MAX_RESOLVED) break;
        if (info.addr) |sa| {
            const sa_bytes: [*]const u8 = @ptrCast(sa);
            const sa4: *const SockAddrIn = @ptrCast(@alignCast(sa_bytes));
            out[count] = .{ .octets = sa4.addr };
            count += 1;
        }
        current = info.next;
    }

    // Sort for stable comparison
    std.mem.sort(ResolvedIp, out[0..count], {}, struct {
        fn lt(_: void, a: ResolvedIp, b: ResolvedIp) bool {
            return std.mem.order(u8, &a.octets, &b.octets) == .lt;
        }
    }.lt);

    return count;
}

// ── Tests ──

test "ipsEqual detects same and different" {
    const a = [_]ResolvedIp{ .{ .octets = .{ 10, 0, 0, 1 } }, .{ .octets = .{ 10, 0, 0, 2 } } };
    const b = [_]ResolvedIp{ .{ .octets = .{ 10, 0, 0, 1 } }, .{ .octets = .{ 10, 0, 0, 2 } } };
    const c = [_]ResolvedIp{ .{ .octets = .{ 10, 0, 0, 1 } }, .{ .octets = .{ 10, 0, 0, 3 } } };
    try std.testing.expect(ipsEqual(&a, &b));
    try std.testing.expect(!ipsEqual(&a, &c));
}

test "ipToStr formats correctly" {
    const ip = ResolvedIp{ .octets = .{ 192, 168, 1, 100 } };
    const s = try ipToStr(std.testing.allocator, ip);
    defer std.testing.allocator.free(s);
    try std.testing.expectEqualStrings("192.168.1.100", s);
}

test "DnsDiscovery init with no DNS upstreams" {
    const upstreams = [_]upstream_mod.Upstream{
        .{ .name = "backend", .servers = &.{} },
    };
    var disc = try DnsDiscovery.init(std.testing.allocator, &upstreams);
    defer disc.deinit();
    try std.testing.expectEqual(@as(usize, 0), disc.entry_count);
    try std.testing.expect(disc.resolvedServers("backend") == null);
}

test "DnsDiscovery init with DNS upstream" {
    const upstreams = [_]upstream_mod.Upstream{
        .{ .name = "api", .servers = &.{}, .dns_discovery = .{ .hostname = "api.internal", .port = 8080, .interval_s = 30 } },
        .{ .name = "static", .servers = &.{} },
    };
    var disc = try DnsDiscovery.init(std.testing.allocator, &upstreams);
    defer disc.deinit();
    try std.testing.expectEqual(@as(usize, 1), disc.entry_count);
    try std.testing.expectEqualStrings("api", disc.entries[0].upstream_name);
    try std.testing.expectEqualStrings("api.internal", disc.entries[0].config.hostname);
}

test "dnsResolveAll resolves localhost" {
    var resolved: [MAX_RESOLVED]ResolvedIp = undefined;
    const count = dnsResolveAll("localhost", &resolved) catch |err| {
        // Some CI environments don't have localhost in DNS
        if (err == error.DnsResolutionFailed) return;
        return err;
    };
    try std.testing.expect(count > 0);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, resolved[0].octets);
}
