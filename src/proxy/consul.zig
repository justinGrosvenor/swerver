const std = @import("std");
const upstream_mod = @import("upstream.zig");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");

pub const ConsulConfig = struct {
    service: []const u8,
    address: []const u8 = "127.0.0.1",
    port: u16 = 8500,
    interval_s: u32 = 15,
    token: []const u8 = "",
};

const MAX_INSTANCES: usize = 64;

const ServiceInstance = struct {
    address: [64]u8 = undefined,
    address_len: u8 = 0,
    port: u16 = 0,

    fn addressSlice(self: *const ServiceInstance) []const u8 {
        return self.address[0..self.address_len];
    }
};

const DiscoveryEntry = struct {
    upstream_name: []const u8,
    config: ConsulConfig,
    last_poll_ms: u64 = 0,
    servers: []upstream_mod.Server = &.{},
    current: [MAX_INSTANCES]ServiceInstance = undefined,
    current_count: usize = 0,
};

pub const ConsulDiscovery = struct {
    allocator: std.mem.Allocator,
    entries: []DiscoveryEntry,
    entry_count: usize,

    pub fn init(allocator: std.mem.Allocator, upstreams: []const upstream_mod.Upstream) !ConsulDiscovery {
        var count: usize = 0;
        for (upstreams) |u| {
            if (u.consul_discovery != null) count += 1;
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
            if (u.consul_discovery) |cfg| {
                entries[ei] = .{
                    .upstream_name = u.name,
                    .config = cfg,
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

    pub fn deinit(self: *ConsulDiscovery) void {
        for (self.entries[0..self.entry_count]) |*e| {
            for (e.servers) |s| self.allocator.free(@constCast(s.address));
            if (e.servers.len > 0) self.allocator.free(e.servers);
        }
        if (self.entry_count > 0) self.allocator.free(self.entries);
    }

    pub fn tick(self: *ConsulDiscovery, now_ms: u64) bool {
        var any_changed = false;
        for (self.entries[0..self.entry_count]) |*entry| {
            const interval_ms: u64 = @as(u64, entry.config.interval_s) * 1000;
            if (now_ms -% entry.last_poll_ms < interval_ms) continue;
            entry.last_poll_ms = now_ms;

            if (self.pollEntry(entry)) {
                any_changed = true;
            }
        }
        return any_changed;
    }

    pub fn resolvedServers(self: *const ConsulDiscovery, upstream_name: []const u8) ?[]const upstream_mod.Server {
        for (self.entries[0..self.entry_count]) |*e| {
            if (std.mem.eql(u8, e.upstream_name, upstream_name)) {
                if (e.servers.len > 0) return e.servers;
                return null;
            }
        }
        return null;
    }

    fn pollEntry(self: *ConsulDiscovery, entry: *DiscoveryEntry) bool {
        var response_buf: [8192]u8 = undefined;
        const body = fetchConsulService(
            entry.config,
            &response_buf,
        ) orelse return false;

        var new_instances: [MAX_INSTANCES]ServiceInstance = undefined;
        const new_count = parseServiceInstances(body, &new_instances);
        if (new_count == 0) return false;

        if (instancesEqual(
            entry.current[0..entry.current_count],
            new_instances[0..new_count],
        )) return false;

        const new_servers = self.allocator.alloc(upstream_mod.Server, new_count) catch return false;
        for (new_instances[0..new_count], 0..) |inst, i| {
            const addr = self.allocator.alloc(u8, inst.address_len) catch {
                for (new_servers[0..i]) |s| self.allocator.free(@constCast(s.address));
                self.allocator.free(new_servers);
                return false;
            };
            @memcpy(addr, inst.addressSlice());
            new_servers[i] = .{ .address = addr, .port = inst.port };
        }

        for (entry.servers) |s| self.allocator.free(@constCast(s.address));
        if (entry.servers.len > 0) self.allocator.free(entry.servers);

        entry.servers = new_servers;
        entry.current_count = new_count;
        @memcpy(entry.current[0..new_count], new_instances[0..new_count]);

        std.log.info("Consul discovery: {s} resolved to {d} instances", .{ entry.upstream_name, new_count });
        return true;
    }
};

fn instancesEqual(a: []const ServiceInstance, b: []const ServiceInstance) bool {
    if (a.len != b.len) return false;
    for (a, b) |ai, bi| {
        if (ai.port != bi.port) return false;
        if (ai.address_len != bi.address_len) return false;
        if (!std.mem.eql(u8, ai.addressSlice(), bi.addressSlice())) return false;
    }
    return true;
}

fn fetchConsulService(config: ConsulConfig, buf: []u8) ?[]const u8 {
    const fd = net.connectBlocking(config.address, config.port, 2000) catch return null;
    defer clock.closeFd(fd);

    var req_buf: [1024]u8 = undefined;
    const req_slice = std.fmt.bufPrint(&req_buf, "GET /v1/health/service/{s}?passing HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n{s}\r\n", .{
        config.service,
        config.address,
        config.port,
        if (config.token.len > 0) blk: {
            var token_hdr: [256]u8 = undefined;
            break :blk std.fmt.bufPrint(&token_hdr, "X-Consul-Token: {s}\r\n", .{config.token}) catch "";
        } else "",
    }) catch return null;

    net.sendAll(fd, req_slice) catch return null;

    var total: usize = 0;
    while (total < buf.len) {
        const n = net.recvBlocking(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    if (total == 0) return null;

    const response = buf[0..total];
    const body_start = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return null;
    return response[body_start + 4 ..];
}

fn parseServiceInstances(json_body: []const u8, out: *[MAX_INSTANCES]ServiceInstance) usize {
    var count: usize = 0;
    var pos: usize = 0;

    while (count < MAX_INSTANCES) {
        const svc_start = std.mem.indexOfPos(u8, json_body, pos, "\"Service\"") orelse break;
        const addr_key = std.mem.indexOfPos(u8, json_body, svc_start, "\"Address\"") orelse break;
        const addr_start = std.mem.indexOfPos(u8, json_body, addr_key + 9, "\"") orelse break;
        const addr_end = std.mem.indexOfPos(u8, json_body, addr_start + 1, "\"") orelse break;
        const addr_val = json_body[addr_start + 1 .. addr_end];

        const port_key = std.mem.indexOfPos(u8, json_body, addr_end, "\"Port\"") orelse break;
        const port_val = extractJsonNumber(json_body, port_key + 6) orelse break;

        if (addr_val.len > 0 and addr_val.len <= 64 and port_val > 0 and port_val <= 65535) {
            var inst = &out[count];
            @memcpy(inst.address[0..addr_val.len], addr_val);
            inst.address_len = @intCast(addr_val.len);
            inst.port = @intCast(port_val);
            count += 1;
        }

        pos = port_key + 6;
    }

    return count;
}

fn extractJsonNumber(json: []const u8, start: usize) ?u32 {
    var i = start;
    while (i < json.len and (json[i] == ' ' or json[i] == ':' or json[i] == '\t' or json[i] == '\n' or json[i] == '\r')) : (i += 1) {}
    var result: u32 = 0;
    var found = false;
    while (i < json.len and json[i] >= '0' and json[i] <= '9') {
        result = result * 10 + (json[i] - '0');
        found = true;
        i += 1;
    }
    if (!found) return null;
    return result;
}

// ── Tests ──

test "parseServiceInstances" {
    const json =
        \\[{"Node":{"Node":"node1"},"Service":{"Address":"10.0.0.1","Port":8080}},
        \\{"Node":{"Node":"node2"},"Service":{"Address":"10.0.0.2","Port":9090}}]
    ;
    var instances: [MAX_INSTANCES]ServiceInstance = undefined;
    const count = parseServiceInstances(json, &instances);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("10.0.0.1", instances[0].addressSlice());
    try std.testing.expectEqual(@as(u16, 8080), instances[0].port);
    try std.testing.expectEqualStrings("10.0.0.2", instances[1].addressSlice());
    try std.testing.expectEqual(@as(u16, 9090), instances[1].port);
}

test "parseServiceInstances handles empty" {
    var instances: [MAX_INSTANCES]ServiceInstance = undefined;
    try std.testing.expectEqual(@as(usize, 0), parseServiceInstances("[]", &instances));
    try std.testing.expectEqual(@as(usize, 0), parseServiceInstances("", &instances));
}

test "instancesEqual" {
    var a = [_]ServiceInstance{.{ .address_len = 7, .port = 80 }};
    @memcpy(a[0].address[0..7], "1.2.3.4");
    var b = [_]ServiceInstance{.{ .address_len = 7, .port = 80 }};
    @memcpy(b[0].address[0..7], "1.2.3.4");
    try std.testing.expect(instancesEqual(&a, &b));

    b[0].port = 81;
    try std.testing.expect(!instancesEqual(&a, &b));
}

test "extractJsonNumber" {
    try std.testing.expectEqual(@as(?u32, 8080), extractJsonNumber(": 8080,", 0));
    try std.testing.expectEqual(@as(?u32, 443), extractJsonNumber("  443}", 0));
    try std.testing.expectEqual(@as(?u32, null), extractJsonNumber(": abc", 0));
}

test "ConsulDiscovery init with no consul upstreams" {
    const upstreams = [_]upstream_mod.Upstream{
        .{ .name = "backend", .servers = &.{} },
    };
    var disc = try ConsulDiscovery.init(std.testing.allocator, &upstreams);
    defer disc.deinit();
    try std.testing.expectEqual(@as(usize, 0), disc.entry_count);
}

test "ConsulDiscovery init with consul upstream" {
    const upstreams = [_]upstream_mod.Upstream{
        .{ .name = "api", .servers = &.{}, .consul_discovery = .{ .service = "api-prod" } },
        .{ .name = "static", .servers = &.{} },
    };
    var disc = try ConsulDiscovery.init(std.testing.allocator, &upstreams);
    defer disc.deinit();
    try std.testing.expectEqual(@as(usize, 1), disc.entry_count);
    try std.testing.expectEqualStrings("api", disc.entries[0].upstream_name);
    try std.testing.expectEqualStrings("api-prod", disc.entries[0].config.service);
}
