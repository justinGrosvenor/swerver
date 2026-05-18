const std = @import("std");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const upstream_mod = @import("../proxy/upstream.zig");
const proxy_mod = @import("../proxy/proxy.zig");
const json_write = @import("../runtime/json_write.zig");

const Server = @import("../server.zig").Server;

const MAX_REQUEST = 65536;
const MAX_RESPONSE = 65536;

pub const AdminConfig = struct {
    enabled: bool = false,
    port: u16 = 9180,
    api_key: []const u8 = "",
};

// ── Listener lifecycle ──────────────────────────────────────────────

pub fn bindAdminSocket(address: []const u8, port: u16) !std.posix.fd_t {
    return net.listen(address, port, 128);
}

pub fn closeAdminSocket(fd: std.posix.fd_t) void {
    clock.closeFd(fd);
}

// ── Housekeeping poll ───────────────────────────────────────────────

pub fn pollAdmin(server: *Server) void {
    const admin_fd = server.admin_listener_fd orelse return;

    const client = net.accept(admin_fd) catch return;
    defer clock.closeFd(client);

    setTimeouts(client);

    var req_buf: [MAX_REQUEST]u8 = undefined;
    const n = std.posix.read(client, &req_buf) catch return;
    if (n == 0) return;

    const req = parseHttpRequest(req_buf[0..n]) orelse {
        _ = writeHttpResponse(client, 400, "{\"error\":\"bad request\"}");
        return;
    };

    if (server.cfg.admin.api_key.len > 0) {
        if (!checkApiKey(req.headers_start, req.headers_end, req_buf[0..n], server.cfg.admin.api_key)) {
            _ = writeHttpResponse(client, 401, "{\"error\":\"unauthorized\"}");
            return;
        }
    }

    var resp_buf: [MAX_RESPONSE]u8 = undefined;
    const result = dispatch(server, req.method, req.path, req.body(req_buf[0..n]), &resp_buf);
    _ = writeHttpResponse(client, result.status, result.body);
}

fn setTimeouts(fd: std.posix.fd_t) void {
    const tv = std.posix.timeval{ .sec = 1, .usec = 0 };
    _ = std.posix.system.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(std.posix.timeval));
    _ = std.posix.system.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(std.posix.timeval));
}

fn writeHttpResponse(fd: std.posix.fd_t, status: u16, json_body: []const u8) bool {
    var hdr_buf: [256]u8 = undefined;
    const status_text = switch (status) {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        else => "OK",
    };
    const hdr = std.fmt.bufPrint(&hdr_buf, "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, status_text, json_body.len }) catch return false;
    _ = writeAll(fd, hdr) catch return false;
    _ = writeAll(fd, json_body) catch return false;
    return true;
}

fn writeAll(fd: std.posix.fd_t, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = std.posix.system.write(fd, data[sent..].ptr, data[sent..].len);
        if (rc < 0) {
            if (std.posix.errno(rc) == .INTR) continue;
            return error.WriteFailed;
        }
        if (rc == 0) return error.WriteFailed;
        sent += @intCast(rc);
    }
}

// ── Request dispatch ────────────────────────────────────────────────

const DispatchResult = struct {
    status: u16,
    body: []const u8,
};

fn dispatch(server: *Server, method: Method, path: []const u8, body: []const u8, buf: []u8) DispatchResult {
    if (startsWith(path, "/v1/routes")) {
        return switch (method) {
            .GET => listRoutes(server, buf),
            .POST => addRoute(server, body, buf),
            .DELETE => deleteRoute(server, path, buf),
            else => .{ .status = 405, .body = "{\"error\":\"method not allowed\"}" },
        };
    }
    if (startsWith(path, "/v1/upstreams")) {
        return switch (method) {
            .GET => listUpstreams(server, buf),
            .POST => addUpstream(server, body, buf),
            .DELETE => deleteUpstream(server, path, buf),
            else => .{ .status = 405, .body = "{\"error\":\"method not allowed\"}" },
        };
    }
    if (startsWith(path, "/v1/status")) {
        return getStatus(server, buf);
    }
    if (startsWith(path, "/v1/config/persist")) {
        if (method != .POST) return .{ .status = 405, .body = "{\"error\":\"method not allowed\"}" };
        return persistConfig(server, buf);
    }
    return .{ .status = 404, .body = "{\"error\":\"not found\"}" };
}

// ── Route handlers ──────────────────────────────────────────────────

fn listRoutes(server: *Server, buf: []u8) DispatchResult {
    const proxy = server.proxy orelse return .{ .status = 200, .body = "{\"routes\":[]}" };
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"routes\":[");
    for (proxy.config.routes, 0..) |route, i| {
        if (i > 0) off += copyInto(buf[off..], ",");
        off += writeRouteJson(buf[off..], route);
    }
    off += copyInto(buf[off..], "]}");
    return .{ .status = 200, .body = buf[0..off] };
}

fn addRoute(server: *Server, body: []const u8, buf: []u8) DispatchResult {
    const config_path = server.config_path orelse return .{ .status = 400, .body = "{\"error\":\"no config file\"}" };
    if (body.len == 0) return .{ .status = 400, .body = "{\"error\":\"empty body\"}" };

    const config_file = @import("../config_file.zig");
    var arena = std.heap.ArenaAllocator.init(server.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const file_bytes = readFileAlloc(alloc, config_path) catch return .{ .status = 500, .body = "{\"error\":\"failed to read config\"}" };
    var tree = std.json.parseFromSliceLeaky(std.json.Value, alloc, file_bytes, .{ .allocate = .alloc_always }) catch
        return .{ .status = 500, .body = "{\"error\":\"config parse failed\"}" };

    const new_route = std.json.parseFromSliceLeaky(std.json.Value, alloc, body, .{ .allocate = .alloc_always }) catch
        return .{ .status = 400, .body = "{\"error\":\"invalid JSON\"}" };

    const prefix = extractString(new_route, "path_prefix") orelse
        return .{ .status = 400, .body = "{\"error\":\"path_prefix required\"}" };
    _ = extractString(new_route, "upstream") orelse
        return .{ .status = 400, .body = "{\"error\":\"upstream required\"}" };

    const routes_arr = ensureRoutesArray(&tree, alloc) catch
        return .{ .status = 500, .body = "{\"error\":\"config structure error\"}" };

    for (routes_arr.items) |existing| {
        if (extractString(existing, "path_prefix")) |ep| {
            if (std.mem.eql(u8, ep, prefix))
                return .{ .status = 409, .body = "{\"error\":\"route already exists\"}" };
        }
    }

    routes_arr.append(new_route) catch
        return .{ .status = 500, .body = "{\"error\":\"alloc failed\"}" };

    writeConfigAndReload(server, alloc, tree, config_path, config_file) catch
        return .{ .status = 500, .body = "{\"error\":\"failed to write config\"}" };

    const n = std.fmt.bufPrint(buf, "{{\"ok\":true,\"route\":\"{s}\"}}", .{prefix}) catch
        return .{ .status = 201, .body = "{\"ok\":true}" };
    return .{ .status = 201, .body = n };
}

fn deleteRoute(server: *Server, path: []const u8, buf: []u8) DispatchResult {
    const config_path = server.config_path orelse return .{ .status = 400, .body = "{\"error\":\"no config file\"}" };
    const prefix = queryParam(path, "prefix") orelse
        return .{ .status = 400, .body = "{\"error\":\"?prefix= required\"}" };

    const config_file = @import("../config_file.zig");
    var arena = std.heap.ArenaAllocator.init(server.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const file_bytes = readFileAlloc(alloc, config_path) catch return .{ .status = 500, .body = "{\"error\":\"failed to read config\"}" };
    var tree = std.json.parseFromSliceLeaky(std.json.Value, alloc, file_bytes, .{ .allocate = .alloc_always }) catch
        return .{ .status = 500, .body = "{\"error\":\"config parse failed\"}" };

    const routes_arr = ensureRoutesArray(&tree, alloc) catch
        return .{ .status = 500, .body = "{\"error\":\"config structure error\"}" };

    var found = false;
    var i: usize = 0;
    while (i < routes_arr.items.len) {
        if (extractString(routes_arr.items[i], "path_prefix")) |ep| {
            if (std.mem.eql(u8, ep, prefix)) {
                _ = routes_arr.orderedRemove(i);
                found = true;
                continue;
            }
        }
        i += 1;
    }

    if (!found) return .{ .status = 404, .body = "{\"error\":\"route not found\"}" };

    writeConfigAndReload(server, alloc, tree, config_path, config_file) catch
        return .{ .status = 500, .body = "{\"error\":\"failed to write config\"}" };

    const n = std.fmt.bufPrint(buf, "{{\"ok\":true,\"deleted\":\"{s}\"}}", .{prefix}) catch
        return .{ .status = 200, .body = "{\"ok\":true}" };
    return .{ .status = 200, .body = n };
}

fn listUpstreams(server: *Server, buf: []u8) DispatchResult {
    const proxy = server.proxy orelse return .{ .status = 200, .body = "{\"upstreams\":[]}" };
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"upstreams\":[");
    for (proxy.config.upstreams, 0..) |u, i| {
        if (i > 0) off += copyInto(buf[off..], ",");
        off += writeUpstreamJson(buf[off..], u);
    }
    off += copyInto(buf[off..], "]}");
    return .{ .status = 200, .body = buf[0..off] };
}

fn addUpstream(server: *Server, body: []const u8, buf: []u8) DispatchResult {
    const config_path = server.config_path orelse return .{ .status = 400, .body = "{\"error\":\"no config file\"}" };
    if (body.len == 0) return .{ .status = 400, .body = "{\"error\":\"empty body\"}" };

    const config_file = @import("../config_file.zig");
    var arena = std.heap.ArenaAllocator.init(server.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const file_bytes = readFileAlloc(alloc, config_path) catch return .{ .status = 500, .body = "{\"error\":\"failed to read config\"}" };
    var tree = std.json.parseFromSliceLeaky(std.json.Value, alloc, file_bytes, .{ .allocate = .alloc_always }) catch
        return .{ .status = 500, .body = "{\"error\":\"config parse failed\"}" };

    const new_upstream = std.json.parseFromSliceLeaky(std.json.Value, alloc, body, .{ .allocate = .alloc_always }) catch
        return .{ .status = 400, .body = "{\"error\":\"invalid JSON\"}" };

    const name = extractString(new_upstream, "name") orelse
        return .{ .status = 400, .body = "{\"error\":\"name required\"}" };

    const upstreams_arr = ensureUpstreamsArray(&tree, alloc) catch
        return .{ .status = 500, .body = "{\"error\":\"config structure error\"}" };

    for (upstreams_arr.items) |existing| {
        if (extractString(existing, "name")) |en| {
            if (std.mem.eql(u8, en, name))
                return .{ .status = 409, .body = "{\"error\":\"upstream already exists\"}" };
        }
    }

    upstreams_arr.append(new_upstream) catch
        return .{ .status = 500, .body = "{\"error\":\"alloc failed\"}" };

    writeConfigAndReload(server, alloc, tree, config_path, config_file) catch
        return .{ .status = 500, .body = "{\"error\":\"failed to write config\"}" };

    const n = std.fmt.bufPrint(buf, "{{\"ok\":true,\"upstream\":\"{s}\"}}", .{name}) catch
        return .{ .status = 201, .body = "{\"ok\":true}" };
    return .{ .status = 201, .body = n };
}

fn deleteUpstream(server: *Server, path: []const u8, buf: []u8) DispatchResult {
    const config_path = server.config_path orelse return .{ .status = 400, .body = "{\"error\":\"no config file\"}" };
    const name = queryParam(path, "name") orelse
        return .{ .status = 400, .body = "{\"error\":\"?name= required\"}" };

    const config_file = @import("../config_file.zig");
    var arena = std.heap.ArenaAllocator.init(server.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const file_bytes = readFileAlloc(alloc, config_path) catch return .{ .status = 500, .body = "{\"error\":\"failed to read config\"}" };
    var tree = std.json.parseFromSliceLeaky(std.json.Value, alloc, file_bytes, .{ .allocate = .alloc_always }) catch
        return .{ .status = 500, .body = "{\"error\":\"config parse failed\"}" };

    const upstreams_arr = ensureUpstreamsArray(&tree, alloc) catch
        return .{ .status = 500, .body = "{\"error\":\"config structure error\"}" };

    var found = false;
    var i: usize = 0;
    while (i < upstreams_arr.items.len) {
        if (extractString(upstreams_arr.items[i], "name")) |en| {
            if (std.mem.eql(u8, en, name)) {
                _ = upstreams_arr.orderedRemove(i);
                found = true;
                continue;
            }
        }
        i += 1;
    }

    if (!found) return .{ .status = 404, .body = "{\"error\":\"upstream not found\"}" };

    writeConfigAndReload(server, alloc, tree, config_path, config_file) catch
        return .{ .status = 500, .body = "{\"error\":\"failed to write config\"}" };

    const n = std.fmt.bufPrint(buf, "{{\"ok\":true,\"deleted\":\"{s}\"}}", .{name}) catch
        return .{ .status = 200, .body = "{\"ok\":true}" };
    return .{ .status = 200, .body = n };
}

fn getStatus(server: *Server, buf: []u8) DispatchResult {
    const route_count: usize = if (server.proxy) |p| p.config.routes.len else 0;
    const upstream_count: usize = if (server.proxy) |p| p.config.upstreams.len else 0;
    const n = std.fmt.bufPrint(buf, "{{\"status\":\"ok\",\"routes\":{d},\"upstreams\":{d},\"port\":{d},\"workers\":{d}}}", .{
        route_count, upstream_count, server.cfg.port, server.cfg.workers,
    }) catch return .{ .status = 200, .body = "{\"status\":\"ok\"}" };
    return .{ .status = 200, .body = n };
}

fn persistConfig(server: *Server, buf: []u8) DispatchResult {
    _ = buf;
    const config_path = server.config_path orelse return .{ .status = 400, .body = "{\"error\":\"no config file\"}" };
    _ = config_path;
    return .{ .status = 200, .body = "{\"ok\":true,\"persisted\":true}" };
}

// ── Config file manipulation ────────────────────────────────────────

fn writeConfigAndReload(server: *Server, alloc: std.mem.Allocator, tree: std.json.Value, config_path: []const u8, config_file: anytype) !void {
    const serialized = std.json.Stringify.valueAlloc(alloc, tree, .{ .whitespace = .indent_2 }) catch return error.SerializeFailed;

    writeFileContents(config_path, serialized) catch return error.WriteFailed;

    var loaded = config_file.loadConfigFile(server.allocator, config_path) catch return error.ReloadFailed;

    loaded.server_config.validate() catch {
        loaded.deinit();
        return error.ValidationFailed;
    };

    const new = loaded.server_config;
    server.cfg.timeouts = new.timeouts;
    server.cfg.limits = new.limits;

    if (loaded.upstreams.len > 0 and loaded.routes.len > 0) {
        var new_proxy = proxy_mod.Proxy.init(server.allocator, .{
            .upstreams = loaded.upstreams,
            .routes = loaded.routes,
        }) catch {
            loaded.deinit();
            return error.ProxyBuildFailed;
        };

        if (server.proxy) |old| {
            old.deinit();
            server.allocator.destroy(old);
        }

        const proxy_ptr = server.allocator.create(proxy_mod.Proxy) catch {
            new_proxy.deinit();
            loaded.deinit();
            return error.AllocFailed;
        };
        proxy_ptr.* = new_proxy;
        server.proxy = proxy_ptr;

        if (server.reload_arena) |*old_arena| old_arena.deinit();
        server.reload_arena = loaded.arena;
    } else if (loaded.upstreams.len == 0 and loaded.routes.len == 0) {
        if (server.proxy) |old| {
            old.deinit();
            server.allocator.destroy(old);
            server.proxy = null;
        }
        if (server.reload_arena) |*old_arena| old_arena.deinit();
        server.reload_arena = loaded.arena;
    } else {
        loaded.deinit();
    }

    std.log.info("[admin] config reloaded from {s}", .{config_path});
}

fn ensureRoutesArray(tree: *std.json.Value, alloc: std.mem.Allocator) !*std.json.Array {
    if (tree.* != .object) return error.BadStructure;
    var obj = &tree.object;
    if (obj.getPtr("routes")) |val| {
        if (val.* == .array) return &val.array;
        return error.BadStructure;
    }
    obj.put("routes", .{ .array = std.json.Array.init(alloc) }) catch return error.BadStructure;
    return &obj.getPtr("routes").?.array;
}

fn ensureUpstreamsArray(tree: *std.json.Value, alloc: std.mem.Allocator) !*std.json.Array {
    if (tree.* != .object) return error.BadStructure;
    var obj = &tree.object;
    if (obj.getPtr("upstreams")) |val| {
        if (val.* == .array) return &val.array;
        return error.BadStructure;
    }
    obj.put("upstreams", .{ .array = std.json.Array.init(alloc) }) catch return error.BadStructure;
    return &obj.getPtr("upstreams").?.array;
}

fn extractString(val: std.json.Value, key: []const u8) ?[]const u8 {
    if (val != .object) return null;
    const entry = val.object.get(key) orelse return null;
    if (entry != .string) return null;
    return entry.string;
}

// ── HTTP request parsing ────────────────────────────────────────────

const Method = enum { GET, POST, PUT, DELETE, OTHER };

const ParsedRequest = struct {
    method: Method,
    path: []const u8,
    headers_start: usize,
    headers_end: usize,
    body_start: usize,

    fn body(self: ParsedRequest, raw: []const u8) []const u8 {
        if (self.body_start >= raw.len) return "";
        return raw[self.body_start..];
    }
};

fn parseHttpRequest(raw: []const u8) ?ParsedRequest {
    const line_end = std.mem.indexOf(u8, raw, "\r\n") orelse return null;
    const line = raw[0..line_end];

    const method_end = std.mem.indexOf(u8, line, " ") orelse return null;
    const method_str = line[0..method_end];
    const rest = line[method_end + 1 ..];
    const path_end = std.mem.indexOf(u8, rest, " ") orelse return null;
    const path = rest[0..path_end];

    const method: Method = if (std.mem.eql(u8, method_str, "GET"))
        .GET
    else if (std.mem.eql(u8, method_str, "POST"))
        .POST
    else if (std.mem.eql(u8, method_str, "PUT"))
        .PUT
    else if (std.mem.eql(u8, method_str, "DELETE"))
        .DELETE
    else
        .OTHER;

    const headers_start = line_end + 2;
    const header_end_marker = std.mem.indexOf(u8, raw[headers_start..], "\r\n\r\n") orelse return null;
    const headers_end = headers_start + header_end_marker;
    const body_start = headers_end + 4;

    return .{
        .method = method,
        .path = path,
        .headers_start = headers_start,
        .headers_end = headers_end,
        .body_start = body_start,
    };
}

fn checkApiKey(headers_start: usize, headers_end: usize, raw: []const u8, expected: []const u8) bool {
    const headers = raw[headers_start..headers_end];
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |header_line| {
        const colon = std.mem.indexOf(u8, header_line, ":") orelse continue;
        const name = std.mem.trim(u8, header_line[0..colon], " ");
        if (std.ascii.eqlIgnoreCase(name, "x-api-key")) {
            const value = std.mem.trim(u8, header_line[colon + 1 ..], " ");
            return std.mem.eql(u8, value, expected);
        }
    }
    return false;
}

fn queryParam(path: []const u8, key: []const u8) ?[]const u8 {
    const q = std.mem.indexOf(u8, path, "?") orelse return null;
    var params = path[q + 1 ..];
    while (params.len > 0) {
        const amp = std.mem.indexOf(u8, params, "&") orelse params.len;
        const pair = params[0..amp];
        const eq = std.mem.indexOf(u8, pair, "=") orelse {
            params = if (amp < params.len) params[amp + 1 ..] else "";
            continue;
        };
        if (std.mem.eql(u8, pair[0..eq], key)) {
            return pair[eq + 1 ..];
        }
        params = if (amp < params.len) params[amp + 1 ..] else "";
    }
    return null;
}

// ── JSON serialization ──────────────────────────────────────────────

fn writeRouteJson(buf: []u8, route: upstream_mod.ProxyRoute) usize {
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"path_prefix\":\"");
    off += copyEscaped(buf[off..], route.path_prefix);
    off += copyInto(buf[off..], "\",\"upstream\":\"");
    off += copyEscaped(buf[off..], route.upstream);
    off += copyInto(buf[off..], "\"");
    if (route.host) |h| {
        off += copyInto(buf[off..], ",\"host\":\"");
        off += copyEscaped(buf[off..], h);
        off += copyInto(buf[off..], "\"");
    }
    if (route.traffic_split) |ts| {
        off += copyInto(buf[off..], ",\"traffic_split\":[");
        for (ts, 0..) |t, i| {
            if (i > 0) off += copyInto(buf[off..], ",");
            const n = std.fmt.bufPrint(buf[off..], "{{\"upstream\":\"{s}\",\"weight\":{d}}}", .{ t.upstream, t.weight }) catch break;
            off += n.len;
        }
        off += copyInto(buf[off..], "]");
    }
    if (route.cache) |cc| {
        const n = std.fmt.bufPrint(buf[off..], ",\"cache\":{{\"ttl_s\":{d},\"max_entries\":{d}", .{ cc.ttl_s, cc.max_entries }) catch {
            off += copyInto(buf[off..], "}");
            return off;
        };
        off += n.len;
        if (cc.vary.len > 0) {
            off += copyInto(buf[off..], ",\"vary\":[");
            for (cc.vary, 0..) |v, vi| {
                if (vi > 0) off += copyInto(buf[off..], ",");
                off += copyInto(buf[off..], "\"");
                off += copyEscaped(buf[off..], v);
                off += copyInto(buf[off..], "\"");
            }
            off += copyInto(buf[off..], "]");
        }
        off += copyInto(buf[off..], "}");
    }
    off += copyInto(buf[off..], "}");
    return off;
}

fn writeUpstreamJson(buf: []u8, u: upstream_mod.Upstream) usize {
    var off: usize = 0;
    off += copyInto(buf[off..], "{\"name\":\"");
    off += copyEscaped(buf[off..], u.name);
    off += copyInto(buf[off..], "\",\"servers\":[");
    for (u.servers, 0..) |s, i| {
        if (i > 0) off += copyInto(buf[off..], ",");
        const n = std.fmt.bufPrint(buf[off..], "{{\"address\":\"{s}\",\"port\":{d},\"weight\":{d}}}", .{ s.address, s.port, s.weight }) catch break;
        off += n.len;
    }
    off += copyInto(buf[off..], "]");
    const lb_name: []const u8 = switch (u.load_balancer) {
        .round_robin => "round_robin",
        .least_conn => "least_conn",
        .ip_hash => "ip_hash",
        .random => "random",
        .weighted_round_robin => "weighted_round_robin",
    };
    off += copyInto(buf[off..], ",\"load_balancer\":\"");
    off += copyInto(buf[off..], lb_name);
    off += copyInto(buf[off..], "\"");
    off += copyInto(buf[off..], "}");
    return off;
}

fn copyInto(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

fn copyEscaped(dst: []u8, src: []const u8) usize {
    const escaped = json_write.writeEscaped(dst, src) catch return 0;
    return escaped.len;
}

// ── File I/O ────────────────────────────────────────────────────────

fn readFileAlloc(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0) catch return error.OpenFailed;
    defer clock.closeFd(fd);

    const max_size = 1024 * 1024;
    const buf = try alloc.alloc(u8, max_size);
    var total: usize = 0;
    while (total < max_size) {
        const n = std.posix.read(fd, buf[total..]) catch return error.ReadFailed;
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

fn writeFileContents(path: []const u8, data: []const u8) !void {
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .TRUNC = true }, 0) catch
        return error.OpenFailed;
    defer clock.closeFd(fd);

    var written: usize = 0;
    while (written < data.len) {
        const rc = std.posix.system.write(fd, data[written..].ptr, data[written..].len);
        if (rc < 0) {
            if (std.posix.errno(rc) == .INTR) continue;
            return error.WriteFailed;
        }
        if (rc == 0) return error.WriteFailed;
        written += @intCast(rc);
    }
}

fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, haystack, prefix);
}

// ── Tests ───────────────────────────────────────────────────────────

test "parseHttpRequest parses simple GET" {
    const raw = "GET /v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const req = parseHttpRequest(raw) orelse return error.ParseFailed;
    try std.testing.expect(req.method == .GET);
    try std.testing.expectEqualStrings("/v1/status", req.path);
    try std.testing.expectEqualStrings("", req.body(raw));
}

test "parseHttpRequest parses POST with body" {
    const raw = "POST /v1/routes HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\n{\"test\":123}";
    const req = parseHttpRequest(raw) orelse return error.ParseFailed;
    try std.testing.expect(req.method == .POST);
    try std.testing.expectEqualStrings("/v1/routes", req.path);
    try std.testing.expectEqualStrings("{\"test\":123}", req.body(raw));
}

test "checkApiKey validates correct key" {
    const raw = "GET / HTTP/1.1\r\nX-API-Key: secret123\r\nHost: localhost\r\n\r\n";
    const req = parseHttpRequest(raw) orelse return error.ParseFailed;
    try std.testing.expect(checkApiKey(req.headers_start, req.headers_end, raw, "secret123"));
    try std.testing.expect(!checkApiKey(req.headers_start, req.headers_end, raw, "wrong"));
}

test "queryParam extracts values" {
    try std.testing.expectEqualStrings("/api/", queryParam("/v1/routes?prefix=/api/", "prefix").?);
    try std.testing.expectEqualStrings("backend", queryParam("/v1/upstreams?name=backend", "name").?);
    try std.testing.expect(queryParam("/v1/routes", "prefix") == null);
    try std.testing.expectEqualStrings("b", queryParam("/v1/x?a=1&b=b&c=3", "b").?);
}

test "writeRouteJson produces valid JSON" {
    var buf: [512]u8 = undefined;
    const route = upstream_mod.ProxyRoute{
        .path_prefix = "/api/",
        .upstream = "backend",
    };
    const n = writeRouteJson(&buf, route);
    try std.testing.expect(n > 0);
    const json = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"path_prefix\":\"/api/\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"upstream\":\"backend\"") != null);
}

test "writeUpstreamJson produces valid JSON" {
    var buf: [512]u8 = undefined;
    const servers = [_]upstream_mod.Server{
        .{ .address = "10.0.0.1", .port = 8080 },
    };
    const u = upstream_mod.Upstream{
        .name = "api",
        .servers = &servers,
    };
    const n = writeUpstreamJson(&buf, u);
    try std.testing.expect(n > 0);
    const json = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"address\":\"10.0.0.1\"") != null);
}
