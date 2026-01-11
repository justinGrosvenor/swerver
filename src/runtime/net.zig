const std = @import("std");
const builtin = @import("builtin");

const has_len_field = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

const SockAddrIn = if (has_len_field)
    extern struct {
        len: u8,
        family: u8,
        port: u16,
        addr: u32,
        zero: [8]u8,
    }
else
    extern struct {
        family: u16,
        port: u16,
        addr: u32,
        zero: [8]u8,
    };

const SockAddrIn6 = if (has_len_field)
    extern struct {
        len: u8,
        family: u8,
        port: u16,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    }
else
    extern struct {
        family: u16,
        port: u16,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    };

pub const ListenError = error{
    UnsupportedPlatform,
    UnsupportedAddress,
    SocketFailed,
    BindFailed,
    ListenFailed,
    SetSockOptFailed,
    NonBlockingFailed,
} || std.posix.FcntlError;

pub const AcceptError = error{
    AcceptFailed,
    WouldBlock,
    NonBlockingFailed,
} || std.posix.FcntlError;

const NonBlockingError = error{NonBlockingFailed} || std.posix.FcntlError;

pub fn listen(address: []const u8, port: u16, backlog: u32) ListenError!std.posix.fd_t {
    if (!isSupportedPlatform()) return error.UnsupportedPlatform;

    const addr = try parseAddress(address, port);
    const domain: c_uint = switch (addr) {
        .ip4 => @intCast(std.posix.AF.INET),
        .ip6 => @intCast(std.posix.AF.INET6),
    };
    const fd = std.posix.system.socket(domain, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (fd < 0) return error.SocketFailed;
    errdefer std.posix.close(fd);

    try setReuseAddr(fd);
    try setReusePort(fd);
    try setNonBlocking(fd);

    var storage = buildSockaddr(addr);
    const sockaddr_ptr: *const std.posix.sockaddr = switch (storage) {
        .ip4 => |*sa| @ptrCast(sa),
        .ip6 => |*sa| @ptrCast(sa),
    };
    const addr_len: std.posix.socklen_t = switch (storage) {
        .ip4 => @intCast(@sizeOf(SockAddrIn)),
        .ip6 => @intCast(@sizeOf(SockAddrIn6)),
    };
    if (std.posix.system.bind(fd, sockaddr_ptr, addr_len) != 0) return error.BindFailed;
    if (std.posix.system.listen(fd, backlog) != 0) return error.ListenFailed;

    return fd;
}

pub fn accept(listener_fd: std.posix.fd_t) AcceptError!std.posix.fd_t {
    if (!isSupportedPlatform()) return error.AcceptFailed;
    const fd = std.posix.system.accept(listener_fd, null, null);
    if (fd < 0) {
        switch (std.posix.errno(fd)) {
            .AGAIN => return error.WouldBlock,
            else => return error.AcceptFailed,
        }
    }
    errdefer std.posix.close(fd);
    setNonBlocking(fd) catch return error.NonBlockingFailed;
    return fd;
}

fn buildSockaddr(address: std.Io.net.IpAddress) SockAddrStorage {
    return switch (address) {
        .ip4 => |ip4| .{ .ip4 = buildSockaddr4(ip4) },
        .ip6 => |ip6| .{ .ip6 = buildSockaddr6(ip6) },
    };
}

fn buildSockaddr4(ip4: std.Io.net.Ip4Address) SockAddrIn {
    const addr_be: u32 = @bitCast(ip4.bytes);
    if (has_len_field) {
        return .{
            .len = @intCast(@sizeOf(SockAddrIn)),
            .family = @intCast(std.posix.AF.INET),
            .port = std.mem.nativeToBig(u16, ip4.port),
            .addr = addr_be,
            .zero = .{0} ** 8,
        };
    }
    return .{
        .family = @intCast(std.posix.AF.INET),
        .port = std.mem.nativeToBig(u16, ip4.port),
        .addr = addr_be,
        .zero = .{0} ** 8,
    };
}

fn buildSockaddr6(ip6: std.Io.net.Ip6Address) SockAddrIn6 {
    if (has_len_field) {
        return .{
            .len = @intCast(@sizeOf(SockAddrIn6)),
            .family = @intCast(std.posix.AF.INET6),
            .port = std.mem.nativeToBig(u16, ip6.port),
            .flowinfo = std.mem.nativeToBig(u32, ip6.flow),
            .addr = ip6.bytes,
            .scope_id = @intCast(ip6.interface.index),
        };
    }
    return .{
        .family = @intCast(std.posix.AF.INET6),
        .port = std.mem.nativeToBig(u16, ip6.port),
        .flowinfo = std.mem.nativeToBig(u32, ip6.flow),
        .addr = ip6.bytes,
        .scope_id = @intCast(ip6.interface.index),
    };
}

fn setReuseAddr(fd: std.posix.fd_t) ListenError!void {
    const opt: c_int = 1;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&opt)) catch {
        return error.SetSockOptFailed;
    };
}

fn setReusePort(fd: std.posix.fd_t) ListenError!void {
    if (@hasDecl(std.posix.SO, "REUSEPORT")) {
        const opt: c_int = 1;
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&opt)) catch {};
    }
}

fn setNonBlocking(fd: std.posix.fd_t) NonBlockingError!void {
    var flags = std.posix.fcntl(fd, std.posix.F.GETFL, 0) catch return error.NonBlockingFailed;
    flags |= 1 << @bitOffsetOf(std.posix.O, "NONBLOCK");
    _ = std.posix.fcntl(fd, std.posix.F.SETFL, flags) catch return error.NonBlockingFailed;
}

fn isSupportedPlatform() bool {
    return switch (builtin.os.tag) {
        .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
        else => false,
    };
}

fn parseAddress(address: []const u8, port: u16) ListenError!std.Io.net.IpAddress {
    if (address.len == 0) return std.Io.net.IpAddress.parse("0.0.0.0", port) catch error.UnsupportedAddress;
    return std.Io.net.IpAddress.parse(address, port) catch error.UnsupportedAddress;
}

const SockAddrStorage = union(enum) {
    ip4: SockAddrIn,
    ip6: SockAddrIn6,
};
