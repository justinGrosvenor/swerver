const std = @import("std");
const builtin = @import("builtin");

const has_len_field = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

pub const SockAddrIn = if (has_len_field)
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

pub const SockAddrIn6 = if (has_len_field)
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

pub const UdpError = error{
    UnsupportedPlatform,
    UnsupportedAddress,
    SocketFailed,
    BindFailed,
    SetSockOptFailed,
    NonBlockingFailed,
    RecvFailed,
    SendFailed,
    WouldBlock,
} || std.posix.FcntlError;

pub const RecvFromResult = struct {
    bytes_read: usize,
    peer_addr: SockAddrStorage,
};

pub const PeerAddress = struct {
    storage: SockAddrStorage,

    pub fn getPort(self: PeerAddress) u16 {
        return switch (self.storage) {
            .ip4 => |sa| std.mem.bigToNative(u16, sa.port),
            .ip6 => |sa| std.mem.bigToNative(u16, sa.port),
        };
    }

    pub fn getIp4Bytes(self: PeerAddress) ?[4]u8 {
        return switch (self.storage) {
            .ip4 => |sa| @bitCast(sa.addr),
            .ip6 => null,
        };
    }

    pub fn getIp6Bytes(self: PeerAddress) ?[16]u8 {
        return switch (self.storage) {
            .ip4 => null,
            .ip6 => |sa| sa.addr,
        };
    }
};

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
        const errno = std.posix.errno(fd);
        switch (errno) {
            .AGAIN => return error.WouldBlock,
            .CONNABORTED => return error.WouldBlock, // Connection aborted before accept
            else => {
                std.log.debug("accept errno: {}", .{errno});
                return error.AcceptFailed;
            },
        }
    }
    errdefer std.posix.close(fd);
    setNonBlocking(fd) catch return error.NonBlockingFailed;
    return fd;
}

/// Bind a UDP socket to the given address and port.
/// Unlike TCP listen(), this only binds and does not call listen().
pub fn bindUdp(address: []const u8, port: u16) UdpError!std.posix.fd_t {
    if (!isSupportedPlatform()) return error.UnsupportedPlatform;

    const addr = parseAddress(address, port) catch return error.UnsupportedAddress;
    const domain: c_uint = switch (addr) {
        .ip4 => @intCast(std.posix.AF.INET),
        .ip6 => @intCast(std.posix.AF.INET6),
    };
    const fd = std.posix.system.socket(domain, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    if (fd < 0) return error.SocketFailed;
    errdefer std.posix.close(fd);

    setReuseAddr(fd) catch return error.SetSockOptFailed;
    setReusePort(fd) catch return error.SetSockOptFailed;
    setNonBlocking(fd) catch return error.NonBlockingFailed;

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

    return fd;
}

/// Receive a UDP datagram from the socket.
/// Returns the number of bytes read and the peer address.
pub fn recvfrom(fd: std.posix.fd_t, buf: []u8) UdpError!RecvFromResult {
    if (!isSupportedPlatform()) return error.RecvFailed;

    var peer_storage: SockAddrStorage = .{ .ip6 = undefined };
    var addr_len: std.posix.socklen_t = @sizeOf(SockAddrIn6);

    const sockaddr_ptr: *std.posix.sockaddr = @ptrCast(&peer_storage.ip6);
    const rc = std.posix.system.recvfrom(
        fd,
        buf.ptr,
        buf.len,
        0,
        sockaddr_ptr,
        &addr_len,
    );

    if (rc < 0) {
        switch (std.posix.errno(rc)) {
            .AGAIN => return error.WouldBlock,
            else => return error.RecvFailed,
        }
    }

    // Determine if it's IPv4 or IPv6 based on family
    if (addr_len == @sizeOf(SockAddrIn)) {
        const ip4_ptr: *SockAddrIn = @ptrCast(&peer_storage.ip6);
        peer_storage = .{ .ip4 = ip4_ptr.* };
    }

    return .{
        .bytes_read = @intCast(rc),
        .peer_addr = peer_storage,
    };
}

/// Send a UDP datagram to the specified peer address.
pub fn sendto(fd: std.posix.fd_t, buf: []const u8, peer: SockAddrStorage) UdpError!usize {
    if (!isSupportedPlatform()) return error.SendFailed;

    const sockaddr_ptr: *const std.posix.sockaddr = switch (peer) {
        .ip4 => |*sa| @ptrCast(sa),
        .ip6 => |*sa| @ptrCast(sa),
    };
    const addr_len: std.posix.socklen_t = switch (peer) {
        .ip4 => @intCast(@sizeOf(SockAddrIn)),
        .ip6 => @intCast(@sizeOf(SockAddrIn6)),
    };

    const rc = std.posix.system.sendto(
        fd,
        buf.ptr,
        buf.len,
        0,
        sockaddr_ptr,
        addr_len,
    );

    if (rc < 0) {
        switch (std.posix.errno(rc)) {
            .AGAIN => return error.WouldBlock,
            else => return error.SendFailed,
        }
    }

    return @intCast(rc);
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

/// Extract the peer IP address from a connected socket via getpeername.
pub fn getPeerAddress(fd: std.posix.fd_t) ?PeerAddress {
    var storage: SockAddrIn6 = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(SockAddrIn6);
    const sockaddr_ptr: *std.posix.sockaddr = @ptrCast(&storage);
    const rc = std.posix.system.getpeername(fd, sockaddr_ptr, &addr_len);
    if (rc != 0) return null;
    if (addr_len == @sizeOf(SockAddrIn)) {
        const ip4_ptr: *SockAddrIn = @ptrCast(&storage);
        return .{ .storage = .{ .ip4 = ip4_ptr.* } };
    }
    return .{ .storage = .{ .ip6 = storage } };
}

fn isSupportedPlatform() bool {
    return switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
        else => false,
    };
}

fn parseAddress(address: []const u8, port: u16) ListenError!std.Io.net.IpAddress {
    if (address.len == 0) return std.Io.net.IpAddress.parse("0.0.0.0", port) catch error.UnsupportedAddress;
    return std.Io.net.IpAddress.parse(address, port) catch error.UnsupportedAddress;
}

pub const SockAddrStorage = union(enum) {
    ip4: SockAddrIn,
    ip6: SockAddrIn6,
};

// ============================================================
// sendfile() - Zero-copy file transfer to socket
// ============================================================

pub const SendfileError = error{
    WouldBlock,
    Closed,
    Failed,
};

pub const SendfileResult = struct {
    bytes_sent: usize,
    done: bool,
};

/// Send file data directly to socket using zero-copy transfer.
/// Returns number of bytes sent and whether EOF was reached.
/// On WouldBlock, returns 0 bytes sent - caller should retry on write event.
pub fn sendfile(socket_fd: std.posix.fd_t, file_fd: std.posix.fd_t, offset: *u64, count: usize) SendfileError!SendfileResult {
    if (!isSupportedPlatform()) return error.Failed;

    switch (builtin.os.tag) {
        .macos, .freebsd, .dragonfly => {
            return sendfileBsd(socket_fd, file_fd, offset, count);
        },
        .linux => {
            return sendfileLinux(socket_fd, file_fd, offset, count);
        },
        else => return error.Failed,
    }
}

fn sendfileBsd(socket_fd: std.posix.fd_t, file_fd: std.posix.fd_t, offset: *u64, count: usize) SendfileError!SendfileResult {
    // BSD sendfile: sendfile(fd, s, offset, len, hdtr, flags)
    // fd = file, s = socket, offset = start position, len = in/out bytes
    var len: i64 = @intCast(count);
    const file_offset: i64 = @intCast(offset.*);

    const rc = darwin_sendfile(file_fd, socket_fd, file_offset, &len, null, 0);

    if (rc == 0) {
        // Success - len contains bytes sent
        const sent: usize = @intCast(len);
        offset.* += sent;
        return .{ .bytes_sent = sent, .done = sent < count };
    }

    const errno = std.posix.errno(rc);
    switch (errno) {
        .AGAIN => {
            // Partial write - len contains bytes sent before blocking
            const sent: usize = if (len > 0) @intCast(len) else 0;
            offset.* += sent;
            return .{ .bytes_sent = sent, .done = false };
        },
        .PIPE, .NOTCONN => return error.Closed,
        else => return error.Failed,
    }
}

fn sendfileLinux(socket_fd: std.posix.fd_t, file_fd: std.posix.fd_t, offset: *u64, count: usize) SendfileError!SendfileResult {
    // Linux sendfile: sendfile(out_fd, in_fd, offset, count)
    var file_offset: i64 = @intCast(offset.*);
    const rc = linux_sendfile(socket_fd, file_fd, &file_offset, count);

    if (rc >= 0) {
        const sent: usize = @intCast(rc);
        offset.* = @intCast(file_offset);
        return .{ .bytes_sent = sent, .done = sent == 0 };
    }

    const errno = std.posix.errno(rc);
    switch (errno) {
        .AGAIN => return .{ .bytes_sent = 0, .done = false },
        .PIPE, .NOTCONN => return error.Closed,
        else => return error.Failed,
    }
}

// Platform-specific sendfile declarations
const darwin_sendfile = if (builtin.os.tag == .macos or builtin.os.tag == .freebsd or builtin.os.tag == .dragonfly)
    struct {
        extern "c" fn sendfile(
            fd: std.posix.fd_t,
            s: std.posix.fd_t,
            offset: i64,
            len: *i64,
            hdtr: ?*anyopaque,
            flags: c_int,
        ) c_int;
    }.sendfile
else
    undefined;

const linux_sendfile = if (builtin.os.tag == .linux)
    struct {
        extern "c" fn sendfile(
            out_fd: std.posix.fd_t,
            in_fd: std.posix.fd_t,
            offset: ?*i64,
            count: usize,
        ) isize;
    }.sendfile
else
    undefined;
