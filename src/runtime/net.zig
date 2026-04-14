const std = @import("std");
const builtin = @import("builtin");
const clock = @import("clock.zig");

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
};

pub const AcceptError = error{
    AcceptFailed,
    WouldBlock,
    NonBlockingFailed,
};

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
};

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

const NonBlockingError = error{NonBlockingFailed};

pub fn listen(address: []const u8, port: u16, backlog: u32) ListenError!std.posix.fd_t {
    if (!isSupportedPlatform()) return error.UnsupportedPlatform;

    const addr = try parseAddress(address, port);
    const domain: c_uint = switch (addr) {
        .ip4 => @intCast(std.posix.AF.INET),
        .ip6 => @intCast(std.posix.AF.INET6),
    };
    const fd = std.posix.system.socket(domain, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (fd < 0) return error.SocketFailed;
    errdefer clock.closeFd(fd);

    try setReuseAddr(fd);
    try setReusePort(fd);
    try setNonBlocking(fd);
    // Set TCP_NODELAY on the listener so accepted sockets inherit it
    // (Linux-specific behavior). Lets us skip a per-accept setsockopt
    // on the connection-churn hot path — previously ~7% of server
    // syscall time under mixed keepalive+close workloads.
    setNoDelay(fd);

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
            .AGAIN, .INTR => return error.WouldBlock,
            .CONNABORTED => return error.WouldBlock, // Connection aborted before accept
            else => {
                std.log.debug("accept errno: {}", .{errno});
                return error.AcceptFailed;
            },
        }
    }
    errdefer clock.closeFd(fd);
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
    errdefer clock.closeFd(fd);

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
            .AGAIN, .INTR => return error.WouldBlock,
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
            .AGAIN, .INTR => return error.WouldBlock,
            else => return error.SendFailed,
        }
    }

    return @intCast(rc);
}

/// Linux UDP GSO (Generic Segmentation Offload) via UDP_SEGMENT.
///
/// Sends a large buffer as multiple same-segment-sized UDP datagrams
/// in a single `sendmsg()` syscall. The kernel splits the buffer into
/// `segment_size`-byte datagrams; the last datagram may be shorter.
///
/// On platforms without UDP GSO (macOS, older Linux), falls back to
/// sending one datagram of the full buffer. The caller is responsible
/// for ensuring the buffer is correctly structured for either path.
///
/// Returns the number of bytes accepted by the kernel (which may be
/// less than `buf.len` under backpressure).
pub fn sendGso(
    fd: std.posix.fd_t,
    buf: []const u8,
    peer: SockAddrStorage,
    segment_size: u16,
) UdpError!usize {
    if (!isSupportedPlatform()) return error.SendFailed;

    const sockaddr_ptr: *const std.posix.sockaddr = switch (peer) {
        .ip4 => |*sa| @ptrCast(sa),
        .ip6 => |*sa| @ptrCast(sa),
    };
    const addr_len: std.posix.socklen_t = switch (peer) {
        .ip4 => @intCast(@sizeOf(SockAddrIn)),
        .ip6 => @intCast(@sizeOf(SockAddrIn6)),
    };

    // On Linux, use sendmsg + cmsg(SOL_UDP, UDP_SEGMENT) for GSO.
    if (comptime builtin.os.tag == .linux) {
        return sendGsoLinux(fd, buf, sockaddr_ptr, addr_len, segment_size);
    }

    // Fallback: send as a single datagram (no segmentation).
    // The caller should only pass a single packet's worth of data on
    // non-GSO platforms, or loop externally.
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
            .AGAIN, .INTR => return error.WouldBlock,
            else => return error.SendFailed,
        }
    }
    return @intCast(rc);
}

/// Linux-specific GSO sendmsg implementation.
fn sendGsoLinux(
    fd: std.posix.fd_t,
    buf: []const u8,
    sockaddr_ptr: *const std.posix.sockaddr,
    addr_len: std.posix.socklen_t,
    segment_size: u16,
) UdpError!usize {
    if (comptime builtin.os.tag != .linux) return error.SendFailed;

    const SOL_UDP = 17;
    const UDP_SEGMENT = 103;

    var iov = [_]std.posix.iovec_const{.{
        .base = buf.ptr,
        .len = buf.len,
    }};

    // Build cmsg manually for portability across Zig stdlib versions.
    // cmsghdr on Linux: { usize len, c_int level, c_int type } then
    // the payload (u16 segment_size), padded to usize alignment.
    // Use a generous 32-byte buffer which covers every 64-bit alignment.
    var cmsg_buf: [32]u8 align(8) = [_]u8{0} ** 32;
    var cmsg_off: usize = 0;

    // cmsg_len (usize): header size + payload size (no alignment tail)
    const hdr_size = @sizeOf(usize) + @sizeOf(c_int) + @sizeOf(c_int);
    const cmsg_len: usize = hdr_size + @sizeOf(u16);
    @memcpy(cmsg_buf[cmsg_off..][0..@sizeOf(usize)], std.mem.asBytes(&cmsg_len));
    cmsg_off += @sizeOf(usize);

    // cmsg_level (c_int): SOL_UDP
    const level: c_int = SOL_UDP;
    @memcpy(cmsg_buf[cmsg_off..][0..@sizeOf(c_int)], std.mem.asBytes(&level));
    cmsg_off += @sizeOf(c_int);

    // cmsg_type (c_int): UDP_SEGMENT
    const cmsg_type: c_int = UDP_SEGMENT;
    @memcpy(cmsg_buf[cmsg_off..][0..@sizeOf(c_int)], std.mem.asBytes(&cmsg_type));
    cmsg_off += @sizeOf(c_int);

    // payload (u16): segment size
    @memcpy(cmsg_buf[cmsg_off..][0..@sizeOf(u16)], std.mem.asBytes(&segment_size));
    cmsg_off += @sizeOf(u16);

    // Round up to usize alignment for controllen. Linux's msghdr.controllen
    // is u32; macOS uses socklen_t (also u32 in practice). Cast at the
    // boundary so the arithmetic above can stay in usize.
    const controllen_usize: usize = (cmsg_off + @alignOf(usize) - 1) & ~(@as(usize, @alignOf(usize)) - 1);
    const controllen: u32 = @intCast(controllen_usize);

    const msg = std.posix.msghdr_const{
        .name = sockaddr_ptr,
        .namelen = addr_len,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = controllen,
        .flags = 0,
    };

    const rc = std.posix.system.sendmsg(fd, &msg, 0);
    if (rc < 0) {
        const e = std.posix.errno(rc);
        switch (e) {
            .AGAIN, .INTR => return error.WouldBlock,
            // EIO / EINVAL can mean the kernel doesn't support GSO on
            // this socket. Caller should fall back to individual sends.
            .IO, .INVAL => return error.SendFailed,
            else => return error.SendFailed,
        }
    }
    return @intCast(rc);
}

/// CMSG_ALIGN: round up to the alignment of usize (usually 8 on 64-bit).
fn cmsgAlign(len: usize) usize {
    const mask: usize = @alignOf(usize) - 1;
    return (len + mask) & ~mask;
}

/// Check at runtime whether the current platform supports UDP GSO.
/// On macOS this is always false; on Linux it's true if the kernel
/// accepts the UDP_SEGMENT socket option.
pub fn supportsGso() bool {
    if (comptime builtin.os.tag != .linux) return false;
    // Quick probe: try setting UDP_SEGMENT on a throwaway socket.
    const SOL_UDP = 17;
    const UDP_SEGMENT = 103;
    const fd = std.posix.system.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    if (fd < 0) return false;
    defer clock.closeFd(fd);
    var val: u16 = 1280;
    const rc = std.posix.system.setsockopt(
        fd,
        SOL_UDP,
        UDP_SEGMENT,
        @ptrCast(&val),
        @sizeOf(u16),
    );
    return rc == 0;
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
    const flags = std.c.fcntl(fd, std.posix.F.GETFL);
    if (flags < 0) return error.NonBlockingFailed;
    const nonblock: c_int = @bitCast(@as(c_uint, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK"));
    if (std.c.fcntl(fd, std.posix.F.SETFL, flags | nonblock) < 0)
        return error.NonBlockingFailed;
}

/// Set `TCP_NODELAY` on a TCP socket. Applied to the listener so newly
/// accepted sockets inherit it on Linux — saves one setsockopt syscall
/// per accept on the connection-churn hot path. H2 still benefits
/// (avoids 40 ms delayed-ACK on multi-frame writes) because HEADERS +
/// DATA go out without Nagle batching. Failure is swallowed: TCP_NODELAY
/// is an optimization, not a correctness requirement.
fn setNoDelay(fd: std.posix.fd_t) void {
    const opt: c_int = 1;
    std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&opt)) catch {};
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
// DNS resolution via getaddrinfo
// ============================================================

const has_bsd_addrinfo = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

// BSD and Linux have different field ordering for struct addrinfo
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

const ResolvedAddr = struct {
    storage: SockAddrStorage,
    len: std.posix.socklen_t,
};

fn resolveAddress(address: []const u8, port: u16) ConnectError!ResolvedAddr {
    // Fast path: try IP literal parse
    if (std.Io.net.IpAddress.parse(address, port)) |ip_addr| {
        const storage = buildSockaddr(ip_addr);
        const len: std.posix.socklen_t = switch (storage) {
            .ip4 => @intCast(@sizeOf(SockAddrIn)),
            .ip6 => @intCast(@sizeOf(SockAddrIn6)),
        };
        return .{ .storage = storage, .len = len };
    } else |_| {}

    // Slow path: DNS resolution via getaddrinfo
    var buf: [256]u8 = undefined;
    if (address.len >= buf.len) return error.UnsupportedAddress;
    @memcpy(buf[0..address.len], address);
    buf[address.len] = 0;

    var hints: addrinfo = std.mem.zeroes(addrinfo);
    hints.family = @intCast(std.posix.AF.INET);
    hints.socktype = @intCast(std.posix.SOCK.STREAM);

    var result: ?*addrinfo = null;
    const rc = getaddrinfo(@ptrCast(buf[0..address.len :0]), null, &hints, &result);
    if (rc != 0 or result == null) return error.UnsupportedAddress;
    defer freeaddrinfo(result.?);

    const info = result.?;
    const sa = info.addr orelse return error.UnsupportedAddress;

    // Copy sockaddr into our SockAddrIn and set the requested port
    const sa_bytes: [*]const u8 = @ptrCast(sa);
    var sa4: SockAddrIn = undefined;
    @memcpy(std.mem.asBytes(&sa4), sa_bytes[0..@sizeOf(SockAddrIn)]);
    sa4.port = std.mem.nativeToBig(u16, port);

    return .{
        .storage = .{ .ip4 = sa4 },
        .len = @intCast(@sizeOf(SockAddrIn)),
    };
}

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
        .AGAIN, .INTR => {
            // Partial write or interrupted - len contains bytes sent before blocking
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
        .AGAIN, .INTR => return .{ .bytes_sent = 0, .done = false },
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

// ============================================================
// Blocking TCP connect for proxy upstream connections
// ============================================================

pub const ConnectError = error{
    UnsupportedPlatform,
    UnsupportedAddress,
    SocketFailed,
    ConnectFailed,
    Timeout,
};

/// Connect to a TCP server with a timeout (blocking).
/// Returns a connected, blocking socket fd.
pub fn connectBlocking(address: []const u8, port: u16, timeout_ms: u32) ConnectError!std.posix.fd_t {
    if (!isSupportedPlatform()) return error.UnsupportedPlatform;

    const resolved = resolveAddress(address, port) catch return error.UnsupportedAddress;
    const domain: c_uint = switch (resolved.storage) {
        .ip4 => @intCast(std.posix.AF.INET),
        .ip6 => @intCast(std.posix.AF.INET6),
    };
    const fd = std.posix.system.socket(domain, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (fd < 0) return error.SocketFailed;
    errdefer clock.closeFd(fd);

    // Set non-blocking for connect with timeout
    setNonBlocking(fd) catch return error.SocketFailed;

    var storage = resolved.storage;
    const sockaddr_ptr: *const std.posix.sockaddr = switch (storage) {
        .ip4 => |*sa| @ptrCast(sa),
        .ip6 => |*sa| @ptrCast(sa),
    };
    const addr_len = resolved.len;

    const rc = std.posix.system.connect(fd, sockaddr_ptr, addr_len);
    if (rc == 0) {
        // Connected immediately — switch back to blocking
        clearNonBlocking(fd) catch return error.SocketFailed;
        return fd;
    }

    const errno = std.posix.errno(rc);
    if (errno != .INPROGRESS) return error.ConnectFailed;

    // Wait for connect to complete using poll
    if (!pollWriteReady(fd, timeout_ms)) return error.Timeout;

    // Check connect result via SO_ERROR
    var err_val: c_int = 0;
    var err_len: std.posix.socklen_t = @sizeOf(c_int);
    const gso_rc = std.posix.system.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&err_val), &err_len);
    if (gso_rc != 0 or err_val != 0) return error.ConnectFailed;

    // Switch back to blocking for simple send/recv
    clearNonBlocking(fd) catch return error.SocketFailed;
    return fd;
}

/// Set send/recv timeouts on a blocking socket.
pub fn setSocketTimeouts(fd: std.posix.fd_t, send_ms: u32, recv_ms: u32) void {
    const send_tv = msToTimeval(send_ms);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv)) catch |err| {
        std.log.warn("setsockopt SO_SNDTIMEO failed: {}", .{err});
    };

    const recv_tv = msToTimeval(recv_ms);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv)) catch |err| {
        std.log.warn("setsockopt SO_RCVTIMEO failed: {}", .{err});
    };
}

fn msToTimeval(ms: u32) std.posix.timeval {
    return .{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
}

fn clearNonBlocking(fd: std.posix.fd_t) NonBlockingError!void {
    const flags = std.c.fcntl(fd, std.posix.F.GETFL);
    if (flags < 0) return error.NonBlockingFailed;
    const nonblock: c_int = @bitCast(@as(c_uint, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK"));
    if (std.c.fcntl(fd, std.posix.F.SETFL, flags & ~nonblock) < 0)
        return error.NonBlockingFailed;
}

fn pollWriteReady(fd: std.posix.fd_t, timeout_ms: u32) bool {
    var pfd = [1]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const rc = std.posix.system.poll(&pfd, 1, @intCast(timeout_ms));
    if (rc <= 0) return false;
    return (pfd[0].revents & std.posix.POLL.OUT) != 0;
}

/// Send all bytes to a socket (blocking, handles partial writes and EINTR).
pub fn sendAll(fd: std.posix.fd_t, data: []const u8) error{SendFailed}!void {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = std.posix.system.write(fd, data[sent..].ptr, data[sent..].len);
        if (rc < 0) {
            // Retry on EINTR (interrupted by signal handler)
            if (std.posix.errno(rc) == .INTR) continue;
            return error.SendFailed;
        }
        if (rc == 0) return error.SendFailed;
        sent += @intCast(rc);
    }
}

/// Receive up to buf.len bytes from a socket (blocking, handles EINTR).
/// Returns 0 on EOF.
pub fn recvBlocking(fd: std.posix.fd_t, buf: []u8) error{RecvFailed}!usize {
    while (true) {
        const rc = std.posix.system.read(fd, buf.ptr, buf.len);
        if (rc < 0) {
            // Retry on EINTR (interrupted by signal handler)
            if (std.posix.errno(rc) == .INTR) continue;
            return error.RecvFailed;
        }
        return @intCast(rc);
    }
}
