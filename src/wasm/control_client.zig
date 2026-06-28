//! Nether control-socket client: the real Tier-1 -> Tier-2 transport for WASM
//! filter host calls (design 10.0, C3). Replaces the C2 mock completion source.
//!
//! A wasm filter stages a host_call and parks; this client writes the staged
//! command line to a Nether sandbox's Unix-domain control socket
//! (~/nether/docs/control-protocol.md, proto_version=1), reads the streamed reply
//! up to the agent's 0x1e<exit>\n trailer, and completes the park with the reply
//! body. The socket fd is registered as ONE external fd on the reactor (the PG
//! client is the template): connect + handshake driven from tick(), readable /
//! writable from onEvent(); failures and timeouts are staged and never resume a
//! continuation beneath a live handler stack frame.
//!
//! Serialized: one sandbox, one in-flight call. Extra parks queue (FIFO) and
//! issue as the socket frees. Concurrency scales by holding more sandbox sockets,
//! not by multiplexing one. Compiled only when build_options.enable_wasm is set.

const std = @import("std");
const builtin = @import("builtin");
const io_mod = @import("../runtime/io.zig");
const net = @import("../runtime/net.zig");
const clock = @import("../runtime/clock.zig");
const host_call = @import("host_call.zig");

pub const Token = host_call.Token;

/// External-fd slot for the control socket. The PG client owns 0..MAX_SLOTS-1
/// (4); the control socket takes the next slot. Kept distinct so dispatch.zig
/// can route external-fd events to the right owner by slot range.
pub const DEFAULT_SLOT: u32 = 4;

/// The agent reply trailer separator (0x1e, ASCII RS), per control-protocol.md.
/// Reports and shell commands end with 0x1e<exit-code>\n.
const RS: u8 = 0x1e;

/// Buffers. Replies are bounded; an overflow before the trailer fails the call.
const RECV_CAP = 64 * 1024;
const CMD_CAP = 4 * 1024; // a queued command line (control commands are short)
const QUEUE_CAP = host_call.Table.CAP; // at most one queued per parked filter

const CONNECT_TIMEOUT_MS: u64 = 5_000;
const HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
/// Per-command wall-clock budget. On expiry the socket is dropped and rebuilt
/// (a streamed command cannot be cancelled in place; reconnect frees the lane).
const COMMAND_TIMEOUT_MS: u64 = 30_000;
const BACKOFF_START_MS: u64 = 250;
const BACKOFF_MAX_MS: u64 = 5_000;

/// sockaddr_un differs by OS: BSD/macOS leads with a 1-byte sun_len then a u8
/// family; Linux has a u16 sun_family and no length byte. Selected at comptime.
const SockaddrUn = if (builtin.os.tag == .macos)
    extern struct { len: u8 = 0, family: u8 = AF_UNIX, path: [104]u8 = [_]u8{0} ** 104 }
else
    extern struct { family: u16 = AF_UNIX, path: [108]u8 = [_]u8{0} ** 108 };

const AF_UNIX: c_int = 1; // same value on macOS and Linux

/// Resume the park whose host call completed with `result`. Installed by the
/// server (-> dispatch.wasmComplete). Opaque ctx keeps this file free of
/// server/router imports, mirroring PgClient.ResumeFn.
pub const CompleteFn = *const fn (ctx: *anyopaque, token: Token, result: []const u8) void;
/// Fail the park closed (host-call transport failure). Installed by the server
/// (-> dispatch.wasmFail). A no-op against the table if the token already timed
/// out, so a late/duplicate failure is harmless.
pub const FailFn = *const fn (ctx: *anyopaque, token: Token) void;

pub const State = enum {
    /// No socket; tick() will (re)connect when retry_at_ms passes.
    closed,
    /// Non-blocking connect() in flight; finishes on the first read/write event.
    connecting,
    /// __info__ sent; reading the report to verify proto_version.
    info_wait,
    /// Handshake done; idle or carrying one in-flight command.
    ready,
    /// Backend cannot host external fds; the client stays dark.
    disabled,
};

const Pending = struct {
    token: Token = 0,
    buf: [CMD_CAP]u8 = undefined,
    len: usize = 0,
};

pub const ControlClient = struct {
    /// Borrowed control-socket path; must outlive the client.
    path: []const u8,
    slot: u32 = DEFAULT_SLOT,
    fd: std.posix.fd_t = -1,
    state: State = .closed,

    // Reactor resume linkage (installed by the server).
    resume_ctx: ?*anyopaque = null,
    complete_fn: ?CompleteFn = null,
    fail_fn: ?FailFn = null,

    // Receive accumulator for the current reply (info report or command output).
    recv_buf: [RECV_CAP]u8 = undefined,
    recv_len: usize = 0,

    // Current outbound command (partial-write safe).
    send_buf: [CMD_CAP]u8 = undefined,
    send_len: usize = 0,
    send_off: usize = 0,

    // FIFO of parked tokens awaiting the socket.
    queue: [QUEUE_CAP]Pending = undefined,
    q_head: usize = 0,
    q_count: usize = 0,

    // Token whose reply we are currently reading (null = idle / handshaking).
    inflight: ?Token = null,
    command_deadline_ms: u64 = 0,

    // Connect/handshake deadline and reconnect backoff.
    deadline_ms: u64 = 0,
    retry_at_ms: u64 = 0,
    backoff_ms: u64 = BACKOFF_START_MS,

    pub fn init(path: []const u8, slot: u32) ControlClient {
        return .{ .path = path, .slot = slot };
    }

    /// Install the resume hooks (server init, before the loop runs). Mirrors
    /// PgClient.installResume.
    pub fn installResume(self: *ControlClient, ctx: *anyopaque, complete_fn: CompleteFn, fail_fn: FailFn) void {
        self.resume_ctx = ctx;
        self.complete_fn = complete_fn;
        self.fail_fn = fail_fn;
    }

    pub fn deinit(self: *ControlClient, io_rt: *io_mod.IoRuntime) void {
        self.failAll();
        if (self.fd >= 0) {
            io_rt.unregisterExternalFd(self.fd) catch {};
            clock.closeFd(self.fd);
            self.fd = -1;
        }
        self.state = .closed;
    }

    /// Stage a host call for `token`: send the staged command line now if the
    /// socket is idle and ready, else queue it. `cmd` is the filter's staged
    /// outbound bytes (valid while parked); copied if queued. The trailing
    /// newline that the line protocol requires is appended here.
    pub fn startCall(self: *ControlClient, io_rt: *io_mod.IoRuntime, token: Token, cmd: []const u8) void {
        // Security choke (D2-1): a Tier-1 wasm filter must not drive the Tier-2
        // control plane. `cmd` is filter-supplied and written verbatim to the
        // Nether control socket, where swerver is the PRIMARY (driving) client.
        // Nether reserves the `__verb__` namespace for control verbs
        // (__shutdown__, __put__/__get__ against the HOST fs, __stats__, ...), so
        // any payload whose first line begins with "__" is neutralized: fail the
        // call closed and never let the bytes reach the socket. Normal shell
        // commands and the `E2E ...` command are untouched; the handshake
        // __info__ is sent internally by sendInfo, not via startCall.
        if (std.mem.startsWith(u8, cmd, "__")) {
            std.log.warn("wasm control ({s}): blocked reserved control verb from filter host_call (payload begins with \"__\"); failing closed", .{self.path});
            self.failOne(token);
            return;
        }
        if (self.state == .disabled) {
            self.failOne(token);
            return;
        }
        if (cmd.len + 1 > CMD_CAP) {
            // Command longer than a control line should ever be: fail closed.
            self.failOne(token);
            return;
        }
        if (self.state == .ready and self.inflight == null and self.send_len == 0) {
            self.issue(io_rt, token, cmd);
            return;
        }
        // Busy or not yet connected: queue (copying cmd to decouple lifetime).
        if (self.q_count >= QUEUE_CAP) {
            self.failOne(token);
            return;
        }
        const slot = &self.queue[(self.q_head + self.q_count) % QUEUE_CAP];
        slot.token = token;
        @memcpy(slot.buf[0..cmd.len], cmd);
        slot.len = cmd.len;
        self.q_count += 1;
    }

    /// Single entry point from the dispatch loop for events tagged with this
    /// client's external-fd slot. Mirrors PgClient.onEvent.
    pub fn onEvent(self: *ControlClient, io_rt: *io_mod.IoRuntime, kind: io_mod.EventKind) void {
        if (self.fd < 0) return; // stale event after a close
        const now_ms = io_rt.nowMs();
        switch (kind) {
            .err => self.fail(io_rt, now_ms, "socket error event"),
            .write => switch (self.state) {
                .connecting => self.finishConnect(io_rt, now_ms),
                .info_wait, .ready => _ = self.flushSend(io_rt, now_ms),
                else => {},
            },
            .read => switch (self.state) {
                // Readability can race ahead of the writable connect arm.
                .connecting => {
                    self.finishConnect(io_rt, now_ms);
                    if (self.state == .info_wait) self.handleReadable(io_rt, now_ms);
                },
                .info_wait, .ready => self.handleReadable(io_rt, now_ms),
                else => {},
            },
            .accept, .datagram => {},
        }
    }

    /// Housekeeping: (re)connect, enforce the connect/handshake deadline and the
    /// per-command timeout. Called from the dispatch loop's housekeeping block.
    pub fn tick(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        switch (self.state) {
            .disabled => {},
            .closed => if (now_ms >= self.retry_at_ms) self.startConnect(io_rt, now_ms),
            .connecting, .info_wait => if (now_ms >= self.deadline_ms) {
                self.fail(io_rt, now_ms, "connect/handshake timeout");
            },
            .ready => if (self.inflight != null and now_ms >= self.command_deadline_ms) {
                // A streamed command cannot be cancelled in place; drop and
                // rebuild the socket so the lane is not wedged. The token's park
                // is failed here (no-op if the table already timed it out).
                self.fail(io_rt, now_ms, "command timeout");
            },
        }
    }

    /// True when the socket is up and handshaked.
    pub fn isReady(self: *const ControlClient) bool {
        return self.state == .ready;
    }

    // ------------------------------------------------------------------
    // Connection state machine
    // ------------------------------------------------------------------

    fn startConnect(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        const fd = std.posix.system.socket(AF_UNIX, std.posix.SOCK.STREAM, 0);
        if (fd < 0) return self.scheduleRetry(now_ms, "socket() failed");
        net.setNonBlocking(fd) catch {
            clock.closeFd(fd);
            return self.scheduleRetry(now_ms, "set O_NONBLOCK failed");
        };
        _ = std.c.fcntl(fd, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));

        var addr = SockaddrUn{};
        if (self.path.len >= addr.path.len) {
            clock.closeFd(fd);
            return self.scheduleRetry(now_ms, "control socket path too long");
        }
        @memcpy(addr.path[0..self.path.len], self.path);
        addr.path[self.path.len] = 0;
        const addr_len: std.posix.socklen_t = @intCast(@offsetOf(SockaddrUn, "path") + self.path.len + 1);
        const rc = std.posix.system.connect(fd, @ptrCast(&addr), addr_len);
        const immediate = rc == 0;
        if (!immediate) {
            const e = std.posix.errno(rc);
            if (e != .INPROGRESS and e != .AGAIN and e != .INTR) {
                clock.closeFd(fd);
                // The sandbox may not be up yet; retry on the backoff schedule.
                return self.scheduleRetry(now_ms, "connect() failed");
            }
        }
        self.fd = fd;
        self.deadline_ms = now_ms + CONNECT_TIMEOUT_MS;
        io_rt.registerExternalFd(self.slot, fd) catch |err| {
            clock.closeFd(fd);
            self.fd = -1;
            if (err == error.UnsupportedBackend) {
                self.state = .disabled;
                std.log.warn("wasm control: external-fd dispatch unsupported on this I/O backend (io_uring); transport disabled", .{});
                self.failAll();
                return;
            }
            return self.scheduleRetry(now_ms, "event-loop registration failed");
        };
        if (immediate) {
            self.sendInfo(io_rt, now_ms);
        } else {
            self.state = .connecting;
            io_rt.armExternalWritable(self.slot, fd) catch {};
        }
    }

    fn finishConnect(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        var err_val: c_int = 0;
        var err_len: std.posix.socklen_t = @sizeOf(c_int);
        const rc = std.posix.system.getsockopt(self.fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&err_val), &err_len);
        if (rc != 0 or err_val != 0) return self.fail(io_rt, now_ms, "connect failed (SO_ERROR)");
        self.sendInfo(io_rt, now_ms);
    }

    /// Connected: send __info__ and read the report to verify proto_version.
    fn sendInfo(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        self.state = .info_wait;
        self.recv_len = 0;
        self.deadline_ms = now_ms + HANDSHAKE_TIMEOUT_MS;
        const msg = "__info__\n";
        @memcpy(self.send_buf[0..msg.len], msg);
        self.send_len = msg.len;
        self.send_off = 0;
        _ = self.flushSend(io_rt, now_ms);
    }

    /// Readable in info_wait (parse the report) or ready (read command output).
    fn handleReadable(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        while (true) {
            if (self.recv_len >= self.recv_buf.len) {
                return self.fail(io_rt, now_ms, "reply exceeded buffer before trailer");
            }
            const rc = std.posix.system.read(self.fd, self.recv_buf[self.recv_len..].ptr, self.recv_buf.len - self.recv_len);
            if (rc < 0) {
                const e = std.posix.errno(rc);
                if (e == .AGAIN) break;
                if (e == .INTR) continue;
                return self.fail(io_rt, now_ms, "read error");
            }
            if (rc == 0) return self.fail(io_rt, now_ms, "control socket closed (EOF)");
            self.recv_len += @intCast(rc);
            if (self.tryConsumeReply(io_rt, now_ms)) {
                // A reply was consumed; loop to drain any pipelined bytes.
                if (self.state != .ready) return;
            }
        }
    }

    /// If recv_buf holds a complete framed reply (body 0x1e<exit>\n), consume it.
    /// Returns true if one was consumed. Handshake replies verify proto_version;
    /// command replies fire the completion. Leftover bytes are shifted to front.
    fn tryConsumeReply(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) bool {
        const buf = self.recv_buf[0..self.recv_len];
        const sep = std.mem.indexOfScalar(u8, buf, RS) orelse {
            // No frame separator yet. Framed replies (shell/guest commands,
            // __info__) end with 0x1e<exit>\n; an unframed `ERR <reason>\n` (a
            // control-layer rejection: bad command, observer gating, unknown
            // __verb__) carries no 0x1e and would otherwise hang until the
            // deadline. We only send framed-reply commands, so the only place a
            // bare ERR is realistically reachable is the handshake -- guard it
            // there (fail fast). In the command phase a leading "ERR" can be real
            // multi-line output whose 0x1e has not arrived, so we keep waiting and
            // let the per-command deadline backstop a pathological unframed reply.
            // Mirrors nether-ctl's bare_status_line guard (~/nether 8fab515).
            if (self.state == .info_wait and
                std.mem.startsWith(u8, buf, "ERR ") and
                std.mem.indexOfScalar(u8, buf, '\n') != null)
            {
                self.fail(io_rt, now_ms, "control handshake rejected (ERR)");
                return true;
            }
            return false;
        };
        // The trailer is 0x1e<digits>\n; wait until the newline lands.
        const nl_rel = std.mem.indexOfScalar(u8, buf[sep + 1 ..], '\n') orelse return false;
        const end = sep + 1 + nl_rel + 1; // one past the trailing newline
        const body = buf[0..sep]; // output before the trailer (handshake parses this)

        switch (self.state) {
            .info_wait => {
                if (!verifyProtoVersion(body)) {
                    self.fail(io_rt, now_ms, "proto_version mismatch (expected 1)");
                    return true;
                }
                self.state = .ready;
                self.backoff_ms = BACKOFF_START_MS;
                self.consumeFront(end);
                self.pumpQueue(io_rt, now_ms);
            },
            .ready => {
                const token = self.inflight;
                // Deliver the COMPLETE agent reply frame (output + 0x1e<exit>\n
                // trailer), not just the output: the exit code is the
                // authoritative host-call verdict (control-protocol.md), and the
                // filter owns interpreting it. The transport only uses the
                // trailer to detect completeness. resumeCall copies the bytes
                // synchronously, so the slice is consumed before we shift.
                if (token) |t| {
                    self.inflight = null;
                    if (self.complete_fn) |cf| cf(self.resume_ctx.?, t, buf[0..end]);
                }
                self.consumeFront(end);
                self.pumpQueue(io_rt, now_ms);
            },
            else => self.consumeFront(end),
        }
        return true;
    }

    /// Shift any bytes past `end` to the front of recv_buf.
    fn consumeFront(self: *ControlClient, end: usize) void {
        const remain = self.recv_len - end;
        if (remain > 0) std.mem.copyForwards(u8, self.recv_buf[0..remain], self.recv_buf[end..self.recv_len]);
        self.recv_len = remain;
    }

    /// Issue the next queued call if the socket is idle.
    fn pumpQueue(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        if (self.state != .ready or self.inflight != null or self.send_len != 0) return;
        if (self.q_count == 0) return;
        const slot = &self.queue[self.q_head];
        self.q_head = (self.q_head + 1) % QUEUE_CAP;
        self.q_count -= 1;
        self.issueAt(io_rt, now_ms, slot.token, slot.buf[0..slot.len]);
    }

    fn issue(self: *ControlClient, io_rt: *io_mod.IoRuntime, token: Token, cmd: []const u8) void {
        self.issueAt(io_rt, io_rt.nowMs(), token, cmd);
    }

    /// Stage `cmd\n` into send_buf, mark the call in-flight, and flush.
    fn issueAt(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64, token: Token, cmd: []const u8) void {
        @memcpy(self.send_buf[0..cmd.len], cmd);
        self.send_buf[cmd.len] = '\n';
        self.send_len = cmd.len + 1;
        self.send_off = 0;
        self.inflight = token;
        self.recv_len = 0;
        self.command_deadline_ms = now_ms + COMMAND_TIMEOUT_MS;
        _ = self.flushSend(io_rt, now_ms);
    }

    /// Write send_buf[send_off..send_len]; arm a writable wake on EAGAIN.
    /// Returns true when fully flushed.
    fn flushSend(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) bool {
        while (self.send_off < self.send_len) {
            const rc = std.posix.system.write(self.fd, self.send_buf[self.send_off..self.send_len].ptr, self.send_len - self.send_off);
            if (rc < 0) {
                const e = std.posix.errno(rc);
                if (e == .AGAIN) {
                    io_rt.armExternalWritable(self.slot, self.fd) catch {};
                    return false;
                }
                if (e == .INTR) continue;
                self.fail(io_rt, now_ms, "write error");
                return false;
            }
            if (rc == 0) {
                self.fail(io_rt, now_ms, "write returned 0");
                return false;
            }
            self.send_off += @intCast(rc);
        }
        self.send_len = 0;
        self.send_off = 0;
        return true;
    }

    // ------------------------------------------------------------------
    // Failure handling
    // ------------------------------------------------------------------

    /// Drop the socket, fail every in-flight + queued token closed, and schedule
    /// a reconnect. The reply stream cannot be trusted after an error, so the
    /// whole lane is rebuilt (PG's kill-and-reconnect discipline).
    fn fail(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64, reason: []const u8) void {
        std.log.warn("wasm control ({s}): {s}", .{ self.path, reason });
        if (self.fd >= 0) {
            io_rt.unregisterExternalFd(self.fd) catch {};
            clock.closeFd(self.fd);
            self.fd = -1;
        }
        self.failAll();
        self.recv_len = 0;
        self.send_len = 0;
        self.send_off = 0;
        self.scheduleRetry(now_ms, reason);
    }

    fn scheduleRetry(self: *ControlClient, now_ms: u64, reason: []const u8) void {
        _ = reason;
        self.state = .closed;
        self.retry_at_ms = now_ms + self.backoff_ms;
        self.backoff_ms = @min(self.backoff_ms * 2, BACKOFF_MAX_MS);
    }

    /// Fail the in-flight token and every queued token closed.
    fn failAll(self: *ControlClient) void {
        if (self.inflight) |t| {
            self.inflight = null;
            self.failOne(t);
        }
        while (self.q_count > 0) {
            const slot = &self.queue[self.q_head];
            self.q_head = (self.q_head + 1) % QUEUE_CAP;
            self.q_count -= 1;
            self.failOne(slot.token);
        }
    }

    fn failOne(self: *ControlClient, token: Token) void {
        if (self.fail_fn) |ff| ff(self.resume_ctx.?, token);
    }
};

/// Verify a __info__ report carries `proto_version=1`. The report is a text
/// block with one `proto_version=<n>` line (control-protocol.md).
fn verifyProtoVersion(report: []const u8) bool {
    const key = "proto_version=";
    const at = std.mem.indexOf(u8, report, key) orelse return false;
    var i = at + key.len;
    var n: u32 = 0;
    var saw_digit = false;
    while (i < report.len and report[i] >= '0' and report[i] <= '9') : (i += 1) {
        n = n * 10 + (report[i] - '0');
        saw_digit = true;
    }
    return saw_digit and n == 1;
}

// ---------------------------------------------------------------------------
// Tests (run with: zig build test -Denable-wasm=true)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "verifyProtoVersion accepts v1, rejects others" {
    try testing.expect(verifyProtoVersion("nether sandbox info\nproto_version=1\nbackend=hvf\n"));
    try testing.expect(!verifyProtoVersion("nether sandbox info\nproto_version=2\n"));
    try testing.expect(!verifyProtoVersion("nether sandbox info\n")); // missing
    try testing.expect(!verifyProtoVersion("proto_version=\n")); // no digits
    try testing.expect(verifyProtoVersion("proto_version=1")); // no trailing newline
}

// A scripted in-process driver that exercises the reply-framing state machine
// without a socket: feed bytes through tryConsumeReply and observe completions.
const Captured = struct {
    var token: ?Token = null;
    var body: [256]u8 = undefined;
    var body_len: usize = 0;
    var failed: ?Token = null;

    fn reset() void {
        token = null;
        body_len = 0;
        failed = null;
    }
    fn complete(ctx: *anyopaque, t: Token, result: []const u8) void {
        _ = ctx;
        token = t;
        const n = @min(result.len, body.len);
        @memcpy(body[0..n], result[0..n]);
        body_len = n;
    }
    fn fail(ctx: *anyopaque, t: Token) void {
        _ = ctx;
        failed = t;
    }
};

test "tryConsumeReply: handshake then a command reply complete the right token" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);

    // We drive the framing layer directly; no fd is touched because every reply
    // is already buffered (tryConsumeReply never reads the socket).
    var io_rt: io_mod.IoRuntime = undefined;

    // Handshake: a proto_version=1 info report ending in the 0x1e0\n trailer.
    cc.state = .info_wait;
    const info = "nether sandbox info\nproto_version=1\nbackend=test\n\x1e0\n";
    @memcpy(cc.recv_buf[0..info.len], info);
    cc.recv_len = info.len;
    try testing.expect(cc.tryConsumeReply(&io_rt, 0));
    try testing.expect(cc.state == .ready);
    try testing.expectEqual(@as(usize, 0), cc.recv_len);

    // Command reply: output then 0x1e<exit>\n. The in-flight token completes
    // with the COMPLETE frame (trailer included) so the filter can read the
    // authoritative exit code.
    cc.inflight = 42;
    const reply = "lookup ok\x1e0\n";
    @memcpy(cc.recv_buf[0..reply.len], reply);
    cc.recv_len = reply.len;
    try testing.expect(cc.tryConsumeReply(&io_rt, 0));
    try testing.expectEqual(@as(?Token, 42), Captured.token);
    try testing.expectEqualStrings("lookup ok\x1e0\n", Captured.body[0..Captured.body_len]);
    try testing.expect(cc.inflight == null);
    try testing.expectEqual(@as(usize, 0), cc.recv_len);
}

test "tryConsumeReply: partial trailer is not consumed until newline" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined;

    cc.state = .ready;
    cc.inflight = 7;
    // 0x1e seen but no newline yet -> incomplete.
    const part = "data\x1e0";
    @memcpy(cc.recv_buf[0..part.len], part);
    cc.recv_len = part.len;
    try testing.expect(!cc.tryConsumeReply(&io_rt, 0));
    try testing.expect(Captured.token == null);

    // Newline arrives -> consumed (full frame delivered, trailer included).
    cc.recv_buf[cc.recv_len] = '\n';
    cc.recv_len += 1;
    try testing.expect(cc.tryConsumeReply(&io_rt, 0));
    try testing.expectEqual(@as(?Token, 7), Captured.token);
    try testing.expectEqualStrings("data\x1e0\n", Captured.body[0..Captured.body_len]);
}

test "tryConsumeReply: a bare ERR at handshake fails fast (no hang)" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined; // fd<0, so fail() never touches it

    cc.state = .info_wait;
    const err = "ERR too many control clients\n"; // unframed, no 0x1e
    @memcpy(cc.recv_buf[0..err.len], err);
    cc.recv_len = err.len;
    // Consumed (fast-fail) rather than waiting for the handshake deadline.
    try testing.expect(cc.tryConsumeReply(&io_rt, 0));
    try testing.expect(cc.state == .closed); // fail() -> scheduleRetry
}

test "startCall queues when not ready and fails closed when disabled" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined;

    // Not connected yet: the call is queued, not failed.
    cc.state = .closed;
    cc.startCall(&io_rt, 3, "lookup:user");
    try testing.expectEqual(@as(usize, 1), cc.q_count);
    try testing.expect(Captured.failed == null);

    // Disabled backend: fail closed immediately.
    cc.state = .disabled;
    cc.startCall(&io_rt, 4, "lookup:user");
    try testing.expectEqual(@as(?Token, 4), Captured.failed);
}

test "startCall: a reserved __verb__ payload fails closed and never enqueues" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined; // never touched: the guard fails before any I/O

    // The guard runs before any state/socket logic, so even a ready+idle socket
    // (where a normal command would issue immediately) never sends a reserved
    // verb: it fails the token closed and is neither issued nor enqueued. State
    // is .ready here precisely to prove the guard short-circuits the issue path
    // (and thus never touches the undefined io_rt).
    cc.state = .ready;
    cc.startCall(&io_rt, 11, "__shutdown__");
    try testing.expectEqual(@as(?Token, 11), Captured.failed);
    try testing.expectEqual(@as(usize, 0), cc.q_count); // not enqueued
    try testing.expect(cc.inflight == null); // not issued
    try testing.expectEqual(@as(usize, 0), cc.send_len); // nothing staged for the socket

    // A normal E2E command is accepted as before: not connected yet, so it
    // queues rather than failing. Proves the guard is scoped to the "__"
    // namespace and leaves ordinary commands intact.
    Captured.reset();
    cc.state = .closed;
    cc.startCall(&io_rt, 12, "E2E /x tok");
    try testing.expectEqual(@as(usize, 1), cc.q_count);
    try testing.expect(Captured.failed == null);
}

test "handleReadable: real fd read path parses a framed reply and completes" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined; // touched only on the (unhit) fail path

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(@intCast(AF_UNIX), @intCast(std.posix.SOCK.STREAM), 0, &fds) != 0) return error.SocketpairFailed;
    defer clock.closeFd(fds[0]);
    defer clock.closeFd(fds[1]);
    // Our end must be non-blocking so the post-reply read returns EAGAIN and the
    // drain loop exits instead of blocking.
    try net.setNonBlocking(fds[0]);

    cc.fd = fds[0];
    cc.state = .ready;
    cc.inflight = 99;

    // The "nether" side writes a framed command reply: output then 0x1e<exit>\n.
    const reply = "user found\x1e0\n";
    try net.sendAll(fds[1], reply);

    cc.handleReadable(&io_rt, 0);
    try testing.expectEqual(@as(?Token, 99), Captured.token);
    try testing.expectEqualStrings("user found\x1e0\n", Captured.body[0..Captured.body_len]);
    try testing.expect(cc.inflight == null);
    try testing.expectEqual(@as(usize, 0), cc.recv_len);
}
