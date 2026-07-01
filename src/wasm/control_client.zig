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
const filter = @import("filter.zig");

pub const Token = host_call.Token;

/// External-fd slot for the control socket. The PG client owns 0..MAX_SLOTS-1
/// (4); the control socket takes the next slot. Kept distinct so dispatch.zig
/// can route external-fd events to the right owner by slot range.
pub const DEFAULT_SLOT: u32 = 4;

/// The agent reply trailer separator (0x1e, ASCII RS), per control-protocol.md.
/// Reports and shell commands end with 0x1e<exit-code>\n.
const RS: u8 = 0x1e;

/// Buffers. A reply larger than RECV_CAP is DRAINED to its frame boundary (the
/// agent always emits the 0x1e<exit>\n trailer; it truncates the body, not the
/// frame -- control-protocol.md "Output bound"), so the socket stays clean and
/// the call still completes with the exit verdict.
const RECV_CAP = 64 * 1024;
/// The delivered command reply must fit the filter's result buffer WITH its
/// trailer, or resumeCall's head-copy would drop the 0x1e<exit> trailer and the
/// filter would lose the verdict (the R2 bug). Truncate the body to fit, never
/// the trailer.
const DELIVER_CAP = filter.CALL_RESULT_CAP;
/// Scratch for discarding over-cap body while scanning for the trailer.
const DRAIN_CAP = 8 * 1024;
/// Upper bound on a trailer (0x1e + decimal exit code + \n), kept across drain
/// reads so a trailer split between reads is still found.
const TRAILER_MAX = 32;
const CMD_CAP = 4 * 1024; // a queued command line (control commands are short)
const QUEUE_CAP = host_call.Table.CAP; // at most one queued per parked filter

const CONNECT_TIMEOUT_MS: u64 = 5_000;
const HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
/// Per-command wall-clock budget. On expiry the socket is dropped and rebuilt
/// (a streamed command cannot be cancelled in place; reconnect frees the lane).
const COMMAND_TIMEOUT_MS: u64 = 30_000;
/// Settle window for an UNFRAMED command reply. A bare `ERR <reason>\n` (e.g.
/// "agent not connected" before the guest is ready, or "unknown command") carries
/// no 0x1e trailer. It could (rarely) be a framed reply whose 0x1e is still in
/// flight, so on seeing a complete bare ERR/OK line we wait this long for a 0x1e
/// before treating it as a bare reply and failing the call fast (vs. blocking the
/// full COMMAND_TIMEOUT). Mirrors nether-ctl read_reply's SETTLE_MS.
const SETTLE_MS: u64 = 500;
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

    // R2 drain state: when a command reply overflows recv_buf before its trailer,
    // we retain recv_buf[0..recv_len] as the (truncated) body prefix and read the
    // rest here, discarding overflow while scanning for the 0x1e<exit>\n trailer.
    draining: bool = false,
    drain_buf: [DRAIN_CAP]u8 = undefined,
    drain_len: usize = 0,

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
    /// True while startCall is on the stack. startCall runs INSIDE the parking
    /// filter's dispatch frame (router/proxy park site -> start_fn -> here), so
    /// a synchronous failOne would re-enter the resume path before the park
    /// sentinel has registered: H1 silently swallows the fail (request hangs to
    /// deadline), H2/H3 queue a 500 and then the sentinel branch queues a
    /// second one on the same stream. failOne defers instead while this is set;
    /// the tokens drain on the next tick/onEvent, off any dispatch frame.
    in_start_call: bool = false,
    /// Tokens whose fail-closed delivery was deferred by failOne (see
    /// in_start_call). Capacity CAP: every deferred token is a live park.
    pending_fail: [host_call.Table.CAP]Token = undefined,
    pending_fail_count: usize = 0,
    command_deadline_ms: u64 = 0,
    /// Per-command wall-clock budget. Defaults to COMMAND_TIMEOUT_MS (30s); the
    /// server overrides it from `wasm_host_call_deadline_ms` so the transport does
    /// not out-live the park deadline (lets a test set a sub-second timeout).
    command_timeout_ms: u64 = COMMAND_TIMEOUT_MS,
    /// Non-zero while a complete bare ERR/OK command reply is buffered with no
    /// 0x1e: the deadline by which a 0x1e must arrive for it to count as framed.
    settle_deadline_ms: u64 = 0,

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
        self.drainPendingFails();
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
        // Any failure below (guard rejection, disabled lane, queue overflow, or
        // a write error inside issue -> fail -> failAll) must NOT resume the
        // park synchronously: we are still inside the park site's dispatch
        // frame. failOne defers to pending_fail while this flag is set.
        self.in_start_call = true;
        defer self.in_start_call = false;
        // Security choke (D2-1): a Tier-1 wasm filter must not drive the Tier-2
        // control plane. `cmd` is filter-supplied bytes (the host_call payload,
        // copied verbatim) written to the Nether control socket, where swerver is
        // the PRIMARY (driving) client. The socket is a `\n`-delimited line
        // protocol and issueAt appends one trailing `\n`, so this MUST stay a
        // single line: an EMBEDDED `\n` (or `\r`) would be delivered to Nether as
        // a SECOND command line, smuggling a reserved verb past the prefix check
        // below (e.g. "lookup\n__shutdown__"). An embedded `0x1e` could also forge
        // a reply trailer. Reject any such payload, fail-closed, before the verb
        // check -- this covers both the immediate and the queued (copied) paths.
        for (cmd) |b| {
            if (b == '\n' or b == '\r' or b == RS) {
                std.log.warn("wasm control ({s}): blocked filter host_call with an embedded control byte (newline/CR/0x1e); failing closed", .{self.path});
                self.failOne(token);
                return;
            }
        }
        // Nether reserves the `__verb__` namespace for control verbs
        // (__shutdown__, __put__/__get__ against the HOST fs, __stats__, ...).
        // Neutralize any payload whose (whitespace-trimmed) first token begins
        // with "__": fail the call closed, never let the bytes reach the socket.
        // Trim leading whitespace first so " __shutdown__" cannot sneak past a
        // downstream parser that trims. Normal shell + `E2E ...` commands are
        // untouched; the handshake __info__ is sent internally, not via startCall.
        var hs: usize = 0;
        while (hs < cmd.len and (cmd[hs] == ' ' or cmd[hs] == '\t')) hs += 1;
        const head = cmd[hs..];
        if (std.mem.startsWith(u8, head, "__")) {
            std.log.warn("wasm control ({s}): blocked reserved control verb from filter host_call (begins with \"__\"); failing closed", .{self.path});
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
        self.drainPendingFails();
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
        self.drainPendingFails();
        switch (self.state) {
            .disabled => {},
            .closed => if (now_ms >= self.retry_at_ms) self.startConnect(io_rt, now_ms),
            .connecting, .info_wait => if (now_ms >= self.deadline_ms) {
                self.fail(io_rt, now_ms, "connect/handshake timeout");
            },
            .ready => {
                if (self.inflight != null and self.settle_deadline_ms != 0 and now_ms >= self.settle_deadline_ms) {
                    // A bare ERR/OK command reply settled (no 0x1e arrived): it is
                    // an unframed control-plane reply for this command (e.g. the
                    // guest was not ready). Fail this call fast and consume the
                    // line; the socket stays healthy for the next command.
                    self.failBareReply(io_rt, now_ms);
                } else if (self.inflight != null and now_ms >= self.command_deadline_ms) {
                    // A streamed command cannot be cancelled in place; drop and
                    // rebuild the socket so the lane is not wedged. The token's park
                    // is failed here (no-op if the table already timed it out).
                    self.fail(io_rt, now_ms, "command timeout");
                }
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
        self.draining = false;
        self.drain_len = 0;
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
            if (self.draining) {
                // drainOverflow returns true once it delivered the truncated reply
                // (loop again for pipelined bytes), false on EAGAIN / terminal fail.
                if (!self.drainOverflow(io_rt, now_ms)) return;
                continue;
            }
            if (self.recv_len >= self.recv_buf.len) {
                // recv_buf is full and tryConsumeReply found no 0x1e in it (else the
                // frame would already be consumed). The agent always emits the
                // trailer (it bounds the body, not the frame), so for an in-flight
                // command DRAIN to the frame boundary instead of failing closed --
                // keeping the socket clean and still completing with the exit code.
                if (self.state == .ready and self.inflight != null) {
                    // Seed the drain scratch with the tail of recv_buf so a trailer
                    // straddling the buffer boundary (its 0x1e landed here but the
                    // \n is still incoming) is still found by drainOverflow. recv_len
                    // shrinks by the seed; the body is being truncated anyway.
                    const seed = @min(self.recv_len, TRAILER_MAX - 1);
                    @memcpy(self.drain_buf[0..seed], self.recv_buf[self.recv_len - seed ..]);
                    self.drain_len = seed;
                    self.recv_len -= seed;
                    self.draining = true;
                    continue;
                }
                // Handshake report, or no in-flight call: a reply this large with no
                // trailer is anomalous; fail and let tick() rebuild the lane.
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

    /// Deliver an in-flight command reply, truncating the BODY (never the trailer)
    /// so the delivered frame fits the filter's result buffer. `body_len` is the
    /// retained output length in recv_buf[0..]; `trailer` is the 0x1e<exit>\n bytes
    /// (which may alias recv_buf past body_len, so it is copied out first). Mirrors
    /// the nether-side max_output_bytes contract one level down (R2).
    fn deliverCommandReply(self: *ControlClient, body_len: usize, trailer: []const u8) void {
        const tn: usize = @min(trailer.len, TRAILER_MAX);
        const max_body: usize = if (DELIVER_CAP > tn) DELIVER_CAP - tn else 0;
        const keep = @min(body_len, max_body);
        if (keep < body_len)
            std.log.warn("wasm control ({s}): agent reply body {d}B over result cap {d}B; body truncated, exit trailer kept", .{ self.path, body_len, DELIVER_CAP });
        var tbuf: [TRAILER_MAX]u8 = undefined;
        @memcpy(tbuf[0..tn], trailer[0..tn]);
        @memcpy(self.recv_buf[keep .. keep + tn], tbuf[0..tn]);
        if (self.inflight) |t| {
            self.inflight = null;
            if (self.complete_fn) |cf| cf(self.resume_ctx.?, t, self.recv_buf[0 .. keep + tn]);
        }
    }

    /// Read and DISCARD over-cap reply body, scanning for the 0x1e<exit>\n trailer
    /// the agent always emits. On finding it, deliver a body-truncated reply (the
    /// exit verdict preserved) and resume normal reads. Returns true when a reply
    /// was delivered, false on EAGAIN (wait for the next read event) or a terminal
    /// failure. The COMMAND_TIMEOUT (tick) bounds a guest that never sends a trailer.
    fn drainOverflow(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) bool {
        while (true) {
            if (std.mem.indexOfScalar(u8, self.drain_buf[0..self.drain_len], RS)) |sep| {
                if (std.mem.indexOfScalar(u8, self.drain_buf[sep + 1 .. self.drain_len], '\n')) |nl_rel| {
                    const tend = sep + 1 + nl_rel + 1;
                    self.deliverCommandReply(self.recv_len, self.drain_buf[sep..tend]);
                    // Bytes after the trailer are the next reply: move them to recv_buf.
                    const leftover = self.drain_buf[tend..self.drain_len];
                    self.draining = false;
                    self.recv_len = leftover.len;
                    std.mem.copyForwards(u8, self.recv_buf[0..leftover.len], leftover);
                    self.drain_len = 0;
                    self.pumpQueue(io_rt, now_ms);
                    return true;
                }
                // 0x1e seen, \n not yet. A real trailer is 0x1e<exit>\n (tiny). If
                // more than TRAILER_MAX bytes already follow this 0x1e with no \n,
                // it is NOT a trailer start (a literal 0x1e in the untrusted guest's
                // output) -> skip past it and keep scanning, so a hostile guest
                // cannot wedge the drain into a zero-length read / spurious EOF.
                if (self.drain_len - sep > TRAILER_MAX) {
                    const past = sep + 1;
                    std.mem.copyForwards(u8, self.drain_buf[0 .. self.drain_len - past], self.drain_buf[past..self.drain_len]);
                    self.drain_len -= past;
                } else if (sep > 0) {
                    // Plausible partial trailer: keep it at the front, read its \n.
                    std.mem.copyForwards(u8, self.drain_buf[0 .. self.drain_len - sep], self.drain_buf[sep..self.drain_len]);
                    self.drain_len -= sep;
                }
            } else if (self.drain_len == self.drain_buf.len) {
                // No trailer in a full scratch: a trailer could straddle reads, so
                // retain the last TRAILER_MAX-1 bytes and discard the rest.
                const keep = TRAILER_MAX - 1;
                std.mem.copyForwards(u8, self.drain_buf[0..keep], self.drain_buf[self.drain_len - keep ..]);
                self.drain_len = keep;
            }
            const rc = std.posix.system.read(self.fd, self.drain_buf[self.drain_len..].ptr, self.drain_buf.len - self.drain_len);
            if (rc < 0) {
                const e = std.posix.errno(rc);
                if (e == .AGAIN) return false;
                if (e == .INTR) continue;
                self.fail(io_rt, now_ms, "read error (draining)");
                return false;
            }
            if (rc == 0) {
                self.fail(io_rt, now_ms, "control socket closed (EOF, draining)");
                return false;
            }
            self.drain_len += @intCast(rc);
        }
    }

    /// If recv_buf holds a complete framed reply (body 0x1e<exit>\n), consume it.
    /// Returns true if one was consumed. Handshake replies verify proto_version;
    /// command replies fire the completion. Leftover bytes are shifted to front.
    fn tryConsumeReply(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) bool {
        const buf = self.recv_buf[0..self.recv_len];
        const sep = std.mem.indexOfScalar(u8, buf, RS) orelse {
            // No frame separator yet. Framed replies (shell/guest commands,
            // __info__) end with 0x1e<exit>\n; an UNFRAMED `ERR <reason>\n` (a
            // control-layer reply: bad/unknown command, observer gating, or
            // "agent not connected" before the guest is ready) carries no 0x1e and
            // would otherwise hang until the deadline. Guard a complete bare line:
            if (std.mem.indexOfScalar(u8, buf, '\n') != null and bareStatusLine(buf)) {
                // Handshake: __info__ never has ERR-prefixed framed output, so a
                // bare ERR is unambiguously a rejection -- fail fast now.
                if (self.state == .info_wait) {
                    self.fail(io_rt, now_ms, "control handshake rejected (ERR)");
                    return true;
                }
                // Command phase: a framed reply's output could (rarely) begin with
                // "ERR" before its 0x1e arrives, so open a short settle window
                // rather than failing immediately; tick() resolves it. Mirrors
                // nether-ctl read_reply's SETTLE_MS disambiguation.
                if (self.state == .ready and self.inflight != null and self.settle_deadline_ms == 0) {
                    self.settle_deadline_ms = now_ms + SETTLE_MS;
                }
            }
            return false;
        };
        // A 0x1e arrived: this is a framed reply after all, so cancel any pending
        // bare-reply settle window opened above.
        self.settle_deadline_ms = 0;
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
                if (token != null) {
                    // Truncate the body if needed so the delivered frame fits the
                    // filter's result cap WITH the trailer (R2); consume the FULL
                    // original frame from recv_buf regardless.
                    self.deliverCommandReply(sep, buf[sep..end]);
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
        self.draining = false;
        self.drain_len = 0;
        self.settle_deadline_ms = 0;
        self.command_deadline_ms = now_ms + self.command_timeout_ms;
        _ = self.flushSend(io_rt, now_ms);
    }

    /// A bare ERR/OK command reply settled (no 0x1e). Fail the in-flight call
    /// fast and consume the line; the socket stays healthy for the next command
    /// (the control plane returned a complete unframed reply, not a desync).
    fn failBareReply(self: *ControlClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        const nl = std.mem.indexOfScalar(u8, self.recv_buf[0..self.recv_len], '\n');
        const end = if (nl) |n| n + 1 else self.recv_len;
        if (self.inflight) |t| {
            self.inflight = null;
            self.failOne(t);
        }
        self.settle_deadline_ms = 0;
        self.consumeFront(end);
        self.pumpQueue(io_rt, now_ms);
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
        self.draining = false;
        self.drain_len = 0;
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
        // Mid-startCall fails are deferred (see in_start_call): delivering now
        // would re-enter the dispatch frame that is still parking this request.
        if (self.in_start_call and self.pending_fail_count < self.pending_fail.len) {
            self.pending_fail[self.pending_fail_count] = token;
            self.pending_fail_count += 1;
            return;
        }
        if (self.fail_fn) |ff| ff(self.resume_ctx.?, token);
    }

    /// Deliver fails deferred by failOne during startCall. Called from tick and
    /// onEvent -- both run off any dispatch frame, after the park site returned
    /// its sentinel and the transport registered the park, so each token yields
    /// exactly one fail-closed response on every protocol.
    fn drainPendingFails(self: *ControlClient) void {
        while (self.pending_fail_count > 0) {
            self.pending_fail_count -= 1;
            const t = self.pending_fail[self.pending_fail_count];
            if (self.fail_fn) |ff| ff(self.resume_ctx.?, t);
        }
    }
};

/// Is `buf` an unframed control-plane status line (a bare `ERR ...` / `OK ...`
/// with no 0x1e trailer)? Used to distinguish a control-plane reply (e.g. "ERR
/// agent not connected" before the guest is ready) from a framed command reply.
/// Mirrors nether-ctl's bare_status_line. Caller has already established there is
/// no 0x1e in the buffer.
fn bareStatusLine(buf: []const u8) bool {
    return std.mem.startsWith(u8, buf, "ERR ") or std.mem.startsWith(u8, buf, "OK ");
}

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
    // R2: a delivered result can be up to the filter's result cap, larger than
    // `body`. Record its full length + last bytes to assert truncation + trailer.
    var last_len: usize = 0;
    var tail: [16]u8 = undefined;
    var tail_len: usize = 0;

    fn reset() void {
        token = null;
        body_len = 0;
        failed = null;
        last_len = 0;
        tail_len = 0;
    }
    fn complete(ctx: *anyopaque, t: Token, result: []const u8) void {
        _ = ctx;
        token = t;
        const n = @min(result.len, body.len);
        @memcpy(body[0..n], result[0..n]);
        body_len = n;
        last_len = result.len;
        const tn = @min(result.len, tail.len);
        @memcpy(tail[0..tn], result[result.len - tn ..]);
        tail_len = tn;
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

test "command-phase bare ERR settles and fails the call fast (guest not ready)" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined; // not dereferenced on these paths

    // A command is in flight; the control plane returns an unframed ERR (no 0x1e)
    // because the guest agent is not connected yet.
    cc.state = .ready;
    cc.inflight = 77;
    const err = "ERR agent not connected (guest not ready)\n"; // no 0x1e
    @memcpy(cc.recv_buf[0..err.len], err);
    cc.recv_len = err.len;

    // First pass: no 0x1e, but a complete bare ERR line -> opens the settle window
    // (does NOT fail yet, in case a framed reply's 0x1e is merely in flight).
    try testing.expect(!cc.tryConsumeReply(&io_rt, 1_000));
    try testing.expect(cc.settle_deadline_ms != 0);
    try testing.expect(Captured.failed == null);

    // The settle window elapses with still no 0x1e -> fail the call fast, keep the
    // socket healthy (ready) for the next command.
    cc.tick(&io_rt, cc.settle_deadline_ms);
    try testing.expectEqual(@as(?Token, 77), Captured.failed);
    try testing.expect(cc.inflight == null);
    try testing.expect(cc.state == .ready); // socket not torn down
    try testing.expectEqual(@as(usize, 0), cc.recv_len); // ERR line consumed
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

    // Disabled backend: fail closed, but DEFERRED -- startCall runs inside the
    // parking dispatch frame, so the fail must not resume synchronously. It is
    // delivered on the next tick/onEvent drain.
    cc.state = .disabled;
    cc.startCall(&io_rt, 4, "lookup:user");
    try testing.expect(Captured.failed == null); // not synchronous
    try testing.expectEqual(@as(usize, 1), cc.pending_fail_count);
    cc.drainPendingFails();
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
    try testing.expect(Captured.failed == null); // deferred, never inline (reentrancy)
    try testing.expectEqual(@as(usize, 1), cc.pending_fail_count);
    cc.drainPendingFails();
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

test "startCall: embedded-newline and leading-ws control-verb injection is blocked" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined; // guard fails before any I/O

    // CRITICAL regression: a filter must not smuggle a SECOND control line via an
    // embedded newline. "lookup\n__shutdown__" would otherwise pass the prefix
    // check (does not start with "__") and reach Nether as two lines, the second
    // a reserved verb. The embedded-control-byte guard fails it closed.
    const injections = [_][]const u8{
        "lookup\n__shutdown__", // embedded LF -> second command line
        "lookup\r\n__shutdown__", // CR + LF
        "x\x1edenied", // embedded 0x1e -> forged reply trailer
        " __shutdown__", // leading space before the reserved verb
        "\t__put__ /etc/passwd /x", // leading tab
    };
    for (injections, 0..) |payload, i| {
        Captured.reset();
        cc.state = .ready; // would issue immediately if not blocked
        cc.inflight = null;
        cc.send_len = 0;
        cc.q_count = 0;
        cc.startCall(&io_rt, @intCast(100 + i), payload);
        try testing.expect(Captured.failed == null); // deferred, never inline (reentrancy)
        cc.drainPendingFails();
        try testing.expectEqual(@as(?Token, @intCast(100 + i)), Captured.failed);
        try testing.expectEqual(@as(usize, 0), cc.q_count); // never enqueued
        try testing.expect(cc.inflight == null); // never issued
        try testing.expectEqual(@as(usize, 0), cc.send_len); // nothing reached the socket
    }
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

test "R2: an over-cap command reply is body-truncated but keeps its exit trailer" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined;

    cc.state = .ready;
    cc.inflight = 5;
    // A body larger than the filter result cap, then a 0x1e<exit>\n trailer. The
    // naive head-copy in resumeCall would drop the trailer (and the exit verdict);
    // the transport must truncate the BODY and keep the trailer.
    const body_n = DELIVER_CAP + 4096;
    @memset(cc.recv_buf[0..body_n], 'a');
    const trailer = "\x1e7\n";
    @memcpy(cc.recv_buf[body_n .. body_n + trailer.len], trailer);
    cc.recv_len = body_n + trailer.len;

    try testing.expect(cc.tryConsumeReply(&io_rt, 0));
    try testing.expectEqual(@as(?Token, 5), Captured.token);
    // Delivered frame fits the result cap, and ends with the exit trailer.
    try testing.expect(Captured.last_len <= DELIVER_CAP);
    try testing.expect(Captured.last_len > 0);
    try testing.expectEqualStrings("\x1e7\n", Captured.tail[Captured.tail_len - 3 .. Captured.tail_len]);
    try testing.expectEqual(@as(usize, 0), cc.recv_len);
}

test "R2: a reply larger than the recv buffer drains to the trailer; socket stays clean" {
    Captured.reset();
    var dummy: u8 = 0;
    var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
    cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
    var io_rt: io_mod.IoRuntime = undefined;

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(@intCast(AF_UNIX), @intCast(std.posix.SOCK.STREAM), 0, &fds) != 0) return error.SocketpairFailed;
    defer clock.closeFd(fds[0]);
    defer clock.closeFd(fds[1]);
    try net.setNonBlocking(fds[0]);
    try net.setNonBlocking(fds[1]); // writer non-blocking so a full sndbuf cannot deadlock the test

    cc.fd = fds[0];
    cc.state = .ready;
    cc.inflight = 11;

    // Push a body well over RECV_CAP plus its trailer, interleaving reader drains
    // so neither side blocks. Writes that EAGAIN trigger a drain to make room.
    const total = RECV_CAP + 16 * 1024; // > the 64 KiB recv buffer
    var chunk: [4096]u8 = undefined;
    @memset(&chunk, 'x');
    var pushed: usize = 0;
    var guard: usize = 0;
    while (pushed < total and guard < 100_000) : (guard += 1) {
        const want = @min(chunk.len, total - pushed);
        const rc = std.posix.system.write(fds[1], chunk[0..want].ptr, want);
        if (rc > 0) pushed += @intCast(rc);
        cc.handleReadable(&io_rt, 0);
    }
    // The trailer (retry on EAGAIN, draining the reader between attempts).
    const trailer = "\x1e3\n";
    var toff: usize = 0;
    while (toff < trailer.len and guard < 100_000) : (guard += 1) {
        const rc = std.posix.system.write(fds[1], trailer[toff..].ptr, trailer.len - toff);
        if (rc > 0) toff += @intCast(rc);
        cc.handleReadable(&io_rt, 0);
    }

    try testing.expectEqual(@as(?Token, 11), Captured.token);
    try testing.expect(Captured.last_len <= DELIVER_CAP); // body discarded, trailer kept
    try testing.expectEqualStrings("\x1e3\n", Captured.tail[Captured.tail_len - 3 .. Captured.tail_len]);
    try testing.expect(!cc.draining);
    try testing.expectEqual(@as(usize, 0), cc.recv_len); // socket left clean

    // Prove the socket is healthy: a normal follow-up reply completes the next call.
    Captured.reset();
    cc.inflight = 12;
    try net.sendAll(fds[1], "ok\x1e0\n");
    cc.handleReadable(&io_rt, 0);
    try testing.expectEqual(@as(?Token, 12), Captured.token);
    try testing.expectEqualStrings("ok\x1e0\n", Captured.body[0..Captured.body_len]);
}

test "issueAt: command_deadline uses the configured command_timeout_ms (default + override)" {
    var dummy: u8 = 0;
    var io_rt: io_mod.IoRuntime = undefined; // touched only on the (unhit) fail path

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(@intCast(AF_UNIX), @intCast(std.posix.SOCK.STREAM), 0, &fds) != 0) return error.SocketpairFailed;
    defer clock.closeFd(fds[0]);
    defer clock.closeFd(fds[1]);
    try net.setNonBlocking(fds[0]);

    // Default (unset): the 30s const is the per-command budget.
    {
        var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
        cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
        cc.fd = fds[0];
        cc.state = .ready;
        try testing.expectEqual(COMMAND_TIMEOUT_MS, cc.command_timeout_ms);
        cc.issueAt(&io_rt, 1_000, 5, "E2E /x tok");
        try testing.expectEqual(@as(u64, 1_000 + COMMAND_TIMEOUT_MS), cc.command_deadline_ms);
    }

    // Override (server sets a sub-second budget): the deadline tracks it.
    {
        var cc = ControlClient.init("/tmp/unused.sock", DEFAULT_SLOT);
        cc.installResume(@ptrCast(&dummy), Captured.complete, Captured.fail);
        cc.fd = fds[0];
        cc.state = .ready;
        cc.command_timeout_ms = 250;
        cc.issueAt(&io_rt, 1_000, 6, "E2E /x tok");
        try testing.expectEqual(@as(u64, 1_250), cc.command_deadline_ms);
    }
}
