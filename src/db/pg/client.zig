//! Native PostgreSQL client — per-worker connection driver and query
//! park machinery (design 9.0, phases 2.1–2.2b).
//!
//! Connection bring-up: non-blocking connect, the phase-1
//! `pg.Handshake` driven by reactor readiness events, reconnect with
//! exponential backoff. Query side: `query()` issues one
//! extended-protocol op per ready slot, parks the HTTP request in the
//! bounded park table, and the installed resume hook runs the
//! continuation when ReadyForQuery (or timeout / connection loss)
//! delivers the outcome. NO pipelining yet — one op in flight per slot;
//! the FIFO is a later phase-2 step.
//!
//! Reactor contract:
//!   - PG sockets register via `IoRuntime.registerExternalFd(slot, fd)`;
//!     their events arrive tagged with `io.EXTERNAL_ID_BIT` and the
//!     dispatch loop routes them to `onEvent(io, slot, kind)`.
//!   - `tick(io, now_ms)` runs from the dispatch housekeeping block
//!     (~100ms cadence) and drives connect/handshake timeouts plus
//!     reconnect backoff.
//!   - Zero heap allocation on the I/O path: each slot embeds fixed
//!     send/recv buffers. The PgClient itself is heap-allocated once at
//!     server init (mirrors `Server.proxy`) so the nonce slice the
//!     in-flight handshake borrows never moves.
//!   - DNS resolves once in `init()` (server startup) — never on the
//!     reactor. Picking up a new address requires a restart; config
//!     hot-reload of the postgres block is out of scope for this step.
//!   - All four backends host external fds as of phase 2.2a (kqueue,
//!     epoll, io_uring_poll, io_uring_native). The `disabled` latch
//!     remains as a guard for any future backend that can't.

const std = @import("std");
const builtin = @import("builtin");
const io_mod = @import("../../runtime/io.zig");
const net = @import("../../runtime/net.zig");
const clock = @import("../../runtime/clock.zig");
const response_mod = @import("../../response/response.zig");
const pg = @import("pg.zig");
const protocol = @import("protocol.zig");
const handler_api = @import("handler_api.zig");

/// Hard cap on per-worker connections (design 9.0: pool of 2–4).
pub const MAX_SLOTS = 4;
pub const DEFAULT_POOL_SIZE = 2;

/// Bound on concurrently parked requests per worker. A parked request
/// holds one table entry (continuation + stash + deadline); when the
/// table is full, query() sheds load synchronously with ParkTableFull.
pub const MAX_PARKED = 64;
/// Sentinel for "no park" in slot.op_park and the per-conn token array.
const NO_PARK: u16 = std.math.maxInt(u16);

const RECV_BUF_SIZE = 16 * 1024;
const SEND_BUF_SIZE = 4 * 1024;
/// Single deadline covering non-blocking connect + handshake.
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const BACKOFF_INITIAL_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 30_000;
/// 18 random bytes -> 24 base64 chars (printable ASCII, no commas).
const NONCE_RAW_LEN = 18;
const NONCE_LEN = 24;

pub const SlotState = enum { closed, connecting, handshaking, ready, busy, failed };

/// One pooled connection. All buffers are embedded — no allocator on
/// the I/O path.
pub const Slot = struct {
    state: SlotState = .closed,
    fd: std.posix.fd_t = -1,
    handshake: pg.Handshake = undefined,
    /// SCRAM nonce storage; `handshake.opts.client_nonce` borrows this,
    /// so the slot must not move while a handshake is in flight.
    nonce_buf: [NONCE_LEN]u8 = undefined,
    recv_buf: [RECV_BUF_SIZE]u8 = undefined,
    recv_len: usize = 0,
    send_buf: [SEND_BUF_SIZE]u8 = undefined,
    send_len: usize = 0,
    send_off: usize = 0,
    /// Absolute reactor-ms deadline for connect + handshake.
    deadline_ms: u64 = 0,
    /// Earliest reconnect time after a failure.
    retry_at_ms: u64 = 0,
    /// Current backoff interval; doubles per failure, resets on ready.
    backoff_ms: u64 = 0,
    /// Park-table index of the request whose op is in flight on this
    /// slot (`.busy` only). NO_PARK when the requester vanished (client
    /// disconnect while parked): the op still runs to ReadyForQuery so
    /// the connection stays usable, but the outcome is discarded.
    op_park: u16 = NO_PARK,
    /// Rows-affected parsed from CommandComplete for the in-flight op.
    op_rows: u64 = 0,
};

/// One parked HTTP request awaiting a PG op (design 9.0 Handler API).
/// The continuation, stash, and generation check live here — the
/// Connection carries only the `.db_parked` state byte.
const ParkedRequest = struct {
    active: bool = false,
    conn_index: u32 = 0,
    /// Connection generation (conn.id) captured at park time; checked
    /// at resume so a recycled connection slot can't receive a stale
    /// continuation's response.
    conn_id: u64 = 0,
    continuation: handler_api.Continuation = undefined,
    stash: [handler_api.STASH_CAPACITY]u8 align(16) = undefined,
    /// Absolute reactor-ms deadline (statement_timeout_ms from park).
    deadline_ms: u64 = 0,
    /// Server-reported error captured from ErrorResponse, if any.
    server_error: ?handler_api.ServerErrorInfo = null,
};

/// Everything the resume layer needs to run a continuation. Borrowed
/// fields (result frames, stash) are valid only inside the resume
/// callback — the slot's recv buffer is reset when it returns.
pub const Outcome = struct {
    conn_index: u32,
    conn_id: u64,
    continuation: handler_api.Continuation,
    stash: *[handler_api.STASH_CAPACITY]u8,
    result: handler_api.PgError!handler_api.Result,
    server_error: ?handler_api.ServerErrorInfo,
};

/// Installed by the server at init: runs the continuation against the
/// (generation-checked) HTTP connection and enqueues its response.
/// Opaque to keep client.zig free of http1/router imports.
pub const ResumeFn = *const fn (ctx: *anyopaque, outcome: *const Outcome) void;

pub const Options = struct {
    /// Hostname or IP literal; resolved once in `init`.
    host: []const u8,
    port: u16 = 5432,
    user: []const u8,
    database: []const u8 = "",
    /// Borrowed; must outlive the client (getenv storage qualifies).
    password: []const u8 = "",
    pool_size: u8 = DEFAULT_POOL_SIZE,
    /// Explicit opt-in for answering an AuthenticationCleartextPassword
    /// request without TLS. Off by default: the spec's TLS-only policy
    /// (cleartext only over TLS) fails the connection instead. SCRAM is
    /// unaffected — it never reveals the password.
    allow_cleartext_password: bool = false,
    /// Per-op deadline; expiry delivers error.Timeout to the
    /// continuation and recycles the PG connection (a wire op cannot be
    /// cancelled without a separate cancel-request connection — v1
    /// kills and reconnects instead).
    statement_timeout_ms: u32 = 5_000,
};

pub const PgClient = struct {
    opts: Options,
    addr: net.ResolvedAddr,
    slots: [MAX_SLOTS]Slot,
    /// Set when the I/O backend cannot host external fds (io_uring, for
    /// now). The client stops trying rather than burning the backoff
    /// schedule on an error that will never clear.
    disabled: bool = false,
    allocator: std.mem.Allocator,
    /// Bounded park table; entries found by linear scan (64 max).
    parked: [MAX_PARKED]ParkedRequest = [1]ParkedRequest{.{}} ** MAX_PARKED,
    /// conn_index → park-table index (NO_PARK when not parked). Owned
    /// here, sized to max_connections, so parking adds no Connection
    /// fields — the Connection auto-layout is load-bearing.
    conn_parks: []u16,
    /// Resume hook installed by the server (see ResumeFn). Null in unit
    /// tests: outcomes are then dropped with a debug log.
    resume_ctx: ?*anyopaque = null,
    resume_fn: ?ResumeFn = null,

    pub const InitError = error{ ResolveFailed, InvalidPoolSize, OutOfMemory };

    /// Resolve the server address (blocking DNS — startup only) and set
    /// up the slot pool. No sockets are opened here; `tick` brings the
    /// connections up once the reactor is running.
    pub fn init(allocator: std.mem.Allocator, max_connections: usize, opts: Options) InitError!PgClient {
        if (opts.pool_size == 0 or opts.pool_size > MAX_SLOTS) return error.InvalidPoolSize;
        const addr = net.resolveAddress(opts.host, opts.port) catch return error.ResolveFailed;
        const conn_parks = try allocator.alloc(u16, max_connections);
        @memset(conn_parks, NO_PARK);
        return .{
            .opts = opts,
            .addr = addr,
            .slots = [1]Slot{.{}} ** MAX_SLOTS,
            .allocator = allocator,
            .conn_parks = conn_parks,
        };
    }

    /// Install the park-resume hook (server init, before the loop runs).
    pub fn installResume(self: *PgClient, ctx: *anyopaque, f: ResumeFn) void {
        self.resume_ctx = ctx;
        self.resume_fn = f;
    }

    pub fn deinit(self: *PgClient, io_rt: *io_mod.IoRuntime) void {
        for (&self.slots) |*slot| {
            if (slot.fd >= 0) {
                io_rt.unregisterExternalFd(slot.fd) catch {};
                clock.closeFd(slot.fd);
                slot.fd = -1;
            }
            slot.state = .closed;
        }
        self.allocator.free(self.conn_parks);
    }

    /// Single entry point from the dispatch loop for events tagged with
    /// EXTERNAL_ID_BIT. `slot_idx` is the low 32 bits of the conn id.
    pub fn onEvent(self: *PgClient, io_rt: *io_mod.IoRuntime, slot_idx: u32, kind: io_mod.EventKind) void {
        if (slot_idx >= self.opts.pool_size) return;
        const slot = &self.slots[slot_idx];
        if (slot.fd < 0) return; // stale event after a close
        const now_ms = io_rt.nowMs();
        switch (kind) {
            .err => self.failSlot(io_rt, slot_idx, now_ms, "socket error event"),
            .write => switch (slot.state) {
                .connecting => self.finishConnect(io_rt, slot_idx, now_ms),
                .handshaking => self.pumpSend(io_rt, slot_idx, now_ms),
                .busy => _ = self.flushSend(io_rt, slot_idx, now_ms),
                else => {},
            },
            .read => switch (slot.state) {
                // Readability can race ahead of the writable arm —
                // treat a read in .connecting as connect completion.
                .connecting => {
                    self.finishConnect(io_rt, slot_idx, now_ms);
                    if (slot.state == .handshaking) self.handleReadable(io_rt, slot_idx, now_ms);
                },
                .handshaking => self.handleReadable(io_rt, slot_idx, now_ms),
                .ready => self.drainReady(io_rt, slot_idx, now_ms),
                .busy => self.pumpBusyRead(io_rt, slot_idx, now_ms),
                else => {},
            },
            .accept, .datagram => {},
        }
    }

    /// Housekeeping: start/restart connections and enforce the
    /// connect/handshake deadline. Called from the dispatch loop's
    /// housekeeping block (~100ms), right after proxy maintenance.
    pub fn tick(self: *PgClient, io_rt: *io_mod.IoRuntime, now_ms: u64) void {
        if (self.disabled) return;
        for (0..self.opts.pool_size) |i| {
            const idx: u32 = @intCast(i);
            const slot = &self.slots[i];
            switch (slot.state) {
                .closed => self.startConnect(io_rt, idx, now_ms),
                .failed => if (now_ms >= slot.retry_at_ms) self.startConnect(io_rt, idx, now_ms),
                .connecting, .handshaking => if (now_ms >= slot.deadline_ms) {
                    self.failSlot(io_rt, idx, now_ms, "connect/handshake timeout");
                },
                .ready => {},
                .busy => if (slot.op_park != NO_PARK and
                    self.parked[slot.op_park].active and
                    now_ms >= self.parked[slot.op_park].deadline_ms)
                {
                    // Deliver Timeout first, then recycle the PG
                    // connection: the wire op can't be cancelled, and
                    // detaching the park (op_park = NO_PARK below, via
                    // deliverOutcome) keeps failSlot's ConnectionLost
                    // path from double-firing.
                    self.deliverOutcome(slot.op_park, error.Timeout);
                    slot.op_park = NO_PARK;
                    self.failSlot(io_rt, idx, now_ms, "statement timeout");
                },
            }
        }
    }

    /// True when at least one pooled connection is authenticated and
    /// idle at ReadyForQuery.
    pub fn anyReady(self: *const PgClient) bool {
        for (self.slots[0..self.opts.pool_size]) |*slot| {
            if (slot.state == .ready) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Connection state machine
    // ------------------------------------------------------------------

    fn startConnect(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        const domain: c_uint = switch (self.addr.storage) {
            .ip4 => @intCast(std.posix.AF.INET),
            .ip6 => @intCast(std.posix.AF.INET6),
        };
        const fd = std.posix.system.socket(domain, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
        if (fd < 0) return self.failSlot(io_rt, idx, now_ms, "socket() failed");
        // SOCK_NONBLOCK / SOCK_CLOEXEC aren't portable to macOS — set
        // both via fcntl immediately after creation.
        net.setNonBlocking(fd) catch {
            clock.closeFd(fd);
            return self.failSlot(io_rt, idx, now_ms, "set O_NONBLOCK failed");
        };
        _ = std.c.fcntl(fd, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));
        net.setNoDelay(fd);

        var storage = self.addr.storage;
        const sockaddr_ptr: *const std.posix.sockaddr = switch (storage) {
            .ip4 => |*sa| @ptrCast(sa),
            .ip6 => |*sa| @ptrCast(sa),
        };
        const rc = std.posix.system.connect(fd, sockaddr_ptr, self.addr.len);
        const immediate = rc == 0;
        if (!immediate and std.posix.errno(rc) != .INPROGRESS) {
            clock.closeFd(fd);
            return self.failSlot(io_rt, idx, now_ms, "connect() failed");
        }
        slot.fd = fd;
        slot.deadline_ms = now_ms + CONNECT_TIMEOUT_MS;
        io_rt.registerExternalFd(idx, fd) catch |err| {
            clock.closeFd(fd);
            slot.fd = -1;
            if (err == error.UnsupportedBackend) {
                // io_uring backends can't carry external-fd tokens yet
                // (explicit follow-up step) — disable instead of
                // retrying an error that will never clear.
                self.disabled = true;
                slot.state = .closed;
                std.log.warn("postgres: external-fd dispatch is not supported on this I/O backend yet (io_uring); client disabled", .{});
                return;
            }
            return self.failSlot(io_rt, idx, now_ms, "event-loop registration failed");
        };
        if (immediate) {
            self.beginHandshake(io_rt, idx, now_ms);
        } else {
            slot.state = .connecting;
            io_rt.armExternalWritable(idx, fd) catch {
                return self.failSlot(io_rt, idx, now_ms, "arm writable failed");
            };
        }
    }

    /// Writable (or readable) in `.connecting`: the non-blocking connect
    /// finished — check SO_ERROR for the outcome.
    fn finishConnect(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        var err_val: c_int = 0;
        var err_len: std.posix.socklen_t = @sizeOf(c_int);
        const rc = std.posix.system.getsockopt(slot.fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&err_val), &err_len);
        if (rc != 0 or err_val != 0) {
            return self.failSlot(io_rt, idx, now_ms, "connect failed (SO_ERROR)");
        }
        self.beginHandshake(io_rt, idx, now_ms);
    }

    fn beginHandshake(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        // CSPRNG nonce; base64 output is printable ASCII without commas,
        // which is exactly what SCRAM requires.
        var raw: [NONCE_RAW_LEN]u8 = undefined;
        fillRandom(&raw);
        _ = std.base64.standard.Encoder.encode(&slot.nonce_buf, &raw);
        slot.handshake = pg.Handshake.init(.{
            .user = self.opts.user,
            .password = self.opts.password,
            .database = if (self.opts.database.len > 0) self.opts.database else null,
            .application_name = "swerver",
            .client_nonce = &slot.nonce_buf,
        });
        slot.state = .handshaking;
        slot.recv_len = 0;
        slot.send_len = 0;
        slot.send_off = 0;
        self.pumpSend(io_rt, idx, now_ms);
    }

    /// Serialize pending handshake messages into the slot's send buffer
    /// and write until done or EAGAIN (re-arming writable on a partial).
    const FlushResult = enum { drained, blocked, failed };

    /// Write send_buf[send_off..send_len] until done or EAGAIN. Shared
    /// by the handshake pump (which refills from takeSend) and the busy
    /// query path (whose buffer is filled once at query() time).
    fn flushSend(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) FlushResult {
        const slot = &self.slots[idx];
        while (slot.send_off < slot.send_len) {
            const raw = std.c.write(slot.fd, slot.send_buf[slot.send_off..].ptr, slot.send_len - slot.send_off);
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => {
                        io_rt.armExternalWritable(idx, slot.fd) catch {
                            self.failSlot(io_rt, idx, now_ms, "arm writable failed");
                            return .failed;
                        };
                        return .blocked;
                    },
                    .INTR => continue,
                    else => {
                        self.failSlot(io_rt, idx, now_ms, "socket write failed");
                        return .failed;
                    },
                }
            }
            slot.send_off += @intCast(raw);
        }
        slot.send_off = 0;
        slot.send_len = 0;
        return .drained;
    }

    fn pumpSend(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        while (true) {
            switch (self.flushSend(io_rt, idx, now_ms)) {
                .blocked, .failed => return,
                .drained => {},
            }
            if (slot.state != .handshaking) return;
            // TLS-only policy gate (design 9.0): never send a
            // cleartext password over an unencrypted link unless the
            // operator explicitly opted in. SCRAM proceeds normally.
            if (slot.handshake.pending_send == .password and !self.opts.allow_cleartext_password) {
                return self.failSlot(io_rt, idx, now_ms, "server requested a cleartext password without TLS; refusing (set allow_cleartext_password to override)");
            }
            const maybe_msg = slot.handshake.takeSend(&slot.send_buf) catch {
                return self.failSlot(io_rt, idx, now_ms, "handshake send failed");
            };
            const msg = maybe_msg orelse return;
            slot.send_len = msg.len; // msg aliases send_buf[0..len]
        }
    }

    /// Readable in `.handshaking`: read until EAGAIN (required for
    /// edge-triggered epoll), feeding the handshake after every read.
    fn handleReadable(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        while (slot.state == .handshaking) {
            if (slot.recv_len == slot.recv_buf.len) {
                return self.failSlot(io_rt, idx, now_ms, "handshake frame exceeds recv buffer");
            }
            const raw = std.posix.system.read(slot.fd, slot.recv_buf[slot.recv_len..].ptr, slot.recv_buf.len - slot.recv_len);
            if (raw == 0) {
                return self.failSlot(io_rt, idx, now_ms, "server closed connection during handshake");
            }
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => break,
                    .INTR => continue,
                    else => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                }
            }
            slot.recv_len += @intCast(raw);
            switch (ingest(slot, idx)) {
                .more => {},
                .ready => return,
                .failed => return self.failSlot(io_rt, idx, now_ms, "handshake failed"),
            }
            // The handshake may have queued a response (SASL round trip).
            self.pumpSend(io_rt, idx, now_ms);
        }
    }

    /// Readable in `.ready` (no op in flight): async backend messages
    /// (NoticeResponse, ParameterStatus) are read and discarded — a
    /// level-triggered backend would otherwise spin on the readiness.
    /// EOF means the server dropped us: reconnect.
    fn drainReady(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        var scratch: [512]u8 = undefined;
        while (true) {
            const raw = std.posix.system.read(slot.fd, &scratch, scratch.len);
            if (raw == 0) {
                return self.failSlot(io_rt, idx, now_ms, "server closed idle connection");
            }
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => return,
                    .INTR => continue,
                    else => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                }
            }
        }
    }

    // ── query / park (design 9.0 Handler API, phase 2.2b) ──────────

    /// Issue one extended-protocol query (Parse/Bind/Describe/Execute/
    /// Sync, unnamed statement, text params in, binary results out) on a
    /// ready slot, park the HTTP request, and return the park sentinel.
    /// One op per slot in flight (pipelining is a later step); one park
    /// per HTTP request.
    ///
    /// The continuation NEVER runs synchronously inside this call — a
    /// send failure here surfaces as error.NotConnected to the handler
    /// instead, because at this point the handler is still on the stack
    /// and the connection is not yet marked .db_parked.
    pub fn query(
        self: *PgClient,
        io_rt: *io_mod.IoRuntime,
        conn_index: u32,
        conn_id: u64,
        sql: []const u8,
        args: []const ?[]const u8,
        stash_bytes: []const u8,
        continuation: handler_api.Continuation,
    ) handler_api.QueryError!response_mod.Response {
        std.debug.assert(stash_bytes.len <= handler_api.STASH_CAPACITY);
        if (conn_index >= self.conn_parks.len) return error.NotConnected;
        if (self.conn_parks[conn_index] != NO_PARK) return error.AlreadyParked;

        var ready_idx: ?u32 = null;
        var any_busy = false;
        for (0..self.opts.pool_size) |i| {
            switch (self.slots[i].state) {
                .ready => {
                    ready_idx = @intCast(i);
                    break;
                },
                .busy => any_busy = true,
                else => {},
            }
        }
        const idx = ready_idx orelse return if (any_busy) error.QueueFull else error.NotConnected;
        const slot = &self.slots[idx];

        const park_idx: u16 = blk: {
            for (&self.parked, 0..) |*p, i| {
                if (!p.active) break :blk @intCast(i);
            }
            return error.ParkTableFull;
        };

        var off: usize = 0;
        off += (protocol.writeParse(slot.send_buf[off..], "", sql, &.{}) catch return error.RequestTooLarge).len;
        off += (protocol.writeBind(slot.send_buf[off..], "", "", args) catch return error.RequestTooLarge).len;
        off += (protocol.writeDescribePortal(slot.send_buf[off..], "") catch return error.RequestTooLarge).len;
        off += (protocol.writeExecute(slot.send_buf[off..], "", 0) catch return error.RequestTooLarge).len;
        off += (protocol.writeSync(slot.send_buf[off..]) catch return error.RequestTooLarge).len;

        const now_ms = io_rt.nowMs();
        const entry = &self.parked[park_idx];
        entry.* = .{
            .active = true,
            .conn_index = conn_index,
            .conn_id = conn_id,
            .continuation = continuation,
            .deadline_ms = now_ms + self.opts.statement_timeout_ms,
        };
        @memcpy(entry.stash[0..stash_bytes.len], stash_bytes);
        if (stash_bytes.len < entry.stash.len) @memset(entry.stash[stash_bytes.len..], 0);

        slot.send_off = 0;
        slot.send_len = off;
        slot.recv_len = 0;
        slot.op_rows = 0;
        slot.state = .busy;
        // Attach the park only after the initial flush: if the socket
        // dies right here, failSlot must NOT deliver ConnectionLost to a
        // continuation while the issuing handler is still running.
        slot.op_park = NO_PARK;
        switch (self.flushSend(io_rt, idx, now_ms)) {
            .drained, .blocked => {},
            .failed => {
                entry.active = false;
                return error.NotConnected;
            },
        }
        slot.op_park = park_idx;
        self.conn_parks[conn_index] = park_idx;
        return response_mod.Response.parked;
    }

    /// True when `conn_index` has a live park whose generation matches.
    /// The dispatch layer uses this to validate the park sentinel: a
    /// handler returning `Response.parked` without a matching live park
    /// is a programmer error answered with a 500.
    pub fn hasParkFor(self: *const PgClient, conn_index: u32, conn_id: u64) bool {
        if (conn_index >= self.conn_parks.len) return false;
        const park_idx = self.conn_parks[conn_index];
        if (park_idx == NO_PARK) return false;
        const entry = &self.parked[park_idx];
        return entry.active and entry.conn_id == conn_id;
    }

    /// The HTTP connection died (or was recycled) while parked: drop the
    /// park entry and detach any in-flight op. The op still runs to
    /// ReadyForQuery — its outcome is discarded — so the PG connection
    /// survives its requester.
    pub fn cancelForConn(self: *PgClient, conn_index: u32, conn_id: u64) void {
        if (conn_index >= self.conn_parks.len) return;
        const park_idx = self.conn_parks[conn_index];
        if (park_idx == NO_PARK) return;
        const entry = &self.parked[park_idx];
        if (!entry.active or entry.conn_id != conn_id) return;
        entry.active = false;
        entry.server_error = null;
        self.conn_parks[conn_index] = NO_PARK;
        for (&self.slots) |*slot| {
            if (slot.state == .busy and slot.op_park == park_idx) slot.op_park = NO_PARK;
        }
    }

    /// Readable in `.busy`: accumulate backend frames until
    /// ReadyForQuery, then deliver the outcome and return the slot to
    /// `.ready`. Result frames borrow recv_buf — valid only inside the
    /// resume callback; the region is poisoned (Debug) and reset after.
    fn pumpBusyRead(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        while (slot.state == .busy) {
            if (slot.recv_len == slot.recv_buf.len) {
                if (slot.op_park != NO_PARK) {
                    self.deliverOutcome(slot.op_park, error.ResultTooLarge);
                    slot.op_park = NO_PARK;
                }
                // The tail of the oversized result is still on the wire;
                // v1 recycles the connection rather than resyncing.
                return self.failSlot(io_rt, idx, now_ms, "result exceeded recv buffer");
            }
            const raw = std.posix.system.read(slot.fd, slot.recv_buf[slot.recv_len..].ptr, slot.recv_buf.len - slot.recv_len);
            if (raw == 0) {
                return self.failSlot(io_rt, idx, now_ms, "server closed connection mid-query");
            }
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => return,
                    .INTR => continue,
                    else => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                }
            }
            slot.recv_len += @intCast(raw);
            if (!self.scanBusyFrames(io_rt, idx, now_ms)) return;
        }
    }

    /// Walk the accumulated frames; returns true to keep reading (op
    /// still in flight and parse is healthy), false when done or the
    /// slot failed. On ReadyForQuery delivers the outcome inline.
    fn scanBusyFrames(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) bool {
        const slot = &self.slots[idx];
        var it = protocol.FrameIter.init(slot.recv_buf[0..slot.recv_len]);
        while (true) {
            const frame_start = it.offset;
            const maybe_frame = it.next() catch {
                self.failSlot(io_rt, idx, now_ms, "malformed backend frame mid-query");
                return false;
            };
            const frame = maybe_frame orelse return true; // need more bytes
            switch (frame.typ) {
                @intFromEnum(protocol.BackendType.error_response) => {
                    if (slot.op_park != NO_PARK) {
                        const info = protocol.parseErrorResponse(frame.payload) catch continue;
                        self.parked[slot.op_park].server_error = handler_api.ServerErrorInfo.capture(info);
                    }
                },
                @intFromEnum(protocol.BackendType.command_complete) => {
                    const cc = protocol.parseCommandComplete(frame.payload) catch continue;
                    slot.op_rows = cc.rows orelse 0;
                },
                @intFromEnum(protocol.BackendType.ready_for_query) => {
                    const park = slot.op_park;
                    slot.op_park = NO_PARK;
                    if (park != NO_PARK) {
                        if (self.parked[park].server_error != null) {
                            self.deliverOutcome(park, error.ServerError);
                        } else {
                            self.deliverOutcome(park, handler_api.Result{
                                .frames = slot.recv_buf[0..frame_start],
                                .rows_affected = slot.op_rows,
                            });
                        }
                    }
                    if (builtin.mode == .Debug) {
                        // Borrow-only contract: any Result slice that
                        // escaped the continuation now reads 0xAA.
                        @memset(slot.recv_buf[0..slot.recv_len], 0xAA);
                    }
                    slot.recv_len = 0;
                    slot.op_rows = 0;
                    slot.state = .ready;
                    return false;
                },
                else => {},
            }
        }
    }

    /// Run the resume hook for a parked request and free the entry.
    /// Reentrancy contract: conn_parks is cleared BEFORE the callback so
    /// a chaining continuation can re-park the same connection, and the
    /// entry stays allocated DURING the callback (the continuation's
    /// stash pointer borrows it) — a re-park scans for a different free
    /// entry because this one is still active.
    fn deliverOutcome(self: *PgClient, park_idx: u16, result: handler_api.PgError!handler_api.Result) void {
        const entry = &self.parked[park_idx];
        if (!entry.active) return;
        if (entry.conn_index < self.conn_parks.len and self.conn_parks[entry.conn_index] == park_idx) {
            self.conn_parks[entry.conn_index] = NO_PARK;
        }
        if (self.resume_fn) |rf| {
            const outcome = Outcome{
                .conn_index = entry.conn_index,
                .conn_id = entry.conn_id,
                .continuation = entry.continuation,
                .stash = &entry.stash,
                .result = result,
                .server_error = entry.server_error,
            };
            rf(self.resume_ctx.?, &outcome);
        } else {
            std.log.debug("pg: dropping op outcome (no resume hook installed)", .{});
        }
        entry.active = false;
        entry.server_error = null;
    }

    fn failSlot(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64, reason: []const u8) void {
        const slot = &self.slots[idx];
        if (slot.state == .busy and slot.op_park != NO_PARK) {
            const park = slot.op_park;
            slot.op_park = NO_PARK;
            self.deliverOutcome(park, error.ConnectionLost);
        }
        slot.op_park = NO_PARK;
        slot.op_rows = 0;
        if (slot.fd >= 0) {
            io_rt.unregisterExternalFd(slot.fd) catch {};
            clock.closeFd(slot.fd);
            slot.fd = -1;
        }
        scheduleRetry(slot, idx, now_ms, reason);
    }
};

/// OS CSPRNG (std.crypto.random is gone in Zig 0.16 stable — same
/// pattern as quic/connection.zig fillRandom).
fn fillRandom(buf: []u8) void {
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .openbsd => {
            std.c.arc4random_buf(buf.ptr, buf.len);
        },
        .linux => {
            _ = std.posix.system.getrandom(buf.ptr, buf.len, 0);
        },
        else => @compileError("unsupported OS for fillRandom"),
    }
}

const IngestResult = enum { more, ready, failed };

/// Feed buffered bytes into the slot's handshake and compact the
/// unconsumed tail (a partial backend frame) to the buffer front. Pure
/// slot-state transition — no I/O — so tests can drive it directly with
/// hand-split frames.
fn ingest(slot: *Slot, idx: u32) IngestResult {
    const consumed = slot.handshake.feed(slot.recv_buf[0..slot.recv_len]) catch |err| {
        if (err == error.ServerError) {
            if (slot.handshake.lastError()) |se| {
                std.log.warn("postgres: slot {d}: server error {s}: {s}", .{ idx, se.code(), se.message() });
            }
        } else {
            std.log.warn("postgres: slot {d}: handshake error: {}", .{ idx, err });
        }
        return .failed;
    };
    if (consumed > 0 and consumed < slot.recv_len) {
        std.mem.copyForwards(u8, slot.recv_buf[0 .. slot.recv_len - consumed], slot.recv_buf[consumed..slot.recv_len]);
    }
    slot.recv_len -= consumed;
    if (slot.handshake.isReady()) {
        slot.state = .ready;
        slot.backoff_ms = 0;
        std.log.info("postgres: slot {d}: connection ready (backend pid {d})", .{ idx, slot.handshake.backend_pid });
        return .ready;
    }
    return .more;
}

/// Close-side bookkeeping for a failed slot: 1s backoff doubling to a
/// 30s cap. Split from `failSlot` so the schedule is unit-testable
/// without an IoRuntime.
fn scheduleRetry(slot: *Slot, idx: u32, now_ms: u64, reason: []const u8) void {
    slot.state = .failed;
    slot.backoff_ms = if (slot.backoff_ms == 0)
        BACKOFF_INITIAL_MS
    else
        @min(slot.backoff_ms * 2, BACKOFF_MAX_MS);
    slot.retry_at_ms = now_ms + slot.backoff_ms;
    std.log.warn("postgres: slot {d}: {s}; reconnecting in {d} ms", .{ idx, reason, slot.backoff_ms });
}

// ---------------------------------------------------------------------------
// URL parsing — postgres://user[:password]@host[:port][/database][?sslmode=…]
// ---------------------------------------------------------------------------

pub const ParsedUrl = struct {
    user: []const u8,
    /// From `user:password@` if present. Discouraged — config uses
    /// password_env; this exists for test DSNs.
    password: []const u8 = "",
    host: []const u8,
    port: u16 = 5432,
    database: []const u8 = "",
    /// Raw sslmode query-parameter value; null when absent.
    sslmode: ?[]const u8 = null,
};

/// Parse a postgres:// (or postgresql://) URL. All slices borrow from
/// `url`. Bare IPv6 literals are not supported (use a hostname or
/// bracketless IPv4). Fails closed on anything malformed.
pub fn parseUrl(url: []const u8) error{InvalidUrl}!ParsedUrl {
    const rest = blk: {
        if (std.mem.startsWith(u8, url, "postgres://")) break :blk url["postgres://".len..];
        if (std.mem.startsWith(u8, url, "postgresql://")) break :blk url["postgresql://".len..];
        return error.InvalidUrl;
    };
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.InvalidUrl;
    const userinfo = rest[0..at];
    var out = ParsedUrl{ .user = userinfo, .host = "" };
    if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon| {
        out.user = userinfo[0..colon];
        out.password = userinfo[colon + 1 ..];
    }
    if (out.user.len == 0) return error.InvalidUrl;

    var hostpart = rest[at + 1 ..];
    if (std.mem.indexOfScalar(u8, hostpart, '?')) |q| {
        var it = std.mem.splitScalar(u8, hostpart[q + 1 ..], '&');
        while (it.next()) |pair| {
            if (std.mem.startsWith(u8, pair, "sslmode=")) {
                out.sslmode = pair["sslmode=".len..];
            }
        }
        hostpart = hostpart[0..q];
    }
    if (std.mem.indexOfScalar(u8, hostpart, '/')) |slash| {
        out.database = hostpart[slash + 1 ..];
        hostpart = hostpart[0..slash];
    }
    if (std.mem.lastIndexOfScalar(u8, hostpart, ':')) |colon| {
        out.port = std.fmt.parseInt(u16, hostpart[colon + 1 ..], 10) catch return error.InvalidUrl;
        out.host = hostpart[0..colon];
    } else {
        out.host = hostpart;
    }
    if (out.host.len == 0) return error.InvalidUrl;
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseUrl: full form with port, database, and sslmode" {
    const p = try parseUrl("postgres://app@db.internal:6432/orders?sslmode=disable");
    try testing.expectEqualStrings("app", p.user);
    try testing.expectEqualStrings("", p.password);
    try testing.expectEqualStrings("db.internal", p.host);
    try testing.expectEqual(@as(u16, 6432), p.port);
    try testing.expectEqualStrings("orders", p.database);
    try testing.expectEqualStrings("disable", p.sslmode.?);
}

test "parseUrl: defaults and postgresql scheme" {
    const p = try parseUrl("postgresql://alice@localhost");
    try testing.expectEqualStrings("alice", p.user);
    try testing.expectEqualStrings("localhost", p.host);
    try testing.expectEqual(@as(u16, 5432), p.port);
    try testing.expectEqualStrings("", p.database);
    try testing.expectEqual(@as(?[]const u8, null), p.sslmode);
}

test "parseUrl: password in userinfo and extra query params" {
    const p = try parseUrl("postgres://u:s3cret@10.0.0.5:5433/db?application_name=x&sslmode=verify-full");
    try testing.expectEqualStrings("u", p.user);
    try testing.expectEqualStrings("s3cret", p.password);
    try testing.expectEqualStrings("10.0.0.5", p.host);
    try testing.expectEqual(@as(u16, 5433), p.port);
    try testing.expectEqualStrings("db", p.database);
    try testing.expectEqualStrings("verify-full", p.sslmode.?);
}

test "parseUrl: bad inputs fail closed" {
    // Wrong scheme.
    try testing.expectError(error.InvalidUrl, parseUrl("mysql://u@h/db"));
    // No userinfo separator.
    try testing.expectError(error.InvalidUrl, parseUrl("postgres://hostonly:5432/db"));
    // Empty user.
    try testing.expectError(error.InvalidUrl, parseUrl("postgres://:pw@h/db"));
    // Empty host.
    try testing.expectError(error.InvalidUrl, parseUrl("postgres://u@:5432/db"));
    try testing.expectError(error.InvalidUrl, parseUrl("postgres://u@"));
    // Bad port.
    try testing.expectError(error.InvalidUrl, parseUrl("postgres://u@h:notaport/db"));
    try testing.expectError(error.InvalidUrl, parseUrl("postgres://u@h:99999/db"));
}

test "backoff schedule: 1s doubling to a 30s cap, reset on ready" {
    // scheduleRetry logs at warn; keep the test runner's stderr clean.
    const saved_log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = saved_log_level;

    var slot = Slot{};
    const expected = [_]u64{ 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000 };
    var now: u64 = 100;
    for (expected) |want| {
        scheduleRetry(&slot, 0, now, "test");
        try testing.expectEqual(SlotState.failed, slot.state);
        try testing.expectEqual(want, slot.backoff_ms);
        try testing.expectEqual(now + want, slot.retry_at_ms);
        now += want;
    }
    // ingest() zeroes backoff_ms on ready; the next failure starts over.
    slot.backoff_ms = 0;
    scheduleRetry(&slot, 0, now, "test");
    try testing.expectEqual(BACKOFF_INITIAL_MS, slot.backoff_ms);
}

/// Append a backend frame to `buf` at `off`; returns the new offset.
fn putFrame(buf: []u8, off: usize, typ: u8, payload: []const u8) usize {
    buf[off] = typ;
    std.mem.writeInt(u32, buf[off + 1 ..][0..4], @intCast(4 + payload.len), .big);
    @memcpy(buf[off + 5 .. off + 5 + payload.len], payload);
    return off + 5 + payload.len;
}

fn putAuthFrame(buf: []u8, off: usize, auth_code: u32, data: []const u8) usize {
    buf[off] = 'R';
    std.mem.writeInt(u32, buf[off + 1 ..][0..4], @intCast(8 + data.len), .big);
    std.mem.writeInt(u32, buf[off + 5 ..][0..4], auth_code, .big);
    @memcpy(buf[off + 9 .. off + 9 + data.len], data);
    return off + 9 + data.len;
}

test "ingest: partial frame split across reads is compacted to the front" {
    var slot = Slot{};
    slot.handshake = pg.Handshake.init(.{
        .user = "u",
        .password = "p",
        .client_nonce = "testnonce0000000",
    });
    var scratch: [256]u8 = undefined;
    _ = (try slot.handshake.takeSend(&scratch)).?; // drain startup → .auth
    slot.state = .handshaking;

    var frames: [64]u8 = undefined;
    var off = putAuthFrame(&frames, 0, 0, ""); // AuthenticationOk
    const auth_len = off;
    off = putFrame(&frames, off, 'Z', "I"); // ReadyForQuery

    // First "read": everything but the final byte. Only the complete
    // auth frame is consumed; the partial RFQ tail must move to front.
    const first = off - 1;
    @memcpy(slot.recv_buf[0..first], frames[0..first]);
    slot.recv_len = first;
    try testing.expectEqual(IngestResult.more, ingest(&slot, 0));
    try testing.expectEqual(first - auth_len, slot.recv_len);
    try testing.expectEqualSlices(u8, frames[auth_len..first], slot.recv_buf[0..slot.recv_len]);

    // Second "read" appends the final byte; the handshake completes and
    // the buffer fully drains.
    slot.recv_buf[slot.recv_len] = frames[off - 1];
    slot.recv_len += 1;
    try testing.expectEqual(IngestResult.ready, ingest(&slot, 0));
    try testing.expectEqual(@as(usize, 0), slot.recv_len);
    try testing.expectEqual(SlotState.ready, slot.state);
    try testing.expectEqual(@as(u64, 0), slot.backoff_ms);
}

test "ingest: server ErrorResponse fails the slot" {
    const saved_log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = saved_log_level;

    var slot = Slot{};
    slot.handshake = pg.Handshake.init(.{
        .user = "u",
        .password = "p",
        .client_nonce = "testnonce0000000",
    });
    var scratch: [256]u8 = undefined;
    _ = (try slot.handshake.takeSend(&scratch)).?;
    slot.state = .handshaking;

    var frames: [128]u8 = undefined;
    const off = putFrame(&frames, 0, 'E', "SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00");
    @memcpy(slot.recv_buf[0..off], frames[0..off]);
    slot.recv_len = off;
    try testing.expectEqual(IngestResult.failed, ingest(&slot, 0));
}

// ---------------------------------------------------------------------------
// Live integration test (PG_TEST_DSN gated): proves the full chain —
// registerExternalFd → kqueue/epoll → EXTERNAL_ID_BIT token through
// pollWithTimeout → onEvent → SCRAM handshake to ready — against a real
// PostgreSQL server, with the REAL IoRuntime backend doing the dispatch.
// ---------------------------------------------------------------------------

test "integration: reactor-driven connection bring-up (PG_TEST_DSN)" {
    const dsn_z = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn = try parseUrl(std.mem.sliceTo(dsn_z, 0));

    const config_mod = @import("../../config.zig");
    var cfg = config_mod.ServerConfig.default();
    cfg.max_connections = 16;
    cfg.buffer_pool = .{
        .buffer_size = 4096,
        .buffer_count = 32,
        .body_buffer_size = 4096,
        .body_buffer_count = 2,
    };

    var rt = try io_mod.IoRuntime.init(testing.allocator, cfg);
    defer rt.deinit();
    switch (rt.backend) {
        .bsd_kqueue, .linux_epoll => {},
        // External fds need the readiness backends (io_uring follow-up).
        else => return error.SkipZigTest,
    }

    var client = try PgClient.init(testing.allocator, cfg.max_connections, .{
        .host = dsn.host,
        .port = dsn.port,
        .user = dsn.user,
        .database = dsn.database,
        .password = dsn.password,
        .pool_size = 2,
    });
    defer client.deinit(&rt);

    const deadline = rt.nowMs() + 10_000;
    var all_ready = false;
    while (rt.nowMs() < deadline and !all_ready) {
        client.tick(&rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            // Mirror of the dispatch-loop external branch.
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(&rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
        all_ready = true;
        for (client.slots[0..client.opts.pool_size]) |*slot| {
            if (slot.state != .ready) all_ready = false;
        }
    }
    try testing.expect(all_ready);
    try testing.expect(client.anyReady());
    for (client.slots[0..client.opts.pool_size]) |*slot| {
        try testing.expect(slot.handshake.backend_pid != 0);
    }

    // ── Live query through the park machinery ──────────────────────
    // The Hook mirrors what the http1 resume layer (phase 2.2b piece 2)
    // does: build a ResumeContext from the Outcome, run the
    // continuation, observe its Response.
    const Stash = struct { magic: u64 = 0 };
    const Hook = struct {
        var ran: bool = false;
        var status: u16 = 0;
        var row_count: u64 = 0;
        var sum: i64 = 0;
        var rows_affected: u64 = 0;
        var stash_magic: u64 = 0;

        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            var buf: [256]u8 = undefined;
            var rctx = handler_api.ResumeContext{
                .result = outcome.result,
                .server_error = outcome.server_error,
                .response_buf = &buf,
                .response_headers = &.{},
                .arena = std.heap.FixedBufferAllocator.init(&.{}),
                .stash_bytes = outcome.stash,
                .repark_ctx = undefined,
                .repark_fn = undefined,
            };
            ran = true;
            if (outcome.result) |res| {
                rows_affected = res.rows_affected;
            } else |_| {}
            status = outcome.continuation(&rctx).status;
        }

        fn cont(rctx: *handler_api.ResumeContext) response_mod.Response {
            stash_magic = rctx.stash(Stash).magic;
            const res = rctx.result catch return .{ .status = 500, .headers = &.{}, .body = .none };
            var rows = res.rows();
            while (rows.next()) |row| {
                sum += row.int4(0) catch -1_000_000;
                row_count += 1;
            }
            return .{ .status = 200, .headers = &.{}, .body = .none };
        }
    };
    var dummy: u8 = 0;
    client.installResume(@ptrCast(&dummy), Hook.onResume);

    const stash = Stash{ .magic = 0xDEAD_BEEF };
    const sentinel = try client.query(&rt, 5, 777, "select generate_series(1, 3)", &.{}, std.mem.asBytes(&stash), Hook.cont);
    try testing.expect(sentinel.isParked());

    const q_deadline = rt.nowMs() + 5_000;
    while (rt.nowMs() < q_deadline and !Hook.ran) {
        client.tick(&rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(&rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
    }
    try testing.expect(Hook.ran);
    try testing.expectEqual(@as(u16, 200), Hook.status);
    try testing.expectEqual(@as(u64, 3), Hook.row_count);
    try testing.expectEqual(@as(i64, 6), Hook.sum);
    try testing.expectEqual(@as(u64, 3), Hook.rows_affected);
    try testing.expectEqual(@as(u64, 0xDEAD_BEEF), Hook.stash_magic);
    // Park bookkeeping released; slot back to ready.
    try testing.expectEqual(NO_PARK, client.conn_parks[5]);
    try testing.expect(client.anyReady());

    // Server-side error path: bad SQL must deliver error.ServerError
    // with a captured SQLSTATE, and the slot must recover to ready.
    const Hook2 = struct {
        var ran: bool = false;
        var got_server_error: bool = false;
        var sqlstate: [5]u8 = undefined;

        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            ran = true;
            if (outcome.result) |_| {} else |err| {
                got_server_error = (err == error.ServerError);
            }
            if (outcome.server_error) |se| sqlstate = se.sqlstate;
        }
    };
    client.installResume(@ptrCast(&dummy), Hook2.onResume);
    _ = try client.query(&rt, 6, 778, "select bogus syntax here", &.{}, &.{}, Hook.cont);
    const e_deadline = rt.nowMs() + 5_000;
    while (rt.nowMs() < e_deadline and !Hook2.ran) {
        client.tick(&rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(&rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
    }
    try testing.expect(Hook2.ran);
    try testing.expect(Hook2.got_server_error);
    // 42601 = syntax_error
    try testing.expectEqualSlices(u8, "42601", &Hook2.sqlstate);
    try testing.expect(client.anyReady());
}

test "park table: cancelForConn generation check, detach, and hookless delivery" {
    var client = try PgClient.init(testing.allocator, 8, .{ .host = "127.0.0.1", .user = "u" });
    defer testing.allocator.free(client.conn_parks);

    // Simulate a parked op in flight on slot 0.
    client.slots[0].state = .busy;
    client.slots[0].op_park = 0;
    client.parked[0] = .{ .active = true, .conn_index = 3, .conn_id = 42, .continuation = undefined };
    client.conn_parks[3] = 0;

    // Wrong generation (recycled conn slot): must be a no-op.
    client.cancelForConn(3, 41);
    try testing.expect(client.parked[0].active);

    // Right generation: entry freed, token cleared, op detached.
    client.cancelForConn(3, 42);
    try testing.expect(!client.parked[0].active);
    try testing.expectEqual(NO_PARK, client.conn_parks[3]);
    try testing.expectEqual(NO_PARK, client.slots[0].op_park);

    // deliverOutcome on the now-inactive entry: harmless.
    client.deliverOutcome(0, error.Timeout);

    // Active entry with no resume hook installed: dropped and freed.
    client.parked[1] = .{ .active = true, .conn_index = 2, .conn_id = 9, .continuation = undefined };
    client.conn_parks[2] = 1;
    client.deliverOutcome(1, error.Timeout);
    try testing.expect(!client.parked[1].active);
    try testing.expectEqual(NO_PARK, client.conn_parks[2]);
}
