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
const build_options = @import("build_options");
const io_mod = @import("../../runtime/io.zig");
const net = @import("../../runtime/net.zig");
const clock = @import("../../runtime/clock.zig");
const config_mod = @import("../../config.zig");
const tls_mod = @import("../../tls/provider.zig");
const response_mod = @import("../../response/response.zig");
const pg = @import("pg.zig");
const protocol = @import("protocol.zig");
const handler_api = @import("handler_api.zig");

/// TLS policy — defined next to the rest of the config surface.
pub const SslMode = config_mod.PgSslMode;

/// Hard cap on per-worker connections (design 9.0: pool of 2–4).
pub const MAX_SLOTS = 4;
pub const DEFAULT_POOL_SIZE = 2;

/// Bound on concurrently parked requests per worker. A parked request
/// holds one table entry (continuation + stash + deadline); when the
/// table is full, query() sheds load synchronously with ParkTableFull.
pub const MAX_PARKED = 64;
/// Sentinel for "no park" in op rings and the per-conn token array.
const NO_PARK: u16 = std.math.maxInt(u16);

/// Pipelining depth: ops in flight per connection (design 9.0 phase 4).
/// Each op carries its own Sync, so ops are protocol-independent — an
/// ErrorResponse consumes only its own op's frames through its own
/// ReadyForQuery and the next op proceeds normally.
pub const OP_QUEUE_DEPTH = 16;
/// Per-connection prepared-statement cache entries (named statements
/// s00..s31). Full cache degrades to unnamed Parse-per-op, never evicts.
pub const STMT_CACHE_SIZE = 32;
const NO_CACHE: u8 = 0xFF;

/// Sized for the worst-case TFB batch op (500 Bind/Execute pairs ≈
/// 18KB out, ≈ 20KB of BindComplete/DataRow/CommandComplete back).
const RECV_BUF_SIZE = 32 * 1024;
const SEND_BUF_SIZE = 32 * 1024;
/// Bind/Execute pairs allowed in one batch op (TFB clamps at 500).
pub const MAX_BATCH = 500;
/// Single deadline covering non-blocking connect + handshake.
const CONNECT_TIMEOUT_MS: u64 = 10_000;
const BACKOFF_INITIAL_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 30_000;
/// 18 random bytes -> 24 base64 chars (printable ASCII, no commas).
const NONCE_RAW_LEN = 18;
const NONCE_LEN = 24;

pub const SlotState = enum {
    closed,
    connecting,
    /// SSLRequest sent; awaiting the server's single-byte 'S'/'N' verdict.
    ssl_request,
    /// TLS handshake in flight over the memory-BIO session.
    tls_handshaking,
    handshaking,
    ready,
    busy,
    failed,
};

/// Why the last TLS bring-up on a slot failed — gives the log lines (and
/// the integration tests) distinct causes instead of one mushy
/// "handshake failed".
pub const TlsFailure = enum {
    none,
    /// Server answered 'N' to the SSLRequest.
    refused,
    /// Handshake failed without a certificate-verification complaint.
    handshake,
    /// Certificate chain did not verify against the trust store.
    chain,
    /// Chain verified but the certificate doesn't match the host.
    hostname,
};

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
    /// In-flight op ring (FIFO). Extended-protocol responses arrive
    /// strictly in submission order; the head op owns all frames up to
    /// the next ReadyForQuery. `.busy` ⇔ op_count > 0.
    ops: [OP_QUEUE_DEPTH]InFlightOp = [1]InFlightOp{.{}} ** OP_QUEUE_DEPTH,
    op_head: u8 = 0,
    op_count: u8 = 0,
    /// Prepared-statement cache: Wyhash of the SQL, by named-statement
    /// index (s00..s31). valid bits gate lookup; entries are claimed
    /// optimistically at query() time (so two queued ops can't both
    /// Parse the same name) and invalidated if the claiming op fails.
    stmt_hashes: [STMT_CACHE_SIZE]u64 = [1]u64{0} ** STMT_CACHE_SIZE,
    stmt_valid: u32 = 0,
    /// TLS session (memory BIOs) once the server accepts the SSLRequest;
    /// null on the plaintext path. Every transport touchpoint branches
    /// on this once — the sslmode=disable byte path is unchanged.
    tls: ?tls_mod.Session = null,
    /// Diagnostic: why the last TLS bring-up failed (sticky across the
    /// retry backoff; reset when the next connect attempt starts).
    tls_fail: TlsFailure = .none,
    /// Set once the slot has run its one-time discard query after first
    /// reaching `.ready`. Works around a first-query readiness gap on the
    /// native io_uring one-shot external poll (epoll's persistent
    /// registration masks it). Reset on every (re)connect. See primeSlot.
    primed: bool = false,

    fn opAt(self: *Slot, i: u8) *InFlightOp {
        return &self.ops[(self.op_head +% i) % OP_QUEUE_DEPTH];
    }
};

/// One pipelined op: a Parse?/Bind/Describe/Execute/Sync unit awaiting
/// its ReadyForQuery.
const InFlightOp = struct {
    /// Park-table index of the awaiting request; NO_PARK when the
    /// requester vanished (the op drains and its outcome is discarded).
    park: u16 = NO_PARK,
    /// Rows-affected parsed from this op's CommandComplete.
    rows: u64 = 0,
    /// Statement-cache slot this op's Parse populates (NO_CACHE when
    /// the op used a cached or unnamed statement).
    cache_slot: u8 = NO_CACHE,
};

/// Named-statement identifiers for the per-connection cache.
const stmt_names: [STMT_CACHE_SIZE][3]u8 = blk: {
    var names: [STMT_CACHE_SIZE][3]u8 = undefined;
    for (&names, 0..) |*n, i| {
        n.* = .{ 's', '0' + @as(u8, i / 10), '0' + @as(u8, i % 10) };
    }
    break :blk names;
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
    /// Failure outcome staged for tick-time delivery (Timeout /
    /// ConnectionLost). Failure paths can trigger inside query() — with
    /// a synchronous delivery, another request's continuation would run
    /// under the current handler's stack frame. Deferring ALL failure
    /// deliveries to tick (≤100ms) makes that reentrancy impossible.
    pending_error: ?handler_api.PgError = null,
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
    /// request over a PLAINTEXT link. Off by default: the spec's policy
    /// (cleartext only over TLS) fails the connection instead. Over an
    /// established TLS channel the request is always answered — the
    /// channel is encrypted. SCRAM is unaffected either way.
    allow_cleartext_password: bool = false,
    /// TLS policy (design 9.0 phase 3). verify_full — chain + hostname —
    /// is the fail-safe default; `require` encrypts without verifying
    /// (discouraged); `disable` never sends the SSLRequest. Anything
    /// other than disable needs a client TLS provider via installTls.
    sslmode: SslMode = .verify_full,
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
    /// Client-mode TLS provider (server-owned, see Server.pg_tls_provider;
    /// installed before the loop runs). Required when sslmode != disable —
    /// slots fail closed without it.
    tls_provider: ?*tls_mod.Provider = null,

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

    /// Install the client TLS provider (server init, before the loop
    /// runs; mirrors installResume). The provider must outlive the
    /// client — slot sessions borrow its SSL_CTX.
    pub fn installTls(self: *PgClient, provider: *tls_mod.Provider) void {
        self.tls_provider = provider;
    }

    pub fn deinit(self: *PgClient, io_rt: *io_mod.IoRuntime) void {
        for (&self.slots) |*slot| {
            if (slot.tls) |*sess| {
                sess.deinit();
                slot.tls = null;
            }
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
                // .ssl_request: the 8-byte SSLRequest blocked mid-write
                // (tls is still null there — flushOut is the raw path).
                // .tls_handshaking: drain pending wbio ciphertext.
                .ssl_request, .tls_handshaking => _ = self.flushOut(io_rt, slot_idx, now_ms),
                .handshaking => self.pumpSend(io_rt, slot_idx, now_ms),
                .busy => _ = self.flushOut(io_rt, slot_idx, now_ms),
                else => {},
            },
            .read => switch (slot.state) {
                // Readability can race ahead of the writable arm —
                // treat a read in .connecting as connect completion.
                .connecting => {
                    self.finishConnect(io_rt, slot_idx, now_ms);
                    switch (slot.state) {
                        .handshaking => self.handleReadable(io_rt, slot_idx, now_ms),
                        .ssl_request => self.handleSslReply(io_rt, slot_idx, now_ms),
                        else => {},
                    }
                },
                .ssl_request => self.handleSslReply(io_rt, slot_idx, now_ms),
                .tls_handshaking => self.tlsHandshakeRead(io_rt, slot_idx, now_ms),
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
                .connecting, .ssl_request, .tls_handshaking, .handshaking => if (now_ms >= slot.deadline_ms) {
                    self.failSlot(io_rt, idx, now_ms, "connect/handshake timeout");
                },
                .ready => {},
                .busy => {
                    // Head-of-FIFO timeout check: ops share one
                    // statement_timeout, so the head always has the
                    // earliest deadline. A wire op can't be cancelled —
                    // mark the head Timeout, then recycle the
                    // connection (failSlot stages ConnectionLost for
                    // the ops queued behind it).
                    const head = slot.opAt(0);
                    if (slot.op_count > 0 and head.park != NO_PARK and
                        self.parked[head.park].active and
                        now_ms >= self.parked[head.park].deadline_ms)
                    {
                        self.parked[head.park].pending_error = error.Timeout;
                        head.park = NO_PARK;
                        self.failSlot(io_rt, idx, now_ms, "statement timeout");
                    }
                },
            }
        }

        // Deliver failure outcomes staged by failSlot/timeout. Done here
        // — never inside query() or failSlot — so a continuation can
        // never run beneath an in-progress handler's stack frame.
        for (&self.parked, 0..) |*entry, pi| {
            if (!entry.active) continue;
            const err = entry.pending_error orelse continue;
            entry.pending_error = null;
            self.deliverOutcome(@intCast(pi), err);
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
        slot.tls_fail = .none;
        slot.primed = false;
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
            self.afterConnect(io_rt, idx, now_ms);
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
        self.afterConnect(io_rt, idx, now_ms);
    }

    /// TCP is up: plaintext goes straight to the PG startup exchange;
    /// any TLS mode opens with the SSLRequest dance first.
    fn afterConnect(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        if (!wantsSslRequest(self.opts.sslmode)) {
            return self.beginHandshake(io_rt, idx, now_ms);
        }
        self.sendSslRequest(io_rt, idx, now_ms);
    }

    /// sslmode=disable never sends the SSLRequest; require/verify-full
    /// always do (and treat the 'N' refusal as fatal — there is no
    /// opportunistic "prefer" mode, see SslMode).
    fn wantsSslRequest(mode: SslMode) bool {
        return mode != .disable;
    }

    /// Send the 8-byte SSLRequest (before the startup message) and wait
    /// for the server's single-byte verdict.
    fn sendSslRequest(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        slot.state = .ssl_request;
        slot.recv_len = 0;
        slot.send_off = 0;
        // send_buf is 4KB; an 8-byte message cannot fail to serialize.
        const msg = protocol.writeSslRequest(&slot.send_buf) catch unreachable;
        slot.send_len = msg.len;
        // Raw flush — no TLS session exists yet.
        _ = self.flushSend(io_rt, idx, now_ms);
    }

    const SslReply = enum { start_tls, refused, protocol_error };

    /// The server's SSLRequest verdict: 'S' → TLS ClientHello next on
    /// this same socket; 'N' → the server cannot/will not do TLS, which
    /// is fatal under require/verify-full (the only modes that send the
    /// SSLRequest at all); anything else is a protocol violation.
    fn classifySslReply(b: u8) SslReply {
        return switch (b) {
            'S' => .start_tls,
            'N' => .refused,
            else => .protocol_error,
        };
    }

    /// Readable in `.ssl_request`: read the one-byte verdict. Exactly one
    /// byte — the server sends nothing further until our ClientHello, so
    /// anything after it would be a protocol violation anyway.
    fn handleSslReply(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        var reply: [1]u8 = undefined;
        while (true) {
            const raw = std.posix.system.read(slot.fd, &reply, 1);
            if (raw == 0) {
                return self.failSlot(io_rt, idx, now_ms, "server closed connection awaiting SSLRequest reply");
            }
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => return,
                    .INTR => continue,
                    else => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                }
            }
            break;
        }
        switch (classifySslReply(reply[0])) {
            .start_tls => self.beginTls(io_rt, idx, now_ms),
            .refused => {
                slot.tls_fail = .refused;
                self.failSlot(io_rt, idx, now_ms, "server refused TLS ('N' SSLRequest reply) but sslmode requires it");
            },
            .protocol_error => self.failSlot(io_rt, idx, now_ms, "unexpected SSLRequest reply byte"),
        }
    }

    /// 'S' received: build the client TLS session (memory BIOs) and kick
    /// the handshake. verify-full pins the configured host into the
    /// session for hostname/IP verification.
    fn beginTls(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        const provider = self.tls_provider orelse {
            return self.failSlot(io_rt, idx, now_ms, "sslmode requires TLS but no client TLS provider is installed (TLS disabled in this build?)");
        };
        var host_z: [256]u8 = undefined;
        if (self.opts.host.len >= host_z.len) {
            return self.failSlot(io_rt, idx, now_ms, "host too long for TLS verification");
        }
        @memcpy(host_z[0..self.opts.host.len], self.opts.host);
        host_z[self.opts.host.len] = 0;
        const host: [:0]const u8 = host_z[0..self.opts.host.len :0];
        // SSL_set1_host / SNI copy the name — host_z may be stack-local.
        const session = provider.createTcpClientSession(host, self.opts.sslmode == .verify_full) catch {
            return self.failSlot(io_rt, idx, now_ms, "TLS session creation failed");
        };
        slot.tls = session;
        slot.state = .tls_handshaking;
        slot.recv_len = 0;
        self.driveTls(io_rt, idx, now_ms);
    }

    /// Advance the TLS handshake: SSL_do_handshake against the memory
    /// BIOs, then drain wbio ciphertext to the socket. On completion the
    /// PG startup exchange begins over the encrypted channel; on failure
    /// the verify result splits the cause three ways for the log.
    fn driveTls(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        const sess = &slot.tls.?;
        switch (sess.doHandshake()) {
            .in_progress => _ = self.flushOut(io_rt, idx, now_ms),
            .complete => {
                sess.handshake_complete = true;
                switch (self.flushOut(io_rt, idx, now_ms)) {
                    .failed => return,
                    // .blocked is fine: the client Finished flight sits
                    // staged in send_buf and beginHandshake preserves it.
                    .drained, .blocked => {},
                }
                self.beginHandshake(io_rt, idx, now_ms);
            },
            .failed => switch (sess.verifyFailureCause()) {
                .chain => {
                    slot.tls_fail = .chain;
                    std.log.warn("postgres: slot {d}: certificate chain verification failed: {s}", .{ idx, sess.verifyErrorString() });
                    self.failSlot(io_rt, idx, now_ms, "TLS certificate chain verification failed (set ssl_root_cert to the server's CA)");
                },
                .hostname_mismatch => {
                    slot.tls_fail = .hostname;
                    self.failSlot(io_rt, idx, now_ms, "TLS hostname verification failed (certificate does not match the configured host)");
                },
                .ok => {
                    slot.tls_fail = .handshake;
                    self.failSlot(io_rt, idx, now_ms, "TLS handshake failed");
                },
            },
        }
    }

    /// Readable in `.tls_handshaking`: drain the socket into the rbio
    /// (mandatory-to-EAGAIN for edge-triggered epoll), then advance.
    fn tlsHandshakeRead(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        const sess = &slot.tls.?;
        while (true) {
            var cbuf: [4096]u8 = undefined;
            const raw = std.posix.system.read(slot.fd, &cbuf, cbuf.len);
            if (raw == 0) {
                return self.failSlot(io_rt, idx, now_ms, "server closed connection during TLS handshake");
            }
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => break,
                    .INTR => continue,
                    else => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                }
            }
            const n: usize = @intCast(raw);
            var fed: usize = 0;
            while (fed < n) {
                fed += sess.feedCryptoData(cbuf[fed..n]) catch {
                    return self.failSlot(io_rt, idx, now_ms, "TLS receive buffer feed failed");
                };
            }
        }
        self.driveTls(io_rt, idx, now_ms);
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
        // Don't clobber staged-but-unflushed bytes: on the TLS path the
        // final handshake flight may still sit in send_buf if the socket
        // blocked mid-flush (flushSend zeroes both fields once drained).
        if (slot.send_off == slot.send_len) {
            slot.send_len = 0;
            slot.send_off = 0;
        }
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

    /// TLS-aware flush. Plaintext slots go straight to flushSend — the
    /// raw fast path costs one null check. TLS slots alternate between
    /// pulling ciphertext out of the session's wbio into send_buf and
    /// writing it to the socket; a partial write leaves the remainder
    /// staged in send_buf (flushSend's normal EAGAIN handling) and the
    /// rest queued in the wbio for the next writable event.
    fn flushOut(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) FlushResult {
        const slot = &self.slots[idx];
        if (slot.tls == null) return self.flushSend(io_rt, idx, now_ms);
        while (true) {
            switch (self.flushSend(io_rt, idx, now_ms)) {
                .blocked => return .blocked,
                .failed => return .failed,
                .drained => {},
            }
            const n = slot.tls.?.readCryptoData(&slot.send_buf) catch {
                self.failSlot(io_rt, idx, now_ms, "TLS send buffer drain failed");
                return .failed;
            };
            if (n == 0) return .drained;
            slot.send_off = 0;
            slot.send_len = n;
        }
    }

    /// Encrypt plaintext into the session's wbio (whence flushOut moves
    /// it to the socket). SSL_write copies, so `plain` may alias
    /// send_buf — which is then reclaimed as the ciphertext staging
    /// area. Returns false after failing the slot.
    fn stageTls(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64, plain: []const u8) bool {
        const slot = &self.slots[idx];
        const sess = &slot.tls.?;
        var off: usize = 0;
        while (off < plain.len) {
            const n = sess.write(plain[off..]) catch 0;
            if (n == 0) {
                self.failSlot(io_rt, idx, now_ms, "TLS write failed");
                return false;
            }
            off += n;
        }
        slot.send_len = 0;
        slot.send_off = 0;
        return true;
    }

    /// Cleartext-password policy (design 9.0): always acceptable over an
    /// established TLS channel (encrypted; server-authenticated under
    /// verify-full). Over plaintext only with the explicit operator
    /// opt-in. SCRAM never consults this — it never reveals the password.
    fn cleartextPasswordAllowed(tls_active: bool, opt_in: bool) bool {
        return tls_active or opt_in;
    }

    fn pumpSend(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        while (true) {
            switch (self.flushOut(io_rt, idx, now_ms)) {
                .blocked, .failed => return,
                .drained => {},
            }
            if (slot.state != .handshaking) return;
            if (slot.handshake.pending_send == .password and
                !cleartextPasswordAllowed(slot.tls != null, self.opts.allow_cleartext_password))
            {
                return self.failSlot(io_rt, idx, now_ms, "server requested a cleartext password without TLS; refusing (set allow_cleartext_password to override)");
            }
            const maybe_msg = slot.handshake.takeSend(&slot.send_buf) catch {
                return self.failSlot(io_rt, idx, now_ms, "handshake send failed");
            };
            const msg = maybe_msg orelse return;
            if (slot.tls != null) {
                // Encrypt into the wbio; the next loop iteration's
                // flushOut pulls the ciphertext back through send_buf.
                if (!self.stageTls(io_rt, idx, now_ms, msg)) return;
            } else {
                slot.send_len = msg.len; // msg aliases send_buf[0..len]
            }
        }
    }

    const ReadStatus = enum { data, would_block, closed, failed };

    /// Pull transport bytes into recv_buf[recv_len..]. Plaintext slots:
    /// one read(2) per call — callers loop until .would_block, exactly
    /// the pre-TLS shape. TLS slots: drain the socket into the rbio,
    /// then drain decrypted plaintext out of the session.
    fn fillRecv(self: *PgClient, idx: u32) ReadStatus {
        const slot = &self.slots[idx];
        if (slot.tls != null) return self.fillRecvTls(idx);
        while (true) {
            const raw = std.posix.system.read(slot.fd, slot.recv_buf[slot.recv_len..].ptr, slot.recv_buf.len - slot.recv_len);
            if (raw == 0) return .closed;
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => return .would_block,
                    .INTR => continue,
                    else => return .failed,
                }
            }
            slot.recv_len += @intCast(raw);
            return .data;
        }
    }

    /// TLS arm of fillRecv. The socket MUST be drained to EAGAIN before
    /// returning (edge-triggered epoll) — ciphertext parks in the rbio,
    /// which grows as needed, so this never stalls on recv_buf space.
    /// Post-handshake records the session absorbs without producing
    /// plaintext (session tickets, key updates) are handled implicitly:
    /// SSL_read consumes them and reports WANT_READ.
    fn fillRecvTls(self: *PgClient, idx: u32) ReadStatus {
        const slot = &self.slots[idx];
        const sess = &slot.tls.?;
        var got_eof = false;
        while (true) {
            var cbuf: [4096]u8 = undefined;
            const raw = std.posix.system.read(slot.fd, &cbuf, cbuf.len);
            if (raw == 0) {
                got_eof = true;
                break;
            }
            if (raw < 0) {
                switch (std.posix.errno(raw)) {
                    .AGAIN => break,
                    .INTR => continue,
                    else => return .failed,
                }
            }
            const n: usize = @intCast(raw);
            var fed: usize = 0;
            while (fed < n) {
                fed += sess.feedCryptoData(cbuf[fed..n]) catch return .failed;
            }
        }
        var any = false;
        while (slot.recv_len < slot.recv_buf.len) {
            const n = sess.read(slot.recv_buf[slot.recv_len..]) catch |err| switch (err) {
                error.WouldBlock => break,
                error.ConnectionClosed => {
                    got_eof = true;
                    break;
                },
                else => return .failed,
            };
            if (n == 0) break;
            slot.recv_len += n;
            any = true;
        }
        if (any) return .data;
        return if (got_eof) .closed else .would_block;
    }

    /// Readable in `.handshaking`: read until EAGAIN (required for
    /// edge-triggered epoll), feeding the handshake after every read.
    fn handleReadable(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        while (slot.state == .handshaking) {
            if (slot.recv_len == slot.recv_buf.len) {
                return self.failSlot(io_rt, idx, now_ms, "handshake frame exceeds recv buffer");
            }
            switch (self.fillRecv(idx)) {
                .would_block => return,
                .closed => return self.failSlot(io_rt, idx, now_ms, "server closed connection during handshake"),
                .failed => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                .data => {},
            }
            switch (ingest(slot, idx)) {
                .more => {},
                .ready => {
                    if (!slot.primed) {
                        slot.primed = true;
                        self.primeSlot(io_rt, idx, now_ms);
                    }
                    return;
                },
                .failed => return self.failSlot(io_rt, idx, now_ms, "handshake failed"),
            }
            // The handshake may have queued a response (SASL round trip).
            self.pumpSend(io_rt, idx, now_ms);
        }
    }

    /// Run one discard query ("select 1") the first time a slot reaches
    /// `.ready`, so the first *real* query is never the connection's very
    /// first. Works around a first-query readiness gap on the native
    /// io_uring one-shot external poll: epoll's persistent registration
    /// masks it, so there it just exercises a harmless extra round-trip at
    /// startup. The op carries no park, so `drainOpResponses` discards its
    /// result. Mirrors `queryBatch`'s serialization (unnamed statement, no
    /// params, no Describe — the result is thrown away).
    fn primeSlot(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        if (slot.state != .ready or slot.op_count != 0) return;

        const no_args: []const ?[]const u8 = &.{};
        const tls_active = slot.tls != null;
        if (!tls_active and slot.send_off > 0) {
            std.mem.copyForwards(u8, slot.send_buf[0 .. slot.send_len - slot.send_off], slot.send_buf[slot.send_off..slot.send_len]);
            slot.send_len -= slot.send_off;
            slot.send_off = 0;
        }
        var plain_scratch: [SEND_BUF_SIZE]u8 = undefined;
        const out_buf: []u8 = if (tls_active) plain_scratch[0..] else slot.send_buf[0..];
        var off: usize = if (tls_active) 0 else slot.send_len;
        const op_start = off;
        off += (protocol.writeParse(out_buf[off..], "", "select 1", &.{}) catch return).len;
        off += (protocol.writeBind(out_buf[off..], "", "", no_args) catch return).len;
        off += (protocol.writeExecute(out_buf[off..], "", 0) catch return).len;
        off += (protocol.writeSync(out_buf[off..]) catch return).len;

        const tail = slot.opAt(slot.op_count);
        tail.* = .{ .park = NO_PARK, .cache_slot = NO_CACHE };
        slot.op_count += 1;
        slot.state = .busy;
        if (tls_active) {
            if (!self.stageTls(io_rt, idx, now_ms, out_buf[op_start..off])) return;
        } else {
            slot.send_len = off;
        }
        switch (self.flushOut(io_rt, idx, now_ms)) {
            .drained, .blocked, .failed => {},
        }
    }

    /// Readable in `.ready` (no op in flight): async backend messages
    /// (NoticeResponse, ParameterStatus) are read and discarded — a
    /// level-triggered backend would otherwise spin on the readiness.
    /// recv_buf is idle between ops and serves as the discard sink; on
    /// the TLS path the bytes must still route through the session so
    /// its record state stays coherent. EOF means the server dropped
    /// us: reconnect.
    fn drainReady(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        slot.recv_len = 0;
        while (true) {
            switch (self.fillRecv(idx)) {
                .data => slot.recv_len = 0, // discard
                .would_block => return,
                .closed => return self.failSlot(io_rt, idx, now_ms, "server closed idle connection"),
                .failed => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
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
        const batch = [1][]const ?[]const u8{args};
        return self.queryBatch(io_rt, conn_index, conn_id, sql, &batch, stash_bytes, continuation);
    }

    /// Batch variant (design 9.0 phase 4): ONE op containing one Parse,
    /// `args_batch.len` Bind/Execute pairs, and one Sync. All result
    /// rows land in a single frames region, so the continuation's
    /// `Result.rows()` iterates every execution's DataRows in order —
    /// this is what makes TFB /queries and /updates one park instead of
    /// N. Describe (column metadata) is emitted only for single-set
    /// batches; multi-set results decode binary columns positionally.
    pub fn queryBatch(
        self: *PgClient,
        io_rt: *io_mod.IoRuntime,
        conn_index: u32,
        conn_id: u64,
        sql: []const u8,
        args_batch: []const []const ?[]const u8,
        stash_bytes: []const u8,
        continuation: handler_api.Continuation,
    ) handler_api.QueryError!response_mod.Response {
        std.debug.assert(stash_bytes.len <= handler_api.STASH_CAPACITY);
        if (args_batch.len == 0 or args_batch.len > MAX_BATCH) return error.RequestTooLarge;
        if (conn_index >= self.conn_parks.len) return error.NotConnected;
        if (self.conn_parks[conn_index] != NO_PARK) return error.AlreadyParked;

        // Pick the connected slot with the shallowest op queue.
        var best: ?u32 = null;
        var best_depth: u8 = OP_QUEUE_DEPTH;
        var any_connected = false;
        for (0..self.opts.pool_size) |i| {
            switch (self.slots[i].state) {
                .ready, .busy => {
                    any_connected = true;
                    if (self.slots[i].op_count < best_depth) {
                        best_depth = self.slots[i].op_count;
                        best = @intCast(i);
                    }
                },
                else => {},
            }
        }
        const idx = best orelse return error.NotConnected;
        if (best_depth == OP_QUEUE_DEPTH) {
            return if (any_connected) error.QueueFull else error.NotConnected;
        }
        const slot = &self.slots[idx];

        const park_idx: u16 = blk: {
            for (&self.parked, 0..) |*p, i| {
                if (!p.active) break :blk @intCast(i);
            }
            return error.ParkTableFull;
        };

        // Prepared-statement cache: skip Parse when this connection has
        // already prepared the SQL; claim a free named slot otherwise
        // (claimed at enqueue so a second op for the same SQL queued
        // behind this one reuses the name instead of re-Parsing it).
        const stmt_hash = std.hash.Wyhash.hash(0, sql);
        var stmt_name: []const u8 = "";
        var claim_slot: u8 = NO_CACHE;
        var need_parse = true;
        for (0..STMT_CACHE_SIZE) |ci| {
            if (slot.stmt_valid & (@as(u32, 1) << @intCast(ci)) != 0 and slot.stmt_hashes[ci] == stmt_hash) {
                stmt_name = &stmt_names[ci];
                need_parse = false;
                break;
            }
        }
        if (need_parse) {
            for (0..STMT_CACHE_SIZE) |ci| {
                if (slot.stmt_valid & (@as(u32, 1) << @intCast(ci)) == 0) {
                    claim_slot = @intCast(ci);
                    stmt_name = &stmt_names[ci];
                    break;
                }
            }
            // Cache full: degrade to the unnamed statement (stmt_name
            // stays "" and every such op re-Parses).
        }

        // Serialization target: the plain path appends plaintext behind
        // earlier ops' bytes in send_buf (compact the flush cursor out
        // first). The TLS path serializes into stack scratch instead —
        // send_buf holds CIPHERTEXT there (wbio staging), so plaintext
        // must never touch it; stageTls encrypts the scratch below.
        var plain_scratch: [SEND_BUF_SIZE]u8 = undefined;
        const tls_active = slot.tls != null;
        if (!tls_active and slot.send_off > 0) {
            std.mem.copyForwards(u8, slot.send_buf[0 .. slot.send_len - slot.send_off], slot.send_buf[slot.send_off..slot.send_len]);
            slot.send_len -= slot.send_off;
            slot.send_off = 0;
        }
        const out_buf: []u8 = if (tls_active) plain_scratch[0..] else slot.send_buf[0..];
        // send_len only advances after the whole op fits — a partial op
        // is simply never committed. An overflow with earlier ops
        // queued is congestion (QueueFull); with an empty buffer the
        // query alone is too big (RequestTooLarge).
        var off: usize = if (tls_active) 0 else slot.send_len;
        const op_start = off;
        const overflow: handler_api.QueryError = if (op_start == 0 and slot.op_count == 0) error.RequestTooLarge else error.QueueFull;
        if (need_parse) {
            off += (protocol.writeParse(out_buf[off..], stmt_name, sql, &.{}) catch return overflow).len;
        }
        for (args_batch) |args| {
            off += (protocol.writeBind(out_buf[off..], "", stmt_name, args) catch return overflow).len;
            if (args_batch.len == 1) {
                off += (protocol.writeDescribePortal(out_buf[off..], "") catch return overflow).len;
            }
            off += (protocol.writeExecute(out_buf[off..], "", 0) catch return overflow).len;
        }
        off += (protocol.writeSync(out_buf[off..]) catch return overflow).len;

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

        // Enqueue the op. The park attaches only after the flush: a
        // flush failure stages ConnectionLost for OTHER queued ops (via
        // failSlot → pending_error, delivered at tick) but this op's
        // failure surfaces synchronously as an error return — no
        // continuation ever runs beneath the issuing handler.
        const tail = slot.opAt(slot.op_count);
        tail.* = .{ .park = NO_PARK, .cache_slot = claim_slot };
        slot.op_count += 1;
        if (claim_slot != NO_CACHE) {
            slot.stmt_hashes[claim_slot] = stmt_hash;
            slot.stmt_valid |= @as(u32, 1) << @intCast(claim_slot);
        }
        slot.state = .busy;
        if (slot.tls != null) {
            // TLS: the op's plaintext was serialized into stack scratch
            // (send_buf holds ciphertext on this path); encrypt it into
            // the wbio. Ciphertext ordering through the wbio is FIFO,
            // matching the op ring. stageTls runs failSlot on failure —
            // ring, cache, and session are already torn down.
            if (!self.stageTls(io_rt, idx, now_ms, out_buf[op_start..off])) {
                entry.active = false;
                return error.NotConnected;
            }
        } else {
            slot.send_len = off;
        }
        switch (self.flushOut(io_rt, idx, now_ms)) {
            .drained, .blocked => {},
            .failed => {
                // failSlot already ran (inside flushOut) and reset the
                // slot — including the ring and the claimed cache bit.
                entry.active = false;
                return error.NotConnected;
            },
        }
        slot.opAt(slot.op_count - 1).park = park_idx;
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
        entry.pending_error = null;
        self.conn_parks[conn_index] = NO_PARK;
        for (&self.slots) |*slot| {
            if (slot.state != .busy) continue;
            var i: u8 = 0;
            while (i < slot.op_count) : (i += 1) {
                const op = slot.opAt(i);
                if (op.park == park_idx) op.park = NO_PARK;
            }
        }
    }

    /// Readable in `.busy`: accumulate backend frames; the head op of
    /// the FIFO owns everything up to the next ReadyForQuery. Result
    /// frames borrow recv_buf — valid only inside the resume callback;
    /// each delivered response's region is poisoned (Debug) and
    /// compacted out before the next op's delivery.
    fn pumpBusyRead(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) void {
        const slot = &self.slots[idx];
        while (slot.state == .busy) {
            if (slot.recv_len == slot.recv_buf.len) {
                // Oversized result for the head op. Its tail is still
                // on the wire; v1 recycles the connection rather than
                // resyncing (ops behind it get ConnectionLost at tick).
                if (slot.op_count > 0) {
                    const head = slot.opAt(0);
                    if (head.park != NO_PARK and self.parked[head.park].active) {
                        self.parked[head.park].pending_error = error.ResultTooLarge;
                        head.park = NO_PARK;
                    }
                }
                return self.failSlot(io_rt, idx, now_ms, "result exceeded recv buffer");
            }
            switch (self.fillRecv(idx)) {
                .would_block => return,
                .closed => return self.failSlot(io_rt, idx, now_ms, "server closed connection mid-query"),
                .failed => return self.failSlot(io_rt, idx, now_ms, "socket read failed"),
                .data => {},
            }
            if (!self.drainOpResponses(io_rt, idx, now_ms)) return;
        }
    }

    /// Deliver every complete response sitting in recv_buf to its FIFO
    /// op, oldest first, compacting the buffer between deliveries.
    /// Returns true to keep reading (parse healthy, slot alive), false
    /// when the slot failed or left `.busy`.
    fn drainOpResponses(self: *PgClient, io_rt: *io_mod.IoRuntime, idx: u32, now_ms: u64) bool {
        const slot = &self.slots[idx];
        outer: while (slot.state == .busy) {
            var it = protocol.FrameIter.init(slot.recv_buf[0..slot.recv_len]);
            while (true) {
                const frame_start = it.offset;
                const maybe_frame = it.next() catch {
                    self.failSlot(io_rt, idx, now_ms, "malformed backend frame mid-query");
                    return false;
                };
                const frame = maybe_frame orelse return true; // need more bytes
                const head = if (slot.op_count > 0) slot.opAt(0) else {
                    // Frames with no op in flight: async server traffic
                    // (NoticeResponse/ParameterStatus) — drop them.
                    slot.recv_len = 0;
                    return true;
                };
                switch (frame.typ) {
                    @intFromEnum(protocol.BackendType.error_response) => {
                        // This op failed; if its Parse claimed a cache
                        // slot, the named statement may not exist —
                        // invalidate the claim.
                        if (head.cache_slot != NO_CACHE) {
                            slot.stmt_valid &= ~(@as(u32, 1) << @intCast(head.cache_slot));
                            head.cache_slot = NO_CACHE;
                        }
                        if (head.park != NO_PARK) {
                            const info = protocol.parseErrorResponse(frame.payload) catch continue;
                            self.parked[head.park].server_error = handler_api.ServerErrorInfo.capture(info);
                        }
                    },
                    @intFromEnum(protocol.BackendType.command_complete) => {
                        const cc = protocol.parseCommandComplete(frame.payload) catch continue;
                        head.rows = cc.rows orelse 0;
                    },
                    @intFromEnum(protocol.BackendType.ready_for_query) => {
                        // The head op's response is complete: deliver,
                        // poison + compact its region, pop the op, and
                        // rescan for the next op's response.
                        const park = head.park;
                        const rows = head.rows;
                        head.park = NO_PARK;
                        if (park != NO_PARK) {
                            if (self.parked[park].server_error != null) {
                                self.deliverOutcome(park, error.ServerError);
                            } else {
                                self.deliverOutcome(park, handler_api.Result{
                                    .frames = slot.recv_buf[0..frame_start],
                                    .rows_affected = rows,
                                });
                            }
                        }
                        const consumed = it.offset;
                        if (builtin.mode == .Debug) {
                            // Borrow-only contract: poison the
                            // delivered region. The compaction below
                            // then overwrites part of it with the next
                            // response's bytes — an escaped Result
                            // slice reads either 0xAA or unrelated
                            // frame data; both fail loudly in tests.
                            @memset(slot.recv_buf[0..consumed], 0xAA);
                        }
                        std.mem.copyForwards(u8, slot.recv_buf[0 .. slot.recv_len - consumed], slot.recv_buf[consumed..slot.recv_len]);
                        slot.recv_len -= consumed;
                        head.* = .{};
                        slot.op_head = (slot.op_head +% 1) % OP_QUEUE_DEPTH;
                        slot.op_count -= 1;
                        if (slot.op_count == 0) slot.state = .ready;
                        continue :outer;
                    },
                    else => {},
                }
            }
        }
        return false;
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
        // Stage ConnectionLost for every op still in the ring. Staged —
        // not delivered — because failSlot can run inside query()'s
        // flushSend; tick delivers (see ParkedRequest.pending_error).
        var i: u8 = 0;
        while (i < slot.op_count) : (i += 1) {
            const op = slot.opAt(i);
            if (op.park != NO_PARK and self.parked[op.park].active and
                self.parked[op.park].pending_error == null)
            {
                self.parked[op.park].pending_error = error.ConnectionLost;
            }
            op.* = .{};
        }
        slot.op_head = 0;
        slot.op_count = 0;
        // The statement cache dies with the connection.
        slot.stmt_valid = 0;
        if (slot.tls) |*sess| {
            // Memory-BIO session: SSL_free only, no shutdown alert to
            // pump (see createTcpClientSession). The provider's SSL_CTX
            // is server-owned and survives.
            sess.deinit();
            slot.tls = null;
        }
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

/// Map a URL sslmode value onto the supported policies. libpq's
/// opportunistic modes (allow/prefer) and verify-ca (chain without
/// hostname) are refused — unknown values return null (fail closed).
pub fn parseSslMode(s: []const u8) ?SslMode {
    if (std.mem.eql(u8, s, "disable")) return .disable;
    if (std.mem.eql(u8, s, "require")) return .require;
    if (std.mem.eql(u8, s, "verify-full")) return .verify_full;
    return null;
}

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

test "parseSslMode: supported modes only, unknown values fail closed" {
    try testing.expectEqual(@as(?SslMode, .disable), parseSslMode("disable"));
    try testing.expectEqual(@as(?SslMode, .require), parseSslMode("require"));
    try testing.expectEqual(@as(?SslMode, .verify_full), parseSslMode("verify-full"));
    // libpq modes without honest semantics here are refused.
    try testing.expectEqual(@as(?SslMode, null), parseSslMode("prefer"));
    try testing.expectEqual(@as(?SslMode, null), parseSslMode("allow"));
    try testing.expectEqual(@as(?SslMode, null), parseSslMode("verify-ca"));
    try testing.expectEqual(@as(?SslMode, null), parseSslMode(""));
    try testing.expectEqual(@as(?SslMode, null), parseSslMode("VERIFY-FULL"));
}

test "sslmode policy: SSLRequest send matrix and 'N'-reply handling" {
    // disable never sends the SSLRequest; the TLS modes always do.
    try testing.expect(!PgClient.wantsSslRequest(.disable));
    try testing.expect(PgClient.wantsSslRequest(.require));
    try testing.expect(PgClient.wantsSslRequest(.verify_full));

    // Reply classification: 'S' proceeds, 'N' is the refusal (fatal in
    // every mode that sent the request), anything else is a violation.
    try testing.expectEqual(PgClient.SslReply.start_tls, PgClient.classifySslReply('S'));
    try testing.expectEqual(PgClient.SslReply.refused, PgClient.classifySslReply('N'));
    try testing.expectEqual(PgClient.SslReply.protocol_error, PgClient.classifySslReply('E'));
    try testing.expectEqual(PgClient.SslReply.protocol_error, PgClient.classifySslReply(0));

    // Options default is the fail-safe mode.
    const defaults = Options{ .host = "h", .user = "u" };
    try testing.expectEqual(SslMode.verify_full, defaults.sslmode);
}

test "cleartext password gate: TLS channel always passes, plaintext needs the opt-in" {
    try testing.expect(PgClient.cleartextPasswordAllowed(true, false));
    try testing.expect(PgClient.cleartextPasswordAllowed(true, true));
    try testing.expect(PgClient.cleartextPasswordAllowed(false, true));
    try testing.expect(!PgClient.cleartextPasswordAllowed(false, false));
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

/// Shared scaffolding for the live integration tests: a small runtime
/// config and the poll-dispatch-tick loop (mirror of the dispatch-loop
/// external branch) that runs until `pred` holds or the timeout lapses.
fn testRuntimeConfig() config_mod.ServerConfig {
    var cfg = config_mod.ServerConfig.default();
    cfg.max_connections = 16;
    cfg.buffer_pool = .{
        .buffer_size = 4096,
        .buffer_count = 32,
        .body_buffer_size = 4096,
        .body_buffer_count = 2,
    };
    return cfg;
}

fn pumpPg(client: *PgClient, rt: *io_mod.IoRuntime, timeout_ms: u64, comptime pred: fn (*const PgClient) bool) !bool {
    const deadline = rt.nowMs() + timeout_ms;
    while (rt.nowMs() < deadline) {
        if (pred(client)) return true;
        client.tick(rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
    }
    return pred(client);
}

fn predAnyReady(c: *const PgClient) bool {
    return c.anyReady();
}

test "integration: reactor-driven connection bring-up (PG_TEST_DSN)" {
    const dsn_z = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn = try parseUrl(std.mem.sliceTo(dsn_z, 0));

    const cfg = testRuntimeConfig();

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
        // This is the plaintext-server setup; TLS rows live in the
        // PG_TLS_TEST_DSN matrix below.
        .sslmode = .disable,
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
                .repark_batch_fn = undefined,
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

    // ── Pipelining: 8 ops enqueued before any response is polled ───
    const HookP = struct {
        var done: u32 = 0;
        var sum: i64 = 0;
        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            done += 1;
            if (outcome.result) |res| {
                var prows = res.rows();
                while (prows.next()) |row| sum += row.int4(0) catch 0;
            } else |_| {}
        }
    };
    client.installResume(@ptrCast(&dummy), HookP.onResume);
    var qi: u32 = 0;
    while (qi < 8) : (qi += 1) {
        var qbuf: [16]u8 = undefined;
        const qarg = std.fmt.bufPrint(&qbuf, "{d}", .{qi + 1}) catch unreachable;
        const s = try client.query(&rt, qi, 1000 + qi, "select $1::int4", &.{qarg}, &.{}, Hook.cont);
        try testing.expect(s.isParked());
    }
    // No poll has happened: all 8 ops are genuinely in flight at once.
    try testing.expectEqual(@as(u8, 8), client.slots[0].op_count + client.slots[1].op_count);
    // Identical SQL → each slot Parsed it once into the statement cache.
    try testing.expect(client.slots[0].stmt_valid != 0);

    const p_deadline = rt.nowMs() + 5_000;
    while (rt.nowMs() < p_deadline and HookP.done < 8) {
        client.tick(&rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(&rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
    }
    try testing.expectEqual(@as(u32, 8), HookP.done);
    try testing.expectEqual(@as(i64, 36), HookP.sum); // 1+2+…+8
    try testing.expectEqual(@as(u8, 0), client.slots[0].op_count + client.slots[1].op_count);
    try testing.expect(client.anyReady());
}

test "integration: statement timeout recycles the connection (PG_TEST_DSN)" {
    const dsn_z = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn = try parseUrl(std.mem.sliceTo(dsn_z, 0));

    const cfg = testRuntimeConfig();
    var rt = try io_mod.IoRuntime.init(testing.allocator, cfg);
    defer rt.deinit();
    switch (rt.backend) {
        .bsd_kqueue, .linux_epoll => {},
        else => return error.SkipZigTest,
    }

    var client = try PgClient.init(testing.allocator, cfg.max_connections, .{
        .host = dsn.host,
        .port = dsn.port,
        .user = dsn.user,
        .database = dsn.database,
        .password = dsn.password,
        .pool_size = 1,
        .statement_timeout_ms = 1_000,
        .sslmode = .disable, // PG_TEST_DSN points at the plaintext server
    });
    defer client.deinit(&rt);

    const HookT = struct {
        var got: ?handler_api.PgError = null;
        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            if (outcome.result) |_| {} else |err| got = err;
        }
    };
    var dummy: u8 = 0;
    client.installResume(@ptrCast(&dummy), HookT.onResume);

    // Bring the slot up.
    var deadline = rt.nowMs() + 10_000;
    while (rt.nowMs() < deadline and !client.anyReady()) {
        client.tick(&rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(&rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
    }
    try testing.expect(client.anyReady());

    const s = try client.query(&rt, 4, 99, "select pg_sleep(30)", &.{}, &.{}, undefined);
    try testing.expect(s.isParked());

    // Timeout fires via tick at ~1s; the slot recycles and reconnects.
    deadline = rt.nowMs() + 8_000;
    while (rt.nowMs() < deadline and HookT.got == null) {
        client.tick(&rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(&rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
    }
    try testing.expectEqual(@as(?handler_api.PgError, error.Timeout), HookT.got);

    // The connection comes back after backoff (1s) + reconnect.
    deadline = rt.nowMs() + 10_000;
    while (rt.nowMs() < deadline and !client.anyReady()) {
        client.tick(&rt, rt.nowMs());
        const events = try rt.pollWithTimeout(10);
        for (events) |ev| {
            if (!io_mod.isExternalId(ev.conn_id)) continue;
            client.onEvent(&rt, @intCast(ev.conn_id & 0xFFFF_FFFF), ev.kind);
        }
    }
    try testing.expect(client.anyReady());
}

test "park table: cancelForConn generation check, detach, and hookless delivery" {
    var client = try PgClient.init(testing.allocator, 8, .{ .host = "127.0.0.1", .user = "u" });
    defer testing.allocator.free(client.conn_parks);

    // Simulate two parked ops queued on slot 0 (pipelined); cancel the
    // SECOND to prove mid-ring detach.
    client.slots[0].state = .busy;
    client.slots[0].op_count = 2;
    client.slots[0].ops[0] = .{ .park = 1 };
    client.slots[0].ops[1] = .{ .park = 0 };
    client.parked[0] = .{ .active = true, .conn_index = 3, .conn_id = 42, .continuation = undefined };
    client.parked[1] = .{ .active = true, .conn_index = 5, .conn_id = 77, .continuation = undefined };
    client.conn_parks[3] = 0;
    client.conn_parks[5] = 1;

    // Wrong generation (recycled conn slot): must be a no-op.
    client.cancelForConn(3, 41);
    try testing.expect(client.parked[0].active);

    // Right generation: entry freed, token cleared, op detached —
    // without disturbing the other queued op.
    client.cancelForConn(3, 42);
    try testing.expect(!client.parked[0].active);
    try testing.expectEqual(NO_PARK, client.conn_parks[3]);
    try testing.expectEqual(NO_PARK, client.slots[0].ops[1].park);
    try testing.expectEqual(@as(u16, 1), client.slots[0].ops[0].park);
    try testing.expect(client.parked[1].active);
    client.parked[1].active = false;
    client.conn_parks[5] = NO_PARK;

    // deliverOutcome on the now-inactive entry: harmless.
    client.deliverOutcome(0, error.Timeout);

    // Active entry with no resume hook installed: dropped and freed.
    client.parked[1] = .{ .active = true, .conn_index = 2, .conn_id = 9, .continuation = undefined };
    client.conn_parks[2] = 1;
    client.deliverOutcome(1, error.Timeout);
    try testing.expect(!client.parked[1].active);
    try testing.expectEqual(NO_PARK, client.conn_parks[2]);
}

// ---------------------------------------------------------------------------
// Live TLS integration matrix (gated on PG_TLS_TEST_DSN + PG_TLS_TEST_CA,
// and on a TLS-enabled build). Server expectations:
//   - PostgreSQL 16 with ssl=on; server certificate signed by the CA at
//     PG_TLS_TEST_CA with SAN = IP:127.0.0.1 ONLY (no DNS names);
//   - PG_TLS_TEST_DSN host must be 127.0.0.1 (matches the IP SAN); the
//     hostname-mismatch row connects via "localhost" to the same port.
// The plaintext-refusal row reuses the ssl=off server from PG_TEST_DSN.
// ---------------------------------------------------------------------------

const TlsTestEnv = struct {
    dsn: ParsedUrl,
    ca: [:0]const u8,
};

fn tlsTestEnv() ?TlsTestEnv {
    const dsn_z = std.c.getenv("PG_TLS_TEST_DSN") orelse return null;
    const ca_z = std.c.getenv("PG_TLS_TEST_CA") orelse return null;
    const dsn = parseUrl(std.mem.sliceTo(dsn_z, 0)) catch return null;
    return .{ .dsn = dsn, .ca = std.mem.sliceTo(ca_z, 0) };
}

fn predSlot0Chain(c: *const PgClient) bool {
    return c.slots[0].tls_fail == .chain;
}

fn predSlot0Hostname(c: *const PgClient) bool {
    return c.slots[0].tls_fail == .hostname;
}

fn predSlot0Refused(c: *const PgClient) bool {
    return c.slots[0].tls_fail == .refused;
}

// Matrix row 1: verify-full against the matching private CA — slots
// come up over TLS and a live query round-trips.
test "integration: TLS verify-full with correct CA — ready and live query (PG_TLS_TEST_DSN)" {
    if (!build_options.enable_tls) return error.SkipZigTest;
    const env = tlsTestEnv() orelse return error.SkipZigTest;

    var rt = try io_mod.IoRuntime.init(testing.allocator, testRuntimeConfig());
    defer rt.deinit();
    switch (rt.backend) {
        .bsd_kqueue, .linux_epoll => {},
        else => return error.SkipZigTest,
    }

    var provider = tls_mod.Provider.initTcpClient(testing.allocator, true, env.ca) catch
        return error.SkipZigTest;
    defer provider.deinit();

    var client = try PgClient.init(testing.allocator, 16, .{
        .host = env.dsn.host,
        .port = env.dsn.port,
        .user = env.dsn.user,
        .database = env.dsn.database,
        .password = env.dsn.password,
        .pool_size = 1,
        .sslmode = .verify_full,
    });
    defer client.deinit(&rt);
    client.installTls(&provider);

    try testing.expect(try pumpPg(&client, &rt, 10_000, predAnyReady));
    try testing.expect(client.slots[0].tls != null);
    try testing.expect(client.slots[0].tls.?.handshake_complete);

    // Live query through the TLS transport.
    const Hook = struct {
        var ran: bool = false;
        var status: u16 = 0;
        var sum: i64 = 0;

        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            ran = true;
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
                .repark_batch_fn = undefined,
            };
            status = outcome.continuation(&rctx).status;
        }

        fn cont(rctx: *handler_api.ResumeContext) response_mod.Response {
            const res = rctx.result catch return .{ .status = 500, .headers = &.{}, .body = .none };
            var rows = res.rows();
            while (rows.next()) |row| {
                sum += row.int4(0) catch -1_000_000;
            }
            return .{ .status = 200, .headers = &.{}, .body = .none };
        }

        fn done(_: *const PgClient) bool {
            return ran;
        }
    };
    var dummy: u8 = 0;
    client.installResume(@ptrCast(&dummy), Hook.onResume);
    const sentinel = try client.query(&rt, 3, 99, "select 20 + 22", &.{}, &.{}, Hook.cont);
    try testing.expect(sentinel.isParked());
    try testing.expect(try pumpPg(&client, &rt, 5_000, Hook.done));
    try testing.expectEqual(@as(u16, 200), Hook.status);
    try testing.expectEqual(@as(i64, 42), Hook.sum);
    try testing.expect(client.anyReady());

    // Pipelined burst over TLS: four ops staged through the wbio before
    // any response is polled — ciphertext FIFO ordering must match the
    // op ring, and the rbio decrypt path must hand the frame scanner
    // multiple responses in one fill.
    const HookB = struct {
        var done_count: u32 = 0;
        var sum: i64 = 0;
        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            done_count += 1;
            if (outcome.result) |res| {
                var rows = res.rows();
                while (rows.next()) |row| sum += row.int4(0) catch 0;
            } else |_| {}
        }
        fn done(_: *const PgClient) bool {
            return done_count >= 4;
        }
    };
    client.installResume(@ptrCast(&dummy), HookB.onResume);
    var qi: u32 = 0;
    while (qi < 4) : (qi += 1) {
        var qb: [8]u8 = undefined;
        const qa = std.fmt.bufPrint(&qb, "{d}", .{qi + 1}) catch unreachable;
        _ = try client.query(&rt, 5 + qi, 200 + qi, "select $1::int4", &.{qa}, &.{}, Hook.cont);
    }
    try testing.expectEqual(@as(u8, 4), client.slots[0].op_count);
    try testing.expect(try pumpPg(&client, &rt, 5_000, HookB.done));
    try testing.expectEqual(@as(i64, 10), HookB.sum); // 1+2+3+4
    try testing.expect(client.anyReady());
}

// Matrix row 2: verify-full with the system trust store against the
// self-signed test CA — must fail closed with the chain cause.
test "integration: TLS verify-full with system CA fails closed on chain (PG_TLS_TEST_DSN)" {
    if (!build_options.enable_tls) return error.SkipZigTest;
    const env = tlsTestEnv() orelse return error.SkipZigTest;

    const saved_log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = saved_log_level;

    var rt = try io_mod.IoRuntime.init(testing.allocator, testRuntimeConfig());
    defer rt.deinit();
    switch (rt.backend) {
        .bsd_kqueue, .linux_epoll => {},
        else => return error.SkipZigTest,
    }

    var provider = tls_mod.Provider.initTcpClient(testing.allocator, true, null) catch
        return error.SkipZigTest;
    defer provider.deinit();

    var client = try PgClient.init(testing.allocator, 16, .{
        .host = env.dsn.host,
        .port = env.dsn.port,
        .user = env.dsn.user,
        .database = env.dsn.database,
        .password = env.dsn.password,
        .pool_size = 1,
        .sslmode = .verify_full,
    });
    defer client.deinit(&rt);
    client.installTls(&provider);

    try testing.expect(try pumpPg(&client, &rt, 10_000, predSlot0Chain));
    try testing.expect(!client.anyReady());
}

// Matrix row 3: verify-full with the correct CA but a host the
// certificate doesn't cover (cert SAN is IP:127.0.0.1 only; we connect
// via "localhost") — must fail closed with the hostname cause.
test "integration: TLS verify-full hostname mismatch fails closed (PG_TLS_TEST_DSN)" {
    if (!build_options.enable_tls) return error.SkipZigTest;
    const env = tlsTestEnv() orelse return error.SkipZigTest;

    const saved_log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = saved_log_level;

    var rt = try io_mod.IoRuntime.init(testing.allocator, testRuntimeConfig());
    defer rt.deinit();
    switch (rt.backend) {
        .bsd_kqueue, .linux_epoll => {},
        else => return error.SkipZigTest,
    }

    var provider = tls_mod.Provider.initTcpClient(testing.allocator, true, env.ca) catch
        return error.SkipZigTest;
    defer provider.deinit();

    var client = try PgClient.init(testing.allocator, 16, .{
        .host = "localhost", // resolves to the same server; not in the cert SAN
        .port = env.dsn.port,
        .user = env.dsn.user,
        .database = env.dsn.database,
        .password = env.dsn.password,
        .pool_size = 1,
        .sslmode = .verify_full,
    });
    defer client.deinit(&rt);
    client.installTls(&provider);

    try testing.expect(try pumpPg(&client, &rt, 10_000, predSlot0Hostname));
    try testing.expect(!client.anyReady());
}

// Matrix row 4: sslmode=require (no CA, no verification) against the
// self-signed server — connects and queries. Discouraged mode, but it
// must work.
test "integration: TLS require without CA — ready and live query (PG_TLS_TEST_DSN)" {
    if (!build_options.enable_tls) return error.SkipZigTest;
    const env = tlsTestEnv() orelse return error.SkipZigTest;

    var rt = try io_mod.IoRuntime.init(testing.allocator, testRuntimeConfig());
    defer rt.deinit();
    switch (rt.backend) {
        .bsd_kqueue, .linux_epoll => {},
        else => return error.SkipZigTest,
    }

    var provider = tls_mod.Provider.initTcpClient(testing.allocator, false, null) catch
        return error.SkipZigTest;
    defer provider.deinit();

    var client = try PgClient.init(testing.allocator, 16, .{
        .host = env.dsn.host,
        .port = env.dsn.port,
        .user = env.dsn.user,
        .database = env.dsn.database,
        .password = env.dsn.password,
        .pool_size = 1,
        .sslmode = .require,
    });
    defer client.deinit(&rt);
    client.installTls(&provider);

    try testing.expect(try pumpPg(&client, &rt, 10_000, predAnyReady));
    try testing.expect(client.slots[0].tls != null);

    const Hook = struct {
        var ran: bool = false;
        var status: u16 = 0;

        fn onResume(_: *anyopaque, outcome: *const Outcome) void {
            ran = true;
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
                .repark_batch_fn = undefined,
            };
            status = outcome.continuation(&rctx).status;
        }

        fn cont(rctx: *handler_api.ResumeContext) response_mod.Response {
            _ = rctx.result catch return .{ .status = 500, .headers = &.{}, .body = .none };
            return .{ .status = 200, .headers = &.{}, .body = .none };
        }

        fn done(_: *const PgClient) bool {
            return ran;
        }
    };
    var dummy: u8 = 0;
    client.installResume(@ptrCast(&dummy), Hook.onResume);
    _ = try client.query(&rt, 4, 100, "select 1", &.{}, &.{}, Hook.cont);
    try testing.expect(try pumpPg(&client, &rt, 5_000, Hook.done));
    try testing.expectEqual(@as(u16, 200), Hook.status);
    try testing.expect(client.anyReady());
}

// Matrix row 5: sslmode=require against a plaintext-only server — the
// 'N' SSLRequest reply must fail the slot closed (never silently
// downgrade to plaintext).
test "integration: sslmode=require against plaintext server fails closed (PG_TEST_DSN)" {
    const dsn_z = std.c.getenv("PG_TEST_DSN") orelse return error.SkipZigTest;
    const dsn = try parseUrl(std.mem.sliceTo(dsn_z, 0));

    const saved_log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = saved_log_level;

    var rt = try io_mod.IoRuntime.init(testing.allocator, testRuntimeConfig());
    defer rt.deinit();
    switch (rt.backend) {
        .bsd_kqueue, .linux_epoll => {},
        else => return error.SkipZigTest,
    }

    // No TLS provider needed: the refusal arrives before any TLS state
    // is built, and it must already be fatal.
    var client = try PgClient.init(testing.allocator, 16, .{
        .host = dsn.host,
        .port = dsn.port,
        .user = dsn.user,
        .database = dsn.database,
        .password = dsn.password,
        .pool_size = 1,
        .sslmode = .require,
    });
    defer client.deinit(&rt);

    try testing.expect(try pumpPg(&client, &rt, 10_000, predSlot0Refused));
    try testing.expect(!client.anyReady());
}
