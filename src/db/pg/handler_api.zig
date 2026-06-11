//! Handler-facing park-and-resume types for the PostgreSQL client
//! (design 9.0 "Handler API", decided 2026-06-10).
//!
//! The contract, briefly:
//!   - `ctx.pg.query(...)` returns the park sentinel `Response` itself —
//!     parking without a query in flight is unwritable.
//!   - Continuations receive a `ResumeContext`, NOT a `HandlerContext`:
//!     the request's read buffer was recycled while parked, so there is
//!     deliberately no `request` field to misuse.
//!   - Stashes are plain data, enforced at comptime by
//!     `assertPlainData` — a pointer or slice field is a compile error.
//!   - `Result` rows borrow the PG connection's recv buffer and are
//!     valid only inside the continuation call.

const std = @import("std");
const response = @import("../../response/response.zig");
const protocol = @import("protocol.zig");
const pgtypes = @import("types.zig");

/// Maximum stash size, in bytes. Lives in the per-worker park table —
/// keep it small; copy fields, not documents.
pub const STASH_CAPACITY: usize = 256;

/// Errors delivered through `ResumeContext.result`. The continuation
/// runs exactly once with either a `Result` or one of these.
pub const PgError = error{
    /// statement_timeout_ms elapsed before the op completed.
    Timeout,
    /// The PG connection died (or was reconnecting) before completion.
    ConnectionLost,
    /// An earlier op in the same pipeline failed; this op was aborted
    /// before execution.
    PipelineAborted,
    /// The server answered with ErrorResponse — SQLSTATE and message
    /// are in `ResumeContext.server_error`.
    ServerError,
    /// The result exceeded the per-op buffer cap.
    ResultTooLarge,
};

/// Synchronous failures of `query()` itself, surfaced to the handler
/// while it still has the request.
pub const QueryError = error{
    /// All PG connections are down or still connecting.
    NotConnected,
    /// The in-flight op queue is full — shed load now (503).
    QueueFull,
    /// This request already has a parked op (one park per request).
    AlreadyParked,
    /// The park table is full (too many concurrently parked requests).
    ParkTableFull,
    /// SQL + parameters did not fit the per-op serialization buffer.
    RequestTooLarge,
};

pub const Continuation = *const fn (rctx: *ResumeContext) response.Response;

/// Comptime guard: a stash must be plain old data. Pointers and slices
/// are rejected because anything they could legally point at (the read
/// buffer, handler stack frames, the arena) is recycled while the
/// request is parked. Copy bytes into fixed arrays instead.
pub fn assertPlainData(comptime T: type) void {
    comptime assertPlainDataInner(T, @typeName(T));
}

fn assertPlainDataInner(comptime T: type, comptime root: []const u8) void {
    switch (@typeInfo(T)) {
        .int, .float, .bool, .void, .@"enum" => {},
        .array => |a| assertPlainDataInner(a.child, root),
        .optional => |o| assertPlainDataInner(o.child, root),
        .@"struct" => |s| {
            inline for (s.fields) |f| assertPlainDataInner(f.type, root);
        },
        .@"union" => |u| {
            inline for (u.fields) |f| assertPlainDataInner(f.type, root);
        },
        .pointer => @compileError("stash type " ++ root ++
            " contains a pointer/slice field (" ++ @typeName(T) ++ "): " ++
            "anything it points at is recycled while parked — copy into a fixed array instead"),
        else => @compileError("stash type " ++ root ++
            " contains a non-plain-data field: " ++ @typeName(T)),
    }
}

/// A completed query result. Borrows the PG connection's recv buffer:
/// valid ONLY during the continuation call — serialize what you need
/// into `rctx.response_buf` / the arena before returning. Debug builds
/// poison this region after the continuation returns.
pub const Result = struct {
    /// Complete backend frames from ParseComplete through
    /// CommandComplete (RowDescription + DataRows live in here).
    frames: []const u8,
    /// Rows affected, parsed from the CommandComplete tag (0 for
    /// SELECTs without a count).
    rows_affected: u64,

    pub fn rows(self: *const Result) RowIter {
        return .{ .iter = protocol.FrameIter.init(self.frames) };
    }

    /// Column metadata (name, type oid) from RowDescription, if the
    /// statement returned rows.
    pub fn columns(self: *const Result) ?protocol.RowDescriptionIter {
        var it = protocol.FrameIter.init(self.frames);
        while (it.next() catch return null) |frame| {
            if (frame.typ == @intFromEnum(protocol.BackendType.row_description)) {
                return protocol.RowDescriptionIter.init(frame.payload) catch null;
            }
        }
        return null;
    }
};

pub const RowIter = struct {
    iter: protocol.FrameIter,

    pub fn next(self: *RowIter) ?Row {
        while (self.iter.next() catch return null) |frame| {
            if (frame.typ == @intFromEnum(protocol.BackendType.data_row)) {
                return Row{ .payload = frame.payload };
            }
        }
        return null;
    }
};

/// One DataRow. Column access walks the wire payload (columns are few;
/// O(n) per access is fine at handler scale). All values are binary
/// format (Bind requests result-format-code 1 for every column).
pub const Row = struct {
    payload: []const u8,

    /// Raw column bytes; null for SQL NULL, error.Malformed if `i` is
    /// out of range or the payload is truncated.
    pub fn col(self: Row, i: usize) protocol.ParseError!protocol.DataValue {
        var it = try protocol.DataRowIter.init(self.payload);
        var idx: usize = 0;
        while (try it.next()) |v| : (idx += 1) {
            if (idx == i) return v;
        }
        return protocol.ParseError.Malformed;
    }

    fn require(self: Row, i: usize) ![]const u8 {
        return (try self.col(i)) orelse error.UnexpectedNull;
    }

    pub fn int2(self: Row, i: usize) !i16 {
        return pgtypes.decodeInt2(try self.require(i));
    }
    pub fn int4(self: Row, i: usize) !i32 {
        return pgtypes.decodeInt4(try self.require(i));
    }
    pub fn int8(self: Row, i: usize) !i64 {
        return pgtypes.decodeInt8(try self.require(i));
    }
    pub fn boolean(self: Row, i: usize) !bool {
        return pgtypes.decodeBool(try self.require(i));
    }
    pub fn float8(self: Row, i: usize) !f64 {
        return pgtypes.decodeFloat8(try self.require(i));
    }
    /// Borrowed text bytes (also use for varchar / numeric-as-text).
    pub fn text(self: Row, i: usize) ![]const u8 {
        return pgtypes.decodeText(try self.require(i));
    }
    /// Null-aware variant: SQL NULL maps to Zig null.
    pub fn textOpt(self: Row, i: usize) !?[]const u8 {
        const v = (try self.col(i)) orelse return null;
        return pgtypes.decodeText(v);
    }
};

/// Server-reported error details, copied into fixed storage so they
/// outlive the recv buffer (delivered alongside `error.ServerError`).
pub const ServerErrorInfo = struct {
    sqlstate: [5]u8 = .{ '0', '0', '0', '0', '0' },
    message_buf: [256]u8 = undefined,
    message_len: u16 = 0,

    pub fn message(self: *const ServerErrorInfo) []const u8 {
        return self.message_buf[0..self.message_len];
    }

    pub fn capture(info: protocol.ErrorInfo) ServerErrorInfo {
        var out = ServerErrorInfo{};
        if (info.code.len >= 5) @memcpy(out.sqlstate[0..5], info.code[0..5]);
        const n = @min(info.message.len, out.message_buf.len);
        @memcpy(out.message_buf[0..n], info.message[0..n]);
        out.message_len = @intCast(n);
        return out;
    }
};

/// Chaining hook: lets a continuation issue the next query and re-park
/// through the same machinery. Installed by the PG client at resume
/// time; opaque to avoid a handler_api → client import cycle.
pub const ReparkFn = *const fn (
    ctx: *anyopaque,
    sql: []const u8,
    args: []const ?[]const u8,
    continuation: Continuation,
) QueryError!response.Response;

/// Batch variant: one op carrying N Bind/Execute pairs (see
/// PgClient.queryBatch). Argument slices are serialized into the wire
/// buffer during the call, so they may safely borrow the CURRENT
/// result's memory (ids read from step 0's rows can feed step 1's
/// update batch directly).
pub const ReparkBatchFn = *const fn (
    ctx: *anyopaque,
    sql: []const u8,
    args_batch: []const []const ?[]const u8,
    continuation: Continuation,
) QueryError!response.Response;

/// What a continuation gets. Mirrors the scratch surface of
/// `HandlerContext` (fresh response_buf / headers / arena) but carries
/// NO request fields: the read buffer was recycled while parked, and
/// this type makes that unrepresentable rather than documented.
pub const ResumeContext = struct {
    result: PgError!Result,
    /// Populated when `result == error.ServerError`.
    server_error: ?ServerErrorInfo = null,
    response_buf: []u8,
    response_headers: []response.Header,
    response_header_count: usize = 0,
    arena: std.heap.FixedBufferAllocator,
    stash_bytes: *[STASH_CAPACITY]u8,
    repark_ctx: *anyopaque,
    repark_fn: ReparkFn,
    repark_batch_fn: ReparkBatchFn,

    /// Typed view of the stash written by `query()` in phase 1. Same
    /// comptime plain-data enforcement as the write side.
    pub fn stash(self: *ResumeContext, comptime T: type) *T {
        comptime assertPlainData(T);
        comptime std.debug.assert(@sizeOf(T) <= STASH_CAPACITY);
        comptime std.debug.assert(@alignOf(T) <= @alignOf(*[STASH_CAPACITY]u8));
        return @ptrCast(@alignCast(self.stash_bytes));
    }

    pub fn allocator(self: *ResumeContext) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Issue the next query in a chain and re-park. Returns the park
    /// sentinel `Response` to return from the continuation — identical
    /// contract to `ctx.pg.query` in phase 1 (text-format params).
    pub fn query(
        self: *ResumeContext,
        sql: []const u8,
        args: []const ?[]const u8,
        continuation: Continuation,
    ) QueryError!response.Response {
        return self.repark_fn(self.repark_ctx, sql, args, continuation);
    }

    /// Batch chain: one op, N Bind/Execute pairs, all rows in one
    /// Result. Argument slices may borrow the current result's memory
    /// (serialized into the wire buffer before this call returns).
    pub fn queryBatch(
        self: *ResumeContext,
        sql: []const u8,
        args_batch: []const []const ?[]const u8,
        continuation: Continuation,
    ) QueryError!response.Response {
        return self.repark_batch_fn(self.repark_ctx, sql, args_batch, continuation);
    }
};

// ── tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "assertPlainData accepts plain structs and rejects pointers at comptime" {
    comptime assertPlainData(struct {
        id: u64,
        name_buf: [64]u8,
        name_len: u8,
        step: u8,
        flag: ?bool,
        kind: enum { a, b },
    });
    // The rejection side is a compile error by design and can't be a
    // runtime test; it is exercised by the doc example failing to
    // compile if anyone tries.
}

test "Row column access over a hand-built DataRow payload" {
    // DataRow payload: int2 column count, then per column i32 length
    // (-1 = NULL) + bytes. Two columns: int4 7, NULL.
    var payload: [32]u8 = undefined;
    var off: usize = 0;
    std.mem.writeInt(i16, payload[off..][0..2], 2, .big);
    off += 2;
    std.mem.writeInt(i32, payload[off..][0..4], 4, .big);
    off += 4;
    std.mem.writeInt(i32, payload[off..][0..4], 7, .big);
    off += 4;
    std.mem.writeInt(i32, payload[off..][0..4], -1, .big);
    off += 4;

    const row = Row{ .payload = payload[0..off] };
    try testing.expectEqual(@as(i32, 7), try row.int4(0));
    try testing.expectEqual(@as(?[]const u8, null), try row.col(1));
    try testing.expectError(error.UnexpectedNull, row.int4(1));
    try testing.expectError(protocol.ParseError.Malformed, row.col(2));
}

test "stash round-trips a typed value" {
    const Stash = struct { user_id: u64 = 0, step: u8 = 0 };
    var bytes: [STASH_CAPACITY]u8 align(16) = @splat(0);
    var rctx = ResumeContext{
        .result = error.Timeout,
        .response_buf = &.{},
        .response_headers = &.{},
        .arena = std.heap.FixedBufferAllocator.init(&.{}),
        .stash_bytes = &bytes,
        .repark_ctx = undefined,
        .repark_fn = undefined,
        .repark_batch_fn = undefined,
    };
    const st = rctx.stash(Stash);
    st.user_id = 42;
    st.step = 1;
    try testing.expectEqual(@as(u64, 42), rctx.stash(Stash).user_id);
    try testing.expectEqual(@as(u8, 1), rctx.stash(Stash).step);
}
