//! Handler-facing types for the Nether sandbox runtime (design 11.0).
//!
//! Mirrors the PostgreSQL park-and-resume handler API (db/pg/handler_api):
//! `ctx.sandbox.exec(...)` parks the request, the command runs in a Nether
//! guest, and the continuation resumes with the guest's output + exit code.
//! The continuation receives a `SandboxResumeContext`, NOT a HandlerContext
//! (the request's read buffer is recycled while parked), and the result
//! borrows the slot recv buffer (valid only inside the continuation call).

const std = @import("std");
const response = @import("../response/response.zig");

/// Maximum stash size, in bytes (carried across the park). Plain data only.
pub const STASH_CAPACITY: usize = 256;

/// Reply trailer separator: the guest agent streams stdout+stderr, then
/// `0x1e<exit-code>\n` (see Nether's control protocol).
pub const TRAILER: u8 = 0x1e;

/// Errors delivered through `SandboxResumeContext.result`. A non-zero guest
/// exit code is NOT one of these: it is a successful exec carried in
/// `SandboxResult.exit_code`. These are transport/lifecycle failures.
pub const SandboxError = error{
    /// Exec deadline elapsed before the guest replied.
    Timeout,
    /// The sandbox connection died (or was respawning) before completion.
    ConnectionLost,
    /// The reply exceeded the per-op recv buffer cap.
    ResultTooLarge,
    /// The reply framing was malformed.
    Malformed,
};

/// Synchronous failures of `exec()` itself, surfaced to the handler while it
/// still holds the request.
pub const QueryError = error{
    /// No ready sandbox in the pool.
    NotConnected,
    /// All sandboxes busy; shed load now.
    QueueFull,
    /// This request already has a parked op.
    AlreadyParked,
    /// The park table is full.
    ParkTableFull,
    /// command + framing did not fit the per-op send buffer.
    RequestTooLarge,
};

pub const Continuation = *const fn (rctx: *SandboxResumeContext) response.Response;

/// A completed exec. `output` (merged stdout+stderr) borrows the slot recv
/// buffer: valid ONLY during the continuation call. Copy what you need into
/// `response_buf`/arena before returning.
pub const SandboxResult = struct {
    output: []const u8,
    exit_code: i32,
};

/// Parse one framed reply out of `buf`. Returns the result and the number of
/// bytes consumed (through the trailing newline), or null when more bytes are
/// needed. `error.Malformed` if the exit-code field is not an integer.
pub const ParseResult = struct { result: SandboxResult, consumed: usize };

pub fn parseReply(buf: []const u8) SandboxError!?ParseResult {
    const sep = std.mem.indexOfScalar(u8, buf, TRAILER) orelse return null;
    // After the separator: ASCII exit code terminated by '\n'.
    const rest = buf[sep + 1 ..];
    const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return null; // trailer not complete yet
    const code_str = rest[0..nl];
    const exit_code = std.fmt.parseInt(i32, code_str, 10) catch return error.Malformed;
    return ParseResult{
        .result = .{ .output = buf[0..sep], .exit_code = exit_code },
        .consumed = sep + 1 + nl + 1,
    };
}

/// Reject stash types that contain pointers/slices: anything they point at is
/// recycled while parked. Same invariant as the PG handler API.
pub fn assertPlainData(comptime T: type) void {
    switch (@typeInfo(T)) {
        .int, .float, .bool, .void, .@"enum" => {},
        .array => |a| assertPlainData(a.child),
        .optional => |o| assertPlainData(o.child),
        .@"struct" => |s| inline for (s.fields) |f| assertPlainData(f.type),
        .@"union" => |u| inline for (u.fields) |f| assertPlainData(f.type),
        .pointer => @compileError("sandbox stash " ++ @typeName(T) ++
            " contains a pointer/slice; copy into a fixed array instead (recycled while parked)"),
        else => @compileError("sandbox stash " ++ @typeName(T) ++ " is not plain data"),
    }
}

/// Chaining hook installed by the client at resume time (opaque to avoid a
/// handler_api -> client import cycle).
pub const ReexecFn = *const fn (
    ctx: *anyopaque,
    command: []const u8,
    continuation: Continuation,
) QueryError!response.Response;

/// What a continuation gets. No request field (read buffer recycled);
/// borrow-only result; typed stash carried from the issuing handler.
pub const SandboxResumeContext = struct {
    result: SandboxError!SandboxResult,
    response_buf: []u8,
    response_headers: []response.Header,
    response_header_count: usize = 0,
    arena: std.heap.FixedBufferAllocator,
    stash_bytes: *[STASH_CAPACITY]u8,
    reexec_ctx: *anyopaque,
    reexec_fn: ReexecFn,

    pub fn stash(self: *SandboxResumeContext, comptime T: type) *T {
        comptime assertPlainData(T);
        comptime std.debug.assert(@sizeOf(T) <= STASH_CAPACITY);
        return @ptrCast(@alignCast(self.stash_bytes));
    }

    pub fn allocator(self: *SandboxResumeContext) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Run the next command in a chain and re-park (the step-switch pattern).
    pub fn exec(
        self: *SandboxResumeContext,
        command: []const u8,
        continuation: Continuation,
    ) QueryError!response.Response {
        return self.reexec_fn(self.reexec_ctx, command, continuation);
    }
};

// ── tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "parseReply: complete frame" {
    const r = (try parseReply("hello world\x1e0\n")).?;
    try testing.expectEqualStrings("hello world", r.result.output);
    try testing.expectEqual(@as(i32, 0), r.result.exit_code);
    try testing.expectEqual(@as(usize, 14), r.consumed);
}

test "parseReply: non-zero exit" {
    const r = (try parseReply("oops\x1e7\n")).?;
    try testing.expectEqualStrings("oops", r.result.output);
    try testing.expectEqual(@as(i32, 7), r.result.exit_code);
}

test "parseReply: incomplete (no trailer yet)" {
    try testing.expectEqual(@as(?ParseResult, null), try parseReply("partial output so far"));
}

test "parseReply: separator present but exit code not terminated" {
    // trailer started (0x1e seen) but the \n hasn't arrived.
    try testing.expectEqual(@as(?ParseResult, null), try parseReply("out\x1e1"));
}

test "parseReply: malformed exit code" {
    try testing.expectError(error.Malformed, parseReply("out\x1eNaN\n"));
}

test "parseReply: empty output, exit 0" {
    const r = (try parseReply("\x1e0\n")).?;
    try testing.expectEqualStrings("", r.result.output);
    try testing.expectEqual(@as(i32, 0), r.result.exit_code);
}

test "assertPlainData accepts a plain stash" {
    comptime assertPlainData(struct { step: u8, id: u64, name: [32]u8 });
}
