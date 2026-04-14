const std = @import("std");

/// Write a JSON-escaped version of `input` into `out`, returning the slice
/// of `out` that was filled. Control characters are emitted as `\u00XX` per
/// RFC 8259. Does NOT emit surrounding quotes — the caller is responsible
/// for wrapping the call in `"`/`"`. Returns `error.NoSpaceLeft` if `out`
/// is too small to hold the escaped output.
///
/// Usage pattern mirrors `std.fmt.bufPrint`:
/// ```zig
/// var off: usize = 0;
/// const escaped = try json_write.writeEscaped(buf[off..], path);
/// off += escaped.len;
/// ```
pub fn writeEscaped(out: []u8, input: []const u8) error{NoSpaceLeft}![]const u8 {
    var pos: usize = 0;
    for (input) |ch| {
        switch (ch) {
            '"' => {
                if (pos + 2 > out.len) return error.NoSpaceLeft;
                out[pos] = '\\';
                out[pos + 1] = '"';
                pos += 2;
            },
            '\\' => {
                if (pos + 2 > out.len) return error.NoSpaceLeft;
                out[pos] = '\\';
                out[pos + 1] = '\\';
                pos += 2;
            },
            '\n' => {
                if (pos + 2 > out.len) return error.NoSpaceLeft;
                out[pos] = '\\';
                out[pos + 1] = 'n';
                pos += 2;
            },
            '\r' => {
                if (pos + 2 > out.len) return error.NoSpaceLeft;
                out[pos] = '\\';
                out[pos + 1] = 'r';
                pos += 2;
            },
            '\t' => {
                if (pos + 2 > out.len) return error.NoSpaceLeft;
                out[pos] = '\\';
                out[pos + 1] = 't';
                pos += 2;
            },
            0x08 => {
                if (pos + 2 > out.len) return error.NoSpaceLeft;
                out[pos] = '\\';
                out[pos + 1] = 'b';
                pos += 2;
            },
            0x0C => {
                if (pos + 2 > out.len) return error.NoSpaceLeft;
                out[pos] = '\\';
                out[pos + 1] = 'f';
                pos += 2;
            },
            else => {
                if (ch < 0x20) {
                    // Hand-roll the 6-byte `\u00XX` form instead of going
                    // through bufPrint. Output length is known exactly, so
                    // there's no reason to allocate a format context, and
                    // this dodges any future bufPrint error-set widening.
                    if (pos + 6 > out.len) return error.NoSpaceLeft;
                    out[pos] = '\\';
                    out[pos + 1] = 'u';
                    out[pos + 2] = '0';
                    out[pos + 3] = '0';
                    const hi: u8 = ch >> 4;
                    const lo: u8 = ch & 0x0F;
                    out[pos + 4] = if (hi < 10) '0' + hi else 'a' + (hi - 10);
                    out[pos + 5] = if (lo < 10) '0' + lo else 'a' + (lo - 10);
                    pos += 6;
                } else {
                    if (pos + 1 > out.len) return error.NoSpaceLeft;
                    out[pos] = ch;
                    pos += 1;
                }
            },
        }
    }
    return out[0..pos];
}

test "writeEscaped handles plain ascii" {
    var buf: [64]u8 = undefined;
    const out = try writeEscaped(&buf, "hello world");
    try std.testing.expectEqualStrings("hello world", out);
}

test "writeEscaped escapes quotes and backslash" {
    var buf: [64]u8 = undefined;
    const out = try writeEscaped(&buf, "say \"hi\" \\");
    try std.testing.expectEqualStrings("say \\\"hi\\\" \\\\", out);
}

test "writeEscaped escapes newline tab and control chars as \\u00XX" {
    var buf: [64]u8 = undefined;
    const out = try writeEscaped(&buf, "a\nb\tc\x01d\x1fe");
    try std.testing.expectEqualStrings("a\\nb\\tc\\u0001d\\u001fe", out);
}

test "writeEscaped emits b f for backspace and form feed" {
    var buf: [32]u8 = undefined;
    const out = try writeEscaped(&buf, "\x08\x0c");
    try std.testing.expectEqualStrings("\\b\\f", out);
}

test "writeEscaped returns NoSpaceLeft when output overflows" {
    var buf: [3]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, writeEscaped(&buf, "\"\"\""));
}
