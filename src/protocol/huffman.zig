const std = @import("std");

/// HPACK / QPACK Huffman code table from RFC 7541 Appendix B.
/// Both HTTP/2 (HPACK) and HTTP/3 (QPACK) use this exact table for
/// header field compression.
///
/// `decodeInto` is the callback-free entry point: hand it the raw
/// Huffman-encoded input bytes and a destination buffer, and it
/// writes the decoded ASCII bytes into the destination, returning
/// the number of bytes written.

pub const Error = error{
    InvalidHuffman,
    OutputTooSmall,
};

const MaxNodes = 1024;
pub const EosSymbol: usize = 256;

const Node = struct {
    left: i16,
    right: i16,
    symbol: i16,
};

/// Decode a Huffman-encoded byte string into `dest`. Returns the number
/// of decoded bytes written. Errors if the input is malformed or `dest`
/// is too small.
pub fn decodeInto(input: []const u8, dest: []u8) Error!usize {
    var nodes: [MaxNodes]Node = undefined;
    const root = buildTree(&nodes);
    var node: usize = root;
    var pending_bits: u32 = 0;
    var pending_len: u8 = 0;
    var out_len: usize = 0;

    for (input) |byte| {
        var bit_index: u4 = 0;
        while (bit_index < 8) : (bit_index += 1) {
            const shift: u3 = @intCast(7 - bit_index);
            const bit = (byte >> shift) & 1;
            pending_bits = (pending_bits << 1) | bit;
            if (pending_len < 32) {
                pending_len += 1;
            } else {
                return error.InvalidHuffman;
            }
            const next = if (bit == 0) nodes[node].left else nodes[node].right;
            if (next < 0) return error.InvalidHuffman;
            node = @intCast(next);
            if (nodes[node].symbol >= 0) {
                const symbol: usize = @intCast(nodes[node].symbol);
                if (symbol == EosSymbol) return error.InvalidHuffman;
                if (out_len >= dest.len) return error.OutputTooSmall;
                dest[out_len] = @intCast(symbol);
                out_len += 1;
                node = root;
                pending_bits = 0;
                pending_len = 0;
            }
        }
    }

    // Trailing bits must be a (possibly truncated) EOS prefix
    if (pending_len > 0) {
        const eos_len: u8 = HuffmanCodeLengths[EosSymbol];
        const eos_code: u32 = HuffmanCodes[EosSymbol] >> @as(u5, @intCast(32 - eos_len));
        if (pending_len > eos_len) return error.InvalidHuffman;
        const prefix = eos_code >> @as(u5, @intCast(eos_len - pending_len));
        if (pending_bits != prefix) return error.InvalidHuffman;
    }

    return out_len;
}

fn buildTree(nodes: *[MaxNodes]Node) usize {
    nodes[0] = .{ .left = -1, .right = -1, .symbol = -1 };
    var next_index: usize = 1;
    for (HuffmanCodes, 0..) |code, sym| {
        const len: u8 = HuffmanCodeLengths[sym];
        const value = code >> @as(u5, @intCast(32 - len));
        var node_index: usize = 0;
        var bit_index: i32 = @as(i32, @intCast(len)) - 1;
        while (bit_index >= 0) : (bit_index -= 1) {
            const bit = (value >> @as(u5, @intCast(bit_index))) & 1;
            const next_ptr = if (bit == 0) &nodes[node_index].left else &nodes[node_index].right;
            if (bit_index == 0) {
                if (next_index >= nodes.len) return 0;
                const new_index = next_index;
                next_index += 1;
                nodes[new_index] = .{ .left = -1, .right = -1, .symbol = @intCast(sym) };
                next_ptr.* = @intCast(new_index);
            } else {
                if (next_ptr.* < 0) {
                    if (next_index >= nodes.len) return 0;
                    const new_index = next_index;
                    next_index += 1;
                    nodes[new_index] = .{ .left = -1, .right = -1, .symbol = -1 };
                    next_ptr.* = @intCast(new_index);
                }
                node_index = @intCast(next_ptr.*);
            }
        }
    }
    return 0;
}

pub const HuffmanCodes = [_]u32{
    0xffc00000, 0xffffb000, 0xfffffe20, 0xfffffe30, 0xfffffe40, 0xfffffe50, 0xfffffe60, 0xfffffe70,
    0xfffffe80, 0xffffea00, 0xfffffff0, 0xfffffe90, 0xfffffea0, 0xfffffff4, 0xfffffeb0, 0xfffffec0,
    0xfffffed0, 0xfffffee0, 0xfffffef0, 0xffffff00, 0xffffff10, 0xffffff20, 0xfffffff8, 0xffffff30,
    0xffffff40, 0xffffff50, 0xffffff60, 0xffffff70, 0xffffff80, 0xffffff90, 0xffffffa0, 0xffffffb0,
    0x50000000, 0xfe000000, 0xfe400000, 0xffa00000, 0xffc80000, 0x54000000, 0xf8000000, 0xff400000,
    0xfe800000, 0xfec00000, 0xf9000000, 0xff600000, 0xfa000000, 0x58000000, 0x5c000000, 0x60000000,
    0x00000000, 0x08000000, 0x10000000, 0x64000000, 0x68000000, 0x6c000000, 0x70000000, 0x74000000,
    0x78000000, 0x7c000000, 0xb8000000, 0xfb000000, 0xfff80000, 0x80000000, 0xffb00000, 0xff000000,
    0xffd00000, 0x84000000, 0xba000000, 0xbc000000, 0xbe000000, 0xc0000000, 0xc2000000, 0xc4000000,
    0xc6000000, 0xc8000000, 0xca000000, 0xcc000000, 0xce000000, 0xd0000000, 0xd2000000, 0xd4000000,
    0xd6000000, 0xd8000000, 0xda000000, 0xdc000000, 0xde000000, 0xe0000000, 0xe2000000, 0xe4000000,
    0xfc000000, 0xe6000000, 0xfd000000, 0xffd80000, 0xfffe0000, 0xffe00000, 0xfff00000, 0x88000000,
    0xfffa0000, 0x18000000, 0x8c000000, 0x20000000, 0x90000000, 0x28000000, 0x94000000, 0x98000000,
    0x9c000000, 0x30000000, 0xe8000000, 0xea000000, 0xa0000000, 0xa4000000, 0xa8000000, 0x38000000,
    0xac000000, 0xec000000, 0xb0000000, 0x40000000, 0x48000000, 0xb4000000, 0xee000000, 0xf0000000,
    0xf2000000, 0xf4000000, 0xf6000000, 0xfffc0000, 0xff800000, 0xfff40000, 0xffe80000, 0xffffffc0,
    0xfffe6000, 0xffff4800, 0xfffe7000, 0xfffe8000, 0xffff4c00, 0xffff5000, 0xffff5400, 0xffffb200,
    0xffff5800, 0xffffb400, 0xffffb600, 0xffffb800, 0xffffba00, 0xffffbc00, 0xffffeb00, 0xffffbe00,
    0xffffec00, 0xffffed00, 0xffff5c00, 0xffffc000, 0xffffee00, 0xffffc200, 0xffffc400, 0xffffc600,
    0xffffc800, 0xfffee000, 0xffff6000, 0xffffca00, 0xffff6400, 0xffffcc00, 0xffffce00, 0xffffef00,
    0xffff6800, 0xfffee800, 0xfffe9000, 0xffff6c00, 0xffff7000, 0xffffd000, 0xffffd200, 0xfffef000,
    0xffffd400, 0xffff7400, 0xffff7800, 0xfffff000, 0xfffef800, 0xffff7c00, 0xffffd600, 0xffffd800,
    0xffff0000, 0xffff0800, 0xffff8000, 0xffff1000, 0xffffda00, 0xffff8400, 0xffffdc00, 0xffffde00,
    0xfffea000, 0xffff8800, 0xffff8c00, 0xffff9000, 0xffffe000, 0xffff9400, 0xffff9800, 0xffffe200,
    0xfffff800, 0xfffff840, 0xfffeb000, 0xfffe2000, 0xffff9c00, 0xffffe400, 0xffffa000, 0xfffff600,
    0xfffff880, 0xfffff8c0, 0xfffff900, 0xfffffbc0, 0xfffffbe0, 0xfffff940, 0xfffff100, 0xfffff680,
    0xfffe4000, 0xffff1800, 0xfffff980, 0xfffffc00, 0xfffffc20, 0xfffff9c0, 0xfffffc40, 0xfffff200,
    0xffff2000, 0xffff2800, 0xfffffa00, 0xfffffa40, 0xffffffd0, 0xfffffc60, 0xfffffc80, 0xfffffca0,
    0xfffec000, 0xfffff300, 0xfffed000, 0xffff3000, 0xffffa400, 0xffff3800, 0xffff4000, 0xffffe600,
    0xffffa800, 0xffffac00, 0xfffff700, 0xfffff780, 0xfffff400, 0xfffff500, 0xfffffa80, 0xffffe800,
    0xfffffac0, 0xfffffcc0, 0xfffffb00, 0xfffffb40, 0xfffffce0, 0xfffffd00, 0xfffffd20, 0xfffffd40,
    0xfffffd60, 0xffffffe0, 0xfffffd80, 0xfffffda0, 0xfffffdc0, 0xfffffde0, 0xfffffe00, 0xfffffb80,
    0xfffffffc,
};

pub const HuffmanCodeLengths = [_]u8{
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
    5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10,
    13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
    15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
    6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
};

test "huffman: decode '/' single character" {
    // From RFC 7541 Appendix B: '/' = 011000, 6 bits.
    // Padded with 2 EOS bits (1s): 0b01100011 = 0x63.
    var out: [16]u8 = undefined;
    const decoded_len = try decodeInto(&[_]u8{0x63}, &out);
    try std.testing.expectEqual(@as(usize, 1), decoded_len);
    try std.testing.expectEqual(@as(u8, '/'), out[0]);
}

test "huffman: round-trip every printable ASCII via the table" {
    // Sanity check that the Huffman table produces a unique prefix code:
    // every printable ASCII character should round-trip through the
    // bit-by-bit decoder when encoded directly from the table.
    var out: [16]u8 = undefined;
    var ch: u8 = 0x20;
    while (ch < 0x7f) : (ch += 1) {
        const code = HuffmanCodes[ch];
        const len: u5 = @intCast(HuffmanCodeLengths[ch]);
        // Pack the code's `len` MSBs followed by EOS-prefix padding.
        var bit_buf: u32 = code; // already left-aligned in u32
        const pad_bits: u5 = @intCast((8 - (len % 8)) % 8);
        // Set EOS pad bits to all 1s (RFC 7541 §5.2: trailing pad must be EOS prefix).
        const total_bits: u6 = @as(u6, len) + @as(u6, pad_bits);
        const total_bytes: usize = total_bits / 8;
        const pad_mask_shift: u5 = @intCast(32 - total_bits);
        const pad_mask: u32 = if (pad_bits > 0)
            ((@as(u32, 1) << pad_bits) - 1) << pad_mask_shift
        else
            0;
        bit_buf |= pad_mask;
        var enc: [4]u8 = undefined;
        var i: usize = 0;
        while (i < total_bytes) : (i += 1) {
            enc[i] = @intCast((bit_buf >> @intCast(24 - i * 8)) & 0xff);
        }
        const decoded_len = decodeInto(enc[0..total_bytes], &out) catch |err| {
            std.debug.print("char 0x{x} ({c}): {}\n", .{ ch, ch, err });
            return err;
        };
        try std.testing.expectEqual(@as(usize, 1), decoded_len);
        try std.testing.expectEqual(ch, out[0]);
    }
}

test "huffman: rejects invalid trailing bits" {
    // 0x60 = 0b01100000 = '/' (011000) followed by zero pad bits.
    // The pad bits must be the EOS prefix (1s), so 0 pad bits is invalid.
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.InvalidHuffman, decodeInto(&[_]u8{0x60}, &out));
}
