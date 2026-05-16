const std = @import("std");
const build_options = @import("build_options");

// ============================================================
// Keccak-256 (pure Zig)
// ============================================================

const KECCAK_ROUNDS = 24;
const KECCAK_RATE = 136; // 1088 bits for keccak-256
const KECCAK_STATE_SIZE = 25; // 5x5 u64

const RC = [KECCAK_ROUNDS]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

const ROT = [25]u6{
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
};

const PI = [25]u5{
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
};

fn keccakF(state: *[KECCAK_STATE_SIZE]u64) void {
    for (0..KECCAK_ROUNDS) |round| {
        var c: [5]u64 = undefined;
        for (0..5) |x| {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (0..5) |x| {
            const d = c[(x + 4) % 5] ^ std.math.rotl(u64, c[(x + 1) % 5], 1);
            for (0..5) |y| {
                state[x + 5 * y] ^= d;
            }
        }

        var temp: [KECCAK_STATE_SIZE]u64 = undefined;
        for (0..25) |i| {
            temp[PI[i]] = std.math.rotl(u64, state[i], ROT[i]);
        }

        for (0..5) |y| {
            const base = 5 * y;
            for (0..5) |x| {
                state[base + x] = temp[base + x] ^ (~temp[base + (x + 1) % 5] & temp[base + (x + 2) % 5]);
            }
        }

        state[0] ^= RC[round];
    }
}

pub fn keccak256(data: []const u8) [32]u8 {
    var state = [_]u64{0} ** KECCAK_STATE_SIZE;
    var offset: usize = 0;

    while (offset + KECCAK_RATE <= data.len) {
        for (0..KECCAK_RATE / 8) |i| {
            state[i] ^= std.mem.readInt(u64, data[offset + i * 8 ..][0..8], .little);
        }
        keccakF(&state);
        offset += KECCAK_RATE;
    }

    var last_block = [_]u8{0} ** KECCAK_RATE;
    const remaining = data.len - offset;
    @memcpy(last_block[0..remaining], data[offset..]);
    last_block[remaining] = 0x01; // keccak padding (NOT SHA-3's 0x06)
    last_block[KECCAK_RATE - 1] |= 0x80;

    for (0..KECCAK_RATE / 8) |i| {
        state[i] ^= std.mem.readInt(u64, last_block[i * 8 ..][0..8], .little);
    }
    keccakF(&state);

    var out: [32]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u64, out[i * 8 ..][0..8], state[i], .little);
    }
    return out;
}

// ============================================================
// EIP-191 message hashing
// ============================================================

pub fn eip191Hash(message: []const u8) [32]u8 {
    const prefix = "\x19Ethereum Signed Message:\n";
    var len_buf: [20]u8 = undefined;
    const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{message.len}) catch unreachable;

    var buf: [4096]u8 = undefined;
    const total = prefix.len + len_str.len + message.len;
    if (total > buf.len) return keccak256(message);

    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..len_str.len], len_str);
    @memcpy(buf[prefix.len + len_str.len ..][0..message.len], message);
    return keccak256(buf[0..total]);
}

// ============================================================
// secp256k1 ecrecover via OpenSSL FFI (requires enable_x402_crypto)
// ============================================================

const has_crypto = build_options.enable_x402_crypto;

const EC_KEY = opaque {};
const EC_GROUP = opaque {};
const EC_POINT = opaque {};
const BIGNUM = opaque {};
const BN_CTX_T = opaque {};
const ECDSA_SIG = opaque {};

const NID_secp256k1: c_int = 714;
const POINT_CONVERSION_UNCOMPRESSED: c_int = 4;

const ssl = if (has_crypto) struct {
    extern fn EC_KEY_new_by_curve_name(nid: c_int) ?*EC_KEY;
    extern fn EC_KEY_free(key: *EC_KEY) void;
    extern fn EC_KEY_get0_group(key: *const EC_KEY) *const EC_GROUP;
    extern fn EC_GROUP_get_order(group: *const EC_GROUP, order: *BIGNUM, ctx: *BN_CTX_T) c_int;
    extern fn EC_POINT_new(group: *const EC_GROUP) ?*EC_POINT;
    extern fn EC_POINT_free(point: *EC_POINT) void;
    extern fn EC_POINT_mul(group: *const EC_GROUP, r: *EC_POINT, n: ?*const BIGNUM, q: ?*const EC_POINT, m: ?*const BIGNUM, ctx: *BN_CTX_T) c_int;
    extern fn EC_POINT_add(group: *const EC_GROUP, r: *EC_POINT, a: *const EC_POINT, b: *const EC_POINT, ctx: *BN_CTX_T) c_int;
    extern fn EC_POINT_oct2point(group: *const EC_GROUP, p: *EC_POINT, buf: [*]const u8, len: usize, ctx: *BN_CTX_T) c_int;
    extern fn EC_POINT_point2oct(group: *const EC_GROUP, p: *const EC_POINT, form: c_int, buf: [*]u8, len: usize, ctx: *BN_CTX_T) usize;
    extern fn BN_new() ?*BIGNUM;
    extern fn BN_free(bn: *BIGNUM) void;
    extern fn BN_bin2bn(s: [*]const u8, len: c_int, ret: ?*BIGNUM) ?*BIGNUM;
    extern fn BN_mod_inverse(r: ?*BIGNUM, a: *const BIGNUM, n: *const BIGNUM, ctx: *BN_CTX_T) ?*BIGNUM;
    extern fn BN_mod_mul(r: *BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *BN_CTX_T) c_int;
    extern fn BN_CTX_new() ?*BN_CTX_T;
    extern fn BN_CTX_free(ctx: *BN_CTX_T) void;
} else struct {};

pub const EcrecoverError = error{
    OpenSSLError,
    InvalidSignature,
    InvalidRecoveryId,
    CryptoNotEnabled,
};

pub fn ecrecover(msg_hash: [32]u8, sig: [65]u8) EcrecoverError![20]u8 {
    if (!has_crypto) return error.CryptoNotEnabled;

    const r_bytes = sig[0..32];
    const s_bytes = sig[32..64];
    const v_raw = sig[64];
    const recovery_id: u8 = if (v_raw >= 27) v_raw - 27 else v_raw;
    if (recovery_id > 1) return error.InvalidRecoveryId;

    const ctx = ssl.BN_CTX_new() orelse return error.OpenSSLError;
    defer ssl.BN_CTX_free(ctx);

    const key = ssl.EC_KEY_new_by_curve_name(NID_secp256k1) orelse return error.OpenSSLError;
    defer ssl.EC_KEY_free(key);

    const group = ssl.EC_KEY_get0_group(key);

    const order = ssl.BN_new() orelse return error.OpenSSLError;
    defer ssl.BN_free(order);
    if (ssl.EC_GROUP_get_order(group, order, ctx) != 1) return error.OpenSSLError;

    const r_bn = ssl.BN_bin2bn(r_bytes.ptr, 32, null) orelse return error.OpenSSLError;
    defer ssl.BN_free(r_bn);
    const s_bn = ssl.BN_bin2bn(s_bytes.ptr, 32, null) orelse return error.OpenSSLError;
    defer ssl.BN_free(s_bn);
    const e_bn = ssl.BN_bin2bn(&msg_hash, 32, null) orelse return error.OpenSSLError;
    defer ssl.BN_free(e_bn);

    // R point: encode r as x-coordinate with recovery_id parity
    var r_point_bytes: [33]u8 = undefined;
    r_point_bytes[0] = 0x02 + recovery_id;
    @memcpy(r_point_bytes[1..33], r_bytes);

    const R = ssl.EC_POINT_new(group) orelse return error.OpenSSLError;
    defer ssl.EC_POINT_free(R);
    if (ssl.EC_POINT_oct2point(group, R, &r_point_bytes, 33, ctx) != 1) return error.InvalidSignature;

    // r_inv = r^(-1) mod n
    const r_inv = ssl.BN_mod_inverse(null, r_bn, order, ctx) orelse return error.InvalidSignature;
    defer ssl.BN_free(r_inv);

    // Q = r_inv * (s*R - e*G)
    const sR = ssl.EC_POINT_new(group) orelse return error.OpenSSLError;
    defer ssl.EC_POINT_free(sR);
    if (ssl.EC_POINT_mul(group, sR, null, R, s_bn, ctx) != 1) return error.OpenSSLError;

    const eG = ssl.EC_POINT_new(group) orelse return error.OpenSSLError;
    defer ssl.EC_POINT_free(eG);
    if (ssl.EC_POINT_mul(group, eG, e_bn, null, null, ctx) != 1) return error.OpenSSLError;

    // Negate eG by flipping y-coordinate (p - y)
    var eg_buf: [65]u8 = undefined;
    const eg_len = ssl.EC_POINT_point2oct(group, eG, POINT_CONVERSION_UNCOMPRESSED, &eg_buf, 65, ctx);
    if (eg_len != 65) return error.OpenSSLError;

    const P_BYTES = [32]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
    };

    var neg_y: [32]u8 = undefined;
    var borrow: u1 = 0;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        const a: u16 = P_BYTES[i];
        const b: u16 = @as(u16, eg_buf[33 + i]) + borrow;
        if (a >= b) {
            neg_y[i] = @intCast(a - b);
            borrow = 0;
        } else {
            neg_y[i] = @intCast(a + 256 - b);
            borrow = 1;
        }
    }

    var neg_eg_buf: [65]u8 = undefined;
    neg_eg_buf[0] = 0x04;
    @memcpy(neg_eg_buf[1..33], eg_buf[1..33]);
    @memcpy(neg_eg_buf[33..65], &neg_y);

    const neg_eG = ssl.EC_POINT_new(group) orelse return error.OpenSSLError;
    defer ssl.EC_POINT_free(neg_eG);
    if (ssl.EC_POINT_oct2point(group, neg_eG, &neg_eg_buf, 65, ctx) != 1) return error.OpenSSLError;

    // diff = sR + (-eG)
    const diff = ssl.EC_POINT_new(group) orelse return error.OpenSSLError;
    defer ssl.EC_POINT_free(diff);
    if (ssl.EC_POINT_add(group, diff, sR, neg_eG, ctx) != 1) return error.OpenSSLError;

    // Q = r_inv * diff
    const Q = ssl.EC_POINT_new(group) orelse return error.OpenSSLError;
    defer ssl.EC_POINT_free(Q);
    if (ssl.EC_POINT_mul(group, Q, null, diff, r_inv, ctx) != 1) return error.OpenSSLError;

    // Ethereum address = keccak256(pubkey_x || pubkey_y)[12..32]
    var pub_buf: [65]u8 = undefined;
    const pub_len = ssl.EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, &pub_buf, 65, ctx);
    if (pub_len != 65) return error.OpenSSLError;

    const hash = keccak256(pub_buf[1..65]);
    var addr: [20]u8 = undefined;
    @memcpy(&addr, hash[12..32]);
    return addr;
}

pub fn verifyPaymentSignature(payment_json: []const u8, expected_pay_to: []const u8) bool {
    if (!has_crypto) return false;

    var arena_buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);

    const Parsed = struct {
        signature: []const u8 = "",
        payload: std.json.Value = .null,
    };
    const parsed = std.json.parseFromSliceLeaky(Parsed, fba.allocator(), payment_json, .{
        .ignore_unknown_fields = true,
    }) catch return false;

    if (parsed.signature.len == 0) return false;

    var payload_buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buf);
    std.json.Stringify.value(parsed.payload, .{}, &writer) catch return false;
    const payload_str = writer.buffered();

    const msg_hash = eip191Hash(payload_str);

    const sig_hex = if (std.mem.startsWith(u8, parsed.signature, "0x"))
        parsed.signature[2..]
    else
        parsed.signature;
    if (sig_hex.len != 130) return false;

    var sig_bytes: [65]u8 = undefined;
    for (0..65) |idx| {
        sig_bytes[idx] = std.fmt.parseInt(u8, sig_hex[idx * 2 ..][0..2], 16) catch return false;
    }

    const recovered_addr = ecrecover(msg_hash, sig_bytes) catch return false;

    const addr_hex = if (std.mem.startsWith(u8, expected_pay_to, "0x"))
        expected_pay_to[2..]
    else
        expected_pay_to;
    if (addr_hex.len != 40) return false;

    var expected_bytes: [20]u8 = undefined;
    for (0..20) |idx| {
        expected_bytes[idx] = std.fmt.parseInt(u8, addr_hex[idx * 2 ..][0..2], 16) catch return false;
    }

    return std.mem.eql(u8, &recovered_addr, &expected_bytes);
}

// ============================================================
// Tests
// ============================================================

// Test key: 0x4c0883a69102937d6231471b5dbb6204fe512961708279f15e12f8d6e3e8e3b4
// Address:  0xb2BA25C6A5d758a6599A400FFA8810e68b2Ac4Db
// Generated with ethers.js v6 — DO NOT use this key outside tests.
const TEST_ADDR = [20]u8{
    0xb2, 0xBA, 0x25, 0xC6, 0xA5, 0xd7, 0x58, 0xa6,
    0x59, 0x9A, 0x40, 0x0F, 0xFA, 0x88, 0x10, 0xe6,
    0x8b, 0x2A, 0xc4, 0xDb,
};

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    for (0..hex.len / 2) |i| {
        out[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch unreachable;
    }
    return out;
}

// --- keccak256 ---

test "keccak256: empty input" {
    const hash = keccak256("");
    const expected = hexToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "keccak256: 'abc'" {
    const hash = keccak256("abc");
    const expected = hexToBytes("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "keccak256: single byte" {
    const hash = keccak256("a");
    try std.testing.expect(!std.mem.eql(u8, &hash, &([_]u8{0} ** 32)));
    try std.testing.expect(!std.mem.eql(u8, &hash, &keccak256("")));
    try std.testing.expect(!std.mem.eql(u8, &hash, &keccak256("b")));
}

test "keccak256: exact block boundary (136 bytes)" {
    const input = "x" ** KECCAK_RATE;
    const hash = keccak256(input);
    try std.testing.expect(!std.mem.eql(u8, &hash, &([_]u8{0} ** 32)));
    try std.testing.expectEqualSlices(u8, &hash, &keccak256(input));
}

test "keccak256: one byte over block boundary (137 bytes)" {
    const input = "x" ** (KECCAK_RATE + 1);
    const hash = keccak256(input);
    try std.testing.expect(!std.mem.eql(u8, &keccak256("x" ** KECCAK_RATE), &hash));
}

test "keccak256: multi-block (200 bytes)" {
    const input = "a" ** 200;
    const hash = keccak256(input);
    try std.testing.expect(!std.mem.eql(u8, &hash, &([_]u8{0} ** 32)));
    try std.testing.expectEqualSlices(u8, &hash, &keccak256(input));
}

// --- eip191Hash ---

test "eip191Hash: known vector from ethers.js" {
    const hash = eip191Hash("hello");
    const expected = hexToBytes("50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750");
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "eip191Hash: matches manual prefix construction" {
    const prefix = "\x19Ethereum Signed Message:\n5hello";
    const direct = keccak256(prefix);
    const via_eip191 = eip191Hash("hello");
    try std.testing.expectEqualSlices(u8, &direct, &via_eip191);
}

test "eip191Hash: empty message" {
    const hash = eip191Hash("");
    const prefix = "\x19Ethereum Signed Message:\n0";
    const direct = keccak256(prefix);
    try std.testing.expectEqualSlices(u8, &direct, &hash);
}

test "eip191Hash: different messages differ" {
    try std.testing.expect(!std.mem.eql(u8, &eip191Hash("hello"), &eip191Hash("world")));
}

test "eip191Hash: length prefix handles multi-digit lengths" {
    const msg = "x" ** 100;
    const hash = eip191Hash(msg);
    const prefix = "\x19Ethereum Signed Message:\n100" ++ ("x" ** 100);
    try std.testing.expectEqualSlices(u8, &keccak256(prefix), &hash);
}

// --- ecrecover ---

test "ecrecover: crypto not enabled returns error" {
    if (has_crypto) return error.SkipZigTest;
    const hash = [_]u8{0} ** 32;
    const sig = [_]u8{0} ** 65;
    try std.testing.expectError(error.CryptoNotEnabled, ecrecover(hash, sig));
}

test "ecrecover: rejects invalid recovery id" {
    if (!has_crypto) return error.SkipZigTest;
    const hash = [_]u8{0} ** 32;
    var sig = [_]u8{0} ** 65;
    sig[64] = 4;
    try std.testing.expectError(error.InvalidRecoveryId, ecrecover(hash, sig));
}

test "ecrecover: recovers correct address from ethers.js signed 'hello'" {
    if (!has_crypto) return error.SkipZigTest;
    // ethers.Wallet.signMessage("hello") with test key
    const msg_hash = eip191Hash("hello");
    const sig = hexToBytes(
        "f9a632134647011d766a2233c3a51a5c4a3ed2eba71fecd6d37caea468a3d885" // r
        ++ "486d26649e985f075f893937ee764a351bb97a35ffd41a23564fd31f763dda3c" // s
        ++ "1c", // v = 28
    );
    const addr = try ecrecover(msg_hash, sig);
    try std.testing.expectEqualSlices(u8, &TEST_ADDR, &addr);
}

test "ecrecover: recovers correct address from ethers.js signed JSON payload" {
    if (!has_crypto) return error.SkipZigTest;
    const payload = "{\"amount\":\"10000\",\"asset\":\"0xUSDC\",\"network\":\"eip155:8453\"}";
    const msg_hash = eip191Hash(payload);
    const sig = hexToBytes(
        "693db4a72b7e8fd75c1894ace1058706c4be88a30830a63658489250e4fd8905" // r
        ++ "3fe9863ad7e748c51fab5fcbf5a44772776d1afc94d34d277a2bae702b713733" // s
        ++ "1c", // v = 28
    );
    const addr = try ecrecover(msg_hash, sig);
    try std.testing.expectEqualSlices(u8, &TEST_ADDR, &addr);
}

test "ecrecover: wrong message hash recovers different address" {
    if (!has_crypto) return error.SkipZigTest;
    const wrong_hash = eip191Hash("wrong message");
    const sig = hexToBytes(
        "f9a632134647011d766a2233c3a51a5c4a3ed2eba71fecd6d37caea468a3d885"
        ++ "486d26649e985f075f893937ee764a351bb97a35ffd41a23564fd31f763dda3c"
        ++ "1c",
    );
    const addr = try ecrecover(wrong_hash, sig);
    try std.testing.expect(!std.mem.eql(u8, &TEST_ADDR, &addr));
}

test "ecrecover: different v values produce different addresses" {
    if (!has_crypto) return error.SkipZigTest;
    const msg_hash = eip191Hash("hello");
    const sig0 = hexToBytes(
        "f9a632134647011d766a2233c3a51a5c4a3ed2eba71fecd6d37caea468a3d885"
        ++ "486d26649e985f075f893937ee764a351bb97a35ffd41a23564fd31f763dda3c"
        ++ "1b", // v = 27
    );
    var sig1 = sig0;
    sig1[64] = 0x1c; // v = 28
    const addr0 = try ecrecover(msg_hash, sig0);
    const addr1 = try ecrecover(msg_hash, sig1);
    try std.testing.expect(!std.mem.eql(u8, &addr0, &addr1));
    // v=28 is the correct one for this signature
    try std.testing.expectEqualSlices(u8, &TEST_ADDR, &addr1);
}

// --- verifyPaymentSignature ---

test "verifyPaymentSignature: rejects empty json" {
    try std.testing.expect(!verifyPaymentSignature("{}", "0x0000000000000000000000000000000000000000"));
}

test "verifyPaymentSignature: rejects missing signature" {
    const json =
        \\{"payload":{"test":true}}
    ;
    try std.testing.expect(!verifyPaymentSignature(json, "0x0000000000000000000000000000000000000000"));
}

test "verifyPaymentSignature: rejects invalid signature length" {
    const json =
        \\{"signature":"0xdeadbeef","payload":{"test":true}}
    ;
    try std.testing.expect(!verifyPaymentSignature(json, "0x0000000000000000000000000000000000000000"));
}

test "verifyPaymentSignature: rejects malformed json" {
    try std.testing.expect(!verifyPaymentSignature("not json at all", "0x0000000000000000000000000000000000000000"));
}

test "verifyPaymentSignature: rejects null payload" {
    const json =
        \\{"signature":"0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","payload":null}
    ;
    try std.testing.expect(!verifyPaymentSignature(json, "0x0000000000000000000000000000000000000000"));
}

test "verifyPaymentSignature: valid signature, wrong address returns false" {
    if (!has_crypto) return error.SkipZigTest;
    const json =
        \\{"signature":"0x693db4a72b7e8fd75c1894ace1058706c4be88a30830a63658489250e4fd89053fe9863ad7e748c51fab5fcbf5a44772776d1afc94d34d277a2bae702b7137331c","payload":{"amount":"10000","asset":"0xUSDC","network":"eip155:8453"}}
    ;
    // Correct address is 0xb2BA25C6..., use a different one
    try std.testing.expect(!verifyPaymentSignature(json, "0x0000000000000000000000000000000000000001"));
}

test "verifyPaymentSignature: valid signature, correct address returns true" {
    if (!has_crypto) return error.SkipZigTest;
    const json =
        \\{"signature":"0x693db4a72b7e8fd75c1894ace1058706c4be88a30830a63658489250e4fd89053fe9863ad7e748c51fab5fcbf5a44772776d1afc94d34d277a2bae702b7137331c","payload":{"amount":"10000","asset":"0xUSDC","network":"eip155:8453"}}
    ;
    try std.testing.expect(verifyPaymentSignature(json, "0xb2BA25C6A5d758a6599A400FFA8810e68b2Ac4Db"));
}
