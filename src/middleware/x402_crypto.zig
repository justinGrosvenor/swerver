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

// ============================================================
// EIP-712 / EIP-3009 TransferWithAuthorization verification
//
// x402's `exact` scheme on EVM chains has the payer sign an EIP-3009
// TransferWithAuthorization as EIP-712 typed data over the token's domain.
// To verify locally we reconstruct the EIP-712 digest from the payment
// envelope plus the route's configured domain (token name/version, chainId,
// token address), recover the signer, and require it to equal
// authorization.from — and authorization.to to equal the merchant.
// ============================================================

/// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
const DOMAIN_TYPEHASH = blk: {
    @setEvalBranchQuota(100000);
    break :blk keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
};
/// keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
const TRANSFER_TYPEHASH = blk: {
    @setEvalBranchQuota(100000);
    break :blk keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
};

pub const Eip712Domain = struct {
    name: []const u8,
    version: []const u8,
    chain_id: u64,
    /// Token contract address ("0x" + 40 hex).
    verifying_contract: []const u8,
};

pub const TransferAuthorization = struct {
    from: []const u8,
    to: []const u8,
    /// Decimal strings (uint256).
    value: []const u8,
    valid_after: []const u8,
    valid_before: []const u8,
    /// "0x" + 64 hex (bytes32).
    nonce: []const u8,
};

pub const VerifyParams = struct {
    name: []const u8,
    version: []const u8,
    chain_id: u64,
    verifying_contract: []const u8,
    /// Expected authorization.to (the configured merchant / pay_to).
    merchant: []const u8,
    /// Minimum acceptable authorization.value (decimal token base units).
    /// Empty disables the amount check (e.g. unit tests of the signature
    /// path only). The full gateway always sets this to the route price.
    min_value: []const u8 = "",
    /// Current Unix time (seconds) for the validAfter/validBefore window
    /// check. Zero disables the window check.
    now_unix: i64 = 0,
};

/// Compare two non-negative decimal integer strings. Returns true when
/// `a < b`. Arbitrary precision (token amounts can exceed u64); compares
/// by significant-digit length then lexicographically. Non-digit input
/// is treated as larger-than-everything so callers reject it via the
/// surrounding logic (an unparseable value never satisfies `value >= min`).
fn decimalLessThan(a_in: []const u8, b_in: []const u8) bool {
    const a = stripLeadingZeros(a_in);
    const b = stripLeadingZeros(b_in);
    if (!allDigits(a) or !allDigits(b)) return false;
    if (a.len != b.len) return a.len < b.len;
    return std.mem.lessThan(u8, a, b);
}

fn stripLeadingZeros(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i + 1 < s.len and s[i] == '0') : (i += 1) {}
    return s[i..];
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn stripHex(s: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) s[2..] else s;
}

/// 20-byte EVM address from hex, left-padded into a 32-byte ABI word.
fn addrWord(s: []const u8) ?[32]u8 {
    const h = stripHex(s);
    if (h.len != 40) return null;
    var out = [_]u8{0} ** 32;
    for (0..20) |i| out[12 + i] = std.fmt.parseInt(u8, h[i * 2 ..][0..2], 16) catch return null;
    return out;
}

fn addr20(s: []const u8) ?[20]u8 {
    const h = stripHex(s);
    if (h.len != 40) return null;
    var out: [20]u8 = undefined;
    for (0..20) |i| out[i] = std.fmt.parseInt(u8, h[i * 2 ..][0..2], 16) catch return null;
    return out;
}

fn bytes32(s: []const u8) ?[32]u8 {
    const h = stripHex(s);
    if (h.len != 64) return null;
    var out: [32]u8 = undefined;
    for (0..32) |i| out[i] = std.fmt.parseInt(u8, h[i * 2 ..][0..2], 16) catch return null;
    return out;
}

/// Decimal string → 32-byte big-endian uint256. Rejects non-digits and
/// values that overflow 2^256.
fn decWord(s: []const u8) ?[32]u8 {
    if (s.len == 0) return null;
    var out = [_]u8{0} ** 32;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return null;
        var carry: u16 = ch - '0';
        var i: usize = 32;
        while (i > 0) {
            i -= 1;
            const v: u16 = @as(u16, out[i]) * 10 + carry;
            out[i] = @intCast(v & 0xff);
            carry = v >> 8;
        }
        if (carry != 0) return null; // > 2^256
    }
    return out;
}

fn u64Word(v: u64) [32]u8 {
    var out = [_]u8{0} ** 32;
    std.mem.writeInt(u64, out[24..32], v, .big);
    return out;
}

fn sig65(s: []const u8) ?[65]u8 {
    const h = stripHex(s);
    if (h.len != 130) return null;
    var out: [65]u8 = undefined;
    for (0..65) |i| out[i] = std.fmt.parseInt(u8, h[i * 2 ..][0..2], 16) catch return null;
    return out;
}

fn domainSeparator(d: Eip712Domain) ?[32]u8 {
    const vc = addrWord(d.verifying_contract) orelse return null;
    var buf: [160]u8 = undefined;
    @memcpy(buf[0..32], &DOMAIN_TYPEHASH);
    @memcpy(buf[32..64], &keccak256(d.name));
    @memcpy(buf[64..96], &keccak256(d.version));
    @memcpy(buf[96..128], &u64Word(d.chain_id));
    @memcpy(buf[128..160], &vc);
    return keccak256(&buf);
}

fn transferStructHash(a: TransferAuthorization) ?[32]u8 {
    const from = addrWord(a.from) orelse return null;
    const to = addrWord(a.to) orelse return null;
    const value = decWord(a.value) orelse return null;
    const va = decWord(a.valid_after) orelse return null;
    const vb = decWord(a.valid_before) orelse return null;
    const nonce = bytes32(a.nonce) orelse return null;
    var buf: [224]u8 = undefined;
    @memcpy(buf[0..32], &TRANSFER_TYPEHASH);
    @memcpy(buf[32..64], &from);
    @memcpy(buf[64..96], &to);
    @memcpy(buf[96..128], &value);
    @memcpy(buf[128..160], &va);
    @memcpy(buf[160..192], &vb);
    @memcpy(buf[192..224], &nonce);
    return keccak256(&buf);
}

/// EIP-712 digest: keccak256(0x1901 || domainSeparator || hashStruct(message)).
pub fn eip712Digest(domain: Eip712Domain, auth: TransferAuthorization) ?[32]u8 {
    const ds = domainSeparator(domain) orelse return null;
    const sh = transferStructHash(auth) orelse return null;
    var buf: [66]u8 = undefined;
    buf[0] = 0x19;
    buf[1] = 0x01;
    @memcpy(buf[2..34], &ds);
    @memcpy(buf[34..66], &sh);
    return keccak256(&buf);
}

/// Verify an x402 `exact`-scheme (EIP-3009) payment envelope locally:
/// rebuild the EIP-712 digest, recover the signer, and require it to equal
/// authorization.from, with authorization.to equal to the configured
/// merchant. Returns true only if both hold; any parse/shape failure → false.
/// This is a cheap forgery pre-filter; the facilitator still verifies funding
/// and nonce state on-chain.
pub fn verifyPaymentSignature(payment_json: []const u8, params: VerifyParams) bool {
    if (!has_crypto) return false;

    var arena_buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);

    // Both x402 v1 and v2 envelopes nest the signed material under
    // `payload`: { signature, authorization: { from, to, value, ... } }.
    const Auth = struct {
        from: []const u8 = "",
        to: []const u8 = "",
        value: []const u8 = "",
        validAfter: []const u8 = "",
        validBefore: []const u8 = "",
        nonce: []const u8 = "",
    };
    const Payload = struct {
        signature: []const u8 = "",
        authorization: Auth = .{},
    };
    const Envelope = struct {
        payload: Payload = .{},
    };
    const env = std.json.parseFromSliceLeaky(Envelope, fba.allocator(), payment_json, .{
        .ignore_unknown_fields = true,
    }) catch return false;

    const a = env.payload.authorization;
    if (env.payload.signature.len == 0 or a.from.len == 0 or a.to.len == 0) return false;

    // authorization.to must be the configured merchant.
    if (!std.ascii.eqlIgnoreCase(a.to, params.merchant)) return false;

    // Amount: the authorized value must cover the required price. Without
    // this a client can sign a valid transfer for "1" and pass the filter.
    if (params.min_value.len > 0) {
        if (decimalLessThan(a.value, params.min_value)) return false;
    }

    // Validity window (EIP-3009 validAfter/validBefore, decimal Unix
    // seconds). Reject expired or not-yet-valid authorizations, and reject
    // unparseable bounds when a window check was requested.
    if (params.now_unix > 0) {
        const va = std.fmt.parseInt(i64, a.validAfter, 10) catch return false;
        const vb = std.fmt.parseInt(i64, a.validBefore, 10) catch return false;
        if (params.now_unix < va or params.now_unix > vb) return false;
    }

    const digest = eip712Digest(.{
        .name = params.name,
        .version = params.version,
        .chain_id = params.chain_id,
        .verifying_contract = params.verifying_contract,
    }, .{
        .from = a.from,
        .to = a.to,
        .value = a.value,
        .valid_after = a.validAfter,
        .valid_before = a.validBefore,
        .nonce = a.nonce,
    }) orelse return false;

    const sig = sig65(env.payload.signature) orelse return false;
    const recovered = ecrecover(digest, sig) catch return false;
    const expected_from = addr20(a.from) orelse return false;
    return std.mem.eql(u8, &recovered, &expected_from);
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

// --- EIP-712 / EIP-3009 verification ---
//
// Golden vector generated with ethers v6 signTypedData using the test key
// (0x4c0883...e3b4 → 0xb2BA25C6...). Domain: USD Coin v2 / chainId 8453 /
// USDC@Base. The intermediate domain-separator, struct-hash, and digest
// values are asserted directly so an encoding bug is localized rather than
// only surfacing as a recovery mismatch.

const VEC_DOMAIN = Eip712Domain{
    .name = "USD Coin",
    .version = "2",
    .chain_id = 8453,
    .verifying_contract = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
};
const VEC_AUTH = TransferAuthorization{
    .from = "0xb2BA25C6A5d758a6599A400FFA8810e68b2Ac4Db",
    .to = "0x000000000000000000000000000000000000dEaD",
    .value = "10000",
    .valid_after = "0",
    .valid_before = "1900000000",
    .nonce = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
};
// Full v2 envelope carrying VEC_AUTH plus the matching signature.
const VEC_ENVELOPE =
    \\{"x402Version":2,"payload":{"signature":"0x61cf25d6dc05ff0c98238d2c8aa1def38222c6a4c2c0d2b66375c2d4ab1968266a4bb6f56db95f4ef9f7fb73b28c63e20f391f5969c8d32f3722ff40c9858ea01c","authorization":{"from":"0xb2BA25C6A5d758a6599A400FFA8810e68b2Ac4Db","to":"0x000000000000000000000000000000000000dEaD","value":"10000","validAfter":"0","validBefore":"1900000000","nonce":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}},"accepted":{"scheme":"exact","network":"eip155:8453"}}
;
const VEC_PARAMS = VerifyParams{
    .name = "USD Coin",
    .version = "2",
    .chain_id = 8453,
    .verifying_contract = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    .merchant = "0x000000000000000000000000000000000000dEaD",
};

// Pure keccak — these run in every build, no OpenSSL needed.
test "eip712: domain separator matches ethers" {
    const ds = domainSeparator(VEC_DOMAIN).?;
    const expected = hexToBytes("02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f");
    try std.testing.expectEqualSlices(u8, &expected, &ds);
}

test "eip712: transfer struct hash matches ethers" {
    const sh = transferStructHash(VEC_AUTH).?;
    const expected = hexToBytes("df36f3da18e07b411a82073d8dc76c8ec8545101847a3bcaafbe07cda166129d");
    try std.testing.expectEqualSlices(u8, &expected, &sh);
}

test "eip712: digest matches ethers" {
    const d = eip712Digest(VEC_DOMAIN, VEC_AUTH).?;
    const expected = hexToBytes("6fa4591f063ae11f6f5aa7ef0957dbf9bc0b6da8ec4bd2b874249f81419f33ef");
    try std.testing.expectEqualSlices(u8, &expected, &d);
}

test "decWord: decimal string to 32-byte big-endian uint256" {
    const ten_k = decWord("10000").?; // 0x2710
    var expected = [_]u8{0} ** 32;
    expected[30] = 0x27;
    expected[31] = 0x10;
    try std.testing.expectEqualSlices(u8, &expected, &ten_k);

    const zero = decWord("0").?;
    const z32 = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, &z32, &zero);

    try std.testing.expect(decWord("") == null);
    try std.testing.expect(decWord("12a") == null);
}

// --- verifyPaymentSignature (full path; ecrecover needs OpenSSL) ---

test "verifyPaymentSignature: accepts a valid EIP-3009 authorization" {
    if (!has_crypto) return error.SkipZigTest;
    try std.testing.expect(verifyPaymentSignature(VEC_ENVELOPE, VEC_PARAMS));
}

test "verifyPaymentSignature: rejects a tampered signature" {
    if (!has_crypto) return error.SkipZigTest;
    // Same r/s but v flipped 0x1c -> 0x1b: recovers the *other* candidate
    // key, so the recovered signer no longer equals authorization.from.
    const tampered =
        \\{"x402Version":2,"payload":{"signature":"0x61cf25d6dc05ff0c98238d2c8aa1def38222c6a4c2c0d2b66375c2d4ab1968266a4bb6f56db95f4ef9f7fb73b28c63e20f391f5969c8d32f3722ff40c9858ea01b","authorization":{"from":"0xb2BA25C6A5d758a6599A400FFA8810e68b2Ac4Db","to":"0x000000000000000000000000000000000000dEaD","value":"10000","validAfter":"0","validBefore":"1900000000","nonce":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}}}
    ;
    try std.testing.expect(!verifyPaymentSignature(tampered, VEC_PARAMS));
}

test "verifyPaymentSignature: rejects when authorization.to != merchant" {
    if (!has_crypto) return error.SkipZigTest;
    var params = VEC_PARAMS;
    params.merchant = "0x0000000000000000000000000000000000000001";
    try std.testing.expect(!verifyPaymentSignature(VEC_ENVELOPE, params));
}

test "verifyPaymentSignature: rejects a wrong EIP-712 domain (chainId)" {
    if (!has_crypto) return error.SkipZigTest;
    // Correct signature, wrong domain → different digest → recovered != from.
    var params = VEC_PARAMS;
    params.chain_id = 1;
    try std.testing.expect(!verifyPaymentSignature(VEC_ENVELOPE, params));
}

test "verifyPaymentSignature: rejects empty / malformed / missing fields" {
    if (!has_crypto) return error.SkipZigTest;
    try std.testing.expect(!verifyPaymentSignature("{}", VEC_PARAMS));
    try std.testing.expect(!verifyPaymentSignature("not json at all", VEC_PARAMS));
    try std.testing.expect(!verifyPaymentSignature(
        \\{"payload":{"authorization":{"from":"0xb2BA25C6A5d758a6599A400FFA8810e68b2Ac4Db","to":"0x000000000000000000000000000000000000dEaD"}}}
    , VEC_PARAMS));
}

test "verifyPaymentSignature: rejects an underpaid authorization" {
    if (!has_crypto) return error.SkipZigTest;
    var params = VEC_PARAMS;
    // VEC value is 10000; require more than that.
    params.min_value = "10001";
    try std.testing.expect(!verifyPaymentSignature(VEC_ENVELOPE, params));
    // Exact and over-payment are accepted.
    params.min_value = "10000";
    try std.testing.expect(verifyPaymentSignature(VEC_ENVELOPE, params));
    params.min_value = "9999";
    try std.testing.expect(verifyPaymentSignature(VEC_ENVELOPE, params));
}

test "verifyPaymentSignature: rejects outside the validity window" {
    if (!has_crypto) return error.SkipZigTest;
    var params = VEC_PARAMS;
    // VEC window is validAfter=0, validBefore=1900000000.
    params.now_unix = 1900000001; // expired
    try std.testing.expect(!verifyPaymentSignature(VEC_ENVELOPE, params));
    params.now_unix = 1_000_000; // within window
    try std.testing.expect(verifyPaymentSignature(VEC_ENVELOPE, params));
}

test "decimalLessThan: arbitrary-precision decimal comparison" {
    try std.testing.expect(decimalLessThan("9", "10"));
    try std.testing.expect(!decimalLessThan("10", "9"));
    try std.testing.expect(!decimalLessThan("100", "100"));
    try std.testing.expect(decimalLessThan("00099", "100")); // leading zeros
    try std.testing.expect(!decimalLessThan(
        "999999999999999999999999999",
        "1000000000000000000000000",
    ));
    // Non-digit input never compares as less (so value >= min fails).
    try std.testing.expect(!decimalLessThan("12a", "100"));
}
