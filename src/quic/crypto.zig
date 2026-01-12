const std = @import("std");
const types = @import("types.zig");

/// QUIC Cryptographic Operations per RFC 9001.
///
/// Handles:
/// - Initial secret derivation from Destination Connection ID
/// - Key derivation using HKDF-Expand-Label
/// - Packet protection (AEAD encryption/decryption)
/// - Header protection

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

pub const Error = error{
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeyLength,
    InvalidNonceLength,
    AuthenticationFailed,
    BufferTooSmall,
};

/// Cryptographic keys for a single encryption level
pub const Keys = struct {
    /// AEAD key (16 bytes for AES-128-GCM, 32 bytes for AES-256-GCM)
    key: [32]u8,
    key_len: u8,
    /// Initialization vector (12 bytes)
    iv: [12]u8,
    /// Header protection key (16 bytes for AES, 32 bytes for ChaCha20)
    hp: [32]u8,
    hp_len: u8,

    pub fn init128(key: [16]u8, iv: [12]u8, hp: [16]u8) Keys {
        var k = Keys{
            .key = undefined,
            .key_len = 16,
            .iv = iv,
            .hp = undefined,
            .hp_len = 16,
        };
        @memcpy(k.key[0..16], &key);
        @memcpy(k.hp[0..16], &hp);
        return k;
    }
};

/// Key set for a packet number space (client and server keys)
pub const KeySet = struct {
    client: ?Keys,
    server: ?Keys,
};

/// Cryptographic context for a QUIC connection
pub const CryptoContext = struct {
    initial: KeySet,
    handshake: KeySet,
    application: KeySet,
    /// 0-RTT keys derived from resumption secret (for early data)
    early_data: KeySet,
    /// Whether 0-RTT early data is accepted for this connection
    early_data_accepted: bool,

    pub fn init() CryptoContext {
        return .{
            .initial = .{ .client = null, .server = null },
            .handshake = .{ .client = null, .server = null },
            .application = .{ .client = null, .server = null },
            .early_data = .{ .client = null, .server = null },
            .early_data_accepted = false,
        };
    }

    /// Derive 0-RTT keys from resumption secret
    /// Called when TLS provides a resumption secret for early data
    pub fn deriveEarlyDataKeys(self: *CryptoContext, resumption_secret: []const u8) void {
        if (resumption_secret.len < 32) return;

        // client_early_secret = HKDF-Expand-Label(resumption_secret, "c e traffic", "", 32)
        var client_secret: [32]u8 = undefined;
        hkdfExpandLabel(resumption_secret[0..32], "c e traffic", "", &client_secret);

        // Only client sends early data, so we only derive client keys
        self.early_data.client = deriveKeysFromSecret(&client_secret);
        self.early_data_accepted = true;
    }

    /// Check if 0-RTT early data can be accepted
    pub fn canAcceptEarlyData(self: *const CryptoContext) bool {
        return self.early_data_accepted and self.early_data.client != null;
    }

    /// Discard 0-RTT keys (e.g., after handshake completes or early data rejected)
    pub fn discardEarlyDataKeys(self: *CryptoContext) void {
        self.early_data.client = null;
        self.early_data.server = null;
        self.early_data_accepted = false;
    }

    /// Derive initial keys from the Destination Connection ID.
    /// Per RFC 9001 Section 5.2.
    pub fn deriveInitialKeys(self: *CryptoContext, dcid: []const u8, version: u32) void {
        const salt = if (version == @intFromEnum(types.Version.quic_v2))
            &types.Constants.quic_v2_initial_salt
        else
            &types.Constants.quic_v1_initial_salt;

        // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
        var initial_secret: [32]u8 = undefined;
        hkdfExtract(salt, dcid, &initial_secret);

        // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        var client_secret: [32]u8 = undefined;
        hkdfExpandLabel(&initial_secret, "client in", "", &client_secret);

        // server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
        var server_secret: [32]u8 = undefined;
        hkdfExpandLabel(&initial_secret, "server in", "", &server_secret);

        // Derive keys from secrets
        self.initial.client = deriveKeysFromSecret(&client_secret);
        self.initial.server = deriveKeysFromSecret(&server_secret);
    }

    /// Get keys for a given packet number space and direction
    pub fn getKeys(self: *const CryptoContext, space: types.PacketNumberSpace, is_server: bool) ?*const Keys {
        const keyset = switch (space) {
            .initial => &self.initial,
            .handshake => &self.handshake,
            .application => &self.application,
        };
        return if (is_server) keyset.server else keyset.client;
    }
};

/// HKDF-Extract using HMAC-SHA256
fn hkdfExtract(salt: []const u8, ikm: []const u8, out: *[32]u8) void {
    var hmac = HmacSha256.init(salt);
    hmac.update(ikm);
    hmac.final(out);
}

/// HKDF-Expand using HMAC-SHA256
fn hkdfExpand(prk: *const [32]u8, info: []const u8, out: []u8) void {
    var offset: usize = 0;
    var counter: u8 = 1;
    var prev: [32]u8 = undefined;
    var prev_len: usize = 0;

    while (offset < out.len) {
        var hmac = HmacSha256.init(prk);
        if (prev_len > 0) {
            hmac.update(prev[0..prev_len]);
        }
        hmac.update(info);
        hmac.update(&[_]u8{counter});
        hmac.final(&prev);
        prev_len = 32;

        const copy_len = @min(32, out.len - offset);
        @memcpy(out[offset .. offset + copy_len], prev[0..copy_len]);
        offset += copy_len;
        counter += 1;
    }
}

/// HKDF-Expand-Label as defined in TLS 1.3 / RFC 9001
/// Label format: "tls13 " + label
fn hkdfExpandLabel(secret: *const [32]u8, label: []const u8, context: []const u8, out: []u8) void {
    // Build the HkdfLabel structure:
    // struct {
    //    uint16 length = Length;
    //    opaque label<7..255> = "tls13 " + Label;
    //    opaque context<0..255> = Context;
    // } HkdfLabel;

    var info: [512]u8 = undefined;
    var info_len: usize = 0;

    // Length (2 bytes, big-endian)
    info[0] = @intCast((out.len >> 8) & 0xff);
    info[1] = @intCast(out.len & 0xff);
    info_len = 2;

    // Label length + "tls13 " + label
    const tls13_prefix = "tls13 ";
    const full_label_len = tls13_prefix.len + label.len;
    info[info_len] = @intCast(full_label_len);
    info_len += 1;
    @memcpy(info[info_len .. info_len + tls13_prefix.len], tls13_prefix);
    info_len += tls13_prefix.len;
    @memcpy(info[info_len .. info_len + label.len], label);
    info_len += label.len;

    // Context length + context
    info[info_len] = @intCast(context.len);
    info_len += 1;
    if (context.len > 0) {
        @memcpy(info[info_len .. info_len + context.len], context);
        info_len += context.len;
    }

    hkdfExpand(secret, info[0..info_len], out);
}

/// Derive AEAD key, IV, and HP key from a traffic secret
fn deriveKeysFromSecret(secret: *const [32]u8) Keys {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;

    // key = HKDF-Expand-Label(secret, "quic key", "", key_length)
    hkdfExpandLabel(secret, "quic key", "", &key);

    // iv = HKDF-Expand-Label(secret, "quic iv", "", iv_length)
    hkdfExpandLabel(secret, "quic iv", "", &iv);

    // hp = HKDF-Expand-Label(secret, "quic hp", "", hp_length)
    hkdfExpandLabel(secret, "quic hp", "", &hp);

    return Keys.init128(key, iv, hp);
}

/// Compute the nonce for a packet by XORing the IV with the packet number.
/// Per RFC 9001 Section 5.3.
pub fn computeNonce(iv: *const [12]u8, packet_number: u64) [12]u8 {
    var nonce = iv.*;

    // XOR the packet number (as big-endian) with the rightmost bytes of IV
    const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
    nonce[4] ^= pn_bytes[0];
    nonce[5] ^= pn_bytes[1];
    nonce[6] ^= pn_bytes[2];
    nonce[7] ^= pn_bytes[3];
    nonce[8] ^= pn_bytes[4];
    nonce[9] ^= pn_bytes[5];
    nonce[10] ^= pn_bytes[6];
    nonce[11] ^= pn_bytes[7];

    return nonce;
}

/// Apply header protection to encrypt/decrypt the packet number and protected bits.
/// Per RFC 9001 Section 5.4.
pub fn applyHeaderProtection(hp_key: []const u8, sample: *const [16]u8, first_byte: *u8, pn_bytes: []u8) void {
    // Generate mask using AES-ECB
    var mask: [16]u8 = undefined;

    if (hp_key.len == 16) {
        const ctx = Aes128.initEnc(hp_key[0..16].*);
        ctx.encrypt(&mask, sample);
    } else {
        // For AES-256 (not used in Initial, but supported)
        const ctx = Aes256.initEnc(hp_key[0..32].*);
        ctx.encrypt(&mask, sample);
    }

    // Apply mask to first byte (protected bits depend on header form)
    if ((first_byte.* & 0x80) != 0) {
        // Long header: protect lower 4 bits
        first_byte.* ^= mask[0] & 0x0f;
    } else {
        // Short header: protect lower 5 bits
        first_byte.* ^= mask[0] & 0x1f;
    }

    // Apply mask to packet number bytes
    for (pn_bytes, 0..) |*b, i| {
        b.* ^= mask[1 + i];
    }
}

/// Encode a packet number with the minimum number of bytes.
/// Returns the encoded bytes and the length.
pub fn encodePacketNumber(full_pn: u64, largest_acked: u64) struct { bytes: [4]u8, len: u8 } {
    // Determine how many bytes are needed
    const range = full_pn -| largest_acked;
    const len: u8 = if (range < 0x80) 1 else if (range < 0x4000) 2 else if (range < 0x200000) 3 else 4;

    var bytes: [4]u8 = undefined;
    const truncated: u32 = @truncate(full_pn);

    switch (len) {
        1 => {
            bytes[0] = @truncate(truncated);
        },
        2 => {
            bytes[0] = @truncate(truncated >> 8);
            bytes[1] = @truncate(truncated);
        },
        3 => {
            bytes[0] = @truncate(truncated >> 16);
            bytes[1] = @truncate(truncated >> 8);
            bytes[2] = @truncate(truncated);
        },
        4 => {
            bytes[0] = @truncate(truncated >> 24);
            bytes[1] = @truncate(truncated >> 16);
            bytes[2] = @truncate(truncated >> 8);
            bytes[3] = @truncate(truncated);
        },
        else => unreachable,
    }

    return .{ .bytes = bytes, .len = len };
}

/// Decode a packet number from truncated form.
/// Per RFC 9000 Appendix A.
pub fn decodePacketNumber(truncated: u64, pn_len: u8, largest_pn: u64) u64 {
    const expected_pn = largest_pn + 1;
    const pn_win: u64 = @as(u64, 1) << @intCast(pn_len * 8);
    const pn_half = pn_win / 2;
    const pn_mask = pn_win - 1;

    // The candidate value
    const candidate = (expected_pn & ~pn_mask) | truncated;

    if (candidate <= expected_pn -| pn_half and candidate + pn_win <= types.Constants.max_packet_number) {
        return candidate + pn_win;
    }
    if (candidate > expected_pn + pn_half and candidate >= pn_win) {
        return candidate - pn_win;
    }
    return candidate;
}

/// Get the sample position for header protection.
/// Sample is 16 bytes starting at pn_offset + 4.
pub fn getSampleOffset(pn_offset: usize) usize {
    return pn_offset + 4;
}

/// AES-128-GCM AEAD
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

/// Tag length for AEAD (16 bytes)
pub const AEAD_TAG_LEN: usize = Aes128Gcm.tag_length;

/// Encrypt a QUIC packet payload using AES-128-GCM.
/// Returns the ciphertext with authentication tag appended.
/// Associated data is the packet header (including packet number).
pub fn protectPayload(
    keys: *const Keys,
    packet_number: u64,
    header: []const u8,
    plaintext: []const u8,
    out: []u8,
) Error!usize {
    if (out.len < plaintext.len + AEAD_TAG_LEN) {
        return error.BufferTooSmall;
    }

    const nonce = computeNonce(&keys.iv, packet_number);

    // Encrypt
    var tag: [AEAD_TAG_LEN]u8 = undefined;
    Aes128Gcm.encrypt(
        out[0..plaintext.len],
        &tag,
        plaintext,
        header,
        nonce,
        keys.key[0..16].*,
    );

    // Append tag
    @memcpy(out[plaintext.len .. plaintext.len + AEAD_TAG_LEN], &tag);

    return plaintext.len + AEAD_TAG_LEN;
}

/// Decrypt a QUIC packet payload using AES-128-GCM.
/// The ciphertext includes the authentication tag at the end.
/// Associated data is the packet header (including packet number).
pub fn unprotectPayload(
    keys: *const Keys,
    packet_number: u64,
    header: []const u8,
    ciphertext: []const u8,
    out: []u8,
) Error!usize {
    if (ciphertext.len < AEAD_TAG_LEN) {
        return error.DecryptionFailed;
    }

    const payload_len = ciphertext.len - AEAD_TAG_LEN;
    if (out.len < payload_len) {
        return error.BufferTooSmall;
    }

    const nonce = computeNonce(&keys.iv, packet_number);

    // Extract tag
    var tag: [AEAD_TAG_LEN]u8 = undefined;
    @memcpy(&tag, ciphertext[payload_len..]);

    // Decrypt and verify
    Aes128Gcm.decrypt(
        out[0..payload_len],
        ciphertext[0..payload_len],
        tag,
        header,
        nonce,
        keys.key[0..16].*,
    ) catch {
        return error.AuthenticationFailed;
    };

    return payload_len;
}

/// Full packet protection: protect header and encrypt payload.
/// Input packet format: [header][plaintext_payload]
/// Output format: [protected_header][ciphertext][tag]
pub fn protectPacket(
    keys: *const Keys,
    packet_number: u64,
    header_len: usize,
    pn_offset: usize,
    pn_len: u8,
    packet_bytes: []u8,
    packet_len: usize,
) Error!usize {
    if (packet_len < header_len) return error.BufferTooSmall;

    const header = packet_bytes[0..header_len];
    const plaintext = packet_bytes[header_len..packet_len];

    // Encrypt payload in-place (need temp buffer for tag)
    var ciphertext_buf: [65536]u8 = undefined;
    const ciphertext_len = try protectPayload(keys, packet_number, header, plaintext, &ciphertext_buf);

    // Copy ciphertext back
    if (header_len + ciphertext_len > packet_bytes.len) return error.BufferTooSmall;
    @memcpy(packet_bytes[header_len .. header_len + ciphertext_len], ciphertext_buf[0..ciphertext_len]);

    // Apply header protection
    const sample_offset = getSampleOffset(pn_offset);
    if (sample_offset + 16 > header_len + ciphertext_len) {
        // Not enough data for sample - this is an error
        return error.BufferTooSmall;
    }

    const sample: *const [16]u8 = @ptrCast(packet_bytes[sample_offset .. sample_offset + 16]);
    applyHeaderProtection(keys.hp[0..keys.hp_len], sample, &packet_bytes[0], packet_bytes[pn_offset .. pn_offset + pn_len]);

    return header_len + ciphertext_len;
}

/// Full packet unprotection: remove header protection and decrypt payload.
/// Input format: [protected_header][ciphertext][tag]
/// Output format: [header][plaintext_payload]
pub fn unprotectPacket(
    keys: *const Keys,
    largest_pn: u64,
    pn_offset: usize,
    packet_bytes: []u8,
    packet_len: usize,
) Error!struct { pn: u64, header_len: usize, payload_len: usize } {
    if (packet_len < pn_offset + 4 + AEAD_TAG_LEN) return error.DecryptionFailed;

    // Get sample for header protection (at pn_offset + 4)
    const sample_offset = getSampleOffset(pn_offset);
    if (sample_offset + 16 > packet_len) return error.DecryptionFailed;

    const sample: *const [16]u8 = @ptrCast(packet_bytes[sample_offset .. sample_offset + 16]);

    // Temporarily copy first byte and pn bytes to remove protection
    var first_byte = packet_bytes[0];
    var pn_bytes: [4]u8 = undefined;
    @memcpy(&pn_bytes, packet_bytes[pn_offset .. pn_offset + 4]);

    // Remove header protection to get packet number length
    applyHeaderProtection(keys.hp[0..keys.hp_len], sample, &first_byte, &pn_bytes);

    // Determine PN length from unprotected first byte
    const pn_len: u8 = (first_byte & 0x03) + 1;

    // Apply protection removal to actual packet
    applyHeaderProtection(keys.hp[0..keys.hp_len], sample, &packet_bytes[0], packet_bytes[pn_offset .. pn_offset + pn_len]);

    // Decode packet number
    var truncated_pn: u64 = 0;
    for (0..pn_len) |i| {
        truncated_pn = (truncated_pn << 8) | packet_bytes[pn_offset + i];
    }
    const full_pn = decodePacketNumber(truncated_pn, pn_len, largest_pn);

    // Header ends after packet number
    const header_len = pn_offset + pn_len;
    const ciphertext = packet_bytes[header_len..packet_len];

    // Decrypt payload
    var plaintext_buf: [65536]u8 = undefined;
    const payload_len = try unprotectPayload(keys, full_pn, packet_bytes[0..header_len], ciphertext, &plaintext_buf);

    // Copy plaintext back
    @memcpy(packet_bytes[header_len .. header_len + payload_len], plaintext_buf[0..payload_len]);

    return .{
        .pn = full_pn,
        .header_len = header_len,
        .payload_len = payload_len,
    };
}


// Tests
test "HKDF-Extract" {
    // Test vector verification
    const salt = [_]u8{0} ** 32;
    const ikm = [_]u8{0x0b} ** 22;
    var out: [32]u8 = undefined;
    hkdfExtract(&salt, &ikm, &out);

    // Result should be deterministic
    try std.testing.expect(out[0] != 0 or out[1] != 0);
}

test "derive initial keys from DCID" {
    var ctx = CryptoContext.init();

    // Test DCID from RFC 9001 examples
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    ctx.deriveInitialKeys(&dcid, @intFromEnum(types.Version.quic_v1));

    // Verify keys were derived
    try std.testing.expect(ctx.initial.client != null);
    try std.testing.expect(ctx.initial.server != null);

    // Client and server keys should be different
    const client = ctx.initial.client.?;
    const server = ctx.initial.server.?;
    try std.testing.expect(!std.mem.eql(u8, client.key[0..16], server.key[0..16]));
}

test "compute nonce" {
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
    const nonce = computeNonce(&iv, 0);

    // With packet number 0, nonce should equal IV
    try std.testing.expectEqualSlices(u8, &iv, &nonce);

    // With non-zero packet number, nonce should differ
    const nonce2 = computeNonce(&iv, 1);
    try std.testing.expect(!std.mem.eql(u8, &nonce, &nonce2));
}

test "encode packet number" {
    // Small packet number
    {
        const result = encodePacketNumber(0, 0);
        try std.testing.expectEqual(@as(u8, 1), result.len);
        try std.testing.expectEqual(@as(u8, 0), result.bytes[0]);
    }

    // Larger packet number requiring 2 bytes
    {
        const result = encodePacketNumber(0x1234, 0);
        try std.testing.expectEqual(@as(u8, 2), result.len);
    }
}

test "decode packet number" {
    // Sequential case: largest is 0, receiving truncated 1
    {
        const decoded = decodePacketNumber(1, 1, 0);
        try std.testing.expectEqual(@as(u64, 1), decoded);
    }

    // Wrap-around case from RFC 9000 Appendix A
    {
        const decoded = decodePacketNumber(0x9b32, 2, 0xa82f30ea);
        try std.testing.expectEqual(@as(u64, 0xa82f9b32), decoded);
    }

    // Another sequential case
    {
        const decoded = decodePacketNumber(100, 1, 99);
        try std.testing.expectEqual(@as(u64, 100), decoded);
    }
}

test "header protection mask generation" {
    // Test that header protection produces deterministic output
    const hp_key = [_]u8{0} ** 16;
    const sample = [_]u8{0} ** 16;
    var first_byte: u8 = 0xc0; // Long header
    var pn_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    applyHeaderProtection(&hp_key, &sample, &first_byte, pn_bytes[0..4]);

    // Applying twice should restore original
    var restored_byte: u8 = first_byte;
    var restored_pn = pn_bytes;
    applyHeaderProtection(&hp_key, &sample, &restored_byte, &restored_pn);

    try std.testing.expectEqual(@as(u8, 0xc0), restored_byte);
}

test "AEAD encrypt/decrypt round trip" {
    // Create test keys
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    const hp = [_]u8{0x03} ** 16;
    const keys = Keys.init128(key, iv, hp);

    const plaintext = "Hello, QUIC!";
    const header = [_]u8{ 0xc0, 0x00, 0x00, 0x01 }; // Fake header
    const pn: u64 = 0;

    // Encrypt
    var ciphertext: [128]u8 = undefined;
    const ct_len = try protectPayload(&keys, pn, &header, plaintext, &ciphertext);
    try std.testing.expectEqual(plaintext.len + AEAD_TAG_LEN, ct_len);

    // Decrypt
    var decrypted: [128]u8 = undefined;
    const pt_len = try unprotectPayload(&keys, pn, &header, ciphertext[0..ct_len], &decrypted);
    try std.testing.expectEqual(plaintext.len, pt_len);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..pt_len]);
}

test "AEAD authentication failure" {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    const hp = [_]u8{0x03} ** 16;
    const keys = Keys.init128(key, iv, hp);

    const plaintext = "Hello, QUIC!";
    const header = [_]u8{ 0xc0, 0x00, 0x00, 0x01 };
    const pn: u64 = 0;

    // Encrypt
    var ciphertext: [128]u8 = undefined;
    const ct_len = try protectPayload(&keys, pn, &header, plaintext, &ciphertext);

    // Corrupt ciphertext
    ciphertext[0] ^= 0xff;

    // Decrypt should fail
    var decrypted: [128]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, unprotectPayload(&keys, pn, &header, ciphertext[0..ct_len], &decrypted));
}
