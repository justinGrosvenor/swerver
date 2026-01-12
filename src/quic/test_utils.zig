const std = @import("std");
const types = @import("types.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const varint = @import("varint.zig");

pub fn buildClientInitialPacket(
    out: []u8,
    dcid: []const u8,
    scid: []const u8,
    pn: u64,
) crypto.Error![]const u8 {
    return buildInitialPacket(out, dcid, scid, pn, .client);
}

pub fn buildServerInitialPacket(
    out: []u8,
    dcid: []const u8,
    scid: []const u8,
    pn: u64,
) crypto.Error![]const u8 {
    return buildInitialPacket(out, dcid, scid, pn, .server);
}

const InitialKeys = enum { client, server };

fn buildInitialPacket(
    out: []u8,
    dcid: []const u8,
    scid: []const u8,
    pn: u64,
    role: InitialKeys,
) crypto.Error![]const u8 {
    if (dcid.len > types.Constants.max_cid_len or scid.len > types.Constants.max_cid_len) {
        return error.BufferTooSmall;
    }
    if (out.len < types.Constants.min_initial_packet_size) {
        return error.BufferTooSmall;
    }

    var offset: usize = 0;
    const pn_encoded = crypto.encodePacketNumber(pn, 0);
    const pn_len: usize = pn_encoded.len;

    // First byte: Long header | Fixed | Initial | PN length
    out[offset] = 0xc0 | @as(u8, @intCast(pn_len - 1));
    offset += 1;

    // Version (QUIC v1)
    out[offset] = 0x00;
    out[offset + 1] = 0x00;
    out[offset + 2] = 0x00;
    out[offset + 3] = 0x01;
    offset += 4;

    // DCID
    out[offset] = @intCast(dcid.len);
    offset += 1;
    if (dcid.len > 0) {
        @memcpy(out[offset .. offset + dcid.len], dcid);
        offset += dcid.len;
    }

    // SCID
    out[offset] = @intCast(scid.len);
    offset += 1;
    if (scid.len > 0) {
        @memcpy(out[offset .. offset + scid.len], scid);
        offset += scid.len;
    }

    // Token length = 0
    offset += varint.encode(out[offset..], 0) catch return error.BufferTooSmall;

    // Length field (varint) for payload (pn + ciphertext).
    const base_len = offset;
    var length_len: usize = 2;
    var payload_len: usize = types.Constants.min_initial_packet_size - base_len - length_len;
    length_len = varint.encodedLength(payload_len);
    payload_len = types.Constants.min_initial_packet_size - base_len - length_len;

    const encoded_len = varint.encode(out[offset..], payload_len) catch return error.BufferTooSmall;
    if (encoded_len != length_len) return error.BufferTooSmall;
    offset += encoded_len;

    const pn_offset = offset;
    @memcpy(out[pn_offset .. pn_offset + pn_len], pn_encoded.bytes[0..pn_len]);
    offset += pn_len;

    const header_len = offset;
    const min_plaintext = types.Constants.min_initial_packet_size - header_len - crypto.AEAD_TAG_LEN;
    if (out.len < header_len + min_plaintext + crypto.AEAD_TAG_LEN) return error.BufferTooSmall;

    while (offset - header_len < min_plaintext) {
        out[offset] = 0x00;
        offset += 1;
    }

    var crypto_ctx = crypto.CryptoContext.init();
    crypto_ctx.deriveInitialKeys(dcid, @intFromEnum(types.Version.quic_v1));
    const keys = switch (role) {
        .client => crypto_ctx.initial.client,
        .server => crypto_ctx.initial.server,
    } orelse return error.KeyDerivationFailed;

    var ciphertext_buf: [2048]u8 = undefined;
    const ciphertext_len = try crypto.protectPayload(
        &keys,
        pn,
        out[0..header_len],
        out[header_len..offset],
        &ciphertext_buf,
    );
    @memcpy(out[header_len .. header_len + ciphertext_len], ciphertext_buf[0..ciphertext_len]);
    offset = header_len + ciphertext_len;

    const sample_offset = pn_offset + 4;
    const sample: *const [16]u8 = @ptrCast(out[sample_offset .. sample_offset + 16]);
    crypto.applyHeaderProtection(keys.hp[0..keys.hp_len], sample, &out[0], out[pn_offset .. pn_offset + pn_len]);

    const parsed = packet.parseHeader(out[0..offset], 0);
    if (parsed.state != .complete or parsed.header == null) return error.DecryptionFailed;
    const pn_off = parsed.header.?.long.packet_number_offset;
    var verify_buf: [types.Constants.min_initial_packet_size]u8 = undefined;
    if (offset > verify_buf.len) return error.BufferTooSmall;
    @memcpy(verify_buf[0..offset], out[0..offset]);
    _ = crypto.unprotectPacket(&keys, 0, pn_off, verify_buf[0..], offset) catch return error.AuthenticationFailed;

    return out[0..offset];
}
