//! SCRAM-SHA-256 client (RFC 5802 / RFC 7677) as a pure state machine.
//!
//! No RNG, no I/O, no allocation: the caller supplies the client nonce
//! (keeps the exchange deterministic for tests) and fixed-size internal
//! buffers hold the pieces of the AuthMessage across steps. Crypto comes
//! from std.crypto only (HMAC-SHA-256, SHA-256, PBKDF2).
//!
//! SASLprep note: RFC 5802 requires SASLprep (RFC 4013) normalization of
//! the password. v1 does not implement SASLprep; instead `init` rejects
//! passwords containing bytes outside printable ASCII (0x20..0x7E) with
//! `error.UnsupportedPassword`. For printable-ASCII passwords SASLprep is
//! the identity transform, so this is fail-closed rather than wrong.
//! Channel binding (SCRAM-SHA-256-PLUS) is out of scope; the client
//! always sends the "n,," GS2 header ("biws" base64-encoded).

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    UnsupportedPassword,
    NonceTooLong,
    UserTooLong,
    InvalidServerFirst,
    InvalidServerFinal,
    NonceMismatch,
    ServerSignatureMismatch,
    ServerRejected,
    BufferTooSmall,
    WrongState,
};

/// Maximum client nonce length accepted from the caller.
pub const MAX_CLIENT_NONCE = 64;
/// Maximum stored client-first-message-bare ("n=" user ",r=" nonce).
const CLIENT_FIRST_BARE_MAX = 512;
/// Maximum stored server-first-message.
const SERVER_FIRST_MAX = 512;
/// Maximum decoded salt length.
const SALT_MAX = 64;
/// Iteration-count sanity cap (PostgreSQL defaults to 4096).
const MAX_ITERATIONS = 16_777_216;

/// Upper bound for the buffer passed to `clientFirst`.
pub const CLIENT_FIRST_MAX = 3 + CLIENT_FIRST_BARE_MAX;
/// Upper bound for the buffer passed to `clientFinal`.
pub const CLIENT_FINAL_MAX = 9 + SERVER_FIRST_MAX + 3 + 44;

const State = enum { init, sent_first, sent_final, done };

pub const Client = struct {
    state: State,
    /// Borrowed: must remain valid until `clientFinal` has been called.
    password: []const u8,
    client_nonce_len: usize,

    client_first_bare: [CLIENT_FIRST_BARE_MAX]u8,
    client_first_bare_len: usize,
    server_first: [SERVER_FIRST_MAX]u8,
    server_first_len: usize,
    /// Offsets of the combined nonce within `server_first`.
    combined_nonce_off: usize,
    combined_nonce_len: usize,
    salt: [SALT_MAX]u8,
    salt_len: usize,
    iterations: u32,
    /// Expected ServerSignature, computed in `clientFinal`.
    server_signature: [32]u8,

    /// Begin an exchange. `user` is included (with RFC 5802 `=`/`,`
    /// escaping) in the client-first message; PostgreSQL ignores it and
    /// uses the startup-message user instead. `password` is borrowed and
    /// must outlive the call to `clientFinal`. `client_nonce` must be
    /// printable ASCII without commas (the caller generates it; tests
    /// pass a fixed value).
    pub fn init(user: []const u8, password: []const u8, client_nonce: []const u8) Error!Client {
        if (client_nonce.len == 0 or client_nonce.len > MAX_CLIENT_NONCE) return error.NonceTooLong;
        for (client_nonce) |c| {
            if (c <= 0x20 or c > 0x7e or c == ',') return error.NonceTooLong;
        }
        // SASLprep stand-in: printable ASCII only (see module doc).
        for (password) |c| {
            if (c < 0x20 or c > 0x7e) return error.UnsupportedPassword;
        }

        var client = Client{
            .state = .init,
            .password = password,
            .client_nonce_len = client_nonce.len,
            .client_first_bare = undefined,
            .client_first_bare_len = 0,
            .server_first = undefined,
            .server_first_len = 0,
            .combined_nonce_off = 0,
            .combined_nonce_len = 0,
            .salt = undefined,
            .salt_len = 0,
            .iterations = 0,
            .server_signature = undefined,
        };

        // client-first-message-bare = "n=" saslname ",r=" c-nonce
        var len: usize = 0;
        len = try appendBare(&client.client_first_bare, len, "n=");
        for (user) |c| {
            switch (c) {
                '=' => len = try appendBare(&client.client_first_bare, len, "=3D"),
                ',' => len = try appendBare(&client.client_first_bare, len, "=2C"),
                else => {
                    if (len >= CLIENT_FIRST_BARE_MAX) return error.UserTooLong;
                    client.client_first_bare[len] = c;
                    len += 1;
                },
            }
        }
        len = try appendBare(&client.client_first_bare, len, ",r=");
        len = try appendBare(&client.client_first_bare, len, client_nonce);
        client.client_first_bare_len = len;
        return client;
    }

    fn appendBare(buf: *[CLIENT_FIRST_BARE_MAX]u8, off: usize, s: []const u8) Error!usize {
        if (CLIENT_FIRST_BARE_MAX - off < s.len) return error.UserTooLong;
        @memcpy(buf[off .. off + s.len], s);
        return off + s.len;
    }

    fn clientNonce(self: *const Client) []const u8 {
        const bare = self.client_first_bare[0..self.client_first_bare_len];
        return bare[bare.len - self.client_nonce_len ..];
    }

    /// Serialize the client-first-message ("n,," GS2 header + bare part).
    /// Idempotent in `.sent_first` so a caller whose outer serialization
    /// failed (e.g. BufferTooSmall) can re-emit.
    pub fn clientFirst(self: *Client, buf: []u8) Error![]u8 {
        if (self.state != .init and self.state != .sent_first) return error.WrongState;
        const bare = self.client_first_bare[0..self.client_first_bare_len];
        const total = 3 + bare.len;
        if (buf.len < total) return error.BufferTooSmall;
        @memcpy(buf[0..3], "n,,");
        @memcpy(buf[3..total], bare);
        self.state = .sent_first;
        return buf[0..total];
    }

    /// Parse the server-first-message: "r=" combined-nonce ",s=" base64
    /// salt ",i=" iterations. The combined nonce must extend the client
    /// nonce (RFC 5802 §5.1).
    pub fn handleServerFirst(self: *Client, msg: []const u8) Error!void {
        if (self.state != .sent_first) return error.WrongState;
        if (msg.len > SERVER_FIRST_MAX) return error.InvalidServerFirst;
        // "m=" announces a mandatory extension we do not implement.
        if (std.mem.startsWith(u8, msg, "m=")) return error.InvalidServerFirst;
        @memcpy(self.server_first[0..msg.len], msg);
        self.server_first_len = msg.len;

        var nonce: ?[]const u8 = null;
        var salt_b64: ?[]const u8 = null;
        var iters: ?[]const u8 = null;
        var it = std.mem.splitScalar(u8, msg, ',');
        while (it.next()) |attr| {
            if (attr.len < 2 or attr[1] != '=') return error.InvalidServerFirst;
            const value = attr[2..];
            switch (attr[0]) {
                'r' => nonce = value,
                's' => salt_b64 = value,
                'i' => iters = value,
                else => {}, // optional extensions are ignored
            }
        }
        const combined = nonce orelse return error.InvalidServerFirst;
        const salt_value = salt_b64 orelse return error.InvalidServerFirst;
        const iter_value = iters orelse return error.InvalidServerFirst;

        // Server nonce must start with — and extend — our nonce.
        if (combined.len <= self.client_nonce_len or
            !std.mem.startsWith(u8, combined, self.clientNonce()))
        {
            return error.NonceMismatch;
        }
        self.combined_nonce_off = @intFromPtr(combined.ptr) - @intFromPtr(msg.ptr);
        self.combined_nonce_len = combined.len;

        const decoder = std.base64.standard.Decoder;
        const salt_len = decoder.calcSizeForSlice(salt_value) catch return error.InvalidServerFirst;
        if (salt_len == 0 or salt_len > SALT_MAX) return error.InvalidServerFirst;
        decoder.decode(self.salt[0..salt_len], salt_value) catch return error.InvalidServerFirst;
        self.salt_len = salt_len;

        const iterations = std.fmt.parseInt(u32, iter_value, 10) catch return error.InvalidServerFirst;
        if (iterations == 0 or iterations > MAX_ITERATIONS) return error.InvalidServerFirst;
        self.iterations = iterations;
    }

    fn combinedNonce(self: *const Client) []const u8 {
        return self.server_first[self.combined_nonce_off .. self.combined_nonce_off + self.combined_nonce_len];
    }

    /// Serialize the client-final-message and compute the expected
    /// ServerSignature for `verifyServerFinal`. "c=biws" is the base64 of
    /// the "n,," GS2 header (no channel binding). Deterministic, and
    /// idempotent in `.sent_final` for the same re-emit reason as
    /// `clientFirst`.
    pub fn clientFinal(self: *Client, buf: []u8) Error![]u8 {
        if (self.state != .sent_first and self.state != .sent_final) return error.WrongState;
        if (self.iterations == 0) return error.WrongState;

        // client-final-message-without-proof = "c=biws,r=" combined-nonce
        const nonce = self.combinedNonce();
        const without_proof_len = 9 + nonce.len;
        const total = without_proof_len + 3 + 44; // ",p=" + base64(32 bytes)
        if (buf.len < total) return error.BufferTooSmall;
        @memcpy(buf[0..9], "c=biws,r=");
        @memcpy(buf[9..without_proof_len], nonce);

        // SaltedPassword := Hi(password, salt, i)
        var salted_password: [32]u8 = undefined;
        std.crypto.pwhash.pbkdf2(
            &salted_password,
            self.password,
            self.salt[0..self.salt_len],
            self.iterations,
            HmacSha256,
        ) catch return error.InvalidServerFirst;

        var client_key: [32]u8 = undefined;
        HmacSha256.create(&client_key, "Client Key", &salted_password);
        var stored_key: [32]u8 = undefined;
        Sha256.hash(&client_key, &stored_key, .{});

        // AuthMessage := client-first-bare "," server-first ","
        //               client-final-without-proof
        var client_sig_ctx = HmacSha256.init(&stored_key);
        self.updateAuthMessage(&client_sig_ctx, buf[0..without_proof_len]);
        var client_signature: [32]u8 = undefined;
        client_sig_ctx.final(&client_signature);

        // ClientProof := ClientKey XOR ClientSignature
        var client_proof: [32]u8 = undefined;
        for (&client_proof, client_key, client_signature) |*p, k, s| p.* = k ^ s;

        // Expected ServerSignature := HMAC(ServerKey, AuthMessage)
        var server_key: [32]u8 = undefined;
        HmacSha256.create(&server_key, "Server Key", &salted_password);
        var server_sig_ctx = HmacSha256.init(&server_key);
        self.updateAuthMessage(&server_sig_ctx, buf[0..without_proof_len]);
        server_sig_ctx.final(&self.server_signature);

        std.crypto.secureZero(u8, &salted_password);
        std.crypto.secureZero(u8, &client_key);

        @memcpy(buf[without_proof_len .. without_proof_len + 3], ",p=");
        _ = std.base64.standard.Encoder.encode(buf[without_proof_len + 3 .. total], &client_proof);
        self.state = .sent_final;
        return buf[0..total];
    }

    fn updateAuthMessage(self: *const Client, ctx: *HmacSha256, without_proof: []const u8) void {
        ctx.update(self.client_first_bare[0..self.client_first_bare_len]);
        ctx.update(",");
        ctx.update(self.server_first[0..self.server_first_len]);
        ctx.update(",");
        ctx.update(without_proof);
    }

    /// Verify the server-final-message ("v=" base64 ServerSignature).
    /// MUST be called and MUST succeed before trusting the connection:
    /// it is the proof that the server actually knows the password
    /// verifier. Fails closed on any mismatch or server "e=" error.
    pub fn verifyServerFinal(self: *Client, msg: []const u8) Error!void {
        if (self.state != .sent_final) return error.WrongState;
        if (std.mem.startsWith(u8, msg, "e=")) return error.ServerRejected;
        if (!std.mem.startsWith(u8, msg, "v=")) return error.InvalidServerFinal;
        // The signature attribute may be followed by extensions.
        const end = std.mem.indexOfScalar(u8, msg, ',') orelse msg.len;
        const sig_b64 = msg[2..end];

        const decoder = std.base64.standard.Decoder;
        const sig_len = decoder.calcSizeForSlice(sig_b64) catch return error.InvalidServerFinal;
        if (sig_len != 32) return error.InvalidServerFinal;
        var received: [32]u8 = undefined;
        decoder.decode(&received, sig_b64) catch return error.InvalidServerFinal;

        if (!std.crypto.timing_safe.eql([32]u8, received, self.server_signature)) {
            return error.ServerSignatureMismatch;
        }
        self.state = .done;
    }
};

// ---------------------------------------------------------------------------
// Tests — RFC 7677 §3 test vector
// ---------------------------------------------------------------------------

const testing = std.testing;

const RFC_USER = "user";
const RFC_PASSWORD = "pencil";
const RFC_CLIENT_NONCE = "rOprNGfwEbeRWgbNEkqO";
const RFC_CLIENT_FIRST = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
const RFC_SERVER_FIRST = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const RFC_CLIENT_FINAL = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const RFC_SERVER_FINAL = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

test "scram RFC 7677 vector reproduces client-final and verifies server-final" {
    var client = try Client.init(RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE);

    var first_buf: [CLIENT_FIRST_MAX]u8 = undefined;
    const first = try client.clientFirst(&first_buf);
    try testing.expectEqualStrings(RFC_CLIENT_FIRST, first);

    try client.handleServerFirst(RFC_SERVER_FIRST);
    try testing.expectEqual(@as(u32, 4096), client.iterations);
    try testing.expectEqual(@as(usize, 16), client.salt_len);

    var final_buf: [CLIENT_FINAL_MAX]u8 = undefined;
    const final = try client.clientFinal(&final_buf);
    try testing.expectEqualStrings(RFC_CLIENT_FINAL, final);

    try client.verifyServerFinal(RFC_SERVER_FINAL);
    try testing.expectEqual(State.done, client.state);
}

test "scram tampered server signature fails closed" {
    var client = try Client.init(RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE);
    var first_buf: [CLIENT_FIRST_MAX]u8 = undefined;
    _ = try client.clientFirst(&first_buf);
    try client.handleServerFirst(RFC_SERVER_FIRST);
    var final_buf: [CLIENT_FINAL_MAX]u8 = undefined;
    _ = try client.clientFinal(&final_buf);

    // Flip one character of the base64 signature.
    var tampered: [RFC_SERVER_FINAL.len]u8 = RFC_SERVER_FINAL.*;
    tampered[2] = if (tampered[2] == 'A') 'B' else 'A';
    try testing.expectError(error.ServerSignatureMismatch, client.verifyServerFinal(&tampered));
}

test "scram server e= error is rejected" {
    var client = try Client.init(RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE);
    var first_buf: [CLIENT_FIRST_MAX]u8 = undefined;
    _ = try client.clientFirst(&first_buf);
    try client.handleServerFirst(RFC_SERVER_FIRST);
    var final_buf: [CLIENT_FINAL_MAX]u8 = undefined;
    _ = try client.clientFinal(&final_buf);
    try testing.expectError(error.ServerRejected, client.verifyServerFinal("e=invalid-proof"));
}

test "scram rejects server nonce that does not extend client nonce" {
    var client = try Client.init(RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE);
    var first_buf: [CLIENT_FIRST_MAX]u8 = undefined;
    _ = try client.clientFirst(&first_buf);
    try testing.expectError(
        error.NonceMismatch,
        client.handleServerFirst("r=evilnonce123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"),
    );
    // Identical nonce (no server extension) is also a mismatch.
    var client2 = try Client.init(RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE);
    _ = try client2.clientFirst(&first_buf);
    try testing.expectError(
        error.NonceMismatch,
        client2.handleServerFirst("r=" ++ RFC_CLIENT_NONCE ++ ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"),
    );
}

test "scram rejects malformed server-first" {
    const cases = [_][]const u8{
        "", // empty
        "m=ext,r=abc,s=AA==,i=1", // mandatory extension
        "r=" ++ RFC_CLIENT_NONCE ++ "X,i=4096", // missing salt
        "r=" ++ RFC_CLIENT_NONCE ++ "X,s=AA==", // missing iterations
        "r=" ++ RFC_CLIENT_NONCE ++ "X,s=!!!,i=4096", // bad base64
        "r=" ++ RFC_CLIENT_NONCE ++ "X,s=AA==,i=0", // zero iterations
        "r=" ++ RFC_CLIENT_NONCE ++ "X,s=AA==,i=999999999", // absurd iterations
    };
    for (cases) |case| {
        var client = try Client.init(RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE);
        var first_buf: [CLIENT_FIRST_MAX]u8 = undefined;
        _ = try client.clientFirst(&first_buf);
        try testing.expectError(error.InvalidServerFirst, client.handleServerFirst(case));
    }
}

test "scram rejects non-ASCII password (SASLprep unimplemented)" {
    try testing.expectError(
        error.UnsupportedPassword,
        Client.init("user", "p\xc3\xa9ncil", RFC_CLIENT_NONCE),
    );
    try testing.expectError(
        error.UnsupportedPassword,
        Client.init("user", "tab\tpass", RFC_CLIENT_NONCE),
    );
}

test "scram escapes = and , in username" {
    var client = try Client.init("a=b,c", "pw", "nonce0123456789");
    var first_buf: [CLIENT_FIRST_MAX]u8 = undefined;
    const first = try client.clientFirst(&first_buf);
    try testing.expectEqualStrings("n,,n=a=3Db=2Cc,r=nonce0123456789", first);
}

test "scram state machine rejects out-of-order calls" {
    var client = try Client.init(RFC_USER, RFC_PASSWORD, RFC_CLIENT_NONCE);
    try testing.expectError(error.WrongState, client.handleServerFirst(RFC_SERVER_FIRST));
    var buf: [CLIENT_FINAL_MAX]u8 = undefined;
    try testing.expectError(error.WrongState, client.clientFinal(&buf));
    try testing.expectError(error.WrongState, client.verifyServerFinal(RFC_SERVER_FINAL));
}
