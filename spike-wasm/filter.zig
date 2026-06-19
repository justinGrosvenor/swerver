// Trivial edge-function filter, compiled to wasm32-freestanding.
// Host writes the candidate API-key bytes into `buf`, then calls check(len).
// Returns 0 = allow (key matches), 1 = reject.
var buf: [256]u8 = undefined;

const KEY = "bench-key-1";

export fn bufptr() u32 {
    return @intFromPtr(&buf);
}

// Bare invocation: measures pure call-into-interpreter overhead.
export fn noop() i32 {
    return 0;
}

// Realistic filter: scan the candidate key against the expected one.
export fn check(len: u32) i32 {
    if (len != KEY.len) return 1;
    var i: u32 = 0;
    while (i < len) : (i += 1) {
        if (buf[i] != KEY[i]) return 1;
    }
    return 0;
}
