//! Example swerver WASM edge filter built on the canonical abi.zig binding.
//!
//! Demonstrates the authoring pattern (no hand-copied externs) AND doubles as the
//! ABI conformance fixture: it references every host import via abi.zig, so the
//! abi-example load test (src/wasm/filter.zig) fails if any signature drifts from
//! the host's linkAbi.
//!
//! Behavior: gate /secure/* on an Authorization header; on /__abi_selfcheck it
//! exercises the whole ABI surface and reports a byte that proves each call ran.
//! Build: see abi.zig's header (requires -mcpu=mvp).

const abi = @import("abi.zig");
const std = @import("std");

var path_buf: [1024]u8 = undefined;
var hdr_buf: [512]u8 = undefined;
var body_buf: [1024]u8 = undefined;
var result_buf: [4096]u8 = undefined;

export fn on_request() i32 {
    const p = abi.path(&path_buf);

    // Self-check route: touch every request-phase import so the conformance test
    // link-validates the whole ABI. Extern calls are not elided when their result
    // is discarded, so each `_ =` still imports its host function.
    if (std.mem.eql(u8, p, "/__abi_selfcheck")) {
        _ = abi.method(); // get_method
        _ = abi.headerCount(); // header_count
        _ = abi.bodyLen(); // body_len
        _ = abi.header("x-probe", &hdr_buf); // get_header
        _ = abi.readBody(0, &body_buf); // read_body
        abi.logMsg("abi selfcheck"); // log
        // Stage a host call and park so on_resume (read_call_result) is reached.
        if (abi.hostCall("true")) return abi.PARKED; // host_call
        abi.respond(200, "selfcheck"); // respond (parking unavailable)
        return abi.REJECT;
    }

    if (!std.mem.startsWith(u8, p, "/secure")) return abi.ALLOW;

    const tok = abi.header("authorization", &hdr_buf);
    if (tok.len == 0) {
        abi.respond(401, "missing credential");
        return abi.REJECT;
    }
    return abi.ALLOW;
}

export fn on_resume() i32 {
    const r = abi.callResult(&result_buf); // read_call_result
    // The Tier-2 verdict is the agent's framed reply; `true` exits 0 -> allow.
    abi.respond(200, "tier2 ok");
    return if (r.len == 0) abi.REJECT else abi.REJECT; // selfcheck: terminal, body staged
}

export fn on_response() i32 {
    // Touch every response-phase import for ABI conformance.
    _ = abi.responseStatus(); // get_response_status
    _ = abi.responseHeader("content-type", &hdr_buf); // get_response_header
    _ = abi.responseBodyLen(); // response_body_len
    _ = abi.readResponseBody(0, &body_buf); // read_response_body
    abi.setResponseStatus(abi.responseStatus()); // set_response_status
    abi.setResponseHeader("x-edge", "swerver"); // set_response_header
    _ = abi.replaceResponseBody(""); // replace_response_body (no-op empty)
    return 0; // apply staged edits
}
