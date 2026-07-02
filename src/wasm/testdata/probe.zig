//! Test fixture module for the runtime binding. Compiled to wasm32-freestanding
//! and committed as probe.wasm (regenerate with build_probe.sh). No host imports
//! so it links cleanly without the ABI layer.
//!
//!   on_request() -> i32   returns 0 (allow); exercises call + result fetch
//!   spin()                infinite loop; exercises fuel interruption

export fn on_request() i32 {
    return 0;
}

export var spin_counter: u64 = 0;

export fn spin() void {
    while (true) {
        spin_counter +%= 1;
    }
}

// Memory-cap probes (resource-bounding tests).
export fn mem_size() i32 {
    return @intCast(@wasmMemorySize(0));
}

/// Attempt to grow linear memory by 8 pages (512 KiB). Returns the previous
/// page count on success, or -1 if the host memory cap refuses the growth.
export fn grow_some() i32 {
    return @intCast(@wasmMemoryGrow(0, 8));
}
