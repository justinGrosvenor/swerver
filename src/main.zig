//! swerver binary: a thin shell over the library bootstrap. All lifecycle
//! logic (config file/URL loading, proxy construction, Master vs
//! single-process dispatch, WASM filter wiring) lives in
//! src/bootstrap.zig so embedders run the exact same path as this binary.

const std = @import("std");

const swerver = @import("swerver");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try swerver.bootstrap.parseArgs(init.minimal.args, allocator);
    try swerver.bootstrap.run(allocator, swerver.bootstrap.optionsFromArgs(&args));
}
