const std = @import("std");
const Build = std.Build;

// Core wasm3 translation units. Excludes the WASI/tracer/meta API bindings
// (not needed for a sandboxed filter; they pull extra surface).
const WASM3_FILES = [_][]const u8{
    "m3_core.c",
    "m3_env.c",
    "m3_module.c",
    "m3_parse.c",
    "m3_compile.c",
    "m3_emit.c",
    "m3_optimize.c",
    "m3_exec.c",
    "m3_function.c",
    "m3_bind.c",
    "m3_code.c",
    "m3_info.c",
    "m3_api_libc.c",
};

const WASM3_CFLAGS = [_][]const u8{
    "-std=gnu11",
    "-Wall",
    "-Wextra",
    "-Wno-unused-function",
    "-Wno-unused-parameter",
    "-Wno-unused-variable",
    "-O3",
    "-fno-sanitize=undefined",
};

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    // Benchmarks are meaningless in Debug; default to ReleaseFast.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    // --- 1. Build the filter to wasm32-freestanding -------------------------
    const filter = b.addExecutable(.{
        .name = "filter",
        .root_module = b.createModule(.{
            .root_source_file = b.path("filter/filter.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .wasm32,
                .os_tag = .freestanding,
            }),
            .optimize = .ReleaseSmall,
        }),
    });
    // Reactor-style module: no _start entry, keep exports.
    filter.entry = .disabled;
    filter.rdynamic = true;
    // Make the compiled wasm available for inspection / wat dumps.
    const install_filter = b.addInstallArtifact(filter, .{});
    b.getInstallStep().dependOn(&install_filter.step);

    // --- 2. zware (pure-Zig) as a local module -----------------------------
    const zware = b.addModule("zware", .{
        .root_source_file = b.path("vendor/zware/src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- 3. The benchmark harness ------------------------------------------
    const harness = b.addExecutable(.{
        .name = "wasm-spike",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    harness.root_module.addImport("zware", zware);

    // wasm3 vendored C
    harness.root_module.addIncludePath(b.path("vendor/wasm3/source"));
    // Shim dir provides a macOS <endian.h> so @cImport translate-c succeeds
    // (see vendor/wasm3/shim/endian.h). Searched after source/, harmless to .c.
    harness.root_module.addIncludePath(b.path("vendor/wasm3/shim"));
    harness.root_module.addCSourceFiles(.{
        .root = b.path("vendor/wasm3/source"),
        .files = &WASM3_FILES,
        .flags = &WASM3_CFLAGS,
    });
    harness.root_module.link_libc = true;

    // Embed the compiled filter so the harness is self-contained.
    harness.root_module.addAnonymousImport("filter_wasm", .{
        .root_source_file = filter.getEmittedBin(),
    });

    b.installArtifact(harness);

    const run = b.addRunArtifact(harness);
    if (b.args) |args| run.addArgs(args);
    const run_step = b.step("run", "Run the wasm spike benchmark");
    run_step.dependOn(&run.step);
}
