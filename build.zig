const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const swerver_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Link the TLS runtime with OpenSSL/BoringSSL.
    swerver_module.linkSystemLibrary("ssl", .{});
    swerver_module.linkSystemLibrary("crypto", .{});
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const exe = b.addExecutable(.{
        .name = "swerver",
        .root_module = root_module,
    });
    exe.root_module.addImport("swerver", swerver_module);

    const options = b.addOptions();
    options.addOption(bool, "enable_tls", b.option(bool, "enable-tls", "Enable TLS support") orelse false);
    options.addOption(bool, "enable_http2", b.option(bool, "enable-http2", "Enable HTTP/2 support") orelse false);
    options.addOption(bool, "enable_http3", b.option(bool, "enable-http3", "Enable HTTP/3 support") orelse false);
    options.addOption(bool, "enable_proxy", b.option(bool, "enable-proxy", "Enable reverse proxy support") orelse false);
    exe.root_module.addOptions("build_options", options);

    b.installArtifact(exe);

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const tests = b.addTest(.{
        .root_module = test_module,
    });
    tests.root_module.addOptions("build_options", options);
    tests.root_module.addImport("swerver", swerver_module);
    const test_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    const fuzz_module = b.createModule(.{
        .root_source_file = b.path("src/fuzz/http1_parser.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    fuzz_module.addImport("swerver", swerver_module);
    fuzz_module.addOptions("build_options", options);
    // Fuzz step (disabled - addFuzz not available in this Zig version)
    _ = b.step("fuzz", "Run fuzz harnesses (not available)");

    const bench_module = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const bench_exe = b.addExecutable(.{
        .name = "swerver-bench",
        .root_module = bench_module,
    });
    bench_exe.root_module.addImport("swerver", swerver_module);
    bench_exe.root_module.addOptions("build_options", options);
    b.installArtifact(bench_exe);

    const bench_cmd = b.addRunArtifact(bench_exe);
    if (b.args) |args| bench_cmd.addArgs(args);
    const bench_step = b.step("bench", "Run microbenchmarks");
    bench_step.dependOn(&bench_cmd.step);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the server");
    run_step.dependOn(&run_cmd.step);
}
