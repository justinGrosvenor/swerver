const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const enable_tls = b.option(bool, "enable-tls", "Enable TLS support") orelse false;
    const enable_http2 = b.option(bool, "enable-http2", "Enable HTTP/2 support") orelse false;
    const enable_http3 = b.option(bool, "enable-http3", "Enable HTTP/3 support") orelse false;
    const enable_proxy = b.option(bool, "enable-proxy", "Enable reverse proxy support") orelse false;
    const enable_io_uring = b.option(bool, "enable-io-uring", "Enable io_uring backend (Linux only)") orelse false;

    const options = b.addOptions();
    options.addOption(bool, "enable_tls", enable_tls);
    options.addOption(bool, "enable_http2", enable_http2);
    options.addOption(bool, "enable_http3", enable_http3);
    options.addOption(bool, "enable_proxy", enable_proxy);
    options.addOption(bool, "enable_io_uring", enable_io_uring);

    const swerver_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    swerver_module.addOptions("build_options", options);
    // SSL/crypto linked unconditionally: TLS FFI symbols are always compiled
    // (gated at runtime via build_options, not compile-time exclusion).
    // Test variants that enable TLS/HTTP3 require these symbols.
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
    exe.root_module.addOptions("build_options", options);

    b.installArtifact(exe);

    // --- Test targets ---
    // Each test variant needs its own module because build_options differ.

    const tests = addTestVariant(b, target, optimize, swerver_module, options);
    const test_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    const options_tls = makeOptions(b, .{ .enable_tls = true });
    const test_tls = addTestVariant(b, target, optimize, swerver_module, options_tls);
    const test_tls_run = b.addRunArtifact(test_tls);

    const options_http2 = makeOptions(b, .{ .enable_http2 = true });
    const test_http2 = addTestVariant(b, target, optimize, swerver_module, options_http2);
    const test_http2_run = b.addRunArtifact(test_http2);

    const options_http3 = makeOptions(b, .{ .enable_tls = true, .enable_http3 = true });
    const test_http3 = addTestVariant(b, target, optimize, swerver_module, options_http3);
    const test_http3_run = b.addRunArtifact(test_http3);

    const options_proxy = makeOptions(b, .{ .enable_proxy = true });
    const test_proxy = addTestVariant(b, target, optimize, swerver_module, options_proxy);
    const test_proxy_run = b.addRunArtifact(test_proxy);

    const options_io_uring = makeOptions(b, .{ .enable_io_uring = true });
    const test_io_uring = addTestVariant(b, target, optimize, swerver_module, options_io_uring);
    const test_io_uring_run = b.addRunArtifact(test_io_uring);

    const options_all = makeOptions(b, .{ .enable_tls = true, .enable_http2 = true, .enable_http3 = true, .enable_proxy = true, .enable_io_uring = true });
    const test_all = addTestVariant(b, target, optimize, swerver_module, options_all);
    const test_all_run = b.addRunArtifact(test_all);

    const test_matrix = b.step("test-matrix", "Run unit tests across build flag combinations");
    test_matrix.dependOn(&test_run.step);
    test_matrix.dependOn(&test_tls_run.step);
    test_matrix.dependOn(&test_http2_run.step);
    test_matrix.dependOn(&test_http3_run.step);
    test_matrix.dependOn(&test_proxy_run.step);
    test_matrix.dependOn(&test_io_uring_run.step);
    test_matrix.dependOn(&test_all_run.step);

    const test_flags = b.step("test-flags", "Compile unit tests across build flag combinations");
    test_flags.dependOn(&tests.step);
    test_flags.dependOn(&test_tls.step);
    test_flags.dependOn(&test_http2.step);
    test_flags.dependOn(&test_http3.step);
    test_flags.dependOn(&test_proxy.step);
    test_flags.dependOn(&test_io_uring.step);
    test_flags.dependOn(&test_all.step);

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

    const example_module = b.createModule(.{
        .root_source_file = b.path("examples/embedded/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    example_module.addImport("swerver", swerver_module);
    example_module.addOptions("build_options", options);
    const example_exe = b.addExecutable(.{
        .name = "swerver-embedded-example",
        .root_module = example_module,
    });
    b.installArtifact(example_exe);
    const example_run = b.addRunArtifact(example_exe);
    if (b.args) |args| example_run.addArgs(args);
    const example_step = b.step("example", "Run embedded API example");
    example_step.dependOn(&example_run.step);
}

const FeatureFlags = struct {
    enable_tls: bool = false,
    enable_http2: bool = false,
    enable_http3: bool = false,
    enable_proxy: bool = false,
    enable_io_uring: bool = false,
};

fn makeOptions(b: *std.Build, flags: FeatureFlags) *std.Build.Step.Options {
    const opts = b.addOptions();
    opts.addOption(bool, "enable_tls", flags.enable_tls);
    opts.addOption(bool, "enable_http2", flags.enable_http2);
    opts.addOption(bool, "enable_http3", flags.enable_http3);
    opts.addOption(bool, "enable_proxy", flags.enable_proxy);
    opts.addOption(bool, "enable_io_uring", flags.enable_io_uring);
    return opts;
}

fn addTestVariant(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    swerver_module: *std.Build.Module,
    opts: *std.Build.Step.Options,
) *std.Build.Step.Compile {
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_module.addOptions("build_options", opts);
    test_module.addImport("swerver", swerver_module);
    return b.addTest(.{ .root_module = test_module });
}
