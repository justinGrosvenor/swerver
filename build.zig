const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption(bool, "enable_tls", b.option(bool, "enable-tls", "Enable TLS support") orelse false);
    options.addOption(bool, "enable_http2", b.option(bool, "enable-http2", "Enable HTTP/2 support") orelse false);
    options.addOption(bool, "enable_http3", b.option(bool, "enable-http3", "Enable HTTP/3 support") orelse false);
    options.addOption(bool, "enable_proxy", b.option(bool, "enable-proxy", "Enable reverse proxy support") orelse false);

    const swerver_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    swerver_module.addOptions("build_options", options);

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

    const test_tls = b.addTest(.{
        .root_module = test_module,
    });
    test_tls.root_module.addImport("swerver", swerver_module);
    const options_tls = b.addOptions();
    options_tls.addOption(bool, "enable_tls", true);
    options_tls.addOption(bool, "enable_http2", false);
    options_tls.addOption(bool, "enable_http3", false);
    options_tls.addOption(bool, "enable_proxy", false);
    test_tls.root_module.addOptions("build_options", options_tls);
    const test_tls_run = b.addRunArtifact(test_tls);

    const test_http2 = b.addTest(.{
        .root_module = test_module,
    });
    test_http2.root_module.addImport("swerver", swerver_module);
    const options_http2 = b.addOptions();
    options_http2.addOption(bool, "enable_tls", false);
    options_http2.addOption(bool, "enable_http2", true);
    options_http2.addOption(bool, "enable_http3", false);
    options_http2.addOption(bool, "enable_proxy", false);
    test_http2.root_module.addOptions("build_options", options_http2);
    const test_http2_run = b.addRunArtifact(test_http2);

    const test_http3 = b.addTest(.{
        .root_module = test_module,
    });
    test_http3.root_module.addImport("swerver", swerver_module);
    const options_http3 = b.addOptions();
    options_http3.addOption(bool, "enable_tls", true);
    options_http3.addOption(bool, "enable_http2", false);
    options_http3.addOption(bool, "enable_http3", true);
    options_http3.addOption(bool, "enable_proxy", false);
    test_http3.root_module.addOptions("build_options", options_http3);
    const test_http3_run = b.addRunArtifact(test_http3);

    const test_proxy = b.addTest(.{
        .root_module = test_module,
    });
    test_proxy.root_module.addImport("swerver", swerver_module);
    const options_proxy = b.addOptions();
    options_proxy.addOption(bool, "enable_tls", false);
    options_proxy.addOption(bool, "enable_http2", false);
    options_proxy.addOption(bool, "enable_http3", false);
    options_proxy.addOption(bool, "enable_proxy", true);
    test_proxy.root_module.addOptions("build_options", options_proxy);
    const test_proxy_run = b.addRunArtifact(test_proxy);

    const test_all = b.addTest(.{
        .root_module = test_module,
    });
    test_all.root_module.addImport("swerver", swerver_module);
    const options_all = b.addOptions();
    options_all.addOption(bool, "enable_tls", true);
    options_all.addOption(bool, "enable_http2", true);
    options_all.addOption(bool, "enable_http3", true);
    options_all.addOption(bool, "enable_proxy", true);
    test_all.root_module.addOptions("build_options", options_all);
    const test_all_run = b.addRunArtifact(test_all);

    const test_matrix = b.step("test-matrix", "Run unit tests across build flag combinations");
    test_matrix.dependOn(&test_run.step);
    test_matrix.dependOn(&test_tls_run.step);
    test_matrix.dependOn(&test_http2_run.step);
    test_matrix.dependOn(&test_http3_run.step);
    test_matrix.dependOn(&test_proxy_run.step);
    test_matrix.dependOn(&test_all_run.step);

    const test_flags = b.step("test-flags", "Compile unit tests across build flag combinations");
    test_flags.dependOn(&tests.step);
    test_flags.dependOn(&test_tls.step);
    test_flags.dependOn(&test_http2.step);
    test_flags.dependOn(&test_http3.step);
    test_flags.dependOn(&test_proxy.step);
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
