const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const enable_tls = b.option(bool, "enable-tls", "Enable TLS support") orelse false;
    const enable_http2 = b.option(bool, "enable-http2", "Enable HTTP/2 support") orelse false;
    const enable_http3 = b.option(bool, "enable-http3", "Enable HTTP/3 support") orelse false;
    const enable_proxy = b.option(bool, "enable-proxy", "Enable reverse proxy support") orelse false;
    const enable_io_uring = b.option(bool, "enable-io-uring", "Enable io_uring backend (Linux only)") orelse false;
    const enable_x402_crypto = b.option(bool, "enable-x402-crypto", "Enable x402 local signature verification (secp256k1)") orelse false;
    // WASM edge functions (design 10.0). Off by default: demand-gated, and the
    // only feature that vendors C source (wasm3). Cross-compiles to static musl.
    const enable_wasm = b.option(bool, "enable-wasm", "Enable WASM edge functions (vendored wasm3)") orelse false;

    const is_native = target.result.os.tag == builtin.os.tag and target.result.cpu.arch == builtin.cpu.arch;
    const effective_enable_tls = enable_tls and is_native;
    const effective_enable_http3 = enable_http3 and effective_enable_tls;
    const effective_enable_x402_crypto = enable_x402_crypto and is_native;
    const enable_compression = b.option(bool, "enable-compression", "Enable response compression (requires zlib)") orelse is_native;

    const options = b.addOptions();
    options.addOption(bool, "enable_tls", effective_enable_tls);
    options.addOption(bool, "enable_http2", enable_http2);
    options.addOption(bool, "enable_http3", effective_enable_http3);
    options.addOption(bool, "enable_proxy", enable_proxy);
    options.addOption(bool, "enable_io_uring", enable_io_uring);
    options.addOption(bool, "enable_x402_crypto", effective_enable_x402_crypto);
    options.addOption(bool, "enable_compression", enable_compression);
    options.addOption(bool, "enable_wasm", enable_wasm);

    const swerver_module = b.addModule("swerver", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    swerver_module.addOptions("build_options", options);
    if (enable_compression) {
        swerver_module.linkSystemLibrary("z", .{});
    }
    if (enable_wasm) {
        addWasm3(b, swerver_module);
    }
    // Only link OpenSSL when TLS/HTTP3 is enabled and the target matches the host.
    const need_tls = effective_enable_tls or effective_enable_http3;
    if (need_tls and is_native) {
        swerver_module.linkSystemLibrary("ssl", .{});
        swerver_module.linkSystemLibrary("crypto", .{});
    } else if (effective_enable_x402_crypto and is_native) {
        swerver_module.linkSystemLibrary("crypto", .{});
    }
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

    const tests = addTestVariant(b, target, optimize, swerver_module, options, enable_wasm);
    const test_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);

    const options_tls = makeOptions(b, .{ .enable_tls = true });
    const test_tls = addTestVariant(b, target, optimize, swerver_module, options_tls, false);
    if (is_native) {
        test_tls.root_module.linkSystemLibrary("ssl", .{});
        test_tls.root_module.linkSystemLibrary("crypto", .{});
    }
    const test_tls_run = b.addRunArtifact(test_tls);

    const options_http2 = makeOptions(b, .{ .enable_http2 = true });
    const test_http2 = addTestVariant(b, target, optimize, swerver_module, options_http2, false);
    const test_http2_run = b.addRunArtifact(test_http2);

    const options_http3 = makeOptions(b, .{ .enable_tls = true, .enable_http3 = true });
    const test_http3 = addTestVariant(b, target, optimize, swerver_module, options_http3, false);
    if (is_native) {
        test_http3.root_module.linkSystemLibrary("ssl", .{});
        test_http3.root_module.linkSystemLibrary("crypto", .{});
    }
    const test_http3_run = b.addRunArtifact(test_http3);

    const options_proxy = makeOptions(b, .{ .enable_proxy = true });
    const test_proxy = addTestVariant(b, target, optimize, swerver_module, options_proxy, false);
    const test_proxy_run = b.addRunArtifact(test_proxy);

    const options_io_uring = makeOptions(b, .{ .enable_io_uring = true });
    const test_io_uring = addTestVariant(b, target, optimize, swerver_module, options_io_uring, false);
    const test_io_uring_run = b.addRunArtifact(test_io_uring);

    const options_x402_crypto = makeOptions(b, .{ .enable_x402_crypto = true });
    const test_x402_crypto = addTestVariant(b, target, optimize, swerver_module, options_x402_crypto, false);
    test_x402_crypto.root_module.linkSystemLibrary("crypto", .{});
    const test_x402_crypto_run = b.addRunArtifact(test_x402_crypto);

    const options_all = makeOptions(b, .{ .enable_tls = true, .enable_http2 = true, .enable_http3 = true, .enable_proxy = true, .enable_io_uring = true, .enable_x402_crypto = true });
    const test_all = addTestVariant(b, target, optimize, swerver_module, options_all, false);
    if (is_native) {
        test_all.root_module.linkSystemLibrary("ssl", .{});
        test_all.root_module.linkSystemLibrary("crypto", .{});
    }
    const test_all_run = b.addRunArtifact(test_all);

    const test_matrix = b.step("test-matrix", "Run unit tests across build flag combinations");
    test_matrix.dependOn(&test_run.step);
    test_matrix.dependOn(&test_tls_run.step);
    test_matrix.dependOn(&test_http2_run.step);
    test_matrix.dependOn(&test_proxy_run.step);
    test_matrix.dependOn(&test_io_uring_run.step);
    // H3 and all-features variants require OpenSSL 3.5+ (QUIC TLS APIs).
    // Skip in test-matrix; use test-matrix-h3 when a suitable OpenSSL is available.
    const test_matrix_h3 = b.step("test-matrix-h3", "Run H3/full-feature tests (needs OpenSSL 3.5+)");
    test_matrix_h3.dependOn(&test_http3_run.step);
    test_matrix_h3.dependOn(&test_x402_crypto_run.step);
    test_matrix_h3.dependOn(&test_all_run.step);

    const test_flags = b.step("test-flags", "Compile unit tests across build flag combinations");
    test_flags.dependOn(&tests.step);
    test_flags.dependOn(&test_tls.step);
    test_flags.dependOn(&test_http2.step);
    test_flags.dependOn(&test_http3.step);
    test_flags.dependOn(&test_proxy.step);
    test_flags.dependOn(&test_io_uring.step);
    test_flags.dependOn(&test_x402_crypto.step);
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

    const gateway_module = b.createModule(.{
        .root_source_file = b.path("examples/gateway/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gateway_module.addImport("swerver", swerver_module);
    gateway_module.addOptions("build_options", options);
    const gateway_exe = b.addExecutable(.{
        .name = "swerver-gateway-example",
        .root_module = gateway_module,
    });
    b.installArtifact(gateway_exe);
    const gateway_run = b.addRunArtifact(gateway_exe);
    if (b.args) |args| gateway_run.addArgs(args);
    const gateway_step = b.step("gateway", "Run gateway example");
    gateway_step.dependOn(&gateway_run.step);

    // WASM edge-function e2e mock server (design 10.0). Only built with
    // -Denable-wasm, since it imports swerver.wasm.*. Embeds the committed filter
    // fixture and runs the mock host-call transport to validate park/resume over
    // real HTTP. `zig build wasm-e2e -Denable-wasm=true`.
    if (enable_wasm) {
        const wasm_e2e_module = b.createModule(.{
            .root_source_file = b.path("examples/wasm_e2e/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        wasm_e2e_module.addImport("swerver", swerver_module);
        wasm_e2e_module.addOptions("build_options", options);
        wasm_e2e_module.addAnonymousImport("filter_wasm", .{
            .root_source_file = b.path("src/wasm/testdata/filter_probe.wasm"),
        });
        const wasm_e2e_exe = b.addExecutable(.{
            .name = "swerver-wasm-e2e",
            .root_module = wasm_e2e_module,
        });
        b.installArtifact(wasm_e2e_exe);
        const wasm_e2e_run = b.addRunArtifact(wasm_e2e_exe);
        if (b.args) |args| wasm_e2e_run.addArgs(args);
        const wasm_e2e_step = b.step("wasm-e2e", "Run the WASM edge-function e2e mock server");
        wasm_e2e_step.dependOn(&wasm_e2e_run.step);
    }

    // --- check: compile everything without running ---
    // `zig build test` only compiles the unit-test binary, not the server
    // exe or the example exes. A changed public signature can therefore pass
    // `zig build test` yet break `zig build` (Zig analyzes lazily, so an
    // unreferenced call site is never checked by the tests). `check` compiles
    // the server exe, both examples, the bench exe, and the matrix-safe test
    // variants without running them, so signature drift is caught before push.
    // Fast: compile-only, no test execution. The H3 / all-features variants
    // are omitted for the same reason test-matrix omits them: they need
    // OpenSSL 3.5+ (QUIC TLS symbols) to link, which CI's OpenSSL 3.0 lacks.
    const check_step = b.step("check", "Compile all artifacts without running (signature-drift guard)");
    check_step.dependOn(&exe.step);
    check_step.dependOn(&example_exe.step);
    check_step.dependOn(&gateway_exe.step);
    check_step.dependOn(&bench_exe.step);
    check_step.dependOn(&tests.step);
    check_step.dependOn(&test_tls.step);
    check_step.dependOn(&test_http2.step);
    check_step.dependOn(&test_proxy.step);
    check_step.dependOn(&test_io_uring.step);
}

const FeatureFlags = struct {
    enable_tls: bool = false,
    enable_http2: bool = false,
    enable_http3: bool = false,
    enable_proxy: bool = false,
    enable_io_uring: bool = false,
    enable_x402_crypto: bool = false,
    enable_compression: bool = false,
    enable_wasm: bool = false,
};

// Core wasm3 translation units. Excludes the WASI/tracer/meta API bindings
// (a sandboxed filter has no ambient syscall surface) and m3_api_uvwasi.c
// (external dep, not vendored). See vendor/wasm3/PATCHES.md.
const WASM3_FILES = [_][]const u8{
    "m3_core.c",   "m3_env.c",      "m3_module.c",   "m3_parse.c",
    "m3_compile.c", "m3_emit.c",    "m3_optimize.c", "m3_exec.c",
    "m3_function.c", "m3_bind.c",   "m3_code.c",     "m3_info.c",
    "m3_api_libc.c",
};

const WASM3_CFLAGS = [_][]const u8{
    "-std=gnu11",          "-Wall",                  "-Wextra",
    "-Wno-unused-function", "-Wno-unused-parameter", "-Wno-unused-variable",
    "-O3",                  "-fno-sanitize=undefined",
};

/// wasm3 include paths only: needed by any module whose source @cImports
/// wasm3.h (so translate-c can find the headers). Does not compile the C.
fn addWasm3Headers(b: *std.Build, module: *std.Build.Module) void {
    module.addIncludePath(b.path("vendor/wasm3/source"));
    // Shim provides a macOS <endian.h> so @cImport translate-c succeeds; see
    // vendor/wasm3/PATCHES.md. Searched after source/, harmless to the .c.
    module.addIncludePath(b.path("vendor/wasm3/shim"));
}

/// Add the vendored wasm3 interpreter (headers + C) to a module. Module must
/// link libc. The C is compiled exactly once (into swerver_module); test
/// modules that re-import wasm source get headers-only via addWasm3Headers to
/// avoid duplicate symbols, since they link swerver_module's compiled objects.
fn addWasm3(b: *std.Build, module: *std.Build.Module) void {
    addWasm3Headers(b, module);
    module.addCSourceFiles(.{
        .root = b.path("vendor/wasm3/source"),
        .files = &WASM3_FILES,
        .flags = &WASM3_CFLAGS,
    });
}

fn makeOptions(b: *std.Build, flags: FeatureFlags) *std.Build.Step.Options {
    const opts = b.addOptions();
    opts.addOption(bool, "enable_tls", flags.enable_tls);
    opts.addOption(bool, "enable_http2", flags.enable_http2);
    opts.addOption(bool, "enable_http3", flags.enable_http3);
    opts.addOption(bool, "enable_proxy", flags.enable_proxy);
    opts.addOption(bool, "enable_io_uring", flags.enable_io_uring);
    opts.addOption(bool, "enable_x402_crypto", flags.enable_x402_crypto);
    opts.addOption(bool, "enable_compression", flags.enable_compression);
    opts.addOption(bool, "enable_wasm", flags.enable_wasm);
    return opts;
}

fn addTestVariant(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    swerver_module: *std.Build.Module,
    opts: *std.Build.Step.Options,
    with_wasm: bool,
) *std.Build.Step.Compile {
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_module.addOptions("build_options", opts);
    test_module.addImport("swerver", swerver_module);
    // tests.zig re-imports swerver source into the root test module, so when
    // wasm is on, the root module needs wasm3 headers for runtime.zig's
    // @cImport. The C objects come from swerver_module (linked), so headers
    // only, never compiling the C twice (duplicate symbols).
    if (with_wasm) addWasm3Headers(b, test_module);
    return b.addTest(.{ .root_module = test_module });
}
