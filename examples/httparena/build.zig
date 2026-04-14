const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Pull in swerver as a library. With `b.dependency("swerver", …)`
    // this example becomes a real end-to-end test of the library
    // packaging story (build.zig.zon + addModule): if the parent's
    // build.zig.zon declares fingerprint/name/paths correctly and the
    // parent's build.zig exposes `swerver` via addModule, this call
    // resolves the module and we can addImport it into our own binary.
    const swerver_dep = b.dependency("swerver", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_module.addImport("swerver", swerver_dep.module("swerver"));

    const exe = b.addExecutable(.{
        .name = "swerver-httparena",
        .root_module = exe_module,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the HttpArena benchmark example server");
    run_step.dependOn(&run_cmd.step);
}
