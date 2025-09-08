const std = @import("std");

pub fn build(b: *std.Build) void {

    const option_libc = (b.option(bool, "libc", "build with libc?")) orelse false;

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("zigdig", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
    });

    const exe = b.addExecutable(.{
        .name = "zigdig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zigdig", .module = lib_mod },
            },
        }),
    });
    if (option_libc) exe.linkLibC();
    b.installArtifact(exe);

    const exe_tinyhost = b.addExecutable(.{
        .name = "zigdig-tiny",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main_tinyhost.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zigdig", .module = lib_mod },
            },
        }),
    });
    b.installArtifact(exe_tinyhost);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    // hence why we have to create two separate ones.
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
