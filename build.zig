const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{
        .abi = .gnu,
        .cpu_arch = .x86,
        .os_tag = .windows,
        .os_version_min = .{ .windows = .xp },
        .os_version_max = .{ .windows = .xp },
    } });
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zig_blaster",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/blaster.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.entry = .{ .symbol_name = "WinMainCRTStartup" };
    exe.linker_dynamicbase = false;
    exe.root_module.strip = true;

    const install_exe = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(&install_exe.step);
}
