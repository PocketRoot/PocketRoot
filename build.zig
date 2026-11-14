const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("PocketRoot", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const exe = b.addExecutable(.{
        .name = "PocketRoot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "PocketRoot", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run PocketRoot");
    run_step.dependOn(&run_cmd.step);

    const mod_tests = b.addRunArtifact(b.addTest(.{ .root_module = mod }));
    const exe_tests = b.addRunArtifact(b.addTest(.{ .root_module = exe.root_module }));
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&mod_tests.step);
    test_step.dependOn(&exe_tests.step);

    const fmt_check = b.addFmt(.{
        .paths = &.{ "build.zig", "build.zig.zon", "src" },
        .check = true,
    });
    const smoke_step = b.step("smoke", "Run offline CLI smoke checks");
    addSmoke(smoke_step, exe, &.{"protocols"});
    addSmokeExit(smoke_step, exe, &.{"capture"}, 2);
    addSmokeExit(smoke_step, exe, &.{ "neighbor", "example.com" }, 1);
    addSmokeExit(smoke_step, exe, &.{ "scan-cidr", "invalid" }, 1);
    addSmokeExit(smoke_step, exe, &.{"unknown-command"}, 2);
    addSmoke(smoke_step, exe, &.{ "analyze", "samples/infrared/demo-power.ir" });
    addSmoke(smoke_step, exe, &.{ "analyze", "--json", "samples/infrared/demo-power.ir" });
    addSmoke(smoke_step, exe, &.{
        "project",
        "--json",
        "samples",
        "--protocol",
        "badusb",
        "samples/badusb/review-demo.txt",
        "--protocol",
        "nmap",
        "samples/network/nmap-demo.xml",
        "--protocol",
        "nuclei",
        "samples/network/nuclei-demo.jsonl",
    });
    addSmoke(smoke_step, exe, &.{
        "vulns",
        "../PocketRootVulnerabilityDb/vulndb/catalog-v1.jsonl",
        "--protocol",
        "nmap",
        "samples/network/nmap-demo.xml",
    });

    const check_step = b.step("check", "Run formatting, tests, and offline smoke checks");
    check_step.dependOn(&fmt_check.step);
    check_step.dependOn(test_step);
    check_step.dependOn(smoke_step);
}

fn addSmoke(step: *std.Build.Step, exe: *std.Build.Step.Compile, args: []const []const u8) void {
    const command = step.owner.addRunArtifact(exe);
    command.addArgs(args);
    step.dependOn(&command.step);
}

fn addSmokeExit(
    step: *std.Build.Step,
    exe: *std.Build.Step.Compile,
    args: []const []const u8,
    exit_code: u8,
) void {
    const command = step.owner.addRunArtifact(exe);
    command.addArgs(args);
    command.expectExitCode(exit_code);
    step.dependOn(&command.step);
}
