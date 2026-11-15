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

    // Documentation facts are generated from the source tree so counts cannot drift.
    const facts_exe = b.addExecutable(.{
        .name = "PocketRootFacts",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/facts.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "PocketRoot", .module = mod }},
        }),
    });
    const facts_write = b.addRunArtifact(facts_exe);
    facts_write.addArg("--write");
    const facts_step = b.step("facts", "Regenerate docs/facts.json and docs/capabilities/facts.md");
    facts_step.dependOn(&facts_write.step);

    const facts_check = b.addRunArtifact(facts_exe);
    facts_check.addArg("--check");
    const docs_check_step = b.step("docs-check", "Verify the generated fact sheet is current");
    docs_check_step.dependOn(&facts_check.step);

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
        .paths = &.{ "build.zig", "build.zig.zon", "src", "tools" },
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
    addSmoke(smoke_step, exe, &.{ "script", "run", "samples/scripts/reference-flow.pk" });
    addSmoke(smoke_step, exe, &.{ "device", "info" });
    addSmoke(smoke_step, exe, &.{ "device", "request", "infrared", "read", "--payload", "capture" });
    addSmokeExit(smoke_step, exe, &.{ "device", "request", "subghz", "transmit", "--authorize-active" }, 1);
    addSmoke(smoke_step, exe, &.{
        "device",
        "serve",
        "--transport",
        "loopback",
        "--frames",
        "samples/device/request-infrared.pkrt",
        "--output",
        ".zig-cache/smoke-device.pkrt",
    });
    addSmokeStdin(smoke_step, exe, &.{
        "device",
        "serve",
        "--transport",
        "stdio",
        "--output",
        ".zig-cache/smoke-device-stdio.pkrt",
    }, "samples/device/request-infrared.pkrt");
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
    // Cross-repo fixture: accept a sibling checkout or one inside the workspace, and
    // keep the engine repo independently checkable when neither is present.
    const vulndb_candidates = [_][]const u8{
        "../PocketRootVulnerabilityDb/vulndb/catalog-v1.jsonl",
        "PocketRootVulnerabilityDb/vulndb/catalog-v1.jsonl",
    };
    var vulndb_catalog: ?[]const u8 = null;
    for (vulndb_candidates) |candidate| {
        if (std.Io.Dir.accessAbsolute(b.graph.io, b.pathFromRoot(candidate), .{})) |_| {
            vulndb_catalog = candidate;
            break;
        } else |_| {}
    }
    if (vulndb_catalog) |catalog| {
        addSmoke(smoke_step, exe, &.{
            "vulns",
            catalog,
            "--protocol",
            "nmap",
            "samples/network/nmap-demo.xml",
        });
    }

    const check_step = b.step("check", "Run formatting, tests, and offline smoke checks");
    check_step.dependOn(&fmt_check.step);
    check_step.dependOn(test_step);
    check_step.dependOn(smoke_step);
    check_step.dependOn(&facts_check.step);
}

fn addSmoke(step: *std.Build.Step, exe: *std.Build.Step.Compile, args: []const []const u8) void {
    const command = step.owner.addRunArtifact(exe);
    command.addArgs(args);
    step.dependOn(&command.step);
}

/// Feeds a recorded frame stream on stdin; this is the same transport a device
/// serial link would use, without a device.
fn addSmokeStdin(
    step: *std.Build.Step,
    exe: *std.Build.Step.Compile,
    args: []const []const u8,
    stdin_path: []const u8,
) void {
    const command = step.owner.addRunArtifact(exe);
    command.addArgs(args);
    command.setStdIn(.{ .lazy_path = step.owner.path(stdin_path) });
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
