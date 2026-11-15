const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const PocketRoot = @import("PocketRoot");

const max_project_inputs = 64;
const discovery_default_ports = [_]u16{ 22, 80, 443 };

pub fn main(init: std.process.Init) !void {
    run(init) catch |err| switch (err) {
        error.InvalidArguments => std.process.exit(2),
        error.CommandFailed => std.process.exit(1),
        else => return err,
    };
}

fn run(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    var runtime = PocketRoot.simulator.Runtime.init(
        arena,
        init.io,
        PocketRoot.apps.builtinApps(),
        PocketRoot.protocols.registry.builtinProtocols(),
    );
    defer runtime.deinit();

    if (args.len <= 1 or std.mem.eql(u8, args[1], "help") or std.mem.eql(u8, args[1], "--help")) {
        try printUsage(stdout);
        return;
    }

    if (std.mem.eql(u8, args[1], "list")) {
        try printApps(stdout, runtime.apps.apps);
        return;
    }

    if (std.mem.eql(u8, args[1], "protocols")) {
        try printProtocols(stdout, runtime.protocols.protocols);
        return;
    }

    if (std.mem.eql(u8, args[1], "network")) {
        if (args.len != 2) {
            try stdout.print("usage: network\n", .{});
            return error.InvalidArguments;
        }
        var result = PocketRoot.inspectNetworkEnvironment(arena, init.io) catch |err| {
            try stdout.print("network inspection failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("network: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "capture")) {
        if (args.len != 5) {
            try stdout.print("usage: capture <seconds> <output.pcapng> <component-id>\n", .{});
            return error.InvalidArguments;
        }

        const duration_seconds = std.fmt.parseInt(u8, args[2], 10) catch {
            try stdout.print("invalid capture duration; use {d}-{d} seconds\n", .{
                PocketRoot.services.live_capture.min_duration_seconds,
                PocketRoot.services.live_capture.max_duration_seconds,
            });
            return error.InvalidArguments;
        };
        const component_id = std.fmt.parseInt(u32, args[4], 10) catch {
            try stdout.print("invalid pktmon component id\n", .{});
            return error.InvalidArguments;
        };

        var result = PocketRoot.captureNetwork(arena, init.io, args[3], .{
            .component_id = component_id,
            .duration_seconds = duration_seconds,
        }) catch |err| {
            try stdout.print("packet capture failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("capture: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "neighbor")) {
        if (args.len < 3 or args.len > 2 + PocketRoot.services.neighbor_probe.max_targets) {
            try stdout.print("usage: neighbor <ip>... (max {d})\n", .{PocketRoot.services.neighbor_probe.max_targets});
            return error.InvalidArguments;
        }

        const targets = try appArgs(arena, args[2..]);
        var result = PocketRoot.probeNeighbors(arena, init.io, targets, .{}) catch |err| {
            try stdout.print("neighbor probe failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("neighbors: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "tcp-scan")) {
        if (args.len < 3 or args.len > 4) {
            try stdout.print("usage: tcp-scan <ip> [ports]\n", .{});
            return error.InvalidArguments;
        }

        var owned_ports: ?[]u16 = null;
        defer if (owned_ports) |ports| arena.free(ports);
        const ports: []const u16 = if (args.len == 4) ports: {
            const parsed = parsePortList(arena, args[3], PocketRoot.services.tcp_scan.max_ports) catch {
                try stdout.print("invalid port list; use comma-separated ports or ranges (max {d})\n", .{PocketRoot.services.tcp_scan.max_ports});
                return error.InvalidArguments;
            };
            owned_ports = parsed;
            break :ports parsed;
        } else PocketRoot.services.tcp_scan.default_ports[0..];

        var result = PocketRoot.scanTcp(arena, init.io, args[2], ports, .{}) catch |err| {
            try stdout.print("tcp scan failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("scan: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "discover")) {
        if (args.len < 3 or args.len > 4) {
            try stdout.print("usage: discover <ipv4-cidr> [ports]\n", .{});
            return error.InvalidArguments;
        }

        var owned_ports: ?[]u16 = null;
        defer if (owned_ports) |ports| arena.free(ports);
        const ports: []const u16 = if (args.len == 4) ports: {
            const parsed = parsePortList(arena, args[3], PocketRoot.services.network_discovery.max_ports) catch {
                try stdout.print("invalid discovery port list; use at most {d} comma-separated ports\n", .{PocketRoot.services.network_discovery.max_ports});
                return error.InvalidArguments;
            };
            owned_ports = parsed;
            break :ports parsed;
        } else discovery_default_ports[0..];

        var result = PocketRoot.discoverNetwork(arena, init.io, args[2], ports, .{}) catch |err| {
            try stdout.print("network discovery failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("discovery: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "scan-cidr")) {
        if (args.len < 3 or args.len > 5) {
            try stdout.print("usage: scan-cidr <ipv4-cidr> [ports] [concurrency]\n", .{});
            return error.InvalidArguments;
        }

        var owned_ports: ?[]u16 = null;
        defer if (owned_ports) |ports| arena.free(ports);
        const ports: []const u16 = if (args.len >= 4) ports: {
            const parsed = parsePortList(arena, args[3], PocketRoot.services.network_scan.max_ports) catch {
                try stdout.print("invalid scan port list; use at most {d} comma-separated ports or ranges\n", .{PocketRoot.services.network_scan.max_ports});
                return error.InvalidArguments;
            };
            owned_ports = parsed;
            break :ports parsed;
        } else discovery_default_ports[0..];

        const concurrency = if (args.len == 5)
            std.fmt.parseInt(usize, args[4], 10) catch {
                try stdout.print("invalid concurrency; use 1-{d}\n", .{PocketRoot.services.network_scan.max_concurrency});
                return error.InvalidArguments;
            }
        else
            8;
        if (concurrency == 0 or concurrency > PocketRoot.services.network_scan.max_concurrency) {
            try stdout.print("invalid concurrency; use 1-{d}\n", .{PocketRoot.services.network_scan.max_concurrency});
            return error.InvalidArguments;
        }

        var result = PocketRoot.scanNetwork(arena, init.io, args[2], ports, .{
            .concurrency = concurrency,
        }) catch |err| {
            try stdout.print("CIDR scan failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("scan-cidr: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "http-inspect")) {
        if (args.len < 3 or args.len > 4) {
            try stdout.print("usage: http-inspect <target> [port]\n", .{});
            return error.InvalidArguments;
        }

        const port = if (args.len == 4)
            std.fmt.parseInt(u16, args[3], 10) catch {
                try stdout.print("invalid HTTP port\n", .{});
                return error.InvalidArguments;
            }
        else
            80;
        if (port == 0) {
            try stdout.print("invalid HTTP port\n", .{});
            return error.InvalidArguments;
        }

        var result = PocketRoot.inspectHttp(arena, init.io, args[2], port, .{}) catch |err| {
            try stdout.print("HTTP inspection failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("http: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "tls-inspect")) {
        if (args.len < 3 or args.len > 4) {
            try stdout.print("usage: tls-inspect <target> [port]\n", .{});
            return error.InvalidArguments;
        }

        const port = if (args.len == 4)
            std.fmt.parseInt(u16, args[3], 10) catch {
                try stdout.print("invalid TLS port\n", .{});
                return error.InvalidArguments;
            }
        else
            443;
        if (port == 0) {
            try stdout.print("invalid TLS port\n", .{});
            return error.InvalidArguments;
        }

        var result = PocketRoot.inspectTls(arena, init.io, args[2], port, .{}) catch |err| {
            try stdout.print("TLS inspection failed: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();

        try stdout.print("tls: ", .{});
        try printTerminalText(stdout, result.summary);
        try stdout.writeByte('\n');
        try printResultDetails(stdout, &result);
        return;
    }

    if (std.mem.eql(u8, args[1], "archive")) {
        const root_path = if (args.len >= 3) args[2] else "samples";
        var listing = try runtime.listArchive(root_path);
        defer listing.deinit();

        try printArchive(stdout, listing.entries.items);
        return;
    }

    if (std.mem.eql(u8, args[1], "project")) {
        const json_output = args.len >= 3 and std.mem.eql(u8, args[2], "--json");
        const raw_inputs = if (json_output) args[3..] else args[2..];
        const inputs = parseProjectInputs(arena, raw_inputs) catch {
            try stdout.print("usage: project [--json] <path>... [--protocol <id> <path>]...\n", .{});
            return error.InvalidArguments;
        };
        defer arena.free(inputs);

        var project = PocketRoot.Project.init(arena);
        defer project.deinit();
        for (inputs) |input| try importProjectInput(&runtime, &project, inputs, input);

        if (json_output) {
            try printJsonProject(stdout, &project);
        } else {
            try printProjectReport(stdout, &project);
        }
        return;
    }

    if (std.mem.eql(u8, args[1], "vulns")) {
        if (args.len < 4) {
            try stdout.print("usage: vulns <catalog.jsonl> <path>... [--protocol <id> <path>]...\n", .{});
            return error.InvalidArguments;
        }
        const inputs = parseProjectInputs(arena, args[3..]) catch {
            try stdout.print("usage: vulns <catalog.jsonl> <path>... [--protocol <id> <path>]...\n", .{});
            return error.InvalidArguments;
        };
        defer arena.free(inputs);

        const catalog_data = runtime.storage.loadBytes(arena, args[2]) catch |err| {
            try stdout.print("cannot load vulnerability catalog: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer arena.free(catalog_data);
        var catalog = PocketRoot.services.vulnerability_catalog.Catalog.load(arena, catalog_data) catch |err| {
            try stdout.print("invalid vulnerability catalog: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer catalog.deinit();

        var project = PocketRoot.Project.init(arena);
        defer project.deinit();
        for (inputs) |input| try importProjectInput(&runtime, &project, inputs, input);
        var graph = try PocketRoot.AssetGraph.build(arena, project.analyses.items);
        defer graph.deinit();
        var report = try PocketRoot.services.vulnerability_matcher.match(
            arena,
            &graph,
            catalog.vulnerabilities,
            .{},
        );
        defer report.deinit();
        try printVulnerabilityReport(stdout, &graph, &catalog, &report);
        return;
    }

    if (std.mem.eql(u8, args[1], "migrate")) {
        const explicit = args.len == 6 and std.mem.eql(u8, args[2], "--protocol");
        if ((!explicit and args.len != 4) or (explicit and args.len != 6)) {
            try stdout.print("usage: migrate [--protocol <id>] <input> <output>\n", .{});
            return error.InvalidArguments;
        }
        const protocol_id: ?[]const u8 = if (explicit) args[3] else null;
        const input_path = if (explicit) args[4] else args[2];
        const output_path = if (explicit) args[5] else args[3];
        if (std.mem.eql(u8, input_path, output_path)) {
            try stdout.print("input and output paths must differ\n", .{});
            return error.InvalidArguments;
        }
        const registered = if (protocol_id) |id|
            runtime.protocols.find(id)
        else
            runtime.protocols.inferFromPath(input_path);
        const descriptor = registered orelse {
            try stdout.print("unknown protocol for: {s}\n", .{input_path});
            return error.InvalidArguments;
        };
        const data = runtime.storage.loadBytes(arena, input_path) catch |err| {
            try stdout.print("cannot load migration input: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer arena.free(data);
        const preserved = descriptor.validatedCopy(arena, data) catch |err| {
            try stdout.print("invalid {s} input: {s}\n", .{ descriptor.id, @errorName(err) });
            return error.CommandFailed;
        };
        defer arena.free(preserved);
        runtime.storage.saveBytes(output_path, preserved) catch |err| {
            try stdout.print("cannot save migration output: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        try stdout.print("migrated {s} byte-exact: {s} -> {s}\n", .{ descriptor.id, input_path, output_path });
        return;
    }

    if (std.mem.eql(u8, args[1], "run")) {
        if (args.len < 3) {
            try stdout.print("missing app id\n\n", .{});
            try printUsage(stdout);
            return error.InvalidArguments;
        }

        const app_args = try appArgs(arena, args[3..]);

        runtime.runAppArgs(args[2], app_args) catch |err| switch (err) {
            error.UnknownApp => {
                try stdout.print("unknown app: {s}\n\n", .{args[2]});
                try printApps(stdout, runtime.apps.apps);
                return error.InvalidArguments;
            },
            else => return err,
        };

        try stdout.print("ran app: {s}\n", .{args[2]});
        try printEvents(stdout, runtime.events.items());
        try printNotifications(stdout, runtime.notifications.items());
        return;
    }

    if (std.mem.eql(u8, args[1], "script")) {
        if (args.len < 4 or !std.mem.eql(u8, args[2], "run")) {
            try stdout.print("usage: script run [--lib a.pk,b.pk] [--authorize-active] [--region <id>] <file.pk>\n\n", .{});
            return error.InvalidArguments;
        }
        const request = parseScriptRunArgs(arena, args[3..]) catch {
            try stdout.print("usage: script run [--lib a.pk,b.pk] [--authorize-active] [--region <id>] <file.pk>\n", .{});
            return error.InvalidArguments;
        };
        const ok = try runScriptCommand(arena, init.io, Io.Dir.cwd(), stdout, request);
        if (!ok) return error.CommandFailed;
        return;
    }

    if (std.mem.eql(u8, args[1], "analyze") or std.mem.eql(u8, args[1], "report")) {
        const command = args[1];
        if (args.len < 3) {
            try stdout.print("missing path\n\n", .{});
            try printUsage(stdout);
            return error.InvalidArguments;
        }

        const request = parseAnalyzeArgs(args[2..], std.mem.eql(u8, command, "analyze")) catch {
            try stdout.print("usage: {s} [--json] [--protocol <id>] <path>\n", .{command});
            return error.InvalidArguments;
        };

        var analysis = (try loadAnalysis(&runtime, stdout, request)) orelse return error.CommandFailed;
        defer analysis.deinit();

        if (std.mem.eql(u8, command, "report")) {
            try printMarkdownReport(stdout, &analysis);
        } else if (request.json_output) {
            try printJsonAnalysis(stdout, &analysis);
        } else {
            try stdout.print("analysis: {s} ", .{analysis.protocol.id});
            try printTerminalText(stdout, analysis.result.summary);
            try stdout.writeByte('\n');
            try printAnalysisDetails(stdout, &analysis);
            try printEvents(stdout, runtime.events.items());
        }
        return;
    }

    try stdout.print("unknown command: {s}\n\n", .{args[1]});
    try printUsage(stdout);
    return error.InvalidArguments;
}

const AnalyzeRequest = struct {
    protocol_id: ?[]const u8,
    path: []const u8,
    json_output: bool,
    base_address: u32 = 0,
    architecture: ?[]const u8 = null,
};

const ProjectInput = struct {
    protocol_id: ?[]const u8,
    path: []const u8,
};

fn importProjectInput(
    runtime: *PocketRoot.simulator.Runtime,
    project: *PocketRoot.Project,
    all_inputs: []const ProjectInput,
    input: ProjectInput,
) !void {
    if (input.protocol_id != null) {
        try importProjectFile(runtime, project, input);
        return;
    }

    const stat = Io.Dir.cwd().statFile(runtime.storage.io, input.path, .{}) catch |err| {
        try project.addIssue(input.path, @errorName(err));
        return;
    };
    switch (stat.kind) {
        .file => try importProjectFile(runtime, project, input),
        .directory => {
            var listing = runtime.listArchive(input.path) catch |err| {
                try project.addIssue(input.path, @errorName(err));
                return;
            };
            defer listing.deinit();

            for (listing.entries.items) |entry| {
                if (entry.protocol_id) |protocol_id| {
                    try importProjectFile(runtime, project, .{
                        .protocol_id = protocol_id,
                        .path = entry.path,
                    });
                } else {
                    if (!hasExplicitProjectInput(all_inputs, entry.path)) project.skipFile();
                }
            }
        },
        else => try project.addIssue(input.path, "unsupported path kind"),
    }
}

fn importProjectFile(
    runtime: *PocketRoot.simulator.Runtime,
    project: *PocketRoot.Project,
    input: ProjectInput,
) !void {
    var analyzer = runtime.workbench();
    const analysis = analyzer.analyzePath(input.protocol_id, input.path) catch |err| {
        try project.addIssue(input.path, @errorName(err));
        return;
    };
    _ = try project.addAnalysis(analysis);
}

fn loadAnalysis(
    runtime: *PocketRoot.simulator.Runtime,
    writer: *Io.Writer,
    request: AnalyzeRequest,
) !?PocketRoot.services.workbench.Analysis {
    return runtime.analyzeProtocolPathWith(request.protocol_id, request.path, .{
        .base_address = request.base_address,
        .architecture = request.architecture,
    }) catch |err| switch (err) {
        error.UnknownProtocol => {
            try writer.print("unknown protocol for: {s}\n", .{request.path});
            try printProtocols(writer, runtime.protocols.protocols);
            return null;
        },
        error.FileNotFound => {
            try writer.print("file not found: {s}\n", .{request.path});
            return null;
        },
        else => return err,
    };
}

fn printUsage(writer: *Io.Writer) !void {
    try writer.print(
        \\PocketRoot Zig simulator
        \\
        \\Commands:
        \\  list                 List built-in apps
        \\  protocols            List built-in protocols
        \\  network              Inspect the local network environment
        \\  capture <seconds> <output.pcapng> <component-id>
        \\                       Capture one explicit pktmon component
        \\  neighbor <ip>...     Probe up to 64 explicit IPv4/IPv6 neighbors
        \\  tcp-scan <ip> [ports]  Probe explicit TCP ports on one IP
        \\  discover <ipv4-cidr> [ports]  Probe at most 64 explicit IPv4 hosts
        \\  scan-cidr <ipv4-cidr> [ports] [concurrency]
        \\                       Scan up to 256 hosts, 64 ports, 32 workers
        \\  http-inspect <target> [port]  Inspect one HTTP endpoint
        \\  tls-inspect <target> [port]  Inspect one TLS endpoint
        \\  archive [root]       List protocol files under a directory
        \\  project [--json] <path>... [--protocol <id> <path>]...
        \\  vulns <catalog.jsonl> <path>... [--protocol <id> <path>]...
        \\                       Match offline observations to the local catalogue
        \\  migrate [--protocol <id>] <input> <output>
        \\                       Validate and preserve a Flipper file byte-exact
        \\  script run [--lib a.pk,b.pk] [--authorize-active] [--region <id>] <file.pk>
        \\                       Compile and run a DSL script on the simulated backend
        \\  analyze [--json] <path>  Analyze a protocol file by extension
        \\  analyze [--json] [--base <hex>] [--arch <thumb|arm>] --protocol firmware <path>
        \\                       Firmware triage with Thumb disassembly
        \\  analyze [--json] --protocol <id> <path>
        \\  report [--protocol <id>] <path>
        \\  run <app-id> [args]  Run an app in the desktop simulator
        \\
        \\Examples:
        \\  PocketRoot list
        \\  PocketRoot protocols
        \\  PocketRoot network
        \\  PocketRoot capture 10 capture.pcapng 7
        \\  PocketRoot neighbor 192.0.2.10 fe80::1%12
        \\  PocketRoot tcp-scan 192.0.2.10 22,80,443,8000-8003
        \\  PocketRoot discover 192.0.2.0/28 22,80,443
        \\  PocketRoot scan-cidr 192.0.2.0/24 22,80,443 16
        \\  PocketRoot http-inspect 192.0.2.10 8080
        \\  PocketRoot tls-inspect example.com 443
        \\  PocketRoot archive
        \\  PocketRoot project samples --protocol nmap samples/network/nmap-demo.xml --protocol nuclei samples/network/nuclei-demo.jsonl
        \\  PocketRoot vulns ../PocketRootVulnerabilityDb/vulndb/catalog-v1.jsonl --protocol nmap samples/network/nmap-demo.xml
        \\  PocketRoot migrate samples/nfc/demo-iso14443-3a.nfc migrated/demo.nfc
        \\  PocketRoot analyze samples/infrared/demo-power.ir
        \\  PocketRoot analyze --json samples/infrared/demo-power.ir
        \\  PocketRoot analyze samples/subghz/demo-princeton.sub
        \\  PocketRoot analyze --protocol infrared samples/infrared/demo-power.ir
        \\  PocketRoot analyze --protocol badusb samples/badusb/review-demo.txt
        \\  PocketRoot analyze --protocol nmap samples/network/nmap-demo.xml
        \\  PocketRoot analyze capture.pcapng
        \\  PocketRoot report --protocol nuclei samples/network/nuclei-demo.jsonl
        \\  PocketRoot run infrared save-demo
        \\  PocketRoot run infrared analyze samples/infrared/demo-power.ir
        \\
    , .{});
}

fn printArchive(writer: *Io.Writer, entries: []const PocketRoot.services.archive.ArchiveEntry) !void {
    try writer.print("archive:\n", .{});
    for (entries) |entry| {
        if (entry.protocol_id) |protocol_id| {
            try writer.print("  {s}\t", .{protocol_id});
            try printTerminalText(writer, entry.path);
            try writer.print("\t.", .{});
            try printTerminalText(writer, entry.extension);
            try writer.writeByte('\n');
        } else {
            try writer.print("  unknown\t", .{});
            try printTerminalText(writer, entry.path);
            try writer.print("\t.", .{});
            try printTerminalText(writer, entry.extension);
            try writer.writeByte('\n');
        }
    }
}

const ScriptRunRequest = struct {
    path: []const u8,
    libs: []const []const u8 = &.{},
    authorize_active: bool = false,
    region: []const u8 = "",
};

fn parseScriptRunArgs(allocator: std.mem.Allocator, raw: []const [:0]const u8) !ScriptRunRequest {
    var request = ScriptRunRequest{ .path = "" };
    var libs: std.ArrayList([]const u8) = .empty;
    var path: ?[]const u8 = null;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--lib")) {
            if (index + 1 >= raw.len) return error.InvalidScriptArgs;
            var pieces = std.mem.splitScalar(u8, raw[index + 1], ',');
            var appended: usize = 0;
            while (pieces.next()) |piece| {
                const trimmed = std.mem.trim(u8, piece, " ");
                if (trimmed.len == 0) return error.InvalidScriptArgs;
                libs.append(allocator, trimmed) catch return error.OutOfMemory;
                appended += 1;
            }
            if (appended == 0) return error.InvalidScriptArgs;
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--authorize-active")) {
            if (request.authorize_active) return error.InvalidScriptArgs;
            request.authorize_active = true;
            index += 1;
        } else if (std.mem.eql(u8, raw[index], "--region")) {
            if (request.region.len != 0 or index + 1 >= raw.len) return error.InvalidScriptArgs;
            request.region = raw[index + 1];
            index += 2;
        } else {
            if (std.mem.startsWith(u8, raw[index], "--") or path != null) return error.InvalidScriptArgs;
            path = raw[index];
            index += 1;
        }
    }
    request.path = path orelse return error.InvalidScriptArgs;
    request.libs = libs.toOwnedSlice(allocator) catch return error.OutOfMemory;
    return request;
}

fn enableAllKinds(backend: *PocketRoot.simulator.device.Backend) void {
    inline for (std.meta.fields(PocketRoot.core.capability.Kind)) |field| {
        backend.enable(@enumFromInt(field.value));
    }
}

/// Runs a DSL script against the simulated backend. Library scripts are parsed in the
/// order given, so a later library script may itself run an earlier one.
fn runScriptCommand(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    writer: *Io.Writer,
    request: ScriptRunRequest,
) !bool {
    const max_bytes = PocketRoot.services.script.max_script_bytes;
    var entries: std.ArrayList(PocketRoot.services.script.LibraryEntry) = .empty;

    for (request.libs) |lib_path| {
        const data = dir.readFileAlloc(io, lib_path, allocator, .limited(max_bytes)) catch |err| {
            try writer.print("cannot read library script {s}: {s}\n", .{ lib_path, @errorName(err) });
            return false;
        };
        const library = PocketRoot.services.script.Library{ .entries = entries.items };
        const parsed = allocator.create(PocketRoot.services.script.Script) catch return error.OutOfMemory;
        parsed.* = PocketRoot.services.script.parseWithLibrary(allocator, data, &library) catch |err| {
            try writer.print("invalid library script {s}: {s}\n", .{ lib_path, @errorName(err) });
            return false;
        };
        try entries.append(allocator, .{ .name = parsed.name, .script = parsed });
    }

    const library = PocketRoot.services.script.Library{ .entries = entries.items };
    const main_data = dir.readFileAlloc(io, request.path, allocator, .limited(max_bytes)) catch |err| {
        try writer.print("cannot read script {s}: {s}\n", .{ request.path, @errorName(err) });
        return false;
    };
    var source = PocketRoot.services.script.parseWithLibrary(
        allocator,
        main_data,
        if (entries.items.len > 0) &library else null,
    ) catch |err| {
        try writer.print("invalid script {s}: {s}\n", .{ request.path, @errorName(err) });
        return false;
    };
    defer source.deinit();

    var harness: PocketRoot.simulator.device.Harness = undefined;
    harness.init(allocator, .{ .region = request.region, .allow_active = request.authorize_active });
    defer harness.deinit();
    enableAllKinds(&harness.backend);

    var executor: PocketRoot.ScriptExecutor = undefined;
    executor.initWithLibrary(allocator, &source, &harness.capabilities, .{
        .authorize_active = request.authorize_active,
        .policy_region = request.region,
    }, if (entries.items.len > 0) &library else null) catch |err| {
        try writer.print("cannot compile script {s}: {s}\n", .{ request.path, @errorName(err) });
        return false;
    };
    defer executor.deinit();

    const status = executor.run() catch |err| {
        try writer.print("script {s} aborted: {s}\n", .{ source.name, @errorName(err) });
        return false;
    };

    try writer.print("script \"{s}\" {s}\n", .{ source.name, @tagName(status) });
    const audit = harness.capabilities.audit.entries.items;
    try writer.print("audit: {d}\n", .{audit.len});
    for (audit, 0..) |entry, position| {
        try writer.print("  {d} {s} {s} {s} {s}\n", .{
            position + 1,
            entry.subject,
            @tagName(entry.kind),
            @tagName(entry.operation),
            @tagName(entry.status),
        });
    }
    const emitted = executor.emitted();
    if (emitted.len > 0) {
        try writer.print("emitted: {d}\n", .{emitted.len});
        for (emitted) |item| try writer.print("  {s} {s}\n", .{ item.severity, item.message });
    }
    return status == PocketRoot.services.workflow.Status.succeeded;
}

fn printProtocols(writer: *Io.Writer, protocols: []const PocketRoot.ProtocolDescriptor) !void {
    try writer.print("protocols:\n", .{});
    for (protocols) |descriptor| {
        try writer.print("  {s}\t{s}\t.{s}", .{
            descriptor.id,
            descriptor.category,
            descriptor.file_extension,
        });
        for (descriptor.additional_extensions) |extension| {
            try writer.print(",.{s}", .{extension});
        }
        try writer.print("\t{s}\t{s}\n", .{
            if (descriptor.auto_detect) "auto" else "manual",
            descriptor.name,
        });
    }
}

fn printVulnerabilityReport(
    writer: *Io.Writer,
    graph: *const PocketRoot.AssetGraph,
    catalog: *const PocketRoot.services.vulnerability_catalog.Catalog,
    report: *const PocketRoot.services.vulnerability_matcher.Report,
) !void {
    try writer.print(
        "vulnerabilities: {d} match(es), {d} endpoint(s) examined\n",
        .{ report.matches.items.len, report.endpoints_examined },
    );
    for (report.matches.items) |match| {
        const vulnerability = catalog.vulnerabilities[match.vulnerability_index];
        const asset = &graph.assets.items[match.asset_index];
        const endpoint = asset.endpoints.items[match.endpoint_index];
        try writer.print("  {s} [{s}] ", .{ vulnerability.id, @tagName(vulnerability.severity) });
        try printTerminalText(writer, asset.preferredName());
        try writer.print(" ", .{});
        try printTerminalText(writer, endpoint.transport);
        if (endpoint.port) |port| try writer.print("/{d}", .{port});
        try writer.print(" ", .{});
        try printTerminalText(writer, endpoint.product);
        try writer.print(" ", .{});
        try printTerminalText(writer, endpoint.version);
        try writer.print(" - ", .{});
        try printTerminalText(writer, vulnerability.title);
        try writer.writeByte('\n');
        if (vulnerability.reference.len > 0) {
            try writer.print("    reference: ", .{});
            try printTerminalText(writer, vulnerability.reference);
            try writer.writeByte('\n');
        }
    }
}

fn printAnalysisDetails(
    writer: *Io.Writer,
    analysis: *const PocketRoot.services.workbench.Analysis,
) !void {
    const digest = analysis.artifact.digestHex();
    try writer.print("artifact: ", .{});
    try printTerminalText(writer, analysis.artifact.path);
    try writer.print(" size={d} sha256={s}\n", .{ analysis.artifact.size, digest[0..] });

    try printResultDetails(writer, &analysis.result);
}

fn printResultDetails(writer: *Io.Writer, result: *const PocketRoot.AnalysisResult) !void {
    if (result.fields.items.len > 0) {
        try writer.print("fields:\n", .{});
        for (result.fields.items) |field| {
            try writer.print("  ", .{});
            try printTerminalText(writer, field.name);
            try writer.print(": ", .{});
            try printTerminalText(writer, field.value);
            try writer.writeByte('\n');
        }
    }

    if (result.observations.items.len > 0) {
        try writer.print("network observations:\n", .{});
        for (result.observations.items) |observation| {
            try writer.print("  {s} [{s}]\n", .{ @tagName(observation.kind), @tagName(observation.confidence) });
            if (observation.address.len > 0) {
                try writer.print("    address: ", .{});
                try printTerminalText(writer, observation.address);
                try writer.writeByte('\n');
            }
            if (observation.hostname.len > 0) {
                try writer.print("    hostname: ", .{});
                try printTerminalText(writer, observation.hostname);
                try writer.writeByte('\n');
            }
            if (observation.transport.len > 0) {
                try writer.print("    transport: ", .{});
                try printTerminalText(writer, observation.transport);
                try writer.writeByte('\n');
            }
            if (observation.port) |port| try writer.print("    port: {d}\n", .{port});
            if (observation.service.len > 0) {
                try writer.print("    service: ", .{});
                try printTerminalText(writer, observation.service);
                try writer.writeByte('\n');
            }
            if (observation.version.len > 0) {
                try writer.print("    version: ", .{});
                try printTerminalText(writer, observation.version);
                try writer.writeByte('\n');
            }
            if (observation.source_id.len > 0) {
                try writer.print("    source: ", .{});
                try printTerminalText(writer, observation.source_id);
                try writer.writeByte('\n');
            }
            if (observation.evidence.len > 0) {
                try writer.print("    evidence: ", .{});
                try printIndentedLines(writer, observation.evidence, "              ");
            }
        }
    }

    if (result.findings.items.len > 0) {
        try writer.print("findings:\n", .{});
        for (result.findings.items) |finding| {
            try writer.print("  {s}: ", .{@tagName(finding.severity)});
            try printTerminalText(writer, finding.message);
            try writer.writeByte('\n');
            if (finding.target.len > 0) {
                try writer.print("    target: ", .{});
                try printTerminalText(writer, finding.target);
                try writer.writeByte('\n');
            }
            if (finding.source_id.len > 0) {
                try writer.print("    source: ", .{});
                try printTerminalText(writer, finding.source_id);
                try writer.writeByte('\n');
            }
            if (finding.detail.len > 0) {
                try writer.print("    detail: ", .{});
                try printIndentedLines(writer, finding.detail, "            ");
            }
        }
    }
}

fn printIndentedLines(writer: *Io.Writer, value: []const u8, continuation: []const u8) !void {
    var lines = std.mem.splitScalar(u8, value, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try writer.print("\n{s}", .{continuation});
        try printTerminalText(writer, std.mem.trimEnd(u8, line, "\r"));
        first = false;
    }
    try writer.print("\n", .{});
}

fn printTerminalText(writer: *Io.Writer, value: []const u8) !void {
    for (value) |byte| switch (byte) {
        0x20...0x7e, 0x80...0xff => try writer.writeByte(byte),
        else => try writer.print("\\x{x:0>2}", .{byte}),
    };
}

fn printJsonAnalysis(
    writer: *Io.Writer,
    analysis: *const PocketRoot.services.workbench.Analysis,
) !void {
    var json: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.beginObject();
    try json.objectField("schema");
    try json.write("pocketroot.analysis.v1");
    try json.objectField("analysis");
    try writeJsonAnalysis(&json, analysis);
    try json.endObject();
    try writer.writeByte('\n');
}

fn printJsonProject(writer: *Io.Writer, project: *const PocketRoot.Project) !void {
    var asset_graph = try PocketRoot.AssetGraph.build(project.allocator, project.analyses.items);
    defer asset_graph.deinit();
    var json: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.beginObject();
    try json.objectField("schema");
    try json.write("pocketroot.project.v1");
    try json.objectField("summary");
    try json.beginObject();
    try writeJsonField(&json, "unique_artifacts", project.analyses.items.len);
    try writeJsonField(&json, "duplicate_artifacts", project.duplicate_artifacts);
    try writeJsonField(&json, "unique_findings", project.uniqueFindingCount());
    try writeJsonField(&json, "duplicate_findings", project.duplicateFindingCount());
    try writeJsonField(&json, "unique_observations", project.uniqueObservationCount());
    try writeJsonField(&json, "duplicate_observations", project.duplicateObservationCount());
    try writeJsonField(&json, "assets", asset_graph.assets.items.len);
    try writeJsonField(&json, "skipped_files", project.skipped_files);
    try writeJsonField(&json, "import_issues", project.issues.items.len);
    try json.objectField("severity");
    try json.beginObject();
    inline for (.{
        PocketRoot.FindingSeverity.critical,
        PocketRoot.FindingSeverity.high,
        PocketRoot.FindingSeverity.medium,
        PocketRoot.FindingSeverity.low,
        PocketRoot.FindingSeverity.info,
        PocketRoot.FindingSeverity.warning,
        PocketRoot.FindingSeverity.@"error",
        PocketRoot.FindingSeverity.unknown,
    }) |severity| {
        try writeJsonField(&json, @tagName(severity), project.countSeverity(severity));
    }
    try json.endObject();
    try json.endObject();

    try json.objectField("analyses");
    try json.beginArray();
    for (project.analyses.items) |*analysis| try writeJsonAnalysis(&json, analysis);
    try json.endArray();

    try json.objectField("assets");
    try json.beginArray();
    for (asset_graph.assets.items) |asset| {
        try json.beginObject();
        try writeJsonTextField(&json, "name", asset.preferredName());
        try writeJsonTextField(&json, "confidence", @tagName(asset.confidence));
        try json.objectField("identities");
        try json.beginArray();
        for (asset.identities.items) |identity| {
            try json.beginObject();
            try writeJsonTextField(&json, "kind", @tagName(identity.kind));
            try writeJsonTextField(&json, "value", identity.value);
            try writeJsonTextField(&json, "confidence", @tagName(identity.confidence));
            try json.objectField("sources");
            try json.beginArray();
            for (identity.sources.items) |source| try writeJsonText(&json, source);
            try json.endArray();
            try json.endObject();
        }
        try json.endArray();
        try json.objectField("endpoints");
        try json.beginArray();
        for (asset.endpoints.items) |endpoint| {
            try json.beginObject();
            try writeJsonTextField(&json, "transport", endpoint.transport);
            try writeJsonField(&json, "port", endpoint.port);
            try writeJsonTextField(&json, "service", endpoint.service);
            try writeJsonTextField(&json, "product", endpoint.product);
            try writeJsonTextField(&json, "version", endpoint.version);
            try writeJsonTextField(&json, "confidence", @tagName(endpoint.confidence));
            try json.objectField("version_confidence");
            if (endpoint.version_confidence) |confidence| {
                try json.write(@tagName(confidence));
            } else {
                try json.write(null);
            }
            try json.objectField("sources");
            try json.beginArray();
            for (endpoint.sources.items) |source| try writeJsonText(&json, source);
            try json.endArray();
            try json.objectField("version_sources");
            try json.beginArray();
            for (endpoint.version_sources.items) |source| try writeJsonText(&json, source);
            try json.endArray();
            try json.endObject();
        }
        try json.endArray();
        try json.objectField("sources");
        try json.beginArray();
        for (asset.sources.items) |source| try writeJsonText(&json, source);
        try json.endArray();
        try json.endObject();
    }
    try json.endArray();

    try json.objectField("issues");
    try json.beginArray();
    for (project.issues.items) |issue| {
        try json.beginObject();
        try writeJsonTextField(&json, "path", issue.path);
        try writeJsonTextField(&json, "message", issue.message);
        try json.endObject();
    }
    try json.endArray();
    try json.endObject();
    try writer.writeByte('\n');
}

fn writeJsonAnalysis(
    json: *std.json.Stringify,
    analysis: *const PocketRoot.services.workbench.Analysis,
) !void {
    const digest = analysis.artifact.digestHex();
    try json.beginObject();
    try json.objectField("protocol");
    try json.beginObject();
    try writeJsonTextField(json, "id", analysis.protocol.id);
    try writeJsonTextField(json, "name", analysis.protocol.name);
    try writeJsonTextField(json, "category", analysis.protocol.category);
    try json.endObject();

    try json.objectField("artifact");
    try json.beginObject();
    try writeJsonTextField(json, "path", analysis.artifact.path);
    try writeJsonTextField(json, "media_type", analysis.artifact.media_type);
    try writeJsonTextField(json, "source", @tagName(analysis.artifact.source));
    try writeJsonField(json, "size", analysis.artifact.size);
    try writeJsonTextField(json, "sha256", digest[0..]);
    try writeJsonField(json, "created_at_unix", analysis.artifact.created_at_unix);
    try json.endObject();

    try json.objectField("result");
    try json.beginObject();
    try writeJsonTextField(json, "summary", analysis.result.summary);
    try json.objectField("fields");
    try json.beginArray();
    for (analysis.result.fields.items) |field| {
        try json.beginObject();
        try writeJsonTextField(json, "name", field.name);
        try writeJsonTextField(json, "value", field.value);
        try json.endObject();
    }
    try json.endArray();

    try json.objectField("findings");
    try json.beginArray();
    for (analysis.result.findings.items) |finding| {
        try json.beginObject();
        try writeJsonTextField(json, "severity", @tagName(finding.severity));
        try writeJsonTextField(json, "message", finding.message);
        try writeJsonTextField(json, "detail", finding.detail);
        try writeJsonTextField(json, "target", finding.target);
        try writeJsonTextField(json, "source_id", finding.source_id);
        try json.endObject();
    }
    try json.endArray();

    try json.objectField("observations");
    try json.beginArray();
    for (analysis.result.observations.items) |observation| {
        try json.beginObject();
        try writeJsonTextField(json, "kind", @tagName(observation.kind));
        try writeJsonTextField(json, "confidence", @tagName(observation.confidence));
        try writeJsonTextField(json, "address", observation.address);
        try writeJsonTextField(json, "hostname", observation.hostname);
        try writeJsonTextField(json, "transport", observation.transport);
        try writeJsonField(json, "port", observation.port);
        try writeJsonTextField(json, "service", observation.service);
        try writeJsonTextField(json, "version", observation.version);
        try writeJsonTextField(json, "evidence", observation.evidence);
        try writeJsonTextField(json, "source_id", observation.source_id);
        try json.endObject();
    }
    try json.endArray();
    try json.endObject();
    try json.endObject();
}

fn writeJsonField(json: *std.json.Stringify, name: []const u8, value: anytype) !void {
    try json.objectField(name);
    try json.write(value);
}

fn writeJsonTextField(json: *std.json.Stringify, name: []const u8, value: []const u8) !void {
    try json.objectField(name);
    try writeJsonText(json, value);
}

fn writeJsonText(json: *std.json.Stringify, value: []const u8) !void {
    if (std.unicode.utf8ValidateSlice(value)) {
        try json.write(value);
        return;
    }

    try json.beginWriteRaw();
    try json.writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try json.writer.writeAll("\\\""),
        '\\' => try json.writer.writeAll("\\\\"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try json.writer.writeByte(byte),
        else => try json.writer.print("\\\\x{x:0>2}", .{byte}),
    };
    try json.writer.writeByte('"');
    json.endWriteRaw();
}

fn printMarkdownReport(
    writer: *Io.Writer,
    analysis: *const PocketRoot.services.workbench.Analysis,
) !void {
    const digest = analysis.artifact.digestHex();
    try writer.print("# PocketRoot Analysis Report\n\n", .{});
    try writer.print("- Protocol: `{s}`\n", .{analysis.protocol.id});
    try writer.print("- Source: ", .{});
    try printMarkdownEscaped(writer, analysis.artifact.path);
    try writer.print("\n- Size: {d} bytes\n- SHA-256: `{s}`\n\n", .{
        analysis.artifact.size,
        digest[0..],
    });

    try writer.print("## Summary\n\n", .{});
    try printMarkdownEscaped(writer, analysis.result.summary);
    try writer.print("\n\n", .{});

    if (analysis.result.fields.items.len > 0) {
        try writer.print("## Fields\n\n", .{});
        for (analysis.result.fields.items) |field| {
            try writer.print("- ", .{});
            try printMarkdownEscaped(writer, field.name);
            try writer.print(": ", .{});
            try printMarkdownEscaped(writer, field.value);
            try writer.print("\n", .{});
        }
        try writer.print("\n", .{});
    }

    if (analysis.result.observations.items.len > 0) {
        try writer.print("## Network Observations\n\n", .{});
        for (analysis.result.observations.items) |observation| {
            try printMarkdownObservation(writer, observation, null, null);
        }
    }

    try writer.print("## Findings\n\n", .{});
    if (analysis.result.findings.items.len == 0) {
        try writer.print("No findings.\n", .{});
        return;
    }

    for (analysis.result.findings.items) |finding| {
        try printMarkdownFinding(writer, finding, null, null);
    }
}

fn printProjectReport(writer: *Io.Writer, project: *const PocketRoot.Project) !void {
    var asset_graph = try PocketRoot.AssetGraph.build(project.allocator, project.analyses.items);
    defer asset_graph.deinit();
    try writer.print("# PocketRoot Project Report\n\n", .{});
    try writer.print("## Summary\n\n", .{});
    try writer.print("- Unique artifacts: {d}\n", .{project.analyses.items.len});
    try writer.print("- Duplicate artifacts: {d}\n", .{project.duplicate_artifacts});
    try writer.print("- Unique findings: {d}\n", .{project.uniqueFindingCount()});
    try writer.print("- Duplicate findings: {d}\n", .{project.duplicateFindingCount()});
    try writer.print("- Unique network observations: {d}\n", .{project.uniqueObservationCount()});
    try writer.print("- Duplicate network observations: {d}\n", .{project.duplicateObservationCount()});
    try writer.print("- Assets: {d}\n", .{asset_graph.assets.items.len});
    try writer.print("- Skipped files: {d}\n", .{project.skipped_files});
    try writer.print("- Import issues: {d}\n\n", .{project.issues.items.len});

    try writer.print("## Severity\n\n", .{});
    inline for (.{
        PocketRoot.FindingSeverity.critical,
        PocketRoot.FindingSeverity.high,
        PocketRoot.FindingSeverity.medium,
        PocketRoot.FindingSeverity.low,
        PocketRoot.FindingSeverity.info,
        PocketRoot.FindingSeverity.warning,
        PocketRoot.FindingSeverity.@"error",
        PocketRoot.FindingSeverity.unknown,
    }) |severity| {
        try writer.print("- {s}: {d}\n", .{ @tagName(severity), project.countSeverity(severity) });
    }

    try writer.print("\n## Artifacts\n\n", .{});
    if (project.analyses.items.len == 0) {
        try writer.print("No artifacts imported.\n\n", .{});
    } else {
        for (project.analyses.items) |analysis| {
            const digest = analysis.artifact.digestHex();
            try writer.print("### {s}: ", .{analysis.protocol.id});
            try printMarkdownEscaped(writer, analysis.artifact.path);
            try writer.print("\n\n- Size: {d} bytes\n- SHA-256: `{s}`\n\n", .{
                analysis.artifact.size,
                digest[0..],
            });
            try printMarkdownEscaped(writer, analysis.result.summary);
            try writer.print("\n\n", .{});
        }
    }

    try writer.print("## Assets\n\n", .{});
    if (asset_graph.assets.items.len == 0) {
        try writer.print("No assets.\n\n", .{});
    } else {
        for (asset_graph.assets.items) |asset| {
            try writer.print("### ", .{});
            try printMarkdownEscaped(writer, asset.preferredName());
            try writer.print("\n\n- Confidence: `{s}`\n", .{@tagName(asset.confidence)});
            for (asset.identities.items) |identity| {
                try writer.print("- {s}: ", .{@tagName(identity.kind)});
                try printMarkdownEscaped(writer, identity.value);
                try writer.print(" (`{s}`", .{@tagName(identity.confidence)});
                if (identity.sources.items.len != 0) {
                    try writer.print("; sources: ", .{});
                    for (identity.sources.items, 0..) |source, index| {
                        if (index != 0) try writer.print(", ", .{});
                        try printMarkdownEscaped(writer, source);
                    }
                }
                try writer.print(")\n", .{});
            }
            for (asset.endpoints.items) |endpoint| {
                try writer.print("- Endpoint: ", .{});
                if (endpoint.transport.len != 0) {
                    try printMarkdownEscaped(writer, endpoint.transport);
                } else {
                    try writer.print("unknown", .{});
                }
                if (endpoint.port) |port| try writer.print("/{d}", .{port});
                if (endpoint.service.len != 0) {
                    try writer.print(" ", .{});
                    try printMarkdownEscaped(writer, endpoint.service);
                }
                if (endpoint.product.len != 0) {
                    try writer.print(" ", .{});
                    try printMarkdownEscaped(writer, endpoint.product);
                }
                if (endpoint.version.len != 0) {
                    try writer.print(" ", .{});
                    try printMarkdownEscaped(writer, endpoint.version);
                }
                try writer.print(" (endpoint: `{s}`", .{@tagName(endpoint.confidence)});
                if (endpoint.version.len != 0) {
                    if (endpoint.version_confidence) |confidence| {
                        try writer.print(", version: `{s}`", .{@tagName(confidence)});
                    } else {
                        try writer.print(", version: `unknown`", .{});
                    }
                    if (endpoint.version_sources.items.len != 0) {
                        try writer.print("; version sources: ", .{});
                        for (endpoint.version_sources.items, 0..) |source, index| {
                            if (index != 0) try writer.print(", ", .{});
                            try printMarkdownEscaped(writer, source);
                        }
                    }
                }
                try writer.print(")\n", .{});
            }
            if (asset.sources.items.len != 0) {
                try writer.print("- Sources: ", .{});
                for (asset.sources.items, 0..) |source, index| {
                    if (index != 0) try writer.print(", ", .{});
                    try printMarkdownEscaped(writer, source);
                }
                try writer.writeByte('\n');
            }
            try writer.writeByte('\n');
        }
    }

    try writer.print("## Network Observations\n\n", .{});
    if (project.uniqueObservationCount() == 0) {
        try writer.print("No network observations.\n\n", .{});
    } else {
        for (project.analyses.items, 0..) |analysis, analysis_index| {
            for (analysis.result.observations.items, 0..) |observation, observation_index| {
                if (!project.observationIsFirst(analysis_index, observation_index)) continue;
                try printMarkdownObservation(
                    writer,
                    observation,
                    analysis.artifact.path,
                    analysis.protocol.id,
                );
            }
        }
    }

    try writer.print("## Findings\n\n", .{});
    if (project.uniqueFindingCount() == 0) {
        try writer.print("No findings.\n\n", .{});
    } else {
        for (project.analyses.items, 0..) |analysis, analysis_index| {
            for (analysis.result.findings.items, 0..) |finding, finding_index| {
                if (!project.findingIsFirst(analysis_index, finding_index)) continue;
                try printMarkdownFinding(
                    writer,
                    finding,
                    analysis.artifact.path,
                    analysis.protocol.id,
                );
            }
        }
    }

    try writer.print("## Import Issues\n\n", .{});
    if (project.issues.items.len == 0) {
        try writer.print("No import issues.\n", .{});
    } else {
        for (project.issues.items) |issue| {
            try writer.print("- ", .{});
            try printMarkdownEscaped(writer, issue.path);
            try writer.print(": ", .{});
            try printMarkdownEscaped(writer, issue.message);
            try writer.print("\n", .{});
        }
    }
}

fn printMarkdownFinding(
    writer: *Io.Writer,
    finding: PocketRoot.Finding,
    artifact_path: ?[]const u8,
    protocol_id: ?[]const u8,
) !void {
    try writer.print("### {s}: ", .{@tagName(finding.severity)});
    try printMarkdownEscaped(writer, finding.message);
    try writer.print("\n\n", .{});
    if (artifact_path) |path| {
        try writer.print("- Artifact: ", .{});
        try printMarkdownEscaped(writer, path);
        try writer.print("\n", .{});
    }
    if (protocol_id) |id| try writer.print("- Protocol: `{s}`\n", .{id});
    if (finding.target.len > 0) {
        try writer.print("- Target: ", .{});
        try printMarkdownEscaped(writer, finding.target);
        try writer.print("\n", .{});
    }
    if (finding.source_id.len > 0) {
        try writer.print("- Source ID: ", .{});
        try printMarkdownEscaped(writer, finding.source_id);
        try writer.print("\n", .{});
    }
    if (finding.detail.len > 0) {
        try writer.print("\n", .{});
        try printMarkdownEscaped(writer, finding.detail);
        try writer.print("\n", .{});
    }
    try writer.print("\n", .{});
}

fn printMarkdownObservation(
    writer: *Io.Writer,
    observation: PocketRoot.NetworkObservation,
    artifact_path: ?[]const u8,
    protocol_id: ?[]const u8,
) !void {
    try writer.print("### {s} ({s})\n\n", .{ @tagName(observation.kind), @tagName(observation.confidence) });
    if (artifact_path) |path| {
        try writer.print("- Artifact: ", .{});
        try printMarkdownEscaped(writer, path);
        try writer.print("\n", .{});
    }
    if (protocol_id) |id| try writer.print("- Protocol: `{s}`\n", .{id});
    if (observation.address.len > 0) {
        try writer.print("- Address: ", .{});
        try printMarkdownEscaped(writer, observation.address);
        try writer.print("\n", .{});
    }
    if (observation.hostname.len > 0) {
        try writer.print("- Hostname: ", .{});
        try printMarkdownEscaped(writer, observation.hostname);
        try writer.print("\n", .{});
    }
    if (observation.transport.len > 0) {
        try writer.print("- Transport: ", .{});
        try printMarkdownEscaped(writer, observation.transport);
        try writer.print("\n", .{});
    }
    if (observation.port) |port| try writer.print("- Port: {d}\n", .{port});
    if (observation.service.len > 0) {
        try writer.print("- Service: ", .{});
        try printMarkdownEscaped(writer, observation.service);
        try writer.print("\n", .{});
    }
    if (observation.version.len > 0) {
        try writer.print("- Version: ", .{});
        try printMarkdownEscaped(writer, observation.version);
        try writer.print("\n", .{});
    }
    if (observation.source_id.len > 0) {
        try writer.print("- Source ID: ", .{});
        try printMarkdownEscaped(writer, observation.source_id);
        try writer.print("\n", .{});
    }
    if (observation.evidence.len > 0) {
        try writer.print("- Evidence: ", .{});
        try printMarkdownEscaped(writer, observation.evidence);
        try writer.print("\n", .{});
    }
    try writer.print("\n", .{});
}

fn printMarkdownEscaped(writer: *Io.Writer, value: []const u8) !void {
    for (value) |byte| {
        switch (byte) {
            '\r' => {},
            '\n' => try writer.print(" ", .{}),
            '\t' => try writer.print("\\t", .{}),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => try writer.print("\\x{x:0>2}", .{byte}),
            '\\', '`', '*', '_', '[', ']', '<', '>', '#', '|' => try writer.print("\\{c}", .{byte}),
            else => try writer.print("{c}", .{byte}),
        }
    }
}

fn parseProjectInputs(
    allocator: std.mem.Allocator,
    raw: []const [:0]const u8,
) ![]ProjectInput {
    if (raw.len == 0) return error.MissingProjectInput;

    var inputs: std.ArrayList(ProjectInput) = .empty;
    errdefer inputs.deinit(allocator);
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--protocol")) {
            if (index + 2 >= raw.len) return error.InvalidProjectInput;
            if (inputs.items.len == max_project_inputs) return error.TooManyProjectInputs;
            try inputs.append(allocator, .{
                .protocol_id = raw[index + 1],
                .path = raw[index + 2],
            });
            index += 3;
        } else {
            if (std.mem.startsWith(u8, raw[index], "--")) return error.InvalidProjectInput;
            if (inputs.items.len == max_project_inputs) return error.TooManyProjectInputs;
            try inputs.append(allocator, .{
                .protocol_id = null,
                .path = raw[index],
            });
            index += 1;
        }
    }
    return inputs.toOwnedSlice(allocator);
}

fn parseAnalyzeArgs(raw: []const [:0]const u8, allow_json: bool) !AnalyzeRequest {
    var protocol_id: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var json_output = false;
    var base_address: ?u32 = null;
    var architecture: ?[]const u8 = null;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--json")) {
            if (!allow_json or json_output) return error.InvalidAnalyzeArgs;
            json_output = true;
            index += 1;
        } else if (std.mem.eql(u8, raw[index], "--protocol")) {
            if (protocol_id != null or index + 1 >= raw.len) return error.InvalidAnalyzeArgs;
            protocol_id = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--base")) {
            if (base_address != null or index + 1 >= raw.len) return error.InvalidAnalyzeArgs;
            const text = raw[index + 1];
            const digits = if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X")) text[2..] else text;
            base_address = std.fmt.parseInt(u32, digits, 16) catch return error.InvalidAnalyzeArgs;
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--arch")) {
            if (architecture != null or index + 1 >= raw.len) return error.InvalidAnalyzeArgs;
            architecture = raw[index + 1];
            index += 2;
        } else {
            if (std.mem.startsWith(u8, raw[index], "--") or path != null) return error.InvalidAnalyzeArgs;
            path = raw[index];
            index += 1;
        }
    }
    return .{
        .protocol_id = protocol_id,
        .path = path orelse return error.InvalidAnalyzeArgs,
        .json_output = json_output,
        .base_address = base_address orelse 0,
        .architecture = architecture,
    };
}

fn hasExplicitProjectInput(inputs: []const ProjectInput, path: []const u8) bool {
    for (inputs) |input| {
        if (input.protocol_id != null and pathsEqual(input.path, path)) return true;
    }
    return false;
}

fn pathsEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_byte, right_byte| {
        const normalized_left = if (left_byte == '\\') '/' else left_byte;
        const normalized_right = if (right_byte == '\\') '/' else right_byte;
        if (builtin.os.tag == .windows) {
            if (std.ascii.toLower(normalized_left) != std.ascii.toLower(normalized_right)) return false;
        } else if (normalized_left != normalized_right) return false;
    }
    return true;
}

fn parsePortList(allocator: std.mem.Allocator, text: []const u8, max_ports: usize) ![]u16 {
    if (max_ports == 0) return error.TooManyPorts;
    var ports: std.ArrayList(u16) = .empty;
    errdefer ports.deinit(allocator);

    var tokens = std.mem.splitScalar(u8, text, ',');
    while (tokens.next()) |raw_token| {
        const token = std.mem.trim(u8, raw_token, " \t");
        if (token.len == 0) return error.InvalidPortList;

        const dash = std.mem.findScalar(u8, token, '-');
        const first = std.fmt.parseInt(u16, if (dash) |index| token[0..index] else token, 10) catch return error.InvalidPortList;
        const last = if (dash) |index|
            std.fmt.parseInt(u16, token[index + 1 ..], 10) catch return error.InvalidPortList
        else
            first;
        if (first == 0 or last < first) return error.InvalidPortList;

        var port: u32 = first;
        while (port <= last) : (port += 1) {
            const candidate: u16 = @intCast(port);
            var duplicate = false;
            for (ports.items) |existing| {
                if (existing == candidate) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            if (ports.items.len == max_ports) return error.TooManyPorts;
            try ports.append(allocator, candidate);
        }
    }
    if (ports.items.len == 0) return error.InvalidPortList;
    return ports.toOwnedSlice(allocator);
}

fn appArgs(allocator: std.mem.Allocator, raw: []const [:0]const u8) ![]const []const u8 {
    const converted = try allocator.alloc([]const u8, raw.len);
    for (raw, converted) |source, *dest| {
        dest.* = source;
    }
    return converted;
}

fn printApps(writer: *Io.Writer, apps: []const PocketRoot.AppDescriptor) !void {
    try writer.print("apps:\n", .{});
    for (apps) |descriptor| {
        try writer.print("  {s}\t{s}\t{s}\n", .{
            descriptor.id,
            descriptor.category,
            descriptor.name,
        });
    }
}

fn printEvents(writer: *Io.Writer, events: []const PocketRoot.Event) !void {
    try writer.print("events:\n", .{});
    for (events) |event| {
        try writer.print("  {s}: ", .{@tagName(event.kind)});
        try printTerminalText(writer, event.topic);
        try writer.writeByte(' ');
        try printTerminalText(writer, event.payload);
        try writer.writeByte('\n');
    }
}

fn printNotifications(writer: *Io.Writer, notifications: []const PocketRoot.services.notification.Notification) !void {
    try writer.print("notifications:\n", .{});
    for (notifications) |notification| {
        try writer.print("  {s}: ", .{@tagName(notification.level)});
        try printTerminalText(writer, notification.topic);
        try writer.writeByte(' ');
        try printTerminalText(writer, notification.message);
        try writer.writeByte('\n');
    }
}

test "project inputs support automatic and explicit protocols" {
    const raw = [_][:0]const u8{
        "samples",
        "--protocol",
        "nmap",
        "scan.xml",
        "capture.ir",
    };
    const inputs = try parseProjectInputs(std.testing.allocator, &raw);
    defer std.testing.allocator.free(inputs);

    try std.testing.expectEqual(@as(usize, 3), inputs.len);
    try std.testing.expect(inputs[0].protocol_id == null);
    try std.testing.expectEqualStrings("samples", inputs[0].path);
    try std.testing.expectEqualStrings("nmap", inputs[1].protocol_id.?);
    try std.testing.expectEqualStrings("scan.xml", inputs[1].path);
    try std.testing.expect(inputs[2].protocol_id == null);
    try std.testing.expectEqualStrings("capture.ir", inputs[2].path);
}

test "project inputs reject incomplete options" {
    const empty = [_][:0]const u8{};
    try std.testing.expectError(
        error.MissingProjectInput,
        parseProjectInputs(std.testing.allocator, &empty),
    );

    const incomplete = [_][:0]const u8{ "--protocol", "nmap" };
    try std.testing.expectError(
        error.InvalidProjectInput,
        parseProjectInputs(std.testing.allocator, &incomplete),
    );

    const too_many = [_][:0]const u8{"sample.ir"} ** (max_project_inputs + 1);
    try std.testing.expectError(
        error.TooManyProjectInputs,
        parseProjectInputs(std.testing.allocator, &too_many),
    );
}

test "analysis options support JSON without changing report behavior" {
    const json_raw = [_][:0]const u8{ "--protocol", "nmap", "--json", "scan.xml" };
    const request = try parseAnalyzeArgs(&json_raw, true);
    try std.testing.expectEqualStrings("nmap", request.protocol_id.?);
    try std.testing.expectEqualStrings("scan.xml", request.path);
    try std.testing.expect(request.json_output);

    try std.testing.expectError(error.InvalidAnalyzeArgs, parseAnalyzeArgs(&json_raw, false));
}

test "explicit project paths match archive separator style" {
    const inputs = [_]ProjectInput{.{
        .protocol_id = "nmap",
        .path = "samples\\network\\scan.xml",
    }};
    try std.testing.expect(hasExplicitProjectInput(&inputs, "samples/network/scan.xml"));
    try std.testing.expect(!hasExplicitProjectInput(&inputs, "samples/network/other.xml"));
}

test "terminal and Markdown renderers escape control bytes" {
    var terminal_buffer: [128]u8 = undefined;
    var terminal: Io.Writer = .fixed(&terminal_buffer);
    try printTerminalText(&terminal, "safe\x1b[31m\n");
    try std.testing.expectEqualStrings("safe\\x1b[31m\\x0a", terminal.buffered());
    try std.testing.expect(std.mem.indexOfScalar(u8, terminal.buffered(), 0x1b) == null);

    var markdown_buffer: [128]u8 = undefined;
    var markdown: Io.Writer = .fixed(&markdown_buffer);
    try printMarkdownEscaped(&markdown, "safe\x1b[31m");
    try std.testing.expectEqualStrings("safe\\x1b\\[31m", markdown.buffered());
    try std.testing.expect(std.mem.indexOfScalar(u8, markdown.buffered(), 0x1b) == null);
}

test "JSON output follows the stable analysis and project schemas" {
    var storage = PocketRoot.StorageService.init(std.testing.io);
    const registry = PocketRoot.ProtocolRegistry.init(PocketRoot.protocols.registry.builtinProtocols());
    var workbench = PocketRoot.ProtocolWorkbench.init(std.testing.allocator, &storage, &registry);
    const sample = try PocketRoot.protocols.infrared.sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);
    var analysis = try workbench.analyzeBytes(registry.find("infrared").?, "sample.ir", sample);
    defer analysis.deinit();

    var analysis_buffer: [16 * 1024]u8 = undefined;
    var analysis_writer: Io.Writer = .fixed(&analysis_buffer);
    try printJsonAnalysis(&analysis_writer, &analysis);
    var parsed_analysis = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, analysis_writer.buffered(), .{});
    defer parsed_analysis.deinit();
    const analysis_root = parsed_analysis.value.object;
    try std.testing.expectEqualStrings("pocketroot.analysis.v1", analysis_root.get("schema").?.string);
    try std.testing.expectEqualStrings(
        "infrared",
        analysis_root.get("analysis").?.object.get("protocol").?.object.get("id").?.string,
    );

    var project = PocketRoot.Project.init(std.testing.allocator);
    defer project.deinit();
    var project_analysis = try workbench.analyzeBytes(registry.find("infrared").?, "asset.ir", sample);
    _ = try project_analysis.result.addNetworkObservation(.{
        .kind = .service,
        .confidence = .confirmed,
        .address = "192.0.2.40",
        .hostname = "asset.local",
        .transport = "tcp",
        .port = 443,
        .service = "https",
        .source_id = "test:asset",
    });
    _ = try project.addAnalysis(project_analysis);
    var project_buffer: [4096]u8 = undefined;
    var project_writer: Io.Writer = .fixed(&project_buffer);
    try printJsonProject(&project_writer, &project);
    var parsed_project = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, project_writer.buffered(), .{});
    defer parsed_project.deinit();
    try std.testing.expectEqualStrings(
        "pocketroot.project.v1",
        parsed_project.value.object.get("schema").?.string,
    );
    try std.testing.expectEqual(@as(usize, 1), parsed_project.value.object.get("assets").?.array.items.len);

    var invalid_buffer: [128]u8 = undefined;
    var invalid_writer: Io.Writer = .fixed(&invalid_buffer);
    var invalid_json: std.json.Stringify = .{ .writer = &invalid_writer };
    try invalid_json.beginObject();
    try writeJsonTextField(&invalid_json, "value", "bad\xff");
    try invalid_json.endObject();
    var parsed_invalid = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, invalid_writer.buffered(), .{});
    defer parsed_invalid.deinit();
    try std.testing.expectEqualStrings("bad\\xff", parsed_invalid.value.object.get("value").?.string);
}

test "builtin registry contains infrared" {
    var runtime = PocketRoot.simulator.Runtime.init(
        std.testing.allocator,
        std.testing.io,
        PocketRoot.apps.builtinApps(),
        PocketRoot.protocols.registry.builtinProtocols(),
    );
    defer runtime.deinit();

    try std.testing.expect(runtime.apps.find("infrared") != null);
    try std.testing.expect(runtime.protocols.find("infrared") != null);
}

test "port lists support ranges and remove duplicates" {
    const ports = try parsePortList(std.testing.allocator, "22,80,80,443-445", 5);
    defer std.testing.allocator.free(ports);

    try std.testing.expectEqualSlices(u16, &.{ 22, 80, 443, 444, 445 }, ports);
    try std.testing.expectError(error.InvalidPortList, parsePortList(std.testing.allocator, "0,80", 5));
    try std.testing.expectError(error.InvalidPortList, parsePortList(std.testing.allocator, "90-80", 5));
    try std.testing.expectError(error.TooManyPorts, parsePortList(std.testing.allocator, "22,80", 1));
}

test "script run arguments accept libraries and authorization flags" {
    const raw = [_][:0]const u8{
        "--lib",
        "a.pk,b.pk",
        "--authorize-active",
        "--region",
        "EU",
        "main.pk",
    };
    const request = try parseScriptRunArgs(std.testing.allocator, &raw);
    defer std.testing.allocator.free(request.libs);

    try std.testing.expectEqualStrings("main.pk", request.path);
    try std.testing.expectEqual(@as(usize, 2), request.libs.len);
    try std.testing.expectEqualStrings("a.pk", request.libs[0]);
    try std.testing.expectEqualStrings("b.pk", request.libs[1]);
    try std.testing.expect(request.authorize_active);
    try std.testing.expectEqualStrings("EU", request.region);
}

test "script run arguments reject malformed options" {
    const missing_path = [_][:0]const u8{"--lib"};
    try std.testing.expectError(error.InvalidScriptArgs, parseScriptRunArgs(std.testing.allocator, &missing_path));

    const two_paths = [_][:0]const u8{ "a.pk", "b.pk" };
    try std.testing.expectError(error.InvalidScriptArgs, parseScriptRunArgs(std.testing.allocator, &two_paths));

    const empty_lib = [_][:0]const u8{ "--lib", " , ", "main.pk" };
    try std.testing.expectError(error.InvalidScriptArgs, parseScriptRunArgs(std.testing.allocator, &empty_lib));

    const unknown_flag = [_][:0]const u8{ "--nope", "main.pk" };
    try std.testing.expectError(error.InvalidScriptArgs, parseScriptRunArgs(std.testing.allocator, &unknown_flag));
}

test "script run inlines a library sub-script end to end" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const helper_source =
        \\script "helper" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "capture" do
        \\        sig = rf { payload = "protocol=Princeton" }
        \\        out sig
        \\    end
        \\end
    ;
    const caller_source =
        \\script "caller" do
        \\    use "pack.rf"
        \\    use "script:helper"
        \\    cap rf = subghz.read
        \\    step "decide" do
        \\        run "helper"
        \\        if sig.protocol == "Princeton" then
        \\            rf { payload = "after" }
        \\        else
        \\            emit warning "miss"
        \\        end
        \\    end
        \\end
    ;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "helper.pk", .data = helper_source });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "caller.pk", .data = caller_source });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw = [_][:0]const u8{ "--lib", "helper.pk", "caller.pk" };
    const request = try parseScriptRunArgs(allocator, &raw);

    var buffer: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    const ok = try runScriptCommand(allocator, std.testing.io, tmp.dir, &writer, request);
    try std.testing.expect(ok);

    const output = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "script \"caller\" succeeded") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "script:helper") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "script:caller") != null);
}

test "script run without a library rejects sub-script imports" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const caller_source =
        \\script "caller" do
        \\    use "script:helper"
        \\    step "s" do
        \\        run "helper"
        \\    end
        \\end
    ;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "caller.pk", .data = caller_source });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw = [_][:0]const u8{"caller.pk"};
    const request = try parseScriptRunArgs(allocator, &raw);

    var buffer: [1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    const ok = try runScriptCommand(allocator, std.testing.io, tmp.dir, &writer, request);
    try std.testing.expect(!ok);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "UnknownScript") != null);
}
