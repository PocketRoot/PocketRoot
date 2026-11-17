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

    if (std.mem.eql(u8, args[1], "device")) {
        try runDeviceCommand(arena, init.io, stdout, args[2..]);
        return;
    }

    if (std.mem.eql(u8, args[1], "audit")) {
        try runAuditCommand(arena, init.io, stdout, args[2..]);
        return;
    }

    if (std.mem.eql(u8, args[1], "campaign")) {
        try runCampaignCommand(arena, init.io, stdout, args[2..]);
        return;
    }

    if (std.mem.eql(u8, args[1], "reproduce")) {
        try runReproduceCommand(arena, init.io, stdout, args[2..]);
        return;
    }

    if (std.mem.eql(u8, args[1], "exploit")) {
        if (args.len < 3 or !std.mem.eql(u8, args[2], "run")) {
            try stdout.print("usage: exploit run <record.json> --campaign <dir> [--param k=v]\n", .{});
            return error.InvalidArguments;
        }
        try runExploitCommand(arena, init.io, stdout, args[3..]);
        return;
    }

    if (std.mem.eql(u8, args[1], "chain")) {
        if (args.len < 3) {
            try stdout.print("usage: chain plan|approve|run ...\n", .{});
            return error.InvalidArguments;
        }
        if (std.mem.eql(u8, args[2], "plan")) {
            try runChainPlanCommand(arena, init.io, stdout, args[3..]);
            return;
        }
        if (std.mem.eql(u8, args[2], "approve")) {
            try runChainApproveCommand(arena, init.io, stdout, args[3..]);
            return;
        }
        if (std.mem.eql(u8, args[2], "run")) {
            try runChainRunCommand(arena, init.io, stdout, args[3..]);
            return;
        }
        if (std.mem.eql(u8, args[2], "adaptive")) {
            try runAdaptiveCommand(arena, init.io, stdout, args[3..]);
            return;
        }
        try stdout.print("unknown chain command\n", .{});
        return error.InvalidArguments;
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

const DeviceTransport = enum { stdio, loopback };

const DeviceRequestArgs = struct {
    kind: PocketRoot.core.capability.Kind,
    operation: PocketRoot.core.capability.Operation,
    subject: []const u8 = "host:cli",
    payload: []const u8 = "",
    region: []const u8 = "",
    authorize_active: bool = false,
    allow_active: bool = false,
    audit_path: ?[]const u8 = null,
};

const DeviceServeArgs = struct {
    transport: DeviceTransport = .stdio,
    frames_path: ?[]const u8 = null,
    output_path: ?[]const u8 = null,
    subject: []const u8 = "host:stdio",
    region: []const u8 = "",
    allow_active: bool = false,
    audit_path: ?[]const u8 = null,
};

fn parseDeviceRequest(raw: []const [:0]const u8) !DeviceRequestArgs {
    var parsed = DeviceRequestArgs{ .kind = .infrared, .operation = .read };
    var positionals: [2][]const u8 = undefined;
    var positional_count: usize = 0;
    var index: usize = 0;
    while (index < raw.len) : (index += 1) {
        const argument = raw[index];
        if (std.mem.eql(u8, argument, "--subject")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.subject = raw[index];
        } else if (std.mem.eql(u8, argument, "--payload")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.payload = raw[index];
        } else if (std.mem.eql(u8, argument, "--region")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.region = raw[index];
        } else if (std.mem.eql(u8, argument, "--audit")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.audit_path = raw[index];
        } else if (std.mem.eql(u8, argument, "--authorize-active")) {
            parsed.authorize_active = true;
        } else if (std.mem.eql(u8, argument, "--allow-active")) {
            parsed.allow_active = true;
        } else if (std.mem.startsWith(u8, argument, "--")) {
            return error.InvalidDeviceArgs;
        } else {
            if (positional_count >= 2) return error.InvalidDeviceArgs;
            positionals[positional_count] = argument;
            positional_count += 1;
        }
    }
    if (positional_count != 2) return error.InvalidDeviceArgs;
    parsed.kind = std.meta.stringToEnum(PocketRoot.core.capability.Kind, positionals[0]) orelse {
        return error.InvalidDeviceArgs;
    };
    parsed.operation = std.meta.stringToEnum(PocketRoot.core.capability.Operation, positionals[1]) orelse {
        return error.InvalidDeviceArgs;
    };
    return parsed;
}

fn parseDeviceServe(raw: []const [:0]const u8) !DeviceServeArgs {
    var parsed = DeviceServeArgs{};
    var index: usize = 0;
    while (index < raw.len) : (index += 1) {
        const argument = raw[index];
        if (std.mem.eql(u8, argument, "--transport")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.transport = std.meta.stringToEnum(DeviceTransport, raw[index]) orelse {
                return error.InvalidDeviceArgs;
            };
        } else if (std.mem.eql(u8, argument, "--frames")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.frames_path = raw[index];
        } else if (std.mem.eql(u8, argument, "--output")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.output_path = raw[index];
        } else if (std.mem.eql(u8, argument, "--subject")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.subject = raw[index];
        } else if (std.mem.eql(u8, argument, "--region")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.region = raw[index];
        } else if (std.mem.eql(u8, argument, "--audit")) {
            index += 1;
            if (index >= raw.len) return error.InvalidDeviceArgs;
            parsed.audit_path = raw[index];
        } else if (std.mem.eql(u8, argument, "--allow-active")) {
            parsed.allow_active = true;
        } else {
            return error.InvalidDeviceArgs;
        }
    }
    if (parsed.transport == .loopback and parsed.frames_path == null) return error.InvalidDeviceArgs;
    if (parsed.transport == .stdio and parsed.frames_path != null) return error.InvalidDeviceArgs;
    return parsed;
}

fn runDeviceCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    if (raw.len == 0) {
        try writer.print("usage: device <info|request|serve> ...\n", .{});
        return error.InvalidArguments;
    }
    if (std.mem.eql(u8, raw[0], "info")) {
        if (raw.len != 1) {
            try writer.print("usage: device info\n", .{});
            return error.InvalidArguments;
        }
        const capability = PocketRoot.core.capability;
        const ipc = PocketRoot.device.ipc;
        try writer.print("device: capability host (PKRT v1 over a caller-supplied transport)\n", .{});
        try writer.print("protocol: {s} v{d} header={d} crc={d} max_payload={d}\n", .{
            ipc.magic,
            ipc.version,
            ipc.header_size,
            ipc.checksum_size,
            ipc.max_payload_bytes,
        });
        try writer.print("kinds: {d}:", .{std.meta.fields(capability.Kind).len});
        inline for (std.meta.fields(capability.Kind)) |field| {
            try writer.print(" {s}", .{field.name});
        }
        try writer.writeByte('\n');
        try writer.print("operations: {d}:", .{std.meta.fields(capability.Operation).len});
        inline for (std.meta.fields(capability.Operation)) |field| {
            try writer.print(" {s}", .{field.name});
        }
        try writer.writeByte('\n');
        try writer.print("default policy: region=\"\" allow_active=no stopped=no\n", .{});
        try writer.print("audit: in-memory {d} entries; export with --audit <path>\n", .{capability.max_audit_entries});
        try writer.print("transports: stdio, loopback (--frames <path>)\n", .{});
        return;
    }
    if (std.mem.eql(u8, raw[0], "request")) {
        const parsed = parseDeviceRequest(raw[1..]) catch {
            try writer.print(
                "usage: device request <kind> <operation> [--subject s] [--payload p] [--region r] [--authorize-active] [--allow-active] [--audit path]\n",
                .{},
            );
            return error.InvalidArguments;
        };
        var host: PocketRoot.DeviceHost = undefined;
        host.init(allocator, io, .{
            .region = parsed.region,
            .allow_active = parsed.allow_active,
            .subject = parsed.subject,
            .audit_path = parsed.audit_path,
        }) catch |err| {
            try writer.print("device host rejected the options: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer host.deinit();

        var result = host.execute(.{
            .id = 1,
            .subject = parsed.subject,
            .kind = parsed.kind,
            .operation = parsed.operation,
            .region = parsed.region,
            .payload = parsed.payload,
            .active_authorized = parsed.authorize_active,
        }) catch |err| {
            try writer.print("status: {s}\n", .{@tagName(host.lastStatus())});
            try writer.print("error: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer result.deinit();
        try writer.print("status: {s}\n", .{@tagName(result.status)});
        try writer.print("data: ", .{});
        try printTerminalText(writer, result.data);
        try writer.writeByte('\n');
        return;
    }
    if (std.mem.eql(u8, raw[0], "serve")) {
        const parsed = parseDeviceServe(raw[1..]) catch {
            try writer.print(
                "usage: device serve [--transport stdio|loopback] [--frames path] [--output path] [--subject s] [--region r] [--allow-active] [--audit path]\n",
                .{},
            );
            return error.InvalidArguments;
        };
        var host: PocketRoot.DeviceHost = undefined;
        host.init(allocator, io, .{
            .region = parsed.region,
            .allow_active = parsed.allow_active,
            .subject = parsed.subject,
            .audit_path = parsed.audit_path,
        }) catch |err| {
            try writer.print("device host rejected the options: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer host.deinit();

        var read_buffer: [64 * 1024]u8 = undefined;
        var file_reader: Io.File.Reader = undefined;
        var frames_file: ?Io.File = null;
        defer if (frames_file) |file| file.close(io);

        if (parsed.transport == .loopback) {
            const path = parsed.frames_path.?;
            const file = Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
                std.debug.print("cannot open frame stream {s}: {s}\n", .{ path, @errorName(err) });
                return error.CommandFailed;
            };
            frames_file = file;
            file_reader = file.reader(io, &read_buffer);
        } else {
            file_reader = Io.File.stdin().reader(io, &read_buffer);
        }

        var output_file: ?Io.File = null;
        defer if (output_file) |file| file.close(io);
        var output_buffer: [4096]u8 = undefined;
        var output_file_writer: Io.File.Writer = undefined;
        var target_writer: *Io.Writer = writer;
        if (parsed.output_path) |path| {
            const file = Io.Dir.cwd().createFile(io, path, .{}) catch |err| {
                std.debug.print("cannot create response stream {s}: {s}\n", .{ path, @errorName(err) });
                return error.CommandFailed;
            };
            output_file = file;
            output_file_writer = .init(file, io, &output_buffer);
            target_writer = &output_file_writer.interface;
        }

        const served = host.serveStream(&file_reader.interface, target_writer, 0) catch |err| {
            std.debug.print("device serve aborted: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        try target_writer.flush();
        std.debug.print("device serve: {d} frame(s)\n", .{served});
        return;
    }
    try writer.print("usage: device <info|request|serve> ...\n", .{});
    return error.InvalidArguments;
}

fn runAuditCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var json_output = false;
    var path: ?[]const u8 = null;
    for (raw) |argument| {
        if (std.mem.eql(u8, argument, "--json")) {
            json_output = true;
        } else if (std.mem.startsWith(u8, argument, "--")) {
            try writer.print("usage: audit [--json] <audit.jsonl>\n", .{});
            return error.InvalidArguments;
        } else {
            if (path != null) {
                try writer.print("usage: audit [--json] <audit.jsonl>\n", .{});
                return error.InvalidArguments;
            }
            path = argument;
        }
    }
    const log_path = path orelse {
        try writer.print("usage: audit [--json] <audit.jsonl>\n", .{});
        return error.InvalidArguments;
    };
    const audit_log = PocketRoot.services.audit_log;
    const data = Io.Dir.cwd().readFileAlloc(io, log_path, allocator, .limited(audit_log.max_file_bytes)) catch |err| {
        try writer.print("cannot load audit log: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    const records = audit_log.parse(allocator, data) catch |err| {
        try writer.print("invalid audit log {s}: {s}\n", .{ log_path, @errorName(err) });
        return error.CommandFailed;
    };
    var summary = audit_log.Summary{};
    for (records) |record| summary.count(record);

    if (json_output) {
        var json: std.json.Stringify = .{
            .writer = writer,
            .options = .{ .whitespace = .indent_2 },
        };
        try json.beginObject();
        try writeJsonTextField(&json, "schema", audit_log.schema);
        try json.objectField("summary");
        try json.beginObject();
        try writeJsonField(&json, "entries", summary.entries);
        try writeJsonField(&json, "succeeded", summary.succeeded);
        try writeJsonField(&json, "denied", summary.denied);
        try writeJsonField(&json, "failed", summary.failed);
        try writeJsonField(&json, "unsupported", summary.unsupported);
        try writeJsonField(&json, "busy", summary.busy);
        try writeJsonField(&json, "cancelled", summary.cancelled);
        try writeJsonField(&json, "active_authorized", summary.active_authorized);
        try writeJsonField(&json, "first_seq", summary.first_seq);
        try writeJsonField(&json, "last_seq", summary.last_seq);
        try writeJsonField(&json, "last_at_unix", summary.last_at_unix);
        try json.endObject();
        try json.objectField("entries");
        try json.beginArray();
        for (records) |record| {
            try json.beginObject();
            try writeJsonField(&json, "seq", record.seq);
            try writeJsonField(&json, "request_id", record.request_id);
            try writeJsonTextField(&json, "subject", record.subject);
            try writeJsonTextField(&json, "kind", record.kind);
            try writeJsonTextField(&json, "operation", record.operation);
            try writeJsonTextField(&json, "status", record.status);
            try writeJsonTextField(&json, "region", record.region);
            try writeJsonField(&json, "active_authorized", record.active_authorized);
            try writeJsonField(&json, "at_unix", record.at_unix);
            try json.endObject();
        }
        try json.endArray();
        try json.endObject();
        try writer.writeByte('\n');
        return;
    }

    try writer.print(
        "audit: {d} entries: succeeded={d} denied={d} failed={d} unsupported={d} busy={d} cancelled={d} active_authorized={d}\n",
        .{
            summary.entries,
            summary.succeeded,
            summary.denied,
            summary.failed,
            summary.unsupported,
            summary.busy,
            summary.cancelled,
            summary.active_authorized,
        },
    );
    const shown = @min(records.len, 100);
    for (records[0..shown]) |record| {
        try writer.print("  seq={d} request={d} subject=", .{ record.seq, record.request_id });
        try printTerminalText(writer, record.subject);
        try writer.print(" {s} {s} {s}", .{ record.kind, record.operation, record.status });
        if (record.region.len > 0) {
            try writer.print(" region=", .{});
            try printTerminalText(writer, record.region);
        }
        if (record.active_authorized) try writer.print(" active_authorized=yes", .{});
        try writer.writeByte('\n');
    }
    if (records.len > shown) try writer.print("  ... {d} more entries\n", .{records.len - shown});
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
        \\  device info          Show the capability host, protocol and audit limits
        \\  device request <kind> <operation> [--subject s] [--payload p] [--region r]
        \\                 [--authorize-active] [--allow-active] [--audit path]
        \\                       Execute one request through the capability kernel
        \\  device serve [--transport stdio|loopback] [--frames path] [--output path]
        \\                 [--subject s] [--region r] [--allow-active] [--audit path]
        \\                       Serve PKRT frames from stdin or a recorded stream
        \\  audit [--json] <path>  Summarize an exported audit log
        \\  campaign init --scope <scope.json> [--dir <dir>]
        \\  campaign arm|stop|status [--dir <dir>]
        \\  campaign surface --catalog <catalog.jsonl> [--json] <path>...
        \\                       Read-only attack surface with candidate actions
        \\  campaign approve <ACTION-ID> --reason <text> --confirm <ACTION-ID>
        \\                       Single-use human approval with the scope's TTL
        \\  campaign approve-repro <record.json> --reason <text> --confirm <CVE>
        \\                       Approve one kind=exploit reproduction record
        \\  campaign run <ACTION-ID> --dry-run
        \\                       Verify the gate and consume the approval
        \\  reproduce <record.json> [--evidence <path>] [--json]
        \\  exploit run <record.json> --campaign <dir> [--param k=v] [--evidence <path>] [--json]
        \\  chain plan --observations <file> [--records <dir>] [--target <t>] [--out <plan.json>]
        \\  chain approve <plan.json> --reason <text> --confirm <CHAIN-ID>
        \\  chain run <plan.json> --campaign <dir> [--evidence <path>]
        \\  chain adaptive <goal.json> --campaign <dir> [--evidence <path>]
        \\  campaign approve-adaptive <goal.json> --reason <text> --confirm <GOAL-ID>
        \\  campaign approve-exploit <record.json> --reason <text> --confirm <CVE> [--param k=v]
        \\                       Run a PocketRoot reproduction record against its target
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
        \\  PocketRoot device request infrared read --payload capture
        \\  PocketRoot device request subghz transmit --authorize-active
        \\  PocketRoot device serve --transport stdio
        \\  PocketRoot audit audit.jsonl
        \\  PocketRoot campaign init --scope samples/campaign/scope.json
        \\  PocketRoot campaign arm
        \\  PocketRoot campaign surface --catalog catalog-v2.jsonl samples/network/lab-repro-hosts.xml
        \\  PocketRoot campaign approve ACTION-1 --reason "ticket SEC-1" --confirm ACTION-1
        \\  PocketRoot campaign run ACTION-1 --dry-run
        \\  PocketRoot campaign stop
        \\  PocketRoot campaign approve-repro samples/reproductions/CVE-2021-41773/record.json --reason "ticket SEC-1" --confirm CVE-2021-41773
        \\  PocketRoot reproduce samples/reproductions/CVE-2021-41773/record.json --campaign .pocketroot --evidence repro.json
        \\  PocketRoot campaign approve-exploit samples/exploits/CVE-2018-7600/record.json --reason "ticket SEC-2" --confirm CVE-2018-7600
        \\  PocketRoot exploit run samples/exploits/CVE-2018-7600/record.json --campaign .pocketroot --param command=id --evidence exploit.json
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
    live: bool = false,
    dump_vars: bool = false,
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
        } else if (std.mem.eql(u8, raw[index], "--dump-vars")) {
            request.dump_vars = true;
            index += 1;
        } else if (std.mem.eql(u8, raw[index], "--live")) {
            request.live = true;
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
    harness.init(allocator, .{ .region = request.region, .allow_active = request.authorize_active }, io);
    defer harness.deinit();
    harness.backend.live = request.live;
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
    if (request.dump_vars) {
        var names: std.ArrayList([]const u8) = .empty;
        defer names.deinit(allocator);
        var iterator = executor.engine.variableIterator();
        while (iterator.next()) |entry| names.append(allocator, entry.key_ptr.*) catch return error.OutOfMemory;
        std.mem.sort([]const u8, names.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);
        try writer.print("variables: {d}\n", .{names.items.len});
        for (names.items) |name| {
            if (executor.engine.variableValue(name)) |value| {
                try writer.print("  {s}={s}\n", .{ name, value });
            }
        }
    }

    const emitted = executor.emitted();
    if (emitted.len > 0) {
        try writer.print("emitted: {d}\n", .{emitted.len});
        for (emitted) |item| {
            try writer.print("  {s} {s}", .{ item.severity, item.message });
            if (item.payload.len > 0) try writer.print(" [tag={s}]", .{item.payload});
            try writer.writeByte('\n');
        }
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
        if (vulnerability.reproducibility != .unclassified) {
            try writer.print(" [{s}]", .{@tagName(vulnerability.reproducibility)});
        }
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

test "device argument parsing accepts requests and rejects unknown flags" {
    const raw = [_][:0]const u8{
        "subghz",
        "transmit",
        "--subject",
        "host:test",
        "--payload",
        "frame",
        "--region",
        "EU",
        "--allow-active",
        "--authorize-active",
    };
    const parsed = try parseDeviceRequest(&raw);
    try std.testing.expectEqual(PocketRoot.core.capability.Kind.subghz, parsed.kind);
    try std.testing.expectEqual(PocketRoot.core.capability.Operation.transmit, parsed.operation);
    try std.testing.expectEqualStrings("host:test", parsed.subject);
    try std.testing.expectEqualStrings("frame", parsed.payload);
    try std.testing.expectEqualStrings("EU", parsed.region);
    try std.testing.expect(parsed.allow_active);
    try std.testing.expect(parsed.authorize_active);

    const unknown_flag = [_][:0]const u8{ "infrared", "read", "--nope" };
    try std.testing.expectError(error.InvalidDeviceArgs, parseDeviceRequest(&unknown_flag));
    const one_positional = [_][:0]const u8{"infrared"};
    try std.testing.expectError(error.InvalidDeviceArgs, parseDeviceRequest(&one_positional));
    const bad_kind = [_][:0]const u8{ "not-a-kind", "read" };
    try std.testing.expectError(error.InvalidDeviceArgs, parseDeviceRequest(&bad_kind));

    const loopback_without_frames = [_][:0]const u8{ "--transport", "loopback" };
    try std.testing.expectError(error.InvalidDeviceArgs, parseDeviceServe(&loopback_without_frames));
    const bad_transport = [_][:0]const u8{ "--transport", "serial" };
    try std.testing.expectError(error.InvalidDeviceArgs, parseDeviceServe(&bad_transport));
}

test "device request writes an audit log that the audit command summarizes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const audit_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/audit.jsonl",
        .{tmp.sub_path[0..]},
    );
    const audit_z = try allocator.dupeZ(u8, audit_path);

    var request_buffer: [4096]u8 = undefined;
    var request_writer: Io.Writer = .fixed(&request_buffer);
    const request_args = [_][:0]const u8{
        "request",
        "infrared",
        "read",
        "--payload",
        "capture",
        "--audit",
        audit_z,
    };
    try runDeviceCommand(allocator, std.testing.io, &request_writer, &request_args);
    const request_output = request_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, request_output, "status: succeeded") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_output, "data: capture") != null);

    var audit_buffer: [8192]u8 = undefined;
    var audit_writer: Io.Writer = .fixed(&audit_buffer);
    const audit_args = [_][:0]const u8{ "--json", audit_z };
    try runAuditCommand(allocator, std.testing.io, &audit_writer, &audit_args);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, audit_writer.buffered(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("pocketroot.audit.v1", root.get("schema").?.string);
    const summary = root.get("summary").?.object;
    try std.testing.expectEqual(@as(i64, 1), summary.get("entries").?.integer);
    try std.testing.expectEqual(@as(i64, 1), summary.get("succeeded").?.integer);
    const entries = root.get("entries").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("infrared", entries[0].object.get("kind").?.string);
}

test "device serve executes a recorded loopback frame stream" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const request = try PocketRoot.device.command.encodeRequest(allocator, 42, .{
        .id = 0,
        .subject = "ignored",
        .kind = .infrared,
        .operation = .read,
        .payload = "capture",
    });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "frames.pkrt", .data = request });

    const frames_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/frames.pkrt",
        .{tmp.sub_path[0..]},
    );
    const frames_z = try allocator.dupeZ(u8, frames_path);

    var output_buffer: [1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&output_buffer);
    const serve_args = [_][:0]const u8{
        "serve",
        "--transport",
        "loopback",
        "--frames",
        frames_z,
    };
    try runDeviceCommand(allocator, std.testing.io, &writer, &serve_args);

    const response = try PocketRoot.device.command.decodeResponse(writer.buffered());
    try std.testing.expectEqual(PocketRoot.core.capability.Status.succeeded, response.status);
    try std.testing.expectEqualStrings("capture", response.data);
}

test "usage lists the device host and audit commands" {
    var buffer: [16 * 1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try printUsage(&writer);
    const usage = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, usage, "device info") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "device request") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "device serve") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "audit [--json]") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "campaign surface") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "campaign approve") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "campaign stop") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "reproduce <record.json>") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "campaign approve-repro") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "exploit run") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "campaign approve-exploit") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "chain plan") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "chain run") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "chain adaptive") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "campaign approve-adaptive") != null);
}

const campaign_default_dir = ".pocketroot";

fn campaignPath(allocator: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ dir, name });
}

fn loadCampaignScope(allocator: std.mem.Allocator, io: Io, dir: []const u8) !PocketRoot.services.control.Scope {
    const path = try campaignPath(allocator, dir, "scope.json");
    defer allocator.free(path);
    const data = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(PocketRoot.services.control.max_json_bytes));
    defer allocator.free(data);
    return PocketRoot.services.control.parseScope(allocator, data);
}

fn campaignNow(io: Io) i64 {
    return std.Io.Timestamp.now(io, .real).toSeconds();
}

fn printCampaignUsage(writer: *Io.Writer) !void {
    try writer.print(
        \\usage: campaign <command> [options]
        \\
        \\  init --scope <scope.json> [--dir <dir>]
        \\  arm [--dir <dir>]
        \\  stop [--dir <dir>]
        \\  status [--json] [--dir <dir>]
        \\  surface --catalog <catalog.jsonl> [--json] <path>... [--protocol <id> <path>]...
        \\  approve <ACTION-ID> --reason <text> --confirm <ACTION-ID> [--operator <name>]
        \\  run <ACTION-ID> --dry-run [--dir <dir>]
        \\
        \\The default campaign directory is .pocketroot. surface is read-only and
        \\needs no approval; approve is a deliberate human action with a configurable
        \\TTL from the scope; stop is checked before every action.
        \\
    , .{});
}

fn runCampaignCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    if (raw.len == 0) {
        try printCampaignUsage(writer);
        return error.InvalidArguments;
    }
    const sub = raw[0];
    if (std.mem.eql(u8, sub, "init")) return runCampaignInit(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "arm")) return runCampaignArm(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "stop")) return runCampaignStop(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "status")) return runCampaignStatus(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "surface")) return runCampaignSurface(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "approve")) return runCampaignApprove(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "approve-repro")) return runCampaignApproveRepro(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "approve-exploit")) return runCampaignApproveExploit(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "approve-adaptive")) return runCampaignApproveAdaptive(allocator, io, writer, raw[1..]);
    if (std.mem.eql(u8, sub, "run")) return runCampaignRun(allocator, io, writer, raw[1..]);
    try writer.print("unknown campaign command: {s}\n", .{sub});
    try printCampaignUsage(writer);
    return error.InvalidArguments;
}

fn runCampaignInit(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var scope_path: ?[]const u8 = null;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir")) {
            if (index + 1 >= raw.len) return error.InvalidArguments;
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--scope")) {
            if (index + 1 >= raw.len or scope_path != null) return error.InvalidArguments;
            scope_path = raw[index + 1];
            index += 2;
        } else return error.InvalidArguments;
    }
    const path = scope_path orelse {
        try writer.print("campaign init requires --scope <scope.json>\n", .{});
        return error.InvalidArguments;
    };
    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(PocketRoot.services.control.max_json_bytes)) catch |err| {
        try writer.print("cannot read scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var scope = PocketRoot.services.control.parseScope(allocator, data) catch |err| {
        try writer.print("invalid scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();

    Io.Dir.cwd().createDirPath(io, dir) catch |err| {
        try writer.print("cannot create campaign directory: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    const approvals = try campaignPath(allocator, dir, "approvals");
    defer allocator.free(approvals);
    try Io.Dir.cwd().createDirPath(io, approvals);
    const scope_copy = try campaignPath(allocator, dir, "scope.json");
    defer allocator.free(scope_copy);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = scope_copy, .data = data });

    var state = try PocketRoot.services.control.State.init(allocator, .disarmed, scope.id);
    defer state.deinit();
    try PocketRoot.services.control.saveState(allocator, io, dir, &state);
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "init",
        .result = scope.id,
        .detail = "campaign initialised disarmed",
    }, campaignNow(io));
    try writer.print(
        "campaign initialised: {s} (scope {s}, ttl {d}s, disarmed)\n",
        .{ dir, scope.id, scope.approval_ttl_seconds },
    );
}

fn runCampaignArm(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else return error.InvalidArguments;
    }
    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    const now = campaignNow(io);
    if (scope.expired(now)) {
        try writer.print("scope has expired\n", .{});
        return error.CommandFailed;
    }
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    try PocketRoot.services.control.clearStop(allocator, io, dir);
    state.phase = .armed;
    try PocketRoot.services.control.saveState(allocator, io, dir, &state);
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "arm",
        .result = scope.id,
        .detail = "campaign armed",
    }, now);
    try writer.print(
        "campaign armed: {s} (ttl {d}s, expires at {d})\n",
        .{ dir, scope.approval_ttl_seconds, scope.expires_at_unix },
    );
}

fn runCampaignStop(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else return error.InvalidArguments;
    }
    const now = campaignNow(io);
    try PocketRoot.services.control.requestStop(allocator, io, dir);
    if (PocketRoot.services.control.loadState(allocator, io, dir)) |loaded| {
        var state = loaded;
        defer state.deinit();
        state.phase = .stopped;
        PocketRoot.services.control.saveState(allocator, io, dir, &state) catch {};
    } else |_| {}
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "stop",
        .result = "stopped",
        .detail = "stop requested; no new action will start",
    }, now);
    try writer.print("campaign stopped: {s} (STOP marker set)\n", .{dir});
}

const ApprovalCounts = struct {
    total: usize = 0,
    unused: usize = 0,
};

fn countApprovals(allocator: std.mem.Allocator, io: Io, dir: []const u8) ApprovalCounts {
    var result = ApprovalCounts{};
    const path = campaignPath(allocator, dir, "approvals") catch return result;
    defer allocator.free(path);
    var approvals_dir = Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch return result;
    defer approvals_dir.close(io);
    var iterator = approvals_dir.iterate();
    while (iterator.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;
        result.total += 1;
        const file_path = campaignPath(allocator, path, entry.name) catch continue;
        defer allocator.free(file_path);
        if (PocketRoot.services.control.loadApproval(allocator, io, file_path)) |loaded| {
            var approval = loaded;
            defer approval.deinit();
            if (!approval.used) result.unused += 1;
        } else |_| {}
    }
    return result;
}

fn runCampaignStatus(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var json_output = false;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--json")) {
            json_output = true;
            index += 1;
        } else return error.InvalidArguments;
    }
    const state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        if (json_output) {
            try writer.print("{{\"schema\":\"pocketroot.campaign-status.v1\",\"initialized\":false}}\n", .{});
        } else {
            try writer.print("campaign not initialised in {s}: {s}\n", .{ dir, @errorName(err) });
        }
        return;
    };
    var loaded_state = state;
    defer loaded_state.deinit();
    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    const approvals = countApprovals(allocator, io, dir);
    const stopped = PocketRoot.services.control.isStopped(allocator, io, dir);
    if (json_output) {
        try writer.print(
            "{{\"schema\":\"pocketroot.campaign-status.v1\",\"initialized\":true,\"phase\":\"{s}\",\"scope_id\":\"{s}\",\"approval_ttl_seconds\":{d},\"expires_at_unix\":{d},\"actions_used\":{d},\"max_actions\":{d},\"stopped\":{s},\"approvals_total\":{d},\"approvals_unused\":{d}}}\n",
            .{
                @tagName(loaded_state.phase),
                scope.id,
                scope.approval_ttl_seconds,
                scope.expires_at_unix,
                loaded_state.actions_used,
                scope.max_actions,
                if (stopped) "true" else "false",
                approvals.total,
                approvals.unused,
            },
        );
        return;
    }
    try writer.print("campaign: {s}\n", .{dir});
    try writer.print("phase: {s}\n", .{@tagName(loaded_state.phase)});
    try writer.print("scope: {s}\n", .{scope.id});
    try writer.print("targets: {d}, techniques: {d}\n", .{ scope.targets.len, scope.techniques.len });
    try writer.print("approval ttl: {d}s, scope expires: {d}\n", .{ scope.approval_ttl_seconds, scope.expires_at_unix });
    try writer.print("actions used: {d}/{d}\n", .{ loaded_state.actions_used, scope.max_actions });
    try writer.print("stop: {s}\n", .{if (stopped) "yes" else "no"});
    try writer.print("approvals: {d} unused / {d} total\n", .{ approvals.unused, approvals.total });
}

fn runCampaignSurface(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var catalog_path: ?[]const u8 = null;
    var json_output = false;
    var inputs_raw: std.ArrayList([:0]const u8) = .empty;
    defer inputs_raw.deinit(allocator);
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--catalog") and index + 1 < raw.len) {
            catalog_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--json")) {
            json_output = true;
            index += 1;
        } else {
            try inputs_raw.append(allocator, raw[index]);
            index += 1;
        }
    }
    const catalog_file = catalog_path orelse {
        try writer.print("campaign surface requires --catalog <catalog.jsonl>\n", .{});
        return error.InvalidArguments;
    };
    const inputs = parseProjectInputs(allocator, inputs_raw.items) catch {
        try printCampaignUsage(writer);
        return error.InvalidArguments;
    };
    defer allocator.free(inputs);

    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    const now = campaignNow(io);
    if (scope.expired(now)) {
        try writer.print("scope has expired\n", .{});
        return error.CommandFailed;
    }

    const catalog_data = Io.Dir.cwd().readFileAlloc(io, catalog_file, allocator, .limited(64 * 1024 * 1024)) catch |err| {
        try writer.print("cannot load vulnerability catalog: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(catalog_data);
    var catalog = PocketRoot.services.vulnerability_catalog.Catalog.load(allocator, catalog_data) catch |err| {
        try writer.print("invalid vulnerability catalog: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer catalog.deinit();

    var runtime = PocketRoot.simulator.Runtime.init(
        allocator,
        io,
        PocketRoot.apps.builtinApps(),
        PocketRoot.protocols.registry.builtinProtocols(),
    );
    defer runtime.deinit();
    var project = PocketRoot.Project.init(allocator);
    defer project.deinit();
    for (inputs) |input| importProjectInput(&runtime, &project, inputs, input) catch |err| {
        try writer.print("cannot import {s}: {s}\n", .{ input.path, @errorName(err) });
        return error.CommandFailed;
    };
    var graph = PocketRoot.AssetGraph.build(allocator, project.analyses.items) catch |err| {
        try writer.print("cannot build asset graph: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer graph.deinit();
    var matches = PocketRoot.services.vulnerability_matcher.match(allocator, &graph, catalog.vulnerabilities, .{}) catch |err| {
        try writer.print("matching failed: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer matches.deinit();

    var report = PocketRoot.services.surface.build(allocator, &graph, catalog.vulnerabilities, &matches, &scope, now) catch |err| {
        try writer.print("cannot build attack surface: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer report.deinit();

    const surface_path = try campaignPath(allocator, dir, "surface.json");
    defer allocator.free(surface_path);
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    try report.writeJson(&output.writer);
    Io.Dir.cwd().writeFile(io, .{ .sub_path = surface_path, .data = output.written() }) catch |err| {
        try writer.print("cannot write surface: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "surface",
        .result = "ok",
        .detail = "read-only attack surface generated",
    }, now);

    if (json_output) {
        try report.writeJson(writer);
    } else {
        try report.writeMarkdown(writer);
        try writer.print("\nsurface written to {s}\n", .{surface_path});
    }
}

fn runCampaignApprove(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var action_id: ?[]const u8 = null;
    var reason: ?[]const u8 = null;
    var confirm: ?[]const u8 = null;
    var operator: []const u8 = "operator";
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--reason") and index + 1 < raw.len) {
            reason = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--confirm") and index + 1 < raw.len) {
            confirm = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--operator") and index + 1 < raw.len) {
            operator = raw[index + 1];
            index += 2;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (action_id != null) return error.InvalidArguments;
            action_id = raw[index];
            index += 1;
        }
    }
    const id = action_id orelse {
        try writer.print("campaign approve requires <ACTION-ID> --reason <text> --confirm <ACTION-ID>\n", .{});
        return error.InvalidArguments;
    };
    const why = reason orelse {
        try writer.print("approval requires --reason (recorded in the ledger)\n", .{});
        return error.InvalidArguments;
    };
    const typed = confirm orelse {
        try writer.print("approval requires --confirm <ACTION-ID>; there is no --yes\n", .{});
        return error.InvalidArguments;
    };
    if (!std.mem.eql(u8, typed, id)) {
        try writer.print("confirmation does not match {s}; nothing approved\n", .{id});
        return error.InvalidArguments;
    }

    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    if (state.phase != .armed) {
        try writer.print("campaign is {s}; run campaign arm first\n", .{@tagName(state.phase)});
        return error.CommandFailed;
    }
    const surface_path = try campaignPath(allocator, dir, "surface.json");
    defer allocator.free(surface_path);
    var stored = PocketRoot.services.surface.load(allocator, io, surface_path) catch |err| {
        try writer.print("cannot load surface: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer stored.deinit();
    const action = stored.find(id) orelse {
        try writer.print("unknown action: {s}\n", .{id});
        return error.CommandFailed;
    };
    if (!std.mem.eql(u8, stored.scope_id, scope.id)) {
        try writer.print("surface belongs to another scope\n", .{});
        return error.CommandFailed;
    }
    if (!std.mem.eql(u8, action.feasibility, "feasible")) {
        try writer.print("action is not feasible ({s}); refusing to approve\n", .{action.feasibility});
        return error.CommandFailed;
    }
    const technique = std.meta.stringToEnum(PocketRoot.services.control.Technique, action.technique) orelse {
        try writer.print("unknown technique: {s}\n", .{action.technique});
        return error.CommandFailed;
    };
    const now = campaignNow(io);
    var approval = PocketRoot.services.control.createApproval(allocator, io, dir, &scope, .{
        .action_id = action.id,
        .target = action.target,
        .technique = technique,
        .params_hash = action.params_hash,
    }, operator, why, now) catch |err| {
        try writer.print("cannot approve {s}: {s}\n", .{ id, @errorName(err) });
        return error.CommandFailed;
    };
    defer approval.deinit();
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "approve",
        .action_id = approval.action_id,
        .approval_id = approval.id,
        .target = approval.target,
        .technique = @tagName(approval.technique),
        .result = "approved",
        .detail = approval.reason,
    }, now);
    try writer.print(
        "approved {s}: {s} on {s} ({s})\napproval {s} expires at {d} (ttl {d}s, single use)\n",
        .{
            approval.action_id,
            action.vulnerability_id,
            approval.target,
            @tagName(approval.technique),
            approval.id,
            approval.expires_at_unix,
            scope.approval_ttl_seconds,
        },
    );
}

fn mapCampaignDenial(err: anyerror) []const u8 {
    return switch (err) {
        error.stopped => "campaign is stopped",
        error.disarmed => "campaign is disarmed",
        error.scope_expired => "scope has expired",
        error.target_not_allowed => "target is outside the scope",
        error.technique_not_allowed => "technique is not allowed by the scope",
        error.approval_missing => "no approval for this action",
        error.approval_invalid => "approval is unreadable",
        error.approval_expired => "approval has expired",
        error.approval_used => "approval was already consumed",
        error.state_scope_mismatch => "campaign state belongs to another scope",
        error.approval_scope_mismatch => "approval belongs to another scope",
        error.approval_action_mismatch => "approval belongs to another action",
        error.approval_target_mismatch => "approval belongs to another target",
        error.approval_params_mismatch => "approval params do not match the action",
        error.approval_technique_mismatch => "approval technique does not match the action",
        error.budget_exhausted => "action budget exhausted",
        else => "approval check failed",
    };
}

fn runCampaignRun(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var action_id: ?[]const u8 = null;
    var dry_run = false;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--dry-run")) {
            dry_run = true;
            index += 1;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (action_id != null) return error.InvalidArguments;
            action_id = raw[index];
            index += 1;
        }
    }
    const id = action_id orelse {
        try writer.print("campaign run requires <ACTION-ID> --dry-run\n", .{});
        return error.InvalidArguments;
    };

    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    const surface_path = try campaignPath(allocator, dir, "surface.json");
    defer allocator.free(surface_path);
    var stored = PocketRoot.services.surface.load(allocator, io, surface_path) catch |err| {
        try writer.print("cannot load surface: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer stored.deinit();
    const action = stored.find(id) orelse {
        try writer.print("unknown action: {s}\n", .{id});
        return error.CommandFailed;
    };
    if (!std.mem.eql(u8, stored.scope_id, scope.id)) {
        try writer.print("surface belongs to another scope\n", .{});
        return error.CommandFailed;
    }
    if (!std.mem.eql(u8, action.feasibility, "feasible")) {
        try writer.print("action is not feasible ({s})\n", .{action.feasibility});
        return error.CommandFailed;
    }
    const technique = std.meta.stringToEnum(PocketRoot.services.control.Technique, action.technique) orelse {
        try writer.print("unknown technique: {s}\n", .{action.technique});
        return error.CommandFailed;
    };
    const request = PocketRoot.services.control.ActionRequest{
        .action_id = action.id,
        .target = action.target,
        .technique = technique,
        .params_hash = action.params_hash,
    };
    const now = campaignNow(io);
    PocketRoot.services.control.evaluate(allocator, io, dir, &scope, &state, request, now) catch |err| {
        try writer.print("denied: {s}\n", .{mapCampaignDenial(err)});
        PocketRoot.services.control.appendLedger(allocator, io, dir, .{
            .event = "denied",
            .action_id = action.id,
            .target = action.target,
            .technique = @tagName(technique),
            .result = @errorName(err),
            .detail = mapCampaignDenial(err),
        }, now) catch {};
        return error.CommandFailed;
    };
    if (!dry_run) {
        try writer.print("no executor is installed; re-run with --dry-run\n", .{});
        PocketRoot.services.control.appendLedger(allocator, io, dir, .{
            .event = "denied",
            .action_id = action.id,
            .target = action.target,
            .technique = @tagName(technique),
            .result = "no-executor",
            .detail = "real execution is not installed in this build",
        }, now) catch {};
        return error.CommandFailed;
    }
    const approval_file = try PocketRoot.services.control.approvalPath(allocator, dir, action.id);
    defer allocator.free(approval_file);
    var approval = PocketRoot.services.control.loadApproval(allocator, io, approval_file) catch |err| {
        try writer.print("cannot load approval: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer approval.deinit();
    PocketRoot.services.control.consumeApproval(allocator, io, approval_file, now) catch |err| {
        try writer.print("cannot consume approval: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "run-start",
        .action_id = action.id,
        .approval_id = approval.id,
        .target = action.target,
        .technique = @tagName(technique),
        .result = "started",
        .detail = action.vulnerability_id,
    }, now);
    try writer.print(
        "dry-run {s}: {s} on {s} ({s})\napproval {s} consumed before the action\nstop: campaign stop (checked before the next action)\n",
        .{ action.id, action.vulnerability_id, action.target, @tagName(technique), approval.id },
    );
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "run-dry",
        .action_id = action.id,
        .approval_id = approval.id,
        .target = action.target,
        .technique = @tagName(technique),
        .result = "dry-run",
        .detail = "no traffic sent",
    }, now);
    if (PocketRoot.services.control.isStopped(allocator, io, dir)) {
        try writer.print("stop marker observed; no further action will start\n", .{});
    }
}

test "campaign surface, approval and stop gate a dry run" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path[0..]});
    defer std.testing.allocator.free(base);
    try Io.Dir.cwd().createDirPath(std.testing.io, base);
    const campaign_dir = try std.fs.path.join(std.testing.allocator, &.{ base, "campaign" });
    defer std.testing.allocator.free(campaign_dir);
    const scope_path = try std.fs.path.join(std.testing.allocator, &.{ base, "scope.json" });
    defer std.testing.allocator.free(scope_path);
    const catalog_path = try std.fs.path.join(std.testing.allocator, &.{ base, "catalog.jsonl" });
    defer std.testing.allocator.free(catalog_path);

    const scope_data =
        \\{"schema":"pocketroot.scope.v1","scope_id":"test-scope","targets":["192.0.2.0/24"],"techniques":["validate","exploit"],"expires_at_unix":4102444800,"approval_ttl_seconds":60,"max_actions":4}
    ;
    try Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = scope_path, .data = scope_data });
    const catalog_data =
        \\{"schema":"pocketroot.vulnerability.v2","id":"CVE-TEST-0001","title":"Apache 2.4.49 test","severity":"critical","cvss_score":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","affected":[{"vendor":"apache","product":"Apache httpd","versions":[{"kind":"dotted_range","introduced":"2.4.0","fixed":"2.4.50"}]}],"reproducibility":{"tier":"container","reason":"network-service"}}
    ;
    try Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = catalog_path, .data = catalog_data });

    const scope_z = try std.testing.allocator.dupeZ(u8, scope_path);
    defer std.testing.allocator.free(scope_z);
    const catalog_z = try std.testing.allocator.dupeZ(u8, catalog_path);
    defer std.testing.allocator.free(catalog_z);
    const dir_z = try std.testing.allocator.dupeZ(u8, campaign_dir);
    defer std.testing.allocator.free(dir_z);

    var buffer: [16 * 1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    var args = [_][:0]const u8{ "init", "--scope", scope_z, "--dir", dir_z };
    try runCampaignCommand(std.testing.allocator, std.testing.io, &writer, &args);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "ttl 60s") != null);

    var buffer_arm: [4096]u8 = undefined;
    var writer_arm: Io.Writer = .fixed(&buffer_arm);
    var arm_args = [_][:0]const u8{ "arm", "--dir", dir_z };
    try runCampaignCommand(std.testing.allocator, std.testing.io, &writer_arm, &arm_args);

    var buffer_surface: [16 * 1024]u8 = undefined;
    var writer_surface: Io.Writer = .fixed(&buffer_surface);
    var surface_args = [_][:0]const u8{
        "surface", "--catalog", catalog_z, "--protocol", "nmap", "--dir", dir_z, "samples/network/lab-repro-hosts.xml",
    };
    try runCampaignCommand(std.testing.allocator, std.testing.io, &writer_surface, &surface_args);
    const surface_output = writer_surface.buffered();
    try std.testing.expect(std.mem.indexOf(u8, surface_output, "feasible: 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, surface_output, "ACTION-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, surface_output, "CVE-TEST-0001") != null);

    var buffer_approve: [4096]u8 = undefined;
    var writer_approve: Io.Writer = .fixed(&buffer_approve);
    var approve_args = [_][:0]const u8{
        "approve", "ACTION-1", "--reason", "ticket SEC-1", "--confirm", "ACTION-1", "--dir", dir_z,
    };
    try runCampaignCommand(std.testing.allocator, std.testing.io, &writer_approve, &approve_args);
    try std.testing.expect(std.mem.indexOf(u8, writer_approve.buffered(), "ttl 60s") != null);

    var buffer_run: [4096]u8 = undefined;
    var writer_run: Io.Writer = .fixed(&buffer_run);
    var run_args = [_][:0]const u8{ "run", "ACTION-1", "--dry-run", "--dir", dir_z };
    try runCampaignCommand(std.testing.allocator, std.testing.io, &writer_run, &run_args);
    const run_output = writer_run.buffered();
    try std.testing.expect(std.mem.indexOf(u8, run_output, "dry-run ACTION-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, run_output, "consumed before the action") != null);

    var buffer_again: [4096]u8 = undefined;
    var writer_again: Io.Writer = .fixed(&buffer_again);
    try std.testing.expectError(error.CommandFailed, runCampaignCommand(
        std.testing.allocator,
        std.testing.io,
        &writer_again,
        &run_args,
    ));
    try std.testing.expect(std.mem.indexOf(u8, writer_again.buffered(), "already consumed") != null);

    var buffer_stop: [4096]u8 = undefined;
    var writer_stop: Io.Writer = .fixed(&buffer_stop);
    var stop_args = [_][:0]const u8{ "stop", "--dir", dir_z };
    try runCampaignCommand(std.testing.allocator, std.testing.io, &writer_stop, &stop_args);

    var buffer_stopped: [4096]u8 = undefined;
    var writer_stopped: Io.Writer = .fixed(&buffer_stopped);
    var run_stopped_args = [_][:0]const u8{ "run", "ACTION-1", "--dry-run", "--dir", dir_z };
    try std.testing.expectError(error.CommandFailed, runCampaignCommand(
        std.testing.allocator,
        std.testing.io,
        &writer_stopped,
        &run_stopped_args,
    ));
    try std.testing.expect(std.mem.indexOf(u8, writer_stopped.buffered(), "stopped") != null);

    const ledger_path = try std.fs.path.join(std.testing.allocator, &.{ campaign_dir, "ledger.jsonl" });
    defer std.testing.allocator.free(ledger_path);
    const ledger = try Io.Dir.cwd().readFileAlloc(std.testing.io, ledger_path, std.testing.allocator, .limited(1024 * 1024));
    defer std.testing.allocator.free(ledger);
    try std.testing.expect(std.mem.indexOf(u8, ledger, "\"event\":\"approve\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, ledger, "\"event\":\"run-dry\"") != null);
}

const ReproductionWire = struct {
    schema: []const u8 = "",
    cve: []const u8 = "",
    class: []const u8 = "",
    oracle: []const u8 = "",
    target: []const u8 = "",
    script: []const u8 = "",
    expected: []const u8 = "",
    kind: []const u8 = "validate",
};

/// Runs a PocketRoot reproduction record: render {{target}}, execute the script live,
/// print the probe output and optionally write a JSON evidence record.
fn runReproduceCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var record_path: ?[]const u8 = null;
    var evidence_path: ?[]const u8 = null;
    var campaign_dir: ?[]const u8 = null;
    var json_output = false;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--campaign") and index + 1 < raw.len) {
            campaign_dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--evidence") and index + 1 < raw.len) {
            evidence_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--json")) {
            json_output = true;
            index += 1;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (record_path != null) return error.InvalidArguments;
            record_path = raw[index];
            index += 1;
        }
    }
    const path = record_path orelse {
        try writer.print("usage: reproduce <record.json> [--evidence <path>] [--json]\n", .{});
        return error.InvalidArguments;
    };

    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024)) catch |err| {
        try writer.print("cannot read reproduction record: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var parsed = std.json.parseFromSlice(ReproductionWire, allocator, data, .{
        .ignore_unknown_fields = true,
    }) catch {
        try writer.print("invalid reproduction record: {s}\n", .{path});
        return error.CommandFailed;
    };
    defer parsed.deinit();
    const record = parsed.value;
    if (!std.mem.eql(u8, record.schema, "pocketroot.reproduction.v1") or
        record.cve.len == 0 or record.target.len == 0 or record.script.len == 0 or record.expected.len == 0)
    {
        try writer.print("reproduction record is missing schema, cve, target, script or expected\n", .{});
        return error.CommandFailed;
    }
    var action_holder: ?ReproAction = null;
    defer if (action_holder) |*value| value.deinit(allocator);
    var approval_holder: ?PocketRoot.services.control.Approval = null;
    defer if (approval_holder) |*value| value.deinit();
    var approval_id: []const u8 = "";

    // Exploitation is not a free-standing command: it must carry a live campaign
    // approval. Validation records remain usable without a campaign.
    if (std.mem.eql(u8, record.kind, "exploit")) {
        const dir = campaign_dir orelse {
            try writer.print("exploit reproduction requires --campaign <dir> and an approval\n", .{});
            return error.CommandFailed;
        };
        var scope = loadCampaignScope(allocator, io, dir) catch |err| {
            try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer scope.deinit();
        var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
            try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        defer state.deinit();
        action_holder = reproAction(allocator, io, path, record) catch |err| {
            try writer.print("cannot bind reproduction: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        const action = action_holder.?;
        const now = campaignNow(io);
        PocketRoot.services.control.evaluate(allocator, io, dir, &scope, &state, .{
            .action_id = action.action_id,
            .target = action.target,
            .technique = .exploit,
            .params_hash = action.params_hash,
        }, now) catch |err| {
            try writer.print("denied: {s}\n", .{mapCampaignDenial(err)});
            PocketRoot.services.control.appendLedger(allocator, io, dir, .{
                .event = "denied",
                .action_id = action.action_id,
                .target = action.target,
                .technique = "exploit",
                .result = @errorName(err),
                .detail = mapCampaignDenial(err),
            }, now) catch {};
            return error.CommandFailed;
        };
        const approval_file = try PocketRoot.services.control.approvalPath(allocator, dir, action.action_id);
        defer allocator.free(approval_file);
        approval_holder = PocketRoot.services.control.loadApproval(allocator, io, approval_file) catch |err| {
            try writer.print("cannot load approval: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        approval_id = approval_holder.?.id;
        PocketRoot.services.control.consumeApproval(allocator, io, approval_file, now) catch |err| {
            try writer.print("cannot consume approval: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
        try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
            .event = "repro-start",
            .action_id = action.action_id,
            .approval_id = approval_id,
            .target = action.target,
            .technique = "exploit",
            .result = "started",
            .detail = record.cve,
        }, now);
    }

    const record_dir = std.fs.path.dirname(path) orelse ".";
    const script_path = try std.fs.path.join(allocator, &.{ record_dir, record.script });
    defer allocator.free(script_path);
    const source = Io.Dir.cwd().readFileAlloc(io, script_path, allocator, .limited(PocketRoot.services.script.max_script_bytes)) catch |err| {
        try writer.print("cannot read reproduction script {s}: {s}\n", .{ script_path, @errorName(err) });
        return error.CommandFailed;
    };
    defer allocator.free(source);
    const rendered = std.mem.replaceOwned(u8, allocator, source, "{{target}}", record.target) catch return error.CommandFailed;
    defer allocator.free(rendered);

    const now = campaignNow(io);
    const temp_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/reproduce-{d}-{s}.pk", .{ now, record.cve });
    defer allocator.free(temp_path);
    Io.Dir.cwd().createDirPath(io, ".zig-cache/tmp") catch {};
    Io.Dir.cwd().writeFile(io, .{ .sub_path = temp_path, .data = rendered }) catch |err| {
        try writer.print("cannot stage reproduction script: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer Io.Dir.cwd().deleteFile(io, temp_path) catch {};

    var capture = std.Io.Writer.Allocating.init(allocator);
    defer capture.deinit();
    const ok = runScriptCommand(allocator, io, Io.Dir.cwd(), &capture.writer, .{
        .path = temp_path,
        .live = true,
    }) catch |err| {
        try writer.print("reproduction aborted: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    try writer.writeAll(capture.written());

    if (std.mem.eql(u8, record.kind, "exploit")) {
        if (campaign_dir) |dir| {
            const ended = campaignNow(io);
            PocketRoot.services.control.appendLedger(allocator, io, dir, .{
                .event = "repro-result",
                .action_id = if (action_holder) |action| action.action_id else "",
                .approval_id = approval_id,
                .target = record.target,
                .technique = "exploit",
                .result = if (ok) "succeeded" else "failed",
                .detail = record.cve,
            }, ended) catch {};
            if (PocketRoot.services.control.isStopped(allocator, io, dir)) {
                try writer.print("stop marker observed; no further reproduction will start\n", .{});
            }
        }
    }

    const observed = if (ok)
        record.expected
    else if (std.mem.eql(u8, record.expected, "vulnerable"))
        "not_vulnerable"
    else if (std.mem.eql(u8, record.expected, "fixed"))
        "not_fixed"
    else
        "unexpected";

    var evidence_buffer = std.Io.Writer.Allocating.init(allocator);
    defer evidence_buffer.deinit();
    const Wire = struct {
        schema: []const u8,
        cve: []const u8,
        class: []const u8,
        oracle: []const u8,
        target: []const u8,
        expected: []const u8,
        observed: []const u8,
        script: []const u8,
        status: []const u8,
        action_id: []const u8,
        approval_id: []const u8,
        recorded_at_unix: i64,
    };
    var json: std.json.Stringify = .{
        .writer = &evidence_buffer.writer,
        .options = .{ .whitespace = .indent_2 },
    };
    json.write(Wire{
        .schema = "pocketroot.reproduction.evidence.v1",
        .cve = record.cve,
        .class = record.class,
        .oracle = record.oracle,
        .target = record.target,
        .expected = record.expected,
        .observed = observed,
        .script = record.script,
        .status = if (ok) "succeeded" else "failed",
        .action_id = if (action_holder) |action| action.action_id else "",
        .approval_id = approval_id,
        .recorded_at_unix = now,
    }) catch return error.CommandFailed;
    try evidence_buffer.writer.writeByte('\n');

    if (evidence_path) |evidence_file| {
        Io.Dir.cwd().writeFile(io, .{ .sub_path = evidence_file, .data = evidence_buffer.written() }) catch |err| {
            try writer.print("cannot write evidence: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
    }
    if (json_output) {
        try writer.writeAll(evidence_buffer.written());
    } else {
        try writer.print("reproduction {s}: {s} (target {s}, expected {s}, observed {s})\n", .{
            record.cve,
            if (ok) "succeeded" else "failed",
            record.target,
            record.expected,
            observed,
        });
    }
    if (!ok) return error.CommandFailed;
}

const ReproAction = struct {
    action_id: []u8,
    target: []const u8,
    params_hash: []u8,

    fn deinit(self: *ReproAction, allocator: std.mem.Allocator) void {
        allocator.free(self.action_id);
        allocator.free(self.params_hash);
        self.* = undefined;
    }
};

/// Binds an exploit reproduction to the exact record, target and script bytes. The same
/// function feeds approve-repro and reproduce, so a changed probe invalidates an approval.
fn reproAction(
    allocator: std.mem.Allocator,
    io: Io,
    record_path: []const u8,
    record: ReproductionWire,
) !ReproAction {
    const record_dir = std.fs.path.dirname(record_path) orelse ".";
    const script_path = try std.fs.path.join(allocator, &.{ record_dir, record.script });
    defer allocator.free(script_path);
    const script = try Io.Dir.cwd().readFileAlloc(io, script_path, allocator, .limited(PocketRoot.services.script.max_script_bytes));
    defer allocator.free(script);
    const canonical = try std.fmt.allocPrint(allocator, "{s}|{s}|{s}", .{ record.cve, record.target, script });
    defer allocator.free(canonical);
    return .{
        .action_id = try std.fmt.allocPrint(allocator, "REPRO-{s}", .{record.cve}),
        .target = record.target,
        .params_hash = try PocketRoot.services.control.sha256Hex(allocator, canonical),
    };
}

fn runCampaignApproveRepro(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var record_path: ?[]const u8 = null;
    var reason: ?[]const u8 = null;
    var confirm: ?[]const u8 = null;
    var operator: []const u8 = "operator";
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--reason") and index + 1 < raw.len) {
            reason = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--confirm") and index + 1 < raw.len) {
            confirm = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--operator") and index + 1 < raw.len) {
            operator = raw[index + 1];
            index += 2;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (record_path != null) return error.InvalidArguments;
            record_path = raw[index];
            index += 1;
        }
    }
    const path = record_path orelse {
        try writer.print("usage: campaign approve-repro <record.json> --reason <text> --confirm <CVE>\n", .{});
        return error.InvalidArguments;
    };
    const why = reason orelse {
        try writer.print("approval requires --reason\n", .{});
        return error.InvalidArguments;
    };
    const typed = confirm orelse {
        try writer.print("approval requires --confirm <CVE>; there is no --yes\n", .{});
        return error.InvalidArguments;
    };

    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024)) catch |err| {
        try writer.print("cannot read reproduction record: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var parsed = std.json.parseFromSlice(ReproductionWire, allocator, data, .{ .ignore_unknown_fields = true }) catch {
        try writer.print("invalid reproduction record: {s}\n", .{path});
        return error.CommandFailed;
    };
    defer parsed.deinit();
    const record = parsed.value;
    if (!std.mem.eql(u8, record.schema, "pocketroot.reproduction.v1") or
        !std.mem.eql(u8, record.kind, "exploit"))
    {
        try writer.print("campaign approve-repro needs a kind=exploit record\n", .{});
        return error.CommandFailed;
    }
    if (!std.mem.eql(u8, typed, record.cve)) {
        try writer.print("confirmation does not match {s}; nothing approved\n", .{record.cve});
        return error.InvalidArguments;
    }

    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    if (state.phase != .armed) {
        try writer.print("campaign is {s}; run campaign arm first\n", .{@tagName(state.phase)});
        return error.CommandFailed;
    }
    var action = reproAction(allocator, io, path, record) catch |err| {
        try writer.print("cannot bind reproduction: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer action.deinit(allocator);
    const now = campaignNow(io);
    var approval = PocketRoot.services.control.createApproval(allocator, io, dir, &scope, .{
        .action_id = action.action_id,
        .target = action.target,
        .technique = .exploit,
        .params_hash = action.params_hash,
    }, operator, why, now) catch |err| {
        try writer.print("cannot approve {s}: {s}\n", .{ action.action_id, @errorName(err) });
        return error.CommandFailed;
    };
    defer approval.deinit();
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "approve",
        .action_id = approval.action_id,
        .approval_id = approval.id,
        .target = approval.target,
        .technique = "exploit",
        .result = "approved",
        .detail = approval.reason,
    }, now);
    try writer.print(
        "approved {s}: {s} on {s}\napproval {s} expires at {d} (ttl {d}s, single use)\n",
        .{ approval.action_id, record.cve, approval.target, approval.id, approval.expires_at_unix, scope.approval_ttl_seconds },
    );
}

const ExploitParams = struct {
    arena: std.heap.ArenaAllocator,
    items: []PocketRoot.services.exploit.Param,

    fn init(allocator: std.mem.Allocator) ExploitParams {
        return .{ .arena = std.heap.ArenaAllocator.init(allocator), .items = &.{} };
    }

    fn deinit(self: *ExploitParams) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn parseExploitParams(
    base: []const PocketRoot.services.exploit.Param,
    raw: []const [:0]const u8,
    allocator: std.mem.Allocator,
) !ExploitParams {
    var result = ExploitParams.init(allocator);
    errdefer result.deinit();
    const a = result.arena.allocator();
    var list: std.ArrayList(PocketRoot.services.exploit.Param) = .empty;
    defer list.deinit(a);
    for (base) |param| try list.append(a, .{
        .name = try a.dupe(u8, param.name),
        .value = try a.dupe(u8, param.value),
    });
    var index: usize = 0;
    while (index < raw.len) {
        if (!std.mem.startsWith(u8, raw[index], "--param")) {
            index += 1;
            continue;
        }
        if (index + 1 >= raw.len) return error.InvalidArguments;
        const pair = raw[index + 1];
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse return error.InvalidArguments;
        const name = pair[0..equals];
        const value = pair[equals + 1 ..];
        if (name.len == 0 or name.len > 64 or value.len > PocketRoot.services.exploit.max_param_bytes) {
            return error.InvalidArguments;
        }
        var replaced = false;
        for (list.items) |*param| {
            if (std.mem.eql(u8, param.name, name)) {
                param.value = try a.dupe(u8, value);
                replaced = true;
                break;
            }
        }
        if (!replaced) try list.append(a, .{
            .name = try a.dupe(u8, name),
            .value = try a.dupe(u8, value),
        });
        index += 2;
    }
    std.mem.sort(PocketRoot.services.exploit.Param, list.items, {}, lessThanParam);
    result.items = try list.toOwnedSlice(a);
    return result;
}

fn lessThanParam(_: void, a: PocketRoot.services.exploit.Param, b: PocketRoot.services.exploit.Param) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

fn exploitAction(
    allocator: std.mem.Allocator,
    spec: *const PocketRoot.services.exploit.Spec,
    record_data: []const u8,
    params: []const PocketRoot.services.exploit.Param,
) !ReproAction {
    var buffer = std.Io.Writer.Allocating.init(allocator);
    defer buffer.deinit();
    try buffer.writer.writeAll(record_data);
    try buffer.writer.print("\n{s}\n{s}\n", .{ spec.cve, spec.target });
    for (params) |param| {
        try buffer.writer.print("{s}={s}\n", .{ param.name, param.value });
    }
    return .{
        .action_id = try std.fmt.allocPrint(allocator, "EXPLOIT-{s}", .{spec.cve}),
        .target = spec.target,
        .params_hash = try PocketRoot.services.control.sha256Hex(allocator, buffer.written()),
    };
}

fn runCampaignApproveExploit(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var record_path: ?[]const u8 = null;
    var reason: ?[]const u8 = null;
    var confirm: ?[]const u8 = null;
    var operator: []const u8 = "operator";
    var param_args: std.ArrayList([:0]const u8) = .empty;
    defer param_args.deinit(allocator);
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--reason") and index + 1 < raw.len) {
            reason = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--confirm") and index + 1 < raw.len) {
            confirm = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--operator") and index + 1 < raw.len) {
            operator = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--param") and index + 1 < raw.len) {
            try param_args.append(allocator, "--param");
            try param_args.append(allocator, raw[index + 1]);
            index += 2;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (record_path != null) return error.InvalidArguments;
            record_path = raw[index];
            index += 1;
        }
    }
    const path = record_path orelse {
        try writer.print("usage: campaign approve-exploit <record.json> --reason <text> --confirm <CVE> [--param k=v]\n", .{});
        return error.InvalidArguments;
    };
    const why = reason orelse {
        try writer.print("approval requires --reason\n", .{});
        return error.InvalidArguments;
    };
    const typed = confirm orelse {
        try writer.print("approval requires --confirm <CVE>; there is no --yes\n", .{});
        return error.InvalidArguments;
    };

    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024)) catch |err| {
        try writer.print("cannot read exploit record: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var spec = PocketRoot.services.exploit.parseSpec(allocator, data) catch {
        try writer.print("invalid exploit record: {s}\n", .{path});
        return error.CommandFailed;
    };
    defer spec.deinit();
    if (!std.mem.eql(u8, typed, spec.cve)) {
        try writer.print("confirmation does not match {s}; nothing approved\n", .{spec.cve});
        return error.InvalidArguments;
    }
    var params = parseExploitParams(spec.params, param_args.items, allocator) catch {
        try writer.print("invalid --param value\n", .{});
        return error.InvalidArguments;
    };
    defer params.deinit();

    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    if (state.phase != .armed) {
        try writer.print("campaign is {s}; run campaign arm first\n", .{@tagName(state.phase)});
        return error.CommandFailed;
    }
    var action = exploitAction(allocator, &spec, data, params.items) catch |err| {
        try writer.print("cannot bind exploit: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer action.deinit(allocator);
    const now = campaignNow(io);
    var approval = PocketRoot.services.control.createApproval(allocator, io, dir, &scope, .{
        .action_id = action.action_id,
        .target = action.target,
        .technique = .exploit,
        .params_hash = action.params_hash,
    }, operator, why, now) catch |err| {
        try writer.print("cannot approve {s}: {s}\n", .{ action.action_id, @errorName(err) });
        return error.CommandFailed;
    };
    defer approval.deinit();
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "approve",
        .action_id = approval.action_id,
        .approval_id = approval.id,
        .target = approval.target,
        .technique = "exploit",
        .result = "approved",
        .detail = approval.reason,
    }, now);
    try writer.print(
        "approved {s}: {s} on {s}\napproval {s} expires at {d} (ttl {d}s, single use)\n",
        .{ approval.action_id, spec.cve, approval.target, approval.id, approval.expires_at_unix, scope.approval_ttl_seconds },
    );
}

fn runExploitCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var record_path: ?[]const u8 = null;
    var evidence_path: ?[]const u8 = null;
    var campaign_dir: ?[]const u8 = null;
    var json_output = false;
    var param_args: std.ArrayList([:0]const u8) = .empty;
    defer param_args.deinit(allocator);
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--campaign") and index + 1 < raw.len) {
            campaign_dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--evidence") and index + 1 < raw.len) {
            evidence_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--json")) {
            json_output = true;
            index += 1;
        } else if (std.mem.eql(u8, raw[index], "--param") and index + 1 < raw.len) {
            try param_args.append(allocator, "--param");
            try param_args.append(allocator, raw[index + 1]);
            index += 2;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (record_path != null) return error.InvalidArguments;
            record_path = raw[index];
            index += 1;
        }
    }
    const path = record_path orelse {
        try writer.print("usage: exploit run <record.json> --campaign <dir> [--param k=v] [--evidence <path>] [--json]\n", .{});
        return error.InvalidArguments;
    };
    const dir = campaign_dir orelse {
        try writer.print("exploit run requires --campaign <dir> and an approval\n", .{});
        return error.CommandFailed;
    };

    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024)) catch |err| {
        try writer.print("cannot read exploit record: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var spec = PocketRoot.services.exploit.parseSpec(allocator, data) catch {
        try writer.print("invalid exploit record: {s}\n", .{path});
        return error.CommandFailed;
    };
    defer spec.deinit();
    var params = parseExploitParams(spec.params, param_args.items, allocator) catch {
        try writer.print("invalid --param value\n", .{});
        return error.InvalidArguments;
    };
    defer params.deinit();
    var action = exploitAction(allocator, &spec, data, params.items) catch |err| {
        try writer.print("cannot bind exploit: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer action.deinit(allocator);

    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    const now = campaignNow(io);
    PocketRoot.services.control.evaluate(allocator, io, dir, &scope, &state, .{
        .action_id = action.action_id,
        .target = action.target,
        .technique = .exploit,
        .params_hash = action.params_hash,
    }, now) catch |err| {
        try writer.print("denied: {s}\n", .{mapCampaignDenial(err)});
        PocketRoot.services.control.appendLedger(allocator, io, dir, .{
            .event = "denied",
            .action_id = action.action_id,
            .target = action.target,
            .technique = "exploit",
            .result = @errorName(err),
            .detail = mapCampaignDenial(err),
        }, now) catch {};
        return error.CommandFailed;
    };
    const approval_file = try PocketRoot.services.control.approvalPath(allocator, dir, action.action_id);
    defer allocator.free(approval_file);
    var approval = PocketRoot.services.control.loadApproval(allocator, io, approval_file) catch |err| {
        try writer.print("cannot load approval: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer approval.deinit();
    const approval_id = approval.id;
    PocketRoot.services.control.consumeApproval(allocator, io, approval_file, now) catch |err| {
        try writer.print("cannot consume approval: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "exploit-start",
        .action_id = action.action_id,
        .approval_id = approval_id,
        .target = action.target,
        .technique = "exploit",
        .result = "started",
        .detail = spec.cve,
    }, now);

    var outcome = PocketRoot.services.exploit.run(allocator, io, &spec, params.items) catch |err| {
        try writer.print("exploit failed: {s}\n", .{@errorName(err)});
        PocketRoot.services.control.appendLedger(allocator, io, dir, .{
            .event = "exploit-result",
            .action_id = action.action_id,
            .approval_id = approval_id,
            .target = action.target,
            .technique = "exploit",
            .result = @errorName(err),
            .detail = spec.cve,
        }, campaignNow(io)) catch {};
        return error.CommandFailed;
    };
    defer outcome.deinit();

    try writer.print("exploit {s}: {s} on {s}\n", .{ spec.cve, @tagName(spec.effect), spec.target });
    for (outcome.steps) |step| {
        try writer.print("  step {s}: status={d} bytes={d}\n", .{ step.name, step.status, step.bytes });
    }
    if (spec.effect == .command) {
        try writer.print("command: {s}\n", .{outcome.command});
    } else {
        var file_value: []const u8 = "";
        for (params.items) |param| {
            if (std.mem.eql(u8, param.name, "file")) file_value = param.value;
        }
        try writer.print("file: {s}\n", .{file_value});
    }
    try writer.print("output:\n{s}\n", .{outcome.output});
    try writer.print("oracle: {s}\n", .{if (outcome.oracle_pass) "pass" else "fail"});

    var evidence_buffer = std.Io.Writer.Allocating.init(allocator);
    defer evidence_buffer.deinit();
    const StepWire = struct { name: []const u8, status: u16, bytes: usize };
    const step_wires = try allocator.alloc(StepWire, outcome.steps.len);
    defer allocator.free(step_wires);
    for (outcome.steps, 0..) |step, i| step_wires[i] = .{ .name = step.name, .status = step.status, .bytes = step.bytes };
    const Wire = struct {
        schema: []const u8,
        cve: []const u8,
        effect: []const u8,
        target: []const u8,
        command: []const u8,
        file: []const u8,
        output: []const u8,
        oracle: []const u8,
        action_id: []const u8,
        approval_id: []const u8,
        steps: []const StepWire,
        recorded_at_unix: i64,
    };
    var json: std.json.Stringify = .{
        .writer = &evidence_buffer.writer,
        .options = .{ .whitespace = .indent_2 },
    };
    json.write(Wire{
        .schema = "pocketroot.exploit.evidence.v1",
        .cve = spec.cve,
        .effect = @tagName(spec.effect),
        .target = spec.target,
        .command = if (spec.effect == .command) outcome.command else "",
        .file = blk: {
            var value: []const u8 = "";
            for (params.items) |param| {
                if (std.mem.eql(u8, param.name, "file")) value = param.value;
            }
            break :blk value;
        },
        .output = outcome.output,
        .oracle = if (outcome.oracle_pass) "pass" else "fail",
        .action_id = action.action_id,
        .approval_id = approval_id,
        .steps = step_wires,
        .recorded_at_unix = campaignNow(io),
    }) catch return error.CommandFailed;
    try evidence_buffer.writer.writeByte('\n');

    if (evidence_path) |file| {
        Io.Dir.cwd().writeFile(io, .{ .sub_path = file, .data = evidence_buffer.written() }) catch |err| {
            try writer.print("cannot write evidence: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
    }
    if (json_output) try writer.writeAll(evidence_buffer.written());

    PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "exploit-result",
        .action_id = action.action_id,
        .approval_id = approval_id,
        .target = action.target,
        .technique = "exploit",
        .result = if (outcome.oracle_pass) "succeeded" else "failed",
        .detail = spec.cve,
    }, campaignNow(io)) catch {};
    if (PocketRoot.services.control.isStopped(allocator, io, dir)) {
        try writer.print("stop marker observed; no further exploit will start\n", .{});
    }
    if (!outcome.oracle_pass) return error.CommandFailed;
}

fn chainParamsHash(allocator: std.mem.Allocator, plan_data: []const u8) ![]u8 {
    return PocketRoot.services.control.sha256Hex(allocator, plan_data);
}

fn runChainPlanCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var observations_path: ?[]const u8 = null;
    var surface_path: ?[]const u8 = null;
    var records_dir: []const u8 = "samples/exploits";
    var out_path: ?[]const u8 = null;
    var target: ?[]const u8 = null;
    var json_output = false;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--observations") and index + 1 < raw.len) {
            observations_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--surface") and index + 1 < raw.len) {
            surface_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--records") and index + 1 < raw.len) {
            records_dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--out") and index + 1 < raw.len) {
            out_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--target") and index + 1 < raw.len) {
            target = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--json")) {
            json_output = true;
            index += 1;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            return error.InvalidArguments;
        }
    }
    if (observations_path == null and surface_path == null) {
        try writer.print("usage: chain plan --observations <file>|--surface <file> [--records <dir>] [--target <target>] [--out <file>]\n", .{});
        return error.InvalidArguments;
    }
    var observations = if (surface_path) |path|
        PocketRoot.services.chain.observationsFromSurface(allocator, io, path) catch |err| {
            try writer.print("cannot load surface observations: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        }
    else
        PocketRoot.services.chain.loadObservations(allocator, io, observations_path.?) catch |err| {
            try writer.print("cannot load observations: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
    defer observations.deinit();
    var chosen: ?PocketRoot.services.chain.Observation = null;
    if (target) |wanted| {
        for (observations.items) |item| {
            if (std.mem.eql(u8, item.target, wanted)) chosen = item;
        }
    } else if (observations.items.len == 1) {
        chosen = observations.items[0];
    }
    const observation = chosen orelse {
        try writer.print("select one observation with --target; {d} available\n", .{observations.items.len});
        return error.InvalidArguments;
    };
    var records = PocketRoot.services.chain.loadIndex(allocator, io, records_dir) catch |err| {
        try writer.print("cannot load exploit records: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer records.deinit();
    var plan = PocketRoot.services.chain.plan(allocator, &records, observation, campaignNow(io)) catch |err| {
        try writer.print("no exploitable chain: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer plan.deinit();

    var buffer = std.Io.Writer.Allocating.init(allocator);
    defer buffer.deinit();
    try PocketRoot.services.chain.writePlanJson(&buffer.writer, &plan);
    if (out_path) |path| {
        Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = buffer.written() }) catch |err| {
            try writer.print("cannot write chain plan: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
    }
    if (json_output or out_path == null) try writer.writeAll(buffer.written());
    try writer.print("chain {s}: {d} step(s) for {s}\n", .{ plan.id, plan.steps.len, plan.target });
    for (plan.steps) |step| {
        try writer.print("  {s} {s} <- {s}\n", .{ @tagName(step.effect), step.cve, step.record_path });
    }
}

fn runChainApproveCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var plan_path: ?[]const u8 = null;
    var reason: ?[]const u8 = null;
    var confirm: ?[]const u8 = null;
    var operator: []const u8 = "operator";
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--reason") and index + 1 < raw.len) {
            reason = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--confirm") and index + 1 < raw.len) {
            confirm = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--operator") and index + 1 < raw.len) {
            operator = raw[index + 1];
            index += 2;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (plan_path != null) return error.InvalidArguments;
            plan_path = raw[index];
            index += 1;
        }
    }
    const path = plan_path orelse {
        try writer.print("usage: chain approve <plan.json> --reason <text> --confirm <CHAIN-ID>\n", .{});
        return error.InvalidArguments;
    };
    const why = reason orelse return error.InvalidArguments;
    const typed = confirm orelse return error.InvalidArguments;
    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024)) catch |err| {
        try writer.print("cannot read chain plan: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var plan = PocketRoot.services.chain.loadPlan(allocator, io, path) catch |err| {
        try writer.print("invalid chain plan: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer plan.deinit();
    if (!std.mem.eql(u8, typed, plan.id)) {
        try writer.print("confirmation does not match {s}; nothing approved\n", .{plan.id});
        return error.InvalidArguments;
    }
    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    const now = campaignNow(io);
    var approval = PocketRoot.services.control.createApproval(allocator, io, dir, &scope, .{
        .action_id = plan.id,
        .target = plan.target,
        .technique = .exploit,
        .params_hash = try chainParamsHash(allocator, data),
    }, operator, why, now) catch |err| {
        try writer.print("cannot approve {s}: {s}\n", .{ plan.id, @errorName(err) });
        return error.CommandFailed;
    };
    defer approval.deinit();
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "approve",
        .action_id = approval.action_id,
        .approval_id = approval.id,
        .target = approval.target,
        .technique = "exploit",
        .result = "approved",
        .detail = approval.reason,
    }, now);
    try writer.print("approved {s}: {d} step(s) on {s}\napproval {s} expires at {d}\n", .{
        plan.id, plan.steps.len, plan.target, approval.id, approval.expires_at_unix,
    });
}

fn runChainRunCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var plan_path: ?[]const u8 = null;
    var campaign_dir: ?[]const u8 = null;
    var evidence_path: ?[]const u8 = null;
    var json_output = false;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--campaign") and index + 1 < raw.len) {
            campaign_dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--evidence") and index + 1 < raw.len) {
            evidence_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--json")) {
            json_output = true;
            index += 1;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (plan_path != null) return error.InvalidArguments;
            plan_path = raw[index];
            index += 1;
        }
    }
    const path = plan_path orelse {
        try writer.print("usage: chain run <plan.json> --campaign <dir> [--evidence <path>]\n", .{});
        return error.InvalidArguments;
    };
    const dir = campaign_dir orelse {
        try writer.print("chain run requires --campaign <dir> and an approval\n", .{});
        return error.CommandFailed;
    };
    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024)) catch |err| {
        try writer.print("cannot read chain plan: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var plan = PocketRoot.services.chain.loadPlan(allocator, io, path) catch |err| {
        try writer.print("invalid chain plan: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer plan.deinit();
    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    var action = ReproAction{
        .action_id = try allocator.dupe(u8, plan.id),
        .target = plan.target,
        .params_hash = try chainParamsHash(allocator, data),
    };
    defer action.deinit(allocator);
    const now = campaignNow(io);
    PocketRoot.services.control.evaluate(allocator, io, dir, &scope, &state, .{
        .action_id = action.action_id,
        .target = action.target,
        .technique = .exploit,
        .params_hash = action.params_hash,
    }, now) catch |err| {
        try writer.print("denied: {s}\n", .{mapCampaignDenial(err)});
        PocketRoot.services.control.appendLedger(allocator, io, dir, .{
            .event = "denied",
            .action_id = action.action_id,
            .target = action.target,
            .technique = "exploit",
            .result = @errorName(err),
            .detail = mapCampaignDenial(err),
        }, now) catch {};
        return error.CommandFailed;
    };
    const approval_file = try PocketRoot.services.control.approvalPath(allocator, dir, action.action_id);
    defer allocator.free(approval_file);
    var approval = PocketRoot.services.control.loadApproval(allocator, io, approval_file) catch |err| {
        try writer.print("cannot load approval: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer approval.deinit();
    const approval_id = approval.id;
    PocketRoot.services.control.consumeApproval(allocator, io, approval_file, now) catch |err| {
        try writer.print("cannot consume approval: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "chain-start",
        .action_id = action.action_id,
        .approval_id = approval_id,
        .target = action.target,
        .technique = "exploit",
        .result = "started",
        .detail = plan.id,
    }, now);

    var evidence_buffer = std.Io.Writer.Allocating.init(allocator);
    defer evidence_buffer.deinit();
    var chain_status: []const u8 = "succeeded";
    var outputs: std.ArrayList(u8) = .empty;
    defer outputs.deinit(allocator);
    var step_report = std.Io.Writer.Allocating.init(allocator);
    defer step_report.deinit();
    var executed: usize = 0;
    for (plan.steps, 0..) |step, step_index| {
        if (PocketRoot.services.control.isStopped(allocator, io, dir)) {
            chain_status = "stopped";
            break;
        }
        const record_data = Io.Dir.cwd().readFileAlloc(io, step.record_path, allocator, .limited(256 * 1024)) catch |err| {
            try writer.print("cannot read step record {s}: {s}\n", .{ step.record_path, @errorName(err) });
            chain_status = "failed";
            break;
        };
        defer allocator.free(record_data);
        const digest = try PocketRoot.services.control.sha256Hex(allocator, record_data);
        defer allocator.free(digest);
        if (!std.mem.eql(u8, digest, step.digest)) {
            try writer.print("step record changed since planning: {s}\n", .{step.record_path});
            chain_status = "failed";
            break;
        }
        var spec = PocketRoot.services.exploit.parseSpec(allocator, record_data) catch |err| {
            try writer.print("invalid step record {s}: {s}\n", .{ step.record_path, @errorName(err) });
            chain_status = "failed";
            break;
        };
        defer spec.deinit();
        spec.target = step.target;
        var outcome = PocketRoot.services.exploit.run(allocator, io, &spec, spec.params) catch |err| {
            try writer.print("step {s} failed: {s}\n", .{ step.cve, @errorName(err) });
            PocketRoot.services.control.appendLedger(allocator, io, dir, .{
                .event = "chain-step",
                .action_id = action.action_id,
                .approval_id = approval_id,
                .target = action.target,
                .technique = "exploit",
                .result = @errorName(err),
                .detail = step.cve,
            }, campaignNow(io)) catch {};
            chain_status = "failed";
            break;
        };
        defer outcome.deinit();
        executed += 1;
        try writer.print("step {d}/{d} {s} {s}: oracle={s}\n", .{
            step_index + 1,                              plan.steps.len, @tagName(step.effect), step.cve,
            if (outcome.oracle_pass) "pass" else "fail",
        });
        try outputs.appendSlice(allocator, outcome.output);
        try outputs.append(allocator, '\n');
        try step_report.writer.print("  {s} {s} oracle={s} bytes={d}\n", .{
            @tagName(step.effect),                       step.cve,
            if (outcome.oracle_pass) "pass" else "fail", outcome.output.len,
        });
        PocketRoot.services.control.appendLedger(allocator, io, dir, .{
            .event = "chain-step",
            .action_id = action.action_id,
            .approval_id = approval_id,
            .target = action.target,
            .technique = "exploit",
            .result = if (outcome.oracle_pass) "succeeded" else "failed",
            .detail = step.cve,
        }, campaignNow(io)) catch {};
        if (!outcome.oracle_pass) {
            chain_status = "failed";
            break;
        }
        if (PocketRoot.services.control.isStopped(allocator, io, dir)) {
            chain_status = "stopped";
            break;
        }
    }
    try writer.print("chain {s}: {s} ({d}/{d} steps)\n", .{ plan.id, chain_status, executed, plan.steps.len });
    try writer.writeAll(step_report.written());
    try writer.print("output:\n{s}\n", .{outputs.items});
    PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "chain-result",
        .action_id = action.action_id,
        .approval_id = approval_id,
        .target = action.target,
        .technique = "exploit",
        .result = chain_status,
        .detail = plan.id,
    }, campaignNow(io)) catch {};

    const Wire = struct {
        schema: []const u8,
        id: []const u8,
        target: []const u8,
        status: []const u8,
        action_id: []const u8,
        approval_id: []const u8,
        executed: usize,
        output: []const u8,
        recorded_at_unix: i64,
    };
    var json: std.json.Stringify = .{
        .writer = &evidence_buffer.writer,
        .options = .{ .whitespace = .indent_2 },
    };
    json.write(Wire{
        .schema = "pocketroot.chain.evidence.v1",
        .id = plan.id,
        .target = plan.target,
        .status = chain_status,
        .action_id = action.action_id,
        .approval_id = approval_id,
        .executed = executed,
        .output = outputs.items,
        .recorded_at_unix = campaignNow(io),
    }) catch {};
    try evidence_buffer.writer.writeByte('\n');
    if (evidence_path) |file| {
        Io.Dir.cwd().writeFile(io, .{ .sub_path = file, .data = evidence_buffer.written() }) catch |err| {
            try writer.print("cannot write chain evidence: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
    }
    if (json_output) try writer.writeAll(evidence_buffer.written());
    if (!std.mem.eql(u8, chain_status, "succeeded")) return error.CommandFailed;
}

fn runCampaignApproveAdaptive(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var dir: []const u8 = campaign_default_dir;
    var goal_path: ?[]const u8 = null;
    var reason: ?[]const u8 = null;
    var confirm: ?[]const u8 = null;
    var operator: []const u8 = "operator";
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--dir") and index + 1 < raw.len) {
            dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--reason") and index + 1 < raw.len) {
            reason = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--confirm") and index + 1 < raw.len) {
            confirm = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--operator") and index + 1 < raw.len) {
            operator = raw[index + 1];
            index += 2;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (goal_path != null) return error.InvalidArguments;
            goal_path = raw[index];
            index += 1;
        }
    }
    const path = goal_path orelse {
        try writer.print("usage: campaign approve-adaptive <goal.json> --reason <text> --confirm <GOAL-ID>\n", .{});
        return error.InvalidArguments;
    };
    const why = reason orelse return error.InvalidArguments;
    const typed = confirm orelse return error.InvalidArguments;
    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024)) catch |err| {
        try writer.print("cannot read adaptive goal: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var goal = PocketRoot.services.adaptive.parseGoal(allocator, data) catch {
        try writer.print("invalid adaptive goal: {s}\n", .{path});
        return error.CommandFailed;
    };
    defer goal.deinit();
    if (!std.mem.eql(u8, typed, goal.id)) {
        try writer.print("confirmation does not match {s}; nothing approved\n", .{goal.id});
        return error.InvalidArguments;
    }
    var scope = loadCampaignScope(allocator, io, dir) catch |err| {
        try writer.print("cannot load scope: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer scope.deinit();
    var state = PocketRoot.services.control.loadState(allocator, io, dir) catch |err| {
        try writer.print("cannot load campaign state: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer state.deinit();
    const action_id = try std.fmt.allocPrint(allocator, "ADAPT-{s}", .{goal.id});
    defer allocator.free(action_id);
    const params_hash = PocketRoot.services.adaptive.goalHash(allocator, io, data, &goal) catch |err| {
        try writer.print("cannot bind adaptive goal: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(params_hash);
    const now = campaignNow(io);
    var approval = PocketRoot.services.control.createApproval(allocator, io, dir, &scope, .{
        .action_id = action_id,
        .target = goal.target,
        .technique = .exploit,
        .params_hash = params_hash,
    }, operator, why, now) catch |err| {
        try writer.print("cannot approve {s}: {s}\n", .{ action_id, @errorName(err) });
        return error.CommandFailed;
    };
    defer approval.deinit();
    try PocketRoot.services.control.appendLedger(allocator, io, dir, .{
        .event = "approve",
        .action_id = approval.action_id,
        .approval_id = approval.id,
        .target = approval.target,
        .technique = "exploit",
        .result = "approved",
        .detail = approval.reason,
    }, now);
    try writer.print("approved {s}: {s} on {s}\napproval {s} expires at {d}\n", .{
        action_id, goal.id, goal.target, approval.id, approval.expires_at_unix,
    });
}

fn runAdaptiveCommand(
    allocator: std.mem.Allocator,
    io: Io,
    writer: *Io.Writer,
    raw: []const [:0]const u8,
) !void {
    var goal_path: ?[]const u8 = null;
    var campaign_dir: ?[]const u8 = null;
    var evidence_path: ?[]const u8 = null;
    var json_output = false;
    var index: usize = 0;
    while (index < raw.len) {
        if (std.mem.eql(u8, raw[index], "--campaign") and index + 1 < raw.len) {
            campaign_dir = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--evidence") and index + 1 < raw.len) {
            evidence_path = raw[index + 1];
            index += 2;
        } else if (std.mem.eql(u8, raw[index], "--json")) {
            json_output = true;
            index += 1;
        } else if (std.mem.startsWith(u8, raw[index], "--")) {
            return error.InvalidArguments;
        } else {
            if (goal_path != null) return error.InvalidArguments;
            goal_path = raw[index];
            index += 1;
        }
    }
    const path = goal_path orelse {
        try writer.print("usage: chain adaptive <goal.json> --campaign <dir> [--evidence <path>]\n", .{});
        return error.InvalidArguments;
    };
    const dir = campaign_dir orelse {
        try writer.print("chain adaptive requires --campaign <dir> and an approval\n", .{});
        return error.CommandFailed;
    };
    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 * 1024)) catch |err| {
        try writer.print("cannot read adaptive goal: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer allocator.free(data);
    var goal = PocketRoot.services.adaptive.parseGoal(allocator, data) catch {
        try writer.print("invalid adaptive goal: {s}\n", .{path});
        return error.CommandFailed;
    };
    defer goal.deinit();
    var execution = PocketRoot.services.adaptive.run(allocator, io, data, &goal, dir) catch |err| {
        try writer.print("adaptive run refused: {s}\n", .{@errorName(err)});
        return error.CommandFailed;
    };
    defer execution.deinit();

    try writer.print("adaptive {s}: {s} on {s}\n", .{ goal.id, execution.status, goal.target });
    for (execution.steps) |step| {
        try writer.print("  {s} {s} oracle={s}\n", .{
            step.module_id, step.cve, if (step.oracle_pass) "pass" else "fail",
        });
    }
    try writer.print("facts:\n{s}\n", .{execution.facts_output});

    var evidence = std.Io.Writer.Allocating.init(allocator);
    defer evidence.deinit();
    const StepWire = struct {
        module: []const u8,
        cve: []const u8,
        oracle: []const u8,
        output: []const u8,
    };
    const steps = try allocator.alloc(StepWire, execution.steps.len);
    defer allocator.free(steps);
    for (execution.steps, 0..) |step, i| {
        steps[i] = .{
            .module = step.module_id,
            .cve = step.cve,
            .oracle = if (step.oracle_pass) "pass" else "fail",
            .output = step.output,
        };
    }
    const Wire = struct {
        schema: []const u8,
        id: []const u8,
        target: []const u8,
        status: []const u8,
        approval_id: []const u8,
        steps: []const StepWire,
        facts: []const u8,
        recorded_at_unix: i64,
    };
    var json: std.json.Stringify = .{
        .writer = &evidence.writer,
        .options = .{ .whitespace = .indent_2 },
    };
    json.write(Wire{
        .schema = "pocketroot.adaptive.evidence.v1",
        .id = execution.goal_id,
        .target = goal.target,
        .status = execution.status,
        .approval_id = execution.approval_id,
        .steps = steps,
        .facts = execution.facts_output,
        .recorded_at_unix = campaignNow(io),
    }) catch return error.CommandFailed;
    try evidence.writer.writeByte('\n');
    if (evidence_path) |file| {
        Io.Dir.cwd().writeFile(io, .{ .sub_path = file, .data = evidence.written() }) catch |err| {
            try writer.print("cannot write adaptive evidence: {s}\n", .{@errorName(err)});
            return error.CommandFailed;
        };
    }
    if (json_output) try writer.writeAll(evidence.written());
    if (!std.mem.eql(u8, execution.status, "succeeded")) return error.CommandFailed;
}
