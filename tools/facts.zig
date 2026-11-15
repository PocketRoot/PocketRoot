//! Generates the repository fact sheet that documentation links to.
//!
//! \`zig build facts\` rewrites \`docs/facts.json\` and \`docs/capabilities/facts.md\`;
//! \`zig build docs-check\` recomputes both and fails when they are stale, so a change in
//! the plugin list, capability enum, test count or catalogue size cannot leave the docs
//! silently wrong.

const std = @import("std");
const Io = std.Io;
const PocketRoot = @import("PocketRoot");

const facts_json_path = "docs/facts.json";
const facts_markdown_path = "docs/capabilities/facts.md";
const facts_schema = "pocketroot.facts.v1";
const max_file_bytes = 16 * 1024 * 1024;

const Facts = struct {
    protocols: usize,
    kinds: usize,
    operations: usize,
    verbs: usize,
    packs: usize,
    test_blocks: usize,
    smoke_checks: usize,
    sample_files: usize,
    catalogue_v1: ?usize,
    catalogue_v2: ?usize,
};

fn walkFiles(
    allocator: std.mem.Allocator,
    io: Io,
    root: []const u8,
    context: anytype,
    comptime visitFn: anytype,
) !void {
    var dir = try Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        try visitFn(context, entry.dir, entry.basename);
    }
}

const SourceScan = struct {
    allocator: std.mem.Allocator,
    io: Io,
    tests: usize = 0,

    fn visit(self: *SourceScan, dir: Io.Dir, basename: []const u8) !void {
        if (!std.mem.endsWith(u8, basename, ".zig")) return;
        const data = try dir.readFileAlloc(self.io, basename, self.allocator, .limited(max_file_bytes));
        defer self.allocator.free(data);
        var lines = std.mem.splitScalar(u8, data, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "test \"") or std.mem.eql(u8, line, "test {")) {
                self.tests += 1;
            }
        }
    }
};

fn countSamples(allocator: std.mem.Allocator, io: Io) !usize {
    var count: usize = 0;
    try walkFiles(allocator, io, "samples", &count, struct {
        fn visit(ctx: *usize, _: Io.Dir, _: []const u8) !void {
            ctx.* += 1;
        }
    }.visit);
    return count;
}

fn countBuildSmokeChecks(allocator: std.mem.Allocator, io: Io) !usize {
    const source = try Io.Dir.cwd().readFileAlloc(io, "build.zig", allocator, .limited(max_file_bytes));
    defer allocator.free(source);
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " ");
        if (std.mem.startsWith(u8, trimmed, "addSmoke(") or
            std.mem.startsWith(u8, trimmed, "addSmokeExit(") or
            std.mem.startsWith(u8, trimmed, "addSmokeStdin("))
        {
            count += 1;
        }
    }
    return count;
}

fn countCatalogue(allocator: std.mem.Allocator, io: Io, name: []const u8) ?usize {
    const roots = [_][]const u8{
        "../PocketRootVulnerabilityDb/vulndb/",
        "PocketRootVulnerabilityDb/vulndb/",
    };
    for (roots) |root| {
        const path = std.fmt.allocPrint(allocator, "{s}{s}", .{ root, name }) catch return null;
        defer allocator.free(path);
        const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_file_bytes)) catch continue;
        defer allocator.free(data);
        var count: usize = 0;
        var lines = std.mem.splitScalar(u8, data, '\n');
        while (lines.next()) |line| {
            if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
            count += 1;
        }
        return count;
    }
    return null;
}

fn compute(allocator: std.mem.Allocator, io: Io) !Facts {
    var scan = SourceScan{ .allocator = allocator, .io = io };
    try walkFiles(allocator, io, "src", &scan, SourceScan.visit);

    const protocols = PocketRoot.protocols.registry.builtinProtocols();
    const script = PocketRoot.services.script;

    return .{
        .protocols = protocols.len,
        .kinds = std.meta.fields(PocketRoot.core.capability.Kind).len,
        .operations = std.meta.fields(PocketRoot.core.capability.Operation).len,
        .verbs = PocketRoot.services.script_builder.verb_map.len,
        .packs = script.packNames().len,
        .test_blocks = scan.tests,
        .smoke_checks = try countBuildSmokeChecks(allocator, io),
        .sample_files = try countSamples(allocator, io),
        .catalogue_v1 = countCatalogue(allocator, io, "catalog-v1.jsonl"),
        .catalogue_v2 = countCatalogue(allocator, io, "catalog-v2.jsonl"),
    };
}

fn renderJson(allocator: std.mem.Allocator, facts: Facts) ![]u8 {
    var buffer: [4096]u8 = undefined;
    var output: Io.Writer = .fixed(&buffer);
    var json: std.json.Stringify = .{
        .writer = &output,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.beginObject();
    try json.objectField("schema");
    try json.write(facts_schema);
    try json.objectField("protocols");
    try json.write(facts.protocols);
    try json.objectField("kinds");
    try json.write(facts.kinds);
    try json.objectField("operations");
    try json.write(facts.operations);
    try json.objectField("dsl_verbs");
    try json.write(facts.verbs);
    try json.objectField("dsl_packs");
    try json.write(facts.packs);
    try json.objectField("test_blocks");
    try json.write(facts.test_blocks);
    try json.objectField("smoke_checks");
    try json.write(facts.smoke_checks);
    try json.objectField("sample_files");
    try json.write(facts.sample_files);
    try json.objectField("catalogue_v1");
    if (facts.catalogue_v1) |value| try json.write(value) else try json.write(null);
    try json.objectField("catalogue_v2");
    if (facts.catalogue_v2) |value| try json.write(value) else try json.write(null);
    try json.endObject();
    try output.writeByte('\n');
    return allocator.dupe(u8, output.buffered());
}

fn renderMarkdown(allocator: std.mem.Allocator, facts: Facts) ![]u8 {
    var buffer: [8192]u8 = undefined;
    var output: Io.Writer = .fixed(&buffer);
    try output.print("# Generated facts\n\n", .{});
    try output.print("<!-- written by `zig build facts`; verified by `zig build docs-check` -->\n\n", .{});
    try output.print("| Fact | Value |\n|---|---|\n", .{});
    try output.print("| Protocol plugins | {d} |\n", .{facts.protocols});
    try output.print("| Capability kinds | {d} |\n", .{facts.kinds});
    try output.print("| Capability operations | {d} |\n", .{facts.operations});
    try output.print("| DSL verbs | {d} |\n", .{facts.verbs});
    try output.print("| DSL packs | {d} |\n", .{facts.packs});
    try output.print("| Test blocks under src/ (declared) | {d} |\n", .{facts.test_blocks});
    try output.print("| CLI smoke invocations | {d} |\n", .{facts.smoke_checks});
    try output.print("| Sample files | {d} |\n", .{facts.sample_files});
    try output.print("| Catalogue v1 entries | ", .{});
    if (facts.catalogue_v1) |value| try output.print("{d}", .{value}) else try output.writeAll("not present");
    try output.print(" |\n", .{});
    try output.print("| Catalogue v2 entries | ", .{});
    if (facts.catalogue_v2) |value| try output.print("{d}", .{value}) else try output.writeAll("not present");
    try output.print(" |\n", .{});
    try output.print("\nGenerated from the source tree, the built-in registry and the capability enums;\n", .{});
    try output.print("run `zig build facts` after changing any of them.\n\n", .{});
    try output.print("Test blocks are counted as declared; the test runner reports passed and\n", .{});
    try output.print("skipped separately (catalogue tests skip without the sibling checkout).\n", .{});
    return allocator.dupe(u8, output.buffered());
}

/// A standalone clone has no sibling catalogue repository. Keep the committed counts for
/// those two fields so the check still exercises every other fact instead of failing on
/// data that cannot be observed there. CI checks out the catalogue and verifies them.
fn fillCatalogueFallback(facts: *Facts, allocator: std.mem.Allocator, io: Io) void {
    if (facts.catalogue_v1 != null and facts.catalogue_v2 != null) return;
    const data = Io.Dir.cwd().readFileAlloc(io, facts_json_path, allocator, .limited(max_file_bytes)) catch return;
    defer allocator.free(data);
    const Committed = struct {
        catalogue_v1: ?usize = null,
        catalogue_v2: ?usize = null,
    };
    const committed = std.json.parseFromSliceLeaky(Committed, allocator, data, .{
        .ignore_unknown_fields = true,
    }) catch return;
    if (facts.catalogue_v1 == null) facts.catalogue_v1 = committed.catalogue_v1;
    if (facts.catalogue_v2 == null) facts.catalogue_v2 = committed.catalogue_v2;
}

fn isCurrent(allocator: std.mem.Allocator, io: Io, path: []const u8, expected: []const u8) !bool {
    const data = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_file_bytes)) catch return false;
    defer allocator.free(data);
    return std.mem.eql(u8, data, expected);
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    var write = false;
    if (args.len > 1) {
        if (std.mem.eql(u8, args[1], "--write")) {
            write = true;
        } else if (std.mem.eql(u8, args[1], "--check")) {
            write = false;
        } else {
            std.debug.print("usage: facts [--check|--write]\n", .{});
            std.process.exit(2);
        }
    }

    var facts = try compute(arena, io);
    // Keep the committed catalogue counts when the sibling repository is absent, so an
    // offline checkout can still run the facts step without zeroing them.
    fillCatalogueFallback(&facts, arena, io);
    const json = try renderJson(arena, facts);
    const markdown = try renderMarkdown(arena, facts);

    if (write) {
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = facts_json_path, .data = json });
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = facts_markdown_path, .data = markdown });
        std.debug.print(
            "facts: wrote {s} and {s} ({d} test blocks, {d} plugins, {d} kinds)\n",
            .{ facts_json_path, facts_markdown_path, facts.test_blocks, facts.protocols, facts.kinds },
        );
        return;
    }

    var stale = false;
    if (!try isCurrent(arena, io, facts_json_path, json)) {
        std.debug.print("stale: {s}\n", .{facts_json_path});
        stale = true;
    }
    if (!try isCurrent(arena, io, facts_markdown_path, markdown)) {
        std.debug.print("stale: {s}\n", .{facts_markdown_path});
        stale = true;
    }
    if (stale) {
        std.debug.print("run `zig build facts` to regenerate the fact sheet\n", .{});
        std.process.exit(1);
    }
    std.debug.print(
        "facts: up to date ({d} test blocks, {d} plugins, {d} kinds, {d} smoke checks)\n",
        .{ facts.test_blocks, facts.protocols, facts.kinds, facts.smoke_checks },
    );
}
