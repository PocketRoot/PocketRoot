//! Exploit-chain detection and planning.
//!
//! Observations (target, service/product/version, CVEs) are matched against exploit
//! records. The result is an ordered, digest-bound plan: a single approval authorises the
//! whole chain, and the runner executes the steps without asking for per-record approvals.

const std = @import("std");
const exploit = @import("exploit.zig");
const control = @import("control.zig");
const surface = @import("surface.zig");

pub const max_steps = 8;

pub const Record = struct {
    path: []const u8,
    cve: []const u8,
    target: []const u8,
    effect: exploit.Effect,
    service: []const u8,
    product: []const u8,
    version_prefix: []const u8,
    digest: []const u8,
};

pub const Index = struct {
    arena: std.heap.ArenaAllocator,
    records: []Record,

    pub fn deinit(self: *Index) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const Observation = struct {
    target: []const u8,
    service: []const u8,
    product: []const u8,
    version: []const u8,
    cves: []const []const u8,
};

pub const Observations = struct {
    arena: std.heap.ArenaAllocator,
    items: []Observation,

    pub fn deinit(self: *Observations) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const PlanStep = struct {
    cve: []const u8,
    record_path: []const u8,
    effect: exploit.Effect,
    target: []const u8,
    digest: []const u8,
};

pub const Plan = struct {
    arena: std.heap.ArenaAllocator,
    id: []const u8,
    target: []const u8,
    steps: []PlanStep,
    created_at_unix: i64,

    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const MatchWire = struct {
    service: []const u8 = "",
    product: []const u8 = "",
    version_prefix: []const u8 = "",
};

const MetaWire = struct {
    schema: []const u8 = "",
    cve: []const u8 = "",
    target: []const u8 = "",
    effect: []const u8 = "",
    match: ?MatchWire = null,
};

const ObservationsWire = struct {
    schema: []const u8 = "",
    observations: []struct {
        target: []const u8 = "",
        service: []const u8 = "",
        product: []const u8 = "",
        version: []const u8 = "",
        cves: []const []const u8 = &.{},
    } = &.{},
};

pub fn loadIndex(allocator: std.mem.Allocator, io: std.Io, dir_path: []const u8) !Index {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(a);
    defer walker.deinit();
    var records: std.ArrayList(Record) = .empty;
    defer records.deinit(a);
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".json")) continue;
        if (records.items.len >= 128) return error.TooManyRecords;
        const path = try std.fs.path.join(a, &.{ dir_path, entry.path });
        const data = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(256 * 1024));
        const meta = std.json.parseFromSliceLeaky(MetaWire, a, data, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidRecord;
        if (!std.mem.eql(u8, meta.schema, "pocketroot.exploit.v1")) return error.InvalidRecord;
        const effect: exploit.Effect = if (std.mem.eql(u8, meta.effect, "command"))
            .command
        else if (std.mem.eql(u8, meta.effect, "read_file"))
            .read_file
        else
            return error.InvalidRecord;
        try records.append(a, .{
            .path = path,
            .cve = meta.cve,
            .target = meta.target,
            .effect = effect,
            .service = if (meta.match) |m| m.service else "",
            .product = if (meta.match) |m| m.product else "",
            .version_prefix = if (meta.match) |m| m.version_prefix else "",
            .digest = try control.sha256Hex(a, data),
        });
    }
    return .{ .arena = arena, .records = try records.toOwnedSlice(a) };
}

pub fn loadObservations(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Observations {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(256 * 1024));
    const wire = std.json.parseFromSliceLeaky(ObservationsWire, a, data, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidObservations;
    if (!std.mem.eql(u8, wire.schema, "pocketroot.observations.v1")) return error.InvalidObservations;
    if (wire.observations.len == 0 or wire.observations.len > 64) return error.InvalidObservations;
    const items = try a.alloc(Observation, wire.observations.len);
    for (wire.observations, 0..) |item, i| {
        if (item.target.len == 0) return error.InvalidObservations;
        items[i] = .{
            .target = item.target,
            .service = item.service,
            .product = item.product,
            .version = item.version,
            .cves = item.cves,
        };
    }
    return .{ .arena = arena, .items = items };
}

/// Turns a surface report into observations: one target, with the vulnerability ids
/// the read-only matcher already found. Empty product/version keep match constraints
/// inactive, while the CVE path still matches the exploit record.
pub fn observationsFromSurface(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !Observations {
    var stored = surface.load(allocator, io, path) catch return error.InvalidSurface;
    defer stored.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var targets: std.ArrayList([]const u8) = .empty;
    defer targets.deinit(a);
    for (stored.actions) |action| {
        var known = false;
        for (targets.items) |target| {
            if (std.mem.eql(u8, target, action.target)) known = true;
        }
        if (!known) try targets.append(a, action.target);
    }
    if (targets.items.len == 0) return error.InvalidObservations;
    const items = try a.alloc(Observation, targets.items.len);
    for (targets.items, 0..) |target, i| {
        var cves: std.ArrayList([]const u8) = .empty;
        defer cves.deinit(a);
        for (stored.actions) |action| {
            if (!std.mem.eql(u8, action.target, target) or action.vulnerability_id.len == 0) continue;
            var duplicate = false;
            for (cves.items) |cve| {
                if (std.mem.eql(u8, cve, action.vulnerability_id)) duplicate = true;
            }
            if (!duplicate) try cves.append(a, action.vulnerability_id);
        }
        items[i] = .{
            .target = target,
            .service = "",
            .product = "",
            .version = "",
            .cves = try cves.toOwnedSlice(a),
        };
    }
    return .{ .arena = arena, .items = items };
}

fn effectRank(effect: exploit.Effect) u8 {
    return switch (effect) {
        .read_file => 0,
        .command => 1,
    };
}

fn lessThanStep(_: void, left: PlanStep, right: PlanStep) bool {
    const left_rank = effectRank(left.effect);
    const right_rank = effectRank(right.effect);
    if (left_rank != right_rank) return left_rank < right_rank;
    return std.mem.lessThan(u8, left.cve, right.cve);
}

fn matches(record: Record, observation: Observation) bool {
    for (observation.cves) |cve| {
        if (std.mem.eql(u8, cve, record.cve)) return true;
    }
    var has_constraint = false;
    if (record.service.len > 0) {
        has_constraint = true;
        if (!std.ascii.eqlIgnoreCase(record.service, observation.service)) return false;
    }
    if (record.product.len > 0) {
        has_constraint = true;
        if (!std.ascii.eqlIgnoreCase(record.product, observation.product)) return false;
    }
    if (record.version_prefix.len > 0) {
        has_constraint = true;
        if (!std.mem.startsWith(u8, observation.version, record.version_prefix)) return false;
    }
    return has_constraint;
}

/// Builds one plan for one observation. Matching records are deduplicated by CVE and
/// ordered so that read-only effects run before command execution.
pub fn plan(
    allocator: std.mem.Allocator,
    index: *const Index,
    observation: Observation,
    now: i64,
) !Plan {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var seen: std.ArrayList([]const u8) = .empty;
    defer seen.deinit(a);
    var steps: std.ArrayList(PlanStep) = .empty;
    defer steps.deinit(a);
    for (index.records) |record| {
        if (!matches(record, observation)) continue;
        var duplicate = false;
        for (seen.items) |cve| {
            if (std.mem.eql(u8, cve, record.cve)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        try seen.append(a, record.cve);
        try steps.append(a, .{
            .cve = record.cve,
            .record_path = record.path,
            .effect = record.effect,
            .target = observation.target,
            .digest = record.digest,
        });
        if (steps.items.len == max_steps) break;
    }
    if (steps.items.len == 0) return error.NoExploitableChain;
    std.mem.sort(PlanStep, steps.items, {}, lessThanStep);

    var digest_input: std.ArrayList(u8) = .empty;
    defer digest_input.deinit(a);
    try digest_input.appendSlice(a, observation.target);
    for (steps.items) |step| {
        try digest_input.appendSlice(a, step.cve);
        try digest_input.appendSlice(a, @tagName(step.effect));
        try digest_input.appendSlice(a, step.digest);
    }
    const digest = try control.sha256Hex(a, digest_input.items);
    return .{
        .arena = arena,
        .id = try std.fmt.allocPrint(a, "CHAIN-{s}", .{digest[0..16]}),
        .target = observation.target,
        .steps = try steps.toOwnedSlice(a),
        .created_at_unix = now,
    };
}

pub fn writePlanJson(writer: *std.Io.Writer, value: *const Plan) !void {
    const StepWire = struct {
        cve: []const u8,
        record: []const u8,
        effect: []const u8,
        target: []const u8,
        digest: []const u8,
    };
    const Wire = struct {
        schema: []const u8,
        id: []const u8,
        target: []const u8,
        created_at_unix: i64,
        steps: []const StepWire,
    };
    const steps = try std.heap.page_allocator.alloc(StepWire, value.steps.len);
    defer std.heap.page_allocator.free(steps);
    for (value.steps, 0..) |step, i| {
        steps[i] = .{
            .cve = step.cve,
            .record = step.record_path,
            .effect = @tagName(step.effect),
            .target = step.target,
            .digest = step.digest,
        };
    }
    var json: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.write(Wire{
        .schema = "pocketroot.chain.v1",
        .id = value.id,
        .target = value.target,
        .created_at_unix = value.created_at_unix,
        .steps = steps,
    });
    try writer.writeByte('\n');
}

const PlanStepWire = struct {
    cve: []const u8 = "",
    record: []const u8 = "",
    effect: []const u8 = "",
    target: []const u8 = "",
    digest: []const u8 = "",
};

const PlanWire = struct {
    schema: []const u8 = "",
    id: []const u8 = "",
    target: []const u8 = "",
    created_at_unix: i64 = 0,
    steps: []const PlanStepWire = &.{},
};

pub fn loadPlan(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Plan {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(256 * 1024));
    const wire = std.json.parseFromSliceLeaky(PlanWire, a, data, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidPlan;
    if (!std.mem.eql(u8, wire.schema, "pocketroot.chain.v1")) return error.InvalidPlan;
    if (wire.id.len == 0 or wire.target.len == 0 or wire.steps.len == 0 or wire.steps.len > max_steps) {
        return error.InvalidPlan;
    }
    const steps = try a.alloc(PlanStep, wire.steps.len);
    for (wire.steps, 0..) |step, i| {
        const effect: exploit.Effect = if (std.mem.eql(u8, step.effect, "command"))
            .command
        else if (std.mem.eql(u8, step.effect, "read_file"))
            .read_file
        else
            return error.InvalidPlan;
        if (step.cve.len == 0 or step.record.len == 0 or step.target.len == 0 or step.digest.len == 0) {
            return error.InvalidPlan;
        }
        steps[i] = .{
            .cve = step.cve,
            .record_path = step.record,
            .effect = effect,
            .target = step.target,
            .digest = step.digest,
        };
    }
    return .{
        .arena = arena,
        .id = wire.id,
        .target = wire.target,
        .steps = steps,
        .created_at_unix = wire.created_at_unix,
    };
}

test "planner matches CVEs and orders read-only effects first" {
    const records = [_]Record{
        .{ .path = "cmd.json", .cve = "CVE-2", .target = "old", .effect = .command, .service = "", .product = "", .version_prefix = "", .digest = "d2" },
        .{ .path = "read.json", .cve = "CVE-1", .target = "old", .effect = .read_file, .service = "", .product = "", .version_prefix = "", .digest = "d1" },
        .{ .path = "other.json", .cve = "CVE-3", .target = "old", .effect = .command, .service = "", .product = "", .version_prefix = "", .digest = "d3" },
    };
    var index = Index{ .arena = undefined, .records = @constCast(&records) };
    const observation = Observation{
        .target = "127.0.0.1:8080",
        .service = "http",
        .product = "drupal",
        .version = "7.57",
        .cves = &.{ "CVE-1", "CVE-2" },
    };
    var result = try plan(std.testing.allocator, &index, observation, 1);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), result.steps.len);
    try std.testing.expectEqualStrings("CVE-1", result.steps[0].cve);
    try std.testing.expectEqualStrings("CVE-2", result.steps[1].cve);
    try std.testing.expect(std.mem.startsWith(u8, result.id, "CHAIN-"));
}

test "planner uses service/product/version constraints" {
    const records = [_]Record{
        .{ .path = "drupal.json", .cve = "CVE-X", .target = "old", .effect = .command, .service = "http", .product = "drupal", .version_prefix = "7.5", .digest = "d" },
    };
    var index = Index{ .arena = undefined, .records = @constCast(&records) };
    const matched = try plan(std.testing.allocator, &index, .{
        .target = "127.0.0.1:1",
        .service = "http",
        .product = "drupal",
        .version = "7.57",
        .cves = &.{},
    }, 1);
    var matched_plan = matched;
    defer matched_plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), matched_plan.steps.len);
    try std.testing.expectError(error.NoExploitableChain, plan(std.testing.allocator, &index, .{
        .target = "127.0.0.1:1",
        .service = "http",
        .product = "wordpress",
        .version = "6.0",
        .cves = &.{},
    }, 1));
}

test "a CVE hit overrides missing fingerprint fields" {
    const records = [_]Record{
        .{ .path = "drupal.json", .cve = "CVE-2018-7600", .target = "old", .effect = .command, .service = "http", .product = "drupal", .version_prefix = "7.57", .digest = "d" },
    };
    var index = Index{ .arena = undefined, .records = @constCast(&records) };
    var result = try plan(std.testing.allocator, &index, .{
        .target = "127.0.0.1:18401",
        .service = "",
        .product = "",
        .version = "",
        .cves = &.{"CVE-2018-7600"},
    }, 1);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.steps.len);
}
