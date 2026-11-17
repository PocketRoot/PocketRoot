//! Multi-target adaptive campaign. Each target has its own approval, runs its own
//! adaptive goal, and failures are isolated per target. Targets execute in bounded
//! batches; the shared ledger is serialized and STOP is checked between batches/modules.

const std = @import("std");
const control = @import("control.zig");
const adaptive = @import("adaptive.zig");
const chain_exec = @import("chain_exec.zig");

pub const max_targets = 64;

pub const Fleet = struct {
    arena: std.heap.ArenaAllocator,
    id: []const u8,
    goal_path: []const u8,
    targets: []const []const u8,
    max_concurrency: u8,

    pub fn deinit(self: *Fleet) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const Wire = struct {
    schema: []const u8 = "",
    id: []const u8 = "",
    goal: []const u8 = "",
    targets: []const []const u8 = &.{},
    max_concurrency: u8 = 1,
};

pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Fleet {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(256 * 1024));
    const wire = std.json.parseFromSliceLeaky(Wire, a, data, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidFleet;
    if (!std.mem.eql(u8, wire.schema, "pocketroot.fleet.v1")) return error.InvalidFleet;
    if (wire.id.len == 0 or wire.goal.len == 0) return error.InvalidFleet;
    if (wire.targets.len == 0 or wire.targets.len > max_targets) return error.InvalidFleet;
    const targets = try a.alloc([]const u8, wire.targets.len);
    for (wire.targets, 0..) |target, i| {
        if (target.len == 0) return error.InvalidFleet;
        for (targets[0..i]) |previous| {
            if (std.mem.eql(u8, previous, target)) return error.InvalidFleet;
        }
        targets[i] = target;
    }
    if (wire.max_concurrency == 0 or wire.max_concurrency > 16) return error.InvalidFleet;
    return .{
        .arena = arena,
        .id = wire.id,
        .goal_path = wire.goal,
        .targets = targets,
        .max_concurrency = wire.max_concurrency,
    };
}

pub fn actionId(allocator: std.mem.Allocator, goal_id: []const u8, target: []const u8) ![]u8 {
    const digest = try control.sha256Hex(allocator, target);
    defer allocator.free(digest);
    return std.fmt.allocPrint(allocator, "ADAPT-{s}@{s}", .{ goal_id, digest[0..8] });
}

pub fn approve(
    allocator: std.mem.Allocator,
    io: std.Io,
    fleet_path: []const u8,
    campaign_dir: []const u8,
    target: []const u8,
    operator: []const u8,
    reason: []const u8,
) !control.Approval {
    var fleet = try load(allocator, io, fleet_path);
    defer fleet.deinit();
    var known = false;
    for (fleet.targets) |item| {
        if (std.mem.eql(u8, item, target)) known = true;
    }
    if (!known) return error.TargetNotInFleet;
    const goal_data = try std.Io.Dir.cwd().readFileAlloc(io, fleet.goal_path, allocator, .limited(256 * 1024));
    defer allocator.free(goal_data);
    var goal = try adaptive.parseGoal(allocator, goal_data);
    defer goal.deinit();
    try adaptive.resolve(&goal, io);
    const hash = try adaptive.goalHash(allocator, io, goal_data, &goal);
    defer allocator.free(hash);
    const id = try actionId(allocator, goal.id, target);
    defer allocator.free(id);

    const scope_path = try std.fs.path.join(allocator, &.{ campaign_dir, "scope.json" });
    defer allocator.free(scope_path);
    const scope_data = try std.Io.Dir.cwd().readFileAlloc(io, scope_path, allocator, .limited(256 * 1024));
    defer allocator.free(scope_data);
    var scope = try control.parseScope(allocator, scope_data);
    defer scope.deinit();
    var state = try control.loadState(allocator, io, campaign_dir);
    defer state.deinit();
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    var approval = try control.createApproval(allocator, io, campaign_dir, &scope, .{
        .action_id = id,
        .target = target,
        .technique = .exploit,
        .params_hash = hash,
    }, operator, reason, now);
    errdefer approval.deinit();
    try control.appendLedger(allocator, io, campaign_dir, .{
        .event = "approve",
        .action_id = id,
        .approval_id = approval.id,
        .target = target,
        .technique = "exploit",
        .result = "approved",
        .detail = reason,
    }, now);
    return approval;
}

const TargetOutcome = struct {
    target: []const u8,
    status: []const u8,
    execution: ?adaptive.Execution = null,
};

fn runTarget(
    goal: *const adaptive.Goal,
    goal_data: []const u8,
    campaign_dir: []const u8,
    target: []const u8,
    action_id: []const u8,
    arena: *std.heap.ArenaAllocator,
    io: std.Io,
    outcome: *TargetOutcome,
) void {
    const execution = adaptive.runForTarget(
        arena.allocator(),
        io,
        goal_data,
        goal,
        campaign_dir,
        target,
        action_id,
    ) catch |err| {
        outcome.status = if (chain_exec.isDenial(err)) "denied" else @errorName(err);
        return;
    };
    outcome.execution = execution;
    outcome.status = execution.status;
}

pub const Execution = struct {
    allocator: std.mem.Allocator,
    fleet_id: []u8,
    goal_path: []u8,
    outcomes: []TargetOutcome,
    arenas: []std.heap.ArenaAllocator,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.fleet_id);
        self.allocator.free(self.goal_path);
        for (self.outcomes) |*outcome| {
            if (outcome.execution) |*execution| execution.deinit();
        }
        self.allocator.free(self.outcomes);
        for (self.arenas) |*arena| arena.deinit();
        self.allocator.free(self.arenas);
        self.* = undefined;
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    fleet_path: []const u8,
    campaign_dir: []const u8,
    concurrency_override: ?u8,
) !Execution {
    var fleet = try load(allocator, io, fleet_path);
    defer fleet.deinit();
    const goal_data = try std.Io.Dir.cwd().readFileAlloc(io, fleet.goal_path, allocator, .limited(256 * 1024));
    defer allocator.free(goal_data);
    var goal = try adaptive.parseGoal(allocator, goal_data);
    defer goal.deinit();
    try adaptive.resolve(&goal, io);

    const concurrency = @min(
        concurrency_override orelse fleet.max_concurrency,
        fleet.max_concurrency,
    );
    if (concurrency == 0) return error.InvalidConcurrency;

    const outcomes = try allocator.alloc(TargetOutcome, fleet.targets.len);
    errdefer allocator.free(outcomes);
    const goals = try allocator.alloc(adaptive.Goal, fleet.targets.len);
    defer allocator.free(goals);
    const arenas = try allocator.alloc(std.heap.ArenaAllocator, fleet.targets.len);
    const action_ids = try allocator.alloc([]u8, fleet.targets.len);
    defer {
        for (action_ids) |id| allocator.free(id);
        allocator.free(action_ids);
    }
    for (fleet.targets, 0..) |target, i| {
        goals[i] = goal;
        goals[i].target = target;
        arenas[i] = std.heap.ArenaAllocator.init(allocator);
        action_ids[i] = try actionId(allocator, goal.id, target);
        outcomes[i] = .{ .target = target, .status = "pending" };
    }
    var start: usize = 0;
    while (start < fleet.targets.len) {
        if (control.isStopped(allocator, io, campaign_dir)) {
            for (outcomes[start..]) |*outcome| outcome.status = "stopped";
            break;
        }
        const count = @min(@as(usize, concurrency), fleet.targets.len - start);
        var group: std.Io.Group = .init;
        errdefer group.cancel(io);
        for (0..count) |offset| {
            const index = start + offset;
            try group.concurrent(io, runTarget, .{
                &goals[index],
                goal_data,
                campaign_dir,
                fleet.targets[index],
                action_ids[index],
                &arenas[index],
                io,
                &outcomes[index],
            });
        }
        try group.await(io);
        start += count;
    }

    return .{
        .allocator = allocator,
        .fleet_id = try allocator.dupe(u8, fleet.id),
        .goal_path = try allocator.dupe(u8, fleet.goal_path),
        .outcomes = outcomes,
        .arenas = arenas,
    };
}

pub fn writeEvidence(writer: *std.Io.Writer, execution: *const Execution, now: i64) !void {
    const StepWire = struct {
        module: []const u8,
        cve: []const u8,
        oracle: []const u8,
        output: []const u8,
    };
    const TargetWire = struct {
        target: []const u8,
        status: []const u8,
        approval_id: []const u8,
        steps: []const StepWire,
        facts: []const u8,
    };
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wire = try a.alloc(TargetWire, execution.outcomes.len);
    for (execution.outcomes, 0..) |outcome, i| {
        if (outcome.execution) |executed| {
            const steps = try a.alloc(StepWire, executed.steps.len);
            for (executed.steps, 0..) |step, j| {
                steps[j] = .{
                    .module = step.module_id,
                    .cve = step.cve,
                    .oracle = if (step.oracle_pass) "pass" else "fail",
                    .output = step.output,
                };
            }
            wire[i] = .{
                .target = outcome.target,
                .status = outcome.status,
                .approval_id = executed.approval_id,
                .steps = steps,
                .facts = executed.facts_output,
            };
        } else {
            wire[i] = .{
                .target = outcome.target,
                .status = outcome.status,
                .approval_id = "",
                .steps = &.{},
                .facts = "",
            };
        }
    }
    const EvidenceWire = struct {
        schema: []const u8,
        id: []const u8,
        goal: []const u8,
        targets: []const TargetWire,
        recorded_at_unix: i64,
    };
    var json: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.write(EvidenceWire{
        .schema = "pocketroot.fleet.evidence.v1",
        .id = execution.fleet_id,
        .goal = execution.goal_path,
        .targets = wire,
        .recorded_at_unix = now,
    });
    try writer.writeByte('\n');
}

test "fleet action ids are distinct per target" {
    const a = try actionId(std.testing.allocator, "ADAPT-X", "127.0.0.1:8080");
    defer std.testing.allocator.free(a);
    const b = try actionId(std.testing.allocator, "ADAPT-X", "127.0.0.1:8081");
    defer std.testing.allocator.free(b);
    try std.testing.expect(!std.mem.eql(u8, a, b));
    try std.testing.expect(std.mem.startsWith(u8, a, "ADAPT-ADAPT-X@"));
}
