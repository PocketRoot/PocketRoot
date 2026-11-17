//! Campaign-gated chain execution shared by the CLI and the kernel exploit capability.
//!
//! One approval covers a digest-bound plan. The executor re-checks every record digest,
//! checks STOP before and after each step and never mints per-record approvals.

const std = @import("std");
const control = @import("control.zig");
const chain = @import("chain.zig");
const exploit = @import("exploit.zig");

pub const StepResult = struct {
    cve: []const u8,
    effect: exploit.Effect,
    status: []const u8,
    bytes: usize,
};

pub const Execution = struct {
    allocator: std.mem.Allocator,
    plan_id: []u8,
    approval_id: []u8,
    status: []u8,
    output: []u8,
    steps: []StepResult,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.plan_id);
        self.allocator.free(self.approval_id);
        self.allocator.free(self.status);
        self.allocator.free(self.output);
        for (self.steps) |step| {
            self.allocator.free(step.cve);
            self.allocator.free(step.status);
        }
        self.allocator.free(self.steps);
        self.* = undefined;
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    plan_path: []const u8,
    campaign_dir: []const u8,
) !Execution {
    const plan_data = try std.Io.Dir.cwd().readFileAlloc(io, plan_path, allocator, .limited(256 * 1024));
    defer allocator.free(plan_data);
    var plan = try chain.loadPlan(allocator, io, plan_path);
    defer plan.deinit();

    const scope_path = try std.fs.path.join(allocator, &.{ campaign_dir, "scope.json" });
    defer allocator.free(scope_path);
    const scope_data = try std.Io.Dir.cwd().readFileAlloc(io, scope_path, allocator, .limited(256 * 1024));
    defer allocator.free(scope_data);
    var scope = try control.parseScope(allocator, scope_data);
    defer scope.deinit();
    var state = try control.loadState(allocator, io, campaign_dir);
    defer state.deinit();
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const params_hash = try control.sha256Hex(allocator, plan_data);
    defer allocator.free(params_hash);
    try control.evaluate(allocator, io, campaign_dir, &scope, &state, .{
        .action_id = plan.id,
        .target = plan.target,
        .technique = .exploit,
        .params_hash = params_hash,
    }, now);

    const approval_file = try control.approvalPath(allocator, campaign_dir, plan.id);
    defer allocator.free(approval_file);
    var approval = control.loadApproval(allocator, io, approval_file) catch |err| switch (err) {
        error.FileNotFound => return error.approval_missing,
        else => return err,
    };
    defer approval.deinit();
    try control.consumeApproval(allocator, io, approval_file, now);
    try control.appendLedger(allocator, io, campaign_dir, .{
        .event = "chain-start",
        .action_id = plan.id,
        .approval_id = approval.id,
        .target = plan.target,
        .technique = "exploit",
        .result = "started",
        .detail = plan.id,
    }, now);

    var status: []const u8 = "succeeded";
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var steps: std.ArrayList(StepResult) = .empty;
    defer steps.deinit(allocator);
    var executed: usize = 0;
    for (plan.steps) |step| {
        if (control.isStopped(allocator, io, campaign_dir)) {
            status = "stopped";
            break;
        }
        const record_data = std.Io.Dir.cwd().readFileAlloc(io, step.record_path, allocator, .limited(256 * 1024)) catch |err| {
            status = @errorName(err);
            break;
        };
        defer allocator.free(record_data);
        const digest = try control.sha256Hex(allocator, record_data);
        defer allocator.free(digest);
        if (!std.mem.eql(u8, digest, step.digest)) {
            status = "record_changed";
            break;
        }
        var spec = exploit.parseSpec(allocator, record_data) catch |err| {
            status = @errorName(err);
            break;
        };
        defer spec.deinit();
        spec.target = step.target;
        var outcome = exploit.run(allocator, io, &spec, spec.params) catch |err| {
            status = @errorName(err);
            break;
        };
        defer outcome.deinit();
        executed += 1;
        try output.appendSlice(allocator, outcome.output);
        try output.append(allocator, '\n');
        try steps.append(allocator, .{
            .cve = try allocator.dupe(u8, step.cve),
            .effect = step.effect,
            .status = try allocator.dupe(u8, if (outcome.oracle_pass) "pass" else "fail"),
            .bytes = outcome.output.len,
        });
        try control.appendLedger(allocator, io, campaign_dir, .{
            .event = "chain-step",
            .action_id = plan.id,
            .approval_id = approval.id,
            .target = plan.target,
            .technique = "exploit",
            .result = if (outcome.oracle_pass) "succeeded" else "failed",
            .detail = step.cve,
        }, std.Io.Timestamp.now(io, .real).toSeconds());
        if (!outcome.oracle_pass) {
            status = "failed";
            break;
        }
        if (control.isStopped(allocator, io, campaign_dir)) {
            status = "stopped";
            break;
        }
    }
    try control.appendLedger(allocator, io, campaign_dir, .{
        .event = "chain-result",
        .action_id = plan.id,
        .approval_id = approval.id,
        .target = plan.target,
        .technique = "exploit",
        .result = status,
        .detail = plan.id,
    }, std.Io.Timestamp.now(io, .real).toSeconds());

    return .{
        .allocator = allocator,
        .plan_id = try allocator.dupe(u8, plan.id),
        .approval_id = try allocator.dupe(u8, approval.id),
        .status = try allocator.dupe(u8, status),
        .output = try output.toOwnedSlice(allocator),
        .steps = try steps.toOwnedSlice(allocator),
    };
}

pub fn writeEvidence(
    writer: *std.Io.Writer,
    plan: *const chain.Plan,
    execution: *const Execution,
    now: i64,
) !void {
    const StepWire = struct {
        cve: []const u8,
        effect: []const u8,
        status: []const u8,
        bytes: usize,
    };
    const Wire = struct {
        schema: []const u8,
        id: []const u8,
        target: []const u8,
        status: []const u8,
        action_id: []const u8,
        approval_id: []const u8,
        output: []const u8,
        steps: []const StepWire,
        recorded_at_unix: i64,
    };
    const step_wires = try std.heap.page_allocator.alloc(StepWire, execution.steps.len);
    defer std.heap.page_allocator.free(step_wires);
    for (execution.steps, 0..) |step, i| {
        step_wires[i] = .{
            .cve = step.cve,
            .effect = @tagName(step.effect),
            .status = step.status,
            .bytes = step.bytes,
        };
    }
    var json: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.write(Wire{
        .schema = "pocketroot.chain.evidence.v1",
        .id = plan.id,
        .target = plan.target,
        .status = execution.status,
        .action_id = plan.id,
        .approval_id = execution.approval_id,
        .output = execution.output,
        .steps = step_wires,
        .recorded_at_unix = now,
    });
    try writer.writeByte('\n');
}

pub fn isDenial(err: anyerror) bool {
    return switch (err) {
        error.stopped,
        error.disarmed,
        error.scope_expired,
        error.target_not_allowed,
        error.technique_not_allowed,
        error.approval_missing,
        error.approval_invalid,
        error.state_scope_mismatch,
        error.approval_expired,
        error.approval_used,
        error.approval_scope_mismatch,
        error.approval_action_mismatch,
        error.approval_target_mismatch,
        error.approval_params_mismatch,
        error.approval_technique_mismatch,
        error.budget_exhausted,
        => true,
        else => false,
    };
}

test "denial classification covers campaign refusals" {
    try std.testing.expect(isDenial(error.approval_used));
    try std.testing.expect(!isDenial(error.OutOfMemory));
}
