const std = @import("std");

pub const Status = enum {
    ready,
    running,
    succeeded,
    failed,
    cancelled,

    pub fn terminal(self: Status) bool {
        return switch (self) {
            .succeeded, .failed, .cancelled => true,
            else => false,
        };
    }
};

pub const ActionState = enum {
    pending,
    succeeded,
    failed,
    cancelled,
};

pub const Action = struct {
    id: []const u8,
    max_attempts: u16 = 1,
    timeout_ms: u64 = 30_000,
};

pub const Condition = struct {
    id: []const u8,
    if_true: usize,
    if_false: usize,
};

pub const Step = union(enum) {
    action: Action,
    condition: Condition,
    delay_ms: u64,
};

pub const Definition = struct {
    id: []const u8,
    steps: []const Step,
};

pub const State = struct {
    status: Status = .ready,
    step_index: usize = 0,
    attempt: u16 = 0,
    step_started_ms: ?u64 = null,
    workflow_hash: u64 = 0,

    pub fn checkpoint(self: State, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(
            allocator,
            "2|{d}|{d}|{d}|{d}|{d}",
            .{
                @intFromEnum(self.status),
                self.step_index,
                self.attempt,
                self.step_started_ms orelse std.math.maxInt(u64),
                self.workflow_hash,
            },
        );
    }

    pub fn restore(checkpoint_text: []const u8) !State {
        var parts = std.mem.splitScalar(u8, checkpoint_text, '|');
        if (!std.mem.eql(u8, parts.next() orelse return error.InvalidCheckpoint, "2")) {
            return error.UnsupportedCheckpointVersion;
        }

        const status_value = try parse(u8, parts.next());
        if (status_value >= std.meta.fields(Status).len) return error.InvalidCheckpoint;
        const step_index = try parse(usize, parts.next());
        const attempt = try parse(u16, parts.next());
        const started = try parse(u64, parts.next());
        const workflow_hash = try parse(u64, parts.next());
        if (parts.next() != null) return error.InvalidCheckpoint;

        return .{
            .status = @enumFromInt(status_value),
            .step_index = step_index,
            .attempt = attempt,
            .step_started_ms = if (started == std.math.maxInt(u64)) null else started,
            .workflow_hash = workflow_hash,
        };
    }

    fn parse(comptime T: type, value: ?[]const u8) !T {
        return std.fmt.parseInt(T, value orelse return error.InvalidCheckpoint, 10) catch {
            return error.InvalidCheckpoint;
        };
    }
};

pub const ActionFn = *const fn (
    context: *anyopaque,
    action_id: []const u8,
    attempt: u16,
) anyerror!ActionState;

pub const ConditionFn = *const fn (
    context: *anyopaque,
    condition_id: []const u8,
) anyerror!bool;

pub const Runner = struct {
    context: *anyopaque,
    action_fn: ActionFn,
    condition_fn: ConditionFn,
    state: State = .{},

    pub fn init(context: *anyopaque, action_fn: ActionFn, condition_fn: ConditionFn) Runner {
        return .{
            .context = context,
            .action_fn = action_fn,
            .condition_fn = condition_fn,
        };
    }

    pub fn fromCheckpoint(
        context: *anyopaque,
        action_fn: ActionFn,
        condition_fn: ConditionFn,
        checkpoint_text: []const u8,
    ) !Runner {
        var runner = init(context, action_fn, condition_fn);
        runner.state = try State.restore(checkpoint_text);
        return runner;
    }

    pub fn cancel(self: *Runner) void {
        if (!self.state.status.terminal()) self.state.status = .cancelled;
    }

    pub fn tick(self: *Runner, definition: Definition, now_ms: u64) !Status {
        if (definition.id.len == 0) return error.MissingWorkflowId;
        const definition_hash = std.hash.Wyhash.hash(0, definition.id);
        if (self.state.workflow_hash == 0) {
            self.state.workflow_hash = definition_hash;
        } else if (self.state.workflow_hash != definition_hash) {
            return error.CheckpointWorkflowMismatch;
        }
        if (self.state.status.terminal()) return self.state.status;
        if (self.state.step_index > definition.steps.len) return error.InvalidCheckpoint;
        if (self.state.step_index == definition.steps.len) {
            self.state.status = .succeeded;
            return self.state.status;
        }

        self.state.status = .running;
        switch (definition.steps[self.state.step_index]) {
            .action => |action| try self.tickAction(action, now_ms),
            .condition => |condition| try self.tickCondition(condition, definition.steps.len),
            .delay_ms => |duration_ms| try self.tickDelay(duration_ms, now_ms),
        }
        return self.state.status;
    }

    fn tickAction(self: *Runner, action: Action, now_ms: u64) !void {
        if (action.id.len == 0) return error.MissingActionId;
        if (action.max_attempts == 0) return error.InvalidAttemptLimit;
        const started = self.state.step_started_ms orelse now_ms;
        self.state.step_started_ms = started;
        if (now_ms < started) return error.ClockMovedBackward;

        if (action.timeout_ms != 0 and now_ms - started >= action.timeout_ms) {
            self.retryOrFail(action.max_attempts);
            return;
        }

        const outcome = self.action_fn(self.context, action.id, self.state.attempt) catch {
            self.retryOrFail(action.max_attempts);
            return;
        };
        switch (outcome) {
            .pending => {},
            .succeeded => self.advance(),
            .failed => self.retryOrFail(action.max_attempts),
            .cancelled => self.cancel(),
        }
    }

    fn tickCondition(self: *Runner, condition: Condition, step_count: usize) !void {
        if (condition.id.len == 0) return error.MissingConditionId;
        const target = if (try self.condition_fn(self.context, condition.id))
            condition.if_true
        else
            condition.if_false;
        if (target > step_count) return error.InvalidBranchTarget;
        self.state.step_index = target;
        self.state.attempt = 0;
        self.state.step_started_ms = null;
        if (target == step_count) self.state.status = .succeeded;
    }

    fn tickDelay(self: *Runner, duration_ms: u64, now_ms: u64) !void {
        const started = self.state.step_started_ms orelse now_ms;
        self.state.step_started_ms = started;
        if (now_ms < started) return error.ClockMovedBackward;
        if (now_ms - started >= duration_ms) self.advance();
    }

    fn retryOrFail(self: *Runner, max_attempts: u16) void {
        if (self.state.attempt + 1 < max_attempts) {
            self.state.attempt += 1;
            self.state.step_started_ms = null;
        } else {
            self.state.status = .failed;
        }
    }

    fn advance(self: *Runner) void {
        self.state.step_index += 1;
        self.state.attempt = 0;
        self.state.step_started_ms = null;
    }
};

const TestContext = struct {
    calls: usize = 0,
    condition: bool = true,

    fn action(context: *anyopaque, _: []const u8, attempt: u16) !ActionState {
        const self: *TestContext = @ptrCast(@alignCast(context));
        self.calls += 1;
        return if (attempt == 0) .failed else .succeeded;
    }

    fn pending(_: *anyopaque, _: []const u8, _: u16) !ActionState {
        return .pending;
    }

    fn evaluate(context: *anyopaque, _: []const u8) !bool {
        const self: *TestContext = @ptrCast(@alignCast(context));
        return self.condition;
    }
};

test "workflow retries actions and completes sequentially" {
    var context = TestContext{};
    var runner = Runner.init(&context, TestContext.action, TestContext.evaluate);
    const steps = [_]Step{.{ .action = .{ .id = "capture", .max_attempts = 2 } }};
    const definition = Definition{ .id = "demo", .steps = &steps };

    try std.testing.expectEqual(Status.running, try runner.tick(definition, 0));
    try std.testing.expectEqual(@as(u16, 1), runner.state.attempt);
    try std.testing.expectEqual(Status.running, try runner.tick(definition, 1));
    try std.testing.expectEqual(Status.succeeded, try runner.tick(definition, 2));
    try std.testing.expectEqual(@as(usize, 2), context.calls);
}

test "workflow times out pending actions" {
    var context = TestContext{};
    var runner = Runner.init(&context, TestContext.pending, TestContext.evaluate);
    const steps = [_]Step{.{ .action = .{
        .id = "wait",
        .max_attempts = 2,
        .timeout_ms = 10,
    } }};
    const definition = Definition{ .id = "timeout", .steps = &steps };

    _ = try runner.tick(definition, 0);
    _ = try runner.tick(definition, 10);
    try std.testing.expectEqual(@as(u16, 1), runner.state.attempt);
    _ = try runner.tick(definition, 11);
    try std.testing.expectEqual(Status.failed, try runner.tick(definition, 21));
}

test "workflow branches and restores checkpoints" {
    var context = TestContext{ .condition = false };
    var runner = Runner.init(&context, TestContext.action, TestContext.evaluate);
    const steps = [_]Step{
        .{ .condition = .{ .id = "allowed", .if_true = 1, .if_false = 2 } },
        .{ .delay_ms = 100 },
    };
    const definition = Definition{ .id = "branch", .steps = &steps };

    try std.testing.expectEqual(Status.succeeded, try runner.tick(definition, 0));
    const saved = try runner.state.checkpoint(std.testing.allocator);
    defer std.testing.allocator.free(saved);
    var restored = try Runner.fromCheckpoint(&context, TestContext.action, TestContext.evaluate, saved);
    try std.testing.expectEqual(Status.succeeded, restored.state.status);
    try std.testing.expectEqual(@as(usize, 2), restored.state.step_index);
    try std.testing.expectError(
        error.CheckpointWorkflowMismatch,
        restored.tick(.{ .id = "different", .steps = &steps }, 1),
    );
}

test "workflow cancellation is terminal" {
    var context = TestContext{};
    var runner = Runner.init(&context, TestContext.pending, TestContext.evaluate);
    runner.cancel();
    const steps = [_]Step{.{ .action = .{ .id = "never" } }};
    try std.testing.expectEqual(Status.cancelled, try runner.tick(.{ .id = "cancel", .steps = &steps }, 0));
    try std.testing.expectEqual(@as(usize, 0), context.calls);
}
