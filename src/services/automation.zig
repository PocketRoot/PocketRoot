const std = @import("std");
const capability = @import("../core/capability.zig");
const workflow = @import("workflow.zig");

pub const max_actions = 256;

/// Script "emit" directives are carried as actions so they keep their position in
/// the workflow order, but they never reach the capability service.
pub const Emit = struct {
    severity: []const u8 = "info",
    message: []const u8 = "",
    payload: []const u8 = "",
    /// Variable paths resolved when the emit step runs. A missing path fails the step
    /// instead of emitting an empty field, so a typo cannot silently change a finding.
    severity_ref: ?[]const u8 = null,
    message_ref: ?[]const u8 = null,
    payload_ref: ?[]const u8 = null,
};

pub const Emitted = struct {
    severity: []const u8,
    message: []const u8,
    payload: []const u8,
};

pub const CompareOp = enum { eq, neq, lt, lte, gt, gte };

/// A condition the script layer asks the engine to evaluate against its variable store.
pub const ConditionSpec = struct {
    id: []const u8,
    variable: []const u8,
    op: CompareOp,
    literal: []const u8,
};

pub const ActionSpec = struct {
    id: []const u8,
    subject: []const u8,
    kind: capability.Kind,
    operation: capability.Operation,
    region: []const u8 = "",
    payload: []const u8 = "",
    /// Variable path that supplies the payload at execution time. Mutually exclusive
    /// with a literal payload; unresolved paths fail the action.
    payload_ref: ?[]const u8 = null,
    active_authorized: bool = false,
    /// A deliberate script failure: append an error finding, fail the step and stop the run.
    fail: ?[]const u8 = null,
    emit: ?Emit = null,
    /// Binds this action's result payload (key=value lines) to a script variable.
    bind: ?[]const u8 = null,
    /// Literal variable binding; used by unrolled loop counters. Never reaches the
    /// capability service.
    set_value: ?[]const u8 = null,
};

/// Two-phase initialization keeps workflow callbacks bound to this engine.
pub const Engine = struct {
    capabilities: *capability.Service,
    actions: []const ActionSpec,
    runner: workflow.Runner,
    next_request_id: u64 = 1,
    last_status: ?capability.Status = null,
    emitted: std.ArrayList(Emitted) = .empty,
    conditions: []const ConditionSpec = &.{},
    variables: std.StringHashMap([]const u8),

    pub fn init(
        self: *Engine,
        capabilities: *capability.Service,
        actions: []const ActionSpec,
    ) !void {
        if (actions.len > max_actions) return error.TooManyActions;
        for (actions) |action| {
            if (action.id.len == 0) return error.MissingActionId;
        }
        self.capabilities = capabilities;
        self.actions = actions;
        self.runner = workflow.Runner.init(self, executeAction, evaluateCondition);
        self.next_request_id = 1;
        self.last_status = null;
        self.emitted = .empty;
        self.conditions = &.{};
        self.variables = std.StringHashMap([]const u8).init(self.capabilities.allocator);
    }

    pub fn deinit(self: *Engine) void {
        var iterator = self.variables.iterator();
        while (iterator.next()) |entry| {
            self.capabilities.allocator.free(entry.key_ptr.*);
            self.capabilities.allocator.free(entry.value_ptr.*);
        }
        self.variables.deinit();
        self.emitted.deinit(self.capabilities.allocator);
        self.* = undefined;
    }

    pub fn setConditions(self: *Engine, conditions: []const ConditionSpec) void {
        self.conditions = conditions;
    }

    pub fn variableValue(self: *const Engine, name: []const u8) ?[]const u8 {
        return self.variables.get(name);
    }

    /// Exposes the bound variables for diagnostics; callers must not retain the iterator
    /// past the next execution step.
    pub fn variableIterator(self: *const Engine) std.StringHashMap([]const u8).Iterator {
        return self.variables.iterator();
    }

    fn storeVariable(self: *Engine, name: []const u8, value: []const u8) !void {
        const allocator = self.capabilities.allocator;
        if (self.variables.fetchRemove(name)) |old| {
            allocator.free(old.key);
            allocator.free(old.value);
        }
        const owned_key = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_key);
        const owned_value = try allocator.dupe(u8, value);
        errdefer allocator.free(owned_value);
        try self.variables.put(owned_key, owned_value);
    }

    /// Result payloads are treated as key=value lines; both the whole payload and
    /// every field are exposed as script variables (name and name.field).
    fn bindResult(self: *Engine, name: []const u8, data: []const u8) !void {
        const allocator = self.capabilities.allocator;
        try self.storeVariable(name, data);
        var lines = std.mem.splitScalar(u8, data, 0x0a);
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            const separator = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = std.mem.trim(u8, line[0..separator], " \t");
            const value = std.mem.trim(u8, line[separator + 1 ..], " \t");
            if (key.len == 0) continue;
            const full_key = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ name, key });
            defer allocator.free(full_key);
            try self.storeVariable(full_key, value);
        }
    }

    fn findCondition(self: *const Engine, id: []const u8) ?ConditionSpec {
        for (self.conditions) |spec| if (std.mem.eql(u8, spec.id, id)) return spec;
        return null;
    }

    pub fn tick(self: *Engine, definition: workflow.Definition, now_ms: u64) !workflow.Status {
        return self.runner.tick(definition, now_ms);
    }

    pub fn cancel(self: *Engine) void {
        self.runner.cancel();
    }

    pub fn emergencyStop(self: *Engine) void {
        self.runner.cancel();
        self.capabilities.emergencyStop();
    }

    /// Resolves a script variable path exactly as bound by bindResult: the whole
    /// payload under "name" and every key=value field under "name.key". An unknown path
    /// is an error, never an empty string.
    fn requireVariable(self: *Engine, path: []const u8) ![]const u8 {
        return self.variables.get(path) orelse error.UnresolvedReference;
    }

    fn executeAction(context: *anyopaque, action_id: []const u8, _: u16) !workflow.ActionState {
        const self: *Engine = @ptrCast(@alignCast(context));
        const spec = self.findAction(action_id) orelse return error.UnknownAction;
        if (spec.fail) |message| {
            try self.emitted.append(self.capabilities.allocator, .{
                .severity = "error",
                .message = message,
                .payload = "",
            });
            self.last_status = .failed;
            return .failed;
        }
        if (spec.set_value) |value| {
            try self.storeVariable(spec.bind orelse action_id, value);
            self.last_status = .succeeded;
            return .succeeded;
        }
        if (spec.emit) |emit| {
            const severity = if (emit.severity_ref) |path| try self.requireVariable(path) else emit.severity;
            const message = if (emit.message_ref) |path| try self.requireVariable(path) else emit.message;
            const payload = if (emit.payload_ref) |path| try self.requireVariable(path) else emit.payload;
            try self.emitted.append(self.capabilities.allocator, .{
                .severity = severity,
                .message = message,
                .payload = payload,
            });
            self.last_status = .succeeded;
            return .succeeded;
        }
        if (self.next_request_id == 0) return error.RequestIdExhausted;
        const request_id = self.next_request_id;
        self.next_request_id +%= 1;

        const payload = if (spec.payload_ref) |path| try self.requireVariable(path) else spec.payload;
        var result = self.capabilities.execute(.{
            .id = request_id,
            .subject = spec.subject,
            .kind = spec.kind,
            .operation = spec.operation,
            .region = spec.region,
            .payload = payload,
            .active_authorized = spec.active_authorized,
        }) catch {
            self.last_status = if (self.capabilities.audit.entries.items.len == 0)
                .failed
            else
                self.capabilities.audit.entries.items[self.capabilities.audit.entries.items.len - 1].status;
            return .failed;
        };
        defer result.deinit();
        if (result.status == .succeeded) {
            if (spec.bind) |name| try self.bindResult(name, result.data);
        }
        self.last_status = result.status;
        return switch (result.status) {
            .succeeded => .succeeded,
            else => .failed,
        };
    }

    fn evaluateCondition(context: *anyopaque, condition_id: []const u8) !bool {
        const self: *Engine = @ptrCast(@alignCast(context));
        if (std.mem.eql(u8, condition_id, "last_succeeded")) {
            return self.last_status == .succeeded;
        }
        if (std.mem.eql(u8, condition_id, "last_supported")) {
            return self.last_status != null and self.last_status != .unsupported;
        }
        const spec = self.findCondition(condition_id) orelse return error.UnknownCondition;
        const actual = self.variables.get(spec.variable) orelse "";
        return compareValues(actual, spec.op, spec.literal);
    }

    fn compareValues(actual: []const u8, op: CompareOp, literal: []const u8) bool {
        switch (op) {
            .eq => return std.mem.eql(u8, actual, literal),
            .neq => return !std.mem.eql(u8, actual, literal),
            else => {},
        }
        const left = std.fmt.parseFloat(f64, actual) catch return false;
        const right = std.fmt.parseFloat(f64, literal) catch return false;
        return switch (op) {
            .lt => left < right,
            .lte => left <= right,
            .gt => left > right,
            .gte => left >= right,
            else => false,
        };
    }

    fn findAction(self: *const Engine, id: []const u8) ?ActionSpec {
        for (self.actions) |action| if (std.mem.eql(u8, action.id, id)) return action;
        return null;
    }
};

const simulated_device = @import("../simulator/device.zig");

test "automation routes actions through capabilities and audit" {
    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.infrared);

    const actions = [_]ActionSpec{.{
        .id = "read_ir",
        .subject = "workflow:demo",
        .kind = .infrared,
        .operation = .read,
    }};
    var engine: Engine = undefined;
    try engine.init(&harness.capabilities, &actions);
    const steps = [_]workflow.Step{
        .{ .action = .{ .id = "read_ir" } },
        .{ .condition = .{ .id = "last_succeeded", .if_true = 2, .if_false = 0 } },
    };
    const definition = workflow.Definition{ .id = "demo", .steps = &steps };

    try std.testing.expectEqual(workflow.Status.running, try engine.tick(definition, 0));
    try std.testing.expectEqual(workflow.Status.succeeded, try engine.tick(definition, 1));
    try std.testing.expectEqual(@as(usize, 1), harness.capabilities.audit.entries.items.len);
    try std.testing.expectEqual(capability.Status.succeeded, harness.capabilities.audit.entries.items[0].status);
}

test "automation cannot bypass active-operation policy" {
    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.infrared);

    const actions = [_]ActionSpec{.{
        .id = "transmit_ir",
        .subject = "workflow:denied",
        .kind = .infrared,
        .operation = .transmit,
        .active_authorized = true,
    }};
    var engine: Engine = undefined;
    try engine.init(&harness.capabilities, &actions);
    const steps = [_]workflow.Step{.{ .action = .{ .id = "transmit_ir" } }};

    try std.testing.expectEqual(workflow.Status.failed, try engine.tick(.{ .id = "denied", .steps = &steps }, 0));
    try std.testing.expectEqual(capability.Status.denied, harness.capabilities.audit.entries.items[0].status);
}
