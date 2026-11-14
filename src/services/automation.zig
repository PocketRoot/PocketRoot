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
};

pub const Emitted = struct {
    severity: []const u8,
    message: []const u8,
    payload: []const u8,
};

pub const ActionSpec = struct {
    id: []const u8,
    subject: []const u8,
    kind: capability.Kind,
    operation: capability.Operation,
    region: []const u8 = "",
    payload: []const u8 = "",
    active_authorized: bool = false,
    emit: ?Emit = null,
};

/// Two-phase initialization keeps workflow callbacks bound to this engine.
pub const Engine = struct {
    capabilities: *capability.Service,
    actions: []const ActionSpec,
    runner: workflow.Runner,
    next_request_id: u64 = 1,
    last_status: ?capability.Status = null,
    emitted: std.ArrayList(Emitted) = .empty,

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
    }

    pub fn deinit(self: *Engine) void {
        self.emitted.deinit(self.capabilities.allocator);
        self.* = undefined;
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

    fn executeAction(context: *anyopaque, action_id: []const u8, _: u16) !workflow.ActionState {
        const self: *Engine = @ptrCast(@alignCast(context));
        const spec = self.findAction(action_id) orelse return error.UnknownAction;
        if (spec.emit) |emit| {
            try self.emitted.append(self.capabilities.allocator, .{
                .severity = emit.severity,
                .message = emit.message,
                .payload = emit.payload,
            });
            self.last_status = .succeeded;
            return .succeeded;
        }
        if (self.next_request_id == 0) return error.RequestIdExhausted;
        const request_id = self.next_request_id;
        self.next_request_id +%= 1;

        var result = self.capabilities.execute(.{
            .id = request_id,
            .subject = spec.subject,
            .kind = spec.kind,
            .operation = spec.operation,
            .region = spec.region,
            .payload = spec.payload,
            .active_authorized = spec.active_authorized,
        }) catch {
            self.last_status = if (self.capabilities.audit.entries.items.len == 0)
                .failed
            else
                self.capabilities.audit.entries.items[self.capabilities.audit.entries.items.len - 1].status;
            return .failed;
        };
        defer result.deinit();
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
        return error.UnknownCondition;
    }

    fn findAction(self: *const Engine, id: []const u8) ?ActionSpec {
        for (self.actions) |action| if (std.mem.eql(u8, action.id, id)) return action;
        return null;
    }
};

const simulated_device = @import("../simulator/device.zig");

test "automation routes actions through capabilities and audit" {
    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{});
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
    harness.init(std.testing.allocator, .{});
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
