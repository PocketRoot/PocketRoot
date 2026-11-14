//! Stage S2: compile a validated pocketroot.script.v1 AST into workflow steps and
//! automation action specs, then drive it through the existing workflow runner.
//!
//! The DSL is a front-end compiler, not a second executor: retries, checkpoints,
//! cancellation and audit all stay in workflow/automation/capability.

const std = @import("std");
const Allocator = std.mem.Allocator;
const capability = @import("../core/capability.zig");
const automation = @import("automation.zig");
const script = @import("script.zig");
const workflow = @import("workflow.zig");

pub const subject_prefix = "script:";
pub const max_ticks = 4096;

pub const Error = error{
    OutOfMemory,
    UnsupportedVerb,
    MissingCapability,
    TickBudgetExceeded,
};

/// The embedder (CLI / tests) stamps authorization decisions that a script must not
/// be able to grant itself: active-operation consent and the policy region.
pub const CompileOptions = struct {
    authorize_active: bool = false,
    policy_region: []const u8 = "",
};

pub const VerbMapping = struct {
    verb: []const u8,
    kind: capability.Kind,
    operation: capability.Operation,
};

pub const verb_map = [_]VerbMapping{
    .{ .verb = "subghz.read", .kind = .subghz, .operation = .read },
    .{ .verb = "subghz.transmit", .kind = .subghz, .operation = .transmit },
    .{ .verb = "nfc.read", .kind = .nfc, .operation = .read },
    .{ .verb = "nfc.emulate", .kind = .nfc, .operation = .emulate },
    .{ .verb = "ir.receive", .kind = .infrared, .operation = .capture },
    .{ .verb = "ir.transmit", .kind = .infrared, .operation = .transmit },
    .{ .verb = "lfrfid.read", .kind = .lfrfid, .operation = .read },
    .{ .verb = "ibutton.read", .kind = .ibutton, .operation = .read },
    .{ .verb = "net.capture", .kind = .network, .operation = .capture },
    .{ .verb = "net.tls", .kind = .network, .operation = .analyze },
    .{ .verb = "net.scan", .kind = .network, .operation = .analyze },
    .{ .verb = "fs.read", .kind = .storage, .operation = .read },
    .{ .verb = "fs.write", .kind = .storage, .operation = .write },
};

pub fn verbMapping(verb: []const u8) ?VerbMapping {
    for (verb_map) |item| if (std.mem.eql(u8, item.verb, verb)) return item;
    return null;
}

pub const Compiled = struct {
    arena: std.heap.ArenaAllocator,
    definition: workflow.Definition,
    actions: []automation.ActionSpec,

    pub fn deinit(self: *Compiled) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn compile(allocator: Allocator, source: *const script.Script, options: CompileOptions) Error!Compiled {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const subject = try std.fmt.allocPrint(a, "{s}{s}", .{ subject_prefix, source.name });
    var steps: std.ArrayList(workflow.Step) = .empty;
    var actions: std.ArrayList(automation.ActionSpec) = .empty;
    var emit_count: usize = 0;

    scan: for (source.steps) |dsl_step| {
        for (dsl_step.body) |statement| {
            switch (statement) {
                .stop => break :scan,
                .call => |call| try appendCall(a, source, subject, call, options, &steps, &actions),
                .assign => |assign| try appendCall(a, source, subject, assign.call, options, &steps, &actions),
                .emit => |emit| {
                    const id = try std.fmt.allocPrint(a, "emit:{d}", .{emit_count});
                    emit_count += 1;
                    const spec = emitSpec(emit) orelse return error.MissingCapability;
                    try steps.append(a, .{ .action = .{ .id = id, .max_attempts = 1, .timeout_ms = 0 } });
                    try actions.append(a, .{
                        .id = id,
                        .subject = subject,
                        .kind = .storage,
                        .operation = .observe,
                        .payload = spec.payload,
                        .emit = spec.emit,
                    });
                },
            }
        }
    }

    if (steps.items.len == 0) return error.MissingCapability;

    return .{
        .arena = arena,
        .definition = .{
            .id = source.name,
            .steps = try steps.toOwnedSlice(a),
        },
        .actions = try actions.toOwnedSlice(a),
    };
}

const EmitSpec = struct { emit: automation.Emit, payload: []const u8 };

fn emitSpec(emit: script.Emit) ?EmitSpec {
    switch (emit) {
        .plain => |plain| return .{
            .emit = .{ .severity = severityText(plain.level), .message = plain.message },
            .payload = "",
        },
        .finding => |options| {
            var severity: []const u8 = "info";
            var message: []const u8 = "";
            var tag: []const u8 = "";
            for (options) |option| {
                const text = switch (option.value) {
                    .string => |value| value,
                    else => continue,
                };
                if (std.mem.eql(u8, option.key, "severity")) severity = text;
                if (std.mem.eql(u8, option.key, "message")) message = text;
                if (std.mem.eql(u8, option.key, "tag")) tag = text;
            }
            if (message.len == 0) return null;
            return .{
                .emit = .{ .severity = severity, .message = message },
                .payload = tag,
            };
        },
    }
}

fn severityText(level: script.Severity) []const u8 {
    return switch (level) {
        .info => "info",
        .warning => "warning",
        .err_level => "error",
        .low => "low",
        .medium => "medium",
        .high => "high",
        .critical => "critical",
        .unknown => "unknown",
    };
}

fn appendCall(
    a: Allocator,
    source: *const script.Script,
    subject: []const u8,
    call: script.Call,
    options: CompileOptions,
    steps: *std.ArrayList(workflow.Step),
    actions: *std.ArrayList(automation.ActionSpec),
) Error!void {
    const cap = source.capByName(call.cap) orelse return error.MissingCapability;
    const mapping = verbMapping(cap.verb) orelse return error.UnsupportedVerb;

    try steps.append(a, .{ .action = .{
        .id = cap.name,
        .max_attempts = attemptLimit(cap),
        .timeout_ms = 0,
    } });
    try actions.append(a, .{
        .id = cap.name,
        .subject = subject,
        .kind = mapping.kind,
        .operation = mapping.operation,
        .region = regionOption(cap, options.policy_region),
        .payload = stringOption(call.options, "payload") orelse "",
        .active_authorized = options.authorize_active,
    });
}

fn attemptLimit(cap: script.Cap) u16 {
    const text = stringOption(cap.options, "on_error") orelse return 1;
    if (!std.mem.startsWith(u8, text, "retry(")) return 1;
    const inner = text[6 .. text.len - 1];
    const parsed = std.fmt.parseInt(u16, inner, 10) catch return 1;
    if (parsed == 0) return 1;
    return parsed;
}

fn regionOption(cap: script.Cap, policy_region: []const u8) []const u8 {
    for (cap.options) |option| {
        if (!std.mem.eql(u8, option.key, "region")) continue;
        return switch (option.value) {
            .string => |value| value,
            .policy => policy_region,
            else => "",
        };
    }
    return "";
}

fn stringOption(options: []const script.Option, key: []const u8) ?[]const u8 {
    for (options) |option| {
        if (!std.mem.eql(u8, option.key, key)) continue;
        return switch (option.value) {
            .string => |value| value,
            else => null,
        };
    }
    return null;
}

const simulated_device = @import("../simulator/device.zig");

pub const Executor = struct {
    compiled: Compiled,
    engine: automation.Engine,

    /// Two-phase initialization keeps the engine's self pointer stable (moving an
    /// initialized Executor by value would leave the runner pointing at a stale copy).
    /// service must outlive the executor; source must outlive the compiled ids.
    pub fn init(
        self: *Executor,
        allocator: Allocator,
        source: *const script.Script,
        service: *capability.Service,
        options: CompileOptions,
    ) Error!void {
        self.compiled = try compile(allocator, source, options);
        self.engine.init(service, self.compiled.actions) catch |err| {
            self.compiled.deinit();
            return switch (err) {
                error.TooManyActions => error.TickBudgetExceeded,
                error.MissingActionId => error.MissingCapability,
            };
        };
    }

    pub fn deinit(self: *Executor) void {
        self.engine.deinit();
        self.compiled.deinit();
        self.* = undefined;
    }

    pub fn run(self: *Executor) !workflow.Status {
        var status = try self.engine.tick(self.compiled.definition, 0);
        var ticks: usize = 0;
        while (!status.terminal()) {
            if (ticks >= max_ticks) return error.TickBudgetExceeded;
            ticks += 1;
            status = try self.engine.tick(self.compiled.definition, 0);
        }
        return status;
    }

    pub fn emitted(self: *const Executor) []const automation.Emitted {
        return self.engine.emitted.items;
    }
};

const demo_source =
    \\script "s2-demo" do
    \\    use "pack.rf"
    \\    cap rf_capture = subghz.read
    \\    cap rf_tx = subghz.transmit { region = from_policy, on_error = "retry(3)" }
    \\    step "one" do
    \\        sig = rf_capture { payload = "alpha" }
    \\        emit finding { severity = "info", message = "captured", tag = "sig" }
    \\        rf_tx { payload = "beta" }
    \\    end
    \\end
;

test "compiles statements into workflow steps and action specs" {
    var source = try script.parse(std.testing.allocator, demo_source);
    defer source.deinit();

    var compiled = try compile(std.testing.allocator, &source, .{});
    defer compiled.deinit();

    try std.testing.expectEqualStrings("s2-demo", compiled.definition.id);
    try std.testing.expectEqual(@as(usize, 3), compiled.definition.steps.len);
    try std.testing.expectEqual(@as(usize, 3), compiled.actions.len);

    try std.testing.expectEqualStrings("rf_capture", compiled.actions[0].id);
    try std.testing.expectEqual(capability.Kind.subghz, compiled.actions[0].kind);
    try std.testing.expectEqual(capability.Operation.read, compiled.actions[0].operation);
    try std.testing.expectEqualStrings("alpha", compiled.actions[0].payload);

    try std.testing.expectEqualStrings("emit:0", compiled.actions[1].id);
    try std.testing.expect(compiled.actions[1].emit != null);
    try std.testing.expectEqualStrings("captured", compiled.actions[1].emit.?.message);
    try std.testing.expectEqualStrings("sig", compiled.actions[1].payload);

    try std.testing.expectEqual(capability.Operation.transmit, compiled.actions[2].operation);
    try std.testing.expectEqual(@as(u16, 3), compiled.definition.steps[2].action.max_attempts);
}

test "every DSL verb has a capability mapping" {
    for (verb_map) |mapping| {
        try std.testing.expect(verbMapping(mapping.verb) != null);
    }
}

test "runs a compiled script through the simulated backend and audits each capability call" {
    var source = try script.parse(std.testing.allocator, demo_source);
    defer source.deinit();

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{ .region = "EU", .allow_active = true });
    defer harness.deinit();
    harness.backend.enable(.subghz);
    const options = CompileOptions{ .authorize_active = true, .policy_region = "EU" };

    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, &source, &harness.capabilities, options);
    defer executor.deinit();

    const status = try executor.run();
    try std.testing.expectEqual(workflow.Status.succeeded, status);

    try std.testing.expectEqual(@as(usize, 2), harness.capabilities.audit.entries.items.len);
    try std.testing.expectEqualStrings("script:s2-demo", harness.capabilities.audit.entries.items[0].subject);
    try std.testing.expectEqual(capability.Status.succeeded, harness.capabilities.audit.entries.items[0].status);

    try std.testing.expectEqual(@as(usize, 1), executor.emitted().len);
    try std.testing.expectEqualStrings("captured", executor.emitted()[0].message);
    try std.testing.expectEqualStrings("info", executor.emitted()[0].severity);
}

test "stop truncates the remaining script" {
    var source = try script.parse(std.testing.allocator,
        \\script "stopper" do
        \\    cap rf_capture = subghz.read
        \\    step "one" do
        \\        rf_capture { payload = "a" }
        \\        stop
        \\        rf_capture { payload = "b" }
        \\    end
        \\end
    );
    defer source.deinit();

    var compiled = try compile(std.testing.allocator, &source, .{});
    defer compiled.deinit();
    try std.testing.expectEqual(@as(usize, 1), compiled.definition.steps.len);
}

test "active operations are denied without policy authorization" {
    var source = try script.parse(std.testing.allocator,
        \\script "tx" do
        \\    cap rf_tx = subghz.transmit
        \\    step "send" do
        \\        rf_tx { payload = "frame" }
        \\    end
        \\end
    );
    defer source.deinit();

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{});
    defer harness.deinit();
    harness.backend.enable(.subghz);
    const options = CompileOptions{};

    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, &source, &harness.capabilities, options);
    defer executor.deinit();

    const status = try executor.run();
    try std.testing.expectEqual(workflow.Status.failed, status);
    try std.testing.expectEqual(@as(usize, 1), harness.capabilities.audit.entries.items.len);
    try std.testing.expectEqual(capability.Status.denied, harness.capabilities.audit.entries.items[0].status);
}
