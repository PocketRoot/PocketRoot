//! Stage S2/S3: compile a validated pocketroot.script.v1 AST into workflow steps
//! and automation action/condition specs, then drive it through the existing runner.
//!
//! The DSL stays a front-end compiler: retries, checkpoints, cancellation and audit
//! all live in workflow/automation/capability. Branching is expressed with condition
//! steps plus trampoline jumps, and for-loops are unrolled (bounded by the parser).

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
    UnsupportedCondition,
    UnknownScript,
    ScriptCycle,
    ScriptDepthExceeded,
};

pub const max_run_depth = 8;

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

/// One entry per verb the DSL accepts (mirrors script.verbs; kept in sync by a test).
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
    conditions: []automation.ConditionSpec,

    pub fn deinit(self: *Compiled) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const Compiler = struct {
    a: Allocator,
    library: ?*const script.Library = null,
    run_stack: std.ArrayList([]const u8) = .empty,
    steps: std.ArrayList(workflow.Step) = .empty,
    actions: std.ArrayList(automation.ActionSpec) = .empty,
    conditions: std.ArrayList(automation.ConditionSpec) = .empty,
    step_ids: std.ArrayList([]const u8) = .empty,
    counter: usize = 0,

    fn nextId(self: *Compiler, prefix: []const u8) Error![]const u8 {
        const id = std.fmt.allocPrint(self.a, "{s}:{d}", .{ prefix, self.counter }) catch return error.OutOfMemory;
        self.counter += 1;
        return id;
    }

    fn addAction(
        self: *Compiler,
        id: []const u8,
        spec: automation.ActionSpec,
        attempts: u16,
    ) Error!void {
        self.steps.append(self.a, .{ .action = .{ .id = id, .max_attempts = attempts, .timeout_ms = 0 } }) catch return error.OutOfMemory;
        self.actions.append(self.a, spec) catch return error.OutOfMemory;
        self.step_ids.append(self.a, id) catch return error.OutOfMemory;
    }

    fn addCondition(self: *Compiler, spec: automation.ConditionSpec) Error!usize {
        const index = self.steps.items.len;
        self.steps.append(self.a, .{ .condition = .{ .id = spec.id, .if_true = 0, .if_false = 0 } }) catch return error.OutOfMemory;
        self.conditions.append(self.a, spec) catch return error.OutOfMemory;
        self.step_ids.append(self.a, spec.id) catch return error.OutOfMemory;
        return index;
    }

    /// A condition step whose two targets are equal acts as an unconditional jump.
    /// The runner always evaluates the condition function, so the jump still needs a
    /// spec; an empty variable compared with an empty literal evaluates to true and
    /// the target is the same either way.
    fn addJump(self: *Compiler) Error!usize {
        const id = try self.nextId("jump");
        return self.addCondition(.{ .id = id, .variable = "", .op = .eq, .literal = "" });
    }

    fn patch(self: *Compiler, index: usize, if_true: usize, if_false: usize) void {
        const id = self.step_ids.items[index];
        self.steps.items[index] = .{ .condition = .{ .id = id, .if_true = if_true, .if_false = if_false } };
    }

    fn emitCall(
        self: *Compiler,
        source: *const script.Script,
        subject: []const u8,
        options: CompileOptions,
        call: script.Call,
        bind: ?[]const u8,
    ) Error!void {
        const cap = source.capByName(call.cap) orelse return error.MissingCapability;
        const mapping = verbMapping(cap.verb) orelse return error.UnsupportedVerb;
        // Ids are per call site, not per cap name: two scripts (or two branches) may
        // declare the same name with different payloads.
        const id = try self.nextId("call");
        try self.addAction(
            id,
            .{
                .id = id,
                .subject = subject,
                .kind = mapping.kind,
                .operation = mapping.operation,
                .region = regionOption(cap, options.policy_region),
                .payload = stringOption(call.options, "payload") orelse "",
                .active_authorized = options.authorize_active,
                .bind = bind,
            },
            attemptLimit(cap),
        );
    }

    /// Inlines a sub-script: its steps are compiled into the caller in place, so
    /// retries, checkpoints and audit stay in the same workflow run. Cycles and deep
    /// nesting are rejected rather than truncated.
    fn emitRun(
        self: *Compiler,
        source: *const script.Script,
        subject: []const u8,
        options: CompileOptions,
        run: script.Run,
    ) Error!void {
        _ = source;
        _ = subject;
        const library = self.library orelse return error.UnknownScript;
        const target = library.find(run.name) orelse return error.UnknownScript;
        for (self.run_stack.items) |active| {
            if (std.mem.eql(u8, active, run.name)) return error.ScriptCycle;
        }
        if (self.run_stack.items.len >= max_run_depth) return error.ScriptDepthExceeded;
        self.run_stack.append(self.a, run.name) catch return error.OutOfMemory;
        defer _ = self.run_stack.pop();

        const sub_subject = std.fmt.allocPrint(self.a, "{s}{s}", .{ subject_prefix, target.name }) catch return error.OutOfMemory;
        for (target.steps) |step| {
            try self.emitStatements(target, sub_subject, options, step.body);
        }
    }

    fn emitStatements(
        self: *Compiler,
        source: *const script.Script,
        subject: []const u8,
        options: CompileOptions,
        statements: []script.Stmt,
    ) Error!void {
        for (statements) |statement| {
            switch (statement) {
                .stop => return,
                .out => {},
                .call => |call| try self.emitCall(source, subject, options, call, null),
                .assign => |assign| try self.emitCall(source, subject, options, assign.call, assign.name),
                .emit => |emit| {
                    const spec = emitSpec(emit) orelse return error.MissingCapability;
                    const id = try self.nextId("emit");
                    try self.addAction(id, .{
                        .id = id,
                        .subject = subject,
                        .kind = .storage,
                        .operation = .observe,
                        .payload = spec.payload,
                        .emit = spec.emit,
                    }, 1);
                },
                .run => |run| try self.emitRun(source, subject, options, run),
                .if_stmt => |branch| try self.emitIf(source, subject, options, branch),
                .for_stmt => |loop| try self.emitFor(source, subject, options, loop),
            }
        }
    }

    fn emitIf(
        self: *Compiler,
        source: *const script.Script,
        subject: []const u8,
        options: CompileOptions,
        branch: script.If,
    ) Error!void {
        const cond = branch.cond;
        if (cond.negated and cond.comparisons.len != 1) return error.UnsupportedCondition;

        var indices: std.ArrayList(usize) = .empty;
        for (cond.comparisons) |comparison| {
            switch (comparison.right) {
                .path => return error.UnsupportedCondition,
                else => {},
            }
            const id = try self.nextId("cond");
            const variable = try joinPath(self.a, comparison.left);
            const literal = try operandText(self.a, comparison.right);
            const index = try self.addCondition(.{
                .id = id,
                .variable = variable,
                .op = mapOp(comparison.op),
                .literal = literal,
            });
            indices.append(self.a, index) catch return error.OutOfMemory;
        }

        const then_start = self.steps.items.len;
        try self.emitStatements(source, subject, options, branch.then_body);
        const trampoline = try self.addJump();
        const else_start = self.steps.items.len;
        try self.emitStatements(source, subject, options, branch.else_body);
        const end_index = self.steps.items.len;

        const has_else = branch.else_body.len > 0;
        const else_target = if (has_else) else_start else end_index;

        if (indices.items.len == 1) {
            const index = indices.items[0];
            if (cond.negated) {
                self.patch(index, else_target, then_start);
            } else {
                self.patch(index, then_start, else_target);
            }
        } else {
            const all_and = allConnectors(cond.connectors, .and_op);
            const all_or = allConnectors(cond.connectors, .or_op);
            if (!all_and and !all_or) return error.UnsupportedCondition;
            for (indices.items, 0..) |index, position| {
                const next: ?usize = if (position + 1 < indices.items.len) indices.items[position + 1] else null;
                if (all_and) {
                    self.patch(index, next orelse then_start, else_target);
                } else {
                    self.patch(index, then_start, next orelse else_target);
                }
            }
        }
        self.patch(trampoline, end_index, end_index);
    }

    fn emitFor(
        self: *Compiler,
        source: *const script.Script,
        subject: []const u8,
        options: CompileOptions,
        loop: script.For,
    ) Error!void {
        var iteration: u32 = 1;
        while (iteration <= loop.count) : (iteration += 1) {
            const id = try self.nextId("set");
            const value = std.fmt.allocPrint(self.a, "{d}", .{iteration}) catch return error.OutOfMemory;
            try self.addAction(id, .{
                .id = id,
                .subject = subject,
                .kind = .storage,
                .operation = .observe,
                .bind = loop.var_name,
                .set_value = value,
            }, 1);
            try self.emitStatements(source, subject, options, loop.body);
        }
    }
};

pub fn compile(allocator: Allocator, source: *const script.Script, options: CompileOptions) Error!Compiled {
    return compileWithLibrary(allocator, source, options, null);
}

pub fn compileWithLibrary(
    allocator: Allocator,
    source: *const script.Script,
    options: CompileOptions,
    library: ?*const script.Library,
) Error!Compiled {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const subject = std.fmt.allocPrint(a, "{s}{s}", .{ subject_prefix, source.name }) catch return error.OutOfMemory;
    var compiler = Compiler{ .a = a, .library = library };
    for (source.steps) |dsl_step| {
        try compiler.emitStatements(source, subject, options, dsl_step.body);
    }
    if (compiler.steps.items.len == 0) return error.MissingCapability;

    return .{
        .arena = arena,
        .definition = .{
            .id = source.name,
            .steps = compiler.steps.toOwnedSlice(a) catch return error.OutOfMemory,
        },
        .actions = compiler.actions.toOwnedSlice(a) catch return error.OutOfMemory,
        .conditions = compiler.conditions.toOwnedSlice(a) catch return error.OutOfMemory,
    };
}

fn joinPath(a: Allocator, parts: []const []const u8) Error![]const u8 {
    if (parts.len == 1) return parts[0];
    var buffer: std.ArrayList(u8) = .empty;
    for (parts, 0..) |part, index| {
        if (index != 0) buffer.append(a, '.') catch return error.OutOfMemory;
        buffer.appendSlice(a, part) catch return error.OutOfMemory;
    }
    return buffer.toOwnedSlice(a) catch return error.OutOfMemory;
}

fn operandText(a: Allocator, operand: script.Operand) Error![]const u8 {
    return switch (operand) {
        .string => |value| value,
        .number => |value| std.fmt.allocPrint(a, "{d}", .{value}) catch return error.OutOfMemory,
        .path => return error.UnsupportedCondition,
    };
}

fn mapOp(op: script.CmpOp) automation.CompareOp {
    return switch (op) {
        .eq => .eq,
        .neq => .neq,
        .lt => .lt,
        .lte => .lte,
        .gt => .gt,
        .gte => .gte,
    };
}

fn allConnectors(connectors: []const script.Connector, expected: script.Connector) bool {
    for (connectors) |connector| if (connector != expected) return false;
    return connectors.len > 0;
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
        return self.initWithLibrary(allocator, source, service, options, null);
    }

    pub fn initWithLibrary(
        self: *Executor,
        allocator: Allocator,
        source: *const script.Script,
        service: *capability.Service,
        options: CompileOptions,
        library: ?*const script.Library,
    ) Error!void {
        self.compiled = try compileWithLibrary(allocator, source, options, library);
        self.engine.init(service, self.compiled.actions) catch |err| {
            self.compiled.deinit();
            return switch (err) {
                error.TooManyActions => error.TickBudgetExceeded,
                error.MissingActionId => error.MissingCapability,
            };
        };
        self.engine.setConditions(self.compiled.conditions);
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

    pub fn variable(self: *const Executor, name: []const u8) ?[]const u8 {
        return self.engine.variableValue(name);
    }
};

fn branchSource() []const u8 {
    return
    \\script "branch" do
    \\    use "pack.rf"
    \\    cap rf = subghz.read
    \\    step "s" do
    \\        sig = rf { payload = "protocol=Princeton" }
    \\        if sig.protocol == "Princeton" then
    \\            rf { payload = "match" }
    \\        else
    \\            rf { payload = "other" }
    \\        end
    \\    end
    \\end
    ;
}

test "compiles statements into workflow steps and action specs" {
    var source = try script.parse(std.testing.allocator, branchSource());
    defer source.deinit();

    var compiled = try compile(std.testing.allocator, &source, .{});
    defer compiled.deinit();

    // assign + condition + then action + trampoline + else action
    try std.testing.expectEqual(@as(usize, 5), compiled.definition.steps.len);
    // One real comparison plus the trampoline jump spec (the runner always evaluates).
    try std.testing.expectEqual(@as(usize, 2), compiled.conditions.len);

    const condition = compiled.definition.steps[1].condition;
    try std.testing.expectEqual(@as(usize, 2), condition.if_true);
    try std.testing.expectEqual(@as(usize, 4), condition.if_false);

    const trampoline = compiled.definition.steps[3].condition;
    try std.testing.expectEqual(@as(usize, 5), trampoline.if_true);
    try std.testing.expectEqual(@as(usize, 5), trampoline.if_false);

    try std.testing.expectEqualStrings(compiled.definition.steps[1].condition.id, compiled.conditions[0].id);
    try std.testing.expectEqualStrings("sig.protocol", compiled.conditions[0].variable);
    try std.testing.expectEqualStrings("Princeton", compiled.conditions[0].literal);
    try std.testing.expectEqual(automation.CompareOp.eq, compiled.conditions[0].op);
    try std.testing.expectEqual(@as(usize, 3), compiled.actions.len);
    try std.testing.expectEqualStrings("sig", compiled.actions[0].bind.?);
}

test "evaluates a branch at runtime from a bound variable" {
    var source = try script.parse(std.testing.allocator, branchSource());
    defer source.deinit();

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.subghz);

    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, &source, &harness.capabilities, .{});
    defer executor.deinit();

    try std.testing.expectEqual(workflow.Status.succeeded, try executor.run());
    try std.testing.expectEqual(@as(usize, 2), harness.capabilities.audit.entries.items.len);
    try std.testing.expectEqualStrings("Princeton", executor.variable("sig.protocol").?);
}

test "takes the else branch when the condition is false" {
    var source = try script.parse(std.testing.allocator,
        \\script "branch-false" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        sig = rf { payload = "protocol=Other" }
        \\        if sig.protocol == "Princeton" then
        \\            emit info "match"
        \\        else
        \\            emit info "other"
        \\        end
        \\    end
        \\end
    );
    defer source.deinit();

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.subghz);

    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, &source, &harness.capabilities, .{});
    defer executor.deinit();

    try std.testing.expectEqual(workflow.Status.succeeded, try executor.run());
    try std.testing.expectEqual(@as(usize, 1), executor.emitted().len);
    try std.testing.expectEqualStrings("other", executor.emitted()[0].message);
}

test "unrolls a bounded for loop and binds the counter" {
    var source = try script.parse(std.testing.allocator,
        \\script "loop" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        for i = 1, 3 do
        \\            rf { payload = "tick" }
        \\        end
        \\        emit info "done"
        \\    end
        \\end
    );
    defer source.deinit();

    var compiled = try compile(std.testing.allocator, &source, .{});
    defer compiled.deinit();
    try std.testing.expectEqual(@as(usize, 7), compiled.definition.steps.len);

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.subghz);

    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, &source, &harness.capabilities, .{});
    defer executor.deinit();

    try std.testing.expectEqual(workflow.Status.succeeded, try executor.run());
    try std.testing.expectEqual(@as(usize, 3), harness.capabilities.audit.entries.items.len);
    try std.testing.expectEqualStrings("3", executor.variable("i").?);
    try std.testing.expectEqual(@as(usize, 1), executor.emitted().len);
}

test "out exports a variable to the following step" {
    var source = try script.parse(std.testing.allocator,
        \\script "export" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "capture" do
        \\        sig = rf { payload = "protocol=Princeton" }
        \\        out sig
        \\    end
        \\    step "decide" do
        \\        if sig.protocol == "Princeton" then
        \\            emit info "exported"
        \\        end
        \\    end
        \\end
    );
    defer source.deinit();

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.subghz);

    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, &source, &harness.capabilities, .{});
    defer executor.deinit();

    try std.testing.expectEqual(workflow.Status.succeeded, try executor.run());
    try std.testing.expectEqual(@as(usize, 1), executor.emitted().len);
    try std.testing.expectEqualStrings("exported", executor.emitted()[0].message);
}

test "rejects conditions that reference unknown variables" {
    try std.testing.expectError(error.UnknownVariable, script.parse(std.testing.allocator,
        \\script "bad" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        if ghost.value == "x" then
        \\            rf { payload = "p" }
        \\        end
        \\    end
        \\end
    ));
}

test "rejects mixed and/or chains and comparing against a variable" {
    var mixed = try script.parse(std.testing.allocator,
        \\script "mixed" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        a = rf { payload = "x=1" }
        \\        b = rf { payload = "y=2" }
        \\        if a.x == "1" and b.y == "2" or a.x == "2" then
        \\            rf { payload = "p" }
        \\        end
        \\    end
        \\end
    );
    defer mixed.deinit();
    try std.testing.expectError(error.UnsupportedCondition, compile(std.testing.allocator, &mixed, .{}));

    var against = try script.parse(std.testing.allocator,
        \\script "against" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        a = rf { payload = "x=1" }
        \\        b = rf { payload = "y=2" }
        \\        if a.x == b.y then
        \\            rf { payload = "p" }
        \\        end
        \\    end
        \\end
    );
    defer against.deinit();
    try std.testing.expectError(error.UnsupportedCondition, compile(std.testing.allocator, &against, .{}));
}

test "stop truncates the remaining script" {
    var source = try script.parse(std.testing.allocator,
        \\script "stopper" do
        \\    use "pack.rf"
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
        \\    use "pack.rf"
        \\    cap rf_tx = subghz.transmit
        \\    step "send" do
        \\        rf_tx { payload = "frame" }
        \\    end
        \\end
    );
    defer source.deinit();

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.subghz);

    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, &source, &harness.capabilities, .{});
    defer executor.deinit();

    try std.testing.expectEqual(workflow.Status.failed, try executor.run());
    try std.testing.expectEqual(@as(usize, 1), harness.capabilities.audit.entries.items.len);
    try std.testing.expectEqual(capability.Status.denied, harness.capabilities.audit.entries.items[0].status);
}

test "every DSL verb has a capability mapping" {
    for (verb_map) |mapping| {
        try std.testing.expect(verbMapping(mapping.verb) != null);
    }
}

test "inlines a sub-script into the caller" {
    var helper = try script.parse(std.testing.allocator,
        \\script "helper" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "capture" do
        \\        sig = rf { payload = "protocol=Princeton" }
        \\        out sig
        \\    end
        \\end
    );
    defer helper.deinit();

    const library = script.Library{ .entries = &.{.{ .name = "helper", .script = &helper }} };
    var caller = try script.parseWithLibrary(std.testing.allocator,
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
    , &library);
    defer caller.deinit();

    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.subghz);

    var executor: Executor = undefined;
    try executor.initWithLibrary(std.testing.allocator, &caller, &harness.capabilities, .{}, &library);
    defer executor.deinit();

    try std.testing.expectEqual(workflow.Status.succeeded, try executor.run());
    try std.testing.expectEqual(@as(usize, 2), harness.capabilities.audit.entries.items.len);
    try std.testing.expectEqualStrings("script:helper", harness.capabilities.audit.entries.items[0].subject);
    try std.testing.expectEqualStrings("script:caller", harness.capabilities.audit.entries.items[1].subject);
    try std.testing.expectEqual(@as(usize, 0), executor.emitted().len);
}

test "each if site gets its own condition spec" {
    var source = try script.parse(std.testing.allocator,
        \\script "two-branches" do
        \\    use "pack.rf"
        \\    cap rf = subghz.read
        \\    step "s" do
        \\        a = rf { payload = "x=1" }
        \\        if a.x == "1" then
        \\            emit info "one"
        \\        end
        \\        if a.x == "2" then
        \\            emit info "two"
        \\        end
        \\    end
        \\end
    );
    defer source.deinit();

    var compiled = try compile(std.testing.allocator, &source, .{});
    defer compiled.deinit();

    // Two comparisons plus their two trampoline jumps.
    try std.testing.expectEqual(@as(usize, 4), compiled.conditions.len);
    try std.testing.expectEqualStrings("1", compiled.conditions[0].literal);
    try std.testing.expectEqualStrings("2", compiled.conditions[2].literal);
    for (compiled.conditions, 0..) |left, i| {
        for (compiled.conditions[i + 1 ..]) |right| {
            try std.testing.expect(!std.mem.eql(u8, left.id, right.id));
        }
    }
}
