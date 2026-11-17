//! Output-driven exploitation. A goal lists modular records with fact preconditions,
//! inputs and captured outputs; the runner selects the next eligible module, binds the
//! previous step's captures into facts and replans until the goal is met.

const std = @import("std");
const control = @import("control.zig");
const exploit = @import("exploit.zig");

pub const max_modules = 32;
pub const max_steps = 16;
pub const max_facts = 128;

pub const Predicate = struct { fact: []const u8, equals: []const u8 };
pub const Input = struct { name: []const u8, fact: []const u8 = "", default: []const u8 = "" };
pub const Transform = enum { identity, trim, lower, upper, url_decode, base64_decode, hex_decode };
pub const Output = struct {
    fact: []const u8,
    capture: []const u8,
    transform: Transform = .identity,
};
pub const Module = struct {
    id: []const u8,
    record: []const u8,
    requires: []const Predicate,
    inputs: []const Input,
    outputs: []const Output,
    priority: u8 = 100,
    repeatable: bool = false,
};
pub const Fact = struct { name: []const u8, value: []const u8 };

pub const Goal = struct {
    arena: std.heap.ArenaAllocator,
    id: []const u8,
    target: []const u8,
    goal_contains: []const u8,
    max_steps: u8,
    facts: []const Fact,
    records_dir: []const u8 = "",
    modules: []Module,

    pub fn deinit(self: *Goal) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const PredicateWire = struct { fact: []const u8 = "", equals: []const u8 = "" };
const InputWire = struct { name: []const u8 = "", fact: []const u8 = "", default: []const u8 = "" };
const OutputWire = struct {
    fact: []const u8 = "",
    capture: []const u8 = "",
    transform: []const u8 = "",
};
const ModuleWire = struct {
    id: []const u8 = "",
    record: []const u8 = "",
    requires: []const PredicateWire = &.{},
    inputs: []const InputWire = &.{},
    outputs: []const OutputWire = &.{},
    priority: u8 = 100,
    repeatable: bool = false,
};
const GoalWire = struct {
    schema: []const u8 = "",
    id: []const u8 = "",
    target: []const u8 = "",
    goal: struct { contains: []const u8 = "" } = .{},
    max_steps: u8 = 8,
    facts: []struct { name: []const u8 = "", value: []const u8 = "" } = &.{},
    records: []const u8 = "",
    modules: []ModuleWire = &.{},
};

pub fn parseTransform(text: []const u8) ?Transform {
    if (text.len == 0 or std.mem.eql(u8, text, "identity")) return .identity;
    if (std.mem.eql(u8, text, "trim")) return .trim;
    if (std.mem.eql(u8, text, "lower")) return .lower;
    if (std.mem.eql(u8, text, "upper")) return .upper;
    if (std.mem.eql(u8, text, "url_decode")) return .url_decode;
    if (std.mem.eql(u8, text, "base64_decode")) return .base64_decode;
    if (std.mem.eql(u8, text, "hex_decode")) return .hex_decode;
    return null;
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn applyTransform(a: std.mem.Allocator, transform: Transform, value: []const u8) ![]const u8 {
    return switch (transform) {
        .identity => value,
        .trim => std.mem.trim(u8, value, " \t\r\n"),
        .lower => blk: {
            const out = try a.dupe(u8, value);
            for (out) |*byte| byte.* = std.ascii.toLower(byte.*);
            break :blk out;
        },
        .upper => blk: {
            const out = try a.dupe(u8, value);
            for (out) |*byte| byte.* = std.ascii.toUpper(byte.*);
            break :blk out;
        },
        .url_decode => blk: {
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(a);
            var i: usize = 0;
            while (i < value.len) {
                if (value[i] == '%') {
                    if (i + 2 >= value.len) return error.InvalidTransform;
                    const high = hexNibble(value[i + 1]) orelse return error.InvalidTransform;
                    const low = hexNibble(value[i + 2]) orelse return error.InvalidTransform;
                    try out.append(a, high << 4 | low);
                    i += 3;
                } else if (value[i] == '+') {
                    try out.append(a, ' ');
                    i += 1;
                } else {
                    try out.append(a, value[i]);
                    i += 1;
                }
            }
            break :blk try out.toOwnedSlice(a);
        },
        .hex_decode => blk: {
            if (value.len % 2 != 0) return error.InvalidTransform;
            const out = try a.alloc(u8, value.len / 2);
            var i: usize = 0;
            while (i < out.len) : (i += 1) {
                const high = hexNibble(value[i * 2]) orelse return error.InvalidTransform;
                const low = hexNibble(value[i * 2 + 1]) orelse return error.InvalidTransform;
                out[i] = high << 4 | low;
            }
            break :blk out;
        },
        .base64_decode => blk: {
            const decoder = std.base64.standard.Decoder;
            const size = decoder.calcSizeForSlice(value) catch return error.InvalidTransform;
            const out = try a.alloc(u8, size);
            decoder.decode(out, value) catch return error.InvalidTransform;
            break :blk out;
        },
    };
}

const SynthMatch = struct {
    service: []const u8 = "",
    product: []const u8 = "",
    version_prefix: []const u8 = "",
};
const SynthCapture = struct {
    name: []const u8 = "",
    prefix: []const u8 = "",
    suffix: []const u8 = "",
};
const SynthStep = struct { capture: ?SynthCapture = null };
const SynthModule = struct {
    id: []const u8 = "",
    requires: []const PredicateWire = &.{},
    inputs: []const InputWire = &.{},
    outputs: []const OutputWire = &.{},
    priority: u8 = 100,
    repeatable: bool = false,
};
const SynthWire = struct {
    schema: []const u8 = "",
    cve: []const u8 = "",
    effect: []const u8 = "",
    match: ?SynthMatch = null,
    steps: []const SynthStep = &.{},
    module: ?SynthModule = null,
};

/// Fills goal.modules from a record directory when the goal omitted them. A record's
/// optional "module" block wins; otherwise requires come from "match" and outputs from
/// step captures. This is synthesis, not magical inference: records without metadata
/// only get their service/product predicates and capture names.
pub fn resolve(goal: *Goal, io: std.Io) !void {
    if (goal.modules.len > 0) return;
    if (goal.records_dir.len == 0) return error.InvalidAdaptiveGoal;
    const a = goal.arena.allocator();
    var dir = try std.Io.Dir.cwd().openDir(io, goal.records_dir, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(a);
    defer walker.deinit();
    var modules: std.ArrayList(Module) = .empty;
    defer modules.deinit(a);
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".json")) continue;
        if (modules.items.len >= max_modules) return error.TooManyModules;
        const path = try std.fs.path.join(a, &.{ goal.records_dir, entry.path });
        const data = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(256 * 1024));
        const wire = std.json.parseFromSliceLeaky(SynthWire, a, data, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidAdaptiveModule;
        if (!std.mem.eql(u8, wire.schema, "pocketroot.exploit.v1") or wire.cve.len == 0) {
            return error.InvalidAdaptiveModule;
        }
        var requires: std.ArrayList(Predicate) = .empty;
        defer requires.deinit(a);
        var inputs: std.ArrayList(Input) = .empty;
        defer inputs.deinit(a);
        var outputs: std.ArrayList(Output) = .empty;
        defer outputs.deinit(a);
        var id: []const u8 = wire.cve;
        var priority: u8 = 100;
        var repeatable = false;
        if (wire.module) |meta| {
            if (meta.id.len > 0) id = meta.id;
            priority = meta.priority;
            repeatable = meta.repeatable;
            for (meta.requires) |predicate| {
                try requires.append(a, .{ .fact = predicate.fact, .equals = predicate.equals });
            }
            for (meta.inputs) |input| {
                try inputs.append(a, .{ .name = input.name, .fact = input.fact, .default = input.default });
            }
            for (meta.outputs) |output| {
                try outputs.append(a, .{
                    .fact = output.fact,
                    .capture = output.capture,
                    .transform = parseTransform(output.transform) orelse .identity,
                });
            }
        } else {
            if (wire.match) |match| {
                if (match.service.len > 0) try requires.append(a, .{ .fact = "service", .equals = match.service });
                if (match.product.len > 0) try requires.append(a, .{ .fact = "product", .equals = match.product });
                if (match.version_prefix.len > 0) try requires.append(a, .{ .fact = "version", .equals = match.version_prefix });
            }
            for (wire.steps) |step| {
                if (step.capture) |capture| {
                    if (capture.name.len > 0) {
                        try outputs.append(a, .{ .fact = capture.name, .capture = capture.name });
                    }
                }
            }
        }
        var duplicate = false;
        for (modules.items) |existing| {
            if (std.mem.eql(u8, existing.id, id)) duplicate = true;
        }
        if (duplicate) continue;
        try modules.append(a, .{
            .id = id,
            .record = path,
            .requires = try requires.toOwnedSlice(a),
            .inputs = try inputs.toOwnedSlice(a),
            .outputs = try outputs.toOwnedSlice(a),
            .priority = priority,
            .repeatable = repeatable,
        });
    }
    if (modules.items.len == 0) return error.NoModules;
    goal.modules = try modules.toOwnedSlice(a);
}

pub fn parseGoal(allocator: std.mem.Allocator, data: []const u8) !Goal {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, data);
    const wire = std.json.parseFromSliceLeaky(GoalWire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidAdaptiveGoal;
    if (!std.mem.eql(u8, wire.schema, "pocketroot.adaptive.v1")) return error.InvalidAdaptiveGoal;
    if (wire.id.len == 0 or wire.target.len == 0 or wire.goal.contains.len == 0) return error.InvalidAdaptiveGoal;
    if (wire.max_steps == 0 or wire.max_steps > max_steps) return error.InvalidAdaptiveGoal;
    if (wire.modules.len > max_modules) return error.InvalidAdaptiveGoal;
    if (wire.modules.len == 0 and wire.records.len == 0) return error.InvalidAdaptiveGoal;
    const facts = try a.alloc(Fact, wire.facts.len);
    for (wire.facts, 0..) |fact, i| {
        if (fact.name.len == 0 or fact.name.len > 64 or fact.value.len > 1024) return error.InvalidAdaptiveGoal;
        facts[i] = .{ .name = fact.name, .value = fact.value };
    }
    const modules = try a.alloc(Module, wire.modules.len);
    for (wire.modules, 0..) |module, i| {
        if (module.id.len == 0 or module.record.len == 0) return error.InvalidAdaptiveGoal;
        var duplicate = false;
        for (modules[0..i]) |previous| {
            if (std.mem.eql(u8, previous.id, module.id)) duplicate = true;
        }
        if (duplicate) return error.InvalidAdaptiveGoal;
        const requires = try a.alloc(Predicate, module.requires.len);
        for (module.requires, 0..) |predicate, j| {
            if (predicate.fact.len == 0 or predicate.equals.len == 0) return error.InvalidAdaptiveGoal;
            requires[j] = .{ .fact = predicate.fact, .equals = predicate.equals };
        }
        const inputs = try a.alloc(Input, module.inputs.len);
        for (module.inputs, 0..) |input, j| {
            if (input.name.len == 0) return error.InvalidAdaptiveGoal;
            inputs[j] = .{ .name = input.name, .fact = input.fact, .default = input.default };
        }
        const outputs = try a.alloc(Output, module.outputs.len);
        for (module.outputs, 0..) |output, j| {
            if (output.fact.len == 0 or output.capture.len == 0) return error.InvalidAdaptiveGoal;
            outputs[j] = .{
                .fact = output.fact,
                .capture = output.capture,
                .transform = parseTransform(output.transform) orelse return error.InvalidAdaptiveGoal,
            };
        }
        modules[i] = .{
            .id = module.id,
            .record = module.record,
            .requires = requires,
            .inputs = inputs,
            .outputs = outputs,
            .priority = module.priority,
            .repeatable = module.repeatable,
        };
    }
    return .{
        .arena = arena,
        .id = wire.id,
        .target = wire.target,
        .goal_contains = wire.goal.contains,
        .max_steps = wire.max_steps,
        .facts = facts,
        .records_dir = wire.records,
        .modules = modules,
    };
}

pub fn writeEvidence(
    writer: *std.Io.Writer,
    goal: *const Goal,
    execution: *const Execution,
    now: i64,
) !void {
    const StepWire = struct {
        module: []const u8,
        cve: []const u8,
        oracle: []const u8,
        output: []const u8,
    };
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
    const steps = try std.heap.page_allocator.alloc(StepWire, execution.steps.len);
    defer std.heap.page_allocator.free(steps);
    for (execution.steps, 0..) |step, i| {
        steps[i] = .{
            .module = step.module_id,
            .cve = step.cve,
            .oracle = if (step.oracle_pass) "pass" else "fail",
            .output = step.output,
        };
    }
    var json: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.write(Wire{
        .schema = "pocketroot.adaptive.evidence.v1",
        .id = goal.id,
        .target = goal.target,
        .status = execution.status,
        .approval_id = execution.approval_id,
        .steps = steps,
        .facts = execution.facts_output,
        .recorded_at_unix = now,
    });
    try writer.writeByte('\n');
}

pub fn goalHash(
    allocator: std.mem.Allocator,
    io: std.Io,
    goal_data: []const u8,
    goal: *const Goal,
) ![]u8 {
    var buffer = std.Io.Writer.Allocating.init(allocator);
    defer buffer.deinit();
    try buffer.writer.writeAll(goal_data);
    for (goal.modules) |module| {
        const record = try std.Io.Dir.cwd().readFileAlloc(io, module.record, allocator, .limited(256 * 1024));
        defer allocator.free(record);
        const digest = try control.sha256Hex(allocator, record);
        defer allocator.free(digest);
        try buffer.writer.print("\n{s}={s}", .{ module.record, digest });
    }
    return control.sha256Hex(allocator, buffer.written());
}

pub const StepResult = struct {
    module_id: []const u8,
    cve: []const u8,
    output: []const u8,
    oracle_pass: bool,
};

pub const Execution = struct {
    allocator: std.mem.Allocator,
    goal_id: []u8,
    approval_id: []u8,
    status: []u8,
    steps: []StepResult,
    facts_output: []u8,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.goal_id);
        self.allocator.free(self.approval_id);
        self.allocator.free(self.status);
        for (self.steps) |step| {
            self.allocator.free(step.module_id);
            self.allocator.free(step.cve);
            self.allocator.free(step.output);
        }
        self.allocator.free(self.steps);
        self.allocator.free(self.facts_output);
        self.* = undefined;
    }
};

const StopContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    campaign_dir: []const u8,
};

fn stopCheck(context: *anyopaque) bool {
    const stop: *StopContext = @ptrCast(@alignCast(context));
    return control.isStopped(stop.allocator, stop.io, stop.campaign_dir);
}

fn applyOutputs(
    module: *const Module,
    outcome: *const exploit.Outcome,
    facts: *std.StringHashMap([]const u8),
    facts_arena: *std.heap.ArenaAllocator,
) !void {
    for (module.outputs) |output| {
        for (outcome.captures) |capture| {
            if (!std.mem.eql(u8, capture.name, output.capture)) continue;
            const transformed = try applyTransform(facts_arena.allocator(), output.transform, capture.value);
            try facts.put(output.fact, try facts_arena.allocator().dupe(u8, transformed));
        }
    }
}

fn factValue(facts: *const std.StringHashMap([]const u8), name: []const u8) ?[]const u8 {
    return facts.get(name);
}

fn eligible(
    module: *const Module,
    facts: *const std.StringHashMap([]const u8),
    executed: *const std.StringHashMap(void),
) bool {
    if (!module.repeatable and executed.contains(module.id)) return false;
    for (module.requires) |predicate| {
        const value = factValue(facts, predicate.fact) orelse return false;
        if (!std.mem.eql(u8, value, predicate.equals)) return false;
    }
    for (module.inputs) |input| {
        if (input.fact.len > 0 and factValue(facts, input.fact) == null and input.default.len == 0) return false;
    }
    return true;
}

var ledger_mutex: std.Io.Mutex = .init;

fn appendLedgerSerialized(
    allocator: std.mem.Allocator,
    io: std.Io,
    campaign_dir: []const u8,
    input: control.LedgerInput,
    now: i64,
) !void {
    ledger_mutex.lockUncancelable(io);
    defer ledger_mutex.unlock(io);
    return control.appendLedger(allocator, io, campaign_dir, input, now);
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    goal_data: []const u8,
    goal: *const Goal,
    campaign_dir: []const u8,
) !Execution {
    const action_id = try std.fmt.allocPrint(allocator, "ADAPT-{s}", .{goal.id});
    defer allocator.free(action_id);
    return runForTarget(allocator, io, goal_data, goal, campaign_dir, goal.target, action_id);
}

pub fn runForTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    goal_data: []const u8,
    goal: *const Goal,
    campaign_dir: []const u8,
    target: []const u8,
    action_id: []const u8,
) !Execution {
    const scope_path = try std.fs.path.join(allocator, &.{ campaign_dir, "scope.json" });
    defer allocator.free(scope_path);
    const scope_data = try std.Io.Dir.cwd().readFileAlloc(io, scope_path, allocator, .limited(256 * 1024));
    defer allocator.free(scope_data);
    var scope = try control.parseScope(allocator, scope_data);
    defer scope.deinit();
    var state = try control.loadState(allocator, io, campaign_dir);
    defer state.deinit();
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const params_hash = try goalHash(allocator, io, goal_data, goal);
    defer allocator.free(params_hash);
    try control.evaluate(allocator, io, campaign_dir, &scope, &state, .{
        .action_id = action_id,
        .target = target,
        .technique = .exploit,
        .params_hash = params_hash,
    }, now);
    const approval_file = try control.approvalPath(allocator, campaign_dir, action_id);
    defer allocator.free(approval_file);
    var approval = control.loadApproval(allocator, io, approval_file) catch |err| switch (err) {
        error.FileNotFound => return error.approval_missing,
        else => return err,
    };
    defer approval.deinit();
    try control.consumeApproval(allocator, io, approval_file, now);
    try appendLedgerSerialized(allocator, io, campaign_dir, .{
        .event = "adaptive-start",
        .action_id = action_id,
        .approval_id = approval.id,
        .target = target,
        .technique = "exploit",
        .result = "started",
        .detail = goal.id,
    }, now);

    var facts_arena = std.heap.ArenaAllocator.init(allocator);
    defer facts_arena.deinit();
    var facts = std.StringHashMap([]const u8).init(allocator);
    defer facts.deinit();
    for (goal.facts) |fact| try facts.put(fact.name, fact.value);
    try facts.put("target", target);

    var stop_context = StopContext{
        .allocator = allocator,
        .io = io,
        .campaign_dir = campaign_dir,
    };
    var executed = std.StringHashMap(void).init(allocator);
    defer executed.deinit();
    var steps: std.ArrayList(StepResult) = .empty;
    defer steps.deinit(allocator);
    var status: []const u8 = "goal_unmet";
    var step_count: usize = 0;
    while (step_count < goal.max_steps) : (step_count += 1) {
        if (control.isStopped(allocator, io, campaign_dir)) {
            status = "stopped";
            break;
        }
        var chosen: ?*const Module = null;
        for (goal.modules) |*module| {
            if (!eligible(module, &facts, &executed)) continue;
            if (chosen == null or module.priority < chosen.?.priority) chosen = module;
        }
        const module = chosen orelse break;

        var overrides: std.ArrayList(exploit.Param) = .empty;
        defer overrides.deinit(allocator);
        for (module.inputs) |input| {
            const value = if (input.fact.len > 0)
                factValue(&facts, input.fact) orelse input.default
            else
                input.default;
            try overrides.append(allocator, .{ .name = input.name, .value = value });
        }

        const record_data = std.Io.Dir.cwd().readFileAlloc(io, module.record, allocator, .limited(256 * 1024)) catch |err| {
            status = @errorName(err);
            break;
        };
        defer allocator.free(record_data);
        var spec = exploit.parseSpec(allocator, record_data) catch |err| {
            status = @errorName(err);
            break;
        };
        defer spec.deinit();
        spec.target = target;
        var outcome = exploit.runWithOptions(allocator, io, &spec, overrides.items, .{
            .stop = .{ .context = &stop_context, .isStopped = stopCheck },
        }) catch |err| {
            status = if (err == error.Stopped) "stopped" else @errorName(err);
            break;
        };
        defer outcome.deinit();
        try executed.put(module.id, {});
        try steps.append(allocator, .{
            .module_id = try allocator.dupe(u8, module.id),
            .cve = try allocator.dupe(u8, spec.cve),
            .output = try allocator.dupe(u8, outcome.output),
            .oracle_pass = outcome.oracle_pass,
        });
        applyOutputs(module, &outcome, &facts, &facts_arena) catch |err| {
            status = @errorName(err);
            break;
        };
        try appendLedgerSerialized(allocator, io, campaign_dir, .{
            .event = "adaptive-step",
            .action_id = action_id,
            .approval_id = approval.id,
            .target = target,
            .technique = "exploit",
            .result = if (outcome.oracle_pass) "succeeded" else "failed",
            .detail = module.id,
        }, std.Io.Timestamp.now(io, .real).toSeconds());
        if (!outcome.oracle_pass) {
            status = "failed";
            break;
        }
        if (std.mem.indexOf(u8, outcome.output, goal.goal_contains) != null) {
            status = "succeeded";
            break;
        }
        if (control.isStopped(allocator, io, campaign_dir)) {
            status = "stopped";
            break;
        }
    }
    try appendLedgerSerialized(allocator, io, campaign_dir, .{
        .event = "adaptive-result",
        .action_id = action_id,
        .approval_id = approval.id,
        .target = target,
        .technique = "exploit",
        .result = status,
        .detail = goal.id,
    }, std.Io.Timestamp.now(io, .real).toSeconds());

    var facts_out = std.Io.Writer.Allocating.init(allocator);
    defer facts_out.deinit();
    var it = facts.iterator();
    while (it.next()) |entry| {
        try facts_out.writer.print("{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    return .{
        .allocator = allocator,
        .goal_id = try allocator.dupe(u8, goal.id),
        .approval_id = try allocator.dupe(u8, approval.id),
        .status = try allocator.dupe(u8, status),
        .steps = try steps.toOwnedSlice(allocator),
        .facts_output = try facts_out.toOwnedSlice(),
    };
}

test "adaptive goal parses facts and modular outputs" {
    var goal = try parseGoal(std.testing.allocator,
        \\{"schema":"pocketroot.adaptive.v1","id":"ADAPT-T","target":"127.0.0.1:80","goal":{"contains":"uid="},"max_steps":2,"facts":[{"name":"service","value":"http"}],"modules":[{"id":"a","record":"a.json","requires":[{"fact":"service","equals":"http"}],"outputs":[{"fact":"route","capture":"route"}],"priority":1},{"id":"b","record":"b.json","requires":[{"fact":"route","equals":"cmd"}]}]}
    );
    defer goal.deinit();
    try std.testing.expectEqualStrings("ADAPT-T", goal.id);
    try std.testing.expectEqual(@as(usize, 2), goal.modules.len);
    try std.testing.expectEqual(@as(usize, 1), goal.modules[0].outputs.len);
    try std.testing.expectEqualStrings("route", goal.modules[0].outputs[0].fact);
}

test "fact transforms decode values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("abc", try applyTransform(a, .trim, "  abc\n"));
    try std.testing.expectEqualStrings("a b", try applyTransform(a, .url_decode, "a%20b"));
    try std.testing.expectEqualStrings("abc", try applyTransform(a, .base64_decode, "YWJj"));
    try std.testing.expectEqualStrings("abc", try applyTransform(a, .hex_decode, "616263"));
    try std.testing.expectEqualStrings("ABC", try applyTransform(a, .upper, "abc"));
}

test "resolve synthesizes modules from the sample record directory" {
    var goal = try parseGoal(std.testing.allocator,
        \\{"schema":"pocketroot.adaptive.v1","id":"ADAPT-AUTO-T","target":"127.0.0.1:8080","goal":{"contains":"uid="},"max_steps":4,"facts":[{"name":"service","value":"http"}],"records":"samples/adaptive/records"}
    );
    defer goal.deinit();
    try resolve(&goal, std.testing.io);
    try std.testing.expect(goal.modules.len >= 3);
    var found = false;
    for (goal.modules) |module| {
        if (std.mem.eql(u8, module.id, "discover")) {
            found = true;
            try std.testing.expect(module.outputs.len == 1);
        }
    }
    try std.testing.expect(found);
}
