//! Attack-surface report: target + weakness + feasibility + candidate action.
//!
//! This is the read-only half of a campaign. It never sends traffic and never
//! needs an approval; the action ids it mints are what a human later approves.

const std = @import("std");
const Io = std.Io;
const asset_graph = @import("asset_graph.zig");
const vulnerability_matcher = @import("vulnerability_matcher.zig");
const control = @import("control.zig");

pub const schema = "pocketroot.surface.v1";
pub const max_actions = 4096;

pub const Access = enum { network, adjacent, local, physical, unknown };
pub const Feasibility = enum { feasible, needs_capability, manual, out_of_scope, unknown };

pub const Action = struct {
    id: []const u8,
    target: []const u8,
    target_identity: []const u8,
    vulnerability_id: []const u8,
    title: []const u8,
    severity: []const u8,
    cvss: f32,
    access: Access,
    capability: []const u8,
    feasibility: Feasibility,
    in_scope: bool,
    requires_approval: bool,
    endpoint: []const u8,
    params_hash: []const u8,
    reason: []const u8,
};

pub const Summary = struct {
    assets: usize = 0,
    endpoints: usize = 0,
    weaknesses: usize = 0,
    feasible: usize = 0,
    needs_capability: usize = 0,
    manual: usize = 0,
    out_of_scope: usize = 0,
    unknown: usize = 0,
};

pub const Report = struct {
    arena: std.heap.ArenaAllocator,
    scope_id: []const u8,
    generated_at_unix: i64,
    summary: Summary,
    actions: []const Action,

    pub fn deinit(self: *Report) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn find(self: *const Report, action_id: []const u8) ?*const Action {
        for (self.actions) |*action| {
            if (std.mem.eql(u8, action.id, action_id)) return action;
        }
        return null;
    }

    pub fn writeJson(self: *Report, writer: *Io.Writer) !void {
        const a = self.arena.allocator();
        const WireAction = struct {
            id: []const u8,
            target: []const u8,
            target_identity: []const u8,
            vulnerability_id: []const u8,
            title: []const u8,
            severity: []const u8,
            cvss: f32,
            access: []const u8,
            capability: []const u8,
            feasibility: []const u8,
            in_scope: bool,
            requires_approval: bool,
            technique: []const u8,
            endpoint: []const u8,
            params_hash: []const u8,
            reason: []const u8,
        };
        const wire_actions = try a.alloc(WireAction, self.actions.len);
        for (self.actions, 0..) |action, index| {
            wire_actions[index] = .{
                .id = action.id,
                .target = action.target,
                .target_identity = action.target_identity,
                .vulnerability_id = action.vulnerability_id,
                .title = action.title,
                .severity = action.severity,
                .cvss = action.cvss,
                .access = @tagName(action.access),
                .capability = action.capability,
                .feasibility = @tagName(action.feasibility),
                .in_scope = action.in_scope,
                .requires_approval = action.requires_approval,
                .technique = "exploit",
                .endpoint = action.endpoint,
                .params_hash = action.params_hash,
                .reason = action.reason,
            };
        }
        const WireReport = struct {
            schema: []const u8,
            scope_id: []const u8,
            generated_at_unix: i64,
            summary: Summary,
            actions: []const WireAction,
        };
        var json: std.json.Stringify = .{ .writer = writer, .options = .{ .whitespace = .indent_2 } };
        try json.write(WireReport{
            .schema = schema,
            .scope_id = self.scope_id,
            .generated_at_unix = self.generated_at_unix,
            .summary = self.summary,
            .actions = wire_actions,
        });
        try writer.writeByte('\n');
    }

    pub fn writeMarkdown(self: *const Report, writer: *Io.Writer) !void {
        try writer.print("# Attack surface\n\n", .{});
        try writer.print("scope: {s}  \ngenerated: {d}  \n", .{ self.scope_id, self.generated_at_unix });
        try writer.print(
            "assets: {d} · endpoints: {d} · weaknesses: {d}\n\n",
            .{ self.summary.assets, self.summary.endpoints, self.summary.weaknesses },
        );
        try writer.print(
            "feasible: {d} (approval required) · needs capability: {d} · manual: {d} · out of scope: {d} · unknown: {d}\n\n",
            .{
                self.summary.feasible,
                self.summary.needs_capability,
                self.summary.manual,
                self.summary.out_of_scope,
                self.summary.unknown,
            },
        );
        try writer.print(
            "| id | target | weakness | access | feasibility | cvss | approval |\n" ++
                "|---|---|---|---|---|---|---|\n",
            .{},
        );
        for (self.actions) |action| {
            try writer.print(
                "| {s} | {s} | {s} | {s} | {s} | {d:.1} | {s} |\n",
                .{
                    action.id,
                    action.target,
                    action.vulnerability_id,
                    @tagName(action.access),
                    @tagName(action.feasibility),
                    action.cvss,
                    if (action.requires_approval) "required" else "no",
                },
            );
        }
        if (self.actions.len > 0) try writer.print("\n", .{});
        for (self.actions) |action| {
            try writer.print("- {s}: {s}\n", .{ action.id, action.reason });
        }
    }
};

pub fn accessFromVector(vector: []const u8) Access {
    var iterator = std.mem.splitScalar(u8, vector, '/');
    while (iterator.next()) |token| {
        if (!std.mem.startsWith(u8, token, "AV:")) continue;
        if (token.len < 4) return .unknown;
        return switch (token[3]) {
            'N' => .network,
            'A' => .adjacent,
            'L' => .local,
            'P' => .physical,
            else => .unknown,
        };
    }
    return .unknown;
}

pub fn capabilityFor(access: Access) []const u8 {
    return switch (access) {
        .network => "network.probe",
        .adjacent => "radio.wifi/ble",
        .local => "host.access",
        .physical => "physical.access",
        .unknown => "unknown",
    };
}

pub fn feasibilityFor(access: Access, in_scope: bool) Feasibility {
    if (!in_scope) return .out_of_scope;
    return switch (access) {
        .network => .feasible,
        .adjacent => .needs_capability,
        .local, .physical => .manual,
        .unknown => .unknown,
    };
}

fn reasonFor(feasibility: Feasibility, access: Access) []const u8 {
    return switch (feasibility) {
        .feasible => "network reachable; exploitation requires human approval",
        .needs_capability => switch (access) {
            .adjacent => "requires a WiFi/BLE radio (not installed)",
            else => "requires a capability that is not installed",
        },
        .manual => "requires local or physical access",
        .out_of_scope => "target is outside the declared scope",
        .unknown => "no CVSS attack vector to classify",
    };
}

fn rank(feasibility: Feasibility) u8 {
    return switch (feasibility) {
        .feasible => 0,
        .needs_capability => 1,
        .manual => 2,
        .out_of_scope => 3,
        .unknown => 4,
    };
}

fn lessThan(_: void, a: Action, b: Action) bool {
    const ra = rank(a.feasibility);
    const rb = rank(b.feasibility);
    if (ra != rb) return ra < rb;
    if (a.cvss != b.cvss) return a.cvss > b.cvss;
    const target_order = std.mem.order(u8, a.target, b.target);
    if (target_order != .eq) return target_order == .lt;
    return std.mem.order(u8, a.vulnerability_id, b.vulnerability_id) == .lt;
}

const Target = struct {
    value: []const u8,
    kind: []const u8,
};

fn chooseTarget(asset: *const asset_graph.Asset, scope: *const control.Scope) Target {
    var address: ?[]const u8 = null;
    var hostname: ?[]const u8 = null;
    var package: ?[]const u8 = null;
    for (asset.identities.items) |identity| {
        switch (identity.kind) {
            .address => if (address == null) {
                address = identity.value;
            },
            .hostname => if (hostname == null) {
                hostname = identity.value;
            },
            .package => if (package == null) {
                package = identity.value;
            },
        }
    }
    // Prefer an identity the scope actually names, so an approval for this action
    // passes the same target check that built it.
    if (address) |value| {
        if (scope.allowsTarget(value)) return .{ .value = value, .kind = "address" };
    }
    if (hostname) |value| {
        if (scope.allowsTarget(value)) return .{ .value = value, .kind = "hostname" };
    }
    if (package) |value| {
        if (scope.allowsTarget(value)) return .{ .value = value, .kind = "package" };
    }
    if (address) |value| return .{ .value = value, .kind = "address" };
    if (hostname) |value| return .{ .value = value, .kind = "hostname" };
    if (package) |value| return .{ .value = value, .kind = "package" };
    return .{ .value = "unknown", .kind = "unknown" };
}

fn inScope(asset: *const asset_graph.Asset, scope: *const control.Scope) bool {
    for (asset.identities.items) |identity| {
        if (scope.allowsTarget(identity.value)) return true;
    }
    return false;
}

pub fn build(
    allocator: std.mem.Allocator,
    graph: *const asset_graph.AssetGraph,
    vulnerabilities: []const vulnerability_matcher.Vulnerability,
    matches: *const vulnerability_matcher.Report,
    scope: *const control.Scope,
    now: i64,
) !Report {
    if (matches.matches.items.len > max_actions) return error.TooManyActions;

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var actions: std.ArrayList(Action) = .empty;
    defer actions.deinit(a);

    for (matches.matches.items) |match| {
        const vulnerability = vulnerabilities[match.vulnerability_index];
        const asset = &graph.assets.items[match.asset_index];
        const endpoint = &asset.endpoints.items[match.endpoint_index];
        const target = chooseTarget(asset, scope);
        const target_in_scope = inScope(asset, scope);
        const access = accessFromVector(vulnerability.cvss_vector);
        const feasibility = feasibilityFor(access, target_in_scope);

        const endpoint_text = if (endpoint.port) |port|
            try std.fmt.allocPrint(a, "{s}/{d}", .{ endpoint.transport, port })
        else
            try a.dupe(u8, endpoint.transport);

        const canonical = try std.fmt.allocPrint(
            a,
            "{s}|{s}|{s}|{s}",
            .{ scope.id, target.value, vulnerability.id, endpoint_text },
        );
        const params_hash = try control.sha256Hex(a, canonical);

        try actions.append(a, .{
            .id = "",
            .target = try a.dupe(u8, target.value),
            .target_identity = target.kind,
            .vulnerability_id = try a.dupe(u8, vulnerability.id),
            .title = try a.dupe(u8, vulnerability.title),
            .severity = @tagName(vulnerability.severity),
            .cvss = vulnerability.cvss_score orelse 0,
            .access = access,
            .capability = capabilityFor(access),
            .feasibility = feasibility,
            .in_scope = target_in_scope,
            .requires_approval = true,
            .endpoint = endpoint_text,
            .params_hash = params_hash,
            .reason = reasonFor(feasibility, access),
        });
    }

    const owned_actions = try actions.toOwnedSlice(a);
    std.mem.sort(Action, owned_actions, {}, lessThan);
    for (owned_actions, 0..) |*action, index| {
        action.id = try std.fmt.allocPrint(a, "ACTION-{d}", .{index + 1});
    }

    var summary = Summary{
        .assets = graph.assets.items.len,
        .endpoints = matches.endpoints_examined,
        .weaknesses = matches.matches.items.len,
    };
    for (owned_actions) |action| {
        switch (action.feasibility) {
            .feasible => summary.feasible += 1,
            .needs_capability => summary.needs_capability += 1,
            .manual => summary.manual += 1,
            .out_of_scope => summary.out_of_scope += 1,
            .unknown => summary.unknown += 1,
        }
    }

    const scope_id_copy = try a.dupe(u8, scope.id);
    return .{
        .arena = arena,
        .scope_id = scope_id_copy,
        .generated_at_unix = now,
        .summary = summary,
        .actions = owned_actions,
    };
}

pub const StoredAction = struct {
    id: []const u8,
    target: []const u8,
    vulnerability_id: []const u8,
    technique: []const u8,
    feasibility: []const u8,
    params_hash: []const u8,
};

pub const Stored = struct {
    arena: std.heap.ArenaAllocator,
    scope_id: []const u8,
    actions: []const StoredAction,

    pub fn deinit(self: *Stored) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn find(self: *const Stored, action_id: []const u8) ?*const StoredAction {
        for (self.actions) |*action| {
            if (std.mem.eql(u8, action.id, action_id)) return action;
        }
        return null;
    }
};

/// Loads a surface document written by `Report.writeJson`. The returned value owns
/// all strings and is independent of the input buffer.
pub fn load(allocator: std.mem.Allocator, io: Io, path: []const u8) !Stored {
    const data = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(data);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, data);

    const WireAction = struct {
        id: []const u8 = "",
        target: []const u8 = "",
        vulnerability_id: []const u8 = "",
        technique: []const u8 = "exploit",
        feasibility: []const u8 = "",
        params_hash: []const u8 = "",
    };
    const Wire = struct {
        schema: []const u8 = "",
        scope_id: []const u8 = "",
        actions: []const WireAction = &.{},
    };
    const wire = std.json.parseFromSliceLeaky(Wire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidSurface;
    if (!std.mem.eql(u8, wire.schema, schema)) return error.UnsupportedSurfaceSchema;
    if (wire.actions.len > max_actions) return error.TooManyActions;

    const actions = try a.alloc(StoredAction, wire.actions.len);
    for (wire.actions, 0..) |action, index| {
        if (action.id.len == 0 or action.target.len == 0 or action.params_hash.len == 0) {
            return error.InvalidSurfaceAction;
        }
        actions[index] = .{
            .id = action.id,
            .target = action.target,
            .vulnerability_id = action.vulnerability_id,
            .technique = action.technique,
            .feasibility = action.feasibility,
            .params_hash = action.params_hash,
        };
    }
    return .{
        .arena = arena,
        .scope_id = wire.scope_id,
        .actions = actions,
    };
}

test "cvss access vectors map to the available capability" {
    try std.testing.expectEqual(Access.network, accessFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    try std.testing.expectEqual(Access.adjacent, accessFromVector("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    try std.testing.expectEqual(Access.local, accessFromVector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"));
    try std.testing.expectEqual(Access.physical, accessFromVector("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    try std.testing.expectEqual(Access.unknown, accessFromVector(""));
    try std.testing.expectEqualStrings("network.probe", capabilityFor(.network));
}

test "feasibility follows access and scope" {
    try std.testing.expectEqual(Feasibility.feasible, feasibilityFor(.network, true));
    try std.testing.expectEqual(Feasibility.needs_capability, feasibilityFor(.adjacent, true));
    try std.testing.expectEqual(Feasibility.manual, feasibilityFor(.local, true));
    try std.testing.expectEqual(Feasibility.manual, feasibilityFor(.physical, true));
    try std.testing.expectEqual(Feasibility.out_of_scope, feasibilityFor(.network, false));
    try std.testing.expectEqual(Feasibility.unknown, feasibilityFor(.unknown, true));
}
