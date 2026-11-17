//! Campaign control plane: scope, human approvals, stop and the ledger.
//!
//! These are the invariants a real action must satisfy:
//!   * the target and technique are inside a declared scope;
//!   * an exploit has a live, single-use human approval bound to the exact action;
//!   * a stop request is honoured before a new action starts.
//!
//! The module is deliberately transport-agnostic. The surface report, a future
//! validation executor and a future exploit executor all call `evaluate` the same way.

const std = @import("std");
const Io = std.Io;

pub const scope_schema = "pocketroot.scope.v1";
pub const approval_schema = "pocketroot.approval.v1";
pub const state_schema = "pocketroot.campaign.v1";
pub const ledger_schema = "pocketroot.ledger.v1";

pub const default_approval_ttl_seconds: u32 = 15 * 60;
pub const max_approval_ttl_seconds: u32 = 24 * 60 * 60;
pub const max_targets: usize = 128;
pub const max_techniques: usize = 8;
pub const max_actions: u32 = 4096;
pub const max_ledger_bytes = 8 * 1024 * 1024;
pub const max_json_bytes = 64 * 1024;

pub const Technique = enum {
    validate,
    exploit,
    credential,
    lateral,

    pub fn isActive(self: Technique) bool {
        return self != .validate;
    }
};

pub const Phase = enum { disarmed, armed, stopped };

pub const Denial = error{
    stopped,
    disarmed,
    scope_expired,
    target_not_allowed,
    technique_not_allowed,
    approval_missing,
    approval_invalid,
    state_scope_mismatch,
    approval_expired,
    approval_used,
    approval_scope_mismatch,
    approval_action_mismatch,
    approval_target_mismatch,
    approval_params_mismatch,
    approval_technique_mismatch,
    budget_exhausted,
};

const ScopeWire = struct {
    schema: []const u8 = scope_schema,
    scope_id: []const u8 = "",
    targets: []const []const u8 = &.{},
    techniques: []const []const u8 = &.{},
    expires_at_unix: i64 = 0,
    /// Configurable per scope; defaults to 15 minutes.
    approval_ttl_seconds: u32 = default_approval_ttl_seconds,
    max_actions: u32 = 32,
};

pub const Scope = struct {
    arena: std.heap.ArenaAllocator,
    id: []const u8,
    targets: []const []const u8,
    techniques: []const Technique,
    expires_at_unix: i64,
    approval_ttl_seconds: u32,
    max_actions: u32,

    pub fn deinit(self: *Scope) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn allowsTechnique(self: *const Scope, technique: Technique) bool {
        for (self.techniques) |allowed| if (allowed == technique) return true;
        return false;
    }

    pub fn expired(self: *const Scope, now: i64) bool {
        return now >= self.expires_at_unix;
    }

    pub fn allowsTarget(self: *const Scope, target: []const u8) bool {
        for (self.targets) |allowed| {
            if (matchesTarget(allowed, target)) return true;
        }
        return false;
    }
};

/// Parses and validates a scope document. The returned Scope owns an arena; its
/// slices live until deinit.
pub fn parseScope(allocator: std.mem.Allocator, data: []const u8) !Scope {
    if (data.len > max_json_bytes) return error.ScopeTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, data);
    const wire = std.json.parseFromSliceLeaky(ScopeWire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidScope;
    if (!std.mem.eql(u8, wire.schema, scope_schema)) return error.UnsupportedScopeSchema;
    if (wire.scope_id.len == 0 or wire.scope_id.len > 128) return error.InvalidScopeId;
    if (wire.targets.len == 0 or wire.targets.len > max_targets) return error.InvalidScopeTargets;
    for (wire.targets) |target| {
        if (target.len == 0 or target.len > 256) return error.InvalidScopeTarget;
    }
    if (wire.techniques.len == 0 or wire.techniques.len > max_techniques) return error.InvalidScopeTechniques;
    if (wire.expires_at_unix <= 0) return error.InvalidScopeExpiry;
    if (wire.approval_ttl_seconds == 0 or wire.approval_ttl_seconds > max_approval_ttl_seconds) {
        return error.InvalidApprovalTtl;
    }
    if (wire.max_actions == 0 or wire.max_actions > max_actions) return error.InvalidActionBudget;

    const techniques = try a.alloc(Technique, wire.techniques.len);
    for (wire.techniques, 0..) |text, index| {
        techniques[index] = std.meta.stringToEnum(Technique, text) orelse return error.InvalidScopeTechnique;
    }

    return .{
        .arena = arena,
        .id = wire.scope_id,
        .targets = wire.targets,
        .techniques = techniques,
        .expires_at_unix = wire.expires_at_unix,
        .approval_ttl_seconds = wire.approval_ttl_seconds,
        .max_actions = wire.max_actions,
    };
}

fn parseIpv4(text: []const u8) ?[4]u8 {
    var parts: [4]u8 = undefined;
    var index: usize = 0;
    var iterator = std.mem.splitScalar(u8, text, '.');
    while (iterator.next()) |part| {
        if (index == 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        parts[index] = std.fmt.parseInt(u8, part, 10) catch return null;
        index += 1;
    }
    if (index != 4) return null;
    return parts;
}

fn ipv4InCidr(address: [4]u8, network: [4]u8, prefix: u8) bool {
    if (prefix > 32) return false;
    var bit: u8 = 0;
    while (bit < prefix) : (bit += 1) {
        const byte_index = bit / 8;
        const bit_index: u3 = @intCast(7 - (bit % 8));
        const mask: u8 = @as(u8, 1) << bit_index;
        if ((address[byte_index] & mask) != (network[byte_index] & mask)) return false;
    }
    return true;
}

fn hostPart(target: []const u8) []const u8 {
    const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return target;
    if (colon + 1 >= target.len) return target;
    _ = std.fmt.parseInt(u16, target[colon + 1 ..], 10) catch return target;
    return target[0..colon];
}

/// Exact hostname/IP match, a host without a port matching host:port, or an IPv4 CIDR
/// such as 192.0.2.0/24.
pub fn matchesTarget(allowed: []const u8, target: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(allowed, target)) return true;
    const host = hostPart(target);
    if (std.mem.indexOfScalar(u8, allowed, '/') == null and
        std.ascii.eqlIgnoreCase(allowed, host)) return true;
    const slash = std.mem.indexOfScalar(u8, allowed, '/') orelse return false;
    const network = parseIpv4(allowed[0..slash]) orelse return false;
    const prefix = std.fmt.parseInt(u8, allowed[slash + 1 ..], 10) catch return false;
    const address = parseIpv4(host) orelse return false;
    return ipv4InCidr(address, network, prefix);
}

pub const ActionRequest = struct {
    action_id: []const u8,
    target: []const u8,
    technique: Technique,
    params_hash: []const u8,
};

pub const Approval = struct {
    arena: std.heap.ArenaAllocator,
    id: []const u8,
    scope_id: []const u8,
    action_id: []const u8,
    target: []const u8,
    technique: Technique,
    params_hash: []const u8,
    operator: []const u8,
    reason: []const u8,
    created_at_unix: i64,
    expires_at_unix: i64,
    used: bool,

    pub fn deinit(self: *Approval) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn expired(self: *const Approval, now: i64) bool {
        return now >= self.expires_at_unix;
    }
};

const ApprovalWire = struct {
    schema: []const u8 = approval_schema,
    id: []const u8 = "",
    scope_id: []const u8 = "",
    action_id: []const u8 = "",
    target: []const u8 = "",
    technique: []const u8 = "exploit",
    params_hash: []const u8 = "",
    operator: []const u8 = "",
    reason: []const u8 = "",
    created_at_unix: i64 = 0,
    expires_at_unix: i64 = 0,
    used: bool = false,
};

pub fn approvalPath(allocator: std.mem.Allocator, campaign_dir: []const u8, action_id: []const u8) ![]u8 {
    const file = try std.fmt.allocPrint(allocator, "{s}.json", .{action_id});
    defer allocator.free(file);
    return std.fs.path.join(allocator, &.{ campaign_dir, "approvals", file });
}

fn writeJsonFile(io: Io, path: []const u8, value: anytype) !void {
    var buffer: [max_json_bytes]u8 = undefined;
    var output: Io.Writer = .fixed(&buffer);
    var json: std.json.Stringify = .{
        .writer = &output,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.write(value);
    try output.writeByte('\n');
    const dir_path = std.fs.path.dirname(path) orelse ".";
    try Io.Dir.cwd().createDirPath(io, dir_path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = output.buffered() });
}

pub fn sha256Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return allocator.dupe(u8, &hex);
}

pub fn paramsHash(
    allocator: std.mem.Allocator,
    scope_id: []const u8,
    action: ActionRequest,
) ![]u8 {
    const canonical = try std.fmt.allocPrint(
        allocator,
        "{s}|{s}|{s}|{s}",
        .{ scope_id, action.action_id, action.target, action.params_hash },
    );
    defer allocator.free(canonical);
    return sha256Hex(allocator, canonical);
}

/// Creates a single-use approval. The TTL comes from the scope, so an operator can
/// configure it per campaign; it is additionally capped by the scope expiry.
pub fn createApproval(
    allocator: std.mem.Allocator,
    io: Io,
    campaign_dir: []const u8,
    scope: *const Scope,
    action: ActionRequest,
    operator: []const u8,
    reason: []const u8,
    now: i64,
) !Approval {
    if (scope.expired(now)) return error.ScopeExpired;
    if (!scope.allowsTarget(action.target)) return error.TargetNotAllowed;
    if (!scope.allowsTechnique(action.technique)) return error.TechniqueNotAllowed;
    if (operator.len == 0 or operator.len > 128) return error.InvalidOperator;
    if (reason.len == 0 or reason.len > 512) return error.InvalidReason;

    const path = try approvalPath(allocator, campaign_dir, action.action_id);
    defer allocator.free(path);
    // A second approval for the same action replaces an unused one; a used one stays
    // as evidence and blocks re-approval until the operator clears it.
    if (loadApproval(allocator, io, path)) |existing| {
        var old = existing;
        defer old.deinit();
        if (old.used) return error.ApprovalAlreadyUsed;
    } else |_| {}

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var id_bytes: [8]u8 = undefined;
    io.random(&id_bytes);
    const id_hex = std.fmt.bytesToHex(id_bytes, .lower);
    const id = try a.dupe(u8, &id_hex);

    const ttl: i64 = @intCast(scope.approval_ttl_seconds);
    const requested = now + ttl;
    const expires = @min(requested, scope.expires_at_unix);

    const scope_id_copy = try a.dupe(u8, scope.id);
    const action_id_copy = try a.dupe(u8, action.action_id);
    const target_copy = try a.dupe(u8, action.target);
    const params_hash_copy = try a.dupe(u8, action.params_hash);
    const operator_copy = try a.dupe(u8, operator);
    const reason_copy = try a.dupe(u8, reason);
    const approval = Approval{
        .arena = arena,
        .id = id,
        .scope_id = scope_id_copy,
        .action_id = action_id_copy,
        .target = target_copy,
        .technique = action.technique,
        .params_hash = params_hash_copy,
        .operator = operator_copy,
        .reason = reason_copy,
        .created_at_unix = now,
        .expires_at_unix = expires,
        .used = false,
    };

    const Wire = struct {
        schema: []const u8,
        id: []const u8,
        scope_id: []const u8,
        action_id: []const u8,
        target: []const u8,
        technique: []const u8,
        params_hash: []const u8,
        operator: []const u8,
        reason: []const u8,
        created_at_unix: i64,
        expires_at_unix: i64,
        used: bool,
    };
    try writeJsonFile(io, path, Wire{
        .schema = approval_schema,
        .id = approval.id,
        .scope_id = approval.scope_id,
        .action_id = approval.action_id,
        .target = approval.target,
        .technique = @tagName(approval.technique),
        .params_hash = approval.params_hash,
        .operator = approval.operator,
        .reason = approval.reason,
        .created_at_unix = approval.created_at_unix,
        .expires_at_unix = approval.expires_at_unix,
        .used = approval.used,
    });
    return approval;
}

pub fn loadApproval(allocator: std.mem.Allocator, io: Io, path: []const u8) !Approval {
    const data = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_json_bytes));
    defer allocator.free(data);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, data);
    const wire = std.json.parseFromSliceLeaky(ApprovalWire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidApproval;
    if (!std.mem.eql(u8, wire.schema, approval_schema)) return error.UnsupportedApprovalSchema;
    const technique = std.meta.stringToEnum(Technique, wire.technique) orelse return error.InvalidApprovalTechnique;
    return .{
        .arena = arena,
        .id = wire.id,
        .scope_id = wire.scope_id,
        .action_id = wire.action_id,
        .target = wire.target,
        .technique = technique,
        .params_hash = wire.params_hash,
        .operator = wire.operator,
        .reason = wire.reason,
        .created_at_unix = wire.created_at_unix,
        .expires_at_unix = wire.expires_at_unix,
        .used = wire.used,
    };
}

/// Marks an approval used before the action starts. A failed action does not refund it.
pub fn consumeApproval(allocator: std.mem.Allocator, io: Io, path: []const u8, now: i64) !void {
    var approval = try loadApproval(allocator, io, path);
    defer approval.deinit();
    if (approval.used) return error.ApprovalAlreadyUsed;
    if (now >= approval.expires_at_unix) return error.ApprovalExpired;

    var buffer: [4096]u8 = undefined;
    var output: Io.Writer = .fixed(&buffer);
    var json: std.json.Stringify = .{
        .writer = &output,
        .options = .{ .whitespace = .indent_2 },
    };
    const Wire = struct {
        schema: []const u8,
        id: []const u8,
        scope_id: []const u8,
        action_id: []const u8,
        target: []const u8,
        technique: []const u8,
        params_hash: []const u8,
        operator: []const u8,
        reason: []const u8,
        created_at_unix: i64,
        expires_at_unix: i64,
        used: bool,
        used_at_unix: i64,
    };
    try json.write(Wire{
        .schema = approval_schema,
        .id = approval.id,
        .scope_id = approval.scope_id,
        .action_id = approval.action_id,
        .target = approval.target,
        .technique = @tagName(approval.technique),
        .params_hash = approval.params_hash,
        .operator = approval.operator,
        .reason = approval.reason,
        .created_at_unix = approval.created_at_unix,
        .expires_at_unix = approval.expires_at_unix,
        .used = true,
        .used_at_unix = now,
    });
    try output.writeByte('\n');
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = output.buffered() });
}

pub fn statePath(allocator: std.mem.Allocator, campaign_dir: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ campaign_dir, "state.json" });
}

pub const State = struct {
    arena: std.heap.ArenaAllocator,
    phase: Phase,
    scope_id: []const u8,
    actions_used: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, phase: Phase, scope_id: []const u8) !State {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        const id = try a.dupe(u8, scope_id);
        return .{
            .arena = arena,
            .phase = phase,
            .scope_id = id,
        };
    }

    pub fn deinit(self: *State) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const StateWire = struct {
    schema: []const u8 = state_schema,
    phase: []const u8 = "disarmed",
    scope_id: []const u8 = "",
    actions_used: u32 = 0,
};

pub fn loadState(allocator: std.mem.Allocator, io: Io, campaign_dir: []const u8) !State {
    const path = try statePath(allocator, campaign_dir);
    defer allocator.free(path);
    const data = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_json_bytes));
    defer allocator.free(data);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, data);
    const wire = std.json.parseFromSliceLeaky(StateWire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidCampaignState;
    if (!std.mem.eql(u8, wire.schema, state_schema)) return error.UnsupportedCampaignState;
    const phase = std.meta.stringToEnum(Phase, wire.phase) orelse return error.InvalidCampaignPhase;
    return .{
        .arena = arena,
        .phase = phase,
        .scope_id = wire.scope_id,
        .actions_used = wire.actions_used,
    };
}

pub fn saveState(allocator: std.mem.Allocator, io: Io, campaign_dir: []const u8, state: *const State) !void {
    const path = try statePath(allocator, campaign_dir);
    defer allocator.free(path);
    const Wire = struct {
        schema: []const u8,
        phase: []const u8,
        scope_id: []const u8,
        actions_used: u32,
    };
    try writeJsonFile(io, path, Wire{
        .schema = state_schema,
        .phase = @tagName(state.phase),
        .scope_id = state.scope_id,
        .actions_used = state.actions_used,
    });
}

pub fn stopPath(allocator: std.mem.Allocator, campaign_dir: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ campaign_dir, "STOP" });
}

pub fn isStopped(allocator: std.mem.Allocator, io: Io, campaign_dir: []const u8) bool {
    const path = stopPath(allocator, campaign_dir) catch return true;
    defer allocator.free(path);
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

pub fn requestStop(allocator: std.mem.Allocator, io: Io, campaign_dir: []const u8) !void {
    const path = try stopPath(allocator, campaign_dir);
    defer allocator.free(path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "stop requested\n" });
}

pub fn clearStop(allocator: std.mem.Allocator, io: Io, campaign_dir: []const u8) !void {
    const path = try stopPath(allocator, campaign_dir);
    defer allocator.free(path);
    Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// The single decision point used by every executor.
pub fn evaluate(
    allocator: std.mem.Allocator,
    io: Io,
    campaign_dir: []const u8,
    scope: *const Scope,
    state: *const State,
    request: ActionRequest,
    now: i64,
) Denial!void {
    if (isStopped(allocator, io, campaign_dir)) return error.stopped;
    if (state.phase != .armed) return error.disarmed;
    if (scope.expired(now)) return error.scope_expired;
    if (!std.mem.eql(u8, state.scope_id, scope.id)) return error.state_scope_mismatch;
    if (state.actions_used >= scope.max_actions) return error.budget_exhausted;
    if (!scope.allowsTarget(request.target)) return error.target_not_allowed;
    if (!scope.allowsTechnique(request.technique)) return error.technique_not_allowed;

    const path = approvalPath(allocator, campaign_dir, request.action_id) catch return error.approval_invalid;
    defer allocator.free(path);
    var approval = loadApproval(allocator, io, path) catch return error.approval_missing;
    defer approval.deinit();

    if (approval.used) return error.approval_used;
    if (approval.expired(now)) return error.approval_expired;
    if (!std.mem.eql(u8, approval.scope_id, scope.id)) return error.approval_scope_mismatch;
    if (!std.mem.eql(u8, approval.action_id, request.action_id)) return error.approval_action_mismatch;
    if (!std.mem.eql(u8, approval.target, request.target)) return error.approval_target_mismatch;
    if (approval.technique != request.technique) return error.approval_technique_mismatch;
    if (!std.mem.eql(u8, approval.params_hash, request.params_hash)) return error.approval_params_mismatch;
}

pub const LedgerInput = struct {
    event: []const u8,
    action_id: []const u8 = "",
    approval_id: []const u8 = "",
    target: []const u8 = "",
    technique: []const u8 = "",
    result: []const u8 = "",
    detail: []const u8 = "",
};

/// Appends one hash-chained ledger entry. The chain is tamper-evident, not signed.
pub fn appendLedger(
    allocator: std.mem.Allocator,
    io: Io,
    campaign_dir: []const u8,
    input: LedgerInput,
    now: i64,
) !void {
    const path = try std.fs.path.join(allocator, &.{ campaign_dir, "ledger.jsonl" });
    defer allocator.free(path);
    const existing = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_ledger_bytes)) catch |err| switch (err) {
        error.FileNotFound => try allocator.alloc(u8, 0),
        else => return err,
    };
    defer allocator.free(existing);

    var seq: u64 = 1;
    var prev_buffer: [64]u8 = undefined;
    var prev_len: usize = 0;
    var offset: usize = 0;
    while (offset < existing.len) : (offset += 1) {
        const line_end = std.mem.indexOfScalarPos(u8, existing, offset, '\n') orelse existing.len;
        const line = std.mem.trim(u8, existing[offset..line_end], " \t\r");
        if (line.len != 0) {
            var scratch = std.heap.ArenaAllocator.init(allocator);
            defer scratch.deinit();
            const Last = struct {
                seq: u64 = 0,
                hash: []const u8 = "",
            };
            if (std.json.parseFromSliceLeaky(Last, scratch.allocator(), line, .{
                .ignore_unknown_fields = true,
            })) |last| {
                seq = last.seq + 1;
                if (last.hash.len <= prev_buffer.len) {
                    @memcpy(prev_buffer[0..last.hash.len], last.hash);
                    prev_len = last.hash.len;
                }
            } else |_| {}
        }
        offset = line_end;
        if (offset >= existing.len) break;
    }
    const prev = prev_buffer[0..prev_len];

    const canonical = try std.fmt.allocPrint(
        allocator,
        "{d}|{d}|{s}|{s}|{s}|{s}|{s}|{s}|{s}|{s}",
        .{
            seq,
            now,
            input.event,
            input.action_id,
            input.approval_id,
            input.target,
            input.technique,
            input.result,
            input.detail,
            prev,
        },
    );
    defer allocator.free(canonical);
    const hash = try sha256Hex(allocator, canonical);
    defer allocator.free(hash);

    var buffer: [8192]u8 = undefined;
    var output: Io.Writer = .fixed(&buffer);
    var json: std.json.Stringify = .{ .writer = &output, .options = .{ .whitespace = .minified } };
    const Wire = struct {
        schema: []const u8,
        seq: u64,
        at_unix: i64,
        event: []const u8,
        action_id: []const u8,
        approval_id: []const u8,
        target: []const u8,
        technique: []const u8,
        result: []const u8,
        detail: []const u8,
        prev_hash: []const u8,
        hash: []const u8,
    };
    try json.write(Wire{
        .schema = ledger_schema,
        .seq = seq,
        .at_unix = now,
        .event = input.event,
        .action_id = input.action_id,
        .approval_id = input.approval_id,
        .target = input.target,
        .technique = input.technique,
        .result = input.result,
        .detail = input.detail,
        .prev_hash = prev,
        .hash = hash,
    });
    try output.writeByte('\n');

    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(allocator);
    try content.appendSlice(allocator, existing);
    if (existing.len > 0 and existing[existing.len - 1] != '\n') try content.append(allocator, '\n');
    try content.appendSlice(allocator, output.buffered());
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = content.items });
}

test "scope parses a configurable approval ttl" {
    const data =
        \\{
        \\  "schema": "pocketroot.scope.v1",
        \\  "scope_id": "lab-1",
        \\  "targets": ["192.0.2.0/24", "lab-apache-249.lan"],
        \\  "techniques": ["validate", "exploit"],
        \\  "expires_at_unix": 4102444800,
        \\  "approval_ttl_seconds": 60,
        \\  "max_actions": 4
        \\}
    ;
    var scope = try parseScope(std.testing.allocator, data);
    defer scope.deinit();
    try std.testing.expectEqual(@as(u32, 60), scope.approval_ttl_seconds);
    try std.testing.expect(scope.allowsTarget("192.0.2.80"));
    try std.testing.expect(scope.allowsTarget("LAB-APACHE-249.LAN"));
    try std.testing.expect(!scope.allowsTarget("192.0.3.1"));
    try std.testing.expect(scope.allowsTechnique(.exploit));
}

test "scope defaults the approval ttl to fifteen minutes" {
    const data =
        \\{"schema":"pocketroot.scope.v1","scope_id":"s","targets":["10.0.0.1"],"techniques":["exploit"],"expires_at_unix":4102444800}
    ;
    var scope = try parseScope(std.testing.allocator, data);
    defer scope.deinit();
    try std.testing.expectEqual(default_approval_ttl_seconds, scope.approval_ttl_seconds);
}

test "approval is single use, target bound and expires with the scope ttl" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/campaign", .{tmp.sub_path[0..]});
    defer std.testing.allocator.free(dir);
    try Io.Dir.cwd().createDirPath(std.testing.io, dir);

    const scope_data =
        \\{"schema":"pocketroot.scope.v1","scope_id":"s1","targets":["192.0.2.0/24"],"techniques":["validate","exploit"],"expires_at_unix":4102444800,"approval_ttl_seconds":60}
    ;
    var scope = try parseScope(std.testing.allocator, scope_data);
    defer scope.deinit();

    var state = try State.init(std.testing.allocator, .armed, "s1");
    defer state.deinit();
    try saveState(std.testing.allocator, std.testing.io, dir, &state);

    const request = ActionRequest{
        .action_id = "ACTION-1",
        .target = "192.0.2.80",
        .technique = .exploit,
        .params_hash = "params-1",
    };
    const now: i64 = 1000;
    var approval = try createApproval(std.testing.allocator, std.testing.io, dir, &scope, request, "alice", "ticket SEC-1", now);
    defer approval.deinit();
    try std.testing.expectEqual(now + 60, approval.expires_at_unix);

    try evaluate(std.testing.allocator, std.testing.io, dir, &scope, &state, request, now + 1);
    try std.testing.expectError(error.approval_expired, evaluate(
        std.testing.allocator,
        std.testing.io,
        dir,
        &scope,
        &state,
        request,
        now + 60,
    ));
    try std.testing.expectError(error.target_not_allowed, evaluate(
        std.testing.allocator,
        std.testing.io,
        dir,
        &scope,
        &state,
        .{ .action_id = "ACTION-1", .target = "192.0.3.1", .technique = .exploit, .params_hash = "params-1" },
        now + 1,
    ));
    try std.testing.expectError(error.approval_params_mismatch, evaluate(
        std.testing.allocator,
        std.testing.io,
        dir,
        &scope,
        &state,
        .{ .action_id = "ACTION-1", .target = "192.0.2.80", .technique = .exploit, .params_hash = "other" },
        now + 1,
    ));

    const path = try approvalPath(std.testing.allocator, dir, "ACTION-1");
    defer std.testing.allocator.free(path);
    try consumeApproval(std.testing.allocator, std.testing.io, path, now + 2);
    try std.testing.expectError(error.approval_used, evaluate(
        std.testing.allocator,
        std.testing.io,
        dir,
        &scope,
        &state,
        request,
        now + 3,
    ));
}

test "stop and disarm deny before any approval is considered" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/campaign", .{tmp.sub_path[0..]});
    defer std.testing.allocator.free(dir);
    try Io.Dir.cwd().createDirPath(std.testing.io, dir);

    const scope_data =
        \\{"schema":"pocketroot.scope.v1","scope_id":"s2","targets":["192.0.2.80"],"techniques":["exploit"],"expires_at_unix":4102444800,"approval_ttl_seconds":60}
    ;
    var scope = try parseScope(std.testing.allocator, scope_data);
    defer scope.deinit();
    var state = try State.init(std.testing.allocator, .armed, "s2");
    defer state.deinit();
    try saveState(std.testing.allocator, std.testing.io, dir, &state);
    const request = ActionRequest{
        .action_id = "ACTION-9",
        .target = "192.0.2.80",
        .technique = .exploit,
        .params_hash = "p",
    };
    try requestStop(std.testing.allocator, std.testing.io, dir);
    try std.testing.expectError(error.stopped, evaluate(
        std.testing.allocator,
        std.testing.io,
        dir,
        &scope,
        &state,
        request,
        10,
    ));
    try clearStop(std.testing.allocator, std.testing.io, dir);
    try std.testing.expectError(error.approval_missing, evaluate(
        std.testing.allocator,
        std.testing.io,
        dir,
        &scope,
        &state,
        request,
        10,
    ));
    state.phase = .disarmed;
    try saveState(std.testing.allocator, std.testing.io, dir, &state);
    try std.testing.expectError(error.disarmed, evaluate(
        std.testing.allocator,
        std.testing.io,
        dir,
        &scope,
        &state,
        request,
        10,
    ));
}

test "ledger entries chain their hashes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/campaign", .{tmp.sub_path[0..]});
    defer std.testing.allocator.free(dir);
    try Io.Dir.cwd().createDirPath(std.testing.io, dir);

    try appendLedger(std.testing.allocator, std.testing.io, dir, .{ .event = "arm" }, 1);
    try appendLedger(std.testing.allocator, std.testing.io, dir, .{ .event = "run", .action_id = "ACTION-1", .result = "dry-run" }, 2);
    const path = try std.fs.path.join(std.testing.allocator, &.{ dir, "ledger.jsonl" });
    defer std.testing.allocator.free(path);
    const data = try Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(max_ledger_bytes));
    defer std.testing.allocator.free(data);

    var lines = std.mem.splitScalar(u8, data, '\n');
    var prev: [64]u8 = undefined;
    var prev_len: usize = 0;
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const Entry = struct {
            seq: u64 = 0,
            prev_hash: []const u8 = "",
            hash: []const u8 = "",
        };
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const entry = try std.json.parseFromSliceLeaky(Entry, arena.allocator(), line, .{
            .ignore_unknown_fields = true,
        });
        try std.testing.expectEqual(count + 1, entry.seq);
        try std.testing.expectEqualStrings(prev[0..prev_len], entry.prev_hash);
        try std.testing.expect(entry.hash.len <= prev.len);
        @memcpy(prev[0..entry.hash.len], entry.hash);
        prev_len = entry.hash.len;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "scope host entries match host:port targets" {
    try std.testing.expect(matchesTarget("127.0.0.1", "127.0.0.1:8080"));
    try std.testing.expect(matchesTarget("192.0.2.0/24", "192.0.2.80:443"));
    try std.testing.expect(!matchesTarget("127.0.0.1", "127.0.0.2:8080"));
}
