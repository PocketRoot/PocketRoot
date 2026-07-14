const std = @import("std");
const builtin = @import("builtin");
const protocol = @import("../protocols/protocol.zig");
const windows_system = @import("windows_system.zig");

pub const max_targets = 64;
pub const max_target_bytes = 80;
pub const min_timeout_ms = 100;
pub const max_timeout_ms = 2_000;
pub const min_total_timeout_ms = 100;
pub const max_total_timeout_ms = 60_000;
pub const max_output_bytes = 256 * 1024;

pub const Options = struct {
    timeout_ms: u32 = 500,
    total_timeout_ms: u32 = 10_000,
};

const Family = enum {
    ipv4,
    ipv6,

    fn protocolName(self: Family) []const u8 {
        return if (self == .ipv4) "icmp" else "icmpv6";
    }
};

const TargetInfo = struct {
    family: Family,
    base: []const u8,
    scope_id: ?u32 = null,
};

const WindowsNeighbor = struct {
    target: []const u8,
    family: []const u8,
    ping: bool,
    mac: ?[]const u8 = null,
    state: ?[]const u8 = null,
    interface_index: ?u32 = null,
};

pub fn probe(
    allocator: std.mem.Allocator,
    io: std.Io,
    targets: []const []const u8,
    options: Options,
) !protocol.AnalysisResult {
    try validateOptions(targets, options);
    return switch (builtin.os.tag) {
        .windows => probeWindows(allocator, io, targets, options),
        else => error.UnsupportedPlatform,
    };
}

fn validateOptions(targets: []const []const u8, options: Options) !void {
    if (targets.len == 0) return error.MissingTargets;
    if (targets.len > max_targets) return error.TooManyTargets;
    if (options.timeout_ms < min_timeout_ms or options.timeout_ms > max_timeout_ms) return error.InvalidTimeout;
    if (options.total_timeout_ms < min_total_timeout_ms or options.total_timeout_ms > max_total_timeout_ms) {
        return error.InvalidTotalTimeout;
    }
    for (targets) |target| _ = try parseTarget(target);
}

fn probeWindows(
    allocator: std.mem.Allocator,
    io: std.Io,
    targets: []const []const u8,
    options: Options,
) !protocol.AnalysisResult {
    const powershell_path = try windows_system.executablePath(
        allocator,
        "WindowsPowerShell\\v1.0\\powershell.exe",
    );
    defer allocator.free(powershell_path);
    const script = try buildWindowsScript(allocator, targets, options.timeout_ms);
    defer allocator.free(script);
    const command = std.process.run(allocator, io, .{
        .argv = &.{ powershell_path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script },
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(64 * 1024),
        .timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(options.total_timeout_ms),
            .clock = .awake,
        } },
    }) catch |err| switch (err) {
        error.StreamTooLong => return error.OutputTooLarge,
        error.Timeout => return error.Timeout,
        else => return err,
    };
    defer allocator.free(command.stdout);
    defer allocator.free(command.stderr);
    switch (command.term) {
        .exited => |code| if (code != 0) return error.NeighborProbeFailed,
        else => return error.NeighborProbeFailed,
    }
    return analyzeWindowsSnapshot(allocator, command.stdout);
}

fn buildWindowsScript(
    allocator: std.mem.Allocator,
    targets: []const []const u8,
    timeout_ms: u32,
) ![]u8 {
    var script: std.ArrayList(u8) = .empty;
    errdefer script.deinit(allocator);
    try script.appendSlice(allocator, "$targets = @(");
    for (targets, 0..) |target, index| {
        if (index != 0) try script.append(allocator, ',');
        try script.append(allocator, '\'');
        try script.appendSlice(allocator, target);
        try script.append(allocator, '\'');
    }
    try script.appendSlice(allocator, ")\n$timeoutMs = ");
    var timeout_buffer: [16]u8 = undefined;
    try script.appendSlice(allocator, try std.fmt.bufPrint(&timeout_buffer, "{d}", .{timeout_ms}));
    try script.append(allocator, '\n');
    try script.appendSlice(allocator,
        \\$ErrorActionPreference = 'Stop'
        \\[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        \\$items = foreach ($target in $targets) {
        \\  $queryTarget = $target
        \\  $scope = $null
        \\  $scopeAt = $target.LastIndexOf('%')
        \\  if ($scopeAt -ge 0) {
        \\    $queryTarget = $target.Substring(0, $scopeAt)
        \\    $scope = [uint32]$target.Substring($scopeAt + 1)
        \\  }
        \\  $ip = [System.Net.IPAddress]::Parse($queryTarget)
        \\  $isV6 = $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
        \\  $pingArgs = @($(if ($isV6) { '-6' } else { '-4' }), '-n', '1', '-w', [string]$timeoutMs, $target)
        \\  & "$env:SystemRoot\System32\PING.EXE" @pingArgs *> $null
        \\  $pingOk = $LASTEXITCODE -eq 0
        \\  $neighborArgs = @{ IPAddress = $queryTarget; ErrorAction = 'SilentlyContinue' }
        \\  if ($null -ne $scope) { $neighborArgs.InterfaceIndex = $scope }
        \\  $neighbor = @(Get-NetNeighbor @neighborArgs | Select-Object -First 1)[0]
        \\  [PSCustomObject]@{
        \\    target = $target
        \\    family = $(if ($isV6) { 'ipv6' } else { 'ipv4' })
        \\    ping = [bool]$pingOk
        \\    mac = if ($neighbor -and $neighbor.LinkLayerAddress) { [string]$neighbor.LinkLayerAddress } else { $null }
        \\    state = if ($neighbor) { [string]$neighbor.State } else { $null }
        \\    interface_index = if ($neighbor) { [uint32]$neighbor.InterfaceIndex } else { $null }
        \\  }
        \\}
        \\ConvertTo-Json -InputObject @($items) -Depth 3 -Compress
    );
    return script.toOwnedSlice(allocator);
}

fn analyzeWindowsSnapshot(allocator: std.mem.Allocator, bytes: []const u8) !protocol.AnalysisResult {
    var json = std.mem.trim(u8, bytes, " \t\r\n");
    if (std.mem.startsWith(u8, json, "\xef\xbb\xbf")) json = json[3..];
    var parsed = try std.json.parseFromSlice([]WindowsNeighbor, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value.len > max_targets) return error.TooManyTargets;

    var result = try protocol.AnalysisResult.init(allocator, "Windows neighbor and ICMP probe");
    errdefer result.deinit();
    try result.addField("platform", "windows");
    try result.addNumberField("targets", parsed.value.len);

    var ping_replies: usize = 0;
    var neighbor_entries: usize = 0;
    var hosts_observed: usize = 0;
    for (parsed.value, 0..) |row, index| {
        const target = parseTarget(row.target) catch return error.InvalidSnapshot;
        const expected_family = if (target.family == .ipv4) "ipv4" else "ipv6";
        if (!std.mem.eql(u8, row.family, expected_family)) return error.InvalidSnapshot;
        const state = if (row.state) |value| safeToken(value) else null;
        const mac = if (row.mac) |value| safeMac(value) else null;
        if (row.ping) ping_replies += 1;
        if (state != null or mac != null or row.interface_index != null) neighbor_entries += 1;

        var key_buffer: [64]u8 = undefined;
        const ordinal = index + 1;
        try result.addField(try std.fmt.bufPrint(&key_buffer, "target_{d}_address", .{ordinal}), row.target);
        try result.addField(try std.fmt.bufPrint(&key_buffer, "target_{d}_protocol", .{ordinal}), target.family.protocolName());
        try result.addField(try std.fmt.bufPrint(&key_buffer, "target_{d}_ping_reply", .{ordinal}), if (row.ping) "yes" else "no");
        if (state) |value| {
            try result.addField(try std.fmt.bufPrint(&key_buffer, "target_{d}_neighbor_state", .{ordinal}), value);
        }
        if (mac) |value| {
            try result.addField(try std.fmt.bufPrint(&key_buffer, "target_{d}_mac", .{ordinal}), value);
        }
        if (row.interface_index) |interface_index| {
            try result.addNumberField(try std.fmt.bufPrint(&key_buffer, "target_{d}_interface_index", .{ordinal}), interface_index);
        }

        if (!row.ping and !neighborStateShowsHost(state, mac)) continue;
        var evidence_buffer: [192]u8 = undefined;
        const evidence = formatEvidence(&evidence_buffer, row.ping, state, mac);
        if (try result.addNetworkObservation(.{
            .kind = .host,
            .confidence = if (row.ping) .confirmed else .observed,
            .address = row.target,
            .transport = if (row.ping)
                target.family.protocolName()
            else if (target.family == .ipv4)
                "arp"
            else
                "ndp",
            .evidence = evidence,
            .source_id = if (row.ping) "windows:ping" else "windows:neighbor-cache",
        })) hosts_observed += 1;
    }

    try result.addNumberField("ping_replies", ping_replies);
    try result.addNumberField("neighbor_entries", neighbor_entries);
    try result.addNumberField("hosts_observed", hosts_observed);
    var summary_buffer: [144]u8 = undefined;
    try result.setSummary(try std.fmt.bufPrint(
        &summary_buffer,
        "Neighbor probe: {d}/{d} ICMP replies, {d} host observations",
        .{ ping_replies, parsed.value.len, hosts_observed },
    ));
    return result;
}

fn parseTarget(value: []const u8) !TargetInfo {
    if (value.len == 0 or value.len > max_target_bytes) return error.InvalidTarget;
    if (std.Io.net.Ip4Address.parse(value, 0)) |address| {
        if ((address.bytes[0] == 0 and address.bytes[1] == 0 and address.bytes[2] == 0 and address.bytes[3] == 0) or
            address.bytes[0] >= 224)
        {
            return error.InvalidTarget;
        }
        return .{ .family = .ipv4, .base = value };
    } else |_| {}

    const percent = std.mem.lastIndexOfScalar(u8, value, '%');
    const base = if (percent) |index| value[0..index] else value;
    if (base.len == 0 or (percent != null and std.mem.indexOfScalar(u8, base, '%') != null)) return error.InvalidTarget;
    const scope_id: ?u32 = if (percent) |index| scope: {
        if (index + 1 == value.len) return error.InvalidTarget;
        const parsed = std.fmt.parseInt(u32, value[index + 1 ..], 10) catch return error.InvalidTarget;
        if (parsed == 0) return error.InvalidTarget;
        break :scope parsed;
    } else null;
    const address = std.Io.net.Ip6Address.parse(base, 0) catch return error.InvalidTarget;
    var nonzero = false;
    for (address.bytes) |byte| nonzero = nonzero or byte != 0;
    if (!nonzero or address.bytes[0] == 0xff) return error.InvalidTarget;
    const link_local = address.bytes[0] == 0xfe and (address.bytes[1] & 0xc0) == 0x80;
    if (link_local and scope_id == null) return error.MissingScopeId;
    return .{ .family = .ipv6, .base = base, .scope_id = scope_id };
}

fn safeToken(value: []const u8) ?[]const u8 {
    if (value.len == 0 or value.len > 32) return null;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return null;
    }
    return value;
}

fn safeMac(value: []const u8) ?[]const u8 {
    if (value.len == 0 or value.len > 32) return null;
    var hex_digits: usize = 0;
    for (value) |byte| {
        if (std.ascii.isHex(byte)) {
            hex_digits += 1;
        } else if (byte != '-' and byte != ':') {
            return null;
        }
    }
    if (hex_digits != 12 and hex_digits != 16) return null;
    return value;
}

fn neighborStateShowsHost(state: ?[]const u8, mac: ?[]const u8) bool {
    if (mac != null) return true;
    const value = state orelse return false;
    return std.ascii.eqlIgnoreCase(value, "Reachable") or
        std.ascii.eqlIgnoreCase(value, "Stale") or
        std.ascii.eqlIgnoreCase(value, "Delay") or
        std.ascii.eqlIgnoreCase(value, "Probe") or
        std.ascii.eqlIgnoreCase(value, "Permanent");
}

fn formatEvidence(
    buffer: *[192]u8,
    ping: bool,
    state: ?[]const u8,
    mac: ?[]const u8,
) []const u8 {
    if (ping) {
        if (state) |state_value| {
            if (mac) |mac_value| return std.fmt.bufPrint(buffer, "ICMP echo reply; neighbor={s}; mac={s}", .{ state_value, mac_value }) catch unreachable;
            return std.fmt.bufPrint(buffer, "ICMP echo reply; neighbor={s}", .{state_value}) catch unreachable;
        }
        if (mac) |mac_value| return std.fmt.bufPrint(buffer, "ICMP echo reply; mac={s}", .{mac_value}) catch unreachable;
        return "ICMP echo reply";
    }
    if (state) |state_value| {
        if (mac) |mac_value| return std.fmt.bufPrint(buffer, "Neighbor cache: state={s}; mac={s}", .{ state_value, mac_value }) catch unreachable;
        return std.fmt.bufPrint(buffer, "Neighbor cache: state={s}", .{state_value}) catch unreachable;
    }
    return std.fmt.bufPrint(buffer, "Neighbor cache: mac={s}", .{mac.?}) catch unreachable;
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

test "neighbor targets are explicit bounded IP literals" {
    try std.testing.expectEqual(Family.ipv4, (try parseTarget("192.0.2.1")).family);
    try std.testing.expectEqual(Family.ipv6, (try parseTarget("2001:db8::1")).family);
    try std.testing.expectEqual(@as(?u32, 12), (try parseTarget("fe80::1%12")).scope_id);
    try std.testing.expectError(error.MissingScopeId, parseTarget("fe80::1"));
    try std.testing.expectError(error.InvalidTarget, parseTarget("example.com"));
    try std.testing.expectError(error.InvalidTarget, parseTarget("224.0.0.1"));
    try std.testing.expectError(error.InvalidTarget, parseTarget("ff02::1%12"));
}

test "neighbor PowerShell plan contains only validated targets and hard timeout" {
    const targets = [_][]const u8{ "192.0.2.1", "fe80::1%7" };
    try validateOptions(&targets, .{ .timeout_ms = 750, .total_timeout_ms = 5_000 });
    const script = try buildWindowsScript(std.testing.allocator, &targets, 750);
    defer std.testing.allocator.free(script);
    try std.testing.expect(std.mem.startsWith(
        u8,
        script,
        "$targets = @('192.0.2.1','fe80::1%7')\n$timeoutMs = 750\n$ErrorActionPreference = 'Stop'",
    ));
    try std.testing.expect(std.mem.indexOf(u8, script, "Get-NetNeighbor") != null);
}

test "neighbor snapshot emits bounded structured host observations" {
    const fixture =
        \\[
        \\  {"target":"192.0.2.10","family":"ipv4","ping":true,"mac":"00-11-22-33-44-55","state":"Reachable","interface_index":4},
        \\  {"target":"2001:db8::20","family":"ipv6","ping":false,"mac":"66-77-88-99-AA-BB","state":"Stale","interface_index":7},
        \\  {"target":"192.0.2.30","family":"ipv4","ping":false,"mac":null,"state":"Unreachable","interface_index":4}
        \\]
    ;
    var result = try analyzeWindowsSnapshot(std.testing.allocator, fixture);
    defer result.deinit();

    try std.testing.expectEqualStrings("1", fieldValue(&result, "ping_replies").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "hosts_observed").?);
    try std.testing.expectEqualStrings("00-11-22-33-44-55", fieldValue(&result, "target_1_mac").?);
    try std.testing.expectEqualStrings("icmpv6", fieldValue(&result, "target_2_protocol").?);
    try std.testing.expectEqual(@as(usize, 2), result.observations.items.len);
    try std.testing.expectEqual(protocol.ObservationConfidence.confirmed, result.observations.items[0].confidence);
    try std.testing.expectEqual(protocol.ObservationConfidence.observed, result.observations.items[1].confidence);
    try std.testing.expectEqualStrings("ndp", result.observations.items[1].transport);
}
