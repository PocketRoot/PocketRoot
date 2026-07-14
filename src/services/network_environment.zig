const std = @import("std");
const builtin = @import("builtin");
const protocol = @import("../protocols/protocol.zig");
const windows_system = @import("windows_system.zig");

const WindowsInterface = struct {
    name: []const u8,
    index: u32,
    status: []const u8,
    metric: ?u32,
    virtual: bool,
    hardware: bool,
    ipv4: []const []const u8,
    ipv6: []const []const u8,
    gateways: []const []const u8,
    dns: []const []const u8,
};

const Ipv4Cidr = struct {
    address: u32,
    prefix: u8,
};

pub fn inspect(allocator: std.mem.Allocator, io: std.Io) !protocol.AnalysisResult {
    return switch (builtin.os.tag) {
        .windows => inspectWindows(allocator, io),
        else => error.UnsupportedPlatform,
    };
}

fn inspectWindows(allocator: std.mem.Allocator, io: std.Io) !protocol.AnalysisResult {
    // ponytail: use the built-in Windows provider on the dev host; replace it when the target runtime is chosen.
    const script =
        \\$ErrorActionPreference = 'Stop'
        \\[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        \\$items = Get-NetIPConfiguration | ForEach-Object {
        \\  [PSCustomObject]@{
        \\    name = [string]($_.InterfaceAlias -replace "[`r`n`t]", " ")
        \\    index = [uint32]$_.InterfaceIndex
        \\    status = [string]$_.NetAdapter.Status
        \\    metric = if ($null -ne $_.NetIPv4Interface.InterfaceMetric) { [uint32]$_.NetIPv4Interface.InterfaceMetric } else { $null }
        \\    virtual = [bool]$_.NetAdapter.Virtual
        \\    hardware = [bool]$_.NetAdapter.HardwareInterface
        \\    ipv4 = @($_.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
        \\    ipv6 = @($_.IPv6Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
        \\    gateways = @(@($_.IPv4DefaultGateway) + @($_.IPv6DefaultGateway) | Where-Object { $_ } | ForEach-Object { [string]$_.NextHop })
        \\    dns = @($_.DNSServer.ServerAddresses | ForEach-Object { [string]$_ })
        \\  }
        \\}
        \\ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
    ;

    const powershell_path = try windows_system.executablePath(
        allocator,
        "WindowsPowerShell\\v1.0\\powershell.exe",
    );
    defer allocator.free(powershell_path);
    const command = try std.process.run(allocator, io, .{
        .argv = &.{ powershell_path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(64 * 1024),
        .timeout = .{ .duration = .{ .raw = std.Io.Duration.fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(command.stdout);
    defer allocator.free(command.stderr);

    switch (command.term) {
        .exited => |code| if (code != 0) return error.NetworkInspectionFailed,
        else => return error.NetworkInspectionFailed,
    }
    return analyzeWindowsSnapshot(allocator, command.stdout);
}

fn analyzeWindowsSnapshot(allocator: std.mem.Allocator, bytes: []const u8) !protocol.AnalysisResult {
    var json = std.mem.trim(u8, bytes, " \t\r\n");
    if (std.mem.startsWith(u8, json, "\xef\xbb\xbf")) json = json[3..];

    var parsed = try std.json.parseFromSlice([]WindowsInterface, allocator, json, .{});
    defer parsed.deinit();

    var result = try protocol.AnalysisResult.init(allocator, "Local network environment");
    errdefer result.deinit();
    try result.addField("platform", "windows");
    try result.addNumberField("interfaces", parsed.value.len);

    var active_interfaces: usize = 0;
    var ipv4_addresses: usize = 0;
    var ipv6_addresses: usize = 0;
    var gateways: usize = 0;
    var dns_servers: usize = 0;
    var direct_scopes: usize = 0;
    const primary_index = selectPrimary(parsed.value);

    for (parsed.value, 0..) |interface, source_index| {
        if (!std.ascii.eqlIgnoreCase(interface.status, "Up")) continue;
        active_interfaces += 1;

        var key_buffer: [64]u8 = undefined;
        const name_key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_name", .{active_interfaces});
        try result.addField(name_key, interface.name);
        const index_key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_index", .{active_interfaces});
        try result.addNumberField(index_key, interface.index);
        const type_key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_type", .{active_interfaces});
        try result.addField(type_key, if (interface.hardware) "physical" else if (interface.virtual) "virtual" else "other");
        if (interface.metric) |metric| {
            const metric_key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_metric", .{active_interfaces});
            try result.addNumberField(metric_key, metric);
        }
        if (primary_index == source_index) {
            try result.addField("primary_interface", interface.name);
            try result.addNumberField("primary_interface_index", interface.index);
            if (interface.gateways.len > 0) try result.addField("primary_gateway", interface.gateways[0]);
        }

        for (interface.ipv4, 0..) |address, index| {
            const key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_ipv4_{d}", .{ active_interfaces, index + 1 });
            try result.addField(key, address);
            ipv4_addresses += 1;

            const cidr = parseIpv4Cidr(address) orelse continue;
            if (!isSuggestedAddress(cidr.address)) continue;
            var scope_buffer: [32]u8 = undefined;
            const scope = formatIpv4Network(cidr, &scope_buffer);
            var duplicate = false;
            for (result.fields.items) |field| {
                if (std.mem.startsWith(u8, field.name, "direct_scope_") and std.mem.eql(u8, field.value, scope)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;

            direct_scopes += 1;
            const scope_key = try std.fmt.bufPrint(&key_buffer, "direct_scope_{d}", .{direct_scopes});
            try result.addField(scope_key, scope);
            if (primary_index == source_index and fieldValue(&result, "primary_scope") == null) {
                try result.addField("primary_scope", scope);
            }
        }

        for (interface.ipv6, 0..) |address, index| {
            const key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_ipv6_{d}", .{ active_interfaces, index + 1 });
            try result.addField(key, address);
            ipv6_addresses += 1;
        }
        for (interface.gateways, 0..) |address, index| {
            const key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_gateway_{d}", .{ active_interfaces, index + 1 });
            try result.addField(key, address);
            gateways += 1;
        }
        for (interface.dns, 0..) |address, index| {
            const key = try std.fmt.bufPrint(&key_buffer, "interface_{d}_dns_{d}", .{ active_interfaces, index + 1 });
            try result.addField(key, address);
            dns_servers += 1;
        }
    }

    try result.addNumberField("active_interfaces", active_interfaces);
    try result.addNumberField("ipv4_addresses", ipv4_addresses);
    try result.addNumberField("ipv6_addresses", ipv6_addresses);
    try result.addNumberField("gateways", gateways);
    try result.addNumberField("dns_servers", dns_servers);
    try result.addNumberField("direct_scopes", direct_scopes);

    const summary = try std.fmt.allocPrint(
        allocator,
        "Local network: {d} active interface{s}, IPv4={d}, IPv6={d}, scopes={d}",
        .{ active_interfaces, if (active_interfaces == 1) "" else "s", ipv4_addresses, ipv6_addresses, direct_scopes },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);
    return result;
}

fn parseIpv4Cidr(value: []const u8) ?Ipv4Cidr {
    const slash = std.mem.findScalar(u8, value, '/') orelse return null;
    const prefix = std.fmt.parseInt(u8, value[slash + 1 ..], 10) catch return null;
    if (prefix > 32) return null;

    var octets: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, value[0..slash], '.');
    for (&octets) |*octet| {
        const part = parts.next() orelse return null;
        if (part.len == 0) return null;
        octet.* = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (parts.next() != null) return null;

    return .{
        .address = (@as(u32, octets[0]) << 24) |
            (@as(u32, octets[1]) << 16) |
            (@as(u32, octets[2]) << 8) |
            octets[3],
        .prefix = prefix,
    };
}

fn selectPrimary(interfaces: []const WindowsInterface) ?usize {
    var selected: ?usize = null;
    for (interfaces, 0..) |candidate, index| {
        if (!std.ascii.eqlIgnoreCase(candidate.status, "Up") or candidate.ipv4.len == 0) continue;
        const current = if (selected) |selected_index| interfaces[selected_index] else {
            selected = index;
            continue;
        };

        const candidate_gateway = candidate.gateways.len != 0;
        const current_gateway = current.gateways.len != 0;
        if (candidate_gateway != current_gateway) {
            if (candidate_gateway) selected = index;
            continue;
        }
        if (candidate.metric != null and current.metric == null) {
            selected = index;
            continue;
        }
        if (candidate.metric != null and current.metric != null and candidate.metric.? < current.metric.?) {
            selected = index;
            continue;
        }
        if (candidate.metric == current.metric and candidate.hardware and !current.hardware) selected = index;
    }
    return selected;
}

fn formatIpv4Network(cidr: Ipv4Cidr, buffer: *[32]u8) []const u8 {
    const mask: u32 = if (cidr.prefix == 0) 0 else mask: {
        const shift: u5 = @intCast(32 - cidr.prefix);
        break :mask @as(u32, std.math.maxInt(u32)) << shift;
    };
    const network = cidr.address & mask;
    return std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}/{d}", .{
        network >> 24,
        (network >> 16) & 0xff,
        (network >> 8) & 0xff,
        network & 0xff,
        cidr.prefix,
    }) catch unreachable;
}

fn isSuggestedAddress(address: u32) bool {
    const first = address >> 24;
    return first != 0 and first != 127 and first < 224;
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

test "Windows network snapshot returns active interfaces and scopes" {
    const fixture =
        \\[
        \\  {"name":"Virtual","index":2,"status":"Up","metric":null,"virtual":true,"hardware":false,"ipv4":["198.18.0.1/30"],"ipv6":[],"gateways":["198.18.0.2"],"dns":["198.18.0.2"]},
        \\  {"name":"Ethernet","index":4,"status":"Up","metric":25,"virtual":false,"hardware":true,"ipv4":["192.168.10.3/24","127.0.0.1/8"],"ipv6":["fe80::1/64"],"gateways":["192.168.10.1"],"dns":["1.1.1.1","8.8.8.8"]},
        \\  {"name":"Offline","index":8,"status":"Disconnected","metric":35,"virtual":false,"hardware":true,"ipv4":["10.0.0.2/8"],"ipv6":[],"gateways":[],"dns":[]}
        \\]
    ;
    var result = try analyzeWindowsSnapshot(std.testing.allocator, fixture);
    defer result.deinit();

    try std.testing.expectEqualStrings("3", fieldValue(&result, "interfaces").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "active_interfaces").?);
    try std.testing.expectEqualStrings("Ethernet", fieldValue(&result, "primary_interface").?);
    try std.testing.expectEqualStrings("192.168.10.0/24", fieldValue(&result, "primary_scope").?);
    try std.testing.expectEqualStrings("198.18.0.0/30", fieldValue(&result, "direct_scope_1").?);
    try std.testing.expectEqualStrings("192.168.10.0/24", fieldValue(&result, "direct_scope_2").?);
}

test "IPv4 CIDR parsing handles boundary prefixes" {
    var buffer: [32]u8 = undefined;
    try std.testing.expectEqualStrings("10.0.0.0/8", formatIpv4Network(parseIpv4Cidr("10.4.3.2/8").?, &buffer));
    try std.testing.expectEqualStrings("203.0.113.9/32", formatIpv4Network(parseIpv4Cidr("203.0.113.9/32").?, &buffer));
    try std.testing.expectEqualStrings("0.0.0.0/0", formatIpv4Network(parseIpv4Cidr("203.0.113.9/0").?, &buffer));
    try std.testing.expect(parseIpv4Cidr("203.0.113.9/33") == null);
    try std.testing.expect(parseIpv4Cidr("203.0.113/24") == null);
}
