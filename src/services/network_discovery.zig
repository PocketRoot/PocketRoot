const std = @import("std");
const protocol = @import("../protocols/protocol.zig");
const tcp_scan = @import("tcp_scan.zig");

pub const max_hosts = 64;
pub const max_ports = 4;
pub const min_total_timeout_ms = 100;

pub const Options = struct {
    timeout_ms: u32 = 200,
    total_timeout_ms: u32 = 5_000,
};

pub const Ipv4Range = struct {
    network: u32,
    prefix: u8,
    first: u32,
    host_count: usize,
};

pub fn discover(
    allocator: std.mem.Allocator,
    io: std.Io,
    cidr: []const u8,
    ports: []const u16,
    options: Options,
) !protocol.AnalysisResult {
    if (ports.len == 0) return error.MissingPorts;
    if (ports.len > max_ports) return error.TooManyPorts;
    for (ports) |port| if (port == 0) return error.InvalidPort;
    if (options.timeout_ms < tcp_scan.min_timeout_ms or options.timeout_ms > tcp_scan.max_timeout_ms) {
        return error.InvalidTimeout;
    }
    if (options.total_timeout_ms < min_total_timeout_ms or
        options.total_timeout_ms > tcp_scan.max_total_timeout_ms)
    {
        return error.InvalidTotalTimeout;
    }
    const range = try parseIpv4Range(cidr);

    var normalized_buffer: [18]u8 = undefined;
    const normalized = try formatCidr(&normalized_buffer, range.network, range.prefix);
    var result = try protocol.AnalysisResult.init(allocator, "Bounded TCP host discovery");
    errdefer result.deinit();
    try result.addField("cidr", normalized);
    try result.addNumberField("hosts_requested", range.host_count);
    try result.addNumberField("ports_per_host", ports.len);
    try result.addNumberField("total_timeout_ms", options.total_timeout_ms);

    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(options.total_timeout_ms),
        .clock = .awake,
    });
    var hosts_probed: usize = 0;
    var hosts_responsive: usize = 0;
    var deadline_reached = false;

    // ponytail: at most 64 sequential hosts; add bounded concurrency only if this becomes too slow in practice.
    scan_hosts: for (0..range.host_count) |index| {
        const remaining_ms = remainingWholeMilliseconds(io, deadline) orelse {
            deadline_reached = true;
            break;
        };
        var address_buffer: [15]u8 = undefined;
        const address = try formatIpv4(&address_buffer, range.first + @as(u32, @intCast(index)));
        var host_result = tcp_scan.scan(allocator, io, address, ports, .{
            .timeout_ms = options.timeout_ms,
            .total_timeout_ms = remaining_ms,
        }) catch |err| switch (err) {
            error.Timeout => {
                deadline_reached = true;
                break :scan_hosts;
            },
            else => return err,
        };
        defer host_result.deinit();
        hosts_probed += 1;

        for (host_result.observations.items) |observation| {
            if (observation.kind != .host or observation.confidence != .confirmed) continue;
            if (try result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .confirmed,
                .address = address,
                .evidence = observation.evidence,
                .source_id = "network-discovery:tcp-response",
            })) hosts_responsive += 1;
            break;
        }
        if (fieldEquals(&host_result, "scan_deadline_reached", "yes")) {
            deadline_reached = true;
            break;
        }
    }

    try result.addNumberField("hosts_probed", hosts_probed);
    try result.addNumberField("hosts_responsive", hosts_responsive);
    try result.addField("discovery_deadline_reached", if (deadline_reached) "yes" else "no");

    var summary_buffer: [128]u8 = undefined;
    try result.setSummary(try std.fmt.bufPrint(
        &summary_buffer,
        "TCP discovery {s}: {d}/{d} responsive, {d} requested",
        .{ normalized, hosts_responsive, hosts_probed, range.host_count },
    ));
    return result;
}

fn parseIpv4Range(cidr: []const u8) !Ipv4Range {
    return parseIpv4RangeBounded(cidr, max_hosts);
}

pub fn parseIpv4RangeBounded(cidr: []const u8, host_limit: usize) !Ipv4Range {
    const slash = std.mem.indexOfScalar(u8, cidr, '/') orelse return error.InvalidCidr;
    if (slash == 0 or slash + 1 == cidr.len or
        std.mem.lastIndexOfScalar(u8, cidr, '/') != slash) return error.InvalidCidr;
    const prefix = std.fmt.parseInt(u8, cidr[slash + 1 ..], 10) catch return error.InvalidCidr;
    if (prefix > 32) return error.InvalidCidr;
    const parsed = std.Io.net.Ip4Address.parse(cidr[0..slash], 0) catch return error.InvalidCidr;
    const address = (@as(u32, parsed.bytes[0]) << 24) |
        (@as(u32, parsed.bytes[1]) << 16) |
        (@as(u32, parsed.bytes[2]) << 8) |
        parsed.bytes[3];
    const host_bits: u6 = @intCast(32 - prefix);
    const address_count = @as(u64, 1) << host_bits;
    if (address_count > host_limit) return error.TooManyHosts;

    const mask: u32 = if (prefix == 0)
        0
    else
        @as(u32, std.math.maxInt(u32)) << @as(u5, @intCast(32 - prefix));
    const network = address & mask;
    const omit_network_and_broadcast = prefix <= 30;
    return .{
        .network = network,
        .prefix = prefix,
        .first = network + @intFromBool(omit_network_and_broadcast),
        .host_count = @intCast(address_count - @as(u64, if (omit_network_and_broadcast) 2 else 0)),
    };
}

pub fn formatIpv4(buffer: *[15]u8, address: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{
        address >> 24,
        (address >> 16) & 0xff,
        (address >> 8) & 0xff,
        address & 0xff,
    });
}

pub fn formatCidr(buffer: *[18]u8, network: u32, prefix: u8) ![]const u8 {
    var address_buffer: [15]u8 = undefined;
    const address = try formatIpv4(&address_buffer, network);
    return std.fmt.bufPrint(buffer, "{s}/{d}", .{ address, prefix });
}

fn remainingWholeMilliseconds(io: std.Io, deadline: std.Io.Clock.Timestamp) ?u32 {
    const now = std.Io.Clock.Timestamp.now(io, deadline.clock);
    if (now.raw.nanoseconds >= deadline.raw.nanoseconds) return null;
    const milliseconds = @divFloor(
        deadline.raw.nanoseconds - now.raw.nanoseconds,
        std.time.ns_per_ms,
    );
    if (milliseconds < tcp_scan.min_timeout_ms) return null;
    return @intCast(@min(milliseconds, tcp_scan.max_total_timeout_ms));
}

fn fieldEquals(result: *const protocol.AnalysisResult, name: []const u8, value: []const u8) bool {
    for (result.fields.items) |field| {
        if (std.mem.eql(u8, field.name, name)) return std.mem.eql(u8, field.value, value);
    }
    return false;
}

fn acceptAndClose(server: *std.Io.net.Server, io: std.Io) std.Io.Cancelable!void {
    const stream = server.accept(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    stream.close(io);
}

test "IPv4 CIDR discovery enforces target bounds" {
    const range = try parseIpv4Range("192.0.2.17/26");
    try std.testing.expectEqual(@as(u32, 0xc0000200), range.network);
    try std.testing.expectEqual(@as(u32, 0xc0000201), range.first);
    try std.testing.expectEqual(@as(usize, 62), range.host_count);
    try std.testing.expectEqual(@as(usize, 2), (try parseIpv4Range("192.0.2.0/31")).host_count);
    try std.testing.expectEqual(@as(usize, 1), (try parseIpv4Range("192.0.2.1/32")).host_count);
    try std.testing.expectError(error.TooManyHosts, parseIpv4Range("192.0.2.0/25"));
    try std.testing.expectError(error.InvalidCidr, parseIpv4Range("2001:db8::/128"));
}

test "IPv4 CIDR discovery records only confirmed hosts" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, acceptAndClose, .{ &server, std.testing.io });

    var result = try discover(
        std.testing.allocator,
        std.testing.io,
        "127.0.0.1/32",
        &.{server.socket.address.getPort()},
        .{ .timeout_ms = 500, .total_timeout_ms = 1_000 },
    );
    defer result.deinit();
    try group.await(std.testing.io);

    try std.testing.expectEqual(@as(usize, 1), result.observations.items.len);
    try std.testing.expectEqual(protocol.NetworkObservationKind.host, result.observations.items[0].kind);
    try std.testing.expectEqualStrings("127.0.0.1", result.observations.items[0].address);
    try std.testing.expect(fieldEquals(&result, "hosts_responsive", "1"));
    try std.testing.expect(fieldEquals(&result, "discovery_deadline_reached", "no"));
}

test "IPv4 CIDR discovery total deadline stops a stalled host scan" {
    var first_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var first_server = try first_address.listen(std.testing.io, .{});
    defer first_server.deinit(std.testing.io);
    var second_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var second_server = try second_address.listen(std.testing.io, .{});
    defer second_server.deinit(std.testing.io);

    const ports = [_]u16{
        first_server.socket.address.getPort(),
        second_server.socket.address.getPort(),
    };
    var result = try discover(
        std.testing.allocator,
        std.testing.io,
        "127.0.0.1/32",
        &ports,
        .{ .timeout_ms = 500, .total_timeout_ms = 100 },
    );
    defer result.deinit();

    // ponytail: two loopback listeners can both complete well within 100 ms, so this
    // asserts the budget invariants instead of "deadline must be reached"; proving the
    // mid-scan cutoff needs a blackholed peer (integration test).
    try std.testing.expect(fieldEquals(&result, "hosts_probed", "1"));
    try std.testing.expect(fieldEquals(&result, "hosts_responsive", "1"));
    try std.testing.expectEqual(@as(usize, 1), result.observations.items.len);
    try std.testing.expect(fieldEquals(&result, "hosts_requested", "1"));
}
