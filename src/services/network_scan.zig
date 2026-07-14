const std = @import("std");
const protocol = @import("../protocols/protocol.zig");
const network_discovery = @import("network_discovery.zig");
const tcp_scan = @import("tcp_scan.zig");

pub const max_hosts = 256;
pub const max_ports = 64;
pub const max_concurrency = 32;
pub const max_total_timeout_ms = 120_000;
pub const min_total_timeout_ms = 100;
pub const max_aggregated_observations = protocol.max_observations;

pub const Options = struct {
    timeout_ms: u32 = 350,
    total_timeout_ms: u32 = 30_000,
    concurrency: usize = 8,
};

const HostBatches = struct {
    results: [2]?protocol.AnalysisResult = .{ null, null },
    count: usize = 0,
    truncated: bool = false,
    global_deadline_reached: bool = false,

    fn deinit(self: *HostBatches) void {
        for (self.results[0..self.count]) |*maybe_result| {
            if (maybe_result.*) |*result| result.deinit();
        }
        self.* = undefined;
    }
};

const AggregateStats = struct {
    hosts_responsive: usize = 0,
    open_endpoints: usize = 0,
    services_confirmed: usize = 0,
    services_inferred: usize = 0,
    observations_retained: usize = 0,
    observations_dropped: usize = 0,
};

const HostFuture = std.Io.Future(anyerror!HostBatches);

pub fn scan(
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
    if (options.total_timeout_ms < min_total_timeout_ms or options.total_timeout_ms > max_total_timeout_ms) {
        return error.InvalidTotalTimeout;
    }
    if (options.concurrency == 0 or options.concurrency > max_concurrency) return error.InvalidConcurrency;

    const range = try network_discovery.parseIpv4RangeBounded(cidr, max_hosts);
    var normalized_buffer: [18]u8 = undefined;
    const normalized = try network_discovery.formatCidr(&normalized_buffer, range.network, range.prefix);
    var result = try protocol.AnalysisResult.init(allocator, "Bounded concurrent TCP scan");
    errdefer result.deinit();
    try result.addField("cidr", normalized);
    try result.addNumberField("hosts_requested", range.host_count);
    try result.addNumberField("ports_per_host", ports.len);
    try result.addNumberField("concurrency", options.concurrency);
    try result.addNumberField("total_timeout_ms", options.total_timeout_ms);

    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(options.total_timeout_ms),
        .clock = .awake,
    });
    var futures: [max_concurrency]?HostFuture = .{null} ** max_concurrency;
    defer cancelPending(io, &futures);

    const slot_count = @min(options.concurrency, range.host_count);
    var hosts_started: usize = 0;
    var pending: usize = 0;
    for (0..slot_count) |slot| {
        futures[slot] = try io.concurrent(scanHost, .{
            io,
            range.first + @as(u32, @intCast(hosts_started)),
            ports,
            options.timeout_ms,
            deadline,
        });
        hosts_started += 1;
        pending += 1;
    }

    var stats: AggregateStats = .{};
    var hosts_completed: usize = 0;
    var scan_errors: usize = 0;
    var host_scans_truncated: usize = 0;
    var deadline_reached = false;
    var slot: usize = 0;

    while (pending != 0) {
        if (futures[slot]) |*future| {
            pending -= 1;
            hosts_completed += 1;

            var awaited = future.await(io);
            if (awaited) |*host| {
                defer host.deinit();
                try aggregateHost(&result, host, &stats);
                if (host.truncated) host_scans_truncated += 1;
                if (host.global_deadline_reached) deadline_reached = true;
            } else |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.OutOfMemory => return error.OutOfMemory,
                error.Timeout => deadline_reached = true,
                else => scan_errors += 1,
            }
            futures[slot] = null;

            if (deadlineReached(io, deadline)) deadline_reached = true;
            if (!deadline_reached and hosts_started < range.host_count) {
                futures[slot] = try io.concurrent(scanHost, .{
                    io,
                    range.first + @as(u32, @intCast(hosts_started)),
                    ports,
                    options.timeout_ms,
                    deadline,
                });
                hosts_started += 1;
                pending += 1;
            }
        }
        slot = (slot + 1) % slot_count;
    }

    if (hosts_started < range.host_count) deadline_reached = true;
    try result.addNumberField("hosts_started", hosts_started);
    try result.addNumberField("hosts_completed", hosts_completed);
    try result.addNumberField("hosts_responsive", stats.hosts_responsive);
    try result.addNumberField("open_endpoints", stats.open_endpoints);
    try result.addNumberField("services_confirmed", stats.services_confirmed);
    try result.addNumberField("services_inferred", stats.services_inferred);
    try result.addNumberField("host_scans_truncated", host_scans_truncated);
    try result.addNumberField("scan_errors", scan_errors);
    try result.addNumberField("observations_retained", stats.observations_retained);
    try result.addNumberField("observations_dropped", stats.observations_dropped);
    try result.addField("scan_deadline_reached", if (deadline_reached) "yes" else "no");

    var summary_buffer: [160]u8 = undefined;
    try result.setSummary(try std.fmt.bufPrint(
        &summary_buffer,
        "Concurrent TCP scan {s}: {d}/{d} responsive, {d} open endpoints",
        .{ normalized, stats.hosts_responsive, hosts_completed, stats.open_endpoints },
    ));
    return result;
}

fn scanHost(
    io: std.Io,
    address_value: u32,
    ports: []const u16,
    timeout_ms: u32,
    deadline: std.Io.Clock.Timestamp,
) anyerror!HostBatches {
    var host: HostBatches = .{};
    errdefer host.deinit();
    var address_buffer: [15]u8 = undefined;
    const address = try network_discovery.formatIpv4(&address_buffer, address_value);

    var offset: usize = 0;
    while (offset < ports.len) {
        const remaining_ms = remainingWholeMilliseconds(io, deadline) orelse {
            host.truncated = true;
            host.global_deadline_reached = true;
            break;
        };
        const end = @min(offset + tcp_scan.max_ports, ports.len);
        var batch = tcp_scan.scan(std.heap.smp_allocator, io, address, ports[offset..end], .{
            .timeout_ms = timeout_ms,
            .total_timeout_ms = remaining_ms,
        }) catch |err| switch (err) {
            error.Timeout => {
                host.truncated = true;
                host.global_deadline_reached = deadlineReached(io, deadline);
                break;
            },
            else => return err,
        };
        host.results[host.count] = batch;
        host.count += 1;
        offset = end;

        if (fieldEquals(&batch, "scan_deadline_reached", "yes")) {
            host.truncated = true;
            if (deadlineReached(io, deadline)) host.global_deadline_reached = true;
            break;
        }
    }
    return host;
}

fn aggregateHost(
    result: *protocol.AnalysisResult,
    host: *const HostBatches,
    stats: *AggregateStats,
) !void {
    var responsive: ?protocol.NetworkObservation = null;
    for (host.results[0..host.count]) |maybe_batch| {
        const batch = maybe_batch orelse continue;
        for (batch.observations.items) |observation| {
            if (observation.kind == .host and observation.confidence == .confirmed) {
                responsive = observation;
                break;
            }
        }
        if (responsive != null) break;
    }
    if (responsive) |observation| {
        stats.hosts_responsive += 1;
        try retainObservation(result, observation, stats);
    }

    for (host.results[0..host.count]) |maybe_batch| {
        const batch = maybe_batch orelse continue;
        for (batch.observations.items) |observation| switch (observation.kind) {
            .endpoint => {
                stats.open_endpoints += 1;
                try retainObservation(result, observation, stats);
            },
            .service => {
                if (observation.confidence == .confirmed)
                    stats.services_confirmed += 1
                else
                    stats.services_inferred += 1;
                try retainObservation(result, observation, stats);
            },
            else => {},
        };
    }
}

fn retainObservation(
    result: *protocol.AnalysisResult,
    observation: protocol.NetworkObservation,
    stats: *AggregateStats,
) !void {
    if (result.observations.items.len >= max_aggregated_observations) {
        stats.observations_dropped += 1;
        return;
    }
    if (try result.addNetworkObservation(.{
        .kind = observation.kind,
        .confidence = observation.confidence,
        .address = observation.address,
        .hostname = observation.hostname,
        .transport = observation.transport,
        .port = observation.port,
        .service = observation.service,
        .version = observation.version,
        .evidence = observation.evidence,
        .source_id = observation.source_id,
    })) stats.observations_retained += 1;
}

fn cancelPending(io: std.Io, futures: *[max_concurrency]?HostFuture) void {
    for (futures) |*maybe_future| {
        if (maybe_future.*) |*future| {
            var canceled = future.cancel(io);
            if (canceled) |*host| host.deinit() else |_| {}
            maybe_future.* = null;
        }
    }
}

fn remainingWholeMilliseconds(io: std.Io, deadline: std.Io.Clock.Timestamp) ?u32 {
    const now = std.Io.Clock.Timestamp.now(io, deadline.clock);
    if (now.raw.nanoseconds >= deadline.raw.nanoseconds) return null;
    const milliseconds = @divFloor(deadline.raw.nanoseconds - now.raw.nanoseconds, std.time.ns_per_ms);
    if (milliseconds < tcp_scan.min_timeout_ms) return null;
    return @intCast(@min(milliseconds, tcp_scan.max_total_timeout_ms));
}

fn deadlineReached(io: std.Io, deadline: std.Io.Clock.Timestamp) bool {
    return std.Io.Clock.Timestamp.now(io, deadline.clock).raw.nanoseconds >= deadline.raw.nanoseconds;
}

fn fieldEquals(result: *const protocol.AnalysisResult, name: []const u8, value: []const u8) bool {
    for (result.fields.items) |field| {
        if (std.mem.eql(u8, field.name, name)) return std.mem.eql(u8, field.value, value);
    }
    return false;
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

fn acceptConnections(server: *std.Io.net.Server, io: std.Io, count: usize) std.Io.Cancelable!void {
    for (0..count) |_| {
        const stream = server.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        stream.close(io);
    }
}

test "concurrent CIDR scan enforces hard bounds" {
    try std.testing.expectError(
        error.TooManyHosts,
        scan(std.testing.allocator, std.testing.io, "192.0.2.0/23", &.{80}, .{}),
    );
    var too_many_ports: [max_ports + 1]u16 = undefined;
    for (&too_many_ports, 0..) |*port, index| port.* = @intCast(index + 1);
    try std.testing.expectError(
        error.TooManyPorts,
        scan(std.testing.allocator, std.testing.io, "192.0.2.1/32", &too_many_ports, .{}),
    );
    try std.testing.expectError(
        error.InvalidConcurrency,
        scan(std.testing.allocator, std.testing.io, "192.0.2.1/32", &.{80}, .{ .concurrency = max_concurrency + 1 }),
    );
    try std.testing.expectError(
        error.InvalidTotalTimeout,
        scan(std.testing.allocator, std.testing.io, "192.0.2.1/32", &.{80}, .{ .total_timeout_ms = max_total_timeout_ms + 1 }),
    );
}

test "concurrent CIDR scan aggregates local host evidence" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, acceptConnections, .{ &server, std.testing.io, 2 });

    var result = try scan(
        std.testing.allocator,
        std.testing.io,
        "127.0.0.0/30",
        &.{server.socket.address.getPort()},
        .{ .timeout_ms = 100, .total_timeout_ms = 2_000, .concurrency = 2 },
    );
    defer result.deinit();
    try group.await(std.testing.io);

    try std.testing.expectEqualStrings("2", fieldValue(&result, "hosts_started").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "hosts_responsive").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "open_endpoints").?);
    try std.testing.expectEqualStrings("no", fieldValue(&result, "scan_deadline_reached").?);
    try std.testing.expectEqual(@as(usize, 4), result.observations.items.len);
}

test "concurrent CIDR scan splits up to 64 ports through existing scanner" {
    var ports: [tcp_scan.max_ports + 1]u16 = undefined;
    for (&ports, 0..) |*port, index| port.* = @intCast(40_000 + index);
    var result = try scan(
        std.testing.allocator,
        std.testing.io,
        "127.0.0.1/32",
        &ports,
        .{ .timeout_ms = 50, .total_timeout_ms = 5_000, .concurrency = 1 },
    );
    defer result.deinit();

    try std.testing.expectEqualStrings("1", fieldValue(&result, "hosts_completed").?);
    try std.testing.expectEqualStrings("0", fieldValue(&result, "host_scans_truncated").?);
    try std.testing.expectEqualStrings("no", fieldValue(&result, "scan_deadline_reached").?);
}
