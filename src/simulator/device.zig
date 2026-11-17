const std = @import("std");
const capability = @import("../core/capability.zig");
const fixtures = @import("fixtures.zig");
const tcp_scan = @import("../services/tcp_scan.zig");
const http_probe = @import("../services/http_probe.zig");
const udp_probe = @import("../services/udp_probe.zig");

pub const Backend = struct {
    supported: [std.meta.fields(capability.Kind).len]bool = @splat(false),
    /// Recorded observations by default; when true, network requests probe the target.
    live: bool = false,
    io: ?std.Io = null,

    pub fn enable(self: *Backend, kind: capability.Kind) void {
        self.supported[@intFromEnum(kind)] = true;
    }

    pub fn disable(self: *Backend, kind: capability.Kind) void {
        self.supported[@intFromEnum(kind)] = false;
    }

    pub fn execute(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: capability.Request,
    ) !capability.Result {
        const self: *Backend = @ptrCast(@alignCast(context));
        if (!self.supported[@intFromEnum(request.kind)]) {
            return capability.Result.init(allocator, .unsupported, "simulator capability unavailable");
        }
        if (request.kind == .network) {
            if (self.live) {
                const io = self.io orelse {
                    return capability.Result.init(allocator, .failed, "live scan unavailable");
                };
                if (http_probe.isHttpSpec(request.payload)) {
                    return http_probe.execute(allocator, io, request.payload);
                }
                if (udp_probe.isUdpSpec(request.payload)) {
                    return udp_probe.execute(allocator, io, request.payload);
                }
                const text = try liveScan(allocator, io, request.payload);
                defer allocator.free(text);
                return capability.Result.init(allocator, .succeeded, text);
            }
            if (fixtures.lookup(request.payload)) |fixture| {
                return capability.Result.init(allocator, .succeeded, fixture.response);
            }
        }
        return capability.Result.init(
            allocator,
            .succeeded,
            if (request.payload.len == 0) "simulated" else request.payload,
        );
    }
};

/// Two-phase initialization keeps the service's backend pointer stable.
pub const Harness = struct {
    backend: Backend,
    capabilities: capability.Service,

    pub fn init(self: *Harness, allocator: std.mem.Allocator, policy: capability.Policy, io: ?std.Io) void {
        self.backend = .{ .io = io };
        self.capabilities = capability.Service.init(allocator, policy, &self.backend, Backend.execute);
    }

    pub fn deinit(self: *Harness) void {
        self.capabilities.deinit();
        self.* = undefined;
    }
};

test "simulated device completes a capability request without claiming hardware" {
    var harness: Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();
    harness.backend.enable(.infrared);

    var result = try harness.capabilities.execute(.{
        .id = 1,
        .subject = "workflow:test",
        .kind = .infrared,
        .operation = .read,
        .payload = "fixture.ir",
    });
    defer result.deinit();
    try std.testing.expectEqual(capability.Status.succeeded, result.status);
    try std.testing.expectEqualStrings("fixture.ir", result.data);
}

test "simulated device reports unsupported capabilities explicitly" {
    var harness: Harness = undefined;
    harness.init(std.testing.allocator, .{}, null);
    defer harness.deinit();

    var result = try harness.capabilities.execute(.{
        .id = 2,
        .subject = "workflow:test",
        .kind = .nfc,
        .operation = .read,
    });
    defer result.deinit();
    try std.testing.expectEqual(capability.Status.unsupported, result.status);
}

const Target = struct { host: []const u8, port: u16 };

/// Extracts "host:port" from a payload such as "target=127.0.0.1:8080".
pub fn parseTarget(payload: []const u8) ?Target {
    const marker = "target=";
    const at = std.mem.indexOf(u8, payload, marker) orelse return null;
    var value = payload[at + marker.len ..];
    if (std.mem.indexOfScalar(u8, value, ';')) |end| value = value[0..end];
    value = std.mem.trim(u8, value, " \t\r\n");
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return null;
    const host = std.mem.trim(u8, value[0..colon], " \t");
    if (host.len == 0) return null;
    const port = std.fmt.parseInt(u16, value[colon + 1 ..], 10) catch return null;
    if (port == 0) return null;
    return .{ .host = host, .port = port };
}

fn liveScan(allocator: std.mem.Allocator, io: std.Io, payload: []const u8) ![]u8 {
    const target = parseTarget(payload) orelse return allocator.dupe(u8, "state=invalid-target");
    var ports = [_]u16{target.port};
    var result = tcp_scan.scan(allocator, io, target.host, &ports, .{}) catch |err| {
        return std.fmt.allocPrint(allocator, "host={s}\nport={d}\nstate=error\nerror={s}", .{ target.host, target.port, @errorName(err) });
    };
    defer result.deinit();
    // Prefer the service observation: the first entry is only host reachability.
    var selected: ?@TypeOf(result.observations.items[0]) = null;
    for (result.observations.items) |observation| {
        if (observation.kind == .service) {
            selected = observation;
            break;
        }
        if (selected == null) selected = observation;
    }
    if (selected) |observation| {
        return std.fmt.allocPrint(allocator, "host={s}\nport={d}\nstate=open\ntransport={s}\nservice={s}\nproduct={s}\nversion={s}", .{
            target.host, target.port, observation.transport, observation.service, observation.product, observation.version,
        });
    }
    return std.fmt.allocPrint(allocator, "host={s}\nport={d}\nstate=closed", .{ target.host, target.port });
}

test "parseTarget accepts the script payload shape" {
    const target = parseTarget("target=127.0.0.1:8080") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("127.0.0.1", target.host);
    try std.testing.expectEqual(@as(u16, 8080), target.port);
}

test "parseTarget rejects malformed payloads" {
    try std.testing.expect(parseTarget("host=127.0.0.1") == null);
    try std.testing.expect(parseTarget("target=127.0.0.1") == null);
    try std.testing.expect(parseTarget("target=:80") == null);
}
