const std = @import("std");
const capability = @import("../core/capability.zig");
const fixtures = @import("fixtures.zig");

pub const Backend = struct {
    supported: [std.meta.fields(capability.Kind).len]bool = @splat(false),

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

    pub fn init(self: *Harness, allocator: std.mem.Allocator, policy: capability.Policy) void {
        self.backend = .{};
        self.capabilities = capability.Service.init(allocator, policy, &self.backend, Backend.execute);
    }

    pub fn deinit(self: *Harness) void {
        self.capabilities.deinit();
        self.* = undefined;
    }
};

test "simulated device completes a capability request without claiming hardware" {
    var harness: Harness = undefined;
    harness.init(std.testing.allocator, .{});
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
    harness.init(std.testing.allocator, .{});
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
