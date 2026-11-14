const std = @import("std");
const capability = @import("../core/capability.zig");
const command = @import("../device/command.zig");
const ipc = @import("../device/ipc.zig");

pub fn exchange(
    allocator: std.mem.Allocator,
    service: *capability.Service,
    subject: []const u8,
    request_frame: []const u8,
) ![]u8 {
    const frame = try ipc.decode(request_frame);
    const wire = try command.decodeRequest(request_frame);
    var result = service.execute(.{
        .id = frame.sequence,
        .subject = subject,
        .kind = wire.kind,
        .operation = wire.operation,
        .region = wire.region,
        .payload = wire.payload,
        .active_authorized = wire.active_authorized,
    }) catch |err| {
        const status: capability.Status = if (service.audit.entries.items.len == 0)
            .failed
        else
            service.audit.entries.items[service.audit.entries.items.len - 1].status;
        return command.encodeResponse(allocator, frame.sequence, status, @errorName(err));
    };
    defer result.deinit();
    return command.encodeResponse(allocator, frame.sequence, result.status, result.data);
}

const simulated_device = @import("device.zig");

test "loopback crosses ipc capability policy audit and simulated backend" {
    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{});
    defer harness.deinit();
    harness.backend.enable(.infrared);

    const request = try command.encodeRequest(std.testing.allocator, 11, .{
        .id = 0,
        .subject = "not-sent-over-wire",
        .kind = .infrared,
        .operation = .read,
        .payload = "capture",
    });
    defer std.testing.allocator.free(request);
    const response_bytes = try exchange(std.testing.allocator, &harness.capabilities, "linux:loopback", request);
    defer std.testing.allocator.free(response_bytes);
    const response = try command.decodeResponse(response_bytes);

    try std.testing.expectEqual(capability.Status.succeeded, response.status);
    try std.testing.expectEqualStrings("capture", response.data);
    try std.testing.expectEqualStrings("linux:loopback", harness.capabilities.audit.entries.items[0].subject);
}

test "loopback returns policy denials as explicit responses" {
    var harness: simulated_device.Harness = undefined;
    harness.init(std.testing.allocator, .{});
    defer harness.deinit();
    harness.backend.enable(.infrared);

    const request = try command.encodeRequest(std.testing.allocator, 12, .{
        .id = 0,
        .subject = "not-sent-over-wire",
        .kind = .infrared,
        .operation = .transmit,
        .active_authorized = true,
    });
    defer std.testing.allocator.free(request);
    const response_bytes = try exchange(std.testing.allocator, &harness.capabilities, "linux:loopback", request);
    defer std.testing.allocator.free(response_bytes);
    const response = try command.decodeResponse(response_bytes);

    try std.testing.expectEqual(capability.Status.denied, response.status);
    try std.testing.expectEqualStrings("ActiveOperationDenied", response.data);
}
