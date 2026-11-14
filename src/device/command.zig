const std = @import("std");
const capability = @import("../core/capability.zig");
const ipc = @import("ipc.zig");

pub const max_region_bytes = 8;
pub const command_header_size = 4;

pub const WireRequest = struct {
    kind: capability.Kind,
    operation: capability.Operation,
    active_authorized: bool,
    region: []const u8,
    payload: []const u8,
};

pub const WireResponse = struct {
    status: capability.Status,
    data: []const u8,
};

pub fn encodeRequest(
    allocator: std.mem.Allocator,
    sequence: u32,
    request: capability.Request,
) ![]u8 {
    if (request.region.len > max_region_bytes) return error.RegionTooLong;
    if (request.payload.len > capability.max_payload_bytes) return error.PayloadTooLarge;
    const payload_len = std.math.add(usize, command_header_size + request.region.len, request.payload.len) catch {
        return error.PayloadTooLarge;
    };
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    payload[0] = @intFromEnum(request.kind);
    payload[1] = @intFromEnum(request.operation);
    payload[2] = @intFromBool(request.active_authorized);
    payload[3] = @intCast(request.region.len);
    @memcpy(payload[command_header_size .. command_header_size + request.region.len], request.region);
    @memcpy(payload[command_header_size + request.region.len ..], request.payload);
    return ipc.encode(allocator, .{ .kind = .request, .sequence = sequence, .payload = payload });
}

pub fn decodeRequest(frame_bytes: []const u8) !WireRequest {
    const frame = try ipc.decode(frame_bytes);
    if (frame.kind != .request) return error.UnexpectedFrameKind;
    if (frame.payload.len < command_header_size) return error.TruncatedCommand;
    const kind = std.enums.fromInt(capability.Kind, frame.payload[0]) orelse return error.InvalidCapabilityKind;
    const operation = std.enums.fromInt(capability.Operation, frame.payload[1]) orelse return error.InvalidOperation;
    if (frame.payload[2] > 1) return error.InvalidAuthorizationFlag;
    const region_len: usize = frame.payload[3];
    if (region_len > max_region_bytes or command_header_size + region_len > frame.payload.len) {
        return error.InvalidRegionLength;
    }
    return .{
        .kind = kind,
        .operation = operation,
        .active_authorized = frame.payload[2] == 1,
        .region = frame.payload[command_header_size .. command_header_size + region_len],
        .payload = frame.payload[command_header_size + region_len ..],
    };
}

pub fn encodeResponse(
    allocator: std.mem.Allocator,
    sequence: u32,
    status: capability.Status,
    data: []const u8,
) ![]u8 {
    if (data.len >= ipc.max_payload_bytes) return error.PayloadTooLarge;
    const payload = try allocator.alloc(u8, data.len + 1);
    defer allocator.free(payload);
    payload[0] = @intFromEnum(status);
    @memcpy(payload[1..], data);
    return ipc.encode(allocator, .{ .kind = .response, .sequence = sequence, .payload = payload });
}

pub fn decodeResponse(frame_bytes: []const u8) !WireResponse {
    const frame = try ipc.decode(frame_bytes);
    if (frame.kind != .response) return error.UnexpectedFrameKind;
    if (frame.payload.len == 0) return error.TruncatedResponse;
    return .{
        .status = std.enums.fromInt(capability.Status, frame.payload[0]) orelse return error.InvalidStatus,
        .data = frame.payload[1..],
    };
}

test "capability commands round trip over ipc" {
    const bytes = try encodeRequest(std.testing.allocator, 7, .{
        .id = 99,
        .subject = "linux-policy",
        .kind = .subghz,
        .operation = .transmit,
        .region = "EU",
        .payload = "fixed-frame",
        .active_authorized = true,
    });
    defer std.testing.allocator.free(bytes);
    const request = try decodeRequest(bytes);
    try std.testing.expectEqual(capability.Kind.subghz, request.kind);
    try std.testing.expectEqual(capability.Operation.transmit, request.operation);
    try std.testing.expect(request.active_authorized);
    try std.testing.expectEqualStrings("EU", request.region);
    try std.testing.expectEqualStrings("fixed-frame", request.payload);
}

test "capability responses round trip over ipc" {
    const bytes = try encodeResponse(std.testing.allocator, 8, .unsupported, "driver unavailable");
    defer std.testing.allocator.free(bytes);
    const response = try decodeResponse(bytes);
    try std.testing.expectEqual(capability.Status.unsupported, response.status);
    try std.testing.expectEqualStrings("driver unavailable", response.data);
}

test "command decoding rejects non-request frames" {
    const bytes = try ipc.encode(std.testing.allocator, .{
        .kind = .heartbeat,
        .sequence = 1,
    });
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(error.UnexpectedFrameKind, decodeRequest(bytes));
}
