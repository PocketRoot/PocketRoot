//! UDP probe for amplification / datagram-oracle reproductions.

const std = @import("std");
const capability = @import("../core/capability.zig");
const tcp_scan = @import("tcp_scan.zig");

pub const max_datagram_bytes = 64 * 1024;

pub const Spec = struct {
    arena: std.heap.ArenaAllocator,
    target: []const u8,
    data: []const u8,
    timeout_ms: u32,
    expect_min_bytes: ?u32,
    expect_body: []const u8,
    expect_absent: []const u8,

    pub fn deinit(self: *Spec) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const SpecWire = struct {
    kind: []const u8 = "udp",
    target: []const u8 = "",
    data: []const u8 = "",
    timeout_ms: u32 = 2000,
    expect_min_bytes: ?u32 = null,
    expect_body: []const u8 = "",
    expect_absent: []const u8 = "",
};

pub fn parseSpec(allocator: std.mem.Allocator, input: []const u8) !Spec {
    if (input.len > 64 * 1024) return error.SpecTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, input);
    const wire = std.json.parseFromSliceLeaky(SpecWire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidUdpSpec;
    if (!std.mem.eql(u8, wire.kind, "udp")) return error.InvalidUdpSpec;
    if (wire.target.len == 0 or wire.target.len > 255) return error.InvalidTarget;
    if (wire.data.len == 0 or wire.data.len > 4096) return error.InvalidDatagram;
    if (wire.timeout_ms < 50 or wire.timeout_ms > 5000) return error.InvalidTimeout;
    if (wire.expect_body.len > 1024 or wire.expect_absent.len > 1024) return error.InvalidExpectation;
    _ = try parseTarget(wire.target);
    return .{
        .arena = arena,
        .target = wire.target,
        .data = wire.data,
        .timeout_ms = wire.timeout_ms,
        .expect_min_bytes = wire.expect_min_bytes,
        .expect_body = wire.expect_body,
        .expect_absent = wire.expect_absent,
    };
}

const ReceiveOutcome = union(enum) {
    message: std.Io.net.IncomingMessage,
    failure: anyerror,
};

fn receiveOne(socket: *const std.Io.net.Socket, io: std.Io, buffer: []u8) ReceiveOutcome {
    return .{ .message = socket.receive(io, buffer) catch |err| return .{ .failure = err } };
}

fn receiveDatagram(
    socket: *const std.Io.net.Socket,
    io: std.Io,
    buffer: []u8,
    timeout: std.Io.Timeout,
) !std.Io.net.IncomingMessage {
    const Event = union(enum) { receive: ReceiveOutcome, timer: std.Io.Cancelable!void };
    var events: [2]Event = undefined;
    var select: std.Io.Select(Event) = .init(io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.receive, receiveOne, .{ socket, io, buffer });
    try select.concurrent(.timer, std.Io.Timeout.sleep, .{ timeout, io });
    return switch (try select.await()) {
        .receive => |outcome| switch (outcome) {
            .message => |message| message,
            .failure => |err| err,
        },
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    };
}

pub fn isUdpSpec(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"kind\":\"udp\"") != null;
}

fn parseTarget(text: []const u8) !struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidTarget;
    const host = std.mem.trim(u8, text[0..colon], " \t");
    const port = std.fmt.parseInt(u16, std.mem.trim(u8, text[colon + 1 ..], " \t"), 10) catch
        return error.InvalidTarget;
    if (host.len == 0 or port == 0) return error.InvalidTarget;
    return .{ .host = host, .port = port };
}

pub fn execute(allocator: std.mem.Allocator, io: std.Io, payload: []const u8) !capability.Result {
    var spec = parseSpec(allocator, payload) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    defer spec.deinit();
    const target = try parseTarget(spec.target);
    const timeout: std.Io.Timeout = .{ .deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(spec.timeout_ms),
        .clock = .awake,
    }) };
    var address = tcp_scan.resolveWithTimeout(io, target.host, target.port, timeout) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    address.setPort(target.port);

    const local = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.unspecified(0) };
    var socket = local.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    defer socket.close(io);
    socket.send(io, &address, spec.data) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };

    var response_buffer: [max_datagram_bytes]u8 = undefined;
    var oracle_pass = true;
    var bytes: usize = 0;
    var reason: []const u8 = "ok";
    var reason_buffer: [128]u8 = undefined;
    const message = receiveDatagram(&socket, io, &response_buffer, timeout) catch |err| switch (err) {
        error.Timeout => null,
        else => return capability.Result.init(allocator, .failed, @errorName(err)),
    };
    if (message) |received| {
        bytes = received.data.len;
        if (spec.expect_min_bytes) |minimum| {
            if (bytes < minimum) {
                oracle_pass = false;
                reason = std.fmt.bufPrint(&reason_buffer, "bytes={d} expected>={d}", .{ bytes, minimum }) catch "too few bytes";
            }
        }
        if (oracle_pass and spec.expect_body.len > 0 and std.mem.indexOf(u8, received.data, spec.expect_body) == null) {
            oracle_pass = false;
            reason = "expected datagram marker absent";
        }
        if (oracle_pass and spec.expect_absent.len > 0 and std.mem.indexOf(u8, received.data, spec.expect_absent) != null) {
            oracle_pass = false;
            reason = "forbidden datagram marker present";
        }
    } else {
        oracle_pass = false;
        reason = "no datagram received";
    }

    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.print("bytes={d}\n", .{bytes});
    try writer.print("ratio={d:.1}\n", .{if (spec.data.len == 0) 0.0 else @as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(spec.data.len))});
    try writer.writeAll("body_prefix=");
    if (message) |received| {
        const limit = @min(received.data.len, 256);
        for (received.data[0..limit]) |byte| {
            switch (byte) {
                '\n' => try writer.writeAll("\\n"),
                '\r' => try writer.writeAll("\\r"),
                0x20...0x7e => try writer.writeByte(byte),
                else => try writer.writeByte('?'),
            }
        }
    }
    try writer.writeByte('\n');
    try writer.print("oracle={s}\n", .{if (oracle_pass) "pass" else "fail"});
    try writer.print("oracle_reason={s}\n", .{reason});
    return capability.Result.init(allocator, .succeeded, output.written());
}

fn serveUdp(socket: *std.Io.net.Socket, io: std.Io) std.Io.Cancelable!void {
    var buffer: [512]u8 = undefined;
    const message = receiveDatagram(socket, io, &buffer, .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(1000),
        .clock = .awake,
    } }) catch return;
    var reply: [1024]u8 = undefined;
    if (message.data.len * 2 > reply.len) return;
    @memcpy(reply[0..message.data.len], message.data);
    @memcpy(reply[message.data.len .. message.data.len * 2], message.data);
    socket.send(io, &message.from, reply[0 .. message.data.len * 2]) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

test "udp probe measures the response and evaluates the minimum size" {
    const local = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.unspecified(0) };
    var socket = try local.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(std.testing.io);
    const port = socket.address.getPort();
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, serveUdp, .{ &socket, std.testing.io });

    const spec = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"kind":"udp","target":"127.0.0.1:{d}","data":"abc","expect_min_bytes":6,"expect_body":"abcabc"}}
    , .{port});
    defer std.testing.allocator.free(spec);
    var result = try execute(std.testing.allocator, std.testing.io, spec);
    defer result.deinit();
    try group.await(std.testing.io);
    try std.testing.expectEqual(capability.Status.succeeded, result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "bytes=6") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "oracle=pass") != null);
}

test "udp spec rejects an empty datagram" {
    try std.testing.expectError(error.InvalidDatagram, parseSpec(std.testing.allocator,
        \\{"kind":"udp","target":"127.0.0.1:53"}
    ));
}
