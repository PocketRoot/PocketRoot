//! Minimal AJP/1.3 request client.
//!
//! This is a protocol transport, not a CVE implementation: callers supply the method, URI
//! and arbitrary request attributes. AJP strings are length-prefixed by their character
//! count (the trailing NUL is not included), and the response frames are parsed back into
//! a status and body.

const std = @import("std");
const tcp_scan = @import("tcp_scan.zig");
const stop = @import("stop.zig");
const capability = @import("../core/capability.zig");

pub const max_response_bytes = 4 * 1024 * 1024;
const max_frame_bytes = 64 * 1024;

pub const Response = struct {
    status: u16,
    body: []u8,
};

pub const Attribute = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: []const u8 = "GET",
    uri: []const u8 = "/",
    server_port: u16 = 8080,
    attributes: []const Attribute = &.{},
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

fn methodCode(method: []const u8) !u8 {
    const pairs = [_]struct { text: []const u8, code: u8 }{
        .{ .text = "OPTIONS", .code = 1 },
        .{ .text = "GET", .code = 2 },
        .{ .text = "HEAD", .code = 3 },
        .{ .text = "POST", .code = 4 },
        .{ .text = "PUT", .code = 5 },
        .{ .text = "DELETE", .code = 6 },
        .{ .text = "TRACE", .code = 7 },
        .{ .text = "PROPFIND", .code = 8 },
        .{ .text = "PROPPATCH", .code = 9 },
        .{ .text = "MKCOL", .code = 10 },
        .{ .text = "COPY", .code = 11 },
        .{ .text = "MOVE", .code = 12 },
        .{ .text = "LOCK", .code = 13 },
        .{ .text = "UNLOCK", .code = 14 },
    };
    for (pairs) |pair| {
        if (std.ascii.eqlIgnoreCase(method, pair.text)) return pair.code;
    }
    return error.InvalidAipMethod;
}

fn buildPacket(a: std.mem.Allocator, host: []const u8, request: Request) ![]u8 {
    if (request.attributes.len > 64) return error.TooManyAipAttributes;
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(a);
    try body.appendSlice(a, &.{ 0x02, try methodCode(request.method) });
    try appendString(&body, a, "HTTP/1.1");
    try appendString(&body, a, request.uri);
    try appendString(&body, a, host);
    try appendString(&body, a, "localhost");
    try appendString(&body, a, "localhost");
    try body.append(a, @intCast(request.server_port >> 8));
    try body.append(a, @intCast(request.server_port & 0xff));
    try body.appendSlice(a, &.{ 0x00, 0x00, 0x00 });
    for (request.attributes) |attribute| {
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
    request: Request,
    timeout_ms: u32,
    stop_check: ?stop.Check,
) !Response {
    if (request.uri.len == 0 or request.uri.len > 4096) return error.InvalidAipPath;
    if (timeout_ms < 50 or timeout_ms > 10000) return error.InvalidTimeout;
    const target = try parseTarget(target_text);
    const packet = try buildPacket(allocator, target.host, request);
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

test "AJP request encodes arbitrary attributes" {
    const attributes = [_]Attribute{
        .{ .name = "javax.servlet.include.path_info", .value = "/WEB-INF/web.xml" },
        .{ .name = "custom.one", .value = "value" },
    };
    const packet = try buildPacket(std.testing.allocator, "127.0.0.1", .{
        .method = "GET",
        .uri = "/",
        .server_port = 8080,
        .attributes = &attributes,
    });
    defer std.testing.allocator.free(packet);
    try std.testing.expectEqual(@as(u8, 0x12), packet[0]);
    try std.testing.expectEqual(@as(u8, 0x34), packet[1]);
    try std.testing.expectEqual(@as(usize, packet.len - 4), (@as(usize, packet[2]) << 8) | packet[3]);
    try std.testing.expect(std.mem.indexOf(u8, packet, "javax.servlet.include.path_info") != null);
    try std.testing.expect(std.mem.indexOf(u8, packet, "/WEB-INF/web.xml") != null);
    try std.testing.expect(std.mem.indexOf(u8, packet, "custom.one") != null);
    try std.testing.expectEqual(@as(u8, 0xFF), packet[packet.len - 1]);
}

const AttributeWire = struct {
    name: []const u8 = "",
    value: []const u8 = "",
};

const SpecWire = struct {
    kind: []const u8 = "ajp",
    target: []const u8 = "",
    method: []const u8 = "GET",
    uri: []const u8 = "/",
    server_port: u16 = 8080,
    attributes: []const AttributeWire = &.{},
    timeout_ms: u32 = 2000,
};

pub fn isAjpSpec(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"kind\":\"ajp\"") != null;
}

fn appendEscaped(writer: *std.Io.Writer, data: []const u8) !void {
    const limit = @min(data.len, 256);
    for (data[0..limit]) |byte| {
        switch (byte) {
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x20...0x7e => try writer.writeByte(byte),
            else => try writer.writeByte('?'),
        }
    }
}

pub fn execute(allocator: std.mem.Allocator, io: std.Io, payload: []const u8) !capability.Result {
    return executeWithStop(allocator, io, payload, null);
}

pub fn executeWithStop(
    allocator: std.mem.Allocator,
    io: std.Io,
    payload: []const u8,
    stop_check: ?stop.Check,
) !capability.Result {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const owned = a.dupe(u8, payload) catch return error.OutOfMemory;
    const wire = std.json.parseFromSliceLeaky(SpecWire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return capability.Result.init(allocator, .failed, "InvalidAjpSpec");
    if (!std.mem.eql(u8, wire.kind, "ajp") or wire.target.len == 0 or wire.uri.len == 0) {
        return capability.Result.init(allocator, .failed, "InvalidAjpSpec");
    }
    if (wire.attributes.len > 64 or wire.timeout_ms < 50 or wire.timeout_ms > 10000) {
        return capability.Result.init(allocator, .failed, "InvalidAjpSpec");
    }
    const attributes = a.alloc(Attribute, wire.attributes.len) catch return error.OutOfMemory;
    for (wire.attributes, 0..) |attribute, i| {
        if (attribute.name.len == 0 or attribute.name.len > 4096 or attribute.value.len > 4096) {
            return capability.Result.init(allocator, .failed, "InvalidAjpSpec");
        }
        attributes[i] = .{ .name = attribute.name, .value = attribute.value };
    }
    const response = exchange(allocator, io, wire.target, .{
        .method = wire.method,
        .uri = wire.uri,
        .server_port = wire.server_port,
        .attributes = attributes,
    }, wire.timeout_ms, stop_check) catch |err| {
        return capability.Result.init(allocator, if (err == error.Stopped) .cancelled else .failed, @errorName(err));
    };
    defer allocator.free(response.body);
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    try output.writer.print("status={d}\n", .{response.status});
    try output.writer.print("bytes={d}\n", .{response.body.len});
    try output.writer.writeAll("body_prefix=");
    try appendEscaped(&output.writer, response.body);
    try output.writer.writeByte('\n');
    return capability.Result.init(allocator, .succeeded, output.written());
}

const StopAfter = struct {
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
};

fn stopAfter(ctx: *anyopaque) bool {
    const state: *StopAfter = @ptrCast(@alignCast(ctx));
    return std.Io.Clock.Timestamp.now(state.io, .awake).raw.nanoseconds >= state.deadline.raw.nanoseconds;
}

fn serveStall(server: *std.Io.net.Server, io: std.Io) std.Io.Cancelable!void {
    const stream = server.accept(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    defer stream.close(io);
    std.Io.Timeout.sleep(.{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(5000),
        .clock = .awake,
    } }, io) catch return;
}

test "ajp probe aborts while waiting for a response" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, serveStall, .{ &server, std.testing.io });

    const spec = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"kind":"ajp","target":"127.0.0.1:{d}","method":"GET","uri":"/"}}
    , .{server.socket.address.getPort()});
    defer std.testing.allocator.free(spec);
    var state = StopAfter{ .io = std.testing.io, .deadline = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{
        .raw = std.Io.Duration.fromMilliseconds(100),
        .clock = .awake,
    }) };
    var result = try executeWithStop(std.testing.allocator, std.testing.io, spec, .{
        .context = &state,
        .isStopped = stopAfter,
    });
    defer result.deinit();
    try std.testing.expectEqual(capability.Status.cancelled, result.status);
}
