//! Raw TCP request/response for non-HTTP exploit records.

const std = @import("std");
const tcp_scan = @import("tcp_scan.zig");
const stop = @import("stop.zig");
const capability = @import("../core/capability.zig");

pub const max_response_bytes = 1024 * 1024;

fn parseTarget(text: []const u8) !struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidTarget;
    const host = std.mem.trim(u8, text[0..colon], " \t");
    const port = std.fmt.parseInt(u16, std.mem.trim(u8, text[colon + 1 ..], " \t"), 10) catch
        return error.InvalidTarget;
    if (host.len == 0 or port == 0) return error.InvalidTarget;
    return .{ .host = host, .port = port };
}

/// Sends one payload and reads until EOF, timeout or the response cap. Used by records
/// with "transport":"tcp"; no HTTP parsing or status is involved.
pub fn exchange(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_text: []const u8,
    data: []const u8,
    timeout_ms: u32,
    stop_check: ?stop.Check,
) ![]u8 {
    if (data.len == 0 or data.len > 4096) return error.InvalidDatagram;
    if (timeout_ms < 50 or timeout_ms > 5000) return error.InvalidTimeout;
    const target = try parseTarget(target_text);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(timeout_ms),
        .clock = .awake,
    });
    const timeout: std.Io.Timeout = .{ .deadline = deadline };
    var address = try tcp_scan.resolveWithTimeout(io, target.host, target.port, timeout);
    address.setPort(target.port);
    const stream = try tcp_scan.connectWithTimeout(io, &address, timeout);
    defer stream.close(io);
    try tcp_scan.writeSmallRequestWithTimeout(io, stream, data, timeout);

    const raw = try allocator.alloc(u8, max_response_bytes);
    defer allocator.free(raw);
    var reader_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var total: usize = 0;
    while (total < raw.len) {
        if (stop_check) |check| {
            if (check.isStopped(check.context)) return error.Stopped;
        }
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        if (now.raw.nanoseconds >= deadline.raw.nanoseconds) {
            if (total == 0) return error.Timeout;
            break;
        }
        const slice_timeout: std.Io.Timeout = .{ .deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = std.Io.Duration.fromMilliseconds(100),
            .clock = .awake,
        }) };
        const count = tcp_scan.readWithTimeout(io, &reader, raw[total..], slice_timeout) catch |err| switch (err) {
            error.Timeout => {
                if (stop_check) |check| {
                    if (check.isStopped(check.context)) return error.Stopped;
                }
                continue;
            },
            else => return err,
        };
        if (count == 0) break;
        total += count;
    }
    if (total == 0) return error.EmptyTcpResponse;
    if (total == raw.len) return error.ResponseTooLarge;
    return allocator.dupe(u8, raw[0..total]);
}

const SpecWire = struct {
    kind: []const u8 = "tcp",
    target: []const u8 = "",
    data: []const u8 = "",
    timeout_ms: u32 = 2000,
};

pub fn isTcpSpec(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"kind\":\"tcp\"") != null;
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
    }) catch return capability.Result.init(allocator, .failed, "InvalidTcpSpec");
    if (!std.mem.eql(u8, wire.kind, "tcp") or wire.target.len == 0 or wire.data.len == 0) {
        return capability.Result.init(allocator, .failed, "InvalidTcpSpec");
    }
    if (wire.data.len > 4096 or wire.timeout_ms < 50 or wire.timeout_ms > 5000) {
        return capability.Result.init(allocator, .failed, "InvalidTcpSpec");
    }
    const body = exchange(allocator, io, wire.target, wire.data, wire.timeout_ms, stop_check) catch |err| {
        return capability.Result.init(allocator, if (err == error.Stopped) .cancelled else .failed, @errorName(err));
    };
    defer allocator.free(body);
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    try output.writer.print("bytes={d}\n", .{body.len});
    try output.writer.writeAll("body_prefix=");
    try appendEscaped(&output.writer, body);
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

test "tcp probe aborts while waiting for a response" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, serveStall, .{ &server, std.testing.io });

    const spec = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"kind":"tcp","target":"127.0.0.1:{d}","data":"PING"}}
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
