//! Minimal HTTP/2 frame client for protocol-level exploit probes.
//!
//! The caller supplies the raw HPACK header block. This keeps the transport generic:
//! PocketRoot sends the preface, SETTINGS and one HEADERS frame, then reports the raw
//! response frames, RST_STREAM/GOAWAY codes and DATA body. It does not implement HPACK
//! encoding or a browser-grade HTTP/2 stack.

const std = @import("std");
const capability = @import("../core/capability.zig");
const tcp_scan = @import("tcp_scan.zig");
const stop = @import("stop.zig");

pub const max_headers_bytes = 64 * 1024;
pub const max_body_bytes = 4 * 1024 * 1024;
const max_frame_bytes = 16 * 1024 * 1024;
const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const Spec = struct {
    arena: std.heap.ArenaAllocator,
    target: []const u8,
    headers_file: []const u8,
    stream_id: u32,
    timeout_ms: u32,
    expect_body: []const u8,
    expect_absent: []const u8,

    pub fn deinit(self: *Spec) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const SpecWire = struct {
    kind: []const u8 = "h2",
    target: []const u8 = "",
    headers_file: []const u8 = "",
    stream_id: u32 = 1,
    timeout_ms: u32 = 3000,
    expect_body: []const u8 = "",
    expect_absent: []const u8 = "",
};

pub fn parseSpec(allocator: std.mem.Allocator, input: []const u8) !Spec {
    if (input.len > 64 * 1024) return error.SpecTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, input);
    const wire = std.json.parseFromSliceLeaky(SpecWire, a, owned, .{}) catch |err| return err;
    if (wire.target.len == 0 or wire.headers_file.len == 0) return error.InvalidTarget;
    if (wire.stream_id == 0 or wire.stream_id > 0x7fffffff) return error.InvalidStreamId;
    if (wire.timeout_ms < 50 or wire.timeout_ms > 10000) return error.InvalidTimeout;
    return .{
        .arena = arena,
        .target = wire.target,
        .headers_file = wire.headers_file,
        .stream_id = wire.stream_id,
        .timeout_ms = wire.timeout_ms,
        .expect_body = wire.expect_body,
        .expect_absent = wire.expect_absent,
    };
}

pub fn isH2Spec(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"kind\":\"h2\"") != null;
}

fn parseTarget(text: []const u8) !struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidTarget;
    const host = std.mem.trim(u8, text[0..colon], " \t");
    const port = std.fmt.parseInt(u16, std.mem.trim(u8, text[colon + 1 ..], " \t"), 10) catch
        return error.InvalidTarget;
    if (host.len == 0 or port == 0) return error.InvalidTarget;
    return .{ .host = host, .port = port };
}

fn appendFrame(output: *std.ArrayList(u8), a: std.mem.Allocator, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) !void {
    if (payload.len > 0xffffff) return error.FrameTooLarge;
    try output.append(a, @intCast(payload.len >> 16));
    try output.append(a, @intCast(payload.len >> 8));
    try output.append(a, @intCast(payload.len));
    try output.append(a, frame_type);
    try output.append(a, flags);
    try output.append(a, @intCast(stream_id >> 24));
    try output.append(a, @intCast(stream_id >> 16));
    try output.append(a, @intCast(stream_id >> 8));
    try output.append(a, @intCast(stream_id));
    try output.appendSlice(a, payload);
}

fn readExact(
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    output: []u8,
    deadline: std.Io.Clock.Timestamp,
    stop_check: ?stop.Check,
) !usize {
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
            error.Timeout => continue,
            else => return err,
        };
        if (count == 0) return error.EndOfStream;
        total += count;
    }
    return total;
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
    var spec = parseSpec(allocator, payload) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    defer spec.deinit();
    const a = spec.arena.allocator();
    const headers = std.Io.Dir.cwd().readFileAlloc(io, spec.headers_file, a, .limited(max_headers_bytes)) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    const target = parseTarget(spec.target) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(spec.timeout_ms),
        .clock = .awake,
    });
    const timeout: std.Io.Timeout = .{ .deadline = deadline };

    var address = tcp_scan.resolveWithTimeout(io, target.host, target.port, timeout) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    address.setPort(target.port);
    const stream = tcp_scan.connectWithTimeout(io, &address, timeout) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    defer stream.close(io);

    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(a);
    try request.appendSlice(a, preface);
    try appendFrame(&request, a, 0x4, 0, 0, &.{});
    try appendFrame(&request, a, 0x1, 0x5, spec.stream_id, headers);
    tcp_scan.writeSmallRequestWithTimeout(io, stream, request.items, timeout) catch |err| {
        return capability.Result.init(allocator, if (err == error.Stopped) .cancelled else .failed, @errorName(err));
    };

    var reader_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    var frames: usize = 0;
    var rst_stream: u32 = 0;
    var goaway: u32 = 0;
    var read_error = false;
    while (frames < 64) {
        var head: [9]u8 = undefined;
        _ = readExact(io, &reader, &head, deadline, stop_check) catch |err| switch (err) {
            error.Timeout, error.EndOfStream => break,
            error.Stopped => return capability.Result.init(allocator, .cancelled, "stopped"),
            else => {
                read_error = true;
                break;
            },
        };
        const length = (@as(usize, head[0]) << 16) | (@as(usize, head[1]) << 8) | head[2];
        if (length > max_frame_bytes) return capability.Result.init(allocator, .failed, "FrameTooLarge");
        const frame_type = head[3];
        const flags = head[4];
        const stream_id = (@as(u32, head[5]) << 24) | (@as(u32, head[6]) << 16) | (@as(u32, head[7]) << 8) | head[8];
        frames += 1;
        if (length > 0) {
            const frame = try allocator.alloc(u8, length);
            defer allocator.free(frame);
            _ = readExact(io, &reader, frame, deadline, stop_check) catch |err| switch (err) {
                error.Timeout, error.EndOfStream => {
                    read_error = true;
                    break;
                },
                error.Stopped => return capability.Result.init(allocator, .cancelled, "stopped"),
                else => {
                    read_error = true;
                    break;
                },
            };
            switch (frame_type) {
                0x0 => {
                    if (body.items.len + frame.len > max_body_bytes) return capability.Result.init(allocator, .failed, "ResponseBodyTooLarge");
                    try body.appendSlice(allocator, frame);
                    if (flags & 0x1 != 0) break;
                },
                0x3 => {
                    if (frame.len >= 4) rst_stream = (@as(u32, frame[0]) << 24) | (@as(u32, frame[1]) << 16) | (@as(u32, frame[2]) << 8) | frame[3];
                    break;
                },
                0x7 => {
                    if (frame.len >= 4) goaway = (@as(u32, frame[0]) << 24) | (@as(u32, frame[1]) << 16) | (@as(u32, frame[2]) << 8) | frame[3];
                    break;
                },
                0x1, 0x9 => {
                    if (flags & 0x1 != 0) break;
                },
                else => {},
            }
        }
        if (frame_type == 0x1 and flags & 0x1 != 0) break;
        if (stream_id == spec.stream_id and frame_type == 0x3) break;
    }

    var oracle_pass = true;
    var reason: []const u8 = "ok";
    if (read_error) {
        oracle_pass = false;
        reason = "frame read error";
    } else if (spec.expect_body.len > 0 and std.mem.indexOf(u8, body.items, spec.expect_body) == null) {
        oracle_pass = false;
        reason = "expected body marker absent";
    } else if (spec.expect_absent.len > 0 and std.mem.indexOf(u8, body.items, spec.expect_absent) != null) {
        oracle_pass = false;
        reason = "forbidden body marker present";
    }

    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.print("frames={d}\n", .{frames});
    try writer.print("rst_stream={d}\n", .{rst_stream});
    try writer.print("goaway={d}\n", .{goaway});
    try writer.print("body_bytes={d}\n", .{body.items.len});
    try writer.writeAll("body_prefix=");
    const limit = @min(body.items.len, 512);
    for (body.items[0..limit]) |byte| {
        switch (byte) {
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            0x20...0x7e => try writer.writeByte(byte),
            else => try writer.writeByte('?'),
        }
    }
    try writer.writeByte('\n');
    try writer.print("oracle={s}\n", .{if (oracle_pass) "pass" else "fail"});
    try writer.print("oracle_reason={s}\n", .{reason});
    return capability.Result.init(allocator, .succeeded, output.written());
}
