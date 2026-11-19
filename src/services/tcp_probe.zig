//! Raw TCP request/response for non-HTTP exploit records.

const std = @import("std");
const tcp_scan = @import("tcp_scan.zig");
const stop = @import("stop.zig");

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
