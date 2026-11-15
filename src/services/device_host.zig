//! Host entry point for the capability kernel.
//!
//! This is the piece that turns `core/capability.zig` from library code into a runnable
//! service: it owns the policy, the simulated backend, the audit sink and the PKRT frame
//! loop. The transport is caller-supplied (stdin/stdout for a real device, a file for a
//! recorded frame stream, memory for tests), so the same path serves all three.

const std = @import("std");
const capability = @import("../core/capability.zig");
const command = @import("../device/command.zig");
const ipc = @import("../device/ipc.zig");
const simulator = @import("../simulator/device.zig");
const audit_log = @import("audit_log.zig");

pub const max_frames_per_run = 4096;

pub const Options = struct {
    region: []const u8 = "",
    allow_active: bool = false,
    subject: []const u8 = "host",
    audit_path: ?[]const u8 = null,
};

pub const Host = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    harness: simulator.Harness = undefined,
    audit: ?audit_log.Writer = null,
    session: ipc.Session = .{},
    audit_seen: usize = 0,

    /// Two-phase initialization is required: `harness.init` stores a pointer to the
    /// backend inside this struct, so the Host must not move afterwards.
    pub fn init(self: *Host, allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
        try validateOptions(options);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .options = options,
        };
        self.harness.init(allocator, .{
            .region = options.region,
            .allow_active = options.allow_active,
        }, io);
        errdefer self.harness.deinit();
        enableAllKinds(&self.harness.backend);
        if (options.audit_path) |path| self.audit = try audit_log.Writer.open(allocator, io, path);
    }

    pub fn deinit(self: *Host) void {
        if (self.audit) |*sink| sink.close();
        self.harness.deinit();
        self.* = undefined;
    }

    pub fn lastStatus(self: *const Host) capability.Status {
        const entries = self.harness.capabilities.audit.entries.items;
        if (entries.len == 0) return .failed;
        return entries[entries.len - 1].status;
    }

    /// Executes one request through the kernel and appends every new audit entry before
    /// returning. A failed audit write fails the call, so a request is never reported as
    /// complete without its record.
    pub fn execute(self: *Host, request: capability.Request) !capability.Result {
        var result = self.harness.capabilities.execute(request) catch |err| {
            try self.recordAudit();
            return err;
        };
        errdefer result.deinit();
        try self.recordAudit();
        return result;
    }

    /// Serves PKRT request frames until the reader ends or `max_frames` is reached
    /// (zero means unlimited). Responses use the same frame format as a device.
    pub fn serveStream(
        self: *Host,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        max_frames: usize,
    ) !usize {
        var served: usize = 0;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        while (max_frames == 0 or served < max_frames) {
            _ = arena.reset(.retain_capacity);
            var header: [ipc.header_size]u8 = undefined;
            reader.readSliceAll(&header) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            const total = (try ipc.frameSize(&header)) orelse return error.TruncatedFrame;
            if (total < ipc.header_size + ipc.checksum_size) return error.InvalidFrameLength;
            const a = arena.allocator();
            const bytes = try a.alloc(u8, total);
            @memcpy(bytes[0..header.len], &header);
            try reader.readSliceAll(bytes[header.len..]);
            const frame = try ipc.decode(bytes);
            const response = try self.respond(a, frame, bytes);
            try writer.writeAll(response);
            try writer.flush();
            served += 1;
            if (served >= max_frames_per_run) return error.FrameBudgetExceeded;
        }
        return served;
    }

    fn respond(self: *Host, allocator: std.mem.Allocator, frame: ipc.Frame, bytes: []const u8) ![]u8 {
        self.session.accept(frame) catch |err| {
            return command.encodeResponse(allocator, frame.sequence, .failed, @errorName(err));
        };
        const wire = command.decodeRequest(bytes) catch |err| {
            return command.encodeResponse(allocator, frame.sequence, .failed, @errorName(err));
        };
        var result = self.harness.capabilities.execute(.{
            .id = frame.sequence,
            .subject = self.options.subject,
            .kind = wire.kind,
            .operation = wire.operation,
            .region = wire.region,
            .payload = wire.payload,
            .active_authorized = wire.active_authorized,
        }) catch |err| {
            try self.recordAudit();
            return command.encodeResponse(allocator, frame.sequence, self.lastStatus(), @errorName(err));
        };
        defer result.deinit();
        try self.recordAudit();
        return command.encodeResponse(allocator, frame.sequence, result.status, result.data);
    }

    fn recordAudit(self: *Host) !void {
        const sink = if (self.audit) |*writer| writer else return;
        const entries = self.harness.capabilities.audit.entries.items;
        const at = std.Io.Timestamp.now(self.io, .real).toSeconds();
        while (self.audit_seen < entries.len) : (self.audit_seen += 1) {
            try sink.append(entries[self.audit_seen], at);
        }
    }
};

fn validateOptions(options: Options) !void {
    if (options.subject.len == 0 or options.subject.len > capability.max_subject_bytes) {
        return error.InvalidSubject;
    }
    if (!std.unicode.utf8ValidateSlice(options.subject)) return error.InvalidSubject;
    if (options.region.len > command.max_region_bytes) return error.RegionTooLong;
    if (!std.unicode.utf8ValidateSlice(options.region)) return error.InvalidRegion;
}

pub fn enableAllKinds(backend: *simulator.Backend) void {
    inline for (std.meta.fields(capability.Kind)) |field| {
        backend.enable(@enumFromInt(field.value));
    }
}

test "host executes passive work, audits it and denies active work by default" {
    var host: Host = undefined;
    try host.init(std.testing.allocator, std.testing.io, .{});
    defer host.deinit();

    var result = try host.execute(.{
        .id = 1,
        .subject = "host:test",
        .kind = .infrared,
        .operation = .read,
        .payload = "capture",
    });
    defer result.deinit();
    try std.testing.expectEqual(capability.Status.succeeded, result.status);
    try std.testing.expectEqualStrings("capture", result.data);

    try std.testing.expectError(error.ActiveOperationDenied, host.execute(.{
        .id = 2,
        .subject = "host:test",
        .kind = .subghz,
        .operation = .transmit,
        .active_authorized = true,
    }));
    try std.testing.expectEqual(capability.Status.denied, host.lastStatus());
    try std.testing.expectEqual(@as(usize, 2), host.harness.capabilities.audit.entries.items.len);
}

test "host serves a PKRT frame stream over any reader and writer" {
    var host: Host = undefined;
    try host.init(std.testing.allocator, std.testing.io, .{ .subject = "host:stdio" });
    defer host.deinit();

    const request = try command.encodeRequest(std.testing.allocator, 9, .{
        .id = 0,
        .subject = "ignored",
        .kind = .infrared,
        .operation = .read,
        .payload = "frame",
    });
    defer std.testing.allocator.free(request);

    var input: std.Io.Reader = .fixed(request);
    var output_buffer: [4 * 1024]u8 = undefined;
    var output: std.Io.Writer = .fixed(&output_buffer);
    const served = try host.serveStream(&input, &output, 0);
    try std.testing.expectEqual(@as(usize, 1), served);

    const response = try command.decodeResponse(output.buffered());
    try std.testing.expectEqual(capability.Status.succeeded, response.status);
    try std.testing.expectEqualStrings("frame", response.data);
    try std.testing.expectEqualStrings("host:stdio", host.harness.capabilities.audit.entries.items[0].subject);
}

test "host rejects replayed frames without executing them" {
    var host: Host = undefined;
    try host.init(std.testing.allocator, std.testing.io, .{});
    defer host.deinit();

    const request = try command.encodeRequest(std.testing.allocator, 5, .{
        .id = 0,
        .subject = "ignored",
        .kind = .infrared,
        .operation = .read,
        .payload = "once",
    });
    defer std.testing.allocator.free(request);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const doubled = try std.mem.concat(arena.allocator(), u8, &.{ request, request });
    var input: std.Io.Reader = .fixed(doubled);
    var output_buffer: [4096]u8 = undefined;
    var output: std.Io.Writer = .fixed(&output_buffer);
    _ = try host.serveStream(&input, &output, 0);

    const first_len = (try ipc.frameSize(output.buffered()[0..ipc.header_size])).?;
    const first = try command.decodeResponse(output.buffered()[0..first_len]);
    try std.testing.expectEqual(capability.Status.succeeded, first.status);
    const second = try command.decodeResponse(output.buffered()[first_len..]);
    try std.testing.expectEqual(capability.Status.failed, second.status);
    try std.testing.expectEqual(@as(usize, 1), host.harness.capabilities.audit.entries.items.len);
}

test "audit log round trips entries as JSONL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const log_path = try std.fmt.allocPrint(
        std.testing.allocator,
        ".zig-cache/tmp/{s}/audit.jsonl",
        .{tmp.sub_path[0..]},
    );
    defer std.testing.allocator.free(log_path);

    // Two separate host runs must continue the sequence rather than restarting at 1.
    for ([_]u64{ 7, 8 }) |request_id| {
        var host: Host = undefined;
        try host.init(std.testing.allocator, std.testing.io, .{ .audit_path = log_path });
        defer host.deinit();
        var result = try host.execute(.{
            .id = request_id,
            .subject = "host:audit",
            .kind = .nfc,
            .operation = .read,
        });
        result.deinit();
    }

    const data = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, log_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(data);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const records = try audit_log.parse(arena.allocator(), data);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    try std.testing.expectEqual(@as(u64, 1), records[0].seq);
    try std.testing.expectEqual(@as(u64, 2), records[1].seq);
    try std.testing.expectEqual(@as(u64, 7), records[0].request_id);
    try std.testing.expectEqual(@as(u64, 8), records[1].request_id);
    try std.testing.expectEqualStrings("host:audit", records[0].subject);
    try std.testing.expectEqualStrings("nfc", records[0].kind);
    try std.testing.expectEqualStrings("succeeded", records[0].status);
}
