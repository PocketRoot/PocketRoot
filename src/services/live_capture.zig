const std = @import("std");
const builtin = @import("builtin");
const protocol = @import("../protocols/protocol.zig");
const windows_system = @import("windows_system.zig");

pub const min_duration_seconds = 1;
pub const max_duration_seconds = 60;
pub const min_file_size_mb = 1;
pub const max_file_size_mb = 64;
pub const max_output_path_bytes = 768;
pub const max_pcapng_bytes = 80 * 1024 * 1024;

pub const Options = struct {
    component_id: u32,
    duration_seconds: u8 = 10,
    file_size_mb: u16 = 16,
};

const Command = struct {
    argv: [14][]const u8 = undefined,
    len: usize = 0,

    fn add(self: *Command, value: []const u8) void {
        self.argv[self.len] = value;
        self.len += 1;
    }

    fn slice(self: *const Command) []const []const u8 {
        return self.argv[0..self.len];
    }
};

const CapturePlan = struct {
    component_buffer: [16]u8 = undefined,
    size_buffer: [16]u8 = undefined,
    start: Command = .{},
    stop: Command = .{},
    convert: Command = .{},

    fn init(
        self: *CapturePlan,
        executable_path: []const u8,
        component_id: u32,
        file_size_mb: u16,
        etl_path: []const u8,
        partial_path: []const u8,
    ) !void {
        self.* = .{};
        const component = try std.fmt.bufPrint(&self.component_buffer, "{d}", .{component_id});
        const size = try std.fmt.bufPrint(&self.size_buffer, "{d}", .{file_size_mb});
        for (&[_][]const u8{
            executable_path,
            "start",
            "--capture",
            "--comp",
            component,
            "--pkt-size",
            "0",
            "--file-name",
            etl_path,
            "--file-size",
            size,
            "--log-mode",
            "circular",
        }) |arg| self.start.add(arg);
        self.stop.add(executable_path);
        self.stop.add("stop");
        for (&[_][]const u8{
            executable_path,
            "etl2pcap",
            etl_path,
            "--out",
            partial_path,
        }) |arg| self.convert.add(arg);
    }
};

pub fn capture(
    allocator: std.mem.Allocator,
    io: std.Io,
    output_path: []const u8,
    options: Options,
) !protocol.AnalysisResult {
    try validateOptions(output_path, options);
    return switch (builtin.os.tag) {
        .windows => captureWindows(allocator, io, output_path, options),
        else => error.UnsupportedPlatform,
    };
}

fn validateOptions(output_path: []const u8, options: Options) !void {
    try validateOutputPath(output_path);
    if (options.component_id == 0) return error.InvalidComponentId;
    if (options.duration_seconds < min_duration_seconds or options.duration_seconds > max_duration_seconds) {
        return error.InvalidDuration;
    }
    if (options.file_size_mb < min_file_size_mb or options.file_size_mb > max_file_size_mb) {
        return error.InvalidFileSize;
    }
}

fn validateOutputPath(path: []const u8) !void {
    if (path.len == 0 or path.len > max_output_path_bytes) return error.InvalidOutputPath;
    for (path) |byte| if (byte == 0 or byte < 0x20) return error.InvalidOutputPath;
    const basename = std.fs.path.basename(path);
    const extension = std.fs.path.extension(basename);
    if (basename.len <= extension.len or !std.ascii.eqlIgnoreCase(extension, ".pcapng")) {
        return error.InvalidOutputPath;
    }
}

fn captureWindows(
    allocator: std.mem.Allocator,
    io: std.Io,
    output_path: []const u8,
    options: Options,
) !protocol.AnalysisResult {
    const pktmon_path = try windows_system.executablePath(allocator, "pktmon.exe");
    defer allocator.free(pktmon_path);
    try ensureParentDirectory(io, output_path);
    try ensureMissing(io, output_path);

    const timestamp = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    const etl_path = try std.fmt.allocPrint(allocator, "{s}.pocketroot-{d}.etl", .{ output_path, timestamp });
    defer allocator.free(etl_path);
    const partial_path = try std.fmt.allocPrint(allocator, "{s}.pocketroot-{d}.partial.pcapng", .{ output_path, timestamp });
    defer allocator.free(partial_path);
    try ensureMissing(io, etl_path);
    try ensureMissing(io, partial_path);
    defer deleteIfExists(io, etl_path);
    defer deleteIfExists(io, partial_path);

    var plan: CapturePlan = undefined;
    try plan.init(pktmon_path, options.component_id, options.file_size_mb, etl_path, partial_path);
    runCommand(allocator, io, plan.start.slice(), 10_000) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => return error.CaptureStartTimeout,
        else => return error.CaptureStartFailed,
    };
    var started = true;
    defer if (started) runCommand(allocator, io, plan.stop.slice(), 10_000) catch {};

    std.Io.Timeout.sleep(.{ .duration = .{
        .raw = std.Io.Duration.fromSeconds(options.duration_seconds),
        .clock = .awake,
    } }, io) catch |err| return err;

    runCommand(allocator, io, plan.stop.slice(), 10_000) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => return error.CaptureStopTimeout,
        else => return error.CaptureStopFailed,
    };
    started = false;
    runCommand(allocator, io, plan.convert.slice(), 60_000) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => return error.CaptureConversionTimeout,
        else => return error.CaptureConversionFailed,
    };

    const output_bytes = inspectPcapng(io, partial_path) catch return error.InvalidCaptureOutput;
    if (output_bytes > max_pcapng_bytes) return error.CaptureOutputTooLarge;
    std.Io.Dir.cwd().renamePreserve(partial_path, std.Io.Dir.cwd(), output_path, io) catch |err| switch (err) {
        error.PathAlreadyExists => return error.OutputExists,
        else => return err,
    };

    var result = try protocol.AnalysisResult.init(allocator, "Windows packet capture completed");
    errdefer result.deinit();
    try result.addField("platform", "windows");
    try result.addField("backend", "pktmon");
    try result.addNumberField("component_id", options.component_id);
    try result.addNumberField("duration_seconds", options.duration_seconds);
    try result.addNumberField("file_size_limit_mb", options.file_size_mb);
    try result.addField("output_path", output_path);
    try result.addNumberField("output_bytes", output_bytes);
    var summary_buffer: [96]u8 = undefined;
    try result.setSummary(try std.fmt.bufPrint(
        &summary_buffer,
        "Captured {d}s from pktmon component {d}",
        .{ options.duration_seconds, options.component_id },
    ));
    return result;
}

fn runCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    timeout_ms: u32,
) !void {
    const command = try std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
        .timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(timeout_ms),
            .clock = .awake,
        } },
    });
    defer allocator.free(command.stdout);
    defer allocator.free(command.stderr);
    switch (command.term) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

fn ensureParentDirectory(io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    var directory = if (std.fs.path.isAbsolute(parent))
        try std.Io.Dir.openDirAbsolute(io, parent, .{})
    else
        try std.Io.Dir.cwd().openDir(io, parent, .{});
    defer directory.close(io);
}

fn ensureMissing(io: std.Io, path: []const u8) !void {
    const access_result = if (std.fs.path.isAbsolute(path))
        std.Io.Dir.accessAbsolute(io, path, .{})
    else
        std.Io.Dir.cwd().access(io, path, .{});
    access_result catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.OutputExists;
}

fn deleteIfExists(io: std.Io, path: []const u8) void {
    if (std.fs.path.isAbsolute(path))
        std.Io.Dir.deleteFileAbsolute(io, path) catch {}
    else
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

fn inspectPcapng(io: std.Io, path: []const u8) !u64 {
    const file = if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.openFileAbsolute(io, path, .{})
    else
        try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    var header: [28]u8 = undefined;
    if (try file.readPositionalAll(io, &header, 0) != header.len) return error.InvalidPcapng;
    const section = parsePcapngSectionHeader(&header, stat.size) catch return error.InvalidPcapng;
    var trailer: [4]u8 = undefined;
    if (try file.readPositionalAll(
        io,
        &trailer,
        @as(u64, section.block_length) - @as(u64, trailer.len),
    ) != trailer.len) {
        return error.InvalidPcapng;
    }
    if (std.mem.readInt(u32, &trailer, section.endian) != section.block_length) return error.InvalidPcapng;
    return stat.size;
}

const PcapngSectionHeader = struct {
    endian: std.builtin.Endian,
    block_length: u32,
};

fn parsePcapngSectionHeader(header: *const [28]u8, file_size: u64) !PcapngSectionHeader {
    if (!std.mem.eql(u8, header[0..4], &.{ 0x0a, 0x0d, 0x0d, 0x0a })) return error.InvalidPcapng;
    const endian: std.builtin.Endian = if (std.mem.eql(u8, header[8..12], &.{ 0x4d, 0x3c, 0x2b, 0x1a }))
        .little
    else if (std.mem.eql(u8, header[8..12], &.{ 0x1a, 0x2b, 0x3c, 0x4d }))
        .big
    else
        return error.InvalidPcapng;
    const block_length = std.mem.readInt(u32, header[4..8], endian);
    const block_length_u64: u64 = block_length;
    if (block_length_u64 < header.len or block_length & 3 != 0 or block_length_u64 > file_size) {
        return error.InvalidPcapng;
    }
    if (std.mem.readInt(u16, header[12..14], endian) != 1 or
        std.mem.readInt(u16, header[14..16], endian) != 0)
    {
        return error.InvalidPcapng;
    }
    const section_length = std.mem.readInt(u64, header[16..24], endian);
    if (section_length != std.math.maxInt(u64) and section_length > file_size - block_length_u64) {
        return error.InvalidPcapng;
    }
    return .{ .endian = endian, .block_length = block_length };
}

test "pktmon capture plan is component scoped and bounded" {
    var plan: CapturePlan = undefined;
    try plan.init("C:\\Windows\\System32\\pktmon.exe", 7, 16, "capture.etl", "capture.partial.pcapng");
    const expected_start = [_][]const u8{
        "C:\\Windows\\System32\\pktmon.exe", "start",      "--capture",   "--comp",      "7",
        "--pkt-size",                        "0",          "--file-name", "capture.etl", "--file-size",
        "16",                                "--log-mode", "circular",
    };
    try std.testing.expectEqual(expected_start.len, plan.start.slice().len);
    for (expected_start, plan.start.slice()) |expected, actual| try std.testing.expectEqualStrings(expected, actual);
    try std.testing.expectEqualStrings("stop", plan.stop.slice()[1]);
    try std.testing.expectEqualStrings("etl2pcap", plan.convert.slice()[1]);
    try std.testing.expectEqualStrings("capture.partial.pcapng", plan.convert.slice()[4]);
}

test "pktmon output validation rejects unsafe or ambiguous paths" {
    try validateOptions("captures/session.pcapng", .{ .component_id = 3 });
    try validateOptions("captures/session.PCAPNG", .{ .component_id = 3, .duration_seconds = 60, .file_size_mb = 64 });
    try std.testing.expectError(error.InvalidOutputPath, validateOutputPath("capture.etl"));
    try std.testing.expectError(error.InvalidOutputPath, validateOutputPath("capture\n.pcapng"));
    try std.testing.expectError(error.InvalidComponentId, validateOptions("capture.pcapng", .{ .component_id = 0 }));
    try std.testing.expectError(error.InvalidDuration, validateOptions("capture.pcapng", .{ .component_id = 1, .duration_seconds = 0 }));
    try std.testing.expectError(error.InvalidFileSize, validateOptions("capture.pcapng", .{ .component_id = 1, .file_size_mb = 65 }));
}

test "pcapng output validation checks the complete section header" {
    var header = [_]u8{0} ** 28;
    @memcpy(header[0..4], &[_]u8{ 0x0a, 0x0d, 0x0d, 0x0a });
    @memcpy(header[8..12], &[_]u8{ 0x4d, 0x3c, 0x2b, 0x1a });
    std.mem.writeInt(u32, header[4..8], 28, .little);
    std.mem.writeInt(u16, header[12..14], 1, .little);
    std.mem.writeInt(u16, header[14..16], 0, .little);
    std.mem.writeInt(u64, header[16..24], std.math.maxInt(u64), .little);
    const parsed = try parsePcapngSectionHeader(&header, header.len);
    try std.testing.expectEqual(std.builtin.Endian.little, parsed.endian);
    try std.testing.expectEqual(@as(u32, 28), parsed.block_length);

    header[8] = 0;
    try std.testing.expectError(error.InvalidPcapng, parsePcapngSectionHeader(&header, header.len));
}

test "capture destination must not already exist" {
    const root = ".zig-cache/live-capture-test";
    const output = ".zig-cache/live-capture-test/existing.pcapng";
    try std.Io.Dir.cwd().createDirPath(std.testing.io, root);
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, output) catch {};
    defer std.Io.Dir.cwd().deleteDir(std.testing.io, root) catch {};
    try ensureParentDirectory(std.testing.io, output);
    try ensureMissing(std.testing.io, output);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = output, .data = "existing" });
    try std.testing.expectError(error.OutputExists, ensureMissing(std.testing.io, output));
}
