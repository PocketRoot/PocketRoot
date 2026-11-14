const std = @import("std");
const flipper_format = @import("../formats/flipper_format.zig");
const protocol = @import("protocol.zig");

pub const max_raw_timings = 128 * 1024;

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "subghz",
    .name = "Sub-GHz",
    .category = "Signal",
    .file_extension = "sub",
    .media_type = "application/x-flipper-subghz",
    .analyze = analyzeText,
    .sample = sampleText,
};

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\Filetype: Flipper SubGhz Key File
        \\Version: 1
        \\Frequency: 433920000
        \\Preset: FuriHalSubGhzPresetOok650Async
        \\Protocol: Princeton
        \\Bit: 24
        \\Key: 00 00 00 00 00 AB CD EF
        \\TE: 400
        \\
    );
}

pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var document = try flipper_format.parse(allocator, data);
    defer document.deinit();

    const filetype = try document.require("Filetype");
    if (!std.mem.eql(u8, filetype, "Flipper SubGhz Key File") and
        !std.mem.eql(u8, filetype, "Flipper SubGhz RAW File"))
    {
        return error.InvalidSubGhzFiletype;
    }

    const version = try document.parseUnsigned(u32, "Version");
    if (version != 1) return error.UnsupportedSubGhzVersion;

    const frequency = try document.parseUnsigned(u32, "Frequency");
    const preset = try document.require("Preset");
    const signal_protocol = try document.require("Protocol");

    if (std.mem.eql(u8, signal_protocol, "RAW")) {
        if (!std.mem.eql(u8, filetype, "Flipper SubGhz RAW File")) return error.InvalidSubGhzRawFiletype;
        const stats = try validateRaw(&document);
        const summary = try std.fmt.allocPrint(
            allocator,
            "RAW: frequency={d} preset={s} timings={d}",
            .{ frequency, preset, stats.timings },
        );
        defer allocator.free(summary);
        var result = try protocol.AnalysisResult.init(allocator, summary);
        errdefer result.deinit();
        try result.addField("filetype", filetype);
        try result.addField("protocol", signal_protocol);
        try result.addNumberField("frequency", frequency);
        try result.addField("preset", preset);
        try result.addNumberField("raw_lines", stats.lines);
        try result.addNumberField("timings", stats.timings);
        return result;
    }

    const summary = try std.fmt.allocPrint(
        allocator,
        "{s}: frequency={d} preset={s}",
        .{ signal_protocol, frequency, preset },
    );
    defer allocator.free(summary);

    var result = try protocol.AnalysisResult.init(allocator, summary);
    errdefer result.deinit();

    var frequency_buffer: [16]u8 = undefined;
    const frequency_text = try std.fmt.bufPrint(&frequency_buffer, "{d}", .{frequency});
    try result.addField("filetype", filetype);
    try result.addField("protocol", signal_protocol);
    try result.addField("frequency", frequency_text);
    try result.addField("preset", preset);
    if (document.first("Key")) |key| try result.addField("key", key);

    return result;
}

const RawStats = struct {
    lines: usize = 0,
    timings: usize = 0,
};

fn validateRaw(document: *const flipper_format.Document) !RawStats {
    var stats = RawStats{};
    var expect_positive = true;
    for (document.entries.items) |entry| {
        if (!std.mem.eql(u8, entry.key, "RAW_Data")) continue;
        stats.lines += 1;
        var line_timings: usize = 0;
        var tokens = std.mem.tokenizeAny(u8, entry.value, " \t");
        while (tokens.next()) |token| {
            const timing = std.fmt.parseInt(i32, token, 10) catch return error.InvalidSubGhzRawTiming;
            if (timing == 0 or (timing > 0) != expect_positive) return error.InvalidSubGhzRawTiming;
            expect_positive = !expect_positive;
            line_timings += 1;
            stats.timings += 1;
            if (line_timings > 512) return error.TooManySubGhzRawTimingsPerLine;
            if (stats.timings > max_raw_timings) return error.TooManySubGhzRawTimings;
        }
        if (line_timings == 0) return error.InvalidSubGhzRawTiming;
    }
    if (stats.lines == 0) return error.MissingSubGhzRawData;
    return stats;
}

test "subghz descriptor analyzes key files" {
    const text = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(text);

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.summary, "Princeton") != null);
    try std.testing.expectEqual(@as(usize, 5), result.fields.items.len);
}

test "subghz rejects unsupported versions" {
    const text =
        \\Filetype: Flipper SubGhz Key File
        \\Version: 2
        \\Frequency: 433920000
        \\Preset: FuriHalSubGhzPresetOok650Async
        \\Protocol: Princeton
    ;

    try std.testing.expectError(
        error.UnsupportedSubGhzVersion,
        descriptor.analyze(std.testing.allocator, text),
    );
}

test "subghz validates official RAW timing rules" {
    const text =
        \\Filetype: Flipper SubGhz RAW File
        \\Version: 1
        \\Frequency: 433920000
        \\Preset: FuriHalSubGhzPresetOok650Async
        \\Protocol: RAW
        \\RAW_Data: 29262 -361 68 -2635
        \\RAW_Data: 66 -24113
    ;
    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "timings=6") != null);
    try std.testing.expectEqualStrings("2", result.fields.items[4].value);

    const invalid =
        \\Filetype: Flipper SubGhz RAW File
        \\Version: 1
        \\Frequency: 433920000
        \\Preset: FuriHalSubGhzPresetOok650Async
        \\Protocol: RAW
        \\RAW_Data: 100 200
    ;
    try std.testing.expectError(error.InvalidSubGhzRawTiming, analyzeText(std.testing.allocator, invalid));
}
