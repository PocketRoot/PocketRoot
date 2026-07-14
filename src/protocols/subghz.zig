const std = @import("std");
const flipper_format = @import("../formats/flipper_format.zig");
const protocol = @import("protocol.zig");

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
