const std = @import("std");
const flipper_format = @import("../formats/flipper_format.zig");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "lfrfid",
    .name = "125 kHz RFID",
    .category = "Credential",
    .file_extension = "rfid",
    .media_type = "application/x-flipper-rfid",
    .analyze = analyzeText,
    .sample = sampleText,
};

const supported_key_types = [_][]const u8{
    "EM4100",
    "H10301",
    "Idteck",
    "Indala26",
    "IOProxXSF",
    "AWID",
    "FDX-A",
    "FDX-B",
    "HIDProx",
    "HIDExt",
    "Pyramid",
    "Viking",
    "Jablotron",
    "Paradox",
    "PAC/Stanley",
    "Keri",
    "Gallagher",
    "GProxII",
};

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\Filetype: Flipper RFID key
        \\Version: 1
        \\Key type: EM4100
        \\Data: 01 23 45 67 89
        \\
    );
}

pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var document = try flipper_format.parse(allocator, data);
    defer document.deinit();

    const filetype = try document.require("Filetype");
    if (!std.mem.eql(u8, filetype, "Flipper RFID key")) return error.InvalidLfRfidFiletype;

    const version = try document.parseUnsigned(u32, "Version");
    if (version != 1) return error.UnsupportedLfRfidVersion;

    const key_type = try document.require("Key type");
    const data_text = try document.require("Data");
    const key_data = try document.parseHexBytes(allocator, "Data");
    defer allocator.free(key_data);

    const summary = try std.fmt.allocPrint(
        allocator,
        "{s} LF RFID key: {d} bytes",
        .{ key_type, key_data.len },
    );
    defer allocator.free(summary);

    var result = try protocol.AnalysisResult.init(allocator, summary);
    errdefer result.deinit();

    var data_size_buffer: [20]u8 = undefined;
    try result.addField("key_type", key_type);
    try result.addField("data_size", try std.fmt.bufPrint(&data_size_buffer, "{d}", .{key_data.len}));
    try result.addField("data", data_text);

    if (!isSupportedKeyType(key_type)) {
        const warning = try std.fmt.allocPrint(allocator, "Unknown LF RFID key type: {s}", .{key_type});
        defer allocator.free(warning);
        try result.addFinding(.warning, warning);
    }

    return result;
}

fn isSupportedKeyType(key_type: []const u8) bool {
    for (supported_key_types) |supported| {
        if (std.mem.eql(u8, key_type, supported)) return true;
    }
    return false;
}

test "lfrfid analyzes EM4100 keys" {
    const text = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(text);

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.summary, "EM4100") != null);
    try std.testing.expectEqual(@as(usize, 3), result.fields.items.len);
    try std.testing.expectEqualStrings("key_type", result.fields.items[0].name);
    try std.testing.expectEqualStrings("EM4100", result.fields.items[0].value);
    try std.testing.expectEqualStrings("5", result.fields.items[1].value);
    try std.testing.expectEqualStrings("01 23 45 67 89", result.fields.items[2].value);
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
}

test "lfrfid warns about unknown key types" {
    const text =
        \\Filetype: Flipper RFID key
        \\Version: 1
        \\Key type: FutureTag
        \\Data: 01 02
    ;

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqual(protocol.FindingSeverity.warning, result.findings.items[0].severity);
    try std.testing.expect(std.mem.indexOf(u8, result.findings.items[0].message, "FutureTag") != null);
}

test "lfrfid rejects malformed hexadecimal data" {
    const text =
        \\Filetype: Flipper RFID key
        \\Version: 1
        \\Key type: EM4100
        \\Data: 01 nope
    ;

    try std.testing.expectError(
        error.InvalidHexBytes,
        descriptor.analyze(std.testing.allocator, text),
    );
}
