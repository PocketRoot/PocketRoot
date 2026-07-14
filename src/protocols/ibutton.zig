const std = @import("std");
const flipper_format = @import("../formats/flipper_format.zig");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "ibutton",
    .name = "iButton",
    .category = "Access",
    .file_extension = "ibtn",
    .media_type = "application/x-flipper-ibutton",
    .analyze = analyzeText,
    .sample = sampleText,
};

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\Filetype: Flipper iButton key
        \\Version: 2
        \\Protocol: DS1990
        \\Rom Data: 01 23 45 67 89 AB CD E9
        \\
    );
}

pub fn maximCrc8(data: []const u8) u8 {
    var crc: u8 = 0;
    for (data) |byte| {
        var input = byte;
        for (0..8) |_| {
            const mix = (crc ^ input) & 1;
            crc >>= 1;
            if (mix != 0) crc ^= 0x8C;
            input >>= 1;
        }
    }
    return crc;
}

pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var document = try flipper_format.parse(allocator, data);
    defer document.deinit();

    const filetype = try document.require("Filetype");
    if (!std.mem.eql(u8, filetype, "Flipper iButton key")) {
        return error.InvalidIButtonFiletype;
    }

    const version = try document.parseUnsigned(u32, "Version");
    if (version != 1 and version != 2) return error.UnsupportedIButtonVersion;

    const protocol_name = try document.require(if (version == 1) "Key type" else "Protocol");
    const summary = try std.fmt.allocPrint(
        allocator,
        "{s} iButton key (version {d})",
        .{ protocol_name, version },
    );
    defer allocator.free(summary);

    var result = try protocol.AnalysisResult.init(allocator, summary);
    errdefer result.deinit();

    try result.addField("protocol", protocol_name);
    var version_buffer: [10]u8 = undefined;
    try result.addField("version", try std.fmt.bufPrint(&version_buffer, "{d}", .{version}));

    const rom_key: []const u8 = if (version == 1) "Data" else "Rom Data";
    const dallas = isDallasProtocol(protocol_name);
    const rom_text = if (dallas) try document.require(rom_key) else document.first("Rom Data");
    if (rom_text) |_| {
        const rom_data = try document.parseHexBytes(allocator, rom_key);
        defer allocator.free(rom_data);

        if (dallas and rom_data.len != 8) return error.InvalidDallasRomLength;
        try addLengthField(&result, "rom_data_length", rom_data.len);
        try result.addField("rom_data", try document.require(rom_key));

        if (dallas and !std.mem.eql(u8, protocol_name, "DSGeneric") and
            rom_data.len == 8 and maximCrc8(rom_data[0..7]) != rom_data[7])
        {
            try result.addFinding(.warning, "Dallas ROM CRC-8 mismatch");
        }
    }

    if (version == 2) {
        try addOptionalDataLength(allocator, &document, &result, "Sram Data", "sram_data_length");
        try addOptionalDataLength(allocator, &document, &result, "Eeprom Data", "eeprom_data_length");
        try addOptionalDataLength(allocator, &document, &result, "Data", "data_length");
    } else {
        const legacy_data = try document.parseHexBytes(allocator, "Data");
        defer allocator.free(legacy_data);

        try addLengthField(&result, "data_length", legacy_data.len);
        try result.addFinding(.info, "Version 1 iButton file uses the legacy key format");
    }

    return result;
}

fn isDallasProtocol(name: []const u8) bool {
    return std.mem.eql(u8, name, "Dallas") or std.mem.startsWith(u8, name, "DS");
}

fn addOptionalDataLength(
    allocator: std.mem.Allocator,
    document: *const flipper_format.Document,
    result: *protocol.AnalysisResult,
    key: []const u8,
    field_name: []const u8,
) !void {
    if (document.first(key) == null) return;

    const bytes = try document.parseHexBytes(allocator, key);
    defer allocator.free(bytes);
    try addLengthField(result, field_name, bytes.len);
}

fn addLengthField(result: *protocol.AnalysisResult, name: []const u8, length: usize) !void {
    var buffer: [20]u8 = undefined;
    try result.addField(name, try std.fmt.bufPrint(&buffer, "{d}", .{length}));
}

test "DS1990 sample has a valid Dallas CRC" {
    const text = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(text);

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqual(@as(u8, 0xE9), maximCrc8(&.{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD }));
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
    try std.testing.expectEqualStrings("DS1990", result.fields.items[0].value);
    try std.testing.expectEqualStrings("8", result.fields.items[2].value);
    try std.testing.expectEqualStrings("01 23 45 67 89 AB CD E9", result.fields.items[3].value);
}

test "Dallas CRC mismatch warns except for DSGeneric" {
    const text =
        \\Filetype: Flipper iButton key
        \\Version: 2
        \\Protocol: DS1990
        \\Rom Data: 01 23 45 67 89 AB CD 00
    ;

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqual(protocol.FindingSeverity.warning, result.findings.items[0].severity);
    try std.testing.expect(std.mem.indexOf(u8, result.findings.items[0].message, "CRC-8") != null);

    const generic_text =
        \\Filetype: Flipper iButton key
        \\Version: 2
        \\Protocol: DSGeneric
        \\Rom Data: 01 23 45 67 89 AB CD 00
    ;
    var generic_result = try descriptor.analyze(std.testing.allocator, generic_text);
    defer generic_result.deinit();
    try std.testing.expectEqual(@as(usize, 0), generic_result.findings.items.len);
}

test "legacy Dallas keys are analyzed and marked for conversion" {
    const text =
        \\Filetype: Flipper iButton key
        \\Version: 1
        \\Key type: Dallas
        \\Data: 01 23 45 67 89 AB CD E9
    ;

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqual(protocol.FindingSeverity.info, result.findings.items[0].severity);
    try std.testing.expectEqualStrings("8", result.fields.items[2].value);
    try std.testing.expectEqualStrings("01 23 45 67 89 AB CD E9", result.fields.items[3].value);
    try std.testing.expectEqualStrings("8", result.fields.items[4].value);
}

test "iButton validates file type, version, and Dallas ROM length" {
    try std.testing.expectError(
        error.InvalidIButtonFiletype,
        descriptor.analyze(
            std.testing.allocator,
            "Filetype: wrong\nVersion: 2\nProtocol: DS1990\nRom Data: 01 23 45 67 89 AB CD E9\n",
        ),
    );
    try std.testing.expectError(
        error.UnsupportedIButtonVersion,
        descriptor.analyze(
            std.testing.allocator,
            "Filetype: Flipper iButton key\nVersion: 3\nProtocol: DS1990\nRom Data: 01 23 45 67 89 AB CD E9\n",
        ),
    );
    try std.testing.expectError(
        error.InvalidDallasRomLength,
        descriptor.analyze(
            std.testing.allocator,
            "Filetype: Flipper iButton key\nVersion: 2\nProtocol: DS1990\nRom Data: 01 23\n",
        ),
    );
}
