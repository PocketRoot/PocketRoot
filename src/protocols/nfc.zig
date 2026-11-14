const std = @import("std");
const flipper_format = @import("../formats/flipper_format.zig");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "nfc",
    .name = "NFC",
    .category = "Credential",
    .file_extension = "nfc",
    .media_type = "application/x-flipper-nfc",
    .analyze = analyzeText,
    .sample = sampleText,
};

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\Filetype: Flipper NFC device
        \\Version: 4
        \\Device type: ISO14443-3A
        \\UID: 04 48 6A 32 33 58 80
        \\ATQA: 00 44
        \\SAK: 00
        \\
    );
}

pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var document = try flipper_format.parse(allocator, data);
    defer document.deinit();

    if (!std.mem.eql(u8, try document.require("Filetype"), "Flipper NFC device")) {
        return error.InvalidNfcFiletype;
    }
    const version = try document.parseUnsigned(u32, "Version");
    if (version < 1 or version > 4) return error.UnsupportedNfcVersion;

    const device_type = try document.require("Device type");
    const uid_text = try document.require("UID");
    const uid = try document.parseHexBytes(allocator, "UID");
    defer allocator.free(uid);
    if (uid.len < 4 or uid.len > 10) return error.InvalidNfcUidLength;

    try validateDeviceFields(allocator, &document, device_type, uid.len);

    const summary = try std.fmt.allocPrint(
        allocator,
        "{s} NFC device: UID {s}",
        .{ device_type, uid_text },
    );
    defer allocator.free(summary);

    var result = try protocol.AnalysisResult.init(allocator, summary);
    errdefer result.deinit();
    try result.addField("device_type", device_type);
    try result.addNumberField("version", version);
    try result.addField("uid", uid_text);
    try result.addNumberField("uid_length", uid.len);
    try result.addNumberField("pages", countPrefixedEntries(&document, "Page "));
    try result.addNumberField("blocks", countPrefixedEntries(&document, "Block "));

    if (version < 4) try result.addFinding(.info, "Deprecated Flipper NFC file version");
    if (!knownDeviceType(device_type)) try result.addFinding(.warning, "Unknown NFC device type");
    return result;
}

fn validateDeviceFields(
    allocator: std.mem.Allocator,
    document: *const flipper_format.Document,
    device_type: []const u8,
    uid_len: usize,
) !void {
    const is_a = std.mem.eql(u8, device_type, "ISO14443-3A") or
        std.mem.eql(u8, device_type, "ISO14443-4A") or
        std.mem.eql(u8, device_type, "NTAG/Ultralight") or
        std.mem.startsWith(u8, device_type, "NTAG") or
        std.mem.startsWith(u8, device_type, "Mifare");
    if (is_a) {
        if (uid_len != 4 and uid_len != 7) return error.InvalidNfcAUidLength;
        try requireHexLength(allocator, document, "ATQA", 2);
        try requireHexLength(allocator, document, "SAK", 1);
    }
    if (std.mem.eql(u8, device_type, "ISO14443-3B")) {
        if (uid_len != 4) return error.InvalidNfcBUidLength;
        try requireHexLength(allocator, document, "Application data", 4);
        try requireHexLength(allocator, document, "Protocol info", 3);
    }
    if (std.mem.eql(u8, device_type, "ISO14443-4A")) {
        const ats = try document.parseHexBytes(allocator, "ATS");
        defer allocator.free(ats);
        if (ats.len < 5) return error.InvalidNfcAtsLength;
    }
}

fn requireHexLength(
    allocator: std.mem.Allocator,
    document: *const flipper_format.Document,
    key: []const u8,
    expected: usize,
) !void {
    const bytes = try document.parseHexBytes(allocator, key);
    defer allocator.free(bytes);
    if (bytes.len != expected) return error.InvalidNfcFieldLength;
}

fn countPrefixedEntries(document: *const flipper_format.Document, prefix: []const u8) usize {
    var count: usize = 0;
    for (document.entries.items) |entry| {
        if (std.mem.startsWith(u8, entry.key, prefix)) count += 1;
    }
    return count;
}

fn knownDeviceType(value: []const u8) bool {
    const exact = [_][]const u8{
        "ISO14443-3A",
        "ISO14443-3B",
        "ISO14443-4A",
        "ISO14443-4B",
        "ISO15693-3",
        "FeliCa",
        "NTAG/Ultralight",
        "Mifare Classic",
        "Mifare DESFire",
        "SLIX",
        "ST25TB",
    };
    for (exact) |known| if (std.mem.eql(u8, known, value)) return true;
    return std.mem.startsWith(u8, value, "NTAG") or
        std.mem.startsWith(u8, value, "Mifare Ultralight");
}

test "nfc analyzes official ISO14443-3A header" {
    const text = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(text);
    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqualStrings("ISO14443-3A", result.fields.items[0].value);
    try std.testing.expectEqualStrings("7", result.fields.items[3].value);
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
}

test "nfc validates ISO14443-3B field sizes" {
    const text =
        \\Filetype: Flipper NFC device
        \\Version: 4
        \\Device type: ISO14443-3B
        \\UID: 30 1D B3 28
        \\Application data: 00 12 34 FF
        \\Protocol info: 11 81 E1
    ;
    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();
    try std.testing.expectEqualStrings("4", result.fields.items[3].value);
}

test "nfc rejects malformed UID lengths" {
    const text =
        \\Filetype: Flipper NFC device
        \\Version: 4
        \\Device type: ISO14443-3A
        \\UID: 01 02 03 04 05
        \\ATQA: 00 44
        \\SAK: 00
    ;
    try std.testing.expectError(error.InvalidNfcAUidLength, analyzeText(std.testing.allocator, text));
}
