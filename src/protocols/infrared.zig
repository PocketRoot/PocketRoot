const std = @import("std");
const flipper = @import("../formats/flipper_format.zig");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "infrared",
    .name = "Infrared",
    .category = "Signal",
    .file_extension = "ir",
    .media_type = "application/x-flipper-ir",
    .analyze = analyzeText,
    .sample = sampleText,
};

pub const Signal = struct {
    name: []const u8,
    protocol: []const u8,
    address: u32,
    command: u32,
    frequency: u32 = 38_000,
    duty_cycle: u8 = 33,
};

pub fn demoSignal() Signal {
    return .{
        .name = "demo_power",
        .protocol = "NEC",
        .address = 0x20DF,
        .command = 0x10EF,
    };
}

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return toOwnedText(allocator, demoSignal());
}

pub fn toOwnedText(allocator: std.mem.Allocator, signal: Signal) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\Filetype: IR signals file
        \\Version: 1
        \\#
        \\name: {s}
        \\type: parsed
        \\protocol: {s}
        \\address: {X:0>2} {X:0>2} {X:0>2} {X:0>2}
        \\command: {X:0>2} {X:0>2} {X:0>2} {X:0>2}
        \\
    , .{
        signal.name,
        signal.protocol,
        @as(u8, @truncate(signal.address)),
        @as(u8, @truncate(signal.address >> 8)),
        @as(u8, @truncate(signal.address >> 16)),
        @as(u8, @truncate(signal.address >> 24)),
        @as(u8, @truncate(signal.command)),
        @as(u8, @truncate(signal.command >> 8)),
        @as(u8, @truncate(signal.command >> 16)),
        @as(u8, @truncate(signal.command >> 24)),
    });
}

pub fn toOwnedSummary(allocator: std.mem.Allocator, signal: Signal) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}: protocol={s} address=0x{x} command=0x{x} frequency={d} duty={d}%",
        .{
            signal.name,
            signal.protocol,
            signal.address,
            signal.command,
            signal.frequency,
            signal.duty_cycle,
        },
    );
}

pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    const signal = try parseSimpleWithAllocator(allocator, data);
    const summary = try toOwnedSummary(allocator, signal);
    defer allocator.free(summary);

    var result = try protocol.AnalysisResult.init(allocator, summary);
    errdefer result.deinit();

    try result.addField("name", signal.name);
    try result.addField("protocol", signal.protocol);

    var address_buffer: [10]u8 = undefined;
    try result.addField("address", try std.fmt.bufPrint(&address_buffer, "0x{x}", .{signal.address}));

    var command_buffer: [10]u8 = undefined;
    try result.addField("command", try std.fmt.bufPrint(&command_buffer, "0x{x}", .{signal.command}));

    var frequency_buffer: [10]u8 = undefined;
    try result.addField("frequency", try std.fmt.bufPrint(&frequency_buffer, "{d}", .{signal.frequency}));

    var duty_buffer: [5]u8 = undefined;
    try result.addField("duty_cycle", try std.fmt.bufPrint(
        &duty_buffer,
        "{d}.{d:0>2}",
        .{ signal.duty_cycle / 100, signal.duty_cycle % 100 },
    ));

    return result;
}

pub fn parseSimple(data: []const u8) !Signal {
    return parseSimpleWithAllocator(std.heap.page_allocator, data);
}

pub fn parseSimpleWithAllocator(allocator: std.mem.Allocator, data: []const u8) !Signal {
    var document = try flipper.parse(allocator, data);
    defer document.deinit();

    if (document.first("type")) |signal_type| {
        if (!std.mem.eql(u8, signal_type, "parsed")) return error.UnsupportedInfraredType;
    }

    const name = try document.require("name");
    const protocol_name = try document.require("protocol");

    if (document.first("Filetype")) |filetype| {
        if (!std.mem.eql(u8, filetype, "IR signals file") and
            !std.mem.eql(u8, filetype, "IR library file"))
        {
            return error.InvalidInfraredFiletype;
        }
    }
    if (document.first("Version") != null and try document.parseUnsigned(u32, "Version") != 1) {
        return error.UnsupportedInfraredVersion;
    }

    return .{
        .name = borrowOriginal(&document, data, name),
        .protocol = borrowOriginal(&document, data, protocol_name),
        .address = try parseCode(&document, "address"),
        .command = try parseCode(&document, "command"),
        .frequency = if (document.first("frequency") != null)
            try document.parseUnsigned(u32, "frequency")
        else
            38_000,
        .duty_cycle = try parseDutyCycle(&document),
    };
}

fn borrowOriginal(
    document: *const flipper.Document,
    original: []const u8,
    value: []const u8,
) []const u8 {
    const offset = @intFromPtr(value.ptr) - @intFromPtr(document.source.ptr);
    return original[offset..][0..value.len];
}

fn parseCode(document: *const flipper.Document, key: []const u8) !u32 {
    const value = try document.require(key);
    if (std.mem.indexOfAny(u8, value, " \t") == null) {
        return document.parseUnsigned(u32, key);
    }

    var result: u32 = 0;
    var count: usize = 0;
    var bytes = std.mem.tokenizeAny(u8, value, " \t");
    while (bytes.next()) |byte_text| {
        if (count == 4 or byte_text.len != 2) return error.InvalidInfraredCode;
        const byte = std.fmt.parseInt(u8, byte_text, 16) catch return error.InvalidInfraredCode;
        result |= @as(u32, byte) << @intCast(count * 8);
        count += 1;
    }
    if (count != 4) return error.InvalidInfraredCode;
    return result;
}

fn parseDutyCycle(document: *const flipper.Document) !u8 {
    const value = document.first("duty_cycle") orelse return 33;
    const point = std.mem.indexOfScalar(u8, value, '.') orelse {
        const percent = try document.parseUnsigned(u8, "duty_cycle");
        if (percent > 100) return error.InvalidDutyCycle;
        return percent;
    };

    const fraction_text = value[point + 1 ..];
    if (point == 0 or fraction_text.len == 0) {
        return error.InvalidDutyCycle;
    }

    const whole = std.fmt.parseInt(u8, value[0..point], 10) catch return error.InvalidDutyCycle;
    if (whole > 1) return error.InvalidDutyCycle;

    for (fraction_text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidDutyCycle;
        if (whole == 1 and byte != '0') return error.InvalidDutyCycle;
    }
    if (whole == 1) return 100;

    var percent: u16 = @as(u16, fraction_text[0] - '0') * 10;
    if (fraction_text.len >= 2) percent += fraction_text[1] - '0';
    if (fraction_text.len >= 3 and fraction_text[2] >= '5') percent += 1;
    if (percent > 100) return error.InvalidDutyCycle;
    return @intCast(percent);
}

test "infrared signal uses canonical Flipper format" {
    const text = try toOwnedText(std.testing.allocator, demoSignal());
    defer std.testing.allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, "address: DF 20 00 00") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "command: EF 10 00 00") != null);

    const parsed = try parseSimple(text);
    try std.testing.expectEqualStrings("demo_power", parsed.name);
    try std.testing.expectEqualStrings("NEC", parsed.protocol);
    try std.testing.expectEqual(@as(u32, 0x20DF), parsed.address);
    try std.testing.expectEqual(@as(u32, 0x10EF), parsed.command);
    try std.testing.expectEqual(@as(u8, 33), parsed.duty_cycle);
}

test "infrared parser accepts canonical decimal duty cycles" {
    const parsed = try parseSimple(
        \\name: legacy_power
        \\type: parsed
        \\protocol: NEC
        \\address: DF 20 00 00
        \\command: EF 10 00 00
        \\duty_cycle: 0.330000
        \\
    );

    try std.testing.expectEqual(@as(u8, 33), parsed.duty_cycle);
}

test "infrared parser accepts legacy numeric fields" {
    const parsed = try parseSimple(
        \\name: legacy_power
        \\type: parsed
        \\protocol: NEC
        \\address: 0x20DF
        \\command: 4335
        \\frequency: 38000
        \\duty_cycle: 33
        \\
    );

    try std.testing.expectEqualStrings("legacy_power", parsed.name);
    try std.testing.expectEqual(@as(u32, 0x20DF), parsed.address);
    try std.testing.expectEqual(@as(u32, 0x10EF), parsed.command);
    try std.testing.expectEqual(@as(u8, 33), parsed.duty_cycle);
}

test "infrared summary includes parsed fields" {
    const summary = try toOwnedSummary(std.testing.allocator, demoSignal());
    defer std.testing.allocator.free(summary);

    try std.testing.expect(std.mem.indexOf(u8, summary, "protocol=NEC") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "address=0x20df") != null);
}

test "infrared descriptor returns structured analysis" {
    const text = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(text);

    var analysis = try descriptor.analyze(std.testing.allocator, text);
    defer analysis.deinit();

    try std.testing.expect(std.mem.indexOf(u8, analysis.summary, "demo_power") != null);
    try std.testing.expectEqual(@as(usize, 6), analysis.fields.items.len);
    try std.testing.expectEqualStrings("name", analysis.fields.items[0].name);
    try std.testing.expectEqualStrings("demo_power", analysis.fields.items[0].value);
    try std.testing.expectEqualStrings("duty_cycle", analysis.fields.items[5].name);
    try std.testing.expectEqualStrings("0.33", analysis.fields.items[5].value);
}
