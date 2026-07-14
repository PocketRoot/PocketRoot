const std = @import("std");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "badusb",
    .name = "BadUSB Script",
    .category = "Script",
    .file_extension = "txt",
    .media_type = "text/x-duckyscript",
    .auto_detect = false,
    .analyze = analyzeText,
    .sample = sampleText,
};

const Stats = struct {
    lines: usize,
    commands: usize = 0,
    explicit_delay_ms: u64 = 0,
    default_delay_ms: u64 = 0,
    current_default_ms: u64 = 0,
    next_string_delay_ms: ?u64 = null,
    default_string_delay_ms: u64 = 0,
    previous_explicit_ms: u64 = 0,
    previous_default_ms: u64 = 0,
    has_previous: bool = false,
    blocking_waits: usize = 0,
};

const ComboStatus = enum { not_combo, valid, missing_key, invalid_key };

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\REM PocketRoot read-only review sample
        \\ID 1209:0001 PocketRoot:Audit
        \\DEFAULT_DELAY 50
        \\STRINGLN PocketRoot audit sample
        \\WAIT_FOR_BUTTON_PRESS
        \\
    );
}

/// Performs static inspection only. Script commands are never executed.
pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var result = try protocol.AnalysisResult.init(allocator, "BadUSB script review");
    errdefer result.deinit();

    var stats = Stats{ .lines = countLines(data) };
    var lines = std.mem.splitScalar(u8, data, '\n');
    var line_number: usize = 0;

    while (lines.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        const command_end = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
        const command = line[0..command_end];
        const argument = std.mem.trim(u8, line[command_end..], " \t");
        if (equal(command, "REM")) continue;

        stats.commands += 1;
        const command_number = stats.commands;
        const inherited_default = stats.current_default_ms;
        var explicit_delay: u64 = 0;
        var default_delay: u64 = inherited_default;
        var valid = true;
        var remember = true;

        if (equal(command, "DELAY")) {
            if (parseUnsigned(argument)) |delay| {
                explicit_delay = delay;
            } else {
                try warn(&result, line_number, command, "missing or invalid integer");
                valid = false;
            }
        } else if (isAny(command, &.{ "DEFAULT_DELAY", "DEFAULTDELAY" })) {
            if (parseUnsigned(argument)) |delay| {
                stats.current_default_ms = delay;
            } else {
                try warn(&result, line_number, command, "missing or invalid integer");
                valid = false;
            }
        } else if (isAny(command, &.{ "STRING_DELAY", "STRINGDELAY" })) {
            if (parseUnsigned(argument)) |delay| {
                stats.next_string_delay_ms = delay;
            } else {
                try warn(&result, line_number, command, "missing or invalid integer");
                valid = false;
            }
        } else if (isAny(command, &.{ "DEFAULT_STRING_DELAY", "DEFAULTSTRINGDELAY" })) {
            if (parseUnsigned(argument)) |delay| {
                stats.default_string_delay_ms = delay;
            } else {
                try warn(&result, line_number, command, "missing or invalid integer");
                valid = false;
            }
        } else if (isAny(command, &.{ "STRING", "STRINGLN" })) {
            if (argument.len == 0) {
                try warn(&result, line_number, command, "missing text");
                valid = false;
            } else {
                const extra: usize = if (equal(command, "STRINGLN")) 1 else 0;
                const characters: u64 = @intCast(utf8Length(argument) + extra);
                if (stats.next_string_delay_ms) |delay| {
                    explicit_delay = delay *| characters;
                    stats.next_string_delay_ms = null;
                } else {
                    default_delay = default_delay +| (stats.default_string_delay_ms *| characters);
                }
            }
        } else if (equal(command, "REPEAT")) {
            remember = false;
            if (parseUnsigned(argument)) |count| {
                if (count == 0) {
                    try warn(&result, line_number, command, "repeat count must be greater than zero");
                    valid = false;
                } else if (!stats.has_previous) {
                    try warn(&result, line_number, command, "no previous command to repeat");
                    valid = false;
                } else {
                    // ponytail: reuse the previous timing estimate; emulate interpreter state only if exact replay timing is needed.
                    explicit_delay = stats.previous_explicit_ms *| count;
                    default_delay = default_delay +| (stats.previous_default_ms *| count);
                }
            } else {
                try warn(&result, line_number, command, "missing or invalid integer");
                valid = false;
            }
        } else if (equal(command, "ID")) {
            if (command_number != 1) try warn(&result, line_number, command, "must be the first effective command");
            if (!validUsbId(argument)) {
                try warn(&result, line_number, command, "expected VID:PID with four hexadecimal digits each");
                valid = false;
            }
        } else if (equal(command, "ALTCHAR")) {
            if (parseUnsigned(argument) == null) {
                try warn(&result, line_number, command, "missing or invalid integer");
                valid = false;
            }
        } else if (isAny(command, &.{ "ALTSTRING", "ALTCODE" })) {
            if (argument.len == 0) {
                try warn(&result, line_number, command, "missing text");
                valid = false;
            }
        } else if (equal(command, "SYSRQ")) {
            if (!isSingleCharacter(argument)) {
                try warn(&result, line_number, command, "expected one character");
                valid = false;
            }
        } else if (equal(command, "MEDIA")) {
            if (!isMediaKey(argument)) {
                try warn(&result, line_number, command, if (argument.len == 0) "missing media key" else "unknown media key");
                valid = false;
            }
        } else if (equal(command, "GLOBE") or isAny(command, &.{ "HOLD", "RELEASE" })) {
            if (!isKey(argument)) {
                try warn(&result, line_number, command, "missing or unknown key");
                valid = false;
            }
        } else if (equal(command, "WAIT_FOR_BUTTON_PRESS")) {
            stats.blocking_waits += 1;
            if (argument.len != 0) {
                try warn(&result, line_number, command, "unexpected parameter");
                valid = false;
            }
        } else if (isMouseClick(command) or isSpecialKey(command) or isSingleCharacter(line)) {
            if (argument.len != 0) {
                try warn(&result, line_number, command, "unexpected parameter");
                valid = false;
            }
        } else if (isAny(command, &.{ "MOUSEMOVE", "MOUSE_MOVE" })) {
            valid = try validateSignedArguments(&result, line_number, command, argument, 2);
        } else if (isAny(command, &.{ "MOUSESCROLL", "MOUSE_SCROLL" })) {
            valid = try validateSignedArguments(&result, line_number, command, argument, 1);
        } else switch (modifierComboStatus(line)) {
            .valid => {},
            .missing_key => {
                try warn(&result, line_number, command, "modifier combination is missing a key");
                valid = false;
            },
            .invalid_key => {
                try warn(&result, line_number, command, "invalid modifier combination");
                valid = false;
            },
            .not_combo => {
                try warn(&result, line_number, command, "unknown command");
                valid = false;
            },
        }

        if (!valid) continue;
        stats.explicit_delay_ms = stats.explicit_delay_ms +| explicit_delay;
        stats.default_delay_ms = stats.default_delay_ms +| default_delay;
        if (remember) {
            stats.previous_explicit_ms = explicit_delay;
            stats.previous_default_ms = default_delay;
            stats.has_previous = true;
        }
    }

    const estimated_delay = stats.explicit_delay_ms +| stats.default_delay_ms;
    const summary = try std.fmt.allocPrint(
        allocator,
        "BadUSB script: {d} lines, {d} commands, at least {d} ms delay, {d} blocking wait{s}, {d} finding{s}",
        .{
            stats.lines,
            stats.commands,
            estimated_delay,
            stats.blocking_waits,
            if (stats.blocking_waits == 1) "" else "s",
            result.findings.items.len,
            if (result.findings.items.len == 1) "" else "s",
        },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);

    try result.addNumberField("lines", stats.lines);
    try result.addNumberField("commands", stats.commands);
    try result.addNumberField("explicit_delay_ms", stats.explicit_delay_ms);
    try result.addNumberField("default_delay_ms", stats.default_delay_ms);
    try result.addNumberField("estimated_delay_ms", estimated_delay);
    try result.addNumberField("blocking_waits", stats.blocking_waits);
    return result;
}

fn parseUnsigned(text: []const u8) ?u64 {
    if (text.len == 0) return null;
    return std.fmt.parseInt(u64, text, 10) catch null;
}

fn validateSignedArguments(
    result: *protocol.AnalysisResult,
    line: usize,
    command: []const u8,
    argument: []const u8,
    expected: usize,
) !bool {
    var tokens = std.mem.tokenizeAny(u8, argument, " \t");
    var count: usize = 0;
    while (tokens.next()) |token| {
        count += 1;
        if (count > expected or (std.fmt.parseInt(i32, token, 10) catch null) == null) {
            try warn(result, line, command, "invalid integer arguments");
            return false;
        }
    }
    if (count != expected) {
        try warn(result, line, command, "missing integer arguments");
        return false;
    }
    return true;
}

fn validUsbId(argument: []const u8) bool {
    var tokens = std.mem.tokenizeAny(u8, argument, " \t");
    const id = tokens.next() orelse return false;
    if (id.len != 9 or id[4] != ':') return false;
    for (id[0..4]) |byte| if (!std.ascii.isHex(byte)) return false;
    for (id[5..9]) |byte| if (!std.ascii.isHex(byte)) return false;
    return true;
}

fn modifierComboStatus(line: []const u8) ComboStatus {
    var tokens = std.mem.tokenizeAny(u8, line, " \t-");
    const first = tokens.next() orelse return .not_combo;
    if (!isModifier(first)) return .not_combo;

    var found_key = false;
    while (tokens.next()) |token| {
        if (!found_key and isModifier(token)) continue;
        if (found_key or !isKey(token)) return .invalid_key;
        found_key = true;
    }
    return if (found_key) .valid else .missing_key;
}

fn isModifier(value: []const u8) bool {
    return isAny(value, &.{ "CTRL", "CONTROL", "SHIFT", "ALT", "GUI", "WINDOWS" });
}

fn isKey(value: []const u8) bool {
    return isSingleCharacter(value) or isSpecialKey(value) or isMouseClick(value);
}

fn isSingleCharacter(value: []const u8) bool {
    return value.len != 0 and utf8Length(value) == 1;
}

fn utf8Length(value: []const u8) usize {
    return std.unicode.utf8CountCodepoints(value) catch value.len;
}

fn isSpecialKey(value: []const u8) bool {
    if (value.len >= 2 and (value[0] == 'F' or value[0] == 'f')) {
        const number = std.fmt.parseInt(u8, value[1..], 10) catch 0;
        if (number >= 1 and number <= 12) return true;
    }
    return isAny(value, &.{
        "DOWNARROW", "DOWN",     "LEFTARROW", "LEFT",    "RIGHTARROW", "RIGHT",       "UPARROW", "UP",
        "ENTER",     "DELETE",   "BACKSPACE", "END",     "HOME",       "ESCAPE",      "ESC",     "INSERT",
        "PAGEUP",    "PAGEDOWN", "CAPSLOCK",  "NUMLOCK", "SCROLLLOCK", "PRINTSCREEN", "BREAK",   "PAUSE",
        "SPACE",     "TAB",      "MENU",      "APP",
    });
}

fn isMouseClick(value: []const u8) bool {
    return isAny(value, &.{ "LEFTCLICK", "LEFT_CLICK", "RIGHTCLICK", "RIGHT_CLICK" });
}

fn isMediaKey(value: []const u8) bool {
    return isAny(value, &.{
        "POWER",     "REBOOT",      "SLEEP", "LOGOFF",     "EXIT",        "HOME",       "BACK", "FORWARD", "REFRESH",
        "SNAPSHOT",  "PLAY",        "PAUSE", "PLAY_PAUSE", "NEXT_TRACK",  "PREV_TRACK", "STOP", "EJECT",   "MUTE",
        "VOLUME_UP", "VOLUME_DOWN", "FN",    "BRIGHT_UP",  "BRIGHT_DOWN",
    });
}

fn isAny(value: []const u8, choices: []const []const u8) bool {
    for (choices) |choice| if (equal(value, choice)) return true;
    return false;
}

fn equal(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(left, right);
}

fn countLines(data: []const u8) usize {
    if (data.len == 0) return 0;
    var count: usize = 0;
    for (data) |byte| {
        if (byte == '\n') count += 1;
    }
    if (data[data.len - 1] != '\n') count += 1;
    return count;
}

fn warn(result: *protocol.AnalysisResult, line: usize, command: []const u8, reason: []const u8) !void {
    const message = try std.fmt.allocPrint(result.allocator, "Line {d}: {s}: {s}", .{ line, command, reason });
    defer result.allocator.free(message);
    try result.addFinding(.warning, message);
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

test "badusb reviews a valid indented CRLF script" {
    const text = "\tREM audit\r\n  ID 1209:0001 PocketRoot:Audit\r\nDEFAULT_DELAY 100\r\nSTRING hello\r\nCTRL-ALT DELETE\r\nLEFTCLICK\r\n";
    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqualStrings("6", fieldValue(&result, "lines").?);
    try std.testing.expectEqualStrings("5", fieldValue(&result, "commands").?);
    try std.testing.expectEqualStrings("300", fieldValue(&result, "estimated_delay_ms").?);
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
}

test "badusb warns without rejecting unknown commands or late ID" {
    var result = try analyzeText(std.testing.allocator, "NOPE value\nID 1209:0001\n");
    defer result.deinit();

    try std.testing.expectEqualStrings("2", fieldValue(&result, "commands").?);
    try std.testing.expectEqual(@as(usize, 2), result.findings.items.len);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "2 findings") != null);
}

test "badusb estimates explicit default and string delays" {
    const text =
        \\DEFAULT_DELAY 100
        \\DELAY 250
        \\STRING_DELAY 10
        \\STRING ab
        \\DEFAULT_STRING_DELAY 5
        \\STRINGLN x
    ;
    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqualStrings("270", fieldValue(&result, "explicit_delay_ms").?);
    try std.testing.expectEqualStrings("510", fieldValue(&result, "default_delay_ms").?);
    try std.testing.expectEqualStrings("780", fieldValue(&result, "estimated_delay_ms").?);
}
