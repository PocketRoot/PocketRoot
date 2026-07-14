const std = @import("std");

pub const Entry = struct {
    key: []const u8,
    value: []const u8,
    line: usize,
};

pub const Document = struct {
    allocator: std.mem.Allocator,
    source: []u8,
    entries: std.ArrayList(Entry),

    pub fn deinit(self: *Document) void {
        self.entries.deinit(self.allocator);
        self.allocator.free(self.source);
    }

    pub fn first(self: *const Document, key: []const u8) ?[]const u8 {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.key, key)) return entry.value;
        }
        return null;
    }

    pub fn require(self: *const Document, key: []const u8) ![]const u8 {
        return self.first(key) orelse error.MissingField;
    }

    pub fn count(self: *const Document, key: []const u8) usize {
        var total: usize = 0;
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.key, key)) total += 1;
        }
        return total;
    }

    pub fn parseUnsigned(self: *const Document, comptime T: type, key: []const u8) !T {
        const value = try self.require(key);
        if (std.mem.startsWith(u8, value, "0x") or std.mem.startsWith(u8, value, "0X")) {
            return std.fmt.parseInt(T, value[2..], 16);
        }
        return std.fmt.parseInt(T, value, 10);
    }

    pub fn parseHexBytes(
        self: *const Document,
        allocator: std.mem.Allocator,
        key: []const u8,
    ) ![]u8 {
        const value = try self.require(key);
        var bytes: std.ArrayList(u8) = .empty;
        errdefer bytes.deinit(allocator);

        var tokens = std.mem.tokenizeAny(u8, value, " \t");
        while (tokens.next()) |token| {
            if (token.len != 2) return error.InvalidHexBytes;
            try bytes.append(
                allocator,
                std.fmt.parseInt(u8, token, 16) catch return error.InvalidHexBytes,
            );
        }
        if (bytes.items.len == 0) return error.InvalidHexBytes;
        return bytes.toOwnedSlice(allocator);
    }
};

pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Document {
    const source = try allocator.dupe(u8, data);
    errdefer allocator.free(source);

    var entries: std.ArrayList(Entry) = .empty;
    errdefer entries.deinit(allocator);

    var line_number: usize = 0;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line_raw| {
        line_number += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const separator = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidLine;
        const key = std.mem.trim(u8, line[0..separator], " \t");
        if (key.len == 0) return error.EmptyKey;

        try entries.append(allocator, .{
            .key = key,
            .value = std.mem.trim(u8, line[separator + 1 ..], " \t"),
            .line = line_number,
        });
    }

    return .{
        .allocator = allocator,
        .source = source,
        .entries = entries,
    };
}

test "parses repeated fields and CRLF" {
    var document = try parse(
        std.testing.allocator,
        "# comment\r\nFiletype: IR signals file\r\n\r\nname: first\r\nname: second\r\n",
    );
    defer document.deinit();

    try std.testing.expectEqual(@as(usize, 3), document.entries.items.len);
    try std.testing.expectEqualStrings("first", document.first("name").?);
    try std.testing.expectEqual(@as(usize, 2), document.count("name"));
    try std.testing.expectEqual(@as(usize, 4), document.entries.items[1].line);
}

test "parses decimal and hexadecimal unsigned values" {
    var document = try parse(std.testing.allocator, "Version: 12\naddress: 0x20DF\ncommand: 0X10\n");
    defer document.deinit();

    try std.testing.expectEqual(@as(u8, 12), try document.parseUnsigned(u8, "Version"));
    try std.testing.expectEqual(@as(u16, 0x20DF), try document.parseUnsigned(u16, "address"));
    try std.testing.expectEqual(@as(u8, 0x10), try document.parseUnsigned(u8, "command"));
}

test "parses space separated hexadecimal bytes" {
    var document = try parse(std.testing.allocator, "Data: 01 AB ff\n");
    defer document.deinit();

    const bytes = try document.parseHexBytes(std.testing.allocator, "Data");
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0xab, 0xff }, bytes);
}

test "rejects malformed lines and empty keys" {
    try std.testing.expectError(error.InvalidLine, parse(std.testing.allocator, "not a field\n"));
    try std.testing.expectError(error.EmptyKey, parse(std.testing.allocator, ": value\n"));
}
