const std = @import("std");

pub const schema = "pocketroot.library.v1";
pub const max_entries = 4096;
pub const max_id_bytes = 128;
pub const max_protocol_bytes = 64;
pub const max_path_bytes = 1024;
pub const max_library_bytes = 8 * 1024 * 1024;

pub const Entry = struct {
    allocator: std.mem.Allocator,
    id: []u8,
    protocol_id: []u8,
    path: []u8,
    favorite: bool,
    created_at_unix: i64,
    last_used_unix: ?i64,

    fn init(
        allocator: std.mem.Allocator,
        id: []const u8,
        protocol_id: []const u8,
        path: []const u8,
        favorite: bool,
        created_at_unix: i64,
        last_used_unix: ?i64,
    ) !Entry {
        try validateText(id, max_id_bytes, error.InvalidLibraryId);
        try validateText(protocol_id, max_protocol_bytes, error.InvalidLibraryProtocol);
        try validatePath(path);
        const owned_id = try allocator.dupe(u8, id);
        errdefer allocator.free(owned_id);
        const owned_protocol = try allocator.dupe(u8, protocol_id);
        errdefer allocator.free(owned_protocol);
        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        for (owned_path) |*byte| if (byte.* == '\\') {
            byte.* = '/';
        };
        return .{
            .allocator = allocator,
            .id = owned_id,
            .protocol_id = owned_protocol,
            .path = owned_path,
            .favorite = favorite,
            .created_at_unix = created_at_unix,
            .last_used_unix = last_used_unix,
        };
    }

    fn deinit(self: *Entry) void {
        self.allocator.free(self.id);
        self.allocator.free(self.protocol_id);
        self.allocator.free(self.path);
        self.* = undefined;
    }
};

const WireEntry = struct {
    id: []const u8,
    protocol_id: []const u8,
    path: []const u8,
    favorite: bool = false,
    created_at_unix: i64,
    last_used_unix: ?i64 = null,
};

const WireLibrary = struct {
    schema: []const u8,
    entries: []const WireEntry,
};

pub const Library = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(allocator: std.mem.Allocator) Library {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Library) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
    }

    pub fn add(
        self: *Library,
        id: []const u8,
        protocol_id: []const u8,
        path: []const u8,
        created_at_unix: i64,
    ) !void {
        if (self.entries.items.len >= max_entries) return error.LibraryFull;
        if (self.find(id) != null) return error.DuplicateLibraryId;
        for (self.entries.items) |entry| if (pathEqual(entry.path, path)) return error.DuplicateLibraryPath;
        var entry = try Entry.init(self.allocator, id, protocol_id, path, false, created_at_unix, null);
        errdefer entry.deinit();
        try self.entries.append(self.allocator, entry);
    }

    pub fn find(self: *Library, id: []const u8) ?*Entry {
        for (self.entries.items) |*entry| if (std.mem.eql(u8, entry.id, id)) return entry;
        return null;
    }

    pub fn setFavorite(self: *Library, id: []const u8, favorite: bool) !void {
        const entry = self.find(id) orelse return error.UnknownLibraryEntry;
        entry.favorite = favorite;
    }

    pub fn markUsed(self: *Library, id: []const u8, timestamp: i64) !void {
        const entry = self.find(id) orelse return error.UnknownLibraryEntry;
        entry.last_used_unix = timestamp;
    }

    pub fn serialize(self: *const Library, allocator: std.mem.Allocator) ![]u8 {
        var output = std.Io.Writer.Allocating.init(allocator);
        defer output.deinit();
        var json: std.json.Stringify = .{
            .writer = &output.writer,
            .options = .{ .whitespace = .indent_2 },
        };
        try json.beginObject();
        try json.objectField("schema");
        try json.write(schema);
        try json.objectField("entries");
        try json.beginArray();
        for (self.entries.items) |entry| {
            try json.beginObject();
            try json.objectField("id");
            try json.write(entry.id);
            try json.objectField("protocol_id");
            try json.write(entry.protocol_id);
            try json.objectField("path");
            try json.write(entry.path);
            try json.objectField("favorite");
            try json.write(entry.favorite);
            try json.objectField("created_at_unix");
            try json.write(entry.created_at_unix);
            try json.objectField("last_used_unix");
            try json.write(entry.last_used_unix);
            try json.endObject();
        }
        try json.endArray();
        try json.endObject();
        return output.toOwnedSlice();
    }

    pub fn load(allocator: std.mem.Allocator, data: []const u8) !Library {
        if (data.len > max_library_bytes) return error.LibraryTooLarge;
        var parsed = try std.json.parseFromSlice(WireLibrary, allocator, data, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = false,
            .max_value_len = max_path_bytes,
        });
        defer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.schema, schema)) return error.UnsupportedLibrarySchema;

        var library = Library.init(allocator);
        errdefer library.deinit();
        if (parsed.value.entries.len > max_entries) return error.LibraryFull;
        for (parsed.value.entries) |wire| {
            try library.add(wire.id, wire.protocol_id, wire.path, wire.created_at_unix);
            const entry = library.find(wire.id).?;
            entry.favorite = wire.favorite;
            entry.last_used_unix = wire.last_used_unix;
        }
        return library;
    }
};

fn validateText(value: []const u8, max_len: usize, invalid: anyerror) !void {
    if (value.len == 0 or value.len > max_len or !std.unicode.utf8ValidateSlice(value)) return invalid;
    for (value) |byte| if (std.ascii.isControl(byte)) return invalid;
}

fn validatePath(path: []const u8) !void {
    try validateText(path, max_path_bytes, error.InvalidLibraryPath);
    if (std.fs.path.isAbsolute(path)) return error.InvalidLibraryPath;
    var segments = std.mem.tokenizeAny(u8, path, "/\\");
    while (segments.next()) |segment| if (std.mem.eql(u8, segment, "..")) return error.InvalidLibraryPath;
}

fn pathEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_byte, right_byte| {
        const normalized_left = if (left_byte == '\\') '/' else left_byte;
        const normalized_right = if (right_byte == '\\') '/' else right_byte;
        if (normalized_left != normalized_right) return false;
    }
    return true;
}

test "library persists favorites and history" {
    var library = Library.init(std.testing.allocator);
    defer library.deinit();
    try library.add("living-room-power", "infrared", "signals/living-room/power.ir", 100);
    try library.setFavorite("living-room-power", true);
    try library.markUsed("living-room-power", 200);

    const data = try library.serialize(std.testing.allocator);
    defer std.testing.allocator.free(data);
    var restored = try Library.load(std.testing.allocator, data);
    defer restored.deinit();
    const entry = restored.find("living-room-power").?;
    try std.testing.expect(entry.favorite);
    try std.testing.expectEqual(@as(?i64, 200), entry.last_used_unix);
    try std.testing.expectEqualStrings("signals/living-room/power.ir", entry.path);
}

test "library rejects traversal and duplicate normalized paths" {
    var library = Library.init(std.testing.allocator);
    defer library.deinit();
    try std.testing.expectError(
        error.InvalidLibraryPath,
        library.add("bad", "nfc", "../secrets/card.nfc", 0),
    );
    try library.add("one", "nfc", "cards\\demo.nfc", 0);
    try std.testing.expectError(
        error.DuplicateLibraryPath,
        library.add("two", "nfc", "cards/demo.nfc", 0),
    );
}
