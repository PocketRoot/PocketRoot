const std = @import("std");

pub const StorageService = struct {
    io: std.Io,
    // ponytail: whole-file analysis is capped at 64 MiB; stream captures when field files outgrow it.
    max_read_size: usize = 64 * 1024 * 1024,

    pub fn init(io: std.Io) StorageService {
        return .{ .io = io };
    }

    pub fn saveBytes(self: *StorageService, path: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(path)) |directory| {
            try std.Io.Dir.cwd().createDirPath(self.io, directory);
        }
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = data });
    }

    pub fn loadBytes(self: *StorageService, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(self.io, path, allocator, .limited(self.max_read_size));
    }

    pub fn saveText(self: *StorageService, path: []const u8, data: []const u8) !void {
        return self.saveBytes(path, data);
    }

    pub fn loadText(self: *StorageService, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        return self.loadBytes(allocator, path);
    }

    pub fn samplePath(
        self: *StorageService,
        allocator: std.mem.Allocator,
        namespace: []const u8,
        name: []const u8,
        extension: []const u8,
    ) ![]u8 {
        _ = self;
        var path: std.ArrayList(u8) = .empty;
        errdefer path.deinit(allocator);

        try path.appendSlice(allocator, "samples/");
        try appendSlug(&path, allocator, namespace);
        try path.append(allocator, '/');
        try appendSlug(&path, allocator, name);
        try path.append(allocator, '.');

        const normalized_extension = if (std.mem.startsWith(u8, extension, ".")) extension[1..] else extension;
        try appendSlug(&path, allocator, normalized_extension);

        return path.toOwnedSlice(allocator);
    }
};

fn appendSlug(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    var wrote_separator = false;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) {
            try list.append(allocator, std.ascii.toLower(byte));
            wrote_separator = false;
        } else if (byte == '-' or byte == '_' or byte == ' ' or byte == '.') {
            if (list.items.len > 0 and !wrote_separator) {
                try list.append(allocator, '-');
                wrote_separator = true;
            }
        }
    }

    while (list.items.len > 0 and list.items[list.items.len - 1] == '-') {
        _ = list.pop();
    }
}

test "storage saves and loads bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fmt.allocPrint(
        std.testing.allocator,
        ".zig-cache/tmp/{s}/sample.bin",
        .{tmp.sub_path},
    );
    defer std.testing.allocator.free(path);

    var storage = StorageService.init(std.testing.io);
    const data = [_]u8{ 0x00, 0xff, 0x42 };
    try storage.saveBytes(path, &data);
    const loaded = try storage.loadBytes(std.testing.allocator, path);
    defer std.testing.allocator.free(loaded);

    try std.testing.expectEqualSlices(u8, &data, loaded);
}

test "storage saves and loads text" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = "sample.txt";
    const data = "PocketRoot";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = data });
    const loaded = try tmp.dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(loaded);

    try std.testing.expectEqualStrings(data, loaded);
}

test "storage builds normalized sample paths" {
    var storage = StorageService.init(std.testing.io);
    const path = try storage.samplePath(std.testing.allocator, "Infrared", "Demo Power", ".ir");
    defer std.testing.allocator.free(path);

    try std.testing.expectEqualStrings("samples/infrared/demo-power.ir", path);
}
