const std = @import("std");
const protocol_registry = @import("../protocols/registry.zig");

pub const default_max_entries = 512;

pub const ArchiveEntry = struct {
    path: []u8,
    extension: []u8,
    protocol_id: ?[]const u8,
    protocol_name: ?[]const u8,

    pub fn deinit(self: *ArchiveEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.extension);
    }
};

pub const ArchiveListing = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(ArchiveEntry),

    pub fn init(allocator: std.mem.Allocator) ArchiveListing {
        return .{
            .allocator = allocator,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *ArchiveListing) void {
        for (self.entries.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
    }

    pub fn count(self: *const ArchiveListing) usize {
        return self.entries.items.len;
    }
};

pub const ArchiveService = struct {
    io: std.Io,
    max_entries: usize = default_max_entries,

    pub fn init(io: std.Io) ArchiveService {
        return .{ .io = io };
    }

    pub fn list(
        self: *ArchiveService,
        allocator: std.mem.Allocator,
        registry: *const protocol_registry.ProtocolRegistry,
        root_path: []const u8,
    ) !ArchiveListing {
        var listing = ArchiveListing.init(allocator);
        errdefer listing.deinit();

        var root_dir = std.Io.Dir.cwd().openDir(self.io, root_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return listing,
            else => return err,
        };
        defer root_dir.close(self.io);

        var walker = try root_dir.walk(allocator);
        defer walker.deinit();

        while (try walker.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (listing.entries.items.len == self.max_entries) return error.TooManyArchiveEntries;

            const full_path = try joinArchivePath(allocator, root_path, entry.path);
            errdefer allocator.free(full_path);

            const extension = try extensionFromPath(allocator, full_path);
            errdefer allocator.free(extension);

            const descriptor = registry.findByExtension(extension);
            try listing.entries.append(allocator, .{
                .path = full_path,
                .extension = extension,
                .protocol_id = if (descriptor) |item| item.id else null,
                .protocol_name = if (descriptor) |item| item.name else null,
            });
        }

        return listing;
    }
};

fn joinArchivePath(allocator: std.mem.Allocator, root_path: []const u8, child_path: []const u8) ![]u8 {
    var path: std.ArrayList(u8) = .empty;
    errdefer path.deinit(allocator);

    try appendNormalizedPath(&path, allocator, root_path);
    if (path.items.len > 0 and path.items[path.items.len - 1] != '/') {
        try path.append(allocator, '/');
    }
    try appendNormalizedPath(&path, allocator, child_path);

    return path.toOwnedSlice(allocator);
}

fn appendNormalizedPath(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    for (value) |byte| {
        try list.append(allocator, if (byte == std.fs.path.sep) '/' else byte);
    }
}

fn extensionFromPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const basename = std.fs.path.basename(path);
    const index = std.mem.lastIndexOfScalar(u8, basename, '.') orelse {
        return allocator.dupe(u8, "");
    };
    return allocator.dupe(u8, basename[index + 1 ..]);
}

test "archive lists protocol files" {
    var archive = ArchiveService.init(std.testing.io);
    const registry = protocol_registry.ProtocolRegistry.init(protocol_registry.builtinProtocols());

    const root = ".zig-cache/archive-test";
    const path = ".zig-cache/archive-test/infrared/demo.ir";
    try std.Io.Dir.cwd().createDirPath(std.testing.io, ".zig-cache/archive-test/infrared");
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
    defer std.Io.Dir.cwd().deleteDir(std.testing.io, ".zig-cache/archive-test/infrared") catch {};
    defer std.Io.Dir.cwd().deleteDir(std.testing.io, root) catch {};

    try std.Io.Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = "Filetype: IR signals file\nVersion: 1\nname: demo\nprotocol: NEC\naddress: 0x1\ncommand: 0x2\n",
    });

    var listing = try archive.list(std.testing.allocator, &registry, root);
    defer listing.deinit();

    try std.testing.expectEqual(@as(usize, 1), listing.count());
    try std.testing.expectEqualStrings("infrared", listing.entries.items[0].protocol_id.?);
}

test "archive entry count is bounded" {
    var archive = ArchiveService.init(std.testing.io);
    archive.max_entries = 1;
    const registry = protocol_registry.ProtocolRegistry.init(protocol_registry.builtinProtocols());

    const root = ".zig-cache/archive-limit-test";
    try std.Io.Dir.cwd().createDirPath(std.testing.io, root);
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, ".zig-cache/archive-limit-test/one.ir") catch {};
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, ".zig-cache/archive-limit-test/two.ir") catch {};
    defer std.Io.Dir.cwd().deleteDir(std.testing.io, root) catch {};
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = ".zig-cache/archive-limit-test/one.ir", .data = "name: one\n" });
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = ".zig-cache/archive-limit-test/two.ir", .data = "name: two\n" });

    try std.testing.expectError(
        error.TooManyArchiveEntries,
        archive.list(std.testing.allocator, &registry, root),
    );
}
