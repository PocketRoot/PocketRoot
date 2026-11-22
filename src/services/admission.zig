//! Repository admission checks. These are generic policy checks; the allowlist is data.

const std = @import("std");

const Legacy = struct {
    records: []const []const u8 = &.{},
};

fn isAllowed(legacy: *const Legacy, name: []const u8) bool {
    for (legacy.records) |record| {
        if (std.mem.eql(u8, record, name)) return true;
    }
    return false;
}

test "admission: legacy JSON records are allowlisted and have a DSL script" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const data = try std.Io.Dir.cwd().readFileAlloc(io, "samples/exploits/legacy.json", allocator, .limited(64 * 1024));
    defer allocator.free(data);
    const legacy = try std.json.parseFromSliceLeaky(Legacy, allocator, data, .{ .ignore_unknown_fields = true });
    defer allocator.free(legacy.records);

    var dir = try std.Io.Dir.cwd().openDir(io, "samples/exploits", .{ .iterate = true });
    defer dir.close(io);
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const record = try std.fmt.allocPrint(allocator, "{s}/record.json", .{entry.name});
        defer allocator.free(record);
        const has_record = blk: {
            dir.access(io, record, .{}) catch break :blk false;
            break :blk true;
        };
        if (!has_record) continue;
        if (!isAllowed(&legacy, entry.name)) {
            std.debug.print("unapproved JSON exploit record: {s}\n", .{entry.name});
            return error.UnapprovedLegacyRecord;
        }
        const pk = try std.fmt.allocPrint(allocator, "{s}/exploit.pk", .{entry.name});
        defer allocator.free(pk);
        dir.access(io, pk, .{}) catch {
            std.debug.print("legacy record has no DSL port: {s}\n", .{entry.name});
            return error.LegacyRecordWithoutDsl;
        };
    }
}
