const std = @import("std");
const builtin = @import("builtin");

pub fn executablePath(allocator: std.mem.Allocator, relative_path: []const u8) ![]u8 {
    if (builtin.os.tag != .windows) return error.UnsupportedPlatform;
    if (relative_path.len == 0 or std.fs.path.isAbsolute(relative_path) or
        std.mem.indexOfScalar(u8, relative_path, 0) != null)
    {
        return error.InvalidSystemExecutable;
    }
    var components = std.mem.splitAny(u8, relative_path, "/\\");
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or std.mem.indexOfScalar(u8, component, ':') != null)
        {
            return error.InvalidSystemExecutable;
        }
    }

    const system_directory_w = std.os.windows.getSystemDirectoryWtf16Le();
    const system_directory = try std.unicode.wtf16LeToWtf8Alloc(allocator, system_directory_w);
    defer allocator.free(system_directory);
    if (!std.fs.path.isAbsolute(system_directory)) return error.InvalidSystemDirectory;

    const path = try std.fs.path.join(allocator, &.{ system_directory, relative_path });
    errdefer allocator.free(path);
    if (!std.fs.path.isAbsolute(path)) return error.InvalidSystemExecutable;
    return path;
}

test "trusted Windows executables resolve below the native system directory" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const path = try executablePath(std.testing.allocator, "pktmon.exe");
    defer std.testing.allocator.free(path);
    try std.testing.expect(std.fs.path.isAbsolute(path));
    try std.testing.expect(std.ascii.endsWithIgnoreCase(path, "\\System32\\pktmon.exe"));
    try std.testing.expectError(
        error.InvalidSystemExecutable,
        executablePath(std.testing.allocator, "C:\\untrusted.exe"),
    );
}
