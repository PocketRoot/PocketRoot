const std = @import("std");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "npm-lock",
    .name = "npm package-lock.json",
    .category = "Software",
    .file_extension = "package-lock.json",
    .media_type = "application/json",
    .auto_detect = false,
    .analyze = analyzeText,
    .sample = sampleText,
};

const max_packages = 4096;

/// Reads package-lock.json v2/v3 ("packages" keyed by install path) and v1
/// ("dependencies" keyed by name). Only entries that declare a version are emitted.
pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSbom,
    };
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidSbom,
    };

    var result = try protocol.AnalysisResult.init(allocator, "npm lockfile");
    errdefer result.deinit();

    const lockfile_version = if (root.get("lockfileVersion")) |value| switch (value) {
        .integer => |number| number,
        else => 0,
    } else 0;
    try result.addNumberField("lockfile_version", @as(u64, @intCast(@max(lockfile_version, 0))));
    if (root.get("name")) |value| switch (value) {
        .string => |text| try result.addField("package_name", text),
        else => {},
    };

    var emitted: usize = 0;
    if (root.get("packages")) |packages_value| {
        if (packages_value == .object) {
            var iterator = packages_value.object.iterator();
            while (iterator.next()) |entry| {
                const path = entry.key_ptr.*;
                const spec = switch (entry.value_ptr.*) {
                    .object => |object| object,
                    else => continue,
                };
                const name = packageNameFromPath(path) orelse continue;
                const version = switch (spec.get("version") orelse continue) {
                    .string => |text| text,
                    else => continue,
                };
                if (version.len == 0) continue;
                if (emitted >= max_packages) return error.TooManyComponents;
                try emit(allocator, &result, name, version);
                emitted += 1;
            }
        }
    } else if (root.get("dependencies")) |dependencies| {
        if (dependencies == .object) {
            var iterator = dependencies.object.iterator();
            while (iterator.next()) |entry| {
                const spec = switch (entry.value_ptr.*) {
                    .object => |object| object,
                    else => continue,
                };
                const version = switch (spec.get("version") orelse continue) {
                    .string => |text| text,
                    else => continue,
                };
                if (version.len == 0) continue;
                if (emitted >= max_packages) return error.TooManyComponents;
                try emit(allocator, &result, entry.key_ptr.*, version);
                emitted += 1;
            }
        }
    } else {
        return error.InvalidSbom;
    }

    try result.addNumberField("packages_emitted", emitted);
    const summary = try std.fmt.allocPrint(allocator, "npm lockfile: {d} packages", .{emitted});
    defer allocator.free(summary);
    try result.setSummary(summary);
    return result;
}

fn emit(allocator: std.mem.Allocator, result: *protocol.AnalysisResult, name: []const u8, version: []const u8) !void {
    var identity_buffer: [320]u8 = undefined;
    const identity = try std.fmt.bufPrint(&identity_buffer, "pkg:npm/{s}@{s}", .{ name, version });
    _ = try result.addNetworkObservation(.{
        .kind = .package,
        .confidence = .confirmed,
        .hostname = identity,
        .product = name,
        .version = version,
        .evidence = "npm:package-lock",
        .source_id = "npm-lock:package",
    });
    _ = allocator;
}

/// "node_modules/@scope/name" -> "@scope/name"; "node_modules/a/node_modules/b" -> "b".
fn packageNameFromPath(path: []const u8) ?[]const u8 {
    if (path.len == 0) return null;
    const marker = "node_modules/";
    const index = std.mem.lastIndexOf(u8, path, marker) orelse return null;
    const name = path[index + marker.len ..];
    if (name.len == 0) return null;
    return name;
}

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\{
        \\  "name": "sample",
        \\  "lockfileVersion": 3,
        \\  "packages": {
        \\    "": { "name": "sample" },
        \\    "node_modules/lodash": { "version": "4.17.21" },
        \\    "node_modules/express": { "version": "4.18.2" }
        \\  }
        \\}
        \\
    );
}

test "npm lockfile v3 emits one observation per package" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);
    var result = try analyzeText(std.testing.allocator, sample);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), result.observations.items.len);
    try std.testing.expectEqualStrings("lodash", result.observations.items[0].product);
    try std.testing.expectEqualStrings("4.17.21", result.observations.items[0].version);
}

test "npm lockfile v1 dependencies are read" {
    const text = "{\"lockfileVersion\":1,\"dependencies\":{\"left-pad\":{\"version\":\"1.3.0\"}}}";
    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.observations.items.len);
    try std.testing.expectEqualStrings("left-pad", result.observations.items[0].product);
}

test "npm lockfile requires a package map" {
    try std.testing.expectError(error.InvalidSbom, analyzeText(std.testing.allocator, "{\"name\":\"x\"}"));
}
