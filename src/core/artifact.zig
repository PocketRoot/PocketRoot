const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ArtifactSource = enum {
    imported,
    captured,
    generated,
};

pub const Artifact = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    media_type: []u8,
    source: ArtifactSource,
    size: usize,
    digest: [Sha256.digest_length]u8,
    created_at_unix: ?i64,

    pub fn fromBytes(
        allocator: std.mem.Allocator,
        path: []const u8,
        media_type: []const u8,
        source: ArtifactSource,
        bytes: []const u8,
        created_at_unix: ?i64,
    ) !Artifact {
        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        if (std.fs.path.sep != '/') {
            for (owned_path) |*byte| {
                if (byte.* == std.fs.path.sep) byte.* = '/';
            }
        }

        const owned_media_type = try allocator.dupe(u8, media_type);
        errdefer allocator.free(owned_media_type);

        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});

        return .{
            .allocator = allocator,
            .path = owned_path,
            .media_type = owned_media_type,
            .source = source,
            .size = bytes.len,
            .digest = digest,
            .created_at_unix = created_at_unix,
        };
    }

    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.path);
        self.allocator.free(self.media_type);
        self.* = undefined;
    }

    pub fn digestHex(self: Artifact) [Sha256.digest_length * 2]u8 {
        return std.fmt.bytesToHex(self.digest, .lower);
    }
};

test "artifact owns metadata and hashes bytes" {
    var artifact = try Artifact.fromBytes(
        std.testing.allocator,
        "captures/example.bin",
        "application/octet-stream",
        .captured,
        "abc",
        1_700_000_000,
    );
    defer artifact.deinit();

    const digest_hex = artifact.digestHex();
    try std.testing.expectEqualStrings("captures/example.bin", artifact.path);
    try std.testing.expectEqualStrings("application/octet-stream", artifact.media_type);
    try std.testing.expectEqual(ArtifactSource.captured, artifact.source);
    try std.testing.expectEqual(@as(usize, 3), artifact.size);
    try std.testing.expectEqual(@as(?i64, 1_700_000_000), artifact.created_at_unix);
    try std.testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        &digest_hex,
    );
}

test "artifact normalizes native path separators" {
    var artifact = try Artifact.fromBytes(
        std.testing.allocator,
        "captures\\example.bin",
        "application/octet-stream",
        .imported,
        "data",
        null,
    );
    defer artifact.deinit();

    if (std.fs.path.sep == '\\') {
        try std.testing.expectEqualStrings("captures/example.bin", artifact.path);
    } else {
        try std.testing.expectEqualStrings("captures\\example.bin", artifact.path);
    }
}
