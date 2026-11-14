const std = @import("std");

pub const magic = "PKRT";
pub const version: u8 = 1;
pub const header_size = 14;
pub const checksum_size = 4;
pub const max_payload_bytes = 1024 * 1024;

pub const Kind = enum(u8) {
    request = 1,
    response = 2,
    event = 3,
    heartbeat = 4,
    cancel = 5,
};

pub const Frame = struct {
    kind: Kind,
    sequence: u32,
    payload: []const u8 = "",
};

pub fn encodedSize(payload_len: usize) !usize {
    if (payload_len > max_payload_bytes) return error.PayloadTooLarge;
    return std.math.add(usize, header_size + checksum_size, payload_len) catch error.PayloadTooLarge;
}

pub fn encode(allocator: std.mem.Allocator, frame: Frame) ![]u8 {
    if (frame.sequence == 0) return error.InvalidSequence;
    const size = try encodedSize(frame.payload.len);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);

    @memcpy(bytes[0..4], magic);
    bytes[4] = version;
    bytes[5] = @intFromEnum(frame.kind);
    std.mem.writeInt(u32, bytes[6..10], frame.sequence, .little);
    std.mem.writeInt(u32, bytes[10..14], @intCast(frame.payload.len), .little);
    @memcpy(bytes[header_size .. header_size + frame.payload.len], frame.payload);
    std.mem.writeInt(u32, bytes[size - checksum_size ..][0..checksum_size], crc32(bytes[0 .. size - checksum_size]), .little);
    return bytes;
}

pub fn decode(bytes: []const u8) !Frame {
    if (bytes.len < header_size + checksum_size) return error.TruncatedFrame;
    if (!std.mem.eql(u8, bytes[0..4], magic)) return error.InvalidMagic;
    if (bytes[4] != version) return error.UnsupportedVersion;
    const kind = std.enums.fromInt(Kind, bytes[5]) orelse return error.InvalidKind;
    const sequence = std.mem.readInt(u32, bytes[6..10], .little);
    if (sequence == 0) return error.InvalidSequence;
    const payload_len: usize = std.mem.readInt(u32, bytes[10..14], .little);
    const expected_size = try encodedSize(payload_len);
    if (bytes.len != expected_size) return error.InvalidFrameLength;

    const expected_crc = std.mem.readInt(u32, bytes[bytes.len - checksum_size ..][0..checksum_size], .little);
    if (crc32(bytes[0 .. bytes.len - checksum_size]) != expected_crc) return error.ChecksumMismatch;
    return .{
        .kind = kind,
        .sequence = sequence,
        .payload = bytes[header_size .. bytes.len - checksum_size],
    };
}

pub fn frameSize(prefix: []const u8) !?usize {
    if (prefix.len < header_size) return null;
    if (!std.mem.eql(u8, prefix[0..4], magic)) return error.InvalidMagic;
    if (prefix[4] != version) return error.UnsupportedVersion;
    const payload_len: usize = std.mem.readInt(u32, prefix[10..14], .little);
    return try encodedSize(payload_len);
}

pub const Session = struct {
    next_tx: u32 = 1,
    last_rx: u32 = 0,

    pub fn nextSequence(self: *Session) !u32 {
        if (self.next_tx == 0 or self.next_tx == std.math.maxInt(u32)) return error.SequenceExhausted;
        const result = self.next_tx;
        self.next_tx += 1;
        return result;
    }

    pub fn accept(self: *Session, frame: Frame) !void {
        if (frame.sequence <= self.last_rx) return error.ReplayedFrame;
        self.last_rx = frame.sequence;
    }
};

pub fn crc32(bytes: []const u8) u32 {
    var crc: u32 = 0xffffffff;
    for (bytes) |byte| {
        crc ^= byte;
        for (0..8) |_| crc = if ((crc & 1) != 0) (crc >> 1) ^ 0xedb88320 else crc >> 1;
    }
    return ~crc;
}

test "ipc frame round trips bounded payloads" {
    const encoded = try encode(std.testing.allocator, .{
        .kind = .request,
        .sequence = 42,
        .payload = "infrared.read",
    });
    defer std.testing.allocator.free(encoded);

    const decoded = try decode(encoded);
    try std.testing.expectEqual(Kind.request, decoded.kind);
    try std.testing.expectEqual(@as(u32, 42), decoded.sequence);
    try std.testing.expectEqualStrings("infrared.read", decoded.payload);
    try std.testing.expectEqual(encoded.len, (try frameSize(encoded[0..header_size])).?);
}

test "ipc rejects corruption and trailing bytes" {
    const encoded = try encode(std.testing.allocator, .{
        .kind = .heartbeat,
        .sequence = 1,
    });
    defer std.testing.allocator.free(encoded);
    encoded[4] = version;
    encoded[6] ^= 0x40;
    try std.testing.expectError(error.ChecksumMismatch, decode(encoded));

    const extra = try std.testing.allocator.alloc(u8, encoded.len + 1);
    defer std.testing.allocator.free(extra);
    @memcpy(extra[0..encoded.len], encoded);
    extra[extra.len - 1] = 0;
    try std.testing.expectError(error.InvalidFrameLength, decode(extra));
}

test "ipc crc matches the standard check vector" {
    try std.testing.expectEqual(@as(u32, 0xcbf43926), crc32("123456789"));
}

test "ipc sessions reject replayed frames" {
    var session = Session{};
    try std.testing.expectEqual(@as(u32, 1), try session.nextSequence());
    try std.testing.expectEqual(@as(u32, 2), try session.nextSequence());
    try session.accept(.{ .kind = .event, .sequence = 7 });
    try std.testing.expectError(error.ReplayedFrame, session.accept(.{ .kind = .event, .sequence = 7 }));
}
