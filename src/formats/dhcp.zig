const std = @import("std");

pub const max_message_len = 4096;
pub const min_message_len = 240;
pub const max_options = 64;

pub const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
    _,
};

pub const Option = struct {
    code: u8,
    value: []const u8,
};

pub const Message = struct {
    op: u8,
    hardware_type: u8,
    hardware_address_length: u8,
    hops: u8,
    transaction_id: u32,
    seconds: u16,
    flags: u16,
    client_address: [4]u8,
    your_address: [4]u8,
    server_address: [4]u8,
    relay_address: [4]u8,
    client_hardware_address: []const u8,
    server_name: []const u8,
    boot_file: []const u8,
    option_data: []const u8,
    message_type: ?MessageType = null,
    hostname: ?[]const u8 = null,
    requested_ip: ?[4]u8 = null,
    lease_time: ?u32 = null,
    server_identifier: ?[4]u8 = null,
    vendor_class: ?[]const u8 = null,
    client_identifier: ?[]const u8 = null,

    pub fn options(self: Message) OptionIterator {
        return .{ .data = self.option_data };
    }
};

pub const Error = error{
    MessageTooLarge,
    Truncated,
    InvalidMagicCookie,
    InvalidHardwareAddressLength,
    TooManyOptions,
    MissingEndOption,
    InvalidOptionLength,
};

pub const OptionIterator = struct {
    data: []const u8,
    offset: usize = 0,
    count: usize = 0,
    ended: bool = false,

    pub fn next(self: *OptionIterator) Error!?Option {
        if (self.ended) return null;

        while (self.offset < self.data.len) {
            const code = self.data[self.offset];
            self.offset += 1;
            switch (code) {
                0 => continue,
                255 => {
                    self.ended = true;
                    return null;
                },
                else => {},
            }

            if (self.count == max_options) return error.TooManyOptions;
            if (self.offset == self.data.len) return error.Truncated;
            const length: usize = self.data[self.offset];
            self.offset += 1;
            if (length > self.data.len - self.offset) return error.Truncated;

            const value = self.data[self.offset .. self.offset + length];
            self.offset += length;
            self.count += 1;
            return .{ .code = code, .value = value };
        }

        return error.MissingEndOption;
    }
};

pub fn decode(data: []const u8) Error!Message {
    if (data.len > max_message_len) return error.MessageTooLarge;
    if (data.len < min_message_len) return error.Truncated;
    if (!std.mem.eql(u8, data[236..240], "\x63\x82\x53\x63")) {
        return error.InvalidMagicCookie;
    }

    const hardware_address_length = data[2];
    if (hardware_address_length > 16) return error.InvalidHardwareAddressLength;

    var message: Message = .{
        .op = data[0],
        .hardware_type = data[1],
        .hardware_address_length = hardware_address_length,
        .hops = data[3],
        .transaction_id = readU32(data, 4),
        .seconds = readU16(data, 8),
        .flags = readU16(data, 10),
        .client_address = data[12..16].*,
        .your_address = data[16..20].*,
        .server_address = data[20..24].*,
        .relay_address = data[24..28].*,
        .client_hardware_address = data[28 .. 28 + @as(usize, hardware_address_length)],
        .server_name = nulTerminated(data[44..108]),
        .boot_file = nulTerminated(data[108..236]),
        .option_data = data[240..],
    };

    var iterator = message.options();
    while (try iterator.next()) |option| {
        switch (option.code) {
            53 => {
                try expectLength(option.value, 1);
                if (message.message_type == null) {
                    message.message_type = @enumFromInt(option.value[0]);
                }
            },
            12 => {
                if (message.hostname == null) message.hostname = option.value;
            },
            50 => {
                try expectLength(option.value, 4);
                if (message.requested_ip == null) message.requested_ip = option.value[0..4].*;
            },
            51 => {
                try expectLength(option.value, 4);
                if (message.lease_time == null) message.lease_time = readU32(option.value, 0);
            },
            54 => {
                try expectLength(option.value, 4);
                if (message.server_identifier == null) message.server_identifier = option.value[0..4].*;
            },
            60 => {
                if (message.vendor_class == null) message.vendor_class = option.value;
            },
            61 => {
                if (message.client_identifier == null) message.client_identifier = option.value;
            },
            else => {},
        }
    }

    return message;
}

fn expectLength(value: []const u8, expected: usize) Error!void {
    if (value.len != expected) return error.InvalidOptionLength;
}

fn nulTerminated(value: []const u8) []const u8 {
    return value[0 .. std.mem.indexOfScalar(u8, value, 0) orelse value.len];
}

fn readU16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .big);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .big);
}

test "decodes BOOTP fields and common DHCP options" {
    var packet = [_]u8{0} ** 320;
    packet[0] = 2;
    packet[1] = 1;
    packet[2] = 6;
    packet[3] = 1;
    packet[4..8].* = .{ 0x12, 0x34, 0x56, 0x78 };
    packet[8..12].* = .{ 0, 3, 0x80, 0 };
    packet[12..28].* = .{
        192, 0, 2, 1,
        192, 0, 2, 20,
        192, 0, 2, 2,
        192, 0, 2, 3,
    };
    packet[28..34].* = .{ 0x02, 0, 0, 0, 0, 1 };
    @memcpy(packet[44..55], "dhcp-server");
    @memcpy(packet[108..118], "pxelinux.0");
    packet[236..240].* = .{ 0x63, 0x82, 0x53, 0x63 };

    const options =
        "\x35\x01\x05" ++
        "\x0c\x06device" ++
        "\x32\x04\xc0\x00\x02\x20" ++
        "\x33\x04\x00\x00\x0e\x10" ++
        "\x36\x04\xc0\x00\x02\x02" ++
        "\x3c\x04test" ++
        "\x3d\x07\x01\x02\x00\x00\x00\x00\x01" ++
        "\xc8\x02ok" ++
        "\x00\xff";
    @memcpy(packet[240 .. 240 + options.len], options);

    const message = try decode(packet[0 .. 240 + options.len]);
    try std.testing.expectEqual(@as(u32, 0x12345678), message.transaction_id);
    try std.testing.expectEqual(@as(u16, 3), message.seconds);
    try std.testing.expectEqual(@as(u16, 0x8000), message.flags);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 20 }, &message.your_address);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0, 0, 1 }, message.client_hardware_address);
    try std.testing.expectEqualStrings("dhcp-server", message.server_name);
    try std.testing.expectEqualStrings("pxelinux.0", message.boot_file);
    try std.testing.expectEqual(MessageType.ack, message.message_type.?);
    try std.testing.expectEqualStrings("device", message.hostname.?);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 32 }, &message.requested_ip.?);
    try std.testing.expectEqual(@as(?u32, 3600), message.lease_time);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, &message.server_identifier.?);
    try std.testing.expectEqualStrings("test", message.vendor_class.?);
    try std.testing.expectEqual(@as(usize, 7), message.client_identifier.?.len);

    var iterator = message.options();
    var option_count: usize = 0;
    var saw_unknown = false;
    while (try iterator.next()) |option| {
        option_count += 1;
        if (option.code == 200) {
            saw_unknown = true;
            try std.testing.expectEqualStrings("ok", option.value);
        }
    }
    try std.testing.expectEqual(@as(usize, 8), option_count);
    try std.testing.expect(saw_unknown);
}

test "rejects invalid DHCP framing and typed option lengths" {
    var short = [_]u8{0} ** (min_message_len - 1);
    try std.testing.expectError(error.Truncated, decode(&short));

    var oversized = [_]u8{0} ** (max_message_len + 1);
    try std.testing.expectError(error.MessageTooLarge, decode(&oversized));

    var packet = [_]u8{0} ** 245;
    try std.testing.expectError(error.InvalidMagicCookie, decode(&packet));
    packet[236..240].* = .{ 0x63, 0x82, 0x53, 0x63 };
    packet[2] = 17;
    try std.testing.expectError(error.InvalidHardwareAddressLength, decode(&packet));
    packet[2] = 6;
    packet[240..245].* = .{ 53, 2, 1, 2, 255 };
    try std.testing.expectError(error.InvalidOptionLength, decode(&packet));
}

test "option iterator enforces bounds and END" {
    var packet = [_]u8{0} ** (240 + max_options * 3 + 4);
    packet[236..240].* = .{ 0x63, 0x82, 0x53, 0x63 };
    var cursor: usize = 240;
    for (0..max_options + 1) |_| {
        packet[cursor..][0..3].* = .{ 200, 1, 0 };
        cursor += 3;
    }
    packet[cursor] = 255;
    try std.testing.expectError(error.TooManyOptions, decode(packet[0 .. cursor + 1]));

    packet[240..243].* = .{ 200, 2, 1 };
    try std.testing.expectError(error.Truncated, decode(packet[0..243]));

    packet[240..243].* = .{ 200, 1, 1 };
    try std.testing.expectError(error.MissingEndOption, decode(packet[0..243]));
}
