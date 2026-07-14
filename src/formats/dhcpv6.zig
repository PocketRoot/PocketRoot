const std = @import("std");

pub const max_message_len = 4096;
pub const max_options = 64;
pub const max_nested_options = 32;
pub const max_addresses = 16;
pub const max_dns_servers = 16;
pub const max_domain_names = 16;
pub const max_fqdn_text_len = 1024;

pub const MessageType = enum(u8) {
    solicit = 1,
    advertise = 2,
    request = 3,
    confirm = 4,
    renew = 5,
    rebind = 6,
    reply = 7,
    release = 8,
    decline = 9,
    reconfigure = 10,
    information_request = 11,
    relay_forward = 12,
    relay_reply = 13,
    _,
};

pub const AddressAssignment = struct {
    address: [16]u8,
    iaid: u32,
    preferred_lifetime: u32,
    valid_lifetime: u32,
};

pub const Message = struct {
    message_type: MessageType,
    transaction_id: u32 = 0,
    relayed: bool = false,
    hop_count: u8 = 0,
    client_identifier: ?[]const u8 = null,
    server_identifier: ?[]const u8 = null,
    fqdn: ?[]const u8 = null,
    fqdn_flags: ?u8 = null,
    preference: ?u8 = null,
    elapsed_time: ?u16 = null,
    rapid_commit: bool = false,
    status_code: ?u16 = null,
    dns_server_count: usize = 0,
    domain_name_count: usize = 0,
    ia_na_count: usize = 0,
    addresses: [max_addresses]AddressAssignment = undefined,
    address_count: usize = 0,

    pub fn hasValidAssignment(self: Message) bool {
        return !self.relayed and
            (self.message_type == .advertise or self.message_type == .reply) and
            self.client_identifier != null and
            self.server_identifier != null and
            (self.status_code == null or self.status_code.? == 0) and
            self.address_count != 0;
    }
};

pub const Option = struct {
    code: u16,
    value: []const u8,
};

pub const Error = error{
    MessageTooLarge,
    Truncated,
    TooManyOptions,
    TooManyAddresses,
    TooManyDnsServers,
    TooManyDomainNames,
    InvalidOptionLength,
    InvalidLifetime,
    InvalidDomainName,
};

const OptionIterator = struct {
    data: []const u8,
    limit: usize,
    offset: usize = 0,
    count: usize = 0,

    fn next(self: *OptionIterator) Error!?Option {
        if (self.offset == self.data.len) return null;
        if (self.count == self.limit) return error.TooManyOptions;
        if (self.data.len - self.offset < 4) return error.Truncated;
        const code = readU16(self.data, self.offset);
        const length: usize = readU16(self.data, self.offset + 2);
        self.offset += 4;
        if (length > self.data.len - self.offset) return error.Truncated;
        const value = self.data[self.offset .. self.offset + length];
        self.offset += length;
        self.count += 1;
        return .{ .code = code, .value = value };
    }
};

pub fn decode(data: []const u8, fqdn_buffer: *[max_fqdn_text_len]u8) Error!Message {
    if (data.len > max_message_len) return error.MessageTooLarge;
    if (data.len < 4) return error.Truncated;

    const message_type: MessageType = @enumFromInt(data[0]);
    const relayed = message_type == .relay_forward or message_type == .relay_reply;
    const options_offset: usize = if (relayed) 34 else 4;
    if (data.len < options_offset) return error.Truncated;
    var message: Message = .{
        .message_type = message_type,
        .transaction_id = if (relayed) 0 else (@as(u32, data[1]) << 16 | @as(u32, data[2]) << 8 | data[3]),
        .relayed = relayed,
        .hop_count = if (relayed) data[1] else 0,
    };

    var iterator = OptionIterator{ .data = data[options_offset..], .limit = max_options };
    while (try iterator.next()) |option| switch (option.code) {
        1 => {
            if (option.value.len < 2) return error.InvalidOptionLength;
            if (message.client_identifier == null) message.client_identifier = option.value;
        },
        2 => {
            if (option.value.len < 2) return error.InvalidOptionLength;
            if (message.server_identifier == null) message.server_identifier = option.value;
        },
        3 => {
            message.ia_na_count += 1;
            try parseIaNa(&message, option.value);
        },
        7 => {
            try expectLength(option.value, 1);
            if (message.preference == null) message.preference = option.value[0];
        },
        8 => {
            try expectLength(option.value, 2);
            if (message.elapsed_time == null) message.elapsed_time = readU16(option.value, 0);
        },
        13 => {
            if (option.value.len < 2) return error.InvalidOptionLength;
            if (message.status_code == null) message.status_code = readU16(option.value, 0);
        },
        14 => {
            try expectLength(option.value, 0);
            message.rapid_commit = true;
        },
        23 => {
            if (option.value.len == 0 or option.value.len % 16 != 0) return error.InvalidOptionLength;
            const count = option.value.len / 16;
            if (count > max_dns_servers) return error.TooManyDnsServers;
            message.dns_server_count += count;
            if (message.dns_server_count > max_dns_servers) return error.TooManyDnsServers;
        },
        24 => {
            message.domain_name_count += try validateDomainList(option.value);
            if (message.domain_name_count > max_domain_names) return error.TooManyDomainNames;
        },
        39 => if (message.fqdn == null) {
            if (option.value.len < 2) return error.InvalidOptionLength;
            message.fqdn_flags = option.value[0];
            message.fqdn = try decodeDomainName(option.value[1..], fqdn_buffer);
        },
        else => {},
    };
    return message;
}

fn parseIaNa(message: *Message, value: []const u8) Error!void {
    if (value.len < 12) return error.InvalidOptionLength;
    const iaid = readU32(value, 0);
    const t1 = readU32(value, 4);
    const t2 = readU32(value, 8);
    if (t2 != 0 and t1 > t2) return error.InvalidLifetime;

    var assignments: [max_addresses]AddressAssignment = undefined;
    var assignment_count: usize = 0;
    var status_code: ?u16 = null;
    var iterator = OptionIterator{ .data = value[12..], .limit = max_nested_options };
    while (try iterator.next()) |option| switch (option.code) {
        5 => if (try parseIaAddress(iaid, option.value)) |assignment| {
            if (assignment_count == assignments.len) return error.TooManyAddresses;
            assignments[assignment_count] = assignment;
            assignment_count += 1;
        },
        13 => {
            if (option.value.len < 2) return error.InvalidOptionLength;
            if (status_code == null) status_code = readU16(option.value, 0);
        },
        else => {},
    };
    if (status_code != null and status_code.? != 0) return;

    for (assignments[0..assignment_count]) |assignment| {
        var duplicate = false;
        for (message.addresses[0..message.address_count]) |existing| {
            if (std.mem.eql(u8, &existing.address, &assignment.address)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (message.address_count == message.addresses.len) return error.TooManyAddresses;
        message.addresses[message.address_count] = assignment;
        message.address_count += 1;
    }
}

fn parseIaAddress(iaid: u32, value: []const u8) Error!?AddressAssignment {
    if (value.len < 24) return error.InvalidOptionLength;
    const preferred = readU32(value, 16);
    const valid = readU32(value, 20);
    if (preferred > valid) return error.InvalidLifetime;

    var status_code: ?u16 = null;
    var iterator = OptionIterator{ .data = value[24..], .limit = max_nested_options };
    while (try iterator.next()) |option| switch (option.code) {
        13 => {
            if (option.value.len < 2) return error.InvalidOptionLength;
            if (status_code == null) status_code = readU16(option.value, 0);
        },
        else => {},
    };
    if (valid == 0 or (status_code != null and status_code.? != 0)) return null;
    return .{
        .address = value[0..16].*,
        .iaid = iaid,
        .preferred_lifetime = preferred,
        .valid_lifetime = valid,
    };
}

fn validateDomainList(data: []const u8) Error!usize {
    if (data.len == 0) return error.InvalidDomainName;
    var offset: usize = 0;
    var count: usize = 0;
    while (offset < data.len) {
        count += 1;
        if (count > max_domain_names) return error.TooManyDomainNames;
        var wire_len: usize = 0;
        while (true) {
            if (offset == data.len) return error.InvalidDomainName;
            const length: usize = data[offset];
            offset += 1;
            wire_len += 1;
            if (length == 0) break;
            if (length > 63 or length > data.len - offset or wire_len + length > 255) return error.InvalidDomainName;
            offset += length;
            wire_len += length;
        }
    }
    return count;
}

fn decodeDomainName(data: []const u8, output: *[max_fqdn_text_len]u8) Error![]const u8 {
    if (data.len == 0 or data.len > 255) return error.InvalidDomainName;
    var offset: usize = 0;
    var written: usize = 0;
    var labels: usize = 0;
    while (true) {
        if (offset == data.len) return error.InvalidDomainName;
        const length: usize = data[offset];
        offset += 1;
        if (length == 0) {
            if (offset != data.len) return error.InvalidDomainName;
            if (labels == 0) return output[0..0];
            return output[0..written];
        }
        if (length > 63 or length > data.len - offset) return error.InvalidDomainName;
        if (labels != 0) try appendByte(output, &written, '.');
        for (data[offset .. offset + length]) |byte| try appendLabelByte(output, &written, byte);
        offset += length;
        labels += 1;
    }
}

fn appendLabelByte(output: *[max_fqdn_text_len]u8, written: *usize, byte: u8) Error!void {
    if (byte >= 0x21 and byte <= 0x7e and byte != '.' and byte != '\\') return appendByte(output, written, byte);
    if (output.len - written.* < 4) return error.InvalidDomainName;
    output[written.*] = '\\';
    output[written.* + 1] = '0' + byte / 100;
    output[written.* + 2] = '0' + (byte / 10) % 10;
    output[written.* + 3] = '0' + byte % 10;
    written.* += 4;
}

fn appendByte(output: *[max_fqdn_text_len]u8, written: *usize, byte: u8) Error!void {
    if (written.* == output.len) return error.InvalidDomainName;
    output[written.*] = byte;
    written.* += 1;
}

fn expectLength(value: []const u8, expected: usize) Error!void {
    if (value.len != expected) return error.InvalidOptionLength;
}

fn readU16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .big);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .big);
}

fn writeU16(data: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, data[offset..][0..2], value, .big);
}

fn writeU32(data: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, data[offset..][0..4], value, .big);
}

fn appendOption(buffer: []u8, cursor: *usize, code: u16, value: []const u8) void {
    writeU16(buffer, cursor.*, code);
    writeU16(buffer, cursor.* + 2, @intCast(value.len));
    @memcpy(buffer[cursor.* + 4 .. cursor.* + 4 + value.len], value);
    cursor.* += 4 + value.len;
}

test "decodes bounded DHCPv6 Advertise assignments and FQDN" {
    var ia_address: [24]u8 = [_]u8{0} ** 24;
    ia_address[0..16].* = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20 };
    writeU32(&ia_address, 16, 3600);
    writeU32(&ia_address, 20, 7200);

    var ia_na: [40]u8 = [_]u8{0} ** 40;
    writeU32(&ia_na, 0, 0x12345678);
    writeU32(&ia_na, 4, 1800);
    writeU32(&ia_na, 8, 3600);
    var ia_cursor: usize = 12;
    appendOption(&ia_na, &ia_cursor, 5, &ia_address);

    var packet: [160]u8 = [_]u8{0} ** 160;
    packet[0..4].* = .{ 2, 0x12, 0x34, 0x56 };
    var cursor: usize = 4;
    appendOption(&packet, &cursor, 1, "\x00\x03\x00\x01client");
    appendOption(&packet, &cursor, 2, "\x00\x03\x00\x01server");
    appendOption(&packet, &cursor, 3, &ia_na);
    appendOption(&packet, &cursor, 7, "\x7f");
    appendOption(&packet, &cursor, 23, &([_]u8{0x20} ++ [_]u8{0} ** 15));
    appendOption(&packet, &cursor, 24, "\x07example\x04test\x00");
    appendOption(&packet, &cursor, 39, "\x00\x06device\x07example\x00");

    var fqdn_buffer: [max_fqdn_text_len]u8 = undefined;
    const message = try decode(packet[0..cursor], &fqdn_buffer);
    try std.testing.expectEqual(MessageType.advertise, message.message_type);
    try std.testing.expectEqual(@as(u32, 0x123456), message.transaction_id);
    try std.testing.expect(message.hasValidAssignment());
    try std.testing.expectEqualStrings("device.example", message.fqdn.?);
    try std.testing.expectEqual(@as(usize, 1), message.address_count);
    try std.testing.expectEqual(@as(u32, 0x12345678), message.addresses[0].iaid);
    try std.testing.expectEqual(@as(u32, 7200), message.addresses[0].valid_lifetime);
    try std.testing.expectEqual(@as(usize, 1), message.dns_server_count);
    try std.testing.expectEqual(@as(usize, 1), message.domain_name_count);
}

test "only successful Advertise and Reply messages expose assignments" {
    var ia_address: [24]u8 = [_]u8{0} ** 24;
    ia_address[15] = 1;
    writeU32(&ia_address, 20, 60);
    var ia_na: [40]u8 = [_]u8{0} ** 40;
    var ia_cursor: usize = 12;
    appendOption(&ia_na, &ia_cursor, 5, &ia_address);

    var packet: [96]u8 = [_]u8{0} ** 96;
    packet[0] = @intFromEnum(MessageType.request);
    var cursor: usize = 4;
    appendOption(&packet, &cursor, 1, "\x00\x01");
    appendOption(&packet, &cursor, 2, "\x00\x02");
    appendOption(&packet, &cursor, 3, &ia_na);
    var fqdn_buffer: [max_fqdn_text_len]u8 = undefined;
    var message = try decode(packet[0..cursor], &fqdn_buffer);
    try std.testing.expect(!message.hasValidAssignment());

    packet[0] = @intFromEnum(MessageType.reply);
    var failed_cursor = cursor;
    appendOption(&packet, &failed_cursor, 13, "\x00\x02failure");
    message = try decode(packet[0..failed_cursor], &fqdn_buffer);
    try std.testing.expect(!message.hasValidAssignment());
}

test "rejects malformed DHCPv6 options names and lifetimes" {
    var fqdn_buffer: [max_fqdn_text_len]u8 = undefined;
    try std.testing.expectError(error.Truncated, decode("\x02\x00\x00\x01\x00", &fqdn_buffer));
    try std.testing.expectError(
        error.InvalidDomainName,
        decode("\x02\x00\x00\x01\x00\x27\x00\x03\x00\xc0\x00", &fqdn_buffer),
    );

    var ia_address: [24]u8 = [_]u8{0} ** 24;
    writeU32(&ia_address, 16, 2);
    writeU32(&ia_address, 20, 1);
    var ia_na: [40]u8 = [_]u8{0} ** 40;
    var ia_cursor: usize = 12;
    appendOption(&ia_na, &ia_cursor, 5, &ia_address);
    var packet: [48]u8 = [_]u8{0} ** 48;
    packet[0] = 2;
    var cursor: usize = 4;
    appendOption(&packet, &cursor, 3, &ia_na);
    try std.testing.expectError(error.InvalidLifetime, decode(packet[0..cursor], &fqdn_buffer));

    var many: [4 + (max_options + 1) * 4]u8 = [_]u8{0} ** (4 + (max_options + 1) * 4);
    many[0] = 1;
    try std.testing.expectError(error.TooManyOptions, decode(&many, &fqdn_buffer));
}
