const std = @import("std");

pub const max_message_len = 65_535;
pub const max_name_wire_len = 255;
pub const max_name_text_len = 1024;
pub const max_pointer_hops = 16;
pub const max_scope_labels = 16;
pub const max_questions = 16;
pub const max_answers = 64;
pub const max_records = 64;
pub const max_addresses_per_answer = 16;

pub const Header = struct {
    id: u16,
    raw_flags: u16,
    is_response: bool,
    opcode: u8,
    truncated: bool,
    rcode: u8,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
};

pub const Question = struct {
    name: []const u8,
    query_type: u16,
    class: u16,
};

pub const Message = struct {
    header: Header,
    first_question: ?Question,
};

pub const Address = struct {
    flags: u16,
    group: bool,
    node_type: u2,
    address: [4]u8,
};

pub const AddressIterator = struct {
    raw: []const u8,
    offset: usize = 0,

    pub fn next(self: *AddressIterator) ?Address {
        if (self.offset == self.raw.len) return null;
        const flags = readU16(self.raw, self.offset);
        const value = Address{
            .flags = flags,
            .group = flags & 0x8000 != 0,
            .node_type = @intCast((flags >> 13) & 0x03),
            .address = self.raw[self.offset + 2 ..][0..4].*,
        };
        self.offset += 6;
        return value;
    }
};

pub const Addresses = struct {
    raw: []const u8,
    count: u8,

    pub fn iterator(self: Addresses) AddressIterator {
        return .{ .raw = self.raw };
    }
};

pub const AnswerValue = union(enum) {
    nb: Addresses,
    unsupported: []const u8,
};

pub const Answer = struct {
    name: []const u8,
    record_type: u16,
    class: u16,
    ttl: u32,
    value: AnswerValue,
};

pub const Error = error{
    MessageTooLarge,
    Truncated,
    UnsupportedLabelType,
    InvalidCompressionPointer,
    TooManyCompressionPointers,
    InvalidEncodedName,
    NameTooLong,
    TooManyScopeLabels,
    TooManyQuestions,
    TooManyAnswers,
    TooManyRecords,
    TooManyAddresses,
    InvalidRecordData,
};

pub fn decodeFirstQuestion(
    packet: []const u8,
    name_buffer: *[max_name_text_len]u8,
) Error!Message {
    const header = try decodeHeader(packet);
    if (header.question_count == 0) return .{ .header = header, .first_question = null };

    const parsed_name = try decodeName(packet, 12, name_buffer);
    if (packet.len - parsed_name.next_offset < 4) return error.Truncated;
    return .{
        .header = header,
        .first_question = .{
            .name = parsed_name.name,
            .query_type = readU16(packet, parsed_name.next_offset),
            .class = readU16(packet, parsed_name.next_offset + 2),
        },
    };
}

pub const AnswerIterator = struct {
    packet: []const u8,
    cursor: usize,
    remaining: u16,
    parsed: usize = 0,

    pub fn next(self: *AnswerIterator, name_buffer: *[max_name_text_len]u8) Error!?Answer {
        if (self.remaining == 0) return null;
        if (self.parsed >= max_answers) return error.TooManyAnswers;

        const owner = try decodeName(self.packet, self.cursor, name_buffer);
        if (self.packet.len - owner.next_offset < 10) return error.Truncated;
        const record_type = readU16(self.packet, owner.next_offset);
        const class = readU16(self.packet, owner.next_offset + 2);
        const ttl = readU32(self.packet, owner.next_offset + 4);
        const rdata_length: usize = readU16(self.packet, owner.next_offset + 8);
        const rdata_start = owner.next_offset + 10;
        if (rdata_length > self.packet.len - rdata_start) return error.Truncated;
        const rdata = self.packet[rdata_start .. rdata_start + rdata_length];
        const value: AnswerValue = if (record_type == 0x20) blk: {
            if (rdata.len == 0 or rdata.len % 6 != 0) return error.InvalidRecordData;
            const count = rdata.len / 6;
            if (count > max_addresses_per_answer) return error.TooManyAddresses;
            break :blk .{ .nb = .{ .raw = rdata, .count = @intCast(count) } };
        } else .{ .unsupported = rdata };

        self.cursor = rdata_start + rdata_length;
        self.remaining -= 1;
        self.parsed += 1;
        return .{
            .name = owner.name,
            .record_type = record_type,
            .class = class,
            .ttl = ttl,
            .value = value,
        };
    }
};

pub fn answers(packet: []const u8) Error!AnswerIterator {
    const header = try decodeHeader(packet);
    return .{
        .packet = packet,
        .cursor = try skipQuestions(packet, header.question_count),
        .remaining = header.answer_count,
    };
}

fn decodeHeader(packet: []const u8) Error!Header {
    if (packet.len > max_message_len) return error.MessageTooLarge;
    if (packet.len < 12) return error.Truncated;

    const question_count = readU16(packet, 4);
    const answer_count = readU16(packet, 6);
    const authority_count = readU16(packet, 8);
    const additional_count = readU16(packet, 10);
    if (question_count > max_questions) return error.TooManyQuestions;
    if (answer_count > max_answers) return error.TooManyAnswers;
    if (authority_count > max_records or additional_count > max_records) return error.TooManyRecords;

    const flags = readU16(packet, 2);
    return .{
        .id = readU16(packet, 0),
        .raw_flags = flags,
        .is_response = flags & 0x8000 != 0,
        .opcode = @intCast((flags >> 11) & 0x0f),
        .truncated = flags & 0x0200 != 0,
        .rcode = @intCast(flags & 0x000f),
        .question_count = question_count,
        .answer_count = answer_count,
        .authority_count = authority_count,
        .additional_count = additional_count,
    };
}

fn skipQuestions(packet: []const u8, count: u16) Error!usize {
    var cursor: usize = 12;
    var scratch: [max_name_text_len]u8 = undefined;
    for (0..count) |_| {
        const name = try decodeName(packet, cursor, &scratch);
        if (packet.len - name.next_offset < 4) return error.Truncated;
        cursor = name.next_offset + 4;
    }
    return cursor;
}

const DecodedName = struct {
    name: []const u8,
    next_offset: usize,
};

fn decodeName(packet: []const u8, start: usize, output: *[max_name_text_len]u8) Error!DecodedName {
    var cursor = start;
    var continuation: ?usize = null;
    var pointer_count: usize = 0;
    var wire_len: usize = 0;
    var written: usize = 0;
    var first_label = true;
    var scope_labels: usize = 0;

    while (true) {
        if (cursor >= packet.len) return error.Truncated;
        const length = packet[cursor];
        if (length & 0xc0 == 0xc0) {
            if (packet.len - cursor < 2) return error.Truncated;
            const pointer: usize = (@as(usize, length & 0x3f) << 8) | packet[cursor + 1];
            if (pointer < 12 or pointer >= cursor or pointer >= packet.len) return error.InvalidCompressionPointer;
            if (pointer_count == max_pointer_hops) return error.TooManyCompressionPointers;
            pointer_count += 1;
            if (continuation == null) continuation = cursor + 2;
            cursor = pointer;
            continue;
        }
        if (length & 0xc0 != 0) return error.UnsupportedLabelType;

        cursor += 1;
        if (length == 0) {
            if (first_label) return error.InvalidEncodedName;
            wire_len += 1;
            if (wire_len > max_name_wire_len) return error.NameTooLong;
            return .{ .name = output[0..written], .next_offset = continuation orelse cursor };
        }
        if (length > packet.len - cursor) return error.Truncated;

        wire_len += 1 + length;
        if (wire_len + 1 > max_name_wire_len) return error.NameTooLong;
        const label = packet[cursor .. cursor + length];
        if (first_label) {
            if (length != 32) return error.InvalidEncodedName;
            try appendFirstLevelName(output, &written, label);
            first_label = false;
        } else {
            if (scope_labels == max_scope_labels) return error.TooManyScopeLabels;
            try appendByte(output, &written, '.');
            for (label) |byte| try appendDisplayByte(output, &written, byte);
            scope_labels += 1;
        }
        cursor += length;
    }
}

fn appendFirstLevelName(output: *[max_name_text_len]u8, written: *usize, encoded: []const u8) Error!void {
    var decoded: [16]u8 = undefined;
    for (0..16) |index| {
        const high = encoded[index * 2];
        const low = encoded[index * 2 + 1];
        if (high < 'A' or high > 'P' or low < 'A' or low > 'P') return error.InvalidEncodedName;
        decoded[index] = ((high - 'A') << 4) | (low - 'A');
    }

    var name_len: usize = 15;
    while (name_len != 0 and (decoded[name_len - 1] == ' ' or decoded[name_len - 1] == 0)) name_len -= 1;
    for (decoded[0..name_len]) |byte| try appendDisplayByte(output, written, byte);
    try appendByte(output, written, '<');
    try appendByte(output, written, hexDigit(decoded[15] >> 4));
    try appendByte(output, written, hexDigit(decoded[15] & 0x0f));
    try appendByte(output, written, '>');
}

fn appendDisplayByte(output: *[max_name_text_len]u8, written: *usize, byte: u8) Error!void {
    if (byte >= 0x20 and byte <= 0x7e and byte != '.' and byte != '\\' and byte != '<' and byte != '>') {
        return appendByte(output, written, byte);
    }
    try appendByte(output, written, '\\');
    try appendByte(output, written, 'x');
    try appendByte(output, written, hexDigit(byte >> 4));
    try appendByte(output, written, hexDigit(byte & 0x0f));
}

fn appendByte(output: *[max_name_text_len]u8, written: *usize, byte: u8) Error!void {
    if (written.* == output.len) return error.NameTooLong;
    output[written.*] = byte;
    written.* += 1;
}

fn hexDigit(value: u8) u8 {
    return if (value < 10) '0' + value else 'A' + value - 10;
}

fn readU16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .big);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .big);
}

const encoded_myhost = "ENFJEIEPFDFECACACACACACACACACACA";

test "NetBIOS first-level names decode suffix and scope" {
    const packet =
        "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x20" ++ encoded_myhost ++ "\x04LABS\x00\x00\x20\x00\x01";
    var name_buffer: [max_name_text_len]u8 = undefined;
    const message = try decodeFirstQuestion(packet, &name_buffer);

    try std.testing.expectEqualStrings("MYHOST<20>.LABS", message.first_question.?.name);
}

test "NBNS question parser reads header type and class" {
    const packet =
        "\x12\x34\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x20" ++ encoded_myhost ++ "\x00\x00\x20\x00\x01";
    var name_buffer: [max_name_text_len]u8 = undefined;
    const message = try decodeFirstQuestion(packet, &name_buffer);

    try std.testing.expectEqual(@as(u16, 0x1234), message.header.id);
    try std.testing.expect(!message.header.is_response);
    try std.testing.expectEqual(@as(u16, 0x20), message.first_question.?.query_type);
    try std.testing.expectEqual(@as(u16, 1), message.first_question.?.class);
}

test "NB address answers expose bounded flags and IPv4 entries" {
    const packet =
        "\x12\x34\x85\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x20" ++ encoded_myhost ++ "\x00\x00\x20\x00\x01\x00\x00\x01\x2c\x00\x0c" ++
        "\x60\x00\xc0\x00\x02\x0a\x80\x00\xc6\x33\x64\x14";
    var iterator = try answers(packet);
    var name_buffer: [max_name_text_len]u8 = undefined;
    const answer = (try iterator.next(&name_buffer)).?;

    try std.testing.expectEqualStrings("MYHOST<20>", answer.name);
    try std.testing.expectEqual(@as(u8, 2), answer.value.nb.count);
    var addresses = answer.value.nb.iterator();
    const first = addresses.next().?;
    try std.testing.expect(!first.group);
    try std.testing.expectEqual(@as(u2, 3), first.node_type);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, &first.address);
    const second = addresses.next().?;
    try std.testing.expect(second.group);
    try std.testing.expectEqualSlices(u8, &.{ 198, 51, 100, 20 }, &second.address);
    try std.testing.expect(addresses.next() == null);
}

test "NBNS rejects malformed names counts and NB address data" {
    const invalid_name =
        "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x20QNFJEIEPFDFECACACACACACACACACACA\x00\x00\x20\x00\x01";
    var name_buffer: [max_name_text_len]u8 = undefined;
    try std.testing.expectError(error.InvalidEncodedName, decodeFirstQuestion(invalid_name, &name_buffer));

    const too_many_answers = "\x00\x01\x80\x00\x00\x00\x00\x41\x00\x00\x00\x00";
    try std.testing.expectError(error.TooManyAnswers, answers(too_many_answers));

    const invalid_rdata =
        "\x00\x01\x85\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x20" ++ encoded_myhost ++ "\x00\x00\x20\x00\x01\x00\x00\x00\x3c\x00\x05" ++
        "\x00\x00\xc0\x00\x02";
    var iterator = try answers(invalid_rdata);
    try std.testing.expectError(error.InvalidRecordData, iterator.next(&name_buffer));
}
