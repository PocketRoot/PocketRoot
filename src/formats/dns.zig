const std = @import("std");

pub const max_message_len = 65_535;
pub const max_name_wire_len = 255;
pub const max_name_text_len = 1024;
pub const max_pointer_hops = 16;
pub const max_questions = 16;
pub const max_answers = 64;
pub const max_txt_strings = 64;

pub const Family = enum {
    dns,
    mdns,
    llmnr,
};

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
    raw_class: u16,
    class: u16,
    unicast_response: bool,
};

pub const Message = struct {
    family: Family,
    header: Header,
    first_question: ?Question,
};

pub const Srv = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: []const u8,
};

pub const Mx = struct {
    preference: u16,
    exchange: []const u8,
};

pub const Soa = struct {
    mname: []const u8,
    rname: []const u8,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub const Txt = struct {
    raw: []const u8,
    strings: u8,

    pub fn iterator(self: Txt) TxtIterator {
        return .{ .raw = self.raw };
    }
};

pub const TxtIterator = struct {
    raw: []const u8,
    offset: usize = 0,

    pub fn next(self: *TxtIterator) ?[]const u8 {
        if (self.offset == self.raw.len) return null;
        const length = self.raw[self.offset];
        self.offset += 1;
        const value = self.raw[self.offset .. self.offset + length];
        self.offset += length;
        return value;
    }
};

pub const AnswerValue = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    cname: []const u8,
    ns: []const u8,
    ptr: []const u8,
    mx: Mx,
    soa: Soa,
    srv: Srv,
    txt: Txt,
    unsupported: []const u8,
};

pub const Answer = struct {
    // Owner and decoded name slices backed by caller buffers last until the iterator's next call.
    name: []const u8,
    record_type: u16,
    raw_class: u16,
    class: u16,
    cache_flush: bool,
    ttl: u32,
    value: AnswerValue,
};

pub const Error = error{
    MessageTooLarge,
    Truncated,
    UnsupportedLabelType,
    InvalidCompressionPointer,
    TooManyCompressionPointers,
    NameTooLong,
    TooManyQuestions,
    TooManyAnswers,
    TooManyTxtStrings,
    InvalidRecordData,
};

pub fn decodeFirstQuestion(
    packet: []const u8,
    family: Family,
    name_buffer: *[max_name_text_len]u8,
) Error!Message {
    const header = try decodeHeader(packet);
    if (header.question_count == 0) return .{
        .family = family,
        .header = header,
        .first_question = null,
    };

    const parsed_name = try decodeName(packet, 12, name_buffer);
    if (packet.len - parsed_name.next_offset < 4) return error.Truncated;
    const raw_class = readU16(packet, parsed_name.next_offset + 2);
    return .{
        .family = family,
        .header = header,
        .first_question = .{
            .name = parsed_name.name,
            .query_type = readU16(packet, parsed_name.next_offset),
            .raw_class = raw_class,
            .class = if (family == .mdns) raw_class & 0x7fff else raw_class,
            .unicast_response = family == .mdns and raw_class & 0x8000 != 0,
        },
    };
}

pub const AnswerIterator = struct {
    packet: []const u8,
    family: Family,
    cursor: usize,
    remaining: u16,
    parsed: usize = 0,

    pub fn next(
        self: *AnswerIterator,
        owner_buffer: *[max_name_text_len]u8,
        value_buffer: *[max_name_text_len]u8,
    ) Error!?Answer {
        if (self.remaining == 0) return null;
        if (self.parsed >= max_answers) return error.TooManyAnswers;

        const owner = try decodeName(self.packet, self.cursor, owner_buffer);
        if (self.packet.len - owner.next_offset < 10) return error.Truncated;
        const record_type = readU16(self.packet, owner.next_offset);
        const raw_class = readU16(self.packet, owner.next_offset + 2);
        const ttl = readU32(self.packet, owner.next_offset + 4);
        const rdata_length: usize = readU16(self.packet, owner.next_offset + 8);
        const rdata_start = owner.next_offset + 10;
        if (rdata_length > self.packet.len - rdata_start) return error.Truncated;
        const rdata_end = rdata_start + rdata_length;
        const value = try decodeAnswerValue(
            self.packet,
            record_type,
            rdata_start,
            rdata_end,
            value_buffer,
        );

        self.cursor = rdata_end;
        self.remaining -= 1;
        self.parsed += 1;
        return .{
            .name = owner.name,
            .record_type = record_type,
            .raw_class = raw_class,
            .class = if (self.family == .mdns) raw_class & 0x7fff else raw_class,
            .cache_flush = self.family == .mdns and raw_class & 0x8000 != 0,
            .ttl = ttl,
            .value = value,
        };
    }
};

pub fn answers(packet: []const u8, family: Family) Error!AnswerIterator {
    const header = try decodeHeader(packet);
    return .{
        .packet = packet,
        .family = family,
        .cursor = try skipQuestions(packet, header.question_count),
        .remaining = header.answer_count,
    };
}

pub fn authority(packet: []const u8, family: Family) Error!AnswerIterator {
    const header = try decodeHeader(packet);
    var cursor = try skipQuestions(packet, header.question_count);
    cursor = try skipRecords(packet, cursor, header.answer_count);
    return .{
        .packet = packet,
        .family = family,
        .cursor = cursor,
        .remaining = header.authority_count,
    };
}

pub fn additional(packet: []const u8, family: Family) Error!AnswerIterator {
    const header = try decodeHeader(packet);
    var cursor = try skipQuestions(packet, header.question_count);
    cursor = try skipRecords(packet, cursor, header.answer_count);
    cursor = try skipRecords(packet, cursor, header.authority_count);
    return .{
        .packet = packet,
        .family = family,
        .cursor = cursor,
        .remaining = header.additional_count,
    };
}

fn skipQuestions(packet: []const u8, count: u16) Error!usize {
    if (count > max_questions) return error.TooManyQuestions;
    var cursor: usize = 12;
    var scratch: [max_name_text_len]u8 = undefined;
    for (0..count) |_| {
        const question_name = try decodeName(packet, cursor, &scratch);
        if (packet.len - question_name.next_offset < 4) return error.Truncated;
        cursor = question_name.next_offset + 4;
    }
    return cursor;
}

fn skipRecords(packet: []const u8, start: usize, count: u16) Error!usize {
    if (count > max_answers) return error.TooManyAnswers;
    var cursor = start;
    var scratch: [max_name_text_len]u8 = undefined;
    for (0..count) |_| {
        const owner = try decodeName(packet, cursor, &scratch);
        if (packet.len - owner.next_offset < 10) return error.Truncated;
        const rdata_length: usize = readU16(packet, owner.next_offset + 8);
        const rdata_start = owner.next_offset + 10;
        if (rdata_length > packet.len - rdata_start) return error.Truncated;
        cursor = rdata_start + rdata_length;
    }
    return cursor;
}

fn decodeAnswerValue(
    packet: []const u8,
    record_type: u16,
    start: usize,
    end: usize,
    value_buffer: *[max_name_text_len]u8,
) Error!AnswerValue {
    const rdata = packet[start..end];
    return switch (record_type) {
        1 => if (rdata.len == 4) .{ .a = rdata[0..4].* } else error.InvalidRecordData,
        28 => if (rdata.len == 16) .{ .aaaa = rdata[0..16].* } else error.InvalidRecordData,
        5 => blk: {
            const decoded = try decodeName(packet, start, value_buffer);
            if (decoded.next_offset != end) return error.InvalidRecordData;
            break :blk .{ .cname = decoded.name };
        },
        2 => blk: {
            const decoded = try decodeName(packet, start, value_buffer);
            if (decoded.next_offset != end) return error.InvalidRecordData;
            break :blk .{ .ns = decoded.name };
        },
        12 => blk: {
            const decoded = try decodeName(packet, start, value_buffer);
            if (decoded.next_offset != end) return error.InvalidRecordData;
            break :blk .{ .ptr = decoded.name };
        },
        15 => blk: {
            if (rdata.len < 3) return error.InvalidRecordData;
            const decoded = try decodeName(packet, start + 2, value_buffer);
            if (decoded.next_offset != end) return error.InvalidRecordData;
            break :blk .{ .mx = .{
                .preference = readU16(packet, start),
                .exchange = decoded.name,
            } };
        },
        6 => blk: {
            var rname_buffer: [max_name_text_len]u8 = undefined;
            const mname = try decodeName(packet, start, value_buffer);
            if (mname.next_offset > end) return error.InvalidRecordData;
            const rname = try decodeName(packet, mname.next_offset, &rname_buffer);
            if (rname.next_offset > end or end - rname.next_offset != 20) return error.InvalidRecordData;
            if (rname.name.len > value_buffer.len - mname.name.len) return error.NameTooLong;
            const rname_start = mname.name.len;
            @memcpy(value_buffer[rname_start..][0..rname.name.len], rname.name);
            break :blk .{ .soa = .{
                .mname = value_buffer[0..mname.name.len],
                .rname = value_buffer[rname_start..][0..rname.name.len],
                .serial = readU32(packet, rname.next_offset),
                .refresh = readU32(packet, rname.next_offset + 4),
                .retry = readU32(packet, rname.next_offset + 8),
                .expire = readU32(packet, rname.next_offset + 12),
                .minimum = readU32(packet, rname.next_offset + 16),
            } };
        },
        33 => blk: {
            if (rdata.len < 7) return error.InvalidRecordData;
            const decoded = try decodeName(packet, start + 6, value_buffer);
            if (decoded.next_offset != end) return error.InvalidRecordData;
            break :blk .{ .srv = .{
                .priority = readU16(packet, start),
                .weight = readU16(packet, start + 2),
                .port = readU16(packet, start + 4),
                .target = decoded.name,
            } };
        },
        16 => blk: {
            var offset: usize = 0;
            var count: usize = 0;
            while (offset < rdata.len) {
                if (count >= max_txt_strings) return error.TooManyTxtStrings;
                const length = rdata[offset];
                offset += 1;
                if (length > rdata.len - offset) return error.InvalidRecordData;
                offset += length;
                count += 1;
            }
            break :blk .{ .txt = .{ .raw = rdata, .strings = @intCast(count) } };
        },
        else => .{ .unsupported = rdata },
    };
}

fn decodeHeader(packet: []const u8) Error!Header {
    if (packet.len > max_message_len) return error.MessageTooLarge;
    if (packet.len < 12) return error.Truncated;

    const flags = readU16(packet, 2);
    return .{
        .id = readU16(packet, 0),
        .raw_flags = flags,
        .is_response = flags & 0x8000 != 0,
        .opcode = @intCast((flags >> 11) & 0x0f),
        .truncated = flags & 0x0200 != 0,
        .rcode = @intCast(flags & 0x000f),
        .question_count = readU16(packet, 4),
        .answer_count = readU16(packet, 6),
        .authority_count = readU16(packet, 8),
        .additional_count = readU16(packet, 10),
    };
}

const DecodedName = struct {
    name: []const u8,
    // Offset immediately after the encoded name in its original field, not after pointer expansion.
    next_offset: usize,
};

fn decodeName(packet: []const u8, start: usize, output: *[max_name_text_len]u8) Error!DecodedName {
    var cursor = start;
    var continuation: ?usize = null;
    var pointer_count: usize = 0;
    var wire_len: usize = 0;
    var written: usize = 0;
    var labels: usize = 0;

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
            wire_len += 1;
            if (wire_len > max_name_wire_len) return error.NameTooLong;
            if (labels == 0) {
                output[0] = '.';
                written = 1;
            }
            return .{
                .name = output[0..written],
                .next_offset = continuation orelse cursor,
            };
        }
        if (length > packet.len - cursor) return error.Truncated;

        wire_len += 1 + length;
        if (wire_len + 1 > max_name_wire_len) return error.NameTooLong;
        if (labels != 0) try appendByte(output, &written, '.');
        for (packet[cursor .. cursor + length]) |byte| try appendLabelByte(output, &written, byte);
        labels += 1;
        cursor += length;
    }
}

fn appendLabelByte(output: *[max_name_text_len]u8, written: *usize, byte: u8) Error!void {
    if (byte >= 0x21 and byte <= 0x7e and byte != '.' and byte != '\\') {
        return appendByte(output, written, byte);
    }
    if (output.len - written.* < 4) return error.NameTooLong;
    output[written.*] = '\\';
    output[written.* + 1] = '0' + byte / 100;
    output[written.* + 2] = '0' + (byte / 10) % 10;
    output[written.* + 3] = '0' + byte % 10;
    written.* += 4;
}

fn appendByte(output: *[max_name_text_len]u8, written: *usize, byte: u8) Error!void {
    if (written.* == output.len) return error.NameTooLong;
    output[written.*] = byte;
    written.* += 1;
}

fn readU16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .big);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .big);
}

test "DNS family decoder reads common header and first question" {
    const packet =
        "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x03www\x07example\x04test\x00\x00\x01\x00\x01";
    var name_buffer: [max_name_text_len]u8 = undefined;
    const message = try decodeFirstQuestion(packet, .dns, &name_buffer);

    try std.testing.expectEqual(@as(u16, 0x1234), message.header.id);
    try std.testing.expectEqualStrings("www.example.test", message.first_question.?.name);
    try std.testing.expectEqual(@as(u16, 1), message.first_question.?.query_type);
    try std.testing.expect(!message.first_question.?.unicast_response);
}

test "mDNS decoder separates QU from QCLASS" {
    const packet =
        "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x05_http\x04_tcp\x05local\x00\x00\x0c\x80\x01";
    var name_buffer: [max_name_text_len]u8 = undefined;
    const message = try decodeFirstQuestion(packet, .mdns, &name_buffer);

    try std.testing.expect(message.first_question.?.unicast_response);
    try std.testing.expectEqual(@as(u16, 1), message.first_question.?.class);
}

test "compressed first questions reject non-prior targets" {
    const forward =
        "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\xc0\x12\x00\x01\x00\x01" ++
        "\x03api\x07example\x00";
    var name_buffer: [max_name_text_len]u8 = undefined;
    try std.testing.expectError(
        error.InvalidCompressionPointer,
        decodeFirstQuestion(forward, .llmnr, &name_buffer),
    );

    const self =
        "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\xc0\x0c\x00\x01\x00\x01";
    try std.testing.expectError(
        error.InvalidCompressionPointer,
        decodeFirstQuestion(self, .dns, &name_buffer),
    );

    const header_target =
        "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\xc0\x00\x00\x01\x00\x01";
    try std.testing.expectError(
        error.InvalidCompressionPointer,
        decodeFirstQuestion(header_target, .dns, &name_buffer),
    );
}

test "name decoder follows a prior compression target" {
    const packet =
        "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++
        "\x03api\x07example\x00\xc0\x0c";
    var name_buffer: [max_name_text_len]u8 = undefined;
    const decoded = try decodeName(packet, 25, &name_buffer);

    try std.testing.expectEqualStrings("api.example", decoded.name);
    try std.testing.expectEqual(@as(usize, 27), decoded.next_offset);
}

test "answer iterator decodes unknown A and AAAA records" {
    const packet =
        "\x00\x01\x84\x00\x00\x01\x00\x03\x00\x00\x00\x00" ++
        "\x04host\x05local\x00\x00\x01\x00\x01" ++
        "\xc0\x0c\x00\x63\x00\x01\x00\x00\x00\x00\x00\x01\xff" ++
        "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x0a" ++
        "\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" ++
        "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10";
    var iterator = try answers(packet, .dns);
    var owner_buffer: [max_name_text_len]u8 = undefined;
    var value_buffer: [max_name_text_len]u8 = undefined;

    const unknown = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqualStrings("host.local", unknown.name);
    try std.testing.expectEqual(@as(u16, 99), unknown.record_type);
    try std.testing.expectEqual(@as(usize, 1), unknown.value.unsupported.len);

    const a = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, &a.value.a);
    try std.testing.expectEqual(@as(u32, 60), a.ttl);

    const aaaa = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 },
        &aaaa.value.aaaa,
    );
    try std.testing.expect((try iterator.next(&owner_buffer, &value_buffer)) == null);
}

test "answer iterator decodes compressed PTR SRV and TXT records" {
    const packet =
        "\x00\x00\x84\x00\x00\x01\x00\x03\x00\x00\x00\x00" ++
        "\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01" ++
        "\xc0\x0c\x00\x0c\x80\x01\x00\x00\x00\x78\x00\x0a\x07Printer\xc0\x0c" ++
        "\xc0\x2e\x00\x21\x80\x01\x00\x00\x00\x78\x00\x0f" ++
        "\x00\x00\x00\x00\x1f\x90\x06device\xc0\x17" ++
        "\xc0\x2e\x00\x10\x80\x01\x00\x00\x00\x78\x00\x08\x03foo\x03bar";
    var iterator = try answers(packet, .mdns);
    var owner_buffer: [max_name_text_len]u8 = undefined;
    var value_buffer: [max_name_text_len]u8 = undefined;

    const ptr = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expect(ptr.cache_flush);
    try std.testing.expectEqual(@as(u16, 1), ptr.class);
    try std.testing.expectEqualStrings("Printer._http._tcp.local", ptr.value.ptr);

    const srv = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqual(@as(u16, 8080), srv.value.srv.port);
    try std.testing.expectEqualStrings("device.local", srv.value.srv.target);

    const txt = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqual(@as(u8, 2), txt.value.txt.strings);
    var strings = txt.value.txt.iterator();
    try std.testing.expectEqualStrings("foo", strings.next().?);
    try std.testing.expectEqualStrings("bar", strings.next().?);
    try std.testing.expect(strings.next() == null);
}

test "answer iterator decodes CNAME and MX records" {
    const packet =
        "\x00\x01\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03www\x07example\x04test\x00\x00\x01\x00\x01" ++
        "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x09\x06origin\xc0\x10" ++
        "\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x09\x00\x0a\x04mail\xc0\x10";
    var iterator = try answers(packet, .dns);
    var owner_buffer: [max_name_text_len]u8 = undefined;
    var value_buffer: [max_name_text_len]u8 = undefined;

    const cname = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqualStrings("origin.example.test", cname.value.cname);

    const mx = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqual(@as(u16, 10), mx.value.mx.preference);
    try std.testing.expectEqualStrings("mail.example.test", mx.value.mx.exchange);
    try std.testing.expect((try iterator.next(&owner_buffer, &value_buffer)) == null);
}

test "authority iterator decodes NS and SOA records" {
    const packet =
        "\x00\x01\x84\x00\x00\x01\x00\x00\x00\x02\x00\x00" ++
        "\x07example\x04test\x00\x00\x01\x00\x01" ++
        "\xc0\x0c\x00\x02\x00\x01\x00\x00\x01\x2c\x00\x06\x03ns1\xc0\x0c" ++
        "\xc0\x0c\x00\x06\x00\x01\x00\x00\x01\x2c\x00\x27" ++
        "\x03ns1\xc0\x0c\x0ahostmaster\xc0\x0c" ++
        "\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58" ++
        "\x00\x01\x51\x80\x00\x00\x00\x3c";
    var iterator = try authority(packet, .dns);
    var owner_buffer: [max_name_text_len]u8 = undefined;
    var value_buffer: [max_name_text_len]u8 = undefined;

    const ns = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqualStrings("ns1.example.test", ns.value.ns);

    const soa = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqualStrings("ns1.example.test", soa.value.soa.mname);
    try std.testing.expectEqualStrings("hostmaster.example.test", soa.value.soa.rname);
    try std.testing.expectEqual(@as(u32, 1), soa.value.soa.serial);
    try std.testing.expectEqual(@as(u32, 3600), soa.value.soa.refresh);
    try std.testing.expectEqual(@as(u32, 600), soa.value.soa.retry);
    try std.testing.expectEqual(@as(u32, 86_400), soa.value.soa.expire);
    try std.testing.expectEqual(@as(u32, 60), soa.value.soa.minimum);
    try std.testing.expect((try iterator.next(&owner_buffer, &value_buffer)) == null);
}

test "additional iterator skips answer and authority sections" {
    const packet =
        "\x00\x00\x84\x00\x00\x01\x00\x01\x00\x01\x00\x01" ++
        "\x04host\x05local\x00\x00\x01\x00\x01" ++
        "\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x00\x00\x02\x01x" ++
        "\xc0\x0c\x00\x02\x00\x01\x00\x00\x00\x00\x00\x02\xc0\x0c" ++
        "\xc0\x0c\x00\x01\x80\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x0a";
    var iterator = try additional(packet, .mdns);
    var owner_buffer: [max_name_text_len]u8 = undefined;
    var value_buffer: [max_name_text_len]u8 = undefined;

    const record = (try iterator.next(&owner_buffer, &value_buffer)).?;
    try std.testing.expectEqualStrings("host.local", record.name);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, &record.value.a);
    try std.testing.expect(record.cache_flush);
    try std.testing.expect((try iterator.next(&owner_buffer, &value_buffer)) == null);
}

test "answer iterator rejects malformed typed RDATA" {
    const packet =
        "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x03\xc0\x00\x02";
    var iterator = try answers(packet, .dns);
    var owner_buffer: [max_name_text_len]u8 = undefined;
    var value_buffer: [max_name_text_len]u8 = undefined;
    try std.testing.expectError(error.InvalidRecordData, iterator.next(&owner_buffer, &value_buffer));

    const short_soa =
        "\x00\x00\x84\x00\x00\x00\x00\x00\x00\x01\x00\x00" ++
        "\x00\x00\x06\x00\x01\x00\x00\x00\x00\x00\x02\x00\x00";
    var authority_iterator = try authority(short_soa, .dns);
    try std.testing.expectError(error.InvalidRecordData, authority_iterator.next(&owner_buffer, &value_buffer));
}

test "DNS decoder rejects truncated and oversized names" {
    var name_buffer: [max_name_text_len]u8 = undefined;
    try std.testing.expectError(error.Truncated, decodeFirstQuestion("\x00\x01", .dns, &name_buffer));

    var packet: [12 + 4 * 64 + 1 + 4]u8 = [_]u8{0} ** (12 + 4 * 64 + 1 + 4);
    packet[5] = 1;
    var cursor: usize = 12;
    for (0..4) |_| {
        packet[cursor] = 63;
        @memset(packet[cursor + 1 .. cursor + 64], 'a');
        cursor += 64;
    }
    packet[cursor] = 0;
    try std.testing.expectError(error.NameTooLong, decodeFirstQuestion(&packet, .dns, &name_buffer));
}
