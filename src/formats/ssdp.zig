const std = @import("std");

pub const max_message_len = 8 * 1024;
pub const max_start_line_len = 256;
pub const max_headers = 32;
pub const max_header_name_len = 64;
pub const max_header_value_len = 1024;

pub const Kind = enum {
    m_search,
    notify,
    response,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Message = struct {
    kind: Kind,
    first_line: []const u8,
    status_code: ?u16 = null,
    reason: []const u8 = "",
    headers: [max_headers]Header = undefined,
    header_count: usize = 0,
    header_bytes: usize = 0,
    st: ?[]const u8 = null,
    nt: ?[]const u8 = null,
    usn: ?[]const u8 = null,
    location: ?[]const u8 = null,
    server: ?[]const u8 = null,

    pub fn header(self: *const Message, name: []const u8) ?[]const u8 {
        for (self.headers[0..self.header_count]) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.value;
        }
        return null;
    }
};

pub const Error = error{
    MessageTooLarge,
    InvalidLineEnding,
    MissingHeaderTerminator,
    InvalidStartLine,
    StartLineTooLong,
    TooManyHeaders,
    InvalidHeader,
    HeaderNameTooLong,
    HeaderValueTooLong,
};

pub fn decode(data: []const u8) Error!Message {
    if (data.len > max_message_len) return error.MessageTooLarge;

    var cursor: usize = 0;
    const first_line = try nextLine(data, &cursor);
    if (first_line.len > max_start_line_len) return error.StartLineTooLong;
    const start = try decodeStartLine(first_line);

    var message: Message = .{
        .kind = start.kind,
        .first_line = first_line,
        .status_code = start.status_code,
        .reason = start.reason,
    };

    while (true) {
        const line = try nextLine(data, &cursor);
        if (line.len == 0) {
            message.header_bytes = cursor;
            return message;
        }
        if (message.header_count == max_headers) return error.TooManyHeaders;

        const separator = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = line[0..separator];
        const raw_value = line[separator + 1 ..];
        if (name.len == 0 or !validHeaderName(name)) return error.InvalidHeader;
        if (name.len > max_header_name_len) return error.HeaderNameTooLong;
        if (raw_value.len > max_header_value_len) return error.HeaderValueTooLong;
        if (!validHeaderValue(raw_value)) return error.InvalidHeader;

        const value = std.mem.trim(u8, raw_value, " \t");
        message.headers[message.header_count] = .{ .name = name, .value = value };
        message.header_count += 1;
        setKnownHeader(&message, name, value);
    }
}

const StartLine = struct {
    kind: Kind,
    status_code: ?u16 = null,
    reason: []const u8 = "",
};

fn decodeStartLine(line: []const u8) Error!StartLine {
    if (std.ascii.eqlIgnoreCase(line, "M-SEARCH * HTTP/1.1")) return .{ .kind = .m_search };
    if (std.ascii.eqlIgnoreCase(line, "NOTIFY * HTTP/1.1")) return .{ .kind = .notify };

    const version_end = std.mem.indexOfScalar(u8, line, ' ') orelse return error.InvalidStartLine;
    const version = line[0..version_end];
    if (!std.ascii.eqlIgnoreCase(version, "HTTP/1.1") and
        !std.ascii.eqlIgnoreCase(version, "HTTP/1.0")) return error.InvalidStartLine;

    const status = line[version_end + 1 ..];
    if (status.len < 4 or status[3] != ' ') return error.InvalidStartLine;
    for (status[0..3]) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidStartLine;
    }
    if (!validText(status[4..])) return error.InvalidStartLine;

    return .{
        .kind = .response,
        .status_code = @as(u16, status[0] - '0') * 100 +
            @as(u16, status[1] - '0') * 10 +
            @as(u16, status[2] - '0'),
        .reason = status[4..],
    };
}

fn nextLine(data: []const u8, cursor: *usize) Error![]const u8 {
    if (cursor.* >= data.len) return error.MissingHeaderTerminator;
    const relative_end = std.mem.indexOfScalar(u8, data[cursor.*..], '\n') orelse
        return error.MissingHeaderTerminator;
    const end = cursor.* + relative_end;
    if (end == cursor.* or data[end - 1] != '\r') return error.InvalidLineEnding;
    const line = data[cursor.* .. end - 1];
    cursor.* = end + 1;
    return line;
}

fn validHeaderName(name: []const u8) bool {
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => false,
            else => true,
        }) return false;
    }
    return true;
}

fn validHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte != '\t' and (byte < 0x20 or byte == 0x7f)) return false;
    }
    return true;
}

fn validText(value: []const u8) bool {
    return validHeaderValue(value);
}

fn setKnownHeader(message: *Message, name: []const u8, value: []const u8) void {
    if (std.ascii.eqlIgnoreCase(name, "ST")) {
        if (message.st == null) message.st = value;
    } else if (std.ascii.eqlIgnoreCase(name, "NT")) {
        if (message.nt == null) message.nt = value;
    } else if (std.ascii.eqlIgnoreCase(name, "USN")) {
        if (message.usn == null) message.usn = value;
    } else if (std.ascii.eqlIgnoreCase(name, "LOCATION")) {
        if (message.location == null) message.location = value;
    } else if (std.ascii.eqlIgnoreCase(name, "SERVER")) {
        if (message.server == null) message.server = value;
    }
}

test "decodes SSDP requests and mixed-case headers" {
    const message = try decode(
        "m-search * http/1.1\r\n" ++
            "Host: 239.255.255.250:1900\r\n" ++
            "sT: ssdp:all\r\n" ++
            "UsN: uuid:device-1\r\n" ++
            "\r\n",
    );

    try std.testing.expectEqual(Kind.m_search, message.kind);
    try std.testing.expectEqual(@as(usize, 3), message.header_count);
    try std.testing.expectEqualStrings("ssdp:all", message.st.?);
    try std.testing.expectEqualStrings("uuid:device-1", message.usn.?);
    try std.testing.expectEqualStrings("239.255.255.250:1900", message.header("HOST").?);

    const notify = try decode("NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n\r\n");
    try std.testing.expectEqual(Kind.notify, notify.kind);
    try std.testing.expectEqualStrings("upnp:rootdevice", notify.nt.?);
}

test "decodes SSDP response metadata without resolving location" {
    const message = try decode(
        "HTTP/1.1 200 OK\r\n" ++
            "LOCATION: http://192.0.2.10/device.xml\r\n" ++
            "SERVER: TestOS/1 UPnP/1.1 Product/2\r\n" ++
            "ST: upnp:rootdevice\r\n" ++
            "\r\n",
    );

    try std.testing.expectEqual(Kind.response, message.kind);
    try std.testing.expectEqual(@as(?u16, 200), message.status_code);
    try std.testing.expectEqualStrings("OK", message.reason);
    try std.testing.expectEqualStrings("http://192.0.2.10/device.xml", message.location.?);
    try std.testing.expectEqualStrings("TestOS/1 UPnP/1.1 Product/2", message.server.?);
    try std.testing.expect(message.header_bytes == message.first_line.len + 2 +
        "LOCATION: http://192.0.2.10/device.xml\r\n".len +
        "SERVER: TestOS/1 UPnP/1.1 Product/2\r\n".len +
        "ST: upnp:rootdevice\r\n\r\n".len);
}

test "rejects malformed SSDP lines" {
    try std.testing.expectError(
        error.InvalidStartLine,
        decode("SEARCH * HTTP/1.1\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        decode("M-SEARCH * HTTP/1.1\r\nBad Header: value\r\n\r\n"),
    );
    try std.testing.expectError(
        error.InvalidLineEnding,
        decode("M-SEARCH * HTTP/1.1\n\n"),
    );
    try std.testing.expectError(
        error.MissingHeaderTerminator,
        decode("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n"),
    );
}

test "enforces SSDP message header and value limits" {
    var too_many: [1024]u8 = undefined;
    var used: usize = 0;
    used += copy(too_many[used..], "NOTIFY * HTTP/1.1\r\n");
    for (0..max_headers + 1) |_| used += copy(too_many[used..], "X: y\r\n");
    used += copy(too_many[used..], "\r\n");
    try std.testing.expectError(error.TooManyHeaders, decode(too_many[0..used]));

    var long_value: [max_header_value_len + 64]u8 = undefined;
    used = 0;
    used += copy(long_value[used..], "NOTIFY * HTTP/1.1\r\nX: ");
    @memset(long_value[used .. used + max_header_value_len + 1], 'a');
    used += max_header_value_len + 1;
    used += copy(long_value[used..], "\r\n\r\n");
    try std.testing.expectError(error.HeaderValueTooLong, decode(long_value[0..used]));

    var oversized: [max_message_len + 1]u8 = undefined;
    @memset(&oversized, 'x');
    try std.testing.expectError(error.MessageTooLarge, decode(&oversized));
}

fn copy(destination: []u8, source: []const u8) usize {
    std.mem.copyForwards(u8, destination[0..source.len], source);
    return source.len;
}
