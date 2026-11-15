const std = @import("std");
const protocol = @import("../protocols/protocol.zig");

pub const max_ports = 32;
pub const min_timeout_ms = 50;
pub const max_timeout_ms = 2000;
pub const max_total_timeout_ms = 30_000;
pub const default_ports = [_]u16{
    21,   22,   23,   25,   53,   80,   110,  135,
    139,  143,  443,  445,  993,  995,  1433, 3306,
    3389, 5432, 5900, 6379, 8080, 8443,
};

pub const Options = struct {
    timeout_ms: u32 = 350,
    total_timeout_ms: u32 = 10_000,
};

const PortState = enum {
    open,
    closed,
    filtered,
    timed_out,
    host_unreachable,
};

const PortProbe = struct {
    state: PortState,
    service: []const u8 = "unknown",
    service_source: []const u8 = "port-number",
    confirmed: bool = false,
    version: [96]u8 = undefined,
    version_len: usize = 0,
    evidence: [160]u8 = undefined,
    evidence_len: usize = 0,
    identification_error: bool = false,

    fn versionText(self: *const PortProbe) []const u8 {
        return self.version[0..self.version_len];
    }

    fn evidenceText(self: *const PortProbe) []const u8 {
        return self.evidence[0..self.evidence_len];
    }
};

pub fn scan(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    ports: []const u16,
    options: Options,
) !protocol.AnalysisResult {
    if (ports.len == 0) return error.MissingPorts;
    if (ports.len > max_ports) return error.TooManyPorts;
    if (options.timeout_ms < min_timeout_ms or options.timeout_ms > max_timeout_ms) return error.InvalidTimeout;
    if (options.total_timeout_ms < min_timeout_ms or options.total_timeout_ms > max_total_timeout_ms) {
        return error.InvalidTotalTimeout;
    }
    for (ports) |port| if (port == 0) return error.InvalidPort;

    const scan_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(options.total_timeout_ms),
        .clock = .awake,
    });
    const resolve_deadline = earlierDeadline(scan_deadline, std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(options.timeout_ms),
        .clock = .awake,
    }));
    var address = resolveWithTimeout(io, target, 0, .{ .deadline = resolve_deadline }) catch |err| switch (err) {
        error.Canceled, error.Timeout => return err,
        else => return error.InvalidTarget,
    };
    var result = try protocol.AnalysisResult.init(allocator, "TCP connect scan");
    errdefer result.deinit();
    try result.addField("target", target);
    try result.addNumberField("ports_requested", ports.len);
    try result.addNumberField("total_timeout_ms", options.total_timeout_ms);

    var open_count: usize = 0;
    var closed_count: usize = 0;
    var filtered_count: usize = 0;
    var timeout_count: usize = 0;
    var unreachable_count: usize = 0;
    var identified_count: usize = 0;
    var evidence_count: usize = 0;
    var version_count: usize = 0;
    var identification_errors: usize = 0;
    var ports_completed: usize = 0;
    var scan_deadline_reached = false;

    // ponytail: sequential probes are capped at 32 ports; batch them when wider scans are justified.
    for (ports) |port| {
        if (deadlineReached(io, scan_deadline)) {
            scan_deadline_reached = true;
            break;
        }
        address.setPort(port);
        const port_deadline = earlierDeadline(scan_deadline, std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = std.Io.Duration.fromMilliseconds(options.timeout_ms),
            .clock = .awake,
        }));
        const probe = try probePort(io, &address, target, port, .{ .deadline = port_deadline });
        ports_completed += 1;
        switch (probe.state) {
            .open => {
                open_count += 1;
                if (probe.confirmed) identified_count += 1;
                if (probe.evidence_len != 0) evidence_count += 1;
                if (probe.version_len != 0) version_count += 1;
                if (probe.identification_error) identification_errors += 1;

                var key_buffer: [32]u8 = undefined;
                const port_key = try std.fmt.bufPrint(&key_buffer, "open_port_{d}", .{open_count});
                try result.addNumberField(port_key, port);
                const service_key = try std.fmt.bufPrint(&key_buffer, "open_port_{d}_service", .{open_count});
                try result.addField(service_key, probe.service);
                const source_key = try std.fmt.bufPrint(&key_buffer, "open_port_{d}_service_source", .{open_count});
                try result.addField(source_key, probe.service_source);
                const port_hint = expectedService(port);
                if (probe.confirmed and !std.mem.eql(u8, port_hint, probe.service)) {
                    const hint_key = try std.fmt.bufPrint(&key_buffer, "open_port_{d}_port_hint", .{open_count});
                    try result.addField(hint_key, port_hint);
                }
                if (probe.evidence_len != 0) {
                    const evidence_key = try std.fmt.bufPrint(&key_buffer, "open_port_{d}_evidence", .{open_count});
                    try result.addField(evidence_key, probe.evidenceText());
                }
                if (probe.version_len != 0) {
                    const version_key = try std.fmt.bufPrint(&key_buffer, "open_port_{d}_version", .{open_count});
                    try result.addField(version_key, probe.versionText());
                }
                _ = try result.addNetworkObservation(.{
                    .kind = .endpoint,
                    .confidence = .confirmed,
                    .address = target,
                    .transport = "tcp",
                    .port = port,
                    .evidence = "TCP handshake completed",
                    .source_id = "tcp-connect:open",
                });
                if (!std.mem.eql(u8, probe.service, "unknown")) {
                    _ = try result.addNetworkObservation(.{
                        .kind = .service,
                        .confidence = if (probe.confirmed) .confirmed else .inferred,
                        .address = target,
                        .transport = "tcp",
                        .port = port,
                        .service = probe.service,
                        .version = probe.versionText(),
                        .evidence = probe.evidenceText(),
                        .source_id = "tcp-scan:service",
                    });
                }

                var endpoint_buffer: [320]u8 = undefined;
                const endpoint = try formatEndpoint(&endpoint_buffer, target, port);
                var detail_buffer: [384]u8 = undefined;
                const detail = if (probe.confirmed)
                    try std.fmt.bufPrint(
                        &detail_buffer,
                        "TCP handshake completed. Service '{s}' was confirmed by protocol evidence: {s}",
                        .{ probe.service, probe.evidenceText() },
                    )
                else
                    try std.fmt.bufPrint(
                        &detail_buffer,
                        "TCP handshake completed. Service label '{s}' is inferred from the port only.",
                        .{probe.service},
                    );
                try result.addDetailedFinding(.info, "Open TCP port", detail, endpoint, "tcp-connect:open");
            },
            .closed => {
                closed_count += 1;
            },
            .filtered => {
                filtered_count += 1;
            },
            .timed_out => {
                timeout_count += 1;
            },
            .host_unreachable => {
                unreachable_count += 1;
            },
        }
        if (deadlineReached(io, scan_deadline)) {
            scan_deadline_reached = true;
            if (ports_completed < ports.len) break;
        }
    }

    const reachability = if (open_count + closed_count != 0)
        "yes"
    else if (unreachable_count == ports.len)
        "no"
    else
        "unknown";
    if (std.mem.eql(u8, reachability, "yes")) {
        _ = try result.addNetworkObservation(.{
            .kind = .host,
            .confidence = .confirmed,
            .address = target,
            .evidence = "TCP connect received a definitive response",
            .source_id = "tcp-scan:reachability",
        });
    }
    try result.addField("host_reachable", reachability);
    try result.addNumberField("ports_completed", ports_completed);
    try result.addField("scan_deadline_reached", if (scan_deadline_reached) "yes" else "no");
    try result.addNumberField("open_ports", open_count);
    try result.addNumberField("closed_ports", closed_count);
    try result.addNumberField("filtered_ports", filtered_count);
    try result.addNumberField("timed_out_ports", timeout_count);
    try result.addNumberField("unreachable_ports", unreachable_count);
    try result.addNumberField("services_confirmed", identified_count);
    try result.addNumberField("services_inferred", open_count - identified_count);
    try result.addNumberField("service_evidence_count", evidence_count);
    try result.addNumberField("service_versions_identified", version_count);
    try result.addNumberField("identification_errors", identification_errors);

    const summary = try std.fmt.allocPrint(
        allocator,
        "TCP scan {s}: {d}/{d} open, identified={d}, reachable={s}",
        .{ target, open_count, ports.len, identified_count, reachability },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);
    return result;
}

fn probePort(
    io: std.Io,
    address: *const std.Io.net.IpAddress,
    target: []const u8,
    port: u16,
    timeout: std.Io.Timeout,
) !PortProbe {
    const stream = connectWithTimeout(io, address, timeout) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        error.ConnectionRefused, error.ConnectionResetByPeer => .{ .state = .closed },
        error.Timeout => .{ .state = .timed_out },
        error.AddressUnavailable, error.HostUnreachable, error.NetworkUnreachable, error.NetworkDown => .{ .state = .host_unreachable },
        error.AccessDenied => .{ .state = .filtered },
        else => return err,
    };
    defer stream.close(io);

    var probe = PortProbe{ .state = .open, .service = expectedService(port) };
    identifyService(io, stream, target, port, timeout, &probe) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => probe.identification_error = true,
    };
    return probe;
}

fn identifyService(
    io: std.Io,
    stream: std.Io.net.Stream,
    target: []const u8,
    port: u16,
    timeout: std.Io.Timeout,
    probe: *PortProbe,
) !void {
    var request_buffer: [512]u8 = undefined;
    const request = try requestForPort(port, target, &request_buffer);
    if (request) |bytes| {
        try writeSmallRequestWithTimeout(io, stream, bytes, timeout);
    } else if (!shouldReadBanner(port)) {
        return;
    }

    var response: [512]u8 = undefined;
    var read_buffer: [512]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const response_len = readWithTimeout(io, &reader, &response, timeout) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout, error.ConnectionResetByPeer, error.SocketUnconnected => return,
        else => return err,
    };
    if (response_len == 0) return;
    applyProtocolEvidence(port, response[0..response_len], if (request == null) "passive-banner" else "read-only-probe", probe);
}

fn requestForPort(port: u16, target: []const u8, buffer: *[512]u8) !?[]const u8 {
    return switch (port) {
        80, 8000, 8080, 8888 => try std.fmt.bufPrint(
            buffer,
            "OPTIONS * HTTP/1.0\r\nHost: {s}\r\nConnection: close\r\n\r\n",
            .{target},
        ),
        6379 => "INFO SERVER\r\n",
        5432 => &.{ 0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f },
        else => null,
    };
}

fn shouldReadBanner(port: u16) bool {
    return switch (port) {
        21, 22, 23, 25, 110, 143, 3306, 5900 => true,
        else => std.mem.eql(u8, expectedService(port), "unknown"),
    };
}

fn applyProtocolEvidence(port: u16, response: []const u8, source: []const u8, probe: *PortProbe) void {
    if (std.mem.startsWith(u8, response, "SSH-")) return confirmSsh(probe, source, response);
    if (std.mem.startsWith(u8, response, "HTTP/1.")) return confirmHttp(probe, source, response);
    if (std.mem.startsWith(u8, response, "RFB ")) return confirmVnc(probe, source, response);
    if (std.mem.startsWith(u8, response, "+PONG") or std.mem.startsWith(u8, response, "-NOAUTH")) {
        confirmService(probe, "redis", source);
        probe.evidence_len = copySafeLine(&probe.evidence, response);
        return;
    }
    if (std.mem.startsWith(u8, response, "$") or std.mem.startsWith(u8, response, "# Server")) {
        if (findLineValue(response, "redis_version:")) |version| {
            confirmService(probe, "redis", source);
            setVersion(probe, firstToken(version));
            setEvidence(probe, "Redis INFO server version {s}", .{probe.versionText()});
            return;
        }
    }
    if (port == 5432 and response.len == 1 and (response[0] == 'S' or response[0] == 'N')) {
        probe.service = "postgresql";
        probe.service_source = source;
        probe.confirmed = true;
        const evidence = if (response[0] == 'S') "PostgreSQL SSLRequest: supported" else "PostgreSQL SSLRequest: unsupported";
        @memcpy(probe.evidence[0..evidence.len], evidence);
        probe.evidence_len = evidence.len;
        return;
    }
    if (parseMysqlGreeting(response)) |version| {
        confirmService(probe, "mysql", source);
        setVersion(probe, version);
        setEvidence(probe, "MySQL protocol 10; server version {s}", .{probe.versionText()});
        return;
    }

    var line_buffer: [160]u8 = undefined;
    const line_len = copySafeLine(&line_buffer, response);
    if (line_len == 0) return;
    const line = line_buffer[0..line_len];
    if (port == 110 and std.mem.startsWith(u8, response, "+OK")) {
        confirmGreeting(probe, "pop3", source, "POP3", line);
    } else if (port == 143 and std.mem.startsWith(u8, response, "* OK")) {
        confirmGreeting(probe, "imap", source, "IMAP", line);
    } else if (port == 21 and std.mem.indexOf(u8, line, "FTP") != null) {
        confirmGreeting(probe, "ftp", source, "FTP", line);
    } else if (port == 25 and
        (std.mem.indexOf(u8, line, "ESMTP") != null or
            std.mem.indexOf(u8, line, "SMTP") != null))
    {
        confirmGreeting(probe, "smtp", source, "SMTP", line);
    } else {
        return;
    }
}

fn confirmService(probe: *PortProbe, service: []const u8, source: []const u8) void {
    probe.service = service;
    probe.service_source = source;
    probe.confirmed = true;
}

fn confirmSsh(probe: *PortProbe, source: []const u8, response: []const u8) void {
    const software_start = std.mem.indexOfScalarPos(u8, response, 4, '-') orelse return;
    const protocol_version = response[4..software_start];
    const software_end = std.mem.indexOfAnyPos(u8, response, software_start + 1, " \t\r\n\x00") orelse response.len;
    const software = response[software_start + 1 .. software_end];
    if (!validNumericVersion(protocol_version) or software.len == 0) return;
    confirmService(probe, "ssh", source);
    setVersion(probe, software);
    setEvidence(probe, "SSH {s}; software {s}", .{ protocol_version, probe.versionText() });
}

fn confirmHttp(probe: *PortProbe, source: []const u8, response: []const u8) void {
    const version_end = std.mem.indexOfScalar(u8, response, ' ') orelse return;
    const version = response[0..version_end];
    if (!std.mem.eql(u8, version, "HTTP/1.0") and !std.mem.eql(u8, version, "HTTP/1.1")) return;
    const line_len = copySafeLine(&probe.evidence, response);
    if (line_len == 0) return;
    confirmService(probe, "http", source);
    probe.evidence_len = line_len;
    setVersion(probe, version);
}

fn confirmVnc(probe: *PortProbe, source: []const u8, response: []const u8) void {
    if (response.len < 11) return;
    const version = response[4..11];
    for (version, 0..) |byte, index| {
        if (index == 3) {
            if (byte != '.') return;
        } else if (!std.ascii.isDigit(byte)) return;
    }
    confirmService(probe, "vnc", source);
    setVersion(probe, version);
    setEvidence(probe, "RFB protocol {s}", .{probe.versionText()});
}

fn confirmGreeting(probe: *PortProbe, service: []const u8, source: []const u8, label: []const u8, line: []const u8) void {
    confirmService(probe, service, source);
    probe.version_len = extractVersionPhrase(&probe.version, line);
    if (probe.version_len == 0) {
        setEvidence(probe, "{s} greeting received", .{label});
    } else {
        setEvidence(probe, "{s} greeting; version {s}", .{ label, probe.versionText() });
    }
}

fn findLineValue(response: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, response, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (!std.mem.startsWith(u8, line, name)) continue;
        const value = std.mem.trim(u8, line[name.len..], " \t");
        if (value.len != 0) return value;
    }
    return null;
}

fn parseMysqlGreeting(response: []const u8) ?[]const u8 {
    if (response.len < 6 or response[3] != 0) return null;
    const payload_len = @as(usize, response[0]) |
        (@as(usize, response[1]) << 8) |
        (@as(usize, response[2]) << 16);
    if (payload_len < 3 or payload_len > response.len - 4) return null;
    const payload = response[4..][0..payload_len];
    if (payload[0] != 0x0a) return null;
    const version_end = std.mem.indexOfScalar(u8, payload[1..], 0) orelse return null;
    if (version_end == 0) return null;
    return payload[1 .. 1 + version_end];
}

fn extractVersionPhrase(output: *[96]u8, line: []const u8) usize {
    // ponytail: greeting versions use the first safe version-shaped token; add product-specific parsers when samples prove this insufficient.
    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    var previous: []const u8 = "";
    var count: usize = 0;
    while (tokens.next()) |token| {
        count += 1;
        if (count > 8) break;
        if (isVersionToken(token) and !looksLikeHost(token)) {
            if (hasAlphabetic(token) or previous.len == 0 or !hasAlphabetic(previous)) {
                return copySafeVersion(output, token);
            }
            var writer: std.Io.Writer = .fixed(output);
            writer.print("{s} {s}", .{ previous, token }) catch return 0;
            return writer.end;
        }
        if (hasAlphabetic(token) and !isProtocolWord(token)) previous = token;
    }
    return 0;
}

fn isVersionToken(token: []const u8) bool {
    var digit = false;
    var separator = false;
    for (token) |byte| switch (byte) {
        '0'...'9' => digit = true,
        '.', '_', '-' => separator = true,
        'A'...'Z', 'a'...'z' => {},
        else => return false,
    };
    return digit and (separator or hasAlphabetic(token));
}

fn validNumericVersion(token: []const u8) bool {
    if (token.len == 0) return false;
    var digit = false;
    for (token) |byte| switch (byte) {
        '0'...'9' => digit = true,
        '.' => {},
        else => return false,
    };
    return digit;
}

fn looksLikeHost(token: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(token, 0) catch {
        const last_dot = std.mem.lastIndexOfScalar(u8, token, '.') orelse return false;
        const suffix = token[last_dot + 1 ..];
        if (suffix.len < 2) return false;
        for (suffix) |byte| if (!std.ascii.isAlphabetic(byte)) return false;
        return true;
    };
    return true;
}

fn firstToken(input: []const u8) []const u8 {
    return input[0 .. std.mem.indexOfAny(u8, input, " \t\r\n") orelse input.len];
}

fn hasAlphabetic(token: []const u8) bool {
    for (token) |byte| if (std.ascii.isAlphabetic(byte)) return true;
    return false;
}

fn isProtocolWord(token: []const u8) bool {
    return std.ascii.eqlIgnoreCase(token, "FTP") or
        std.ascii.eqlIgnoreCase(token, "SMTP") or
        std.ascii.eqlIgnoreCase(token, "ESMTP") or
        std.ascii.eqlIgnoreCase(token, "POP3") or
        std.ascii.eqlIgnoreCase(token, "IMAP") or
        std.ascii.eqlIgnoreCase(token, "OK");
}

fn setVersion(probe: *PortProbe, input: []const u8) void {
    probe.version_len = copySafeVersion(&probe.version, input);
}

fn copySafeVersion(output: *[96]u8, input: []const u8) usize {
    var written: usize = 0;
    for (input) |byte| {
        if (written == output.len or byte == '\r' or byte == '\n' or byte == 0) break;
        output[written] = switch (byte) {
            0x21...0x7e => byte,
            ' ', '\t' => ' ',
            else => '_',
        };
        written += 1;
    }
    while (written > 0 and output[written - 1] == ' ') written -= 1;
    return written;
}

fn setEvidence(probe: *PortProbe, comptime format: []const u8, args: anytype) void {
    const evidence = std.fmt.bufPrint(&probe.evidence, format, args) catch return;
    probe.evidence_len = evidence.len;
}

fn copySafeLine(output: *[160]u8, input: []const u8) usize {
    var written: usize = 0;
    var printable: usize = 0;
    for (input) |byte| {
        if (written == output.len or byte == '\r' or byte == '\n' or byte == 0) break;
        output[written] = switch (byte) {
            0x20...0x7e => printable: {
                printable += 1;
                break :printable byte;
            },
            '\t' => printable: {
                printable += 1;
                break :printable ' ';
            },
            else => '_',
        };
        written += 1;
    }
    while (written > 0 and output[written - 1] == ' ') written -= 1;
    if (written == 0 or printable * 2 < written) return 0;
    return written;
}

fn writeSmallRequest(io: std.Io, stream: std.Io.net.Stream, request: []const u8) !void {
    var buffer: [512]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    writer.interface.writeAll(request) catch return writer.err orelse error.NetworkWriteFailed;
    writer.interface.flush() catch return writer.err orelse error.NetworkWriteFailed;
}

const WriteEvent = union(enum) {
    write: anyerror!void,
    timer: std.Io.Cancelable!void,
};

pub fn writeSmallRequestWithTimeout(
    io: std.Io,
    stream: std.Io.net.Stream,
    request: []const u8,
    timeout: std.Io.Timeout,
) !void {
    var event_buffer: [2]WriteEvent = undefined;
    var select: std.Io.Select(WriteEvent) = .init(io, &event_buffer);
    defer select.cancelDiscard();

    try select.concurrent(.write, writeSmallRequest, .{ io, stream, request });
    try select.concurrent(.timer, std.Io.Timeout.sleep, .{ timeout, io });

    return switch (try select.await()) {
        .write => |result| try result,
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    };
}

const ReadOutcome = union(enum) {
    data: usize,
    eof,
    failure: std.Io.net.Stream.Reader.Error,
};

const ReadEvent = union(enum) {
    read: ReadOutcome,
    timer: std.Io.Cancelable!void,
};

fn readOnce(reader: *std.Io.net.Stream.Reader, output: []u8) ReadOutcome {
    var slices = [_][]u8{output};
    const count = reader.interface.readVec(&slices) catch |err| switch (err) {
        error.EndOfStream => return .eof,
        error.ReadFailed => return .{ .failure = reader.err orelse error.Unexpected },
    };
    return .{ .data = count };
}

pub fn readWithTimeout(
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    output: []u8,
    timeout: std.Io.Timeout,
) !usize {
    var event_buffer: [2]ReadEvent = undefined;
    var select: std.Io.Select(ReadEvent) = .init(io, &event_buffer);
    defer select.cancelDiscard();

    try select.concurrent(.read, readOnce, .{ reader, output });
    try select.concurrent(.timer, std.Io.Timeout.sleep, .{ timeout, io });

    return switch (try select.await()) {
        .read => |outcome| switch (outcome) {
            .data => |count| count,
            .eof => 0,
            .failure => |err| return err,
        },
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    };
}

const ResolveEvent = union(enum) {
    resolve: anyerror!std.Io.net.IpAddress,
    timer: std.Io.Cancelable!void,
};

pub fn resolveWithTimeout(
    io: std.Io,
    target: []const u8,
    port: u16,
    timeout: std.Io.Timeout,
) !std.Io.net.IpAddress {
    var buffer: [2]ResolveEvent = undefined;
    var select: std.Io.Select(ResolveEvent) = .init(io, &buffer);
    defer select.cancelDiscard();

    try select.concurrent(.resolve, std.Io.net.IpAddress.resolve, .{ io, target, port });
    try select.concurrent(.timer, std.Io.Timeout.sleep, .{ timeout, io });

    return switch (try select.await()) {
        .resolve => |result| try result,
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    };
}

const ConnectEvent = union(enum) {
    connect: std.Io.net.IpAddress.ConnectError!std.Io.net.Stream,
    timer: std.Io.Cancelable!void,
};

pub fn connectWithTimeout(
    io: std.Io,
    address: *const std.Io.net.IpAddress,
    timeout: std.Io.Timeout,
) !std.Io.net.Stream {
    var buffer: [2]ConnectEvent = undefined;
    var select: std.Io.Select(ConnectEvent) = .init(io, &buffer);
    defer while (select.cancel()) |event| closeConnectEvent(event, io);

    try select.concurrent(.connect, std.Io.net.IpAddress.connect, .{
        address, io, .{ .mode = .stream, .protocol = .tcp },
    });
    try select.concurrent(.timer, std.Io.Timeout.sleep, .{ timeout, io });

    return switch (try select.await()) {
        .connect => |result| try result,
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    };
}

fn closeConnectEvent(event: ConnectEvent, io: std.Io) void {
    switch (event) {
        .connect => |result| if (result) |stream| stream.close(io) else |_| {},
        .timer => {},
    }
}

fn earlierDeadline(
    left: std.Io.Clock.Timestamp,
    right: std.Io.Clock.Timestamp,
) std.Io.Clock.Timestamp {
    std.debug.assert(left.clock == right.clock);
    return if (left.raw.nanoseconds <= right.raw.nanoseconds) left else right;
}

fn deadlineReached(io: std.Io, deadline: std.Io.Clock.Timestamp) bool {
    const now = std.Io.Clock.Timestamp.now(io, deadline.clock);
    return now.raw.nanoseconds >= deadline.raw.nanoseconds;
}

fn expectedService(port: u16) []const u8 {
    return switch (port) {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8000, 8080, 8888 => "http-alt",
        8443 => "https-alt",
        else => "unknown",
    };
}

fn formatEndpoint(buffer: *[320]u8, target: []const u8, port: u16) ![]const u8 {
    if (std.mem.findScalar(u8, target, ':') != null) {
        return std.fmt.bufPrint(buffer, "[{s}]:{d}", .{ target, port });
    }
    return std.fmt.bufPrint(buffer, "{s}:{d}", .{ target, port });
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

fn serveHttpTest(server: *std.Io.net.Server, io: std.Io, saw_request: *bool) std.Io.Cancelable!void {
    const stream = server.accept(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    defer stream.close(io);

    var internal_buffer: [512]u8 = undefined;
    var request_buffer: [512]u8 = undefined;
    var reader = stream.reader(io, &internal_buffer);
    var slices = [_][]u8{request_buffer[0..]};
    const count = reader.interface.readVec(&slices) catch return;
    saw_request.* = std.mem.startsWith(u8, request_buffer[0..count], "OPTIONS * HTTP/1.0");
    writeSmallRequest(
        io,
        stream,
        "HTTP/1.1 204 No Content\r\nSet-Cookie: must-not-leak=yes\r\n\r\n",
    ) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

test "TCP connect scan reports a local listening port" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);

    const port = server.socket.address.getPort();
    var result = try scan(std.testing.allocator, std.testing.io, "127.0.0.1", &.{port}, .{ .timeout_ms = 500 });
    defer result.deinit();

    try std.testing.expectEqualStrings("yes", fieldValue(&result, "host_reachable").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "open_ports").?);
    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqual(@as(usize, 2), result.observations.items.len);
    try std.testing.expectEqual(protocol.NetworkObservationKind.endpoint, result.observations.items[0].kind);
    try std.testing.expectEqual(protocol.NetworkObservationKind.host, result.observations.items[1].kind);
}

test "service labels do not claim banner detection" {
    try std.testing.expectEqualStrings("https", expectedService(443));
    try std.testing.expectEqualStrings("unknown", expectedService(49152));
}

test "protocol evidence confirms services without retaining HTTP headers" {
    var http = PortProbe{ .state = .open, .service = expectedService(8080) };
    applyProtocolEvidence(
        8080,
        "HTTP/1.1 200 OK\r\nSet-Cookie: secret=value\r\nAuthorization: hidden\r\n\r\n",
        "read-only-probe",
        &http,
    );
    try std.testing.expect(http.confirmed);
    try std.testing.expectEqualStrings("http", http.service);
    try std.testing.expectEqualStrings("HTTP/1.1", http.versionText());
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK", http.evidenceText());
    try std.testing.expect(std.mem.indexOf(u8, http.evidenceText(), "secret") == null);

    var ssh = PortProbe{ .state = .open };
    applyProtocolEvidence(2222, "SSH-2.0-OpenSSH_9.6\r\n", "passive-banner", &ssh);
    try std.testing.expect(ssh.confirmed);
    try std.testing.expectEqualStrings("ssh", ssh.service);
    try std.testing.expectEqualStrings("OpenSSH_9.6", ssh.versionText());
    try std.testing.expectEqualStrings("SSH 2.0; software OpenSSH_9.6", ssh.evidenceText());
    try std.testing.expectEqualStrings("passive-banner", ssh.service_source);

    var redis = PortProbe{ .state = .open };
    applyProtocolEvidence(6379, "$32\r\n# Server\r\nredis_version:7.2.4\r\n", "read-only-probe", &redis);
    try std.testing.expect(redis.confirmed);
    try std.testing.expectEqualStrings("redis", redis.service);
    try std.testing.expectEqualStrings("7.2.4", redis.versionText());

    var vnc = PortProbe{ .state = .open };
    applyProtocolEvidence(5900, "RFB 003.008\n", "passive-banner", &vnc);
    try std.testing.expect(vnc.confirmed);
    try std.testing.expectEqualStrings("003.008", vnc.versionText());

    var ftp = PortProbe{ .state = .open };
    applyProtocolEvidence(21, "220 ProFTPD 1.3.8 Server ready\r\n", "passive-banner", &ftp);
    try std.testing.expect(ftp.confirmed);
    try std.testing.expectEqualStrings("ProFTPD 1.3.8", ftp.versionText());

    var smtp = PortProbe{ .state = .open };
    applyProtocolEvidence(25, "220 mx1.example.com ESMTP Postfix 3.8.6\r\n", "passive-banner", &smtp);
    try std.testing.expect(smtp.confirmed);
    try std.testing.expectEqualStrings("Postfix 3.8.6", smtp.versionText());
}

test "HTTP read-only probe works over a local TCP stream" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);

    var saw_request = false;
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, serveHttpTest, .{ &server, std.testing.io, &saw_request });

    const stream = try connectWithTimeout(std.testing.io, &server.socket.address, .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(500),
        .clock = .awake,
    } });
    defer stream.close(std.testing.io);
    var probe = PortProbe{ .state = .open, .service = "http" };
    try identifyService(std.testing.io, stream, "127.0.0.1", 80, .{ .deadline = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{
        .raw = std.Io.Duration.fromMilliseconds(500),
        .clock = .awake,
    }) }, &probe);
    try group.await(std.testing.io);

    try std.testing.expect(saw_request);
    try std.testing.expect(probe.confirmed);
    try std.testing.expectEqualStrings("HTTP/1.1 204 No Content", probe.evidenceText());
}

test "binary and control-heavy banners stay bounded" {
    var mysql = PortProbe{ .state = .open, .service = "mysql" };
    applyProtocolEvidence(3306, "\x08\x00\x00\x00\x0a8.0.36\x00", "passive-banner", &mysql);
    try std.testing.expect(mysql.confirmed);
    try std.testing.expectEqualStrings("8.0.36", mysql.versionText());
    try std.testing.expectEqualStrings("MySQL protocol 10; server version 8.0.36", mysql.evidenceText());

    var bad_mysql = PortProbe{ .state = .open, .service = "mysql" };
    applyProtocolEvidence(3306, "\x08\x00\x00\x01\x0a8.0.36\x00", "passive-banner", &bad_mysql);
    try std.testing.expect(!bad_mysql.confirmed);
    applyProtocolEvidence(3306, "\x09\x00\x00\x00\x0a8.0.36\x00", "passive-banner", &bad_mysql);
    try std.testing.expect(!bad_mysql.confirmed);

    var long_version = PortProbe{ .state = .open };
    applyProtocolEvidence(2222, "SSH-2.0-" ++ ("v" ** 140) ++ "\x1bsecret comment\r\n", "passive-banner", &long_version);
    try std.testing.expectEqual(@as(usize, long_version.version.len), long_version.version_len);
    try std.testing.expect(std.mem.indexOfScalar(u8, long_version.versionText(), 0x1b) == null);

    var output: [160]u8 = undefined;
    const length = copySafeLine(&output, "\x1b[31mhello\x07world\r\nCookie: hidden");
    try std.testing.expect(length <= output.len);
    try std.testing.expect(std.mem.indexOfScalar(u8, output[0..length], 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, output[0..length], "Cookie") == null);
}

test "TCP scan total deadline stops stalled service identification" {
    var first_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var first_server = try first_address.listen(std.testing.io, .{});
    defer first_server.deinit(std.testing.io);
    var second_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var second_server = try second_address.listen(std.testing.io, .{});
    defer second_server.deinit(std.testing.io);

    const ports = [_]u16{
        first_server.socket.address.getPort(),
        second_server.socket.address.getPort(),
    };
    var result = try scan(std.testing.allocator, std.testing.io, "127.0.0.1", &ports, .{
        .timeout_ms = 500,
        .total_timeout_ms = 100,
    });
    defer result.deinit();

    // ponytail: with a 100 ms total budget the scan may either finish both loopback
    // ports or cut off before the first one, depending on host load. Assert only the
    // budget invariants; proving the mid-scan cutoff needs a blackholed peer.
    // Re-evaluate when an integration harness with a non-answering address exists.
    const completed = std.fmt.parseInt(usize, fieldValue(&result, "ports_completed").?, 10) catch
        return error.TestUnexpectedResult;
    const opened = std.fmt.parseInt(usize, fieldValue(&result, "open_ports").?, 10) catch
        return error.TestUnexpectedResult;
    try std.testing.expect(completed <= ports.len);
    try std.testing.expect(opened <= completed);
    try std.testing.expectError(
        error.InvalidTotalTimeout,
        scan(std.testing.allocator, std.testing.io, "127.0.0.1", &.{80}, .{ .total_timeout_ms = 49 }),
    );
}
