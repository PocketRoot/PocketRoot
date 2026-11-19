//! Raw HTTP/1.1 probe for reproduction scripts.
//!
//! Unlike http_inspect (HEAD/OPTIONS for security headers), this service sends the exact
//! request a reproduction needs: any method, an unnormalised path, an optional body and
//! assertions over the response. It never follows redirects.

const std = @import("std");
const capability = @import("../core/capability.zig");
const tcp_scan = @import("tcp_scan.zig");

pub const max_response_bytes = 256 * 1024;
pub const max_body_bytes = 64 * 1024;
pub const max_path_bytes = 4096;
pub const max_header_bytes = 16 * 1024;
pub const max_target_bytes = 255;

pub const Method = enum { get, post, head, put, delete };

pub const Header = struct { name: []const u8, value: []const u8 };
pub const Capture = struct { name: []const u8, prefix: []const u8, suffix: []const u8 };

pub const Spec = struct {
    arena: std.heap.ArenaAllocator,
    target: []const u8,
    method: Method,
    path: []const u8,
    body: []const u8,
    headers: []const Header,
    capture: ?Capture,
    timeout_ms: u32,
    expect_status: ?u16,
    expect_body: []const u8,
    expect_absent: []const u8,

    pub fn deinit(self: *Spec) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const HeaderWire = struct { name: []const u8 = "", value: []const u8 = "" };
const CaptureWire = struct { name: []const u8 = "", prefix: []const u8 = "", suffix: []const u8 = "" };

const SpecWire = struct {
    kind: []const u8 = "http",
    target: []const u8 = "",
    method: []const u8 = "GET",
    path: []const u8 = "/",
    body: []const u8 = "",
    headers: []const HeaderWire = &.{},
    capture: ?CaptureWire = null,
    timeout_ms: u32 = 2000,
    expect_status: ?u16 = null,
    expect_body: []const u8 = "",
    expect_absent: []const u8 = "",
};

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: u16,
    status_line: []u8,
    body: []u8,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.status_line);
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

/// Parses the JSON spec a net.http action carries. The input is copied into an arena, so
/// the returned Spec does not borrow the capability payload.
pub fn parseSpec(allocator: std.mem.Allocator, data: []const u8) !Spec {
    if (data.len > 128 * 1024) return error.SpecTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const owned = try a.dupe(u8, data);
    const wire = std.json.parseFromSliceLeaky(SpecWire, a, owned, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidHttpSpec;
    if (!std.mem.eql(u8, wire.kind, "http")) return error.InvalidHttpSpec;
    if (wire.target.len == 0 or wire.target.len > max_target_bytes) return error.InvalidTarget;
    _ = try parseTarget(wire.target);
    if (wire.path.len == 0 or wire.path.len > max_path_bytes) return error.InvalidRequestPath;
    if (wire.body.len > max_body_bytes) return error.RequestBodyTooLarge;
    if (wire.timeout_ms < 50 or wire.timeout_ms > 5000) return error.InvalidTimeout;
    if (wire.headers.len > 16) return error.TooManyHeaders;
    const headers = try a.alloc(Header, wire.headers.len);
    var header_bytes: usize = 0;
    for (wire.headers, 0..) |header, header_index| {
        if (header.name.len == 0 or header.name.len > 64) return error.InvalidHeader;
        if (header.value.len > 1024) return error.InvalidHeader;
        for (header.name) |byte| {
            if (byte <= 0x20 or byte >= 0x7f or byte == ':') return error.InvalidHeader;
        }
        for (header.value) |byte| {
            if (byte == '\r' or byte == '\n' or byte == 0) return error.InvalidHeader;
        }
        header_bytes += header.name.len + header.value.len + 4;
        headers[header_index] = .{ .name = header.name, .value = header.value };
    }
    if (header_bytes > 8 * 1024) return error.HeadersTooLarge;
    var capture: ?Capture = null;
    if (wire.capture) |value| {
        if (value.name.len == 0 or value.name.len > 64) return error.InvalidCapture;
        if (value.prefix.len == 0 or value.suffix.len == 0) return error.InvalidCapture;
        if (value.prefix.len > 1024 or value.suffix.len > 1024) return error.InvalidCapture;
        for (value.name) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '_') return error.InvalidCapture;
        }
        capture = .{ .name = value.name, .prefix = value.prefix, .suffix = value.suffix };
    }
    const method = std.meta.stringToEnum(Method, wire.method) orelse blk: {
        // Accept upper-case spellings from the DSL.
        if (std.ascii.eqlIgnoreCase(wire.method, "GET")) break :blk Method.get;
        if (std.ascii.eqlIgnoreCase(wire.method, "POST")) break :blk Method.post;
        if (std.ascii.eqlIgnoreCase(wire.method, "HEAD")) break :blk Method.head;
        if (std.ascii.eqlIgnoreCase(wire.method, "PUT")) break :blk Method.put;
        if (std.ascii.eqlIgnoreCase(wire.method, "DELETE")) break :blk Method.delete;
        return error.InvalidMethod;
    };
    if (wire.path[0] != '/' and !std.mem.eql(u8, wire.path, "*")) return error.InvalidRequestPath;
    for (wire.path) |byte| {
        if (byte < 0x21 or byte == 0x7f) return error.InvalidRequestPath;
    }
    return .{
        .arena = arena,
        .target = wire.target,
        .method = method,
        .path = wire.path,
        .body = wire.body,
        .headers = headers,
        .capture = capture,
        .timeout_ms = wire.timeout_ms,
        .expect_status = wire.expect_status,
        .expect_body = wire.expect_body,
        .expect_absent = wire.expect_absent,
    };
}

pub fn isHttpSpec(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"kind\":\"http\"") != null;
}

const Target = struct { host: []const u8, port: u16 };

fn parseTarget(text: []const u8) !Target {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidTarget;
    const host = std.mem.trim(u8, text[0..colon], " \t");
    const port = std.fmt.parseInt(u16, std.mem.trim(u8, text[colon + 1 ..], " \t"), 10) catch
        return error.InvalidTarget;
    if (host.len == 0 or port == 0) return error.InvalidTarget;
    for (host) |byte| {
        if (byte < 0x21 or byte == 0x7f or byte == '/' or byte == '\\') return error.InvalidTarget;
    }
    return .{ .host = host, .port = port };
}

fn methodText(method: Method) []const u8 {
    return switch (method) {
        .get => "GET",
        .post => "POST",
        .head => "HEAD",
        .put => "PUT",
        .delete => "DELETE",
    };
}

/// Builds the request bytes. Connection: close makes the read terminate without parsing
/// every transfer-encoding edge case; the response parser still understands chunked bodies.
fn hasHeader(spec: *const Spec, name: []const u8) bool {
    for (spec.headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
    }
    return false;
}

fn buildRequest(allocator: std.mem.Allocator, spec: *const Spec, target: Target) ![]u8 {
    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.print("{s} {s} HTTP/1.1\r\n", .{ methodText(spec.method), spec.path });
    if (!hasHeader(spec, "Host")) {
        if (target.port == 80) {
            try writer.print("Host: {s}\r\n", .{target.host});
        } else {
            try writer.print("Host: {s}:{d}\r\n", .{ target.host, target.port });
        }
    }
    if (!hasHeader(spec, "Connection")) try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Accept: */*\r\n");
    try writer.writeAll("User-Agent: PocketRoot/1\r\n");
    if (spec.body.len > 0 or spec.method == .post or spec.method == .put) {
        if (!hasHeader(spec, "Content-Type")) try writer.writeAll("Content-Type: application/x-www-form-urlencoded\r\n");
        if (!hasHeader(spec, "Content-Length")) try writer.print("Content-Length: {d}\r\n", .{spec.body.len});
    }
    for (spec.headers) |header| {
        try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    try writer.writeAll("\r\n");
    try writer.writeAll(spec.body);
    return output.toOwnedSlice();
}

const stop_mod = @import("stop.zig");

pub const StopCheck = stop_mod.Check;

pub fn probe(allocator: std.mem.Allocator, io: std.Io, spec: *const Spec) !Response {
    return probeWithStop(allocator, io, spec, null);
}

pub fn probeWithStop(
    allocator: std.mem.Allocator,
    io: std.Io,
    spec: *const Spec,
    stop: ?StopCheck,
) !Response {
    const target = try parseTarget(spec.target);
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(spec.timeout_ms),
        .clock = .awake,
    });
    const timeout: std.Io.Timeout = .{ .deadline = deadline };
    var address = try tcp_scan.resolveWithTimeout(io, target.host, target.port, timeout);
    address.setPort(target.port);
    const stream = try tcp_scan.connectWithTimeout(io, &address, timeout);
    defer stream.close(io);

    const request = try buildRequest(allocator, spec, target);
    defer allocator.free(request);
    try tcp_scan.writeSmallRequestWithTimeout(io, stream, request, timeout);

    const raw = try allocator.alloc(u8, max_response_bytes);
    defer allocator.free(raw);
    var reader_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var total: usize = 0;
    while (total < raw.len) {
        if (stop) |check| {
            if (check.isStopped(check.context)) return error.Stopped;
        }
        const now = std.Io.Clock.Timestamp.now(io, .awake);
        if (now.raw.nanoseconds >= deadline.raw.nanoseconds) {
            if (total == 0) return error.Timeout;
            break;
        }
        const slice_timeout: std.Io.Timeout = .{ .deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = std.Io.Duration.fromMilliseconds(100),
            .clock = .awake,
        }) };
        const count = tcp_scan.readWithTimeout(io, &reader, raw[total..], slice_timeout) catch |err| switch (err) {
            error.Timeout => {
                if (stop) |check| {
                    if (check.isStopped(check.context)) return error.Stopped;
                }
                continue;
            },
            else => return err,
        };
        if (count == 0) break;
        total += count;
    }
    if (total == raw.len) return error.ResponseTooLarge;
    if (total == 0) return error.EmptyHttpResponse;

    return parseResponse(allocator, raw[0..total]);
}

fn headerEnd(response: []const u8) ?usize {
    return std.mem.indexOf(u8, response, "\r\n\r\n") orelse std.mem.indexOf(u8, response, "\n\n");
}

fn parseResponse(allocator: std.mem.Allocator, raw: []const u8) !Response {
    const headers_end = headerEnd(raw) orelse return error.IncompleteHttpHeaders;
    const separator_len: usize = if (std.mem.startsWith(u8, raw[headers_end..], "\r\n\r\n")) 4 else 2;
    const status_end = std.mem.indexOfScalar(u8, raw, '\n') orelse return error.InvalidHttpResponse;
    const status_line = std.mem.trimEnd(u8, raw[0..status_end], "\r");
    var tokens = std.mem.tokenizeScalar(u8, status_line, ' ');
    _ = tokens.next() orelse return error.InvalidHttpResponse;
    const status_text = tokens.next() orelse return error.InvalidHttpResponse;
    const status = std.fmt.parseInt(u16, status_text, 10) catch return error.InvalidHttpResponse;
    if (status < 100 or status > 599) return error.InvalidHttpResponse;

    const headers = raw[status_end + 1 .. headers_end];
    var content_length: ?usize = null;
    var chunked = false;
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const name = std.mem.trim(u8, trimmed[0..colon], " \t");
        const value = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidHttpResponse;
        } else if (std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") and
            std.ascii.indexOfIgnoreCase(value, "chunked") != null)
        {
            chunked = true;
        }
    }

    const body_start = headers_end + separator_len;
    const raw_body = raw[body_start..];
    const body = if (chunked)
        try decodeChunked(allocator, raw_body)
    else if (content_length) |expected| blk: {
        if (raw_body.len < expected) return error.IncompleteHttpBody;
        break :blk try allocator.dupe(u8, raw_body[0..expected]);
    } else try allocator.dupe(u8, raw_body);
    errdefer allocator.free(body);
    if (body.len > max_body_bytes) return error.ResponseBodyTooLarge;

    return .{
        .allocator = allocator,
        .status = status,
        .status_line = try allocator.dupe(u8, status_line),
        .body = body,
    };
}

fn decodeChunked(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var position: usize = 0;
    while (position < raw.len) {
        const line_end = std.mem.indexOfPos(u8, raw, position, "\r\n") orelse break;
        var size_text = raw[position..line_end];
        if (std.mem.indexOfScalar(u8, size_text, ';')) |extension| size_text = size_text[0..extension];
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_text, " \t"), 16) catch
            return error.InvalidChunk;
        position = line_end + 2;
        if (size == 0) return output.toOwnedSlice(allocator);
        if (position + size > raw.len) return error.IncompleteChunk;
        try output.appendSlice(allocator, raw[position .. position + size]);
        if (output.items.len > max_body_bytes) return error.ResponseBodyTooLarge;
        position += size;
        if (position + 1 < raw.len and raw[position] == '\r' and raw[position + 1] == '\n') {
            position += 2;
        } else break;
    }
    return error.IncompleteChunk;
}

fn findBetween(body: []const u8, prefix: []const u8, suffix: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, body, prefix) orelse return null;
    const from = start + prefix.len;
    if (from > body.len) return null;
    const end = std.mem.indexOfPos(u8, body, from, suffix) orelse return null;
    return body[from..end];
}

fn appendEscaped(writer: *std.Io.Writer, text: []const u8) !void {
    const limit = @min(text.len, 512);
    for (text[0..limit]) |byte| {
        switch (byte) {
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x20...0x7e => try writer.writeByte(byte),
            else => try writer.writeByte('?'),
        }
    }
}

/// Runs a spec and turns the response into the key=value payload scripts bind. Oracle
/// failures are returned as succeeded with oracle=fail so the script can decide and fail
/// with a message; transport and parse errors are failed results.
pub fn execute(allocator: std.mem.Allocator, io: std.Io, payload: []const u8) !capability.Result {
    var spec = parseSpec(allocator, payload) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    defer spec.deinit();
    var response = probe(allocator, io, &spec) catch |err| {
        return capability.Result.init(allocator, .failed, @errorName(err));
    };
    defer response.deinit();

    var oracle_pass = true;
    var reason_buffer: [256]u8 = undefined;
    var reason: []const u8 = "ok";
    if (spec.expect_status) |expected| {
        if (response.status != expected) {
            oracle_pass = false;
            reason = std.fmt.bufPrint(&reason_buffer, "status={d} expected={d}", .{ response.status, expected }) catch "status mismatch";
        }
    }
    if (oracle_pass and spec.expect_body.len > 0 and std.mem.indexOf(u8, response.body, spec.expect_body) == null) {
        oracle_pass = false;
        reason = "expected body marker absent";
    }
    if (oracle_pass and spec.expect_absent.len > 0 and std.mem.indexOf(u8, response.body, spec.expect_absent) != null) {
        oracle_pass = false;
        reason = "forbidden body marker present";
    }

    var output = std.Io.Writer.Allocating.init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.print("status={d}\n", .{response.status});
    try writer.print("status_line={s}\n", .{response.status_line});
    try writer.print("body_bytes={d}\n", .{response.body.len});
    try writer.writeAll("body_prefix=");
    try appendEscaped(writer, response.body);
    try writer.writeAll("\ncaptured=");
    var capture_found = false;
    if (spec.capture) |capture| {
        if (findBetween(response.body, capture.prefix, capture.suffix)) |value| {
            capture_found = true;
            try appendEscaped(writer, value);
        }
    }
    try writer.print("\ncapture_found={d}", .{@intFromBool(capture_found)});
    try writer.writeByte('\n');
    try writer.print("oracle={s}\n", .{if (oracle_pass) "pass" else "fail"});
    try writer.print("oracle_reason={s}\n", .{reason});
    return capability.Result.init(allocator, .succeeded, output.written());
}

fn serveOne(server: *std.Io.net.Server, io: std.Io, response: []const u8) std.Io.Cancelable!void {
    const stream = server.accept(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    defer stream.close(io);
    var reader_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var request: [2048]u8 = undefined;
    var slices = [_][]u8{request[0..]};
    _ = reader.interface.readVec(&slices) catch return;
    tcp_scan.writeSmallRequestWithTimeout(io, stream, response, .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(500),
        .clock = .awake,
    } }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

test "http probe sends a raw path and evaluates status and body" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\nroot:x:0:0\nroot:/root:/bin/sh\n";
    try group.concurrent(std.testing.io, serveOne, .{ &server, std.testing.io, response });
    const port = server.socket.address.getPort();

    const spec = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"kind":"http","target":"127.0.0.1:{d}","method":"GET","path":"/cgi-bin/.%2e/etc/passwd","expect_status":200,"expect_body":"root:x:0:0"}}
    , .{port});
    defer std.testing.allocator.free(spec);
    var result = try execute(std.testing.allocator, std.testing.io, spec);
    defer result.deinit();
    try group.await(std.testing.io);
    try std.testing.expectEqual(capability.Status.succeeded, result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "status=200") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "oracle=pass") != null);
}

test "http probe reports an oracle failure without hiding the response" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    const response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied";
    try group.concurrent(std.testing.io, serveOne, .{ &server, std.testing.io, response });
    const port = server.socket.address.getPort();

    const spec = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"kind":"http","target":"127.0.0.1:{d}","method":"GET","path":"/safe","expect_status":200}}
    , .{port});
    defer std.testing.allocator.free(spec);
    var result = try execute(std.testing.allocator, std.testing.io, spec);
    defer result.deinit();
    try group.await(std.testing.io);
    try std.testing.expectEqual(capability.Status.succeeded, result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "status=403") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "oracle=fail") != null);
}

test "http probe decodes a chunked body" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    const response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nuid=0\r\n0\r\n\r\n";
    try group.concurrent(std.testing.io, serveOne, .{ &server, std.testing.io, response });
    const port = server.socket.address.getPort();

    const spec = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"kind":"http","target":"127.0.0.1:{d}","method":"POST","path":"/form","body":"x=1","expect_status":200,"expect_body":"uid=0"}}
    , .{port});
    defer std.testing.allocator.free(spec);
    var result = try execute(std.testing.allocator, std.testing.io, spec);
    defer result.deinit();
    try group.await(std.testing.io);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "oracle=pass") != null);
}

test "http spec rejects header and path injection" {
    try std.testing.expectError(error.InvalidRequestPath, parseSpec(std.testing.allocator,
        \\{"kind":"http","target":"127.0.0.1:80","path":"/x X-Evil: 1"}
    ));
    try std.testing.expectError(error.InvalidTarget, parseSpec(std.testing.allocator,
        \\{"kind":"http","target":"127.0.0.1","path":"/"}
    ));
}

fn serveHeader(server: *std.Io.net.Server, io: std.Io) std.Io.Cancelable!void {
    const stream = server.accept(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    defer stream.close(io);
    var reader_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var request: [2048]u8 = undefined;
    var slices = [_][]u8{request[0..]};
    const count = reader.interface.readVec(&slices) catch return;
    const has_header = std.mem.indexOf(u8, request[0..count], "X-Test: yes\r\n") != null;
    const response = if (has_header)
        "HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\ncaptured=yes;header-ok"
    else
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied";
    tcp_scan.writeSmallRequestWithTimeout(io, stream, response, .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(500),
        .clock = .awake,
    } }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

test "http probe sends custom headers and uses them in the oracle" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, serveHeader, .{ &server, std.testing.io });
    const port = server.socket.address.getPort();

    const spec = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"kind":"http","target":"127.0.0.1:{d}","method":"GET","path":"/","headers":[{{"name":"X-Test","value":"yes"}}],"capture":{{"name":"marker","prefix":"captured=","suffix":";"}},"expect_status":200,"expect_body":"header-ok"}}
    , .{port});
    defer std.testing.allocator.free(spec);
    var result = try execute(std.testing.allocator, std.testing.io, spec);
    defer result.deinit();
    try group.await(std.testing.io);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "oracle=pass") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "captured=yes") != null);
}

test "http spec rejects header injection" {
    try std.testing.expectError(error.InvalidHeader, parseSpec(std.testing.allocator,
        \\{"kind":"http","target":"127.0.0.1:80","headers":[{"name":"X-Test: evil","value":"1"}]}
    ));
}
