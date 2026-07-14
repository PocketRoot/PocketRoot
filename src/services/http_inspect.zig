const std = @import("std");
const protocol = @import("../protocols/protocol.zig");
const tcp_scan = @import("tcp_scan.zig");

pub const max_response_bytes = 8 * 1024;
pub const max_target_bytes = 255;
pub const max_redirects = 3;
pub const max_location_bytes = 1024;
pub const max_request_target_bytes = 1024;

pub const Method = enum {
    head,
    options,
};

pub const Options = struct {
    timeout_ms: u32 = 500,
    method: Method = .head,
};

const SecurityHeader = struct {
    name: []const u8,
    field: []const u8,
};

const security_headers = [_]SecurityHeader{
    .{ .name = "Content-Security-Policy", .field = "security_header_content_security_policy" },
    .{ .name = "Strict-Transport-Security", .field = "security_header_strict_transport_security" },
    .{ .name = "X-Content-Type-Options", .field = "security_header_x_content_type_options" },
    .{ .name = "X-Frame-Options", .field = "security_header_x_frame_options" },
    .{ .name = "Referrer-Policy", .field = "security_header_referrer_policy" },
    .{ .name = "Permissions-Policy", .field = "security_header_permissions_policy" },
};

const ParsedResponse = struct {
    status_line: []const u8,
    http_version: []const u8,
    status_code: u16,
    present: [security_headers.len]bool,
    location: ?[]const u8,
};

const RedirectOutcome = enum {
    none,
    followed,
    blocked_cross_origin,
    blocked_scheme_change,
    invalid_location,
    missing_location,
    limit_reached,
};

const RedirectTarget = union(enum) {
    follow: []const u8,
    blocked_cross_origin,
    blocked_scheme_change,
    invalid_location,
};

pub fn inspect(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    port: u16,
    options: Options,
) !protocol.AnalysisResult {
    if (target.len == 0 or target.len > max_target_bytes or
        std.mem.indexOfScalar(u8, target, '\r') != null or
        std.mem.indexOfScalar(u8, target, '\n') != null) return error.InvalidTarget;
    if (port == 0) return error.InvalidPort;
    if (options.timeout_ms < 50 or options.timeout_ms > 2000) return error.InvalidTimeout;

    const timeout: std.Io.Timeout = .{ .deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(options.timeout_ms),
        .clock = .awake,
    }) };
    var address = tcp_scan.resolveWithTimeout(io, target, port, timeout) catch |err| switch (err) {
        error.Canceled, error.Timeout => return err,
        else => return error.InvalidTarget,
    };
    address.setPort(port);
    var response: [max_response_bytes]u8 = undefined;
    var redirect_targets: [2][max_request_target_bytes]u8 = undefined;
    var current_target: []const u8 = if (options.method == .head) "/" else "*";
    var redirect_slot: usize = 0;
    var redirect_hops: usize = 0;
    var response_bytes_read: usize = 0;
    var redirect_outcome: RedirectOutcome = .none;
    var final_response: ?ParsedResponse = null;

    while (true) {
        if (response_bytes_read == max_response_bytes) return error.HttpResponseByteLimitExceeded;
        const stream = try tcp_scan.connectWithTimeout(io, &address, timeout);
        defer stream.close(io);

        var request_buffer: [max_request_target_bytes + max_target_bytes + 128]u8 = undefined;
        const request = try formatRequestTarget(&request_buffer, target, port, options.method, current_target);
        try tcp_scan.writeSmallRequestWithTimeout(io, stream, request, timeout);

        var reader_buffer: [1024]u8 = undefined;
        var reader = stream.reader(io, &reader_buffer);
        const response_len = try readHeadersWithTimeout(
            io,
            &reader,
            response[0 .. max_response_bytes - response_bytes_read],
            timeout,
        );
        response_bytes_read += response_len;
        const parsed = try parseResponse(response[0..response_len]);
        final_response = parsed;
        if (!isRedirectStatus(parsed.status_code)) {
            if (redirect_hops != 0) redirect_outcome = .followed;
            break;
        }

        const location = parsed.location orelse {
            redirect_outcome = .missing_location;
            break;
        };
        if (redirect_hops == max_redirects) {
            redirect_outcome = .limit_reached;
            break;
        }
        const resolution = resolveRedirect(
            target,
            port,
            if (std.mem.eql(u8, current_target, "*")) "/" else current_target,
            location,
            &redirect_targets[redirect_slot],
        );
        switch (resolution) {
            .follow => |next_target| {
                current_target = next_target;
                redirect_slot = (redirect_slot + 1) % redirect_targets.len;
                redirect_hops += 1;
            },
            .blocked_cross_origin => {
                redirect_outcome = .blocked_cross_origin;
                break;
            },
            .blocked_scheme_change => {
                redirect_outcome = .blocked_scheme_change;
                break;
            },
            .invalid_location => {
                redirect_outcome = .invalid_location;
                break;
            },
        }
    }
    const parsed = final_response orelse return error.EmptyHttpResponse;

    var result = try protocol.AnalysisResult.init(allocator, "HTTP inspection");
    errdefer result.deinit();
    const target_is_ip = isIpLiteral(target);
    try result.addField("target", target);
    try result.addNumberField("port", port);
    try result.addField("method", methodText(options.method));
    try result.addField("status_line", parsed.status_line);
    try result.addField("http_version", parsed.http_version);
    try result.addNumberField("redirect_hops", redirect_hops);
    try result.addField("redirect_outcome", @tagName(redirect_outcome));
    try result.addNumberField("response_bytes_read", response_bytes_read);
    for (security_headers, parsed.present) |header, present| {
        try result.addField(header.field, if (present) "present" else "absent");
    }

    _ = try result.addNetworkObservation(.{
        .kind = .host,
        .confidence = .confirmed,
        .address = if (target_is_ip) target else "",
        .hostname = if (target_is_ip) "" else target,
        .evidence = parsed.status_line,
        .source_id = "http-inspect:response",
    });
    _ = try result.addNetworkObservation(.{
        .kind = .endpoint,
        .confidence = .confirmed,
        .address = if (target_is_ip) target else "",
        .hostname = if (target_is_ip) "" else target,
        .transport = "tcp",
        .port = port,
        .evidence = parsed.status_line,
        .source_id = "http-inspect:response",
    });
    _ = try result.addNetworkObservation(.{
        .kind = .service,
        .confidence = .confirmed,
        .address = if (target_is_ip) target else "",
        .hostname = if (target_is_ip) "" else target,
        .transport = "tcp",
        .port = port,
        .service = "http",
        .version = parsed.http_version,
        .evidence = parsed.status_line,
        .source_id = "http-inspect:response",
    });

    const summary = try std.fmt.allocPrint(allocator, "HTTP {s} on {s}:{d}", .{
        parsed.status_line,
        target,
        port,
    });
    defer allocator.free(summary);
    try result.setSummary(summary);
    return result;
}

fn formatRequest(buffer: []u8, target: []const u8, port: u16, method: Method) ![]const u8 {
    return formatRequestTarget(buffer, target, port, method, if (method == .head) "/" else "*");
}

fn formatRequestTarget(buffer: []u8, target: []const u8, port: u16, method: Method, request_target: []const u8) ![]const u8 {
    if (request_target.len == 0 or request_target.len > max_request_target_bytes or
        (request_target[0] != '/' and !std.mem.eql(u8, request_target, "*")) or
        std.mem.indexOfAny(u8, request_target, "\r\n") != null) return error.InvalidRedirectLocation;
    const name = methodText(method);
    if (std.mem.indexOfScalar(u8, target, ':') != null) {
        return std.fmt.bufPrint(
            buffer,
            "{s} {s} HTTP/1.1\r\nHost: [{s}]:{d}\r\nConnection: close\r\n\r\n",
            .{ name, request_target, target, port },
        );
    }
    return std.fmt.bufPrint(
        buffer,
        "{s} {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n\r\n",
        .{ name, request_target, target, port },
    );
}

fn methodText(method: Method) []const u8 {
    return switch (method) {
        .head => "HEAD",
        .options => "OPTIONS",
    };
}

fn parseResponse(response: []const u8) !ParsedResponse {
    const headers_end = headerEnd(response) orelse return error.IncompleteHttpHeaders;
    const status_end = std.mem.indexOfScalar(u8, response, '\n') orelse return error.InvalidHttpResponse;
    if (status_end > headers_end + 1) return error.InvalidHttpResponse;

    const status_line = std.mem.trimEnd(u8, response[0..status_end], "\r");
    if (!validStatusLine(status_line)) return error.InvalidHttpResponse;

    var tokens = std.mem.tokenizeScalar(u8, status_line, ' ');
    const http_version = tokens.next() orelse return error.InvalidHttpResponse;
    const status_code = std.fmt.parseInt(u16, tokens.next() orelse return error.InvalidHttpResponse, 10) catch
        return error.InvalidHttpResponse;

    var present = [_]bool{false} ** security_headers.len;
    var location: ?[]const u8 = null;
    const headers_start = status_end + 1;
    if (headers_start < headers_end) {
        var lines = std.mem.splitScalar(u8, response[headers_start..headers_end], '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            const separator = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = std.mem.trim(u8, line[0..separator], " \t");
            if (location == null and std.ascii.eqlIgnoreCase(name, "Location")) {
                location = std.mem.trim(u8, line[separator + 1 ..], " \t");
            }
            for (security_headers, 0..) |header, index| {
                if (std.ascii.eqlIgnoreCase(name, header.name)) present[index] = true;
            }
        }
    }
    return .{
        .status_line = status_line,
        .http_version = http_version,
        .status_code = status_code,
        .present = present,
        .location = location,
    };
}

fn readHeadersWithTimeout(
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    output: []u8,
    timeout: std.Io.Timeout,
) !usize {
    var written: usize = 0;
    while (written < output.len) {
        const count = try tcp_scan.readWithTimeout(io, reader, output[written..], timeout);
        if (count == 0) return if (written == 0) error.EmptyHttpResponse else error.IncompleteHttpHeaders;
        written += count;
        if (headerEnd(output[0..written]) != null) return written;
    }
    return error.HttpResponseByteLimitExceeded;
}

fn headerEnd(response: []const u8) ?usize {
    return std.mem.indexOf(u8, response, "\r\n\r\n") orelse std.mem.indexOf(u8, response, "\n\n");
}

fn isRedirectStatus(status: u16) bool {
    return switch (status) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

fn resolveRedirect(
    target: []const u8,
    port: u16,
    current_target: []const u8,
    location: []const u8,
    output: *[max_request_target_bytes]u8,
) RedirectTarget {
    if (location.len == 0 or location.len > max_location_bytes) return .invalid_location;
    for (location) |byte| if (byte < 0x20 or byte == 0x7f) return .invalid_location;

    var base_buffer: [max_target_bytes + max_request_target_bytes + 32]u8 = undefined;
    const base_text = if (std.mem.indexOfScalar(u8, target, ':') != null)
        std.fmt.bufPrint(&base_buffer, "http://[{s}]:{d}{s}", .{ target, port, current_target }) catch return .invalid_location
    else
        std.fmt.bufPrint(&base_buffer, "http://{s}:{d}{s}", .{ target, port, current_target }) catch return .invalid_location;
    const base = std.Uri.parse(base_text) catch return .invalid_location;

    var work: [max_location_bytes + max_request_target_bytes + 16]u8 = undefined;
    @memcpy(work[0..location.len], location);
    var aux: []u8 = &work;
    const resolved = std.Uri.resolveInPlace(base, location.len, &aux) catch return .invalid_location;
    if (!std.ascii.eqlIgnoreCase(resolved.scheme, "http")) return .blocked_scheme_change;
    if (resolved.user != null or resolved.password != null) return .invalid_location;

    var host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const redirect_host = (resolved.getHost(&host_buffer) catch return .invalid_location).bytes;
    if (!std.ascii.eqlIgnoreCase(redirect_host, target) or (resolved.port orelse 80) != port) {
        return .blocked_cross_origin;
    }

    var writer: std.Io.Writer = .fixed(output);
    if (resolved.path.isEmpty()) {
        writer.writeByte('/') catch return .invalid_location;
    } else {
        resolved.path.formatPath(&writer) catch return .invalid_location;
    }
    if (resolved.query) |query| {
        writer.writeByte('?') catch return .invalid_location;
        query.formatQuery(&writer) catch return .invalid_location;
    }
    return .{ .follow = output[0..writer.end] };
}

fn validStatusLine(line: []const u8) bool {
    if (line.len == 0 or line.len > 160) return false;
    for (line) |byte| if (byte < 0x20 or byte > 0x7e) return false;

    var tokens = std.mem.tokenizeScalar(u8, line, ' ');
    const version = tokens.next() orelse return false;
    const status = tokens.next() orelse return false;
    if (!std.mem.eql(u8, version, "HTTP/1.0") and !std.mem.eql(u8, version, "HTTP/1.1")) return false;
    if (status.len != 3) return false;
    for (status) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

fn isIpLiteral(target: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(target, 0) catch return std.mem.indexOfScalar(u8, target, ':') != null;
    return true;
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

fn containsRetained(result: *const protocol.AnalysisResult, needle: []const u8) bool {
    if (std.mem.indexOf(u8, result.summary, needle) != null) return true;
    for (result.fields.items) |field| {
        if (std.mem.indexOf(u8, field.name, needle) != null or
            std.mem.indexOf(u8, field.value, needle) != null) return true;
    }
    for (result.findings.items) |finding| {
        if (std.mem.indexOf(u8, finding.message, needle) != null or
            std.mem.indexOf(u8, finding.detail, needle) != null) return true;
    }
    for (result.observations.items) |observation| {
        if (std.mem.indexOf(u8, observation.evidence, needle) != null) return true;
    }
    return false;
}

fn serveTest(server: *std.Io.net.Server, io: std.Io, saw_head: *bool) std.Io.Cancelable!void {
    const stream = server.accept(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    defer stream.close(io);

    var reader_buffer: [512]u8 = undefined;
    var request: [512]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var slices = [_][]u8{request[0..]};
    const count = reader.interface.readVec(&slices) catch return;
    saw_head.* = std.mem.startsWith(u8, request[0..count], "HEAD / HTTP/1.1\r\n");

    const timeout: std.Io.Timeout = .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(500),
        .clock = .awake,
    } };
    tcp_scan.writeSmallRequestWithTimeout(
        io,
        stream,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Security-Policy: default-src 'none'; report-uri https://header-secret.test\r\n" ++
            "X-Content-Type-Options: nosniff\r\n" ++
            "Set-Cookie: cookie-secret=value\r\n" ++
            "Authorization: bearer auth-secret\r\n\r\n" ++
            "body-secret",
        timeout,
    ) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn serveRedirectTest(
    server: *std.Io.net.Server,
    io: std.Io,
    port: u16,
    saw_targets: *[3]bool,
) std.Io.Cancelable!void {
    for (0..3) |index| {
        const stream = server.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        defer stream.close(io);

        var reader_buffer: [512]u8 = undefined;
        var request: [512]u8 = undefined;
        var reader = stream.reader(io, &reader_buffer);
        var slices = [_][]u8{request[0..]};
        const count = reader.interface.readVec(&slices) catch return;
        const expected = switch (index) {
            0 => "HEAD / HTTP/1.1\r\n",
            1 => "HEAD /next HTTP/1.1\r\n",
            else => "HEAD /final?token=redirect-secret HTTP/1.1\r\n",
        };
        saw_targets[index] = std.mem.startsWith(u8, request[0..count], expected);

        var response_buffer: [256]u8 = undefined;
        const response = switch (index) {
            0 => "HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n",
            1 => std.fmt.bufPrint(
                &response_buffer,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{d}/final?token=redirect-secret\r\n\r\n",
                .{port},
            ) catch return,
            else => "HTTP/1.0 200 OK\r\nX-Frame-Options: DENY\r\n\r\n",
        };
        tcp_scan.writeSmallRequestWithTimeout(io, stream, response, .{ .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(500),
            .clock = .awake,
        } }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
    }
}

fn serveStaticResponses(
    server: *std.Io.net.Server,
    io: std.Io,
    response: []const u8,
    count: usize,
) std.Io.Cancelable!void {
    for (0..count) |_| {
        const stream = server.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        defer stream.close(io);
        var reader_buffer: [512]u8 = undefined;
        var request: [512]u8 = undefined;
        var reader = stream.reader(io, &reader_buffer);
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
}

test "HTTP inspection retains only status and security header presence" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);

    var saw_head = false;
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, serveTest, .{ &server, std.testing.io, &saw_head });

    var result = try inspect(
        std.testing.allocator,
        std.testing.io,
        "127.0.0.1",
        server.socket.address.getPort(),
        .{ .timeout_ms = 500 },
    );
    defer result.deinit();
    try group.await(std.testing.io);

    try std.testing.expect(saw_head);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK", fieldValue(&result, "status_line").?);
    try std.testing.expectEqualStrings("HTTP/1.1", fieldValue(&result, "http_version").?);
    try std.testing.expectEqualStrings("present", fieldValue(&result, "security_header_content_security_policy").?);
    try std.testing.expectEqualStrings("absent", fieldValue(&result, "security_header_x_frame_options").?);
    try std.testing.expectEqual(@as(usize, 3), result.observations.items.len);
    try std.testing.expectEqualStrings("127.0.0.1", result.observations.items[0].address);
    try std.testing.expectEqualStrings("", result.observations.items[0].hostname);
    try std.testing.expect(!containsRetained(&result, "header-secret"));
    try std.testing.expect(!containsRetained(&result, "cookie-secret"));
    try std.testing.expect(!containsRetained(&result, "auth-secret"));
    try std.testing.expect(!containsRetained(&result, "body-secret"));

    var request_buffer: [512]u8 = undefined;
    const options_request = try formatRequest(&request_buffer, "::1", 8080, .options);
    try std.testing.expect(std.mem.startsWith(u8, options_request, "OPTIONS * HTTP/1.1\r\nHost: [::1]:8080\r\n"));
    try std.testing.expectError(error.IncompleteHttpHeaders, parseResponse("HTTP/1.1 200 OK\r\nServer: partial"));
    try std.testing.expectError(
        error.InvalidTimeout,
        inspect(std.testing.allocator, std.testing.io, "127.0.0.1", 80, .{ .timeout_ms = 49 }),
    );
    try std.testing.expectError(
        error.InvalidTarget,
        inspect(std.testing.allocator, std.testing.io, "x" ** (max_target_bytes + 1), 80, .{}),
    );
}

test "HTTP observation identity distinguishes IP literals and DNS names" {
    try std.testing.expect(isIpLiteral("192.0.2.1"));
    try std.testing.expect(isIpLiteral("2001:db8::1"));
    try std.testing.expect(!isIpLiteral("service.example"));
}

test "HTTP inspection follows at most same-origin HTTP redirects" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);

    const port = server.socket.address.getPort();
    var saw_targets = [_]bool{false} ** 3;
    var group: std.Io.Group = .init;
    defer group.cancel(std.testing.io);
    try group.concurrent(std.testing.io, serveRedirectTest, .{ &server, std.testing.io, port, &saw_targets });

    var result = try inspect(std.testing.allocator, std.testing.io, "127.0.0.1", port, .{ .timeout_ms = 1000 });
    defer result.deinit();
    try group.await(std.testing.io);

    for (saw_targets) |saw_target| try std.testing.expect(saw_target);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "redirect_hops").?);
    try std.testing.expectEqualStrings("followed", fieldValue(&result, "redirect_outcome").?);
    try std.testing.expectEqualStrings("HTTP/1.0 200 OK", fieldValue(&result, "status_line").?);
    try std.testing.expectEqualStrings("HTTP/1.0", result.observations.items[2].version);
    try std.testing.expect(!containsRetained(&result, "redirect-secret"));

    var output: [max_request_target_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/next",
        switch (resolveRedirect("example.com", 80, "/base/start", "../next", &output)) {
            .follow => |next| next,
            else => return error.TestUnexpectedResult,
        },
    );
    try std.testing.expect(resolveRedirect("example.com", 80, "/", "https://example.com/secret", &output) == .blocked_scheme_change);
    try std.testing.expect(resolveRedirect("example.com", 80, "/", "http://other.test/secret", &output) == .blocked_cross_origin);
}

test "HTTP inspection records blocked and exhausted redirects" {
    var blocked_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var blocked_server = try blocked_address.listen(std.testing.io, .{});
    defer blocked_server.deinit(std.testing.io);
    var blocked_group: std.Io.Group = .init;
    defer blocked_group.cancel(std.testing.io);
    try blocked_group.concurrent(std.testing.io, serveStaticResponses, .{
        &blocked_server,
        std.testing.io,
        "HTTP/1.1 302 Found\r\nLocation: http://other.test/cross-origin-secret\r\n\r\n",
        1,
    });
    var blocked = try inspect(
        std.testing.allocator,
        std.testing.io,
        "127.0.0.1",
        blocked_server.socket.address.getPort(),
        .{ .timeout_ms = 500 },
    );
    defer blocked.deinit();
    try blocked_group.await(std.testing.io);
    try std.testing.expectEqualStrings("blocked_cross_origin", fieldValue(&blocked, "redirect_outcome").?);
    try std.testing.expect(!containsRetained(&blocked, "cross-origin-secret"));

    var limit_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var limit_server = try limit_address.listen(std.testing.io, .{});
    defer limit_server.deinit(std.testing.io);
    var limit_group: std.Io.Group = .init;
    defer limit_group.cancel(std.testing.io);
    try limit_group.concurrent(std.testing.io, serveStaticResponses, .{
        &limit_server,
        std.testing.io,
        "HTTP/1.1 302 Found\r\nLocation: /again\r\n\r\n",
        max_redirects + 1,
    });
    var limited = try inspect(
        std.testing.allocator,
        std.testing.io,
        "127.0.0.1",
        limit_server.socket.address.getPort(),
        .{ .timeout_ms = 1000 },
    );
    defer limited.deinit();
    try limit_group.await(std.testing.io);
    try std.testing.expectEqualStrings("3", fieldValue(&limited, "redirect_hops").?);
    try std.testing.expectEqualStrings("limit_reached", fieldValue(&limited, "redirect_outcome").?);
}

test "HTTP inspection times out when the peer stalls" {
    var listen_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_address.listen(std.testing.io, .{});
    defer server.deinit(std.testing.io);

    try std.testing.expectError(
        error.Timeout,
        inspect(
            std.testing.allocator,
            std.testing.io,
            "127.0.0.1",
            server.socket.address.getPort(),
            .{ .timeout_ms = 50 },
        ),
    );
}
