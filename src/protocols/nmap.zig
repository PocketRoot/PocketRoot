const std = @import("std");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "nmap",
    .name = "Nmap Results",
    .category = "Network",
    .file_extension = "xml",
    .media_type = "application/xml",
    .auto_detect = false,
    .analyze = analyzeText,
    .sample = sampleText,
};

const Stats = struct {
    hosts: usize = 0,
    up_hosts: usize = 0,
    open_ports: usize = 0,
    scripts: usize = 0,
};

const Host = struct {
    active: bool = false,
    up: bool = false,
    address: []const u8 = "",
    hostname: []const u8 = "",

    fn target(self: Host) []const u8 {
        return if (self.hostname.len != 0) self.hostname else self.address;
    }
};

const Port = struct {
    active: bool = false,
    open: bool = false,
    transport: []const u8 = "",
    number: []const u8 = "",
    service: []const u8 = "",
    service_method: []const u8 = "",
    product: []const u8 = "",
    version: []const u8 = "",
};

const Context = struct {
    result: *protocol.AnalysisResult,
    stats: Stats = .{},
    host: Host = .{},
    port: Port = .{},

    fn start(self: *Context, tag: Tag) !void {
        if (std.mem.eql(u8, tag.name, "host")) {
            if (self.host.active) return error.MalformedNmapXml;
            self.host = .{ .active = true };
            self.stats.hosts += 1;
        } else if (std.mem.eql(u8, tag.name, "status") and self.host.active) {
            self.host.up = std.mem.eql(u8, try requiredAttribute(tag.attributes, "state"), "up");
        } else if (std.mem.eql(u8, tag.name, "address") and self.host.active) {
            const address = try requiredAttribute(tag.attributes, "addr");
            const address_type = (try attribute(tag.attributes, "addrtype")) orelse "";
            if (self.host.address.len == 0 or
                std.mem.eql(u8, address_type, "ipv4") or
                std.mem.eql(u8, address_type, "ipv6"))
            {
                self.host.address = address;
            }
        } else if (std.mem.eql(u8, tag.name, "hostname") and self.host.active) {
            if (self.host.hostname.len == 0) {
                self.host.hostname = try requiredAttribute(tag.attributes, "name");
            }
        } else if (std.mem.eql(u8, tag.name, "port") and self.host.active) {
            if (self.port.active) return error.MalformedNmapXml;
            self.port = .{
                .active = true,
                .transport = try requiredAttribute(tag.attributes, "protocol"),
                .number = try requiredAttribute(tag.attributes, "portid"),
            };
        } else if (std.mem.eql(u8, tag.name, "state") and self.port.active) {
            self.port.open = std.mem.eql(u8, try requiredAttribute(tag.attributes, "state"), "open");
        } else if (std.mem.eql(u8, tag.name, "service") and self.port.active) {
            self.port.service = (try attribute(tag.attributes, "name")) orelse "";
            self.port.service_method = (try attribute(tag.attributes, "method")) orelse "";
            self.port.product = (try attribute(tag.attributes, "product")) orelse "";
            self.port.version = (try attribute(tag.attributes, "version")) orelse "";
        } else if (std.mem.eql(u8, tag.name, "script")) {
            try self.addScript(tag);
        }
    }

    fn end(self: *Context, name: []const u8) !void {
        if (std.mem.eql(u8, name, "port") and self.port.active) {
            if (self.port.open) try self.addOpenPort();
            self.port = .{};
        } else if (std.mem.eql(u8, name, "host") and self.host.active) {
            if (self.host.up) {
                self.stats.up_hosts += 1;
                _ = try self.result.addNetworkObservation(.{
                    .kind = .host,
                    .confidence = .observed,
                    .address = self.host.address,
                    .hostname = self.host.hostname,
                    .source_id = "nmap:host",
                });
            }
            self.host = .{};
        }
    }

    fn addOpenPort(self: *Context) !void {
        self.stats.open_ports += 1;
        const port_number = std.fmt.parseInt(u16, self.port.number, 10) catch return error.MalformedNmapXml;

        const source_id = try std.fmt.allocPrint(
            self.result.allocator,
            "{s}/{s}",
            .{ self.port.transport, self.port.number },
        );
        defer self.result.allocator.free(source_id);

        const message = try std.fmt.allocPrint(self.result.allocator, "Open port {s}", .{source_id});
        defer self.result.allocator.free(message);

        const detail = try std.fmt.allocPrint(
            self.result.allocator,
            "service={s}; product={s}; version={s}",
            .{ self.port.service, self.port.product, self.port.version },
        );
        defer self.result.allocator.free(detail);

        try self.result.addDetailedFinding(.info, message, detail, self.host.target(), source_id);
        _ = try self.result.addNetworkObservation(.{
            .kind = .endpoint,
            .confidence = .observed,
            .address = self.host.address,
            .hostname = self.host.hostname,
            .transport = self.port.transport,
            .port = port_number,
            .evidence = "state=open",
            .source_id = "nmap:port",
        });
        if (self.port.service.len != 0) {
            _ = try self.result.addNetworkObservation(.{
                .kind = .service,
                .confidence = serviceConfidence(self.port.service_method),
                .address = self.host.address,
                .hostname = self.host.hostname,
                .transport = self.port.transport,
                .port = port_number,
                .service = self.port.service,
                .product = self.port.product,
                .version = self.port.version,
                .evidence = detail,
                .source_id = "nmap:service",
            });
        }
    }

    fn addScript(self: *Context, tag: Tag) !void {
        const id = try requiredAttribute(tag.attributes, "id");
        const output = (try attribute(tag.attributes, "output")) orelse "";
        self.stats.scripts += 1;

        const message = try std.fmt.allocPrint(self.result.allocator, "Nmap script {s}", .{id});
        defer self.result.allocator.free(message);

        const source_id = try std.fmt.allocPrint(self.result.allocator, "nmap:{s}", .{id});
        defer self.result.allocator.free(source_id);

        try self.result.addDetailedFinding(.info, message, output, self.host.target(), source_id);
    }
};

fn serviceConfidence(method: []const u8) protocol.ObservationConfidence {
    if (std.mem.eql(u8, method, "probed")) return .confirmed;
    if (std.mem.eql(u8, method, "table")) return .inferred;
    return .observed;
}

const Tag = struct {
    name: []const u8,
    attributes: []const u8,
    closing: bool,
    self_closing: bool,
};

const TagScanner = struct {
    data: []const u8,
    index: usize = 0,

    fn next(self: *TagScanner) !?Tag {
        while (std.mem.indexOfScalarPos(u8, self.data, self.index, '<')) |start| {
            if (std.mem.startsWith(u8, self.data[start..], "<!--")) {
                self.index = try skipDelimited(self.data, start + 4, "-->");
                continue;
            }
            if (std.mem.startsWith(u8, self.data[start..], "<?")) {
                self.index = try skipDelimited(self.data, start + 2, "?>");
                continue;
            }
            if (std.mem.startsWith(u8, self.data[start..], "<![CDATA[")) {
                self.index = try skipDelimited(self.data, start + 9, "]]>");
                continue;
            }
            if (std.mem.startsWith(u8, self.data[start..], "<!")) {
                const end = std.mem.indexOfScalarPos(u8, self.data, start + 2, '>') orelse return error.MalformedXml;
                self.index = end + 1;
                continue;
            }

            const end = try tagEnd(self.data, start + 1);
            self.index = end + 1;
            return try parseTag(self.data[start + 1 .. end]);
        }
        self.index = self.data.len;
        return null;
    }
};

const Attribute = struct {
    name: []const u8,
    value: []const u8,
};

const AttributeIterator = struct {
    text: []const u8,
    index: usize = 0,

    fn next(self: *AttributeIterator) !?Attribute {
        while (self.index < self.text.len and std.ascii.isWhitespace(self.text[self.index])) self.index += 1;
        if (self.index == self.text.len) return null;

        const name_start = self.index;
        while (self.index < self.text.len and
            !std.ascii.isWhitespace(self.text[self.index]) and
            self.text[self.index] != '=')
        {
            const byte = self.text[self.index];
            if (byte == '/' or byte == '<' or byte == '>' or byte == '\'' or byte == '"') {
                return error.MalformedXmlAttribute;
            }
            self.index += 1;
        }
        if (name_start == self.index) return error.MalformedXmlAttribute;
        const name = self.text[name_start..self.index];

        while (self.index < self.text.len and std.ascii.isWhitespace(self.text[self.index])) self.index += 1;
        if (self.index == self.text.len or self.text[self.index] != '=') return error.MalformedXmlAttribute;
        self.index += 1;
        while (self.index < self.text.len and std.ascii.isWhitespace(self.text[self.index])) self.index += 1;
        if (self.index == self.text.len or (self.text[self.index] != '"' and self.text[self.index] != '\'')) {
            return error.MalformedXmlAttribute;
        }

        const quote = self.text[self.index];
        self.index += 1;
        const value_start = self.index;
        while (self.index < self.text.len and self.text[self.index] != quote) {
            if (self.text[self.index] == '<') return error.MalformedXmlAttribute;
            self.index += 1;
        }
        if (self.index == self.text.len) return error.MalformedXmlAttribute;
        const value = self.text[value_start..self.index];
        self.index += 1;
        return .{ .name = name, .value = value };
    }
};

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\<?xml version="1.0"?>
        \\<nmaprun scanner="nmap">
        \\  <host>
        \\    <status state="up"/>
        \\    <address addr="192.0.2.10" addrtype="ipv4"/>
        \\    <hostnames><hostname name="demo.example"/></hostnames>
        \\    <ports>
        \\      <port protocol="tcp" portid="443">
        \\        <state state="open"/>
        \\        <service name="https" product="Example service" version="1.0"/>
        \\        <script id="ssl-cert" output="Local sample metadata only"/>
        \\      </port>
        \\    </ports>
        \\  </host>
        \\</nmaprun>
        \\
    );
}

/// Imports existing Nmap XML. It never starts a scan or executes NSE scripts.
pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var result = try protocol.AnalysisResult.init(allocator, "Nmap results");
    errdefer result.deinit();

    var context = Context{ .result = &result };
    var scanner = TagScanner{ .data = data };
    var stack: std.ArrayList([]const u8) = .empty;
    defer stack.deinit(allocator);
    var root_seen = false;
    var root_closed = false;

    while (try scanner.next()) |tag| {
        if (tag.closing) {
            const expected = stack.pop() orelse return error.MalformedXml;
            if (!std.mem.eql(u8, expected, tag.name)) return error.MalformedXml;
            try context.end(tag.name);
            if (std.mem.eql(u8, tag.name, "nmaprun")) root_closed = true;
            continue;
        }

        try validateAttributes(tag.attributes);
        if (stack.items.len == 0) {
            if (root_seen) return error.MultipleXmlRoots;
            if (!std.mem.eql(u8, tag.name, "nmaprun")) return error.InvalidNmapRoot;
            root_seen = true;
        }

        try context.start(tag);
        if (tag.self_closing) {
            try context.end(tag.name);
            if (std.mem.eql(u8, tag.name, "nmaprun")) root_closed = true;
        } else {
            try stack.append(allocator, tag.name);
        }
    }

    if (!root_seen) return error.MissingNmapRoot;
    if (stack.items.len != 0 or !root_closed) return error.MalformedXml;

    const summary = try std.fmt.allocPrint(
        allocator,
        "Nmap results: {d} host{s}, {d} up, {d} open port{s}, {d} script{s}",
        .{
            context.stats.hosts,
            if (context.stats.hosts == 1) "" else "s",
            context.stats.up_hosts,
            context.stats.open_ports,
            if (context.stats.open_ports == 1) "" else "s",
            context.stats.scripts,
            if (context.stats.scripts == 1) "" else "s",
        },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);

    try result.addNumberField("hosts", context.stats.hosts);
    try result.addNumberField("up_hosts", context.stats.up_hosts);
    try result.addNumberField("open_ports", context.stats.open_ports);
    try result.addNumberField("scripts", context.stats.scripts);
    return result;
}

fn skipDelimited(data: []const u8, start: usize, delimiter: []const u8) !usize {
    const relative = std.mem.indexOf(u8, data[start..], delimiter) orelse return error.MalformedXml;
    return start + relative + delimiter.len;
}

fn tagEnd(data: []const u8, start: usize) !usize {
    var quote: ?u8 = null;
    var index = start;
    while (index < data.len) : (index += 1) {
        const byte = data[index];
        if (quote) |active_quote| {
            if (byte == active_quote) quote = null;
        } else if (byte == '"' or byte == '\'') {
            quote = byte;
        } else if (byte == '>') {
            return index;
        } else if (byte == '<') {
            return error.MalformedXml;
        }
    }
    return error.MalformedXml;
}

fn parseTag(raw: []const u8) !Tag {
    var text = std.mem.trim(u8, raw, " \t\r\n");
    if (text.len == 0) return error.MalformedXml;

    const closing = text[0] == '/';
    if (closing) {
        text = std.mem.trimStart(u8, text[1..], " \t\r\n");
        if (text.len == 0) return error.MalformedXml;
    }

    const name_end = std.mem.indexOfAny(u8, text, " \t\r\n/") orelse text.len;
    if (name_end == 0) return error.MalformedXml;
    const name = text[0..name_end];
    var remainder = std.mem.trim(u8, text[name_end..], " \t\r\n");

    if (closing) {
        if (remainder.len != 0) return error.MalformedXml;
        return .{ .name = name, .attributes = "", .closing = true, .self_closing = false };
    }

    const self_closing = remainder.len != 0 and remainder[remainder.len - 1] == '/';
    if (self_closing) remainder = std.mem.trimEnd(u8, remainder[0 .. remainder.len - 1], " \t\r\n");
    return .{ .name = name, .attributes = remainder, .closing = false, .self_closing = self_closing };
}

fn validateAttributes(text: []const u8) !void {
    var iterator = AttributeIterator{ .text = text };
    while (try iterator.next()) |_| {}
}

fn attribute(text: []const u8, name: []const u8) !?[]const u8 {
    var iterator = AttributeIterator{ .text = text };
    while (try iterator.next()) |item| {
        if (std.mem.eql(u8, item.name, name)) return item.value;
    }
    return null;
}

fn requiredAttribute(text: []const u8, name: []const u8) ![]const u8 {
    return (try attribute(text, name)) orelse error.MissingNmapAttribute;
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

fn findingBySource(result: *const protocol.AnalysisResult, source_id: []const u8) ?protocol.Finding {
    for (result.findings.items) |finding| {
        if (std.mem.eql(u8, finding.source_id, source_id)) return finding;
    }
    return null;
}

fn observationByKindAndPort(
    result: *const protocol.AnalysisResult,
    kind: protocol.NetworkObservationKind,
    port: u16,
) ?protocol.NetworkObservation {
    for (result.observations.items) |observation| {
        if (observation.kind == kind and observation.port == port) return observation;
    }
    return null;
}

test "nmap imports multiple hosts and reports open ports" {
    const text =
        \\<?xml version="1.0"?>
        \\<nmaprun scanner="nmap">
        \\  <host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
        \\    <hostnames><hostname name="one.example"/></hostnames><ports>
        \\      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="probed" product="OpenSSH" version="9.2"/><script id="ssh-hostkey" output="key &amp; fingerprint"/></port>
        \\      <port protocol="udp" portid="53"><state state="closed"/></port>
        \\    </ports><hostscript><script id="uptime" output="123 seconds"/></hostscript>
        \\  </host>
        \\  <host><status state="down"/><address addr="192.0.2.2" addrtype="ipv4"/><ports>
        \\    <port protocol="tcp" portid="443"><state state="open"/><service name="https" method="table" product="Example" version="1.0"/></port>
        \\  </ports></host>
        \\</nmaprun>
    ;

    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqualStrings("2", fieldValue(&result, "hosts").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "up_hosts").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "open_ports").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "scripts").?);
    try std.testing.expectEqual(@as(usize, 4), result.findings.items.len);
    try std.testing.expectEqual(@as(usize, 5), result.observations.items.len);
    try std.testing.expect(observationByKindAndPort(&result, .endpoint, 22) != null);
    try std.testing.expectEqual(
        protocol.ObservationConfidence.confirmed,
        observationByKindAndPort(&result, .service, 22).?.confidence,
    );
    try std.testing.expectEqualStrings(
        "OpenSSH",
        observationByKindAndPort(&result, .service, 22).?.product,
    );
    try std.testing.expectEqual(
        protocol.ObservationConfidence.inferred,
        observationByKindAndPort(&result, .service, 443).?.confidence,
    );

    const ssh = findingBySource(&result, "tcp/22").?;
    try std.testing.expectEqual(protocol.FindingSeverity.info, ssh.severity);
    try std.testing.expectEqualStrings("one.example", ssh.target);
    try std.testing.expect(std.mem.indexOf(u8, ssh.detail, "service=ssh") != null);
    try std.testing.expect(std.mem.indexOf(u8, ssh.detail, "product=OpenSSH") != null);
    try std.testing.expect(std.mem.indexOf(u8, ssh.detail, "version=9.2") != null);

    const script = findingBySource(&result, "nmap:ssh-hostkey").?;
    try std.testing.expectEqualStrings("key &amp; fingerprint", script.detail);
    try std.testing.expectEqualStrings("one.example", script.target);
    try std.testing.expectEqualStrings("192.0.2.2", findingBySource(&result, "tcp/443").?.target);
}

test "nmap sample is local and read only" {
    const text = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(text);

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqualStrings("1", fieldValue(&result, "hosts").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "open_ports").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "scripts").?);
}

test "nmap rejects bad roots and malformed attributes" {
    try std.testing.expectError(error.InvalidNmapRoot, analyzeText(std.testing.allocator, "<scan/>"));
    try std.testing.expectError(error.MalformedXmlAttribute, analyzeText(std.testing.allocator, "<nmaprun scanner=nmap/>"));
}
