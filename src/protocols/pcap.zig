const std = @import("std");
const dhcp = @import("../formats/dhcp.zig");
const dhcpv6 = @import("../formats/dhcpv6.zig");
const dns = @import("../formats/dns.zig");
const nbns = @import("../formats/nbns.zig");
const ssdp = @import("../formats/ssdp.zig");
const tls_certificate = @import("../formats/tls_certificate.zig");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "pcap",
    .name = "Packet Capture",
    .category = "Network",
    .file_extension = "pcap",
    .additional_extensions = &.{"pcapng"},
    .media_type = "application/vnd.tcpdump.pcap",
    .analyze = analyzeCapture,
};

const max_packet_bytes: u32 = 16 * 1024 * 1024;
const max_wire_bytes: u32 = 64 * 1024 * 1024;
const max_ipv6_extensions = 8;
const max_name_queries = 10;
const max_answer_records = 16;
const max_authority_records = 16;
const max_additional_records = 16;
const max_passive_observations = 32;
const max_ndp_options = 16;
const max_dhcp_records = 16;
const max_ssdp_records = 16;
const max_nbns_records = 16;
const max_mdns_links = 16;
const max_tls_hellos = 16;
const max_tcp_streams = 64;
const max_tcp_segments = 4096;
const max_tcp_segments_per_stream = 256;
const max_tcp_queued_segments = 8;
const max_tcp_stream_bytes = dns.max_message_len + 2;
const max_tcp_reassembly_bytes = 2 * 1024 * 1024;
const max_http_line_bytes = 4096;

const Interface = struct {
    linktype: u32,
    snaplen: u32,
    scope: usize,
};

const NdpOptions = struct {
    source_link_layer: ?[]const u8 = null,
    target_link_layer: ?[]const u8 = null,
};

const DnsRecordSection = enum { answer, authority, additional };

const MdnsPtrLink = struct {
    scope: usize,
    generation: usize,
    service: [dns.max_name_text_len]u8,
    service_len: usize,
    instance: [dns.max_name_text_len]u8,
    instance_len: usize,
};

const MdnsSrvLink = struct {
    scope: usize,
    generation: usize,
    instance: [dns.max_name_text_len]u8,
    instance_len: usize,
    hostname: [dns.max_name_text_len]u8,
    hostname_len: usize,
    port: u16,
};

const MdnsAddressLink = struct {
    scope: usize,
    generation: usize,
    record_type: u16,
    hostname: [dns.max_name_text_len]u8,
    hostname_len: usize,
    address: [64]u8,
    address_len: usize,
};

const MdnsLinks = struct {
    ptrs: [max_mdns_links]MdnsPtrLink = undefined,
    ptr_count: usize = 0,
    srvs: [max_mdns_links]MdnsSrvLink = undefined,
    srv_count: usize = 0,
    addresses: [max_mdns_links]MdnsAddressLink = undefined,
    address_count: usize = 0,

    fn remember(self: *MdnsLinks, scope: usize, generation: usize, answer: dns.Answer) !void {
        if (answer.ttl == 0) return self.forget(scope, answer);
        if (answer.cache_flush) self.flushOlder(scope, generation, answer);
        switch (answer.value) {
            .ptr => |instance| {
                for (self.ptrs[0..self.ptr_count]) |*link| {
                    if (link.scope == scope and
                        std.ascii.eqlIgnoreCase(link.service[0..link.service_len], answer.name) and
                        std.ascii.eqlIgnoreCase(link.instance[0..link.instance_len], instance))
                    {
                        link.generation = generation;
                        return;
                    }
                }
                if (self.ptr_count == self.ptrs.len) return;
                const link = &self.ptrs[self.ptr_count];
                link.scope = scope;
                link.generation = generation;
                std.mem.copyForwards(u8, link.service[0..answer.name.len], answer.name);
                link.service_len = answer.name.len;
                std.mem.copyForwards(u8, link.instance[0..instance.len], instance);
                link.instance_len = instance.len;
                self.ptr_count += 1;
            },
            .srv => |srv| {
                for (self.srvs[0..self.srv_count]) |*link| {
                    if (link.scope == scope and
                        link.port == srv.port and
                        std.ascii.eqlIgnoreCase(link.instance[0..link.instance_len], answer.name) and
                        std.ascii.eqlIgnoreCase(link.hostname[0..link.hostname_len], srv.target))
                    {
                        link.generation = generation;
                        return;
                    }
                }
                if (self.srv_count == self.srvs.len) return;
                const link = &self.srvs[self.srv_count];
                link.scope = scope;
                link.generation = generation;
                std.mem.copyForwards(u8, link.instance[0..answer.name.len], answer.name);
                link.instance_len = answer.name.len;
                std.mem.copyForwards(u8, link.hostname[0..srv.target.len], srv.target);
                link.hostname_len = srv.target.len;
                link.port = srv.port;
                self.srv_count += 1;
            },
            .a => |address| try self.rememberAddress(scope, generation, answer.record_type, answer.name, &address),
            .aaaa => |address| try self.rememberAddress(scope, generation, answer.record_type, answer.name, &address),
            .cname, .ns, .mx, .soa, .txt, .unsupported => {},
        }
    }

    fn rememberAddress(
        self: *MdnsLinks,
        scope: usize,
        generation: usize,
        record_type: u16,
        hostname: []const u8,
        address: []const u8,
    ) !void {
        var buffer: [64]u8 = undefined;
        const formatted = try formatAddress(&buffer, address);
        for (self.addresses[0..self.address_count]) |*link| {
            if (link.scope == scope and
                link.record_type == record_type and
                std.ascii.eqlIgnoreCase(link.hostname[0..link.hostname_len], hostname) and
                std.mem.eql(u8, link.address[0..link.address_len], formatted))
            {
                link.generation = generation;
                return;
            }
        }
        if (self.address_count == self.addresses.len) return;
        const link = &self.addresses[self.address_count];
        link.scope = scope;
        link.generation = generation;
        link.record_type = record_type;
        std.mem.copyForwards(u8, link.hostname[0..hostname.len], hostname);
        link.hostname_len = hostname.len;
        std.mem.copyForwards(u8, link.address[0..formatted.len], formatted);
        link.address_len = formatted.len;
        self.address_count += 1;
    }

    fn flushOlder(self: *MdnsLinks, scope: usize, generation: usize, answer: dns.Answer) void {
        switch (answer.value) {
            .ptr => {
                var index: usize = 0;
                while (index < self.ptr_count) {
                    const link = self.ptrs[index];
                    if (link.scope == scope and link.generation != generation and
                        std.ascii.eqlIgnoreCase(link.service[0..link.service_len], answer.name))
                    {
                        self.ptr_count -= 1;
                        if (index != self.ptr_count) self.ptrs[index] = self.ptrs[self.ptr_count];
                    } else index += 1;
                }
            },
            .srv => {
                var index: usize = 0;
                while (index < self.srv_count) {
                    const link = self.srvs[index];
                    if (link.scope == scope and link.generation != generation and
                        std.ascii.eqlIgnoreCase(link.instance[0..link.instance_len], answer.name))
                    {
                        self.srv_count -= 1;
                        if (index != self.srv_count) self.srvs[index] = self.srvs[self.srv_count];
                    } else index += 1;
                }
            },
            .a, .aaaa => {
                var index: usize = 0;
                while (index < self.address_count) {
                    const link = self.addresses[index];
                    if (link.scope == scope and link.generation != generation and
                        link.record_type == answer.record_type and
                        std.ascii.eqlIgnoreCase(link.hostname[0..link.hostname_len], answer.name))
                    {
                        self.address_count -= 1;
                        if (index != self.address_count) self.addresses[index] = self.addresses[self.address_count];
                    } else index += 1;
                }
            },
            .cname, .ns, .mx, .soa, .txt, .unsupported => {},
        }
    }

    fn forget(self: *MdnsLinks, scope: usize, answer: dns.Answer) !void {
        switch (answer.value) {
            .ptr => |instance| {
                var index: usize = 0;
                while (index < self.ptr_count) {
                    const link = self.ptrs[index];
                    if (link.scope == scope and
                        std.ascii.eqlIgnoreCase(link.service[0..link.service_len], answer.name) and
                        std.ascii.eqlIgnoreCase(link.instance[0..link.instance_len], instance))
                    {
                        self.ptr_count -= 1;
                        if (index != self.ptr_count) self.ptrs[index] = self.ptrs[self.ptr_count];
                    } else index += 1;
                }
            },
            .srv => |srv| {
                var index: usize = 0;
                while (index < self.srv_count) {
                    const link = self.srvs[index];
                    if (link.scope == scope and
                        link.port == srv.port and
                        std.ascii.eqlIgnoreCase(link.instance[0..link.instance_len], answer.name) and
                        std.ascii.eqlIgnoreCase(link.hostname[0..link.hostname_len], srv.target))
                    {
                        self.srv_count -= 1;
                        if (index != self.srv_count) self.srvs[index] = self.srvs[self.srv_count];
                    } else index += 1;
                }
            },
            .a => |address| try self.forgetAddress(scope, answer.record_type, answer.name, &address),
            .aaaa => |address| try self.forgetAddress(scope, answer.record_type, answer.name, &address),
            .cname, .ns, .mx, .soa, .txt, .unsupported => {},
        }
    }

    fn forgetAddress(self: *MdnsLinks, scope: usize, record_type: u16, hostname: []const u8, address: []const u8) !void {
        var buffer: [64]u8 = undefined;
        const formatted = try formatAddress(&buffer, address);
        var index: usize = 0;
        while (index < self.address_count) {
            const link = self.addresses[index];
            if (link.scope == scope and
                link.record_type == record_type and
                std.ascii.eqlIgnoreCase(link.hostname[0..link.hostname_len], hostname) and
                std.mem.eql(u8, link.address[0..link.address_len], formatted))
            {
                self.address_count -= 1;
                if (index != self.address_count) self.addresses[index] = self.addresses[self.address_count];
            } else index += 1;
        }
    }
};

const TcpKey = struct {
    scope: usize,
    source: [16]u8 = [_]u8{0} ** 16,
    destination: [16]u8 = [_]u8{0} ** 16,
    address_len: u8,
    source_port: u16,
    destination_port: u16,

    fn init(scope: usize, source: []const u8, destination: []const u8, source_port: u16, destination_port: u16) ?TcpKey {
        if ((source.len != 4 and source.len != 16) or source.len != destination.len) return null;
        var key = TcpKey{
            .scope = scope,
            .address_len = @intCast(source.len),
            .source_port = source_port,
            .destination_port = destination_port,
        };
        @memcpy(key.source[0..source.len], source);
        @memcpy(key.destination[0..destination.len], destination);
        return key;
    }

    fn reversed(self: TcpKey) TcpKey {
        var key = self;
        key.source = self.destination;
        key.destination = self.source;
        key.source_port = self.destination_port;
        key.destination_port = self.source_port;
        return key;
    }

    fn eql(left: TcpKey, right: TcpKey) bool {
        const length: usize = left.address_len;
        return left.scope == right.scope and
            left.address_len == right.address_len and
            left.source_port == right.source_port and
            left.destination_port == right.destination_port and
            std.mem.eql(u8, left.source[0..length], right.source[0..length]) and
            std.mem.eql(u8, left.destination[0..length], right.destination[0..length]);
    }
};

const QueuedTcpSegment = struct {
    sequence: u32,
    data: []u8,
};

const TcpStream = struct {
    key: TcpKey,
    next_sequence: u32 = 0,
    initialized: bool = false,
    disabled: bool = false,
    application_done: bool = false,
    segment_count: usize = 0,
    data: std.ArrayList(u8) = .empty,
    queued: [max_tcp_queued_segments]QueuedTcpSegment = undefined,
    queued_count: usize = 0,

    fn deinit(self: *TcpStream, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        for (self.queued[0..self.queued_count]) |segment| allocator.free(segment.data);
    }

    fn storedBytes(self: *const TcpStream) usize {
        var total = self.data.items.len;
        for (self.queued[0..self.queued_count]) |segment| total += segment.data.len;
        return total;
    }
};

const Stats = struct {
    format: []const u8 = "",
    byte_order: ?std.builtin.Endian = null,
    mixed_byte_order: bool = false,
    timestamp_resolution: []const u8 = "interface-defined",
    sections: usize = 0,
    interfaces: usize = 0,
    packets: usize = 0,
    captured_bytes: u64 = 0,
    wire_bytes: u64 = 0,
    malformed_packets: usize = 0,
    unsupported_link_packets: usize = 0,
    ipv4_packets: usize = 0,
    ipv6_packets: usize = 0,
    fragments: usize = 0,
    tcp_packets: usize = 0,
    tcp_streams: usize = 0,
    tcp_reassembly_segments: usize = 0,
    tcp_reassembly_bytes: usize = 0,
    tcp_out_of_order_segments: usize = 0,
    dns_tcp_messages: usize = 0,
    tls_client_hellos: usize = 0,
    tls_server_hellos: usize = 0,
    tls_client_fields: usize = 0,
    tls_server_fields: usize = 0,
    tls_client_observations: usize = 0,
    tls_server_observations: usize = 0,
    udp_packets: usize = 0,
    arp_packets: usize = 0,
    arp_observations: usize = 0,
    icmp_packets: usize = 0,
    ndp_observations: usize = 0,
    tcp_observations: usize = 0,
    dhcp_messages: usize = 0,
    dhcp_fields: usize = 0,
    dhcp_observations: usize = 0,
    dhcpv6_messages: usize = 0,
    dhcpv6_fields: usize = 0,
    dhcpv6_observations: usize = 0,
    ssdp_messages: usize = 0,
    ssdp_fields: usize = 0,
    ssdp_observations: usize = 0,
    nbns_messages: usize = 0,
    nbns_fields: usize = 0,
    nbns_answers: usize = 0,
    nbns_observations: usize = 0,
    dns_messages: usize = 0,
    mdns_messages: usize = 0,
    llmnr_messages: usize = 0,
    dns_fields: usize = 0,
    mdns_fields: usize = 0,
    llmnr_fields: usize = 0,
    dns_observations: usize = 0,
    mdns_observations: usize = 0,
    llmnr_observations: usize = 0,
    dns_answers: usize = 0,
    mdns_answers: usize = 0,
    llmnr_answers: usize = 0,
    dns_authorities: usize = 0,
    mdns_authorities: usize = 0,
    llmnr_authorities: usize = 0,
    dns_additionals: usize = 0,
    mdns_additionals: usize = 0,
    llmnr_additionals: usize = 0,
    dns_answer_fields: usize = 0,
    mdns_answer_fields: usize = 0,
    llmnr_answer_fields: usize = 0,
    dns_authority_fields: usize = 0,
    mdns_authority_fields: usize = 0,
    llmnr_authority_fields: usize = 0,
    dns_additional_fields: usize = 0,
    mdns_additional_fields: usize = 0,
    llmnr_additional_fields: usize = 0,
    mdns_associations: usize = 0,
    first_linktype: ?u32 = null,

    fn observeEndian(self: *Stats, endian: std.builtin.Endian) void {
        if (self.byte_order) |first| {
            if (first != endian) self.mixed_byte_order = true;
        } else {
            self.byte_order = endian;
        }
    }

    fn observeLinktype(self: *Stats, linktype: u32) void {
        if (self.first_linktype == null) self.first_linktype = linktype;
    }
};

const Parser = struct {
    allocator: std.mem.Allocator,
    result: *protocol.AnalysisResult,
    stats: Stats = .{},
    interfaces: std.ArrayList(Interface) = .empty,
    tcp_streams: std.ArrayList(TcpStream) = .empty,
    tcp_reassembly_bytes: usize = 0,
    mdns_links: MdnsLinks = .{},
    mdns_generation: usize = 0,
    current_scope: usize = 0,
    next_scope: usize = 1,
    http_reported: bool = false,

    fn deinit(self: *Parser) void {
        self.interfaces.deinit(self.allocator);
        for (self.tcp_streams.items) |*stream| stream.deinit(self.allocator);
        self.tcp_streams.deinit(self.allocator);
    }

    fn resetSectionState(self: *Parser) void {
        for (self.tcp_streams.items) |*stream| stream.deinit(self.allocator);
        self.tcp_streams.clearRetainingCapacity();
        self.tcp_reassembly_bytes = 0;
        self.mdns_links = .{};
    }

    fn parseClassic(
        self: *Parser,
        data: []const u8,
        endian: std.builtin.Endian,
        nanoseconds: bool,
    ) !void {
        if (data.len < 24) return error.TruncatedCapture;
        if (readU16(data, 4, endian) != 2 or readU16(data, 6, endian) != 4) {
            return error.UnsupportedPcapVersion;
        }

        const snaplen = readU32(data, 16, endian);
        if (snaplen == 0 or snaplen > max_packet_bytes) return error.InvalidSnaplen;

        const linktype = readU32(data, 20, endian) & 0xffff;
        self.stats.format = "pcap";
        self.stats.sections = 1;
        self.stats.interfaces = 1;
        self.stats.timestamp_resolution = if (nanoseconds) "nanoseconds" else "microseconds";
        self.stats.observeEndian(endian);
        self.stats.observeLinktype(linktype);

        var cursor: usize = 24;
        while (cursor < data.len) {
            if (data.len - cursor < 16) return error.TruncatedPacketHeader;

            const fraction = readU32(data, cursor + 4, endian);
            const included = readU32(data, cursor + 8, endian);
            const original = readU32(data, cursor + 12, endian);
            const fraction_limit: u32 = if (nanoseconds) 1_000_000_000 else 1_000_000;
            if (fraction >= fraction_limit) {
                return error.InvalidTimestamp;
            }
            if (included > snaplen or included > max_packet_bytes or original > max_wire_bytes or included > original) {
                return error.InvalidPacketLength;
            }

            cursor += 16;
            const captured: usize = @intCast(included);
            if (captured > data.len - cursor) return error.TruncatedPacketData;
            try self.parsePacket(0, linktype, data[cursor .. cursor + captured], original);
            cursor += captured;
        }
    }

    fn parsePcapng(self: *Parser, data: []const u8) !void {
        self.stats.format = "pcapng";
        var cursor: usize = 0;
        var section_endian: ?std.builtin.Endian = null;
        var section_end: ?usize = null;

        while (cursor < data.len) {
            if (data.len - cursor < 12) return error.TruncatedBlock;
            const is_section_header = std.mem.eql(u8, data[cursor..][0..4], &.{ 0x0a, 0x0d, 0x0d, 0x0a });
            if (section_end) |expected_end| {
                if ((cursor == expected_end) != is_section_header) return error.SectionLengthMismatch;
            }

            if (is_section_header) {
                if (data.len - cursor < 28) return error.TruncatedBlock;
                const endian: std.builtin.Endian = if (std.mem.eql(
                    u8,
                    data[cursor + 8 ..][0..4],
                    &.{ 0x4d, 0x3c, 0x2b, 0x1a },
                ))
                    .little
                else if (std.mem.eql(
                    u8,
                    data[cursor + 8 ..][0..4],
                    &.{ 0x1a, 0x2b, 0x3c, 0x4d },
                ))
                    .big
                else
                    return error.InvalidByteOrderMagic;

                const block_len = try checkedBlock(data, cursor, endian, 28);
                if (readU16(data, cursor + 12, endian) != 1 or readU16(data, cursor + 14, endian) != 0) {
                    return error.UnsupportedPcapngVersion;
                }
                const section_length = readU64(data, cursor + 16, endian);
                if (section_length != std.math.maxInt(u64) and section_length > std.math.maxInt(i64)) {
                    return error.InvalidSectionLength;
                }
                try validateOptions(data[cursor + 24 .. cursor + block_len - 4], endian);

                const section_start = cursor + block_len;
                if (section_length == std.math.maxInt(u64)) {
                    section_end = null;
                } else {
                    if (section_length & 3 != 0) return error.InvalidSectionLength;
                    if (section_length > @as(u64, @intCast(data.len - section_start))) {
                        return error.TruncatedSection;
                    }
                    section_end = section_start + @as(usize, @intCast(section_length));
                }

                section_endian = endian;
                self.interfaces.clearRetainingCapacity();
                self.resetSectionState();
                self.stats.sections += 1;
                self.stats.observeEndian(endian);
                cursor += block_len;
                continue;
            }

            const endian = section_endian orelse return error.MissingSectionHeader;
            const block_type = readU32(data, cursor, endian);
            const block_len = try checkedBlock(data, cursor, endian, 12);
            if (section_end) |expected_end| {
                if (block_len > expected_end - cursor) return error.SectionLengthMismatch;
            }
            switch (block_type) {
                0x00000001 => try self.parseInterfaceBlock(data[cursor .. cursor + block_len], endian),
                0x00000006 => try self.parseEnhancedPacket(data[cursor .. cursor + block_len], endian),
                0x00000003 => try self.parseSimplePacket(data[cursor .. cursor + block_len], endian),
                else => {},
            }
            cursor += block_len;
        }

        if (self.stats.sections == 0) return error.MissingSectionHeader;
    }

    fn parseInterfaceBlock(self: *Parser, block: []const u8, endian: std.builtin.Endian) !void {
        if (block.len < 20) return error.InvalidInterfaceBlock;
        const snaplen = readU32(block, 12, endian);
        if (snaplen > max_packet_bytes) return error.InvalidSnaplen;

        const linktype = readU16(block, 8, endian);
        try validateOptions(block[16 .. block.len - 4], endian);
        const scope = self.next_scope;
        self.next_scope += 1;
        try self.interfaces.append(self.allocator, .{ .linktype = linktype, .snaplen = snaplen, .scope = scope });
        self.stats.interfaces += 1;
        self.stats.observeLinktype(linktype);
    }

    fn parseEnhancedPacket(self: *Parser, block: []const u8, endian: std.builtin.Endian) !void {
        if (block.len < 32) return error.InvalidPacketBlock;
        const interface_id = readU32(block, 8, endian);
        if (interface_id >= self.interfaces.items.len) return error.InvalidInterface;
        const interface = self.interfaces.items[interface_id];
        const captured = readU32(block, 20, endian);
        const original = readU32(block, 24, endian);
        try validatePacketLengths(interface.snaplen, captured, original);

        const captured_len: usize = @intCast(captured);
        const padded_len = try padded4(captured_len);
        const packet_start: usize = 28;
        const trailer_start = block.len - 4;
        if (packet_start > trailer_start or padded_len > trailer_start - packet_start) {
            return error.TruncatedPacketData;
        }
        try validateOptions(block[packet_start + padded_len .. trailer_start], endian);
        try self.parsePacket(interface.scope, interface.linktype, block[packet_start .. packet_start + captured_len], original);
    }

    fn parseSimplePacket(self: *Parser, block: []const u8, endian: std.builtin.Endian) !void {
        if (self.interfaces.items.len == 0) return error.InvalidInterface;
        if (block.len < 16) return error.InvalidPacketBlock;

        const interface = self.interfaces.items[0];
        const original = readU32(block, 8, endian);
        if (original > max_wire_bytes) return error.InvalidPacketLength;
        const captured = if (interface.snaplen == 0) original else @min(original, interface.snaplen);
        if (captured > max_packet_bytes) return error.InvalidPacketLength;
        const captured_len: usize = @intCast(captured);
        const padded_len = try padded4(captured_len);
        if (block.len != 16 + padded_len) return error.InvalidPacketPadding;
        try self.parsePacket(interface.scope, interface.linktype, block[12 .. 12 + captured_len], original);
    }

    fn parsePacket(self: *Parser, scope: usize, linktype: u32, data: []const u8, original: u32) !void {
        const previous_scope = self.current_scope;
        self.current_scope = scope;
        defer self.current_scope = previous_scope;
        self.stats.packets += 1;
        self.stats.captured_bytes += data.len;
        self.stats.wire_bytes += original;

        const valid = switch (linktype) {
            1 => try self.parseEthernet(data),
            101 => try self.parseRawIp(data),
            113 => if (data.len < 16)
                false
            else
                try self.parseEtherType(readBe16(data, 14), data[16..]),
            276 => if (data.len < 20)
                false
            else
                try self.parseEtherType(readBe16(data, 0), data[20..]),
            else => blk: {
                self.stats.unsupported_link_packets += 1;
                break :blk true;
            },
        };
        if (!valid) self.stats.malformed_packets += 1;
    }

    fn parseEthernet(self: *Parser, data: []const u8) !bool {
        if (data.len < 14) return false;
        var ethertype = readBe16(data, 12);
        var offset: usize = 14;
        var tags: usize = 0;
        while (ethertype == 0x8100 or ethertype == 0x88a8 or ethertype == 0x9100) {
            if (tags == 4 or data.len - offset < 4) return false;
            ethertype = readBe16(data, offset + 2);
            offset += 4;
            tags += 1;
        }
        return self.parseEtherType(ethertype, data[offset..]);
    }

    fn parseRawIp(self: *Parser, data: []const u8) !bool {
        if (data.len == 0) return false;
        return switch (data[0] >> 4) {
            4 => self.parseIpv4(data),
            6 => self.parseIpv6(data),
            else => false,
        };
    }

    fn parseEtherType(self: *Parser, ethertype: u16, data: []const u8) !bool {
        return switch (ethertype) {
            0x0800 => self.parseIpv4(data),
            0x86dd => self.parseIpv6(data),
            0x0806 => self.parseArp(data),
            else => true,
        };
    }

    fn parseArp(self: *Parser, data: []const u8) !bool {
        self.stats.arp_packets += 1;
        if (data.len < 8) return false;
        const hardware_len: usize = data[4];
        const protocol_len: usize = data[5];
        const needed: usize = 8 + 2 * (hardware_len + protocol_len);
        if (data.len < needed) return false;
        if (readBe16(data, 0) != 1 or readBe16(data, 2) != 0x0800 or hardware_len != 6 or protocol_len != 4) return true;

        const opcode = readBe16(data, 6);
        if ((opcode != 1 and opcode != 2) or self.stats.arp_observations >= max_passive_observations) return true;
        const sender_protocol = data[8 + hardware_len .. 8 + hardware_len + protocol_len];
        var nonzero = false;
        for (sender_protocol) |byte| nonzero = nonzero or byte != 0;
        if (!nonzero) return true;

        var address_buffer: [64]u8 = undefined;
        const address = try formatAddress(&address_buffer, sender_protocol);
        const sender_hardware = data[8 .. 8 + hardware_len];
        var evidence_buffer: [128]u8 = undefined;
        const evidence = try std.fmt.bufPrint(
            &evidence_buffer,
            "ARP {s} sender; mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
            .{
                if (opcode == 2) "reply" else "request",
                sender_hardware[0],
                sender_hardware[1],
                sender_hardware[2],
                sender_hardware[3],
                sender_hardware[4],
                sender_hardware[5],
            },
        );
        if (try self.result.addNetworkObservation(.{
            .kind = .host,
            .confidence = if (opcode == 2) .confirmed else .observed,
            .address = address,
            .evidence = evidence,
            .source_id = "pcap:arp",
        })) self.stats.arp_observations += 1;
        return true;
    }

    fn parseIpv4(self: *Parser, data: []const u8) !bool {
        self.stats.ipv4_packets += 1;
        if (data.len < 20 or data[0] >> 4 != 4) return false;
        const header_len: usize = @as(usize, data[0] & 0x0f) * 4;
        if (header_len < 20 or header_len > data.len) return false;
        const total_len: usize = readBe16(data, 2);
        if (total_len < header_len) return false;

        const end = @min(total_len, data.len);
        var valid = total_len <= data.len;
        const fragment = readBe16(data, 6);
        const fragment_offset = fragment & 0x1fff;
        if (fragment_offset != 0 or fragment & 0x2000 != 0) self.stats.fragments += 1;
        if (fragment & 0x3fff != 0) return valid;

        const transport_valid = try self.parseTransport(
            data[9],
            data[12..16],
            data[16..20],
            data[header_len..end],
            null,
        );
        valid = valid and transport_valid;
        return valid;
    }

    fn parseIpv6(self: *Parser, data: []const u8) !bool {
        self.stats.ipv6_packets += 1;
        if (data.len < 40 or data[0] >> 4 != 6) return false;

        const payload_len: usize = readBe16(data, 4);
        // Zero means either no payload or a jumbogram; both require avoiding captured link padding here.
        if (payload_len == 0) return true;
        const expected = 40 + payload_len;
        const end = @min(expected, data.len);
        var valid = expected <= data.len;
        var next = data[6];
        var offset: usize = 40;
        var extensions: usize = 0;
        var fragmented = false;
        var more_fragments = false;

        while (true) {
            switch (next) {
                0, 43, 60, 135 => {
                    if (extensions == max_ipv6_extensions or end - offset < 2) return false;
                    const size: usize = (@as(usize, data[offset + 1]) + 1) * 8;
                    if (size > end - offset) return false;
                    next = data[offset];
                    offset += size;
                    extensions += 1;
                },
                51 => {
                    if (extensions == max_ipv6_extensions or end - offset < 2) return false;
                    const size: usize = (@as(usize, data[offset + 1]) + 2) * 4;
                    if (size < 12 or size > end - offset) return false;
                    next = data[offset];
                    offset += size;
                    extensions += 1;
                },
                44 => {
                    if (extensions == max_ipv6_extensions or end - offset < 8) return false;
                    const fragment = readBe16(data, offset + 2);
                    self.stats.fragments += 1;
                    if (data[offset + 1] != 0 or fragment & 0x0006 != 0) return false;
                    fragmented = true;
                    next = data[offset];
                    offset += 8;
                    extensions += 1;
                    if (fragment & 0xfff8 != 0) return valid;
                    more_fragments = fragment & 0x0001 != 0;
                },
                50, 59 => return valid,
                else => break,
            }
        }

        if (offset > end) return false;
        if (fragmented and next == 58 and offset < end and isNeighborDiscoveryType(data[offset])) return false;
        if (more_fragments) return valid;
        const transport_valid = try self.parseTransport(next, data[8..24], data[24..40], data[offset..end], data[7]);
        valid = valid and transport_valid;
        return valid;
    }

    fn parseTransport(
        self: *Parser,
        next: u8,
        source: []const u8,
        destination: []const u8,
        data: []const u8,
        hop_limit: ?u8,
    ) !bool {
        return switch (next) {
            6 => self.parseTcp(source, destination, data),
            17 => self.parseUdp(source, destination, data),
            1 => blk: {
                self.stats.icmp_packets += 1;
                break :blk data.len >= 4;
            },
            58 => blk: {
                self.stats.icmp_packets += 1;
                break :blk self.parseIcmpv6(source, destination, data, hop_limit orelse return false);
            },
            else => true,
        };
    }

    fn parseIcmpv6(
        self: *Parser,
        source: []const u8,
        destination: []const u8,
        data: []const u8,
        hop_limit: u8,
    ) !bool {
        if (data.len < 4) return false;
        const message_type = data[0];
        if (message_type != 135 and message_type != 136) return true;
        if (hop_limit != 255) return false;
        if (source.len != 16 or destination.len != 16 or data.len < 24 or data[1] != 0) return false;
        if (!validIcmpv6Checksum(source, destination, data)) return false;
        if (source[0] == 0xff or (message_type == 136 and isIpv6Unspecified(source))) return false;
        if (message_type == 136 and destination[0] == 0xff and data[4] & 0x40 != 0) return false;

        const target = data[8..24];
        if (isIpv6Unspecified(target) or target[0] == 0xff) return false;
        const options = parseNdpOptions(data[24..]) orelse return false;
        if (self.stats.ndp_observations >= max_passive_observations) return true;
        if (message_type == 135 and isIpv6Unspecified(source)) return true;

        var address_buffer: [64]u8 = undefined;
        var peer_buffer: [64]u8 = undefined;
        var source_link_buffer: [64]u8 = undefined;
        var target_link_buffer: [64]u8 = undefined;
        const source_link = try formatLinkLayer(&source_link_buffer, options.source_link_layer);
        const target_link = try formatLinkLayer(&target_link_buffer, options.target_link_layer);
        var evidence_buffer: [256]u8 = undefined;
        const evidence = if (message_type == 135)
            try std.fmt.bufPrint(
                &evidence_buffer,
                "NDP neighbor solicitation; target={s}; source_lladdr={s}; target_lladdr={s}",
                .{ try formatAddress(&peer_buffer, target), source_link, target_link },
            )
        else
            try std.fmt.bufPrint(
                &evidence_buffer,
                "NDP neighbor advertisement; from={s}; router={s}; solicited={s}; override={s}; source_lladdr={s}; target_lladdr={s}",
                .{
                    try formatAddress(&peer_buffer, source),
                    if (data[4] & 0x80 != 0) "yes" else "no",
                    if (data[4] & 0x40 != 0) "yes" else "no",
                    if (data[4] & 0x20 != 0) "yes" else "no",
                    source_link,
                    target_link,
                },
            );
        if (try self.result.addNetworkObservation(.{
            .kind = .host,
            .confidence = if (message_type == 136) .confirmed else .observed,
            .address = try formatAddress(&address_buffer, if (message_type == 136) target else source),
            .evidence = evidence,
            .source_id = "pcap:ndp",
        })) self.stats.ndp_observations += 1;
        return true;
    }

    fn parseTcp(self: *Parser, source: []const u8, destination: []const u8, data: []const u8) !bool {
        self.stats.tcp_packets += 1;
        if (data.len < 20) return false;
        const source_port = readBe16(data, 0);
        const destination_port = readBe16(data, 2);
        const sequence = readU32(data, 4, .big);
        const header_len: usize = @as(usize, data[12] >> 4) * 4;
        if (header_len < 20 or header_len > data.len) return false;
        const flags = data[13];
        const payload = data[header_len..];

        if (self.stats.tcp_observations < max_passive_observations) {
            const is_reset = flags & 0x04 != 0;
            const is_syn_ack = flags & 0x12 == 0x12 and !is_reset and source_port != 0;
            if (is_reset or is_syn_ack) {
                var address_buffer: [64]u8 = undefined;
                const address = try formatAddress(&address_buffer, source);
                var peer_buffer: [96]u8 = undefined;
                const peer = try formatEndpoint(&peer_buffer, destination, destination_port);
                var evidence_buffer: [160]u8 = undefined;
                const evidence = if (is_syn_ack)
                    try std.fmt.bufPrint(&evidence_buffer, "TCP SYN-ACK; peer={s}", .{peer})
                else
                    try std.fmt.bufPrint(&evidence_buffer, "TCP RST; source_port={d}; peer={s}", .{ source_port, peer });
                if (try self.result.addNetworkObservation(.{
                    .kind = if (is_syn_ack) .endpoint else .host,
                    .confidence = .confirmed,
                    .address = address,
                    .transport = if (is_syn_ack) "tcp" else "",
                    .port = if (is_syn_ack) source_port else null,
                    .evidence = evidence,
                    .source_id = "pcap:tcp",
                })) self.stats.tcp_observations += 1;
            }
        }

        const syn = flags & 0x02 != 0;
        const key = TcpKey.init(self.current_scope, source, destination, source_port, destination_port);
        if (syn and flags & 0x10 == 0) {
            if (key) |present| self.removeTcpStreamByKey(present.reversed());
        }
        const payload_sequence = sequence +% @as(u32, if (syn) 1 else 0);
        if (syn and payload.len == 0) {
            if (key) |present| _ = try self.startTcpStream(present, payload_sequence);
        } else if (payload.len != 0 and !try self.acceptTcpPayload(
            source,
            destination,
            source_port,
            destination_port,
            payload_sequence,
            payload,
            syn,
        )) {
            switch (httpDirection(payload)) {
                .request => try self.addHttpFinding(destination, destination_port),
                .response => try self.addHttpFinding(source, source_port),
                .none => {},
            }
        }
        if (key) |present| {
            if (flags & 0x04 != 0) {
                self.removeTcpStreamByKey(present);
                self.removeTcpStreamByKey(present.reversed());
            } else if (flags & 0x01 != 0) {
                self.removeTcpStreamByKey(present);
            }
        }
        return true;
    }

    fn acceptTcpPayload(
        self: *Parser,
        source: []const u8,
        destination: []const u8,
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        payload: []const u8,
        syn: bool,
    ) !bool {
        const key = TcpKey.init(self.current_scope, source, destination, source_port, destination_port) orelse return false;
        const stream_index = if (syn)
            (try self.startTcpStream(key, sequence) orelse return false)
        else
            (self.findTcpStream(key) orelse try self.createTcpStream(key) orelse return false);

        const stream = &self.tcp_streams.items[stream_index];
        if (stream.disabled) return false;
        if (stream.application_done) return true;
        if (self.stats.tcp_reassembly_segments == max_tcp_segments or
            stream.segment_count == max_tcp_segments_per_stream)
        {
            return false;
        }
        self.stats.tcp_reassembly_segments += 1;
        stream.segment_count += 1;
        if (!stream.initialized) {
            stream.next_sequence = sequence;
            stream.initialized = true;
        }

        var segment_sequence = sequence;
        var bytes = payload;
        if (sequenceBefore(segment_sequence, stream.next_sequence)) {
            const overlap: usize = @intCast(stream.next_sequence -% segment_sequence);
            if (overlap >= bytes.len) return true;
            bytes = bytes[overlap..];
            segment_sequence = stream.next_sequence;
        }

        if (segment_sequence == stream.next_sequence) {
            if (!self.canStoreTcpBytes(stream, bytes.len)) {
                self.abandonTcpStream(stream);
                return false;
            }
            try stream.data.appendSlice(self.allocator, bytes);
            self.tcp_reassembly_bytes += bytes.len;
            self.stats.tcp_reassembly_bytes += bytes.len;
            stream.next_sequence +%= @intCast(bytes.len);
            try self.flushQueuedTcpSegments(stream);
            try self.processTcpStream(stream);
            return true;
        }

        if (!sequenceBefore(stream.next_sequence, segment_sequence)) return true;
        const gap: usize = @intCast(segment_sequence -% stream.next_sequence);
        if (gap > max_tcp_stream_bytes or stream.queued_count == stream.queued.len) return true;
        if (!self.canStoreTcpBytes(stream, bytes.len)) {
            self.abandonTcpStream(stream);
            return false;
        }
        const owned = try self.allocator.dupe(u8, bytes);
        stream.queued[stream.queued_count] = .{ .sequence = segment_sequence, .data = owned };
        stream.queued_count += 1;
        self.tcp_reassembly_bytes += bytes.len;
        self.stats.tcp_reassembly_bytes += bytes.len;
        self.stats.tcp_out_of_order_segments += 1;
        return true;
    }

    fn findTcpStream(self: *const Parser, key: TcpKey) ?usize {
        for (self.tcp_streams.items, 0..) |stream, index| {
            if (TcpKey.eql(stream.key, key)) return index;
        }
        return null;
    }

    fn createTcpStream(self: *Parser, key: TcpKey) !?usize {
        if (self.tcp_streams.items.len == max_tcp_streams) {
            for (self.tcp_streams.items, 0..) |stream, index| {
                if (stream.disabled or stream.application_done or stream.segment_count == 0) {
                    self.removeTcpStreamAt(index);
                    break;
                }
            }
            if (self.tcp_streams.items.len == max_tcp_streams) return null;
        }
        try self.tcp_streams.append(self.allocator, .{ .key = key });
        self.stats.tcp_streams += 1;
        return self.tcp_streams.items.len - 1;
    }

    fn startTcpStream(self: *Parser, key: TcpKey, next_sequence: u32) !?usize {
        const index = self.findTcpStream(key) orelse try self.createTcpStream(key) orelse return null;
        const stream = &self.tcp_streams.items[index];
        self.resetTcpStream(stream);
        stream.next_sequence = next_sequence;
        stream.initialized = true;
        return index;
    }

    fn removeTcpStreamByKey(self: *Parser, key: TcpKey) void {
        const index = self.findTcpStream(key) orelse return;
        self.removeTcpStreamAt(index);
    }

    fn removeTcpStreamAt(self: *Parser, index: usize) void {
        var stream = self.tcp_streams.orderedRemove(index);
        self.tcp_reassembly_bytes -= stream.storedBytes();
        stream.deinit(self.allocator);
    }

    fn flushQueuedTcpSegments(self: *Parser, stream: *TcpStream) !void {
        while (true) {
            var candidate: ?usize = null;
            for (stream.queued[0..stream.queued_count], 0..) |segment, index| {
                if (!sequenceBefore(stream.next_sequence, segment.sequence)) {
                    candidate = index;
                    break;
                }
            }
            const index = candidate orelse return;
            const segment = stream.queued[index];
            const overlap: usize = @intCast(stream.next_sequence -% segment.sequence);
            if (overlap < segment.data.len) {
                const suffix = segment.data[overlap..];
                try stream.data.appendSlice(self.allocator, suffix);
                stream.next_sequence +%= @intCast(suffix.len);
            }
            const discarded = @min(overlap, segment.data.len);
            self.tcp_reassembly_bytes -= discarded;
            self.allocator.free(segment.data);
            stream.queued_count -= 1;
            if (index != stream.queued_count) stream.queued[index] = stream.queued[stream.queued_count];
        }
    }

    fn processTcpStream(self: *Parser, stream: *TcpStream) !void {
        if (stream.application_done) return;
        const address_len: usize = stream.key.address_len;
        const source = stream.key.source[0..address_len];
        const destination = stream.key.destination[0..address_len];
        if (stream.key.source_port == 53 or stream.key.destination_port == 53) {
            var consumed: usize = 0;
            while (stream.data.items.len - consumed >= 2) {
                const message_len: usize = readBe16(stream.data.items, consumed);
                if (message_len > stream.data.items.len - consumed - 2) break;
                const message = stream.data.items[consumed + 2 .. consumed + 2 + message_len];
                if (try self.parseDnsFamily(source, destination, message, .dns)) self.stats.dns_tcp_messages += 1;
                consumed += 2 + message_len;
            }
            if (consumed != 0) self.consumeTcpData(stream, consumed);
            return;
        }

        const tls_hello = tls_certificate.parseHello(stream.data.items) catch {
            stream.application_done = true;
            self.releaseTcpStorage(stream);
            return;
        };
        switch (tls_hello) {
            .need_more => return,
            .not_tls => {},
            .unsupported => {
                stream.application_done = true;
                self.releaseTcpStorage(stream);
                return;
            },
            .client => |hello| {
                try self.addTlsClientHello(destination, stream.key.destination_port, &hello);
                stream.application_done = true;
                self.releaseTcpStorage(stream);
                return;
            },
            .server => |hello| {
                try self.addTlsServerHello(source, stream.key.source_port, hello);
                stream.application_done = true;
                self.releaseTcpStorage(stream);
                return;
            },
        }

        switch (httpDirection(stream.data.items)) {
            .request => {
                try self.addHttpFinding(destination, stream.key.destination_port);
                stream.application_done = true;
                self.releaseTcpStorage(stream);
            },
            .response => {
                try self.addHttpFinding(source, stream.key.source_port);
                stream.application_done = true;
                self.releaseTcpStorage(stream);
            },
            .none => {
                const waiting_for_http2_preface = std.mem.startsWith(u8, stream.data.items, "PRI * HTTP/2.0") and
                    stream.data.items.len < "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".len;
                if ((!waiting_for_http2_preface and std.mem.indexOfScalar(u8, stream.data.items, '\n') != null) or
                    stream.data.items.len >= max_http_line_bytes)
                {
                    stream.application_done = true;
                    self.releaseTcpStorage(stream);
                }
            },
        }
    }

    fn canStoreTcpBytes(self: *const Parser, stream: *const TcpStream, additional: usize) bool {
        const stream_bytes = stream.storedBytes();
        return additional <= max_tcp_stream_bytes - stream_bytes and
            additional <= max_tcp_reassembly_bytes - self.tcp_reassembly_bytes;
    }

    fn consumeTcpData(self: *Parser, stream: *TcpStream, count: usize) void {
        std.debug.assert(count <= stream.data.items.len);
        const remaining = stream.data.items.len - count;
        std.mem.copyForwards(u8, stream.data.items[0..remaining], stream.data.items[count..]);
        stream.data.items.len = remaining;
        self.tcp_reassembly_bytes -= count;
    }

    fn resetTcpStream(self: *Parser, stream: *TcpStream) void {
        self.releaseTcpStorage(stream);
        stream.next_sequence = 0;
        stream.initialized = false;
        stream.disabled = false;
        stream.application_done = false;
        stream.segment_count = 0;
    }

    fn abandonTcpStream(self: *Parser, stream: *TcpStream) void {
        self.releaseTcpStorage(stream);
        stream.disabled = true;
        stream.application_done = true;
    }

    fn releaseTcpStorage(self: *Parser, stream: *TcpStream) void {
        self.tcp_reassembly_bytes -= stream.storedBytes();
        stream.data.clearRetainingCapacity();
        for (stream.queued[0..stream.queued_count]) |segment| self.allocator.free(segment.data);
        stream.queued_count = 0;
    }

    fn parseUdp(self: *Parser, source: []const u8, destination: []const u8, data: []const u8) !bool {
        self.stats.udp_packets += 1;
        if (data.len < 8) return false;
        const source_port = readBe16(data, 0);
        const destination_port = readBe16(data, 2);
        const udp_len: usize = readBe16(data, 4);
        if (udp_len < 8) return false;
        const end = @min(udp_len, data.len);
        var valid = udp_len <= data.len;
        const family: ?dns.Family = if (source_port == 53 or destination_port == 53)
            .dns
        else if (source_port == 5353 or destination_port == 5353)
            .mdns
        else if (source_port == 5355 or destination_port == 5355)
            .llmnr
        else
            null;
        const payload = data[8..end];
        if (family) |detected| {
            valid = (try self.parseDnsFamily(source, destination, payload, detected)) and valid;
        } else if (source_port == 137 or destination_port == 137) {
            valid = (try self.parseNbns(source, destination, payload)) and valid;
        } else if (source.len == 4 and
            destination.len == 4 and
            (source_port == 67 or source_port == 68) and
            (destination_port == 67 or destination_port == 68))
        {
            valid = (try self.parseDhcp(source, source_port, destination_port, payload)) and valid;
        } else if (source.len == 16 and
            destination.len == 16 and
            (source_port == 546 or source_port == 547) and
            (destination_port == 546 or destination_port == 547))
        {
            valid = (try self.parseDhcpv6(source, source_port, destination_port, payload)) and valid;
        } else if (source_port == 1900 or destination_port == 1900) {
            valid = (try self.parseSsdp(source, source_port, payload)) and valid;
        }
        return valid;
    }

    fn parseNbns(self: *Parser, source: []const u8, destination: []const u8, data: []const u8) !bool {
        self.stats.nbns_messages += 1;
        var name_buffer: [nbns.max_name_text_len]u8 = undefined;
        const message = nbns.decodeFirstQuestion(data, &name_buffer) catch return false;

        if (message.first_question) |question| {
            var field_buffer: [nbns.max_name_text_len + 64]u8 = undefined;
            _ = try self.addNbnsField(try std.fmt.bufPrint(
                &field_buffer,
                "question {s}; type={d}; class={d}",
                .{ question.name, question.query_type, question.class },
            ));

            if (self.stats.nbns_observations < max_nbns_records) {
                var address_buffer: [64]u8 = undefined;
                const requester = try formatAddress(
                    &address_buffer,
                    if (message.header.is_response) destination else source,
                );
                var evidence_buffer: [96]u8 = undefined;
                const evidence = try std.fmt.bufPrint(
                    &evidence_buffer,
                    "type={d}; class={d}; opcode={d}",
                    .{ question.query_type, question.class, message.header.opcode },
                );
                if (try self.result.addNetworkObservation(.{
                    .kind = .name_query,
                    .confidence = .observed,
                    .address = requester,
                    .hostname = question.name,
                    .evidence = evidence,
                    .source_id = "pcap:nbns",
                })) self.stats.nbns_observations += 1;
            }
        }

        const valid_response = message.header.is_response and
            !message.header.truncated and
            message.header.opcode == 0 and
            message.header.rcode == 0;
        var responder_buffer: [64]u8 = undefined;
        const responder = try formatAddress(&responder_buffer, source);
        var iterator = nbns.answers(data) catch return false;
        while (true) {
            const answer = (iterator.next(&name_buffer) catch return false) orelse break;
            self.stats.nbns_answers += 1;
            switch (answer.value) {
                .nb => |addresses| {
                    var entries = addresses.iterator();
                    while (entries.next()) |entry| {
                        var address_buffer: [64]u8 = undefined;
                        const address = try formatAddress(&address_buffer, &entry.address);
                        var field_buffer: [nbns.max_name_text_len + 192]u8 = undefined;
                        const summary = try std.fmt.bufPrint(
                            &field_buffer,
                            "answer {s}; address={s}; flags=0x{x:0>4}; group={s}; node_type={d}; ttl={d}; from={s}",
                            .{
                                answer.name,
                                address,
                                entry.flags,
                                if (entry.group) "yes" else "no",
                                entry.node_type,
                                answer.ttl,
                                responder,
                            },
                        );
                        _ = try self.addNbnsField(summary);

                        if (valid_response and
                            answer.record_type == 0x20 and
                            answer.class == 1 and
                            answer.ttl != 0 and
                            entry.flags & 0x1fff == 0 and
                            isValidNbnsAddress(&entry.address) and
                            self.stats.nbns_observations < max_nbns_records)
                        {
                            if (try self.result.addNetworkObservation(.{
                                .kind = .host,
                                .confidence = .observed,
                                .address = address,
                                .hostname = answer.name,
                                .evidence = summary,
                                .source_id = "pcap:nbns",
                            })) self.stats.nbns_observations += 1;
                        }
                    }
                },
                .unsupported => {},
            }
        }
        return true;
    }

    fn addNbnsField(self: *Parser, value: []const u8) !bool {
        for (self.result.fields.items) |field| {
            if (std.mem.startsWith(u8, field.name, "nbns_record_") and std.mem.eql(u8, field.value, value)) return false;
        }
        if (self.stats.nbns_fields == max_nbns_records) return false;
        var field_name: [24]u8 = undefined;
        try self.result.addField(
            try std.fmt.bufPrint(&field_name, "nbns_record_{d}", .{self.stats.nbns_fields + 1}),
            value,
        );
        self.stats.nbns_fields += 1;
        return true;
    }

    fn parseDhcp(
        self: *Parser,
        source: []const u8,
        source_port: u16,
        destination_port: u16,
        data: []const u8,
    ) !bool {
        self.stats.dhcp_messages += 1;
        const message = dhcp.decode(data) catch return false;

        var source_buffer: [64]u8 = undefined;
        var offered_buffer: [64]u8 = undefined;
        var requested_buffer: [64]u8 = undefined;
        var server_buffer: [64]u8 = undefined;
        var hardware_buffer: [64]u8 = undefined;
        var client_buffer: [64]u8 = undefined;
        var hostname_buffer: [64]u8 = undefined;
        var vendor_buffer: [64]u8 = undefined;
        var lease_buffer: [32]u8 = undefined;
        const hostname = limitedPrintable(&hostname_buffer, message.hostname);
        const vendor = limitedPrintable(&vendor_buffer, message.vendor_class);
        const client = try formatClientIdentifier(&client_buffer, message.client_identifier);
        const lease = if (message.lease_time) |seconds|
            try std.fmt.bufPrint(&lease_buffer, "{d}s", .{seconds})
        else
            "none";
        const requested = if (message.requested_ip) |address|
            try formatAddress(&requested_buffer, &address)
        else
            "none";
        const server = if (message.server_identifier) |address|
            try formatAddress(&server_buffer, &address)
        else
            "none";
        var summary_buffer: [768]u8 = undefined;
        const summary = try std.fmt.bufPrint(
            &summary_buffer,
            "type={s}; yiaddr={s}; requested_ip={s}; hostname={s}; server_id={s}; lease={s}; chaddr={s}; vendor={s}; client_id={s}; from={s}:{d}",
            .{
                dhcpMessageTypeName(message.message_type),
                try formatAddress(&offered_buffer, &message.your_address),
                requested,
                if (hostname.len == 0) "none" else hostname,
                server,
                lease,
                try formatLinkLayer(&hardware_buffer, message.client_hardware_address),
                if (vendor.len == 0) "none" else vendor,
                client,
                try formatAddress(&source_buffer, source),
                source_port,
            },
        );

        var field_exists = false;
        for (self.result.fields.items) |field| {
            if (std.mem.startsWith(u8, field.name, "dhcp_") and std.mem.eql(u8, field.value, summary)) {
                field_exists = true;
                break;
            }
        }
        if (!field_exists and self.stats.dhcp_fields < max_dhcp_records) {
            var field_name: [24]u8 = undefined;
            try self.result.addField(
                try std.fmt.bufPrint(&field_name, "dhcp_{d}", .{self.stats.dhcp_fields + 1}),
                summary,
            );
            self.stats.dhcp_fields += 1;
        }

        const message_type = message.message_type orelse return true;
        if (message.op == 2 and
            source_port == 67 and
            (destination_port == 67 or destination_port == 68) and
            (message_type == .offer or message_type == .ack) and
            !isZeroAddress(&message.your_address) and
            self.stats.dhcp_observations < max_dhcp_records)
        {
            if (try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .address = try formatAddress(&offered_buffer, &message.your_address),
                .hostname = hostname,
                .evidence = summary,
                .source_id = "pcap:dhcp",
            })) self.stats.dhcp_observations += 1;
        }
        return true;
    }

    fn parseDhcpv6(
        self: *Parser,
        source: []const u8,
        source_port: u16,
        destination_port: u16,
        data: []const u8,
    ) !bool {
        self.stats.dhcpv6_messages += 1;
        var fqdn_buffer: [dhcpv6.max_fqdn_text_len]u8 = undefined;
        const message = dhcpv6.decode(data, &fqdn_buffer) catch return false;

        const fqdn_value = message.fqdn orelse "";
        const fqdn = fqdn_value[0..@min(fqdn_value.len, 256)];
        var source_buffer: [64]u8 = undefined;
        var assignment_buffer: [64]u8 = undefined;
        const first_assignment = if (message.address_count != 0)
            try formatAddress(&assignment_buffer, &message.addresses[0].address)
        else
            "none";
        var summary_buffer: [1536]u8 = undefined;
        const summary = try std.fmt.bufPrint(
            &summary_buffer,
            "type={s}; transaction=0x{x:0>6}; client_id={d} bytes; server_id={d} bytes; fqdn={s}; ia_na={d}; addresses={d}; first_address={s}; preferred={d}s; valid={d}s; preference={d}; elapsed={d}; rapid_commit={s}; status={d}; dns_servers={d}; domains={d}; from={s}:{d}",
            .{
                dhcpv6MessageTypeName(message.message_type),
                message.transaction_id,
                if (message.client_identifier) |value| value.len else 0,
                if (message.server_identifier) |value| value.len else 0,
                if (fqdn.len == 0) "none" else fqdn,
                message.ia_na_count,
                message.address_count,
                first_assignment,
                if (message.address_count != 0) message.addresses[0].preferred_lifetime else 0,
                if (message.address_count != 0) message.addresses[0].valid_lifetime else 0,
                message.preference orelse 0,
                message.elapsed_time orelse 0,
                if (message.rapid_commit) "yes" else "no",
                message.status_code orelse 0,
                message.dns_server_count,
                message.domain_name_count,
                try formatAddress(&source_buffer, source),
                source_port,
            },
        );

        var field_exists = false;
        for (self.result.fields.items) |field| {
            if (std.mem.startsWith(u8, field.name, "dhcpv6_") and std.mem.eql(u8, field.value, summary)) {
                field_exists = true;
                break;
            }
        }
        if (!field_exists and self.stats.dhcpv6_fields < max_dhcp_records) {
            var field_name: [24]u8 = undefined;
            try self.result.addField(
                try std.fmt.bufPrint(&field_name, "dhcpv6_{d}", .{self.stats.dhcpv6_fields + 1}),
                summary,
            );
            self.stats.dhcpv6_fields += 1;
        }

        if (!message.hasValidAssignment() or
            source_port != 547 or destination_port != 546 or
            !isValidDhcpv6Address(source)) return true;
        for (message.addresses[0..message.address_count]) |assignment| {
            if (self.stats.dhcpv6_observations == max_dhcp_records) break;
            if (!isValidDhcpv6Address(&assignment.address)) continue;
            var address_buffer: [64]u8 = undefined;
            if (try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .address = try formatAddress(&address_buffer, &assignment.address),
                .hostname = fqdn,
                .evidence = summary,
                .source_id = "pcap:dhcpv6",
            })) self.stats.dhcpv6_observations += 1;
        }
        return true;
    }

    fn parseSsdp(self: *Parser, source: []const u8, source_port: u16, data: []const u8) !bool {
        self.stats.ssdp_messages += 1;
        const message = ssdp.decode(data) catch return false;

        var address_buffer: [64]u8 = undefined;
        const address = try formatAddress(&address_buffer, source);
        var summary_buffer: [1024]u8 = undefined;
        const summary = try std.fmt.bufPrint(
            &summary_buffer,
            "kind={s}; status={d}; st={s}; nt={s}; usn={s}; location={s}; server={s}; from={s}; source_port={d}",
            .{
                ssdpKindName(message.kind),
                message.status_code orelse 0,
                limitedSsdpValue(message.st),
                limitedSsdpValue(message.nt),
                limitedSsdpValue(message.usn),
                limitedSsdpValue(message.location),
                limitedSsdpValue(message.server),
                address,
                source_port,
            },
        );

        var field_exists = false;
        for (self.result.fields.items) |field| {
            if (std.mem.startsWith(u8, field.name, "ssdp_") and std.mem.eql(u8, field.value, summary)) {
                field_exists = true;
                break;
            }
        }
        if (!field_exists and self.stats.ssdp_fields < max_ssdp_records) {
            var field_name: [24]u8 = undefined;
            try self.result.addField(
                try std.fmt.bufPrint(&field_name, "ssdp_{d}", .{self.stats.ssdp_fields + 1}),
                summary,
            );
            self.stats.ssdp_fields += 1;
        }

        if (self.stats.ssdp_observations < max_ssdp_records) {
            const search_target = message.st orelse message.nt orelse "ssdp";
            if (try self.result.addNetworkObservation(.{
                .kind = if (message.kind == .m_search) .name_query else .service,
                .confidence = .observed,
                .address = address,
                .transport = "udp",
                .service = search_target,
                .evidence = summary,
                .source_id = "pcap:ssdp",
            })) self.stats.ssdp_observations += 1;
        }
        return true;
    }

    fn parseDnsFamily(
        self: *Parser,
        source: []const u8,
        destination: []const u8,
        data: []const u8,
        family: dns.Family,
    ) !bool {
        if (data.len < 12) return false;
        messageCounter(&self.stats, family).* += 1;

        var name_buffer: [dns.max_name_text_len]u8 = undefined;
        const message = dns.decodeFirstQuestion(data, family, &name_buffer) catch return false;
        if (!validateDnsRecords(data, family)) return false;
        var generation: usize = 0;
        if (family == .mdns) {
            self.mdns_generation +%= 1;
            if (self.mdns_generation == 0) self.mdns_generation = 1;
            generation = self.mdns_generation;
        }
        if (message.first_question) |question| {
            var field_value: [dns.max_name_text_len + 32]u8 = undefined;
            const value = try std.fmt.bufPrint(&field_value, "{s} (type {d})", .{ question.name, question.query_type });
            const prefix = queryFieldPrefix(family);
            var field_exists = false;
            for (self.result.fields.items) |field| {
                if (std.mem.startsWith(u8, field.name, prefix) and std.mem.eql(u8, field.value, value)) {
                    field_exists = true;
                    break;
                }
            }
            const field_count = queryFieldCounter(&self.stats, family);
            if (!field_exists and field_count.* < max_name_queries) {
                var field_name: [32]u8 = undefined;
                const name = try std.fmt.bufPrint(&field_name, "{s}{d}", .{ prefix, field_count.* + 1 });
                try self.result.addField(name, value);
                field_count.* += 1;
            }

            const requester: ?[]const u8 = if (!message.header.is_response)
                source
            else if (family == .mdns)
                null
            else
                destination;
            if (requester) |requester_address| {
                const observation_count = queryObservationCounter(&self.stats, family);
                if (observation_count.* < max_name_queries) {
                    var address_buffer: [64]u8 = undefined;
                    const query_address = try formatAddress(&address_buffer, requester_address);
                    var evidence_buffer: [96]u8 = undefined;
                    const evidence = try std.fmt.bufPrint(
                        &evidence_buffer,
                        "type={d}; class={d}; unicast_response={s}",
                        .{ question.query_type, question.class, if (question.unicast_response) "yes" else "no" },
                    );
                    if (try self.result.addNetworkObservation(.{
                        .kind = .name_query,
                        .confidence = .observed,
                        .address = query_address,
                        .hostname = question.name,
                        .evidence = evidence,
                        .source_id = querySourceId(family),
                    })) observation_count.* += 1;
                }
            }
        }

        var responder_buffer: [64]u8 = undefined;
        const responder = try formatAddress(&responder_buffer, source);
        var iterator = dns.answers(data, family) catch return false;
        var owner_buffer: [dns.max_name_text_len]u8 = undefined;
        var value_buffer: [dns.max_name_text_len]u8 = undefined;
        while (true) {
            const answer = iterator.next(&owner_buffer, &value_buffer) catch |err| switch (err) {
                error.TooManyAnswers => break,
                else => return false,
            } orelse break;
            answerCounter(&self.stats, family).* += 1;
            if (family == .mdns) try self.mdns_links.remember(self.current_scope, generation, answer);
            try self.addDnsRecord(family, responder, answer, .answer);
        }

        var authority_iterator = dns.authority(data, family) catch return false;
        while (true) {
            const record = authority_iterator.next(&owner_buffer, &value_buffer) catch |err| switch (err) {
                error.TooManyAnswers => break,
                else => return false,
            } orelse break;
            authorityCounter(&self.stats, family).* += 1;
            try self.addDnsRecord(family, responder, record, .authority);
        }

        var additional_iterator = dns.additional(data, family) catch return false;
        while (true) {
            const record = additional_iterator.next(&owner_buffer, &value_buffer) catch |err| switch (err) {
                error.TooManyAnswers => break,
                else => return false,
            } orelse break;
            additionalCounter(&self.stats, family).* += 1;
            if (family == .mdns) try self.mdns_links.remember(self.current_scope, generation, record);
            try self.addDnsRecord(family, responder, record, .additional);
        }
        if (family == .mdns) try self.addMdnsAssociations(self.current_scope, &self.mdns_links);
        return true;
    }

    fn addDnsRecord(
        self: *Parser,
        family: dns.Family,
        responder: []const u8,
        answer: dns.Answer,
        section: DnsRecordSection,
    ) !void {
        if (recordFieldCounter(&self.stats, family, section).* >= recordLimit(section)) return;

        var field_value: [protocol.max_field_value_bytes]u8 = undefined;
        var address_buffer: [64]u8 = undefined;
        const flush = if (answer.cache_flush) "yes" else "no";
        const value = switch (answer.value) {
            .a => |address| try std.fmt.bufPrint(
                &field_value,
                "{s} A {s} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, try formatAddress(&address_buffer, &address), answer.ttl, answer.class, flush, responder },
            ),
            .aaaa => |address| try std.fmt.bufPrint(
                &field_value,
                "{s} AAAA {s} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, try formatAddress(&address_buffer, &address), answer.ttl, answer.class, flush, responder },
            ),
            .cname => |target| try std.fmt.bufPrint(
                &field_value,
                "{s} CNAME {s} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, target, answer.ttl, answer.class, flush, responder },
            ),
            .ns => |target| try std.fmt.bufPrint(
                &field_value,
                "{s} NS {s} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, target, answer.ttl, answer.class, flush, responder },
            ),
            .ptr => |target| try std.fmt.bufPrint(
                &field_value,
                "{s} PTR {s} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, target, answer.ttl, answer.class, flush, responder },
            ),
            .mx => |mx| try std.fmt.bufPrint(
                &field_value,
                "{s} MX {s} preference={d} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, mx.exchange, mx.preference, answer.ttl, answer.class, flush, responder },
            ),
            .soa => |soa| try std.fmt.bufPrint(
                &field_value,
                "{s} SOA mname={s} rname={s} serial={d} refresh={d} retry={d} expire={d} minimum={d} ttl={d} class={d} flush={s} from={s}",
                .{
                    answer.name,
                    soa.mname,
                    soa.rname,
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expire,
                    soa.minimum,
                    answer.ttl,
                    answer.class,
                    flush,
                    responder,
                },
            ),
            .srv => |srv| try std.fmt.bufPrint(
                &field_value,
                "{s} SRV {s}:{d} priority={d} weight={d} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, srv.target, srv.port, srv.priority, srv.weight, answer.ttl, answer.class, flush, responder },
            ),
            .txt => |txt| try std.fmt.bufPrint(
                &field_value,
                "{s} TXT strings={d} bytes={d} ttl={d} class={d} flush={s} from={s}",
                .{ answer.name, txt.strings, txt.raw.len, answer.ttl, answer.class, flush, responder },
            ),
            .unsupported => return,
        };
        if (!try self.addDnsRecordField(family, section, value)) return;
        if (answer.ttl == 0) return;

        switch (answer.value) {
            .a => |address| _ = try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .address = try formatAddress(&address_buffer, &address),
                .hostname = answer.name,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .aaaa => |address| _ = try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .address = try formatAddress(&address_buffer, &address),
                .hostname = answer.name,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .cname => |target| _ = try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .hostname = target,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .ns => |target| _ = try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .hostname = target,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .ptr => |target| _ = try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .hostname = target,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .mx => |mx| _ = try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .hostname = mx.exchange,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .soa => |soa| _ = try self.result.addNetworkObservation(.{
                .kind = .host,
                .confidence = .observed,
                .hostname = soa.mname,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .srv => |srv| _ = try self.result.addNetworkObservation(.{
                .kind = .service,
                .confidence = .observed,
                .hostname = srv.target,
                .transport = serviceTransport(answer.name),
                .port = srv.port,
                .service = answer.name,
                .evidence = value,
                .source_id = recordSourceId(family, section),
            }),
            .txt, .unsupported => {},
        }
    }

    fn addDnsRecordField(
        self: *Parser,
        family: dns.Family,
        section: DnsRecordSection,
        value: []const u8,
    ) !bool {
        const prefix = recordFieldPrefix(family, section);
        for (self.result.fields.items) |field| {
            if (std.mem.startsWith(u8, field.name, prefix) and std.mem.eql(u8, field.value, value)) return false;
        }
        const field_count = recordFieldCounter(&self.stats, family, section);
        if (field_count.* >= recordLimit(section)) return false;
        var field_name: [32]u8 = undefined;
        try self.result.addField(
            try std.fmt.bufPrint(&field_name, "{s}{d}", .{ prefix, field_count.* + 1 }),
            value,
        );
        field_count.* += 1;
        return true;
    }

    fn addMdnsAssociations(self: *Parser, scope: usize, links: *const MdnsLinks) !void {
        if (self.stats.mdns_associations == max_mdns_links) return;
        for (links.ptrs[0..links.ptr_count]) |ptr| {
            if (ptr.scope != scope) continue;
            const service = ptr.service[0..ptr.service_len];
            const transport = serviceTransport(service);
            if (transport.len == 0) continue;
            const instance = ptr.instance[0..ptr.instance_len];
            for (links.srvs[0..links.srv_count]) |srv| {
                if (srv.scope != scope or !std.ascii.eqlIgnoreCase(instance, srv.instance[0..srv.instance_len])) continue;
                const hostname = srv.hostname[0..srv.hostname_len];
                for (links.addresses[0..links.address_count]) |address| {
                    if (address.scope != scope or !std.ascii.eqlIgnoreCase(hostname, address.hostname[0..address.hostname_len])) continue;
                    var evidence_buffer: [dns.max_name_text_len * 3 + 256]u8 = undefined;
                    const evidence = try std.fmt.bufPrint(
                        &evidence_buffer,
                        "capture mDNS PTR {s} -> {s}; SRV -> {s}:{d}; address={s}",
                        .{ service, instance, hostname, srv.port, address.address[0..address.address_len] },
                    );
                    if (try self.result.addNetworkObservation(.{
                        .kind = .service,
                        .confidence = .observed,
                        .address = address.address[0..address.address_len],
                        .hostname = hostname,
                        .transport = transport,
                        .port = srv.port,
                        .service = service,
                        .evidence = evidence,
                        .source_id = "pcap:mdns:service-discovery",
                    })) {
                        self.stats.mdns_associations += 1;
                        if (self.stats.mdns_associations == max_mdns_links) return;
                    }
                }
            }
        }
    }

    fn addHttpFinding(self: *Parser, address: []const u8, port: u16) !void {
        if (self.http_reported) return;
        var target_buffer: [96]u8 = undefined;
        const target = try formatEndpoint(&target_buffer, address, port);
        try self.result.addDetailedFinding(
            .low,
            "Cleartext HTTP traffic observed",
            "An unencrypted HTTP request or response was present in the capture.",
            target,
            "pcap:cleartext-http",
        );
        self.http_reported = true;
    }

    fn addTlsClientHello(
        self: *Parser,
        destination: []const u8,
        destination_port: u16,
        hello: *const tls_certificate.ClientHello,
    ) !void {
        self.stats.tls_client_hellos += 1;
        const highest_offered_version = clientHighestTlsVersion(hello);
        const server_name = if (hello.serverName().len == 0) "none" else hello.serverName();
        const alpn = if (hello.alpnSummary().len == 0) "none" else hello.alpnSummary();

        var destination_buffer: [96]u8 = undefined;
        var field_value: [896]u8 = undefined;
        try self.addTlsField(
            "tls_client_hello_",
            &self.stats.tls_client_fields,
            try std.fmt.bufPrint(
                &field_value,
                "server={s}; sni={s}; offered_alpn={s}; alpn_truncated={s}; highest_offered_version={s}; offers_tls_1_2={s}; offers_tls_1_3={s}; cipher_suites={d}",
                .{
                    try formatEndpoint(&destination_buffer, destination, destination_port),
                    server_name,
                    alpn,
                    if (hello.alpn_truncated) "yes" else "no",
                    highest_offered_version,
                    if (hello.offers_tls_1_2) "yes" else "no",
                    if (hello.offers_tls_1_3) "yes" else "no",
                    hello.cipher_suite_count,
                },
            ),
        );

        if (self.stats.tls_client_observations < max_tls_hellos) {
            var address_buffer: [64]u8 = undefined;
            var evidence_buffer: [320]u8 = undefined;
            if (try self.result.addNetworkObservation(.{
                .kind = .service,
                .confidence = .inferred,
                .address = try formatAddress(&address_buffer, destination),
                .hostname = hello.serverName(),
                .transport = "tcp",
                .port = destination_port,
                .service = "tls",
                .evidence = try std.fmt.bufPrint(
                    &evidence_buffer,
                    "TLS ClientHello; offered_alpn={s}; highest_offered_version={s}; offers_tls_1_2={s}; offers_tls_1_3={s}; cipher_suites={d}",
                    .{
                        alpn,
                        highest_offered_version,
                        if (hello.offers_tls_1_2) "yes" else "no",
                        if (hello.offers_tls_1_3) "yes" else "no",
                        hello.cipher_suite_count,
                    },
                ),
                .source_id = "pcap:tls-client-hello",
            })) self.stats.tls_client_observations += 1;
        }
    }

    fn addTlsServerHello(
        self: *Parser,
        source: []const u8,
        source_port: u16,
        hello: tls_certificate.Negotiated,
    ) !void {
        self.stats.tls_server_hellos += 1;
        const version = tlsVersionText(hello.version);
        const cipher = std.enums.tagName(std.crypto.tls.CipherSuite, hello.cipher_suite) orelse "unknown";

        var source_buffer: [96]u8 = undefined;
        var field_value: [384]u8 = undefined;
        try self.addTlsField(
            "tls_server_hello_",
            &self.stats.tls_server_fields,
            try std.fmt.bufPrint(
                &field_value,
                "server={s}; version={s}; cipher={s}; cipher_id=0x{x:0>4}",
                .{
                    try formatEndpoint(&source_buffer, source, source_port),
                    version,
                    cipher,
                    @intFromEnum(hello.cipher_suite),
                },
            ),
        );

        if (self.stats.tls_server_observations < max_tls_hellos) {
            var address_buffer: [64]u8 = undefined;
            var evidence_buffer: [256]u8 = undefined;
            if (try self.result.addNetworkObservation(.{
                .kind = .service,
                .confidence = .confirmed,
                .address = try formatAddress(&address_buffer, source),
                .transport = "tcp",
                .port = source_port,
                .service = "tls",
                .version = version,
                .evidence = try std.fmt.bufPrint(
                    &evidence_buffer,
                    "TLS ServerHello; cipher={s}; cipher_id=0x{x:0>4}",
                    .{ cipher, @intFromEnum(hello.cipher_suite) },
                ),
                .source_id = "pcap:tls-server-hello",
            })) self.stats.tls_server_observations += 1;
        }
    }

    fn addTlsField(self: *Parser, prefix: []const u8, counter: *usize, value: []const u8) !void {
        for (self.result.fields.items) |field| {
            if (std.mem.startsWith(u8, field.name, prefix) and std.mem.eql(u8, field.value, value)) return;
        }
        if (counter.* == max_tls_hellos) return;
        counter.* += 1;
        var field_name: [32]u8 = undefined;
        try self.result.addField(try std.fmt.bufPrint(&field_name, "{s}{d}", .{ prefix, counter.* }), value);
    }
};

pub fn analyzeCapture(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    if (data.len < 4) return error.TruncatedCapture;

    var result = try protocol.AnalysisResult.init(allocator, "Packet capture");
    errdefer result.deinit();
    var parser = Parser{ .allocator = allocator, .result = &result };
    defer parser.deinit();

    if (std.mem.eql(u8, data[0..4], &.{ 0xd4, 0xc3, 0xb2, 0xa1 })) {
        try parser.parseClassic(data, .little, false);
    } else if (std.mem.eql(u8, data[0..4], &.{ 0xa1, 0xb2, 0xc3, 0xd4 })) {
        try parser.parseClassic(data, .big, false);
    } else if (std.mem.eql(u8, data[0..4], &.{ 0x4d, 0x3c, 0xb2, 0xa1 })) {
        try parser.parseClassic(data, .little, true);
    } else if (std.mem.eql(u8, data[0..4], &.{ 0xa1, 0xb2, 0x3c, 0x4d })) {
        try parser.parseClassic(data, .big, true);
    } else if (std.mem.eql(u8, data[0..4], &.{ 0x0a, 0x0d, 0x0d, 0x0a })) {
        try parser.parsePcapng(data);
    } else {
        return error.UnsupportedCaptureFormat;
    }

    const summary = try std.fmt.allocPrint(
        allocator,
        "{s}: {d} packet{s}, IPv4={d}, IPv6={d}, TCP={d}, UDP={d}, TLS={d}, DNS={d}, mDNS={d}, LLMNR={d}, NBNS={d}, DHCP={d}, DHCPv6={d}, SSDP={d}, malformed={d}",
        .{
            parser.stats.format,
            parser.stats.packets,
            if (parser.stats.packets == 1) "" else "s",
            parser.stats.ipv4_packets,
            parser.stats.ipv6_packets,
            parser.stats.tcp_packets,
            parser.stats.udp_packets,
            parser.stats.tls_client_hellos + parser.stats.tls_server_hellos,
            parser.stats.dns_messages,
            parser.stats.mdns_messages,
            parser.stats.llmnr_messages,
            parser.stats.nbns_messages,
            parser.stats.dhcp_messages,
            parser.stats.dhcpv6_messages,
            parser.stats.ssdp_messages,
            parser.stats.malformed_packets,
        },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);

    try result.addField("format", parser.stats.format);
    try result.addField("byte_order", if (parser.stats.mixed_byte_order)
        "mixed"
    else if (parser.stats.byte_order == .little)
        "little"
    else
        "big");
    try result.addField("timestamp_resolution", parser.stats.timestamp_resolution);
    if (parser.stats.first_linktype) |linktype| {
        var buffer: [64]u8 = undefined;
        try result.addField("link_type", try std.fmt.bufPrint(&buffer, "{d} ({s})", .{ linktype, linktypeName(linktype) }));
    }
    try result.addNumberField("sections", parser.stats.sections);
    try result.addNumberField("interfaces", parser.stats.interfaces);
    try result.addNumberField("packets", parser.stats.packets);
    try result.addNumberField("captured_bytes", parser.stats.captured_bytes);
    try result.addNumberField("wire_bytes", parser.stats.wire_bytes);
    try result.addNumberField("malformed_packets", parser.stats.malformed_packets);
    try result.addNumberField("unsupported_link_packets", parser.stats.unsupported_link_packets);
    try result.addNumberField("ipv4_packets", parser.stats.ipv4_packets);
    try result.addNumberField("ipv6_packets", parser.stats.ipv6_packets);
    try result.addNumberField("fragments", parser.stats.fragments);
    try result.addNumberField("tcp_packets", parser.stats.tcp_packets);
    try result.addNumberField("tcp_reassembled_streams", parser.stats.tcp_streams);
    try result.addNumberField("tcp_reassembly_segments", parser.stats.tcp_reassembly_segments);
    try result.addNumberField("tcp_reassembly_bytes", parser.stats.tcp_reassembly_bytes);
    try result.addNumberField("tcp_out_of_order_segments", parser.stats.tcp_out_of_order_segments);
    try result.addNumberField("tls_client_hellos", parser.stats.tls_client_hellos);
    try result.addNumberField("tls_server_hellos", parser.stats.tls_server_hellos);
    try result.addNumberField(
        "tls_service_observations",
        parser.stats.tls_client_observations + parser.stats.tls_server_observations,
    );
    try result.addNumberField("udp_packets", parser.stats.udp_packets);
    try result.addNumberField("arp_packets", parser.stats.arp_packets);
    try result.addNumberField("arp_host_observations", parser.stats.arp_observations);
    try result.addNumberField("icmp_packets", parser.stats.icmp_packets);
    try result.addNumberField("ndp_host_observations", parser.stats.ndp_observations);
    try result.addNumberField("tcp_response_observations", parser.stats.tcp_observations);
    try result.addNumberField("dhcp_messages", parser.stats.dhcp_messages);
    try result.addNumberField("dhcp_host_observations", parser.stats.dhcp_observations);
    try result.addNumberField("dhcpv6_messages", parser.stats.dhcpv6_messages);
    try result.addNumberField("dhcpv6_host_observations", parser.stats.dhcpv6_observations);
    try result.addNumberField("ssdp_messages", parser.stats.ssdp_messages);
    try result.addNumberField("ssdp_observations", parser.stats.ssdp_observations);
    try result.addNumberField("nbns_messages", parser.stats.nbns_messages);
    try result.addNumberField("nbns_answer_records", parser.stats.nbns_answers);
    try result.addNumberField("nbns_observations", parser.stats.nbns_observations);
    try result.addNumberField("dns_messages", parser.stats.dns_messages);
    try result.addNumberField("dns_tcp_messages", parser.stats.dns_tcp_messages);
    try result.addNumberField("mdns_messages", parser.stats.mdns_messages);
    try result.addNumberField("llmnr_messages", parser.stats.llmnr_messages);
    try result.addNumberField("dns_answer_records", parser.stats.dns_answers);
    try result.addNumberField("mdns_answer_records", parser.stats.mdns_answers);
    try result.addNumberField("llmnr_answer_records", parser.stats.llmnr_answers);
    try result.addNumberField("dns_authority_records", parser.stats.dns_authorities);
    try result.addNumberField("mdns_authority_records", parser.stats.mdns_authorities);
    try result.addNumberField("llmnr_authority_records", parser.stats.llmnr_authorities);
    try result.addNumberField("dns_additional_records", parser.stats.dns_additionals);
    try result.addNumberField("mdns_additional_records", parser.stats.mdns_additionals);
    try result.addNumberField("mdns_service_associations", parser.stats.mdns_associations);
    try result.addNumberField("llmnr_additional_records", parser.stats.llmnr_additionals);
    return result;
}

const HttpDirection = enum { none, request, response };

fn tlsVersionText(version: std.crypto.tls.ProtocolVersion) []const u8 {
    return switch (version) {
        .tls_1_0 => "TLS 1.0",
        .tls_1_1 => "TLS 1.1",
        .tls_1_2 => "TLS 1.2",
        .tls_1_3 => "TLS 1.3",
        else => "unknown TLS version",
    };
}

fn clientHighestTlsVersion(hello: *const tls_certificate.ClientHello) []const u8 {
    if (hello.offers_tls_1_3) return "TLS 1.3";
    if (hello.offers_tls_1_2) return "TLS 1.2";
    if (hello.supported_versions_present) return "other TLS versions";
    return tlsVersionText(hello.legacy_version);
}

fn validateDnsRecords(data: []const u8, family: dns.Family) bool {
    var owner_buffer: [dns.max_name_text_len]u8 = undefined;
    var value_buffer: [dns.max_name_text_len]u8 = undefined;
    var iterator = dns.answers(data, family) catch return false;
    while (true) {
        _ = iterator.next(&owner_buffer, &value_buffer) catch |err| switch (err) {
            error.TooManyAnswers => break,
            else => return false,
        } orelse break;
    }

    var authority_iterator = dns.authority(data, family) catch return false;
    while (true) {
        _ = authority_iterator.next(&owner_buffer, &value_buffer) catch |err| switch (err) {
            error.TooManyAnswers => break,
            else => return false,
        } orelse break;
    }

    var additional_iterator = dns.additional(data, family) catch return false;
    while (true) {
        _ = additional_iterator.next(&owner_buffer, &value_buffer) catch |err| switch (err) {
            error.TooManyAnswers => break,
            else => return false,
        } orelse break;
    }
    return true;
}

fn httpDirection(payload: []const u8) HttpDirection {
    if (std.mem.startsWith(u8, payload, "HTTP/1.0 ") or std.mem.startsWith(u8, payload, "HTTP/1.1 ")) {
        return .response;
    }
    if (std.mem.startsWith(u8, payload, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) return .request;

    const inspected = payload[0..@min(payload.len, 4096)];
    const line_end = std.mem.indexOfScalar(u8, inspected, '\n') orelse inspected.len;
    const first_line = inspected[0..line_end];
    inline for (.{ "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE " }) |prefix| {
        if (std.mem.startsWith(u8, first_line, prefix) and
            (std.mem.indexOf(u8, first_line, " HTTP/1.0") != null or
                std.mem.indexOf(u8, first_line, " HTTP/1.1") != null)) return .request;
    }
    return .none;
}

fn messageCounter(stats: *Stats, family: dns.Family) *usize {
    return switch (family) {
        .dns => &stats.dns_messages,
        .mdns => &stats.mdns_messages,
        .llmnr => &stats.llmnr_messages,
    };
}

fn queryFieldCounter(stats: *Stats, family: dns.Family) *usize {
    return switch (family) {
        .dns => &stats.dns_fields,
        .mdns => &stats.mdns_fields,
        .llmnr => &stats.llmnr_fields,
    };
}

fn queryObservationCounter(stats: *Stats, family: dns.Family) *usize {
    return switch (family) {
        .dns => &stats.dns_observations,
        .mdns => &stats.mdns_observations,
        .llmnr => &stats.llmnr_observations,
    };
}

fn answerCounter(stats: *Stats, family: dns.Family) *usize {
    return switch (family) {
        .dns => &stats.dns_answers,
        .mdns => &stats.mdns_answers,
        .llmnr => &stats.llmnr_answers,
    };
}

fn additionalCounter(stats: *Stats, family: dns.Family) *usize {
    return switch (family) {
        .dns => &stats.dns_additionals,
        .mdns => &stats.mdns_additionals,
        .llmnr => &stats.llmnr_additionals,
    };
}

fn authorityCounter(stats: *Stats, family: dns.Family) *usize {
    return switch (family) {
        .dns => &stats.dns_authorities,
        .mdns => &stats.mdns_authorities,
        .llmnr => &stats.llmnr_authorities,
    };
}

fn recordFieldCounter(stats: *Stats, family: dns.Family, section: DnsRecordSection) *usize {
    return switch (section) {
        .answer => switch (family) {
            .dns => &stats.dns_answer_fields,
            .mdns => &stats.mdns_answer_fields,
            .llmnr => &stats.llmnr_answer_fields,
        },
        .authority => switch (family) {
            .dns => &stats.dns_authority_fields,
            .mdns => &stats.mdns_authority_fields,
            .llmnr => &stats.llmnr_authority_fields,
        },
        .additional => switch (family) {
            .dns => &stats.dns_additional_fields,
            .mdns => &stats.mdns_additional_fields,
            .llmnr => &stats.llmnr_additional_fields,
        },
    };
}

fn recordLimit(section: DnsRecordSection) usize {
    return switch (section) {
        .answer => max_answer_records,
        .authority => max_authority_records,
        .additional => max_additional_records,
    };
}

fn queryFieldPrefix(family: dns.Family) []const u8 {
    return switch (family) {
        .dns => "dns_query_",
        .mdns => "mdns_query_",
        .llmnr => "llmnr_query_",
    };
}

fn querySourceId(family: dns.Family) []const u8 {
    return switch (family) {
        .dns => "pcap:dns",
        .mdns => "pcap:mdns",
        .llmnr => "pcap:llmnr",
    };
}

fn recordFieldPrefix(family: dns.Family, section: DnsRecordSection) []const u8 {
    return switch (section) {
        .answer => switch (family) {
            .dns => "dns_answer_",
            .mdns => "mdns_answer_",
            .llmnr => "llmnr_answer_",
        },
        .authority => switch (family) {
            .dns => "dns_authority_",
            .mdns => "mdns_authority_",
            .llmnr => "llmnr_authority_",
        },
        .additional => switch (family) {
            .dns => "dns_additional_",
            .mdns => "mdns_additional_",
            .llmnr => "llmnr_additional_",
        },
    };
}

fn recordSourceId(family: dns.Family, section: DnsRecordSection) []const u8 {
    return switch (section) {
        .answer => switch (family) {
            .dns => "pcap:dns:answer",
            .mdns => "pcap:mdns:answer",
            .llmnr => "pcap:llmnr:answer",
        },
        .authority => switch (family) {
            .dns => "pcap:dns:authority",
            .mdns => "pcap:mdns:authority",
            .llmnr => "pcap:llmnr:authority",
        },
        .additional => switch (family) {
            .dns => "pcap:dns:additional",
            .mdns => "pcap:mdns:additional",
            .llmnr => "pcap:llmnr:additional",
        },
    };
}

fn ssdpKindName(kind: ssdp.Kind) []const u8 {
    return switch (kind) {
        .m_search => "m-search",
        .notify => "notify",
        .response => "response",
    };
}

fn limitedSsdpValue(value: ?[]const u8) []const u8 {
    const present = value orelse return "";
    return present[0..@min(present.len, 160)];
}

fn serviceTransport(name: []const u8) []const u8 {
    if (containsAsciiIgnoreCase(name, "._tcp.")) return "tcp";
    if (containsAsciiIgnoreCase(name, "._udp.")) return "udp";
    return "";
}

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |start| {
        if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) return true;
    }
    return false;
}

fn dhcpMessageTypeName(message_type: ?dhcp.MessageType) []const u8 {
    const value = message_type orelse return "unknown";
    return switch (value) {
        .discover => "discover",
        .offer => "offer",
        .request => "request",
        .decline => "decline",
        .ack => "ack",
        .nak => "nak",
        .release => "release",
        .inform => "inform",
        else => "unknown",
    };
}

fn dhcpv6MessageTypeName(message_type: dhcpv6.MessageType) []const u8 {
    return switch (message_type) {
        .solicit => "solicit",
        .advertise => "advertise",
        .request => "request",
        .confirm => "confirm",
        .renew => "renew",
        .rebind => "rebind",
        .reply => "reply",
        .release => "release",
        .decline => "decline",
        .reconfigure => "reconfigure",
        .information_request => "information-request",
        .relay_forward => "relay-forward",
        .relay_reply => "relay-reply",
        else => "unknown",
    };
}

fn limitedPrintable(buffer: *[64]u8, value: ?[]const u8) []const u8 {
    const bytes = value orelse return "";
    const limited = bytes[0..@min(bytes.len, buffer.len)];
    for (limited, 0..) |byte, index| {
        buffer[index] = if (byte >= 0x20 and byte <= 0x7e) byte else '.';
    }
    return buffer[0..limited.len];
}

fn formatClientIdentifier(buffer: *[64]u8, value: ?[]const u8) ![]const u8 {
    const bytes = value orelse return "none";
    if (bytes.len == 7 and bytes[0] == 1) return formatLinkLayer(buffer, bytes[1..]);
    return std.fmt.bufPrint(buffer, "{d}-byte identifier", .{bytes.len});
}

fn isZeroAddress(address: []const u8) bool {
    for (address) |byte| if (byte != 0) return false;
    return true;
}

fn isValidDhcpv6Address(address: []const u8) bool {
    return address.len == 16 and address[0] != 0xff and !isZeroAddress(address);
}

fn sequenceBefore(left: u32, right: u32) bool {
    return @as(i32, @bitCast(left -% right)) < 0;
}

fn isValidNbnsAddress(address: *const [4]u8) bool {
    return address[0] < 224 and !isZeroAddress(address);
}

fn isNeighborDiscoveryType(message_type: u8) bool {
    return message_type >= 133 and message_type <= 137;
}

fn validIcmpv6Checksum(source: []const u8, destination: []const u8, data: []const u8) bool {
    return icmpv6Checksum(source, destination, data) == 0;
}

fn icmpv6Checksum(source: []const u8, destination: []const u8, data: []const u8) u16 {
    var sum: u64 = @as(u64, @intCast(data.len >> 16)) + @as(u64, @intCast(data.len & 0xffff)) + 58;
    addChecksumBytes(&sum, source);
    addChecksumBytes(&sum, destination);
    addChecksumBytes(&sum, data);
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @truncate(sum));
}

fn addChecksumBytes(sum: *u64, data: []const u8) void {
    var offset: usize = 0;
    while (offset + 1 < data.len) : (offset += 2) {
        sum.* += @as(u16, data[offset]) << 8 | data[offset + 1];
    }
    if (offset < data.len) sum.* += @as(u16, data[offset]) << 8;
}

fn parseNdpOptions(data: []const u8) ?NdpOptions {
    var result: NdpOptions = .{};
    var offset: usize = 0;
    var count: usize = 0;
    while (offset < data.len) {
        if (count == max_ndp_options) return null;
        if (data.len - offset < 2) return null;
        const option_len: usize = @as(usize, data[offset + 1]) * 8;
        if (option_len == 0 or option_len > data.len - offset) return null;
        const value = data[offset + 2 .. offset + option_len];
        switch (data[offset]) {
            1 => if (result.source_link_layer == null) {
                result.source_link_layer = value;
            },
            2 => if (result.target_link_layer == null) {
                result.target_link_layer = value;
            },
            else => {},
        }
        offset += option_len;
        count += 1;
    }
    return result;
}

fn isIpv6Unspecified(address: []const u8) bool {
    if (address.len != 16) return false;
    for (address) |byte| if (byte != 0) return false;
    return true;
}

fn formatLinkLayer(buffer: *[64]u8, address: ?[]const u8) ![]const u8 {
    const bytes = address orelse return "none";
    if (bytes.len == 6) {
        return std.fmt.bufPrint(
            buffer,
            "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
            .{ bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5] },
        );
    }
    return std.fmt.bufPrint(buffer, "{d}-byte address", .{bytes.len});
}

fn formatAddress(buffer: *[64]u8, address: []const u8) ![]const u8 {
    if (address.len == 4) {
        return std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{ address[0], address[1], address[2], address[3] });
    }
    if (address.len == 16) {
        return std.fmt.bufPrint(
            buffer,
            "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
            .{
                readBe16(address, 0),
                readBe16(address, 2),
                readBe16(address, 4),
                readBe16(address, 6),
                readBe16(address, 8),
                readBe16(address, 10),
                readBe16(address, 12),
                readBe16(address, 14),
            },
        );
    }
    return error.InvalidAddressLength;
}

fn formatEndpoint(buffer: *[96]u8, address: []const u8, port: u16) ![]const u8 {
    if (address.len == 4) {
        return std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}:{d}", .{ address[0], address[1], address[2], address[3], port });
    }
    if (address.len == 16) {
        return std.fmt.bufPrint(
            buffer,
            "[{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}]:{d}",
            .{
                readBe16(address, 0),
                readBe16(address, 2),
                readBe16(address, 4),
                readBe16(address, 6),
                readBe16(address, 8),
                readBe16(address, 10),
                readBe16(address, 12),
                readBe16(address, 14),
                port,
            },
        );
    }
    return std.fmt.bufPrint(buffer, "port {d}", .{port});
}

fn checkedBlock(data: []const u8, cursor: usize, endian: std.builtin.Endian, minimum: usize) !usize {
    const block_len: usize = readU32(data, cursor + 4, endian);
    if (block_len < minimum or block_len & 3 != 0) return error.InvalidBlockLength;
    if (block_len > data.len - cursor) return error.TruncatedBlock;
    if (readU32(data, cursor + block_len - 4, endian) != block_len) return error.BlockLengthMismatch;
    return block_len;
}

fn validatePacketLengths(snaplen: u32, captured: u32, original: u32) !void {
    const limit = if (snaplen == 0) max_packet_bytes else snaplen;
    if (captured > limit or captured > max_packet_bytes or original > max_wire_bytes or captured > original) {
        return error.InvalidPacketLength;
    }
}

fn validateOptions(options: []const u8, endian: std.builtin.Endian) !void {
    var cursor: usize = 0;
    while (cursor < options.len) {
        if (options.len - cursor < 4) return error.InvalidOptions;
        const code = readU16(options, cursor, endian);
        const length: usize = readU16(options, cursor + 2, endian);
        cursor += 4;
        if (code == 0) {
            if (length != 0) return error.InvalidOptions;
            for (options[cursor..]) |byte| if (byte != 0) return error.InvalidOptions;
            return;
        }
        const padded = try padded4(length);
        if (padded > options.len - cursor) return error.InvalidOptions;
        cursor += padded;
    }
}

fn padded4(value: usize) !usize {
    if (value > std.math.maxInt(usize) - 3) return error.InvalidPacketLength;
    return (value + 3) & ~@as(usize, 3);
}

fn linktypeName(linktype: u32) []const u8 {
    return switch (linktype) {
        1 => "Ethernet",
        101 => "RAW IP",
        113 => "Linux cooked v1",
        276 => "Linux cooked v2",
        else => "unsupported",
    };
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

fn readU16(data: []const u8, offset: usize, endian: std.builtin.Endian) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], endian);
}

fn readU32(data: []const u8, offset: usize, endian: std.builtin.Endian) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], endian);
}

fn readU64(data: []const u8, offset: usize, endian: std.builtin.Endian) u64 {
    return std.mem.readInt(u64, data[offset..][0..8], endian);
}

fn readBe16(data: []const u8, offset: usize) u16 {
    return readU16(data, offset, .big);
}

fn writeU16(data: []u8, offset: usize, value: u16, endian: std.builtin.Endian) void {
    std.mem.writeInt(u16, data[offset..][0..2], value, endian);
}

fn writeU32(data: []u8, offset: usize, value: u32, endian: std.builtin.Endian) void {
    std.mem.writeInt(u32, data[offset..][0..4], value, endian);
}

fn writeU64(data: []u8, offset: usize, value: u64, endian: std.builtin.Endian) void {
    std.mem.writeInt(u64, data[offset..][0..8], value, endian);
}

fn makeDnsEthernetPacket(packet: *[76]u8) void {
    packet.* = [_]u8{0} ** packet.len;
    packet[12] = 0x08;
    packet[13] = 0x00;

    const ip = 14;
    packet[ip] = 0x45;
    writeU16(packet, ip + 2, 62, .big);
    packet[ip + 8] = 64;
    packet[ip + 9] = 17;
    packet[ip + 12] = 192;
    packet[ip + 13] = 0;
    packet[ip + 14] = 2;
    packet[ip + 15] = 1;
    packet[ip + 16] = 198;
    packet[ip + 17] = 51;
    packet[ip + 18] = 100;
    packet[ip + 19] = 53;

    const udp = ip + 20;
    writeU16(packet, udp, 53_000, .big);
    writeU16(packet, udp + 2, 53, .big);
    writeU16(packet, udp + 4, 42, .big);

    const dns_offset = udp + 8;
    writeU16(packet, dns_offset, 1, .big);
    writeU16(packet, dns_offset + 2, 0x0100, .big);
    writeU16(packet, dns_offset + 4, 1, .big);
    const qname = "\x03www\x07example\x04test\x00";
    std.mem.copyForwards(u8, packet[dns_offset + 12 ..], qname);
    writeU16(packet, dns_offset + 12 + qname.len, 1, .big);
    writeU16(packet, dns_offset + 14 + qname.len, 1, .big);
}

fn makeDnsUdp(
    buffer: *[64]u8,
    source_port: u16,
    destination_port: u16,
    id: u16,
    flags: u16,
    qname: []const u8,
    query_type: u16,
    query_class: u16,
) []const u8 {
    const dns_len = 12 + qname.len + 4;
    const udp_len = 8 + dns_len;
    std.debug.assert(udp_len <= buffer.len);
    buffer.* = [_]u8{0} ** buffer.len;
    writeU16(buffer, 0, source_port, .big);
    writeU16(buffer, 2, destination_port, .big);
    writeU16(buffer, 4, @intCast(udp_len), .big);
    writeU16(buffer, 8, id, .big);
    writeU16(buffer, 10, flags, .big);
    writeU16(buffer, 12, 1, .big);
    std.mem.copyForwards(u8, buffer[20 .. 20 + qname.len], qname);
    writeU16(buffer, 20 + qname.len, query_type, .big);
    writeU16(buffer, 22 + qname.len, query_class, .big);
    return buffer[0..udp_len];
}

const nbns_encoded_myhost = "ENFJEIEPFDFECACACACACACACACACACA";

fn makeNbnsQueryUdp(buffer: *[80]u8) []u8 {
    buffer.* = [_]u8{0} ** buffer.len;
    writeU16(buffer, 0, 50_000, .big);
    writeU16(buffer, 2, 137, .big);
    writeU16(buffer, 4, 58, .big);
    writeU16(buffer, 8, 0x1234, .big);
    writeU16(buffer, 10, 0x0110, .big);
    writeU16(buffer, 12, 1, .big);
    buffer[20] = 32;
    std.mem.copyForwards(u8, buffer[21..53], nbns_encoded_myhost);
    writeU16(buffer, 54, 0x20, .big);
    writeU16(buffer, 56, 1, .big);
    return buffer[0..58];
}

fn makeNbnsResponseUdp(buffer: *[80]u8, address: [4]u8) []u8 {
    buffer.* = [_]u8{0} ** buffer.len;
    writeU16(buffer, 0, 137, .big);
    writeU16(buffer, 2, 50_000, .big);
    writeU16(buffer, 4, 70, .big);
    writeU16(buffer, 8, 0x1234, .big);
    writeU16(buffer, 10, 0x8500, .big);
    writeU16(buffer, 14, 1, .big);
    buffer[20] = 32;
    std.mem.copyForwards(u8, buffer[21..53], nbns_encoded_myhost);
    writeU16(buffer, 54, 0x20, .big);
    writeU16(buffer, 56, 1, .big);
    writeU32(buffer, 58, 300, .big);
    writeU16(buffer, 62, 6, .big);
    std.mem.copyForwards(u8, buffer[66..70], &address);
    return buffer[0..70];
}

fn makeClassic(
    capture: *[116]u8,
    packet: *const [76]u8,
    endian: std.builtin.Endian,
    nanoseconds: bool,
) void {
    capture.* = [_]u8{0} ** capture.len;
    const magic: [4]u8 = if (endian == .little)
        if (nanoseconds) .{ 0x4d, 0x3c, 0xb2, 0xa1 } else .{ 0xd4, 0xc3, 0xb2, 0xa1 }
    else if (nanoseconds)
        .{ 0xa1, 0xb2, 0x3c, 0x4d }
    else
        .{ 0xa1, 0xb2, 0xc3, 0xd4 };
    std.mem.copyForwards(u8, capture[0..4], &magic);
    writeU16(capture, 4, 2, endian);
    writeU16(capture, 6, 4, endian);
    writeU32(capture, 16, 65_535, endian);
    writeU32(capture, 20, 1, endian);
    writeU32(capture, 24, 1_700_000_000, endian);
    writeU32(capture, 28, if (nanoseconds) 999_999_999 else 999_999, endian);
    writeU32(capture, 32, packet.len, endian);
    writeU32(capture, 36, packet.len, endian);
    std.mem.copyForwards(u8, capture[40..], packet);
}

fn makePcapngSection(section: *[248]u8, packet: *const [76]u8, endian: std.builtin.Endian) void {
    section.* = [_]u8{0} ** section.len;

    writeU32(section, 0, 0x0a0d0d0a, endian);
    writeU32(section, 4, 28, endian);
    writeU32(section, 8, 0x1a2b3c4d, endian);
    writeU16(section, 12, 1, endian);
    writeU64(section, 16, std.math.maxInt(u64), endian);
    writeU32(section, 24, 28, endian);

    const idb = 28;
    writeU32(section, idb, 1, endian);
    writeU32(section, idb + 4, 20, endian);
    writeU16(section, idb + 8, 1, endian);
    writeU32(section, idb + 12, 65_535, endian);
    writeU32(section, idb + 16, 20, endian);

    const epb = 48;
    writeU32(section, epb, 6, endian);
    writeU32(section, epb + 4, 108, endian);
    writeU32(section, epb + 16, 1, endian);
    writeU32(section, epb + 20, packet.len, endian);
    writeU32(section, epb + 24, packet.len, endian);
    std.mem.copyForwards(u8, section[epb + 28 ..], packet);
    writeU32(section, epb + 104, 108, endian);

    const spb = 156;
    writeU32(section, spb, 3, endian);
    writeU32(section, spb + 4, 92, endian);
    writeU32(section, spb + 8, packet.len, endian);
    std.mem.copyForwards(u8, section[spb + 12 ..], packet);
    writeU32(section, spb + 88, 92, endian);
}

fn makeEnhancedPacketBlock(block: *[108]u8, interface_id: u32, packet: *const [76]u8) void {
    block.* = [_]u8{0} ** block.len;
    writeU32(block, 0, 6, .little);
    writeU32(block, 4, block.len, .little);
    writeU32(block, 8, interface_id, .little);
    writeU32(block, 20, packet.len, .little);
    writeU32(block, 24, packet.len, .little);
    @memcpy(block[28 .. 28 + packet.len], packet);
    writeU32(block, block.len - 4, block.len, .little);
}

fn appendPcapngSection(buffer: []u8, cursor: *usize, linktype: u16) void {
    const start = cursor.*;
    std.debug.assert(buffer.len - start >= 48);
    @memset(buffer[start .. start + 48], 0);
    writeU32(buffer, start, 0x0a0d0d0a, .little);
    writeU32(buffer, start + 4, 28, .little);
    writeU32(buffer, start + 8, 0x1a2b3c4d, .little);
    writeU16(buffer, start + 12, 1, .little);
    writeU64(buffer, start + 16, std.math.maxInt(u64), .little);
    writeU32(buffer, start + 24, 28, .little);
    const idb = start + 28;
    writeU32(buffer, idb, 1, .little);
    writeU32(buffer, idb + 4, 20, .little);
    writeU16(buffer, idb + 8, linktype, .little);
    writeU32(buffer, idb + 12, 65_535, .little);
    writeU32(buffer, idb + 16, 20, .little);
    cursor.* += 48;
}

fn appendEnhancedPacket(buffer: []u8, cursor: *usize, packet: []const u8) void {
    const padded = (packet.len + 3) & ~@as(usize, 3);
    const block_len = 32 + padded;
    const start = cursor.*;
    std.debug.assert(buffer.len - start >= block_len);
    @memset(buffer[start .. start + block_len], 0);
    writeU32(buffer, start, 6, .little);
    writeU32(buffer, start + 4, @intCast(block_len), .little);
    writeU32(buffer, start + 20, @intCast(packet.len), .little);
    writeU32(buffer, start + 24, @intCast(packet.len), .little);
    @memcpy(buffer[start + 28 .. start + 28 + packet.len], packet);
    writeU32(buffer, start + block_len - 4, @intCast(block_len), .little);
    cursor.* += block_len;
}

fn makeIpv4UdpPacket(
    buffer: []u8,
    source: [4]u8,
    destination: [4]u8,
    source_port: u16,
    destination_port: u16,
    payload: []const u8,
) []u8 {
    const length = 20 + 8 + payload.len;
    std.debug.assert(length <= buffer.len and length <= std.math.maxInt(u16));
    @memset(buffer[0..length], 0);
    buffer[0] = 0x45;
    writeU16(buffer, 2, @intCast(length), .big);
    buffer[8] = 64;
    buffer[9] = 17;
    @memcpy(buffer[12..16], &source);
    @memcpy(buffer[16..20], &destination);
    writeU16(buffer, 20, source_port, .big);
    writeU16(buffer, 22, destination_port, .big);
    writeU16(buffer, 24, @intCast(8 + payload.len), .big);
    @memcpy(buffer[28..length], payload);
    return buffer[0..length];
}

fn makeIpv4TcpPacket(
    buffer: []u8,
    source: [4]u8,
    destination: [4]u8,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    flags: u8,
    payload: []const u8,
) []u8 {
    const length = 20 + 20 + payload.len;
    std.debug.assert(length <= buffer.len and length <= std.math.maxInt(u16));
    @memset(buffer[0..length], 0);
    buffer[0] = 0x45;
    writeU16(buffer, 2, @intCast(length), .big);
    buffer[8] = 64;
    buffer[9] = 6;
    @memcpy(buffer[12..16], &source);
    @memcpy(buffer[16..20], &destination);
    _ = makeTcpSegment(buffer[20..], source_port, destination_port, sequence, flags, payload);
    return buffer[0..length];
}

fn makeHttpRawPacket(packet: *[58]u8) void {
    packet.* = [_]u8{0} ** packet.len;
    packet[0] = 0x45;
    writeU16(packet, 2, packet.len, .big);
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 192;
    packet[13] = 0;
    packet[14] = 2;
    packet[15] = 10;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 10;
    writeU16(packet, 20, 50_000, .big);
    writeU16(packet, 22, 80, .big);
    packet[32] = 0x50;
    std.mem.copyForwards(u8, packet[40..], "GET / HTTP/1.1\r\n\r\n");
}

fn makeTcpSegment(
    buffer: []u8,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    flags: u8,
    payload: []const u8,
) []u8 {
    const length = 20 + payload.len;
    std.debug.assert(length <= buffer.len);
    @memset(buffer[0..length], 0);
    writeU16(buffer, 0, source_port, .big);
    writeU16(buffer, 2, destination_port, .big);
    writeU32(buffer, 4, sequence, .big);
    buffer[12] = 0x50;
    buffer[13] = flags;
    @memcpy(buffer[20..length], payload);
    return buffer[0..length];
}

fn makeTcpEthernetPacket(
    packet: *[76]u8,
    source: [4]u8,
    destination: [4]u8,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    flags: u8,
    payload: []const u8,
) void {
    std.debug.assert(payload.len <= packet.len - 14 - 20 - 20);
    packet.* = [_]u8{0} ** packet.len;
    packet[12..14].* = .{ 0x08, 0x00 };
    const ip = 14;
    packet[ip] = 0x45;
    writeU16(packet, ip + 2, @intCast(20 + 20 + payload.len), .big);
    packet[ip + 8] = 64;
    packet[ip + 9] = 6;
    @memcpy(packet[ip + 12 .. ip + 16], &source);
    @memcpy(packet[ip + 16 .. ip + 20], &destination);
    _ = makeTcpSegment(packet[ip + 20 ..], source_port, destination_port, sequence, flags, payload);
}

fn makeUdpPacket(buffer: []u8, source_port: u16, destination_port: u16, payload: []const u8) []u8 {
    const length = 8 + payload.len;
    std.debug.assert(length <= buffer.len);
    @memset(buffer[0..length], 0);
    writeU16(buffer, 0, source_port, .big);
    writeU16(buffer, 2, destination_port, .big);
    writeU16(buffer, 4, @intCast(length), .big);
    @memcpy(buffer[8..length], payload);
    return buffer[0..length];
}

fn appendDhcpv6Option(buffer: []u8, cursor: *usize, code: u16, value: []const u8) void {
    writeU16(buffer, cursor.*, code, .big);
    writeU16(buffer, cursor.* + 2, @intCast(value.len), .big);
    @memcpy(buffer[cursor.* + 4 .. cursor.* + 4 + value.len], value);
    cursor.* += 4 + value.len;
}

fn makeMdnsAnswer(
    buffer: []u8,
    owner: []const u8,
    record_type: u16,
    ttl: u32,
    rdata: []const u8,
) []u8 {
    const length = 12 + owner.len + 10 + rdata.len;
    std.debug.assert(length <= buffer.len);
    @memset(buffer[0..length], 0);
    writeU16(buffer, 2, 0x8400, .big);
    writeU16(buffer, 6, 1, .big);
    var cursor: usize = 12;
    @memcpy(buffer[cursor .. cursor + owner.len], owner);
    cursor += owner.len;
    writeU16(buffer, cursor, record_type, .big);
    writeU16(buffer, cursor + 2, 0x8001, .big);
    writeU32(buffer, cursor + 4, ttl, .big);
    writeU16(buffer, cursor + 8, @intCast(rdata.len), .big);
    @memcpy(buffer[cursor + 10 .. length], rdata);
    return buffer[0..length];
}

test "classic PCAP accepts all byte-order and timestamp magics" {
    var packet: [76]u8 = undefined;
    makeDnsEthernetPacket(&packet);

    for ([_]struct { endian: std.builtin.Endian, nanoseconds: bool }{
        .{ .endian = .little, .nanoseconds = false },
        .{ .endian = .big, .nanoseconds = false },
        .{ .endian = .little, .nanoseconds = true },
        .{ .endian = .big, .nanoseconds = true },
    }) |case| {
        var capture: [116]u8 = undefined;
        makeClassic(&capture, &packet, case.endian, case.nanoseconds);
        var result = try analyzeCapture(std.testing.allocator, &capture);
        defer result.deinit();

        try std.testing.expectEqualStrings("1", fieldValue(&result, "packets").?);
        try std.testing.expectEqualStrings("1", fieldValue(&result, "udp_packets").?);
        try std.testing.expectEqualStrings("1", fieldValue(&result, "dns_messages").?);
        try std.testing.expectEqualStrings("www.example.test (type 1)", fieldValue(&result, "dns_query_1").?);
        try std.testing.expectEqual(@as(usize, 1), result.observations.items.len);
        try std.testing.expectEqual(protocol.NetworkObservationKind.name_query, result.observations.items[0].kind);
        try std.testing.expectEqualStrings("192.0.2.1", result.observations.items[0].address);
    }
}

test "UDP parser recognizes mDNS and LLMNR with name-query observations" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var buffer: [64]u8 = undefined;
    const mdns_packet = makeDnsUdp(
        &buffer,
        5353,
        5353,
        0,
        0,
        "\x07printer\x05local\x00",
        12,
        0x8001,
    );
    try std.testing.expect(try parser.parseUdp(
        &.{ 192, 0, 2, 44 },
        &.{ 224, 0, 0, 251 },
        mdns_packet,
    ));

    const llmnr_packet = makeDnsUdp(
        &buffer,
        5355,
        53_000,
        0x1234,
        0x8000,
        "\x07printer\x00",
        1,
        1,
    );
    try std.testing.expect(try parser.parseUdp(
        &.{ 192, 0, 2, 10 },
        &.{ 192, 0, 2, 45 },
        llmnr_packet,
    ));

    try std.testing.expectEqual(@as(usize, 2), parser.stats.udp_packets);
    try std.testing.expectEqual(@as(usize, 0), parser.stats.dns_messages);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.mdns_messages);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.llmnr_messages);
    try std.testing.expectEqualStrings("printer.local (type 12)", fieldValue(&result, "mdns_query_1").?);
    try std.testing.expectEqualStrings("printer (type 1)", fieldValue(&result, "llmnr_query_1").?);
    try std.testing.expectEqual(@as(usize, 2), result.observations.items.len);
    try std.testing.expectEqualStrings("192.0.2.44", result.observations.items[0].address);
    try std.testing.expectEqualStrings("printer.local", result.observations.items[0].hostname);
    try std.testing.expectEqualStrings("pcap:mdns", result.observations.items[0].source_id);
    try std.testing.expectEqualStrings("192.0.2.45", result.observations.items[1].address);
    try std.testing.expectEqualStrings("printer", result.observations.items[1].hostname);
    try std.testing.expectEqualStrings("pcap:llmnr", result.observations.items[1].source_id);
}

test "UDP port 137 records NBNS questions and valid address answers" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var query_buffer: [80]u8 = undefined;
    try std.testing.expect(try parser.parseUdp(
        &.{ 192, 0, 2, 10 },
        &.{ 192, 0, 2, 255 },
        makeNbnsQueryUdp(&query_buffer),
    ));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.nbns_messages);
    try std.testing.expectEqualStrings(
        "question MYHOST<20>; type=32; class=1",
        fieldValue(&result, "nbns_record_1").?,
    );
    try std.testing.expectEqual(protocol.NetworkObservationKind.name_query, result.observations.items[0].kind);
    try std.testing.expectEqualStrings("192.0.2.10", result.observations.items[0].address);
    try std.testing.expectEqualStrings("MYHOST<20>", result.observations.items[0].hostname);

    var response_buffer: [80]u8 = undefined;
    try std.testing.expect(try parser.parseUdp(
        &.{ 192, 0, 2, 53 },
        &.{ 192, 0, 2, 10 },
        makeNbnsResponseUdp(&response_buffer, .{ 192, 0, 2, 20 }),
    ));
    try std.testing.expectEqual(@as(usize, 2), parser.stats.nbns_messages);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.nbns_answers);
    try std.testing.expectEqual(@as(usize, 2), parser.stats.nbns_observations);
    try std.testing.expectEqual(protocol.NetworkObservationKind.host, result.observations.items[1].kind);
    try std.testing.expectEqualStrings("192.0.2.20", result.observations.items[1].address);
    try std.testing.expectEqualStrings("MYHOST<20>", result.observations.items[1].hostname);
    try std.testing.expectEqualStrings("pcap:nbns", result.observations.items[1].source_id);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "nbns_record_2").?, "flags=0x0000") != null);

    var invalid_flags_buffer: [80]u8 = undefined;
    const invalid_flags = makeNbnsResponseUdp(&invalid_flags_buffer, .{ 192, 0, 2, 21 });
    writeU16(invalid_flags, 64, 1, .big);
    try std.testing.expect(try parser.parseUdp(
        &.{ 192, 0, 2, 53 },
        &.{ 192, 0, 2, 10 },
        invalid_flags,
    ));
    try std.testing.expectEqual(@as(usize, 2), parser.stats.nbns_observations);

    var malformed_buffer: [80]u8 = undefined;
    const malformed = makeNbnsResponseUdp(&malformed_buffer, .{ 192, 0, 2, 21 });
    writeU16(malformed, 62, 5, .big);
    try std.testing.expect(!try parser.parseUdp(
        &.{ 192, 0, 2, 53 },
        &.{ 192, 0, 2, 10 },
        malformed,
    ));
    try std.testing.expectEqual(@as(usize, 2), parser.stats.nbns_observations);
}

test "NBNS retained fields and observations stay bounded" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var response_buffer: [80]u8 = undefined;
    for (0..20) |index| {
        try std.testing.expect(try parser.parseUdp(
            &.{ 192, 0, 2, 53 },
            &.{ 192, 0, 2, 10 },
            makeNbnsResponseUdp(&response_buffer, .{ 192, 0, 2, @intCast(index + 1) }),
        ));
    }

    try std.testing.expectEqual(@as(usize, 20), parser.stats.nbns_messages);
    try std.testing.expectEqual(@as(usize, 20), parser.stats.nbns_answers);
    try std.testing.expectEqual(@as(usize, max_nbns_records), parser.stats.nbns_fields);
    try std.testing.expectEqual(@as(usize, max_nbns_records), parser.stats.nbns_observations);
    try std.testing.expect(fieldValue(&result, "nbns_record_16") != null);
    try std.testing.expect(fieldValue(&result, "nbns_record_17") == null);
}

test "mDNS answer and additional records produce same-message service associations" {
    const message =
        "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x04" ++
        "\x05_http\x04_tcp\x05local\x00\x00\x0c\x80\x01\x00\x00\x00\x78\x00\x0a\x07Printer\xc0\x0c" ++
        "\xc0\x28\x00\x21\x80\x01\x00\x00\x00\x78\x00\x0f" ++
        "\x00\x00\x00\x00\x1f\x90\x06device\xc0\x17" ++
        "\xc0\x28\x00\x10\x80\x01\x00\x00\x00\x78\x00\x08\x03foo\x03bar" ++
        "\xc0\x44\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x37" ++
        "\xc0\x44\x00\x1c\x80\x01\x00\x00\x00\x78\x00\x10" ++
        "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x55";
    var udp: [8 + message.len]u8 = [_]u8{0} ** (8 + message.len);
    writeU16(&udp, 0, 5353, .big);
    writeU16(&udp, 2, 5353, .big);
    writeU16(&udp, 4, udp.len, .big);
    std.mem.copyForwards(u8, udp[8..], message);

    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    try std.testing.expect(try parser.parseUdp(
        &.{ 192, 0, 2, 55 },
        &.{ 224, 0, 0, 251 },
        &udp,
    ));

    try std.testing.expectEqual(@as(usize, 1), parser.stats.mdns_messages);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.mdns_answers);
    try std.testing.expectEqual(@as(usize, 4), parser.stats.mdns_additionals);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.mdns_answer_fields);
    try std.testing.expectEqual(@as(usize, 4), parser.stats.mdns_additional_fields);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "mdns_answer_1").?, " PTR ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "mdns_additional_1").?, " SRV ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "mdns_additional_2").?, " TXT ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "mdns_additional_3").?, " A ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "mdns_additional_4").?, " AAAA ") != null);
    try std.testing.expectEqual(@as(usize, 6), result.observations.items.len);

    var saw_ipv4 = false;
    var saw_ipv6 = false;
    var saw_service = false;
    var associated_addresses: usize = 0;
    for (result.observations.items) |observation| {
        if (std.mem.eql(u8, observation.address, "192.0.2.55") and
            std.mem.eql(u8, observation.hostname, "device.local")) saw_ipv4 = true;
        if (std.mem.eql(u8, observation.address, "2001:db8:0:0:0:0:0:55") and
            std.mem.eql(u8, observation.hostname, "device.local")) saw_ipv6 = true;
        if (observation.kind == .service and observation.port == 8080 and
            std.mem.eql(u8, observation.transport, "tcp")) saw_service = true;
        if (std.mem.eql(u8, observation.source_id, "pcap:mdns:service-discovery") and
            std.mem.eql(u8, observation.service, "_http._tcp.local") and
            std.mem.eql(u8, observation.hostname, "device.local")) associated_addresses += 1;
    }
    try std.testing.expect(saw_ipv4);
    try std.testing.expect(saw_ipv6);
    try std.testing.expect(saw_service);
    try std.testing.expectEqual(@as(usize, 2), associated_addresses);
}

test "mDNS service discovery correlates bounded records across packets and honors goodbye" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    const source = [_]u8{ 192, 0, 2, 55 };
    const destination = [_]u8{ 224, 0, 0, 251 };
    const service = "\x05_http\x04_tcp\x05local\x00";
    const instance = "\x07Printer\x05_http\x04_tcp\x05local\x00";
    const hostname = "\x06device\x05local\x00";
    var packet: [256]u8 = undefined;

    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, service, 12, 120, instance),
        .mdns,
    ));
    try std.testing.expectEqual(@as(usize, 1), parser.mdns_links.ptr_count);

    var srv: [6 + hostname.len]u8 = [_]u8{0} ** (6 + hostname.len);
    writeU16(&srv, 4, 8080, .big);
    @memcpy(srv[6..], hostname);
    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, instance, 33, 120, &srv),
        .mdns,
    ));
    try std.testing.expectEqual(@as(usize, 1), parser.mdns_links.srv_count);

    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, hostname, 1, 120, &.{ 192, 0, 2, 99 }),
        .mdns,
    ));
    try std.testing.expectEqual(@as(usize, 1), parser.mdns_links.address_count);
    var associated: usize = 0;
    for (result.observations.items) |observation| {
        if (std.mem.eql(u8, observation.source_id, "pcap:mdns:service-discovery")) {
            associated += 1;
            try std.testing.expectEqualStrings("192.0.2.99", observation.address);
            try std.testing.expectEqualStrings("device.local", observation.hostname);
            try std.testing.expectEqualStrings("tcp", observation.transport);
            try std.testing.expectEqual(@as(?u16, 8080), observation.port);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), associated);

    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, hostname, 1, 0, &.{ 192, 0, 2, 99 }),
        .mdns,
    ));
    try std.testing.expectEqual(@as(usize, 0), parser.mdns_links.address_count);
    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, service, 12, 0, instance),
        .mdns,
    ));
    try std.testing.expectEqual(@as(usize, 0), parser.mdns_links.ptr_count);
}

test "mDNS service discovery does not cross capture scopes" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    const source = [_]u8{ 192, 0, 2, 55 };
    const destination = [_]u8{ 224, 0, 0, 251 };
    const service = "\x05_http\x04_tcp\x05local\x00";
    const instance = "\x07Printer\x05_http\x04_tcp\x05local\x00";
    const hostname = "\x06device\x05local\x00";
    var packet: [256]u8 = undefined;

    parser.current_scope = 1;
    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, service, 12, 120, instance),
        .mdns,
    ));

    var srv: [6 + hostname.len]u8 = [_]u8{0} ** (6 + hostname.len);
    writeU16(&srv, 4, 8080, .big);
    @memcpy(srv[6..], hostname);
    parser.current_scope = 2;
    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, instance, 33, 120, &srv),
        .mdns,
    ));
    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, hostname, 1, 120, &.{ 192, 0, 2, 99 }),
        .mdns,
    ));
    for (result.observations.items) |observation| {
        try std.testing.expect(!std.mem.eql(u8, observation.source_id, "pcap:mdns:service-discovery"));
    }

    parser.current_scope = 1;
    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, instance, 33, 120, &srv),
        .mdns,
    ));
    try std.testing.expect(try parser.parseDnsFamily(
        &source,
        &destination,
        makeMdnsAnswer(&packet, hostname, 1, 120, &.{ 192, 0, 2, 99 }),
        .mdns,
    ));
    var associated: usize = 0;
    for (result.observations.items) |observation| {
        if (std.mem.eql(u8, observation.source_id, "pcap:mdns:service-discovery")) associated += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), associated);
}

test "mDNS cache flush preserves the current packet RRSet" {
    var links: MdnsLinks = .{};
    const hostname = "device.local";
    try links.remember(7, 1, .{
        .name = hostname,
        .record_type = 1,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .a = .{ 192, 0, 2, 1 } },
    });
    try links.remember(7, 1, .{
        .name = hostname,
        .record_type = 1,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .a = .{ 192, 0, 2, 2 } },
    });
    try links.remember(7, 1, .{
        .name = hostname,
        .record_type = 28,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .aaaa = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
    });
    try links.remember(7, 1, .{
        .name = "Printer._http._tcp.local",
        .record_type = 33,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .srv = .{ .priority = 0, .weight = 0, .port = 80, .target = "old.local" } },
    });

    for ([_][4]u8{ .{ 192, 0, 2, 10 }, .{ 192, 0, 2, 11 } }) |address| {
        try links.remember(7, 2, .{
            .name = hostname,
            .record_type = 1,
            .raw_class = 0x8001,
            .class = 1,
            .cache_flush = true,
            .ttl = 120,
            .value = .{ .a = address },
        });
    }
    for ([_]struct { port: u16, target: []const u8 }{
        .{ .port = 8080, .target = "one.local" },
        .{ .port = 8081, .target = "two.local" },
    }) |srv| {
        try links.remember(7, 2, .{
            .name = "Printer._http._tcp.local",
            .record_type = 33,
            .raw_class = 0x8001,
            .class = 1,
            .cache_flush = true,
            .ttl = 120,
            .value = .{ .srv = .{ .priority = 0, .weight = 0, .port = srv.port, .target = srv.target } },
        });
    }

    try std.testing.expectEqual(@as(usize, 3), links.address_count);
    var a_records: usize = 0;
    var aaaa_records: usize = 0;
    for (links.addresses[0..links.address_count]) |link| {
        if (link.record_type == 1) {
            a_records += 1;
            try std.testing.expectEqual(@as(usize, 2), link.generation);
        } else if (link.record_type == 28) {
            aaaa_records += 1;
            try std.testing.expectEqual(@as(usize, 1), link.generation);
        }
    }
    try std.testing.expectEqual(@as(usize, 2), a_records);
    try std.testing.expectEqual(@as(usize, 1), aaaa_records);
    try std.testing.expectEqual(@as(usize, 2), links.srv_count);
    for (links.srvs[0..links.srv_count]) |link| try std.testing.expectEqual(@as(usize, 2), link.generation);
}

test "mDNS service associations have a capture-wide hard limit" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    var links: MdnsLinks = .{};
    try links.remember(0, 1, .{
        .name = "_http._tcp.local",
        .record_type = 12,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .ptr = "Printer._http._tcp.local" },
    });
    try links.remember(0, 1, .{
        .name = "Printer._http._tcp.local",
        .record_type = 33,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .srv = .{ .priority = 0, .weight = 0, .port = 8080, .target = "device.local" } },
    });
    for (0..max_mdns_links) |index| {
        try links.remember(0, 1, .{
            .name = "device.local",
            .record_type = 1,
            .raw_class = 1,
            .class = 1,
            .cache_flush = false,
            .ttl = 120,
            .value = .{ .a = .{ 192, 0, 2, @intCast(index + 1) } },
        });
    }
    try parser.addMdnsAssociations(0, &links);
    try std.testing.expectEqual(@as(usize, max_mdns_links), parser.stats.mdns_associations);
    try std.testing.expectEqual(@as(usize, max_mdns_links), result.observations.items.len);

    links.address_count = 0;
    for (0..max_mdns_links) |index| {
        try links.remember(0, 2, .{
            .name = "device.local",
            .record_type = 1,
            .raw_class = 1,
            .class = 1,
            .cache_flush = false,
            .ttl = 120,
            .value = .{ .a = .{ 198, 51, 100, @intCast(index + 1) } },
        });
    }
    try parser.addMdnsAssociations(0, &links);
    try std.testing.expectEqual(@as(usize, max_mdns_links), parser.stats.mdns_associations);
    try std.testing.expectEqual(@as(usize, max_mdns_links), result.observations.items.len);
}

test "malformed trailing mDNS records do not leave partial evidence" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    var packet: [256]u8 = [_]u8{0} ** 256;
    const message = makeMdnsAnswer(
        &packet,
        "\x05_http\x04_tcp\x05local\x00",
        12,
        120,
        "\x07Printer\x05_http\x04_tcp\x05local\x00",
    );
    writeU16(message, 6, 2, .big);
    try std.testing.expect(!try parser.parseDnsFamily(
        &.{ 192, 0, 2, 55 },
        &.{ 224, 0, 0, 251 },
        packet[0 .. message.len + 1],
        .mdns,
    ));
    try std.testing.expectEqual(@as(usize, 0), parser.mdns_links.ptr_count);
    try std.testing.expectEqual(@as(usize, 0), result.fields.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.observations.items.len);
}

test "mDNS associations ignore goodbye and non-DNS-SD PTR records" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    const goodbye = dns.Answer{
        .name = "_http._tcp.local",
        .record_type = 12,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 0,
        .value = .{ .ptr = "Printer._http._tcp.local" },
    };
    var links: MdnsLinks = .{};
    try links.remember(0, 1, goodbye);
    try std.testing.expectEqual(@as(usize, 0), links.ptr_count);
    try parser.addDnsRecord(.mdns, "192.0.2.1", goodbye, .answer);
    try std.testing.expectEqual(@as(usize, 0), result.observations.items.len);

    try links.remember(0, 1, .{
        .name = "reverse.local",
        .record_type = 12,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .ptr = "instance.local" },
    });
    try links.remember(0, 1, .{
        .name = "instance.local",
        .record_type = 33,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .srv = .{ .priority = 0, .weight = 0, .port = 80, .target = "host.local" } },
    });
    try links.remember(0, 1, .{
        .name = "host.local",
        .record_type = 1,
        .raw_class = 1,
        .class = 1,
        .cache_flush = false,
        .ttl = 120,
        .value = .{ .a = .{ 192, 0, 2, 2 } },
    });
    try parser.addMdnsAssociations(0, &links);
    try std.testing.expectEqual(@as(usize, 0), result.observations.items.len);
}

test "ARP senders and TCP responses produce bounded passive observations" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var arp: [28]u8 = [_]u8{0} ** 28;
    writeU16(&arp, 0, 1, .big);
    writeU16(&arp, 2, 0x0800, .big);
    arp[4] = 6;
    arp[5] = 4;
    writeU16(&arp, 6, 1, .big);
    std.mem.copyForwards(u8, arp[8..14], &.{ 0x02, 0, 0, 0, 0, 1 });
    arp[14] = 192;
    arp[15] = 0;
    arp[16] = 2;
    arp[17] = 200;
    std.mem.copyForwards(u8, arp[24..28], &.{ 192, 0, 2, 250 });
    try std.testing.expect(try parser.parseArp(&arp));
    try std.testing.expectEqual(protocol.ObservationConfidence.observed, result.observations.items[0].confidence);
    try std.testing.expectEqualStrings("192.0.2.200", result.observations.items[0].address);

    writeU16(&arp, 6, 2, .big);
    for (0..40) |index| {
        arp[17] = @intCast(index + 1);
        try std.testing.expect(try parser.parseArp(&arp));
    }
    try std.testing.expectEqual(@as(usize, max_passive_observations), parser.stats.arp_observations);
    var saw_arp_reply = false;
    for (result.observations.items) |observation| {
        if (std.mem.eql(u8, observation.source_id, "pcap:arp") and
            observation.confidence == .confirmed) saw_arp_reply = true;
        try std.testing.expect(!std.mem.eql(u8, observation.address, "192.0.2.250"));
    }
    try std.testing.expect(saw_arp_reply);

    var tcp: [20]u8 = [_]u8{0} ** 20;
    writeU16(&tcp, 0, 443, .big);
    writeU16(&tcp, 2, 50_000, .big);
    tcp[12] = 0x50;
    tcp[13] = 0x14;
    try std.testing.expect(try parser.parseTcp(&.{ 198, 51, 100, 1 }, &.{ 192, 0, 2, 1 }, &tcp));
    tcp[13] = 0x12;
    for (1..40) |index| {
        var source = [_]u8{ 198, 51, 100, @intCast(index + 1) };
        try std.testing.expect(try parser.parseTcp(&source, &.{ 192, 0, 2, 1 }, &tcp));
    }
    try std.testing.expectEqual(@as(usize, max_passive_observations), parser.stats.tcp_observations);

    var saw_rst_host = false;
    var saw_syn_ack_endpoint = false;
    for (result.observations.items) |observation| {
        if (std.mem.eql(u8, observation.source_id, "pcap:tcp") and observation.kind == .host) saw_rst_host = true;
        if (std.mem.eql(u8, observation.source_id, "pcap:tcp") and observation.kind == .endpoint and
            observation.port == 443) saw_syn_ack_endpoint = true;
    }
    try std.testing.expect(saw_rst_host);
    try std.testing.expect(saw_syn_ack_endpoint);
}

test "IPv6 NDP observes solicitation senders and advertisement targets" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    const source = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const destination = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 2 };
    const target = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    var solicitation: [32]u8 = [_]u8{0} ** 32;
    solicitation[0] = 135;
    std.mem.copyForwards(u8, solicitation[8..24], &target);
    solicitation[24] = 1;
    solicitation[25] = 1;
    std.mem.copyForwards(u8, solicitation[26..32], &.{ 0x02, 0, 0, 0, 0, 1 });
    writeU16(&solicitation, 2, icmpv6Checksum(&source, &destination, &solicitation), .big);
    try std.testing.expect(!try parser.parseTransport(58, &source, &destination, &solicitation, 254));
    try std.testing.expect(try parser.parseTransport(58, &source, &destination, &solicitation, 255));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.ndp_observations);
    try std.testing.expectEqual(protocol.ObservationConfidence.observed, result.observations.items[0].confidence);
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:1", result.observations.items[0].address);
    try std.testing.expect(std.mem.indexOf(u8, result.observations.items[0].evidence, "source_lladdr=02:00:00:00:00:01") != null);

    var bad_checksum = solicitation;
    bad_checksum[3] ^= 1;
    try std.testing.expect(!try parser.parseTransport(58, &source, &destination, &bad_checksum, 255));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.ndp_observations);

    var fragmented: [40 + 8 + solicitation.len]u8 = [_]u8{0} ** (40 + 8 + solicitation.len);
    fragmented[0] = 0x60;
    writeU16(&fragmented, 4, 8 + solicitation.len, .big);
    fragmented[6] = 44;
    fragmented[7] = 255;
    std.mem.copyForwards(u8, fragmented[8..24], &source);
    std.mem.copyForwards(u8, fragmented[24..40], &destination);
    fragmented[40] = 58;
    std.mem.copyForwards(u8, fragmented[48..], &solicitation);
    try std.testing.expect(!try parser.parseIpv6(&fragmented));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.ndp_observations);

    const unspecified = [_]u8{0} ** 16;
    var dad: [24]u8 = [_]u8{0} ** 24;
    dad[0] = 135;
    std.mem.copyForwards(u8, dad[8..24], &target);
    writeU16(&dad, 2, icmpv6Checksum(&unspecified, &destination, &dad), .big);
    try std.testing.expect(try parser.parseTransport(58, &unspecified, &destination, &dad, 255));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.ndp_observations);

    var malformed = solicitation;
    malformed[25] = 0;
    writeU16(&malformed, 2, 0, .big);
    writeU16(&malformed, 2, icmpv6Checksum(&source, &destination, &malformed), .big);
    try std.testing.expect(!try parser.parseTransport(58, &source, &destination, &malformed, 255));

    var too_many: [24 + (max_ndp_options + 1) * 8]u8 = [_]u8{0} ** (24 + (max_ndp_options + 1) * 8);
    too_many[0] = 135;
    std.mem.copyForwards(u8, too_many[8..24], &target);
    for (0..max_ndp_options + 1) |index| {
        too_many[24 + index * 8] = 1;
        too_many[25 + index * 8] = 1;
    }
    writeU16(&too_many, 2, icmpv6Checksum(&source, &destination, &too_many), .big);
    try std.testing.expect(!try parser.parseTransport(58, &source, &destination, &too_many, 255));

    var advertisement: [32]u8 = [_]u8{0} ** 32;
    advertisement[0] = 136;
    advertisement[4] = 0xe0;
    std.mem.copyForwards(u8, advertisement[8..24], &target);
    advertisement[24] = 2;
    advertisement[25] = 1;
    std.mem.copyForwards(u8, advertisement[26..32], &.{ 0x02, 0, 0, 0, 0, 2 });
    writeU16(&advertisement, 2, icmpv6Checksum(&unspecified, &source, &advertisement), .big);
    try std.testing.expect(!try parser.parseTransport(58, &unspecified, &source, &advertisement, 255));
    writeU16(&advertisement, 2, 0, .big);
    writeU16(&advertisement, 2, icmpv6Checksum(&target, &destination, &advertisement), .big);
    try std.testing.expect(!try parser.parseTransport(58, &target, &destination, &advertisement, 255));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.ndp_observations);
    writeU16(&advertisement, 2, 0, .big);
    writeU16(&advertisement, 2, icmpv6Checksum(&target, &source, &advertisement), .big);
    try std.testing.expect(try parser.parseTransport(58, &target, &source, &advertisement, 255));
    try std.testing.expectEqual(protocol.ObservationConfidence.confirmed, result.observations.items[1].confidence);
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:2", result.observations.items[1].address);
    try std.testing.expect(std.mem.indexOf(u8, result.observations.items[1].evidence, "target_lladdr=02:00:00:00:00:02") != null);

    for (1..40) |suffix| {
        advertisement[23] = @intCast(suffix + 2);
        writeU16(&advertisement, 2, 0, .big);
        writeU16(&advertisement, 2, icmpv6Checksum(&target, &source, &advertisement), .big);
        try std.testing.expect(try parser.parseTransport(58, &target, &source, &advertisement, 255));
    }
    try std.testing.expectEqual(@as(usize, max_passive_observations), parser.stats.ndp_observations);
}

test "DHCP assignments produce bounded host observations without inventing requests" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    const options =
        "\x35\x01\x02" ++
        "\x0c\x06device" ++
        "\x32\x04\xc0\x00\x02\x63" ++
        "\x33\x04\x00\x00\x0e\x10" ++
        "\x36\x04\xc0\x00\x02\x01" ++
        "\x3c\x06vendor" ++
        "\x3d\x07\x01\x02\x00\x00\x00\x00\x01" ++
        "\xff";
    var udp: [8 + 240 + options.len]u8 = [_]u8{0} ** (8 + 240 + options.len);
    writeU16(&udp, 0, 67, .big);
    writeU16(&udp, 2, 68, .big);
    writeU16(&udp, 4, udp.len, .big);
    const payload = udp[8..];
    payload[0] = 2;
    payload[1] = 1;
    payload[2] = 6;
    payload[16..20].* = .{ 192, 0, 2, 20 };
    payload[28..34].* = .{ 0x02, 0, 0, 0, 0, 1 };
    payload[236..240].* = .{ 0x63, 0x82, 0x53, 0x63 };
    @memcpy(payload[240..], options);

    try std.testing.expect(try parser.parseUdp(&.{ 192, 0, 2, 1 }, &.{ 255, 255, 255, 255 }, &udp));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcp_observations);
    try std.testing.expectEqualStrings("192.0.2.20", result.observations.items[0].address);
    try std.testing.expectEqualStrings("device", result.observations.items[0].hostname);
    try std.testing.expect(std.mem.indexOf(u8, result.observations.items[0].evidence, "type=offer") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.observations.items[0].evidence, "server_id=192.0.2.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.observations.items[0].evidence, "lease=3600s") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.observations.items[0].evidence, "chaddr=02:00:00:00:00:01") != null);

    writeU16(&udp, 2, 9999, .big);
    try std.testing.expect(try parser.parseUdp(&.{ 192, 0, 2, 1 }, &.{ 255, 255, 255, 255 }, &udp));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcp_fields);
    const ipv6 = [_]u8{0} ** 16;
    writeU16(&udp, 2, 68, .big);
    try std.testing.expect(try parser.parseUdp(&ipv6, &ipv6, &udp));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcp_fields);

    writeU16(&udp, 0, 68, .big);
    writeU16(&udp, 2, 67, .big);
    try std.testing.expect(try parser.parseUdp(&.{ 192, 0, 2, 20 }, &.{ 192, 0, 2, 1 }, &udp));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcp_observations);

    payload[0] = 1;
    payload[16..20].* = .{ 0, 0, 0, 0 };
    payload[242] = @intFromEnum(dhcp.MessageType.request);
    try std.testing.expect(try parser.parseUdp(&.{ 0, 0, 0, 0 }, &.{ 255, 255, 255, 255 }, &udp));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcp_observations);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "dhcp_3").?, "requested_ip=192.0.2.99") != null);

    payload[0] = 2;
    payload[242] = @intFromEnum(dhcp.MessageType.ack);
    writeU16(&udp, 0, 67, .big);
    writeU16(&udp, 2, 68, .big);
    for (0..20) |index| {
        payload[19] = @intCast(30 + index);
        try std.testing.expect(try parser.parseUdp(&.{ 192, 0, 2, 1 }, &.{ 255, 255, 255, 255 }, &udp));
    }
    try std.testing.expectEqual(@as(usize, max_dhcp_records), parser.stats.dhcp_fields);
    try std.testing.expectEqual(@as(usize, max_dhcp_records), parser.stats.dhcp_observations);
    for (result.observations.items) |observation| {
        try std.testing.expect(!std.mem.eql(u8, observation.address, "192.0.2.99"));
    }
}

test "DHCPv6 Advertise and Reply assignments produce bounded host evidence" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var ia_address: [24]u8 = [_]u8{0} ** 24;
    ia_address[0..16].* = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20 };
    writeU32(&ia_address, 16, 3600, .big);
    writeU32(&ia_address, 20, 7200, .big);
    var ia_na: [40]u8 = [_]u8{0} ** 40;
    writeU32(&ia_na, 0, 7, .big);
    writeU32(&ia_na, 4, 1800, .big);
    writeU32(&ia_na, 8, 3600, .big);
    var ia_cursor: usize = 12;
    appendDhcpv6Option(&ia_na, &ia_cursor, 5, &ia_address);

    var payload: [160]u8 = [_]u8{0} ** 160;
    payload[0..4].* = .{ @intFromEnum(dhcpv6.MessageType.advertise), 0x12, 0x34, 0x56 };
    var cursor: usize = 4;
    appendDhcpv6Option(&payload, &cursor, 1, "\x00\x03\x00\x01client");
    appendDhcpv6Option(&payload, &cursor, 2, "\x00\x03\x00\x01server");
    appendDhcpv6Option(&payload, &cursor, 3, &ia_na);
    appendDhcpv6Option(&payload, &cursor, 39, "\x00\x06device\x05local\x00");
    const server = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const client = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20 };
    var udp: [200]u8 = undefined;
    try std.testing.expect(try parser.parseUdp(&server, &client, makeUdpPacket(&udp, 547, 546, payload[0..cursor])));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcpv6_observations);
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:20", result.observations.items[0].address);
    try std.testing.expectEqualStrings("device.local", result.observations.items[0].hostname);
    try std.testing.expect(std.mem.indexOf(u8, result.observations.items[0].evidence, "type=advertise") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "dhcpv6_1").?, "valid=7200s") != null);

    payload[0] = @intFromEnum(dhcpv6.MessageType.request);
    try std.testing.expect(try parser.parseUdp(&client, &server, makeUdpPacket(&udp, 546, 547, payload[0..cursor])));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcpv6_observations);

    writeU16(&payload, 6, 0xffff, .big);
    try std.testing.expect(!try parser.parseUdp(&server, &client, makeUdpPacket(&udp, 547, 546, payload[0..cursor])));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dhcpv6_observations);
}

test "UDP port 1900 records SSDP summaries and observations" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "ST: upnp:rootdevice\r\n" ++
        "USN: uuid:device-1\r\n" ++
        "LOCATION: http://192.0.2.20/device.xml\r\n" ++
        "SERVER: TestOS/1 UPnP/1.1 Product/2\r\n\r\n";
    var response_udp: [8 + response.len]u8 = [_]u8{0} ** (8 + response.len);
    writeU16(&response_udp, 0, 1900, .big);
    writeU16(&response_udp, 2, 50_000, .big);
    writeU16(&response_udp, 4, response_udp.len, .big);
    std.mem.copyForwards(u8, response_udp[8..], response);
    try std.testing.expect(try parser.parseUdp(&.{ 192, 0, 2, 20 }, &.{ 192, 0, 2, 10 }, &response_udp));

    const search = "M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n";
    var search_udp: [8 + search.len]u8 = [_]u8{0} ** (8 + search.len);
    writeU16(&search_udp, 0, 50_001, .big);
    writeU16(&search_udp, 2, 1900, .big);
    writeU16(&search_udp, 4, search_udp.len, .big);
    std.mem.copyForwards(u8, search_udp[8..], search);
    try std.testing.expect(try parser.parseUdp(&.{ 192, 0, 2, 10 }, &.{ 239, 255, 255, 250 }, &search_udp));

    try std.testing.expectEqual(@as(usize, 2), parser.stats.ssdp_messages);
    try std.testing.expectEqual(@as(usize, 2), parser.stats.ssdp_fields);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "ssdp_1").?, "device.xml") != null);
    try std.testing.expectEqual(@as(usize, 2), parser.stats.ssdp_observations);
    try std.testing.expectEqual(protocol.NetworkObservationKind.service, result.observations.items[0].kind);
    try std.testing.expectEqualStrings("upnp:rootdevice", result.observations.items[0].service);
    try std.testing.expectEqual(@as(?u16, null), result.observations.items[0].port);
    try std.testing.expectEqual(protocol.NetworkObservationKind.name_query, result.observations.items[1].kind);
    try std.testing.expectEqualStrings("ssdp:all", result.observations.items[1].service);
}

test "DNS query fields and observations stay bounded" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var buffer: [64]u8 = undefined;
    for (0..12) |index| {
        const packet = makeDnsUdp(&buffer, 53_000, 53, 1, 0x0100, "\x01a\x00", 1, 1);
        buffer[21] = @intCast('a' + index);
        try std.testing.expect(try parser.parseUdp(
            &.{ 192, 0, 2, 1 },
            &.{ 198, 51, 100, 53 },
            packet,
        ));
    }

    try std.testing.expectEqual(@as(usize, 12), parser.stats.dns_messages);
    try std.testing.expectEqual(@as(usize, max_name_queries), parser.stats.dns_fields);
    try std.testing.expectEqual(@as(usize, max_name_queries), parser.stats.dns_observations);
    try std.testing.expectEqual(@as(usize, max_name_queries), result.observations.items.len);
    try std.testing.expect(fieldValue(&result, "dns_query_11") == null);
}

test "DNS answer retention stays bounded" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    for (0..20) |index| {
        var value_buffer: [32]u8 = undefined;
        _ = try parser.addDnsRecordField(
            .dns,
            .answer,
            try std.fmt.bufPrint(&value_buffer, "answer-{d}", .{index}),
        );
    }
    try std.testing.expectEqual(@as(usize, max_answer_records), parser.stats.dns_answer_fields);
    try std.testing.expect(fieldValue(&result, "dns_answer_16") != null);
    try std.testing.expect(fieldValue(&result, "dns_answer_17") == null);
}

test "DNS authority and common named records reach fields and observations" {
    const packet =
        "\x00\x01\x84\x00\x00\x01\x00\x02\x00\x02\x00\x01" ++
        "\x03www\x07example\x04test\x00\x00\x01\x00\x01" ++
        "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x09\x06origin\xc0\x10" ++
        "\xc0\x10\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x09\x00\x0a\x04mail\xc0\x10" ++
        "\xc0\x10\x00\x02\x00\x01\x00\x00\x01\x2c\x00\x06\x03ns1\xc0\x10" ++
        "\xc0\x10\x00\x06\x00\x01\x00\x00\x01\x2c\x00\x27" ++
        "\x03ns1\xc0\x10\x0ahostmaster\xc0\x10" ++
        "\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x02\x58" ++
        "\x00\x01\x51\x80\x00\x00\x00\x3c" ++
        "\x03ns1\xc0\x10\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x35";
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    try std.testing.expect(try parser.parseDnsFamily(
        &.{ 198, 51, 100, 53 },
        &.{ 192, 0, 2, 10 },
        packet,
        .dns,
    ));
    try std.testing.expectEqual(@as(usize, 2), parser.stats.dns_answers);
    try std.testing.expectEqual(@as(usize, 2), parser.stats.dns_authorities);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dns_additionals);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "dns_answer_1").?, " CNAME origin.example.test ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "dns_answer_2").?, " MX mail.example.test preference=10 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "dns_authority_1").?, " NS ns1.example.test ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "dns_authority_2").?, " SOA mname=ns1.example.test rname=hostmaster.example.test ") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "dns_additional_1").?, " A 192.0.2.53 ") != null);

    var saw_mail = false;
    var saw_nameserver = false;
    for (result.observations.items) |observation| {
        if (std.mem.eql(u8, observation.hostname, "mail.example.test")) saw_mail = true;
        if (std.mem.eql(u8, observation.hostname, "ns1.example.test") and
            std.mem.eql(u8, observation.source_id, "pcap:dns:authority")) saw_nameserver = true;
    }
    try std.testing.expect(saw_mail);
    try std.testing.expect(saw_nameserver);
}

test "DNS authority retention stays bounded" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    for (0..20) |index| {
        var value_buffer: [32]u8 = undefined;
        _ = try parser.addDnsRecordField(
            .dns,
            .authority,
            try std.fmt.bufPrint(&value_buffer, "authority-{d}", .{index}),
        );
    }
    try std.testing.expectEqual(@as(usize, max_authority_records), parser.stats.dns_authority_fields);
    try std.testing.expect(fieldValue(&result, "dns_authority_16") != null);
    try std.testing.expect(fieldValue(&result, "dns_authority_17") == null);
}

test "PCAPNG applies each section BOM and parses EPB and SPB" {
    var packet: [76]u8 = undefined;
    makeDnsEthernetPacket(&packet);
    var little: [248]u8 = undefined;
    var big: [248]u8 = undefined;
    makePcapngSection(&little, &packet, .little);
    makePcapngSection(&big, &packet, .big);

    var capture: [496]u8 = undefined;
    std.mem.copyForwards(u8, capture[0..248], &little);
    std.mem.copyForwards(u8, capture[248..], &big);
    var result = try analyzeCapture(std.testing.allocator, &capture);
    defer result.deinit();

    try std.testing.expectEqualStrings("2", fieldValue(&result, "sections").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "interfaces").?);
    try std.testing.expectEqualStrings("4", fieldValue(&result, "packets").?);
    try std.testing.expectEqualStrings("4", fieldValue(&result, "dns_messages").?);
    try std.testing.expectEqualStrings("mixed", fieldValue(&result, "byte_order").?);
    try std.testing.expect(fieldValue(&result, "dns_query_2") == null);
}

test "PCAPNG enforces finite section lengths and unlimited snaplen safely" {
    var packet: [76]u8 = undefined;
    makeDnsEthernetPacket(&packet);
    var section: [248]u8 = undefined;

    makePcapngSection(&section, &packet, .little);
    writeU64(&section, 16, section.len - 28, .little);
    var result = try analyzeCapture(std.testing.allocator, &section);
    result.deinit();

    makePcapngSection(&section, &packet, .little);
    writeU64(&section, 16, section.len - 32, .little);
    try std.testing.expectError(error.SectionLengthMismatch, analyzeCapture(std.testing.allocator, &section));

    makePcapngSection(&section, &packet, .little);
    writeU32(&section, 40, 0, .little);
    writeU32(&section, 164, max_packet_bytes + 1, .little);
    try std.testing.expectError(error.InvalidPacketLength, analyzeCapture(std.testing.allocator, &section));
}

test "cleartext HTTP finding is low severity and deduplicated" {
    var packet: [58]u8 = undefined;
    makeHttpRawPacket(&packet);
    var capture: [172]u8 = [_]u8{0} ** 172;
    std.mem.copyForwards(u8, capture[0..4], &.{ 0xd4, 0xc3, 0xb2, 0xa1 });
    writeU16(&capture, 4, 2, .little);
    writeU16(&capture, 6, 4, .little);
    writeU32(&capture, 16, 65_535, .little);
    writeU32(&capture, 20, 101, .little);
    for ([_]usize{ 24, 98 }) |record| {
        writeU32(&capture, record + 8, packet.len, .little);
        writeU32(&capture, record + 12, packet.len, .little);
        std.mem.copyForwards(u8, capture[record + 16 ..], &packet);
    }

    var result = try analyzeCapture(std.testing.allocator, &capture);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqual(protocol.FindingSeverity.low, result.findings.items[0].severity);
    try std.testing.expectEqualStrings("198.51.100.10:80", result.findings.items[0].target);
}

test "malformed packet is counted while malformed containers are rejected" {
    var packet: [76]u8 = undefined;
    makeDnsEthernetPacket(&packet);
    packet[14] = 0x41;
    var capture: [116]u8 = undefined;
    makeClassic(&capture, &packet, .little, false);

    var result = try analyzeCapture(std.testing.allocator, &capture);
    defer result.deinit();
    try std.testing.expectEqualStrings("1", fieldValue(&result, "malformed_packets").?);

    writeU32(&capture, 28, 1_000_000, .little);
    try std.testing.expectError(error.InvalidTimestamp, analyzeCapture(std.testing.allocator, &capture));

    makeDnsEthernetPacket(&packet);
    var section: [248]u8 = undefined;
    makePcapngSection(&section, &packet, .little);
    writeU32(&section, 152, 104, .little);
    try std.testing.expectError(error.BlockLengthMismatch, analyzeCapture(std.testing.allocator, &section));

    makePcapngSection(&section, &packet, .little);
    writeU32(&section, 56, 1, .little);
    try std.testing.expectError(error.InvalidInterface, analyzeCapture(std.testing.allocator, &section));
}

test "IPv4 and IPv6 fragments skip transport decoding" {
    var packet: [76]u8 = undefined;
    var capture: [116]u8 = undefined;

    for ([_]u16{ 0x2000, 0x0001 }) |fragment| {
        makeDnsEthernetPacket(&packet);
        writeU16(&packet, 20, fragment, .big);
        makeClassic(&capture, &packet, .little, false);

        var result = try analyzeCapture(std.testing.allocator, &capture);
        defer result.deinit();
        try std.testing.expectEqualStrings("1", fieldValue(&result, "fragments").?);
        try std.testing.expectEqualStrings("0", fieldValue(&result, "udp_packets").?);
        try std.testing.expectEqualStrings("0", fieldValue(&result, "malformed_packets").?);
    }

    for ([_]u16{ 0x0001, 0x0008 }) |fragment| {
        packet = [_]u8{0} ** packet.len;
        packet[12] = 0x86;
        packet[13] = 0xdd;
        const ip = 14;
        packet[ip] = 0x60;
        writeU16(&packet, ip + 4, 22, .big);
        packet[ip + 6] = 44;
        packet[ip + 7] = 64;
        const fragment_header = ip + 40;
        packet[fragment_header] = 17;
        writeU16(&packet, fragment_header + 2, fragment, .big);
        makeClassic(&capture, &packet, .little, false);

        var result = try analyzeCapture(std.testing.allocator, &capture);
        defer result.deinit();
        try std.testing.expectEqualStrings("1", fieldValue(&result, "fragments").?);
        try std.testing.expectEqualStrings("0", fieldValue(&result, "udp_packets").?);
        try std.testing.expectEqualStrings("0", fieldValue(&result, "malformed_packets").?);
    }
}

test "IPv6 zero payload length does not decode captured padding" {
    var packet: [76]u8 = [_]u8{0} ** 76;
    packet[12] = 0x86;
    packet[13] = 0xdd;
    const ip = 14;
    packet[ip] = 0x60;
    packet[ip + 6] = 6;
    packet[ip + 7] = 64;
    packet[ip + 40 + 12] = 0x50;

    var capture: [116]u8 = undefined;
    makeClassic(&capture, &packet, .little, false);
    var result = try analyzeCapture(std.testing.allocator, &capture);
    defer result.deinit();

    try std.testing.expectEqualStrings("1", fieldValue(&result, "ipv6_packets").?);
    try std.testing.expectEqualStrings("0", fieldValue(&result, "tcp_packets").?);
    try std.testing.expectEqualStrings("0", fieldValue(&result, "malformed_packets").?);
}

test "short IPv6 authentication header is rejected before transport decoding" {
    var packet: [76]u8 = [_]u8{0} ** 76;
    packet[12] = 0x86;
    packet[13] = 0xdd;
    const ip = 14;
    packet[ip] = 0x60;
    writeU16(&packet, ip + 4, 22, .big);
    packet[ip + 6] = 51;
    packet[ip + 7] = 64;
    packet[ip + 40] = 6;
    packet[ip + 41] = 0;

    var capture: [116]u8 = undefined;
    makeClassic(&capture, &packet, .little, false);
    var result = try analyzeCapture(std.testing.allocator, &capture);
    defer result.deinit();

    try std.testing.expectEqualStrings("0", fieldValue(&result, "tcp_packets").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "malformed_packets").?);
}

test "PCAPNG interfaces isolate TCP reassembly state" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var idb: [20]u8 = [_]u8{0} ** 20;
    writeU32(&idb, 0, 1, .little);
    writeU32(&idb, 4, idb.len, .little);
    writeU16(&idb, 8, 1, .little);
    writeU32(&idb, 12, 65_535, .little);
    writeU32(&idb, 16, idb.len, .little);
    try parser.parseInterfaceBlock(&idb, .little);
    try parser.parseInterfaceBlock(&idb, .little);

    const message =
        "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x03www\x07example\x04test\x00\x00\x01\x00\x01";
    var framed: [2 + message.len]u8 = undefined;
    writeU16(&framed, 0, message.len, .big);
    @memcpy(framed[2..], message);
    const split = framed.len / 2;
    var first_packet: [76]u8 = undefined;
    var second_packet: [76]u8 = undefined;
    makeTcpEthernetPacket(&first_packet, .{ 192, 0, 2, 1 }, .{ 198, 51, 100, 53 }, 50_000, 53, 100, 0x18, framed[0..split]);
    makeTcpEthernetPacket(&second_packet, .{ 192, 0, 2, 1 }, .{ 198, 51, 100, 53 }, 50_000, 53, @intCast(100 + split), 0x18, framed[split..]);
    var block: [108]u8 = undefined;
    makeEnhancedPacketBlock(&block, 0, &first_packet);
    try parser.parseEnhancedPacket(&block, .little);
    makeEnhancedPacketBlock(&block, 1, &second_packet);
    try parser.parseEnhancedPacket(&block, .little);

    try std.testing.expectEqual(@as(usize, 0), parser.stats.dns_tcp_messages);
    try std.testing.expectEqual(@as(usize, 2), parser.tcp_streams.items.len);
    try std.testing.expect(parser.tcp_streams.items[0].key.scope != parser.tcp_streams.items[1].key.scope);
}

test "PCAPNG sections isolate TCP reassembly state" {
    const message =
        "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x03www\x07example\x04test\x00\x00\x01\x00\x01";
    var framed: [2 + message.len]u8 = undefined;
    writeU16(&framed, 0, message.len, .big);
    @memcpy(framed[2..], message);
    const split = framed.len / 2;
    var first_packet: [76]u8 = undefined;
    var second_packet: [76]u8 = undefined;
    makeTcpEthernetPacket(&first_packet, .{ 192, 0, 2, 1 }, .{ 198, 51, 100, 53 }, 50_000, 53, 100, 0x18, framed[0..split]);
    makeTcpEthernetPacket(&second_packet, .{ 192, 0, 2, 1 }, .{ 198, 51, 100, 53 }, 50_000, 53, @intCast(100 + split), 0x18, framed[split..]);
    var first_section: [248]u8 = undefined;
    var second_section: [248]u8 = undefined;
    makePcapngSection(&first_section, &first_packet, .little);
    makePcapngSection(&second_section, &second_packet, .little);
    var capture: [first_section.len + second_section.len]u8 = undefined;
    @memcpy(capture[0..first_section.len], &first_section);
    @memcpy(capture[first_section.len..], &second_section);

    var result = try analyzeCapture(std.testing.allocator, &capture);
    defer result.deinit();
    try std.testing.expectEqualStrings("0", fieldValue(&result, "dns_tcp_messages").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "tcp_reassembled_streams").?);
}

test "a new PCAPNG section releases full TCP stream state" {
    var capture: [16 * 1024]u8 = undefined;
    var cursor: usize = 0;
    appendPcapngSection(&capture, &cursor, 1);
    var packet: [76]u8 = undefined;
    for (0..max_tcp_streams) |index| {
        makeTcpEthernetPacket(
            &packet,
            .{ 192, 0, 2, 1 },
            .{ 198, 51, 100, 53 },
            @intCast(10_000 + index),
            53,
            1,
            0x18,
            "x",
        );
        appendEnhancedPacket(&capture, &cursor, &packet);
    }

    appendPcapngSection(&capture, &cursor, 1);
    const message =
        "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x03www\x07example\x04test\x00\x00\x01\x00\x01";
    var framed: [2 + message.len]u8 = undefined;
    writeU16(&framed, 0, message.len, .big);
    @memcpy(framed[2..], message);
    const split = framed.len / 2;
    makeTcpEthernetPacket(&packet, .{ 192, 0, 2, 1 }, .{ 198, 51, 100, 53 }, 50_000, 53, 100, 0x18, framed[0..split]);
    appendEnhancedPacket(&capture, &cursor, &packet);
    makeTcpEthernetPacket(&packet, .{ 192, 0, 2, 1 }, .{ 198, 51, 100, 53 }, 50_000, 53, @intCast(100 + split), 0x18, framed[split..]);
    appendEnhancedPacket(&capture, &cursor, &packet);

    var result = try analyzeCapture(std.testing.allocator, capture[0..cursor]);
    defer result.deinit();
    try std.testing.expectEqualStrings("1", fieldValue(&result, "dns_tcp_messages").?);
}

test "a new PCAPNG section releases full mDNS cache state" {
    var capture: [8 * 1024]u8 = undefined;
    var cursor: usize = 0;
    appendPcapngSection(&capture, &cursor, 101);
    const old_service = "\x05_http\x04_tcp\x05local\x00";
    var dns_packet: [256]u8 = undefined;
    var ip_packet: [512]u8 = undefined;
    for (0..max_mdns_links) |index| {
        var instance: [2 + old_service.len]u8 = undefined;
        instance[0] = 1;
        instance[1] = @intCast('A' + index);
        @memcpy(instance[2..], old_service);
        const message = makeMdnsAnswer(&dns_packet, old_service, 12, 120, &instance);
        writeU16(message, 12 + old_service.len + 2, 1, .big);
        appendEnhancedPacket(
            &capture,
            &cursor,
            makeIpv4UdpPacket(&ip_packet, .{ 192, 0, 2, 55 }, .{ 224, 0, 0, 251 }, 5353, 5353, message),
        );
    }

    appendPcapngSection(&capture, &cursor, 101);
    const service = "\x06_fresh\x04_tcp\x05local\x00";
    const instance = "\x07Printer\x06_fresh\x04_tcp\x05local\x00";
    const hostname = "\x06device\x05local\x00";
    appendEnhancedPacket(
        &capture,
        &cursor,
        makeIpv4UdpPacket(
            &ip_packet,
            .{ 192, 0, 2, 55 },
            .{ 224, 0, 0, 251 },
            5353,
            5353,
            makeMdnsAnswer(&dns_packet, service, 12, 120, instance),
        ),
    );
    var srv: [6 + hostname.len]u8 = [_]u8{0} ** (6 + hostname.len);
    writeU16(&srv, 4, 8080, .big);
    @memcpy(srv[6..], hostname);
    appendEnhancedPacket(
        &capture,
        &cursor,
        makeIpv4UdpPacket(
            &ip_packet,
            .{ 192, 0, 2, 55 },
            .{ 224, 0, 0, 251 },
            5353,
            5353,
            makeMdnsAnswer(&dns_packet, instance, 33, 120, &srv),
        ),
    );
    appendEnhancedPacket(
        &capture,
        &cursor,
        makeIpv4UdpPacket(
            &ip_packet,
            .{ 192, 0, 2, 55 },
            .{ 224, 0, 0, 251 },
            5353,
            5353,
            makeMdnsAnswer(&dns_packet, hostname, 1, 120, &.{ 192, 0, 2, 99 }),
        ),
    );

    var result = try analyzeCapture(std.testing.allocator, capture[0..cursor]);
    defer result.deinit();
    var associated = false;
    for (result.observations.items) |observation| {
        if (std.mem.eql(u8, observation.source_id, "pcap:mdns:service-discovery") and
            std.mem.eql(u8, observation.service, "_fresh._tcp.local")) associated = true;
    }
    try std.testing.expect(associated);
}

test "TCP reassembly decodes DNS across overlap and out-of-order segments" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    const message =
        "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x03www\x07example\x04test\x00\x00\x01\x00\x01";
    var framed: [2 + message.len]u8 = undefined;
    writeU16(&framed, 0, message.len, .big);
    @memcpy(framed[2..], message);
    var tcp: [128]u8 = undefined;
    const source = [_]u8{ 192, 0, 2, 1 };
    const destination = [_]u8{ 198, 51, 100, 53 };

    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 53, 100, 0x18, framed[0..8])));
    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 53, 116, 0x18, framed[16..])));
    try std.testing.expectEqual(@as(usize, 0), parser.stats.dns_messages);
    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 53, 106, 0x18, framed[6..18])));

    try std.testing.expectEqual(@as(usize, 1), parser.stats.dns_messages);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dns_tcp_messages);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tcp_out_of_order_segments);
    try std.testing.expectEqualStrings("www.example.test (type 1)", fieldValue(&result, "dns_query_1").?);
    try std.testing.expectEqualStrings("192.0.2.1", result.observations.items[0].address);

    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 53, 100, 0x18, framed[0..8])));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.dns_messages);
}

test "TCP reassembly detects cleartext HTTP split across segments" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var tcp: [64]u8 = undefined;
    const source = [_]u8{ 192, 0, 2, 10 };
    const destination = [_]u8{ 198, 51, 100, 10 };
    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 8080, 100, 0x18, "GE")));
    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 8080, 102, 0x18, "T / HT")));
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 8080, 108, 0x18, "TP/1.1\r\nHost: test\r\n")));
    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqualStrings("198.51.100.10:8080", result.findings.items[0].target);
}

test "TCP reassembly records passive TLS client and server hello metadata" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    const client_hello =
        "\x16\x03\x01\x00\x60" ++
        "\x01\x00\x00\x5c\x03\x03" ++
        ("\x11" ** 32) ++
        "\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x2f" ++
        "\x00\x00\x00\x10\x00\x0e\x00\x00\x0bexample.com" ++
        "\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1" ++
        "\x00\x2b\x00\x05\x04\x03\x04\x03\x03";
    const server_hello =
        "\x16\x03\x03\x00\x32" ++
        "\x02\x00\x00\x2e\x03\x03" ++
        ("\x22" ** 32) ++
        "\x00\x13\x01\x00\x00\x06\x00\x2b\x00\x02\x03\x04";
    const client = [_]u8{ 192, 0, 2, 10 };
    const server = [_]u8{ 198, 51, 100, 10 };
    var tcp: [160]u8 = undefined;

    try std.testing.expect(try parser.parseTcp(
        &client,
        &server,
        makeTcpSegment(&tcp, 50_000, 443, 100, 0x18, client_hello[0..17]),
    ));
    try std.testing.expectEqual(@as(usize, 0), parser.stats.tls_client_hellos);
    try std.testing.expect(try parser.parseTcp(
        &client,
        &server,
        makeTcpSegment(&tcp, 50_000, 443, 117, 0x18, client_hello[17..]),
    ));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tls_client_hellos);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "tls_client_hello_1").?, "sni=example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "tls_client_hello_1").?, "offered_alpn=h2,http/1.1") != null);
    try std.testing.expect(try parser.parseTcp(
        &client,
        &server,
        makeTcpSegment(&tcp, 50_001, 443, 300, 0x18, client_hello),
    ));
    try std.testing.expectEqual(@as(usize, 2), parser.stats.tls_client_hellos);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tls_client_fields);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tls_client_observations);

    try std.testing.expect(try parser.parseTcp(
        &server,
        &client,
        makeTcpSegment(&tcp, 443, 50_000, 500, 0x18, server_hello),
    ));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tls_server_hellos);
    try std.testing.expect(std.mem.indexOf(u8, fieldValue(&result, "tls_server_hello_1").?, "version=TLS 1.3") != null);
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tls_server_observations);
    try std.testing.expectEqual(.inferred, result.observations.items[0].confidence);
    try std.testing.expectEqualStrings("example.com", result.observations.items[0].hostname);
    try std.testing.expectEqual(.confirmed, result.observations.items[1].confidence);
    try std.testing.expectEqualStrings("TLS 1.3", result.observations.items[1].version);
    try std.testing.expectEqual(@as(usize, 0), parser.tcp_reassembly_bytes);
}

test "malformed passive TLS terminates only its directional stream" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    const client = [_]u8{ 192, 0, 2, 10 };
    const server = [_]u8{ 198, 51, 100, 10 };
    const malformed = "\x16\x03\x03\x00\x05\x01\x00\x00\x01\x03";
    var tcp: [96]u8 = undefined;

    try std.testing.expect(try parser.parseTcp(
        &client,
        &server,
        makeTcpSegment(&tcp, 50_000, 443, 100, 0x18, malformed),
    ));
    const key = TcpKey.init(0, &client, &server, 50_000, 443).?;
    const stream = parser.tcp_streams.items[parser.findTcpStream(key).?];
    try std.testing.expect(stream.application_done);
    try std.testing.expectEqual(@as(usize, 0), parser.tcp_reassembly_bytes);
    try std.testing.expectEqual(@as(usize, 0), parser.stats.malformed_packets);
    try std.testing.expectEqual(@as(usize, 0), parser.stats.tls_client_hellos);
    try std.testing.expectEqual(@as(usize, 0), result.fields.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.observations.items.len);

    const server_hello =
        "\x16\x03\x03\x00\x32" ++
        "\x02\x00\x00\x2e\x03\x03" ++
        ("\x55" ** 32) ++
        "\x00\x13\x01\x00\x00\x06\x00\x2b\x00\x02\x03\x04";
    try std.testing.expect(try parser.parseTcp(
        &server,
        &client,
        makeTcpSegment(&tcp, 443, 50_000, 500, 0x18, server_hello),
    ));
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tls_server_hellos);
    try std.testing.expectEqual(.confirmed, result.observations.items[0].confidence);
}

test "confirmed TLS observations keep capacity after client metadata" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    parser.stats.tls_client_observations = max_tls_hellos;

    try parser.addTlsServerHello(&.{ 198, 51, 100, 10 }, 443, .{
        .version = .tls_1_3,
        .cipher_suite = .AES_128_GCM_SHA256,
    });
    try std.testing.expectEqual(@as(usize, 1), parser.stats.tls_server_observations);
    try std.testing.expectEqual(.confirmed, result.observations.items[0].confidence);
}

test "capture analysis exposes passive TLS counters" {
    const server_hello =
        "\x16\x03\x03\x00\x32" ++
        "\x02\x00\x00\x2e\x03\x03" ++
        ("\x44" ** 32) ++
        "\x00\x13\x01\x00\x00\x06\x00\x2b\x00\x02\x03\x04";
    var capture: [320]u8 = undefined;
    var cursor: usize = 0;
    appendPcapngSection(&capture, &cursor, 101);
    var packet: [160]u8 = undefined;
    appendEnhancedPacket(
        &capture,
        &cursor,
        makeIpv4TcpPacket(
            &packet,
            .{ 198, 51, 100, 10 },
            .{ 192, 0, 2, 10 },
            443,
            50_000,
            500,
            0x18,
            server_hello,
        ),
    );

    var result = try analyzeCapture(std.testing.allocator, capture[0..cursor]);
    defer result.deinit();
    try std.testing.expectEqualStrings("0", fieldValue(&result, "tls_client_hellos").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "tls_server_hellos").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "tls_service_observations").?);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "TLS=1") != null);
}

test "TCP reassembly detects an HTTP status line split across segments" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();

    var tcp: [64]u8 = undefined;
    try std.testing.expect(try parser.parseTcp(
        &.{ 198, 51, 100, 10 },
        &.{ 192, 0, 2, 10 },
        makeTcpSegment(&tcp, 8000, 50_000, 50, 0x18, "HTTP/1."),
    ));
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
    try std.testing.expect(try parser.parseTcp(
        &.{ 198, 51, 100, 10 },
        &.{ 192, 0, 2, 10 },
        makeTcpSegment(&tcp, 8000, 50_000, 57, 0x18, "1 200 OK\r\n"),
    ));
    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqualStrings("198.51.100.10:8000", result.findings.items[0].target);
}

test "TCP SYN resets reused state and completed inspection drops later payload" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    const source = [_]u8{ 192, 0, 2, 10 };
    const destination = [_]u8{ 198, 51, 100, 10 };
    const key = TcpKey.init(0, &source, &destination, 50_000, 8080).?;
    const oversized = [_]u8{'x'} ** (max_tcp_stream_bytes + 1);
    try std.testing.expect(!try parser.acceptTcpPayload(&source, &destination, 50_000, 8080, 1, &oversized, false));
    try std.testing.expect(parser.tcp_streams.items[parser.findTcpStream(key).?].disabled);

    var tcp: [128]u8 = undefined;
    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 8080, 1_000, 0x02, "")));
    var stream = &parser.tcp_streams.items[parser.findTcpStream(key).?];
    try std.testing.expect(!stream.disabled);
    try std.testing.expect(!stream.application_done);
    try std.testing.expectEqual(@as(u32, 1_001), stream.next_sequence);

    const request = "GET / HTTP/1.1\r\nHost: example.test\r\n";
    try std.testing.expect(try parser.parseTcp(&source, &destination, makeTcpSegment(&tcp, 50_000, 8080, 1_001, 0x18, request)));
    stream = &parser.tcp_streams.items[parser.findTcpStream(key).?];
    try std.testing.expect(stream.application_done);
    try std.testing.expectEqual(@as(usize, 0), parser.tcp_reassembly_bytes);
    const segments = parser.stats.tcp_reassembly_segments;
    try std.testing.expect(try parser.parseTcp(
        &source,
        &destination,
        makeTcpSegment(&tcp, 50_000, 8080, @intCast(1_001 + request.len), 0x18, "body"),
    ));
    try std.testing.expectEqual(segments, parser.stats.tcp_reassembly_segments);
    try std.testing.expectEqual(@as(usize, 0), parser.tcp_reassembly_bytes);
}

test "TCP FIN and RST release directional stream state" {
    var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
    defer result.deinit();
    var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
    defer parser.deinit();
    const client = [_]u8{ 192, 0, 2, 10 };
    const server = [_]u8{ 198, 51, 100, 10 };
    try std.testing.expect(try parser.acceptTcpPayload(&client, &server, 50_000, 8080, 1, "G", false));
    try std.testing.expect(try parser.acceptTcpPayload(&server, &client, 8080, 50_000, 1, "H", false));
    try std.testing.expectEqual(@as(usize, 2), parser.tcp_streams.items.len);

    var tcp: [64]u8 = undefined;
    try std.testing.expect(try parser.parseTcp(&client, &server, makeTcpSegment(&tcp, 50_000, 8080, 2, 0x11, "")));
    try std.testing.expectEqual(@as(usize, 1), parser.tcp_streams.items.len);
    try std.testing.expect(parser.findTcpStream(TcpKey.init(0, &server, &client, 8080, 50_000).?) != null);

    try std.testing.expect(try parser.parseTcp(&server, &client, makeTcpSegment(&tcp, 8080, 50_000, 2, 0x14, "")));
    try std.testing.expectEqual(@as(usize, 0), parser.tcp_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), parser.tcp_reassembly_bytes);
}

test "TCP reassembly limits streams queues segments and bytes" {
    {
        var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
        defer result.deinit();
        var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
        defer parser.deinit();
        for (0..max_tcp_streams) |index| {
            try std.testing.expect(try parser.acceptTcpPayload(
                &.{ 192, 0, 2, 1 },
                &.{ 198, 51, 100, 1 },
                @intCast(10_000 + index),
                9_999,
                1,
                "x",
                false,
            ));
        }
        try std.testing.expect(!try parser.acceptTcpPayload(&.{ 192, 0, 2, 1 }, &.{ 198, 51, 100, 1 }, 20_000, 9_999, 1, "x", false));
        try std.testing.expectEqual(@as(usize, max_tcp_streams), parser.tcp_streams.items.len);
        try std.testing.expect(try parser.acceptTcpPayload(&.{ 192, 0, 2, 1 }, &.{ 198, 51, 100, 1 }, 10_000, 9_999, 2, "\n", false));
        try std.testing.expect(try parser.acceptTcpPayload(&.{ 192, 0, 2, 1 }, &.{ 198, 51, 100, 1 }, 20_000, 9_999, 1, "x", false));
        try std.testing.expectEqual(@as(usize, max_tcp_streams), parser.tcp_streams.items.len);
    }

    {
        var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
        defer result.deinit();
        var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
        defer parser.deinit();
        const oversized = [_]u8{'x'} ** (max_tcp_stream_bytes + 1);
        try std.testing.expect(!try parser.acceptTcpPayload(&.{ 192, 0, 2, 1 }, &.{ 198, 51, 100, 1 }, 1, 2, 1, &oversized, false));
        try std.testing.expectEqual(@as(usize, 0), parser.tcp_reassembly_bytes);
        try std.testing.expect(parser.tcp_streams.items[0].disabled);
    }

    {
        var result = try protocol.AnalysisResult.init(std.testing.allocator, "test");
        defer result.deinit();
        var parser = Parser{ .allocator = std.testing.allocator, .result = &result };
        defer parser.deinit();
        try std.testing.expect(try parser.acceptTcpPayload(&.{ 192, 0, 2, 1 }, &.{ 198, 51, 100, 1 }, 1, 2, 1, "G", false));
        for (0..max_tcp_queued_segments + 2) |index| {
            try std.testing.expect(try parser.acceptTcpPayload(
                &.{ 192, 0, 2, 1 },
                &.{ 198, 51, 100, 1 },
                1,
                2,
                @intCast(100 + index),
                "x",
                false,
            ));
        }
        try std.testing.expectEqual(@as(usize, max_tcp_queued_segments), parser.tcp_streams.items[0].queued_count);
        parser.stats.tcp_reassembly_segments = max_tcp_segments;
        try std.testing.expect(!try parser.acceptTcpPayload(&.{ 192, 0, 2, 1 }, &.{ 198, 51, 100, 1 }, 1, 2, 2, "x", false));
    }
}

test "HTTP detection requires a protocol marker on the request line" {
    try std.testing.expectEqual(HttpDirection.none, httpDirection("GET this is plain text"));
    try std.testing.expectEqual(HttpDirection.request, httpDirection("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"));
}

test "mDNS service transport matching is ASCII case-insensitive" {
    try std.testing.expectEqualStrings("tcp", serviceTransport("_http._TCP.local"));
    try std.testing.expectEqualStrings("udp", serviceTransport("_dns-sd._UdP.local"));
}
