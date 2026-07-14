const std = @import("std");

pub const Kind = enum {
    host,
    name_query,
    endpoint,
    service,
};

pub const Confidence = enum {
    inferred,
    observed,
    confirmed,
};

pub const Spec = struct {
    kind: Kind,
    confidence: Confidence,
    address: []const u8 = "",
    hostname: []const u8 = "",
    transport: []const u8 = "",
    port: ?u16 = null,
    service: []const u8 = "",
    product: []const u8 = "",
    version: []const u8 = "",
    evidence: []const u8 = "",
    source_id: []const u8 = "",
};

pub const NetworkObservation = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    confidence: Confidence,
    address: []u8,
    hostname: []u8,
    transport: []u8,
    port: ?u16,
    service: []u8,
    product: []u8,
    version: []u8,
    evidence: []u8,
    source_id: []u8,

    pub fn init(allocator: std.mem.Allocator, spec: Spec) !NetworkObservation {
        const address = try allocator.dupe(u8, spec.address);
        errdefer allocator.free(address);
        const hostname = try allocator.dupe(u8, spec.hostname);
        errdefer allocator.free(hostname);
        const transport = try allocator.dupe(u8, spec.transport);
        errdefer allocator.free(transport);
        const service = try allocator.dupe(u8, spec.service);
        errdefer allocator.free(service);
        const product = try allocator.dupe(u8, spec.product);
        errdefer allocator.free(product);
        const version = try allocator.dupe(u8, spec.version);
        errdefer allocator.free(version);
        const evidence = try allocator.dupe(u8, spec.evidence);
        errdefer allocator.free(evidence);
        const source_id = try allocator.dupe(u8, spec.source_id);
        errdefer allocator.free(source_id);

        return .{
            .allocator = allocator,
            .kind = spec.kind,
            .confidence = spec.confidence,
            .address = address,
            .hostname = hostname,
            .transport = transport,
            .port = spec.port,
            .service = service,
            .product = product,
            .version = version,
            .evidence = evidence,
            .source_id = source_id,
        };
    }

    pub fn deinit(self: *NetworkObservation) void {
        self.allocator.free(self.address);
        self.allocator.free(self.hostname);
        self.allocator.free(self.transport);
        self.allocator.free(self.service);
        self.allocator.free(self.product);
        self.allocator.free(self.version);
        self.allocator.free(self.evidence);
        self.allocator.free(self.source_id);
        self.* = undefined;
    }

    pub fn eql(left: NetworkObservation, right: NetworkObservation) bool {
        return left.kind == right.kind and
            left.confidence == right.confidence and
            left.port == right.port and
            std.mem.eql(u8, left.address, right.address) and
            std.mem.eql(u8, left.hostname, right.hostname) and
            std.mem.eql(u8, left.transport, right.transport) and
            std.mem.eql(u8, left.service, right.service) and
            std.mem.eql(u8, left.product, right.product) and
            std.mem.eql(u8, left.version, right.version) and
            std.mem.eql(u8, left.evidence, right.evidence) and
            std.mem.eql(u8, left.source_id, right.source_id);
    }
};

test "network observation owns structured evidence" {
    var observation = try NetworkObservation.init(std.testing.allocator, .{
        .kind = .service,
        .confidence = .confirmed,
        .address = "192.0.2.10",
        .transport = "tcp",
        .port = 443,
        .service = "https",
        .product = "Example Server",
        .version = "1.3",
        .evidence = "TLS handshake",
        .source_id = "test",
    });
    defer observation.deinit();

    try std.testing.expectEqual(Kind.service, observation.kind);
    try std.testing.expectEqual(@as(?u16, 443), observation.port);
    try std.testing.expectEqualStrings("https", observation.service);
    try std.testing.expectEqualStrings("Example Server", observation.product);
    try std.testing.expectEqualStrings("1.3", observation.version);
}
