const std = @import("std");
const network = @import("../core/network_observation.zig");
const workbench = @import("workbench.zig");

pub const max_assets = 2048;
pub const max_identities_per_asset = 64;
pub const max_sources_per_identity = 64;
pub const max_endpoints_per_asset = 512;
pub const max_sources_per_asset = 512;

pub const IdentityKind = enum {
    address,
    hostname,
};

pub const Identity = struct {
    kind: IdentityKind,
    value: []u8,
    confidence: network.Confidence,
    sources: std.ArrayList([]u8) = .empty,

    fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
        for (self.sources.items) |source| allocator.free(source);
        self.sources.deinit(allocator);
        self.* = undefined;
    }

    fn addSource(self: *Identity, allocator: std.mem.Allocator, source: []const u8) !void {
        try addUniqueSource(allocator, &self.sources, source, max_sources_per_identity);
    }
};

pub const Endpoint = struct {
    transport: []u8,
    port: ?u16,
    service: []u8,
    product: []u8,
    version: []u8,
    confidence: network.Confidence,
    version_confidence: ?network.Confidence,
    sources: std.ArrayList([]u8) = .empty,
    version_sources: std.ArrayList([]u8) = .empty,

    fn deinit(self: *Endpoint, allocator: std.mem.Allocator) void {
        allocator.free(self.transport);
        allocator.free(self.service);
        allocator.free(self.product);
        allocator.free(self.version);
        for (self.sources.items) |source| allocator.free(source);
        self.sources.deinit(allocator);
        for (self.version_sources.items) |source| allocator.free(source);
        self.version_sources.deinit(allocator);
        self.* = undefined;
    }

    fn addSource(self: *Endpoint, allocator: std.mem.Allocator, source: []const u8) !void {
        try addUniqueSource(allocator, &self.sources, source, max_sources_per_asset);
    }

    fn addVersionSource(self: *Endpoint, allocator: std.mem.Allocator, source: []const u8) !void {
        try addUniqueSource(allocator, &self.version_sources, source, max_sources_per_asset);
    }
};

pub const Asset = struct {
    identities: std.ArrayList(Identity) = .empty,
    endpoints: std.ArrayList(Endpoint) = .empty,
    sources: std.ArrayList([]u8) = .empty,
    confidence: network.Confidence = .inferred,

    fn deinit(self: *Asset, allocator: std.mem.Allocator) void {
        for (self.identities.items) |*identity| identity.deinit(allocator);
        self.identities.deinit(allocator);
        for (self.endpoints.items) |*endpoint| endpoint.deinit(allocator);
        self.endpoints.deinit(allocator);
        for (self.sources.items) |source| allocator.free(source);
        self.sources.deinit(allocator);
        self.* = undefined;
    }

    pub fn preferredName(self: *const Asset) []const u8 {
        if (self.identities.items.len == 0) return "unknown";
        var best_index: usize = 0;
        for (self.identities.items[1..], 1..) |identity, index| {
            const best = self.identities.items[best_index];
            const rank = confidenceRank(identity.confidence);
            const best_rank = confidenceRank(best.confidence);
            if (rank > best_rank or
                (rank == best_rank and identity.kind == .hostname and best.kind == .address))
            {
                best_index = index;
            }
        }
        return self.identities.items[best_index].value;
    }
};

pub const AssetGraph = struct {
    allocator: std.mem.Allocator,
    assets: std.ArrayList(Asset) = .empty,

    pub fn init(allocator: std.mem.Allocator) AssetGraph {
        return .{ .allocator = allocator };
    }

    pub fn build(allocator: std.mem.Allocator, analyses: []const workbench.Analysis) !AssetGraph {
        var graph = AssetGraph.init(allocator);
        errdefer graph.deinit();
        for (analyses) |analysis| {
            for (analysis.result.observations.items) |observation| try graph.addObservation(observation);
        }
        return graph;
    }

    pub fn deinit(self: *AssetGraph) void {
        for (self.assets.items) |*asset| asset.deinit(self.allocator);
        self.assets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addObservation(self: *AssetGraph, observation: network.NetworkObservation) !void {
        const associate_hostname = observation.kind != .name_query;
        if (observation.address.len == 0 and (!associate_hostname or observation.hostname.len == 0)) return;
        const address_index = if (observation.address.len == 0)
            null
        else
            self.findIdentity(.address, observation.address);
        const hostname_index = if (!associate_hostname or observation.hostname.len == 0)
            null
        else
            self.findIdentity(.hostname, observation.hostname);

        var asset_index = address_index orelse hostname_index orelse try self.addAsset();
        if (address_index != null and hostname_index != null and address_index.? != hostname_index.?) {
            asset_index = try self.mergeAssets(address_index.?, hostname_index.?);
        }

        if (observation.address.len != 0) {
            _ = try self.addIdentity(
                asset_index,
                .address,
                observation.address,
                observation.confidence,
                observation.source_id,
            );
        }
        if (associate_hostname and observation.hostname.len != 0) {
            _ = try self.addIdentity(
                asset_index,
                .hostname,
                observation.hostname,
                observation.confidence,
                observation.source_id,
            );
        }

        var asset = &self.assets.items[asset_index];
        asset.confidence = strongerConfidence(asset.confidence, observation.confidence);
        try addUniqueSource(self.allocator, &asset.sources, observation.source_id, max_sources_per_asset);
        if (observation.kind == .endpoint or observation.kind == .service) {
            const version_confidence: ?network.Confidence = if (observation.version.len == 0)
                null
            else
                observation.confidence;
            _ = try self.addEndpoint(
                asset_index,
                observation,
                version_confidence,
                if (observation.version.len == 0) "" else observation.source_id,
            );
        }
    }

    fn addAsset(self: *AssetGraph) !usize {
        if (self.assets.items.len == max_assets) return error.TooManyAssets;
        try self.assets.append(self.allocator, .{});
        return self.assets.items.len - 1;
    }

    fn findIdentity(self: *const AssetGraph, kind: IdentityKind, value: []const u8) ?usize {
        for (self.assets.items, 0..) |asset, asset_index| {
            for (asset.identities.items) |identity| {
                if (identity.kind == kind and identityEqual(kind, identity.value, value)) return asset_index;
            }
        }
        return null;
    }

    fn addIdentity(
        self: *AssetGraph,
        asset_index: usize,
        kind: IdentityKind,
        value: []const u8,
        confidence: network.Confidence,
        source: []const u8,
    ) !usize {
        var asset = &self.assets.items[asset_index];
        for (asset.identities.items, 0..) |*identity, identity_index| {
            if (identity.kind == kind and identityEqual(kind, identity.value, value)) {
                try identity.addSource(self.allocator, source);
                identity.confidence = strongerConfidence(identity.confidence, confidence);
                return identity_index;
            }
        }
        if (asset.identities.items.len == max_identities_per_asset) return error.TooManyAssetIdentities;
        const owned = if (kind == .hostname)
            try normalizedHostname(self.allocator, value)
        else
            try self.allocator.dupe(u8, value);
        var identity = Identity{ .kind = kind, .value = owned, .confidence = confidence };
        errdefer identity.deinit(self.allocator);
        try identity.addSource(self.allocator, source);
        try asset.identities.append(self.allocator, identity);
        return asset.identities.items.len - 1;
    }

    fn addEndpoint(
        self: *AssetGraph,
        asset_index: usize,
        observation: network.NetworkObservation,
        version_confidence: ?network.Confidence,
        version_source: []const u8,
    ) !usize {
        var asset = &self.assets.items[asset_index];
        for (asset.endpoints.items, 0..) |*endpoint, endpoint_index| {
            if (endpoint.port != observation.port or
                !std.ascii.eqlIgnoreCase(endpoint.transport, observation.transport) or
                (endpoint.service.len != 0 and observation.service.len != 0 and
                    !std.ascii.eqlIgnoreCase(endpoint.service, observation.service)) or
                (endpoint.product.len != 0 and observation.product.len != 0 and
                    !std.ascii.eqlIgnoreCase(endpoint.product, observation.product))) continue;
            if (endpoint.version.len != 0 and observation.version.len != 0 and
                !std.mem.eql(u8, endpoint.version, observation.version)) continue;

            if (endpoint.service.len == 0 and observation.service.len != 0) {
                const owned_service = try self.allocator.dupe(u8, observation.service);
                self.allocator.free(endpoint.service);
                endpoint.service = owned_service;
            }
            if (endpoint.product.len == 0 and observation.product.len != 0) {
                const owned_product = try self.allocator.dupe(u8, observation.product);
                self.allocator.free(endpoint.product);
                endpoint.product = owned_product;
            }
            if (endpoint.version.len == 0 and observation.version.len != 0) {
                const owned_version = try self.allocator.dupe(u8, observation.version);
                errdefer self.allocator.free(owned_version);
                try endpoint.addVersionSource(self.allocator, version_source);
                self.allocator.free(endpoint.version);
                endpoint.version = owned_version;
                endpoint.version_confidence = version_confidence;
            } else if (observation.version.len != 0) {
                try endpoint.addVersionSource(self.allocator, version_source);
                if (version_confidence) |confidence| {
                    endpoint.version_confidence = if (endpoint.version_confidence) |existing|
                        strongerConfidence(existing, confidence)
                    else
                        confidence;
                }
            }
            endpoint.confidence = strongerConfidence(endpoint.confidence, observation.confidence);
            try endpoint.addSource(self.allocator, observation.source_id);
            return endpoint_index;
        }

        if (asset.endpoints.items.len == max_endpoints_per_asset) return error.TooManyAssetEndpoints;
        try asset.endpoints.ensureUnusedCapacity(self.allocator, 1);
        const transport = try self.allocator.dupe(u8, observation.transport);
        errdefer self.allocator.free(transport);
        const service = try self.allocator.dupe(u8, observation.service);
        errdefer self.allocator.free(service);
        const product = try self.allocator.dupe(u8, observation.product);
        errdefer self.allocator.free(product);
        const version = try self.allocator.dupe(u8, observation.version);
        errdefer self.allocator.free(version);
        var endpoint = Endpoint{
            .transport = transport,
            .port = observation.port,
            .service = service,
            .product = product,
            .version = version,
            .confidence = observation.confidence,
            .version_confidence = if (observation.version.len == 0) null else version_confidence,
        };
        errdefer {
            for (endpoint.sources.items) |source| self.allocator.free(source);
            endpoint.sources.deinit(self.allocator);
            for (endpoint.version_sources.items) |source| self.allocator.free(source);
            endpoint.version_sources.deinit(self.allocator);
        }
        try endpoint.addSource(self.allocator, observation.source_id);
        if (observation.version.len != 0) try endpoint.addVersionSource(self.allocator, version_source);
        asset.endpoints.appendAssumeCapacity(endpoint);
        return asset.endpoints.items.len - 1;
    }

    fn mergeAssets(self: *AssetGraph, first_index: usize, second_index: usize) !usize {
        const keep_index = @min(first_index, second_index);
        const remove_index = @max(first_index, second_index);

        const removed = self.assets.items[remove_index];
        for (removed.identities.items) |identity| {
            const identity_index = try self.addIdentity(
                keep_index,
                identity.kind,
                identity.value,
                identity.confidence,
                if (identity.sources.items.len == 0) "" else identity.sources.items[0],
            );
            if (identity.sources.items.len > 1) {
                for (identity.sources.items[1..]) |source| {
                    try self.assets.items[keep_index].identities.items[identity_index].addSource(
                        self.allocator,
                        source,
                    );
                }
            }
        }
        for (removed.sources.items) |source| {
            try addUniqueSource(
                self.allocator,
                &self.assets.items[keep_index].sources,
                source,
                max_sources_per_asset,
            );
        }
        for (removed.endpoints.items) |endpoint| {
            var observation = try network.NetworkObservation.init(self.allocator, .{
                .kind = .service,
                .confidence = endpoint.confidence,
                .transport = endpoint.transport,
                .port = endpoint.port,
                .service = endpoint.service,
                .product = endpoint.product,
                .version = endpoint.version,
                .source_id = if (endpoint.sources.items.len == 0) "" else endpoint.sources.items[0],
            });
            defer observation.deinit();
            const endpoint_index = try self.addEndpoint(
                keep_index,
                observation,
                endpoint.version_confidence,
                if (endpoint.version_sources.items.len == 0) "" else endpoint.version_sources.items[0],
            );
            if (endpoint.sources.items.len > 1) {
                for (endpoint.sources.items[1..]) |source| {
                    const kept_endpoint = &self.assets.items[keep_index].endpoints.items[endpoint_index];
                    try kept_endpoint.addSource(self.allocator, source);
                }
            }
            if (endpoint.version_sources.items.len > 1) {
                for (endpoint.version_sources.items[1..]) |source| {
                    const kept_endpoint = &self.assets.items[keep_index].endpoints.items[endpoint_index];
                    try kept_endpoint.addVersionSource(self.allocator, source);
                }
            }
        }
        self.assets.items[keep_index].confidence = strongerConfidence(
            self.assets.items[keep_index].confidence,
            removed.confidence,
        );

        var owned_removed = self.assets.orderedRemove(remove_index);
        owned_removed.deinit(self.allocator);
        return keep_index;
    }
};

fn addUniqueSource(
    allocator: std.mem.Allocator,
    sources: *std.ArrayList([]u8),
    source: []const u8,
    limit: usize,
) !void {
    if (source.len == 0) return;
    for (sources.items) |existing| if (std.mem.eql(u8, existing, source)) return;
    if (sources.items.len == limit) return error.TooManyAssetSources;
    const owned = try allocator.dupe(u8, source);
    errdefer allocator.free(owned);
    try sources.append(allocator, owned);
}

fn identityEqual(kind: IdentityKind, left: []const u8, right: []const u8) bool {
    return switch (kind) {
        .address => addressEqual(left, right),
        .hostname => hostnameEqual(left, right),
    };
}

fn addressEqual(left: []const u8, right: []const u8) bool {
    if (std.mem.indexOfScalar(u8, left, '%') != null or std.mem.indexOfScalar(u8, right, '%') != null) {
        return std.ascii.eqlIgnoreCase(left, right);
    }
    var left_address = std.Io.net.IpAddress.parse(left, 0) catch return std.ascii.eqlIgnoreCase(left, right);
    var right_address = std.Io.net.IpAddress.parse(right, 0) catch return std.ascii.eqlIgnoreCase(left, right);
    return left_address.eql(&right_address);
}

fn hostnameEqual(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(trimTrailingDot(left), trimTrailingDot(right));
}

fn trimTrailingDot(value: []const u8) []const u8 {
    return if (value.len != 0 and value[value.len - 1] == '.') value[0 .. value.len - 1] else value;
}

fn normalizedHostname(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const trimmed = trimTrailingDot(value);
    const owned = try allocator.dupe(u8, trimmed);
    for (owned) |*byte| byte.* = std.ascii.toLower(byte.*);
    return owned;
}

fn strongerConfidence(left: network.Confidence, right: network.Confidence) network.Confidence {
    return if (confidenceRank(right) > confidenceRank(left)) right else left;
}

fn confidenceRank(confidence: network.Confidence) u2 {
    return switch (confidence) {
        .inferred => 0,
        .observed => 1,
        .confirmed => 2,
    };
}

test "asset graph merges deterministic cross-source identities" {
    var graph = AssetGraph.init(std.testing.allocator);
    defer graph.deinit();

    var first = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .observed,
        .address = "192.0.2.10",
        .hostname = "Printer.LOCAL.",
        .source_id = "pcap:mdns",
    });
    defer first.deinit();
    try graph.addObservation(first);

    var second = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .service,
        .confidence = .confirmed,
        .hostname = "printer.local",
        .transport = "tcp",
        .port = 443,
        .service = "https",
        .version = "1.0",
        .source_id = "nmap:service",
    });
    defer second.deinit();
    try graph.addObservation(second);

    try std.testing.expectEqual(@as(usize, 1), graph.assets.items.len);
    try std.testing.expectEqualStrings("printer.local", graph.assets.items[0].preferredName());
    try std.testing.expectEqual(network.Confidence.confirmed, graph.assets.items[0].confidence);
    try std.testing.expectEqual(@as(usize, 2), graph.assets.items[0].sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items.len);
    try std.testing.expectEqual(network.Confidence.confirmed, graph.assets.items[0].identities.items[1].confidence);
    try std.testing.expectEqual(@as(usize, 2), graph.assets.items[0].identities.items[1].sources.items.len);
    try std.testing.expectEqual(
        network.Confidence.confirmed,
        graph.assets.items[0].endpoints.items[0].version_confidence.?,
    );
}

test "asset graph bridges previously separate address and hostname assets" {
    var graph = AssetGraph.init(std.testing.allocator);
    defer graph.deinit();

    var address_only = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .observed,
        .address = "192.0.2.20",
        .source_id = "pcap:arp",
    });
    defer address_only.deinit();
    try graph.addObservation(address_only);
    var address_service = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .service,
        .confidence = .observed,
        .address = "192.0.2.20",
        .transport = "tcp",
        .port = 80,
        .service = "http",
        .version = "1.0",
        .source_id = "tcp-scan:service",
    });
    defer address_service.deinit();
    try graph.addObservation(address_service);
    var hostname_only = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .observed,
        .hostname = "camera.local",
        .source_id = "pcap:mdns",
    });
    defer hostname_only.deinit();
    try graph.addObservation(hostname_only);
    var hostname_service = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .service,
        .confidence = .confirmed,
        .hostname = "camera.local",
        .transport = "tcp",
        .port = 80,
        .service = "http",
        .version = "2.0",
        .source_id = "nmap:service",
    });
    defer hostname_service.deinit();
    try graph.addObservation(hostname_service);
    try std.testing.expectEqual(@as(usize, 2), graph.assets.items.len);

    var bridge = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .confirmed,
        .address = "192.0.2.20",
        .hostname = "CAMERA.local.",
        .source_id = "nmap:host",
    });
    defer bridge.deinit();
    try graph.addObservation(bridge);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items.len);
    try std.testing.expectEqualStrings("camera.local", graph.assets.items[0].preferredName());
    try std.testing.expectEqual(network.Confidence.confirmed, graph.assets.items[0].identities.items[0].confidence);
    try std.testing.expectEqual(network.Confidence.confirmed, graph.assets.items[0].identities.items[1].confidence);
    try std.testing.expectEqual(@as(usize, 3), graph.assets.items[0].identities.items[0].sources.items.len);
    try std.testing.expectEqual(@as(usize, 3), graph.assets.items[0].identities.items[1].sources.items.len);
    try std.testing.expectEqual(@as(usize, 2), graph.assets.items[0].endpoints.items.len);
    try std.testing.expectEqualStrings("1.0", graph.assets.items[0].endpoints.items[0].version);
    try std.testing.expectEqualStrings("2.0", graph.assets.items[0].endpoints.items[1].version);
    try std.testing.expectEqual(network.Confidence.observed, graph.assets.items[0].endpoints.items[0].version_confidence.?);
    try std.testing.expectEqual(network.Confidence.confirmed, graph.assets.items[0].endpoints.items[1].version_confidence.?);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items[0].sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items[1].sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items[0].version_sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items[1].version_sources.items.len);
}

test "asset graph keeps endpoint and version evidence independent" {
    var graph = AssetGraph.init(std.testing.allocator);
    defer graph.deinit();

    var observed_v1 = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .service,
        .confidence = .observed,
        .hostname = "service.example",
        .transport = "tcp",
        .port = 443,
        .service = "https",
        .version = "1.0",
        .source_id = "source-v1",
    });
    defer observed_v1.deinit();
    try graph.addObservation(observed_v1);

    var confirmed_without_version = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .service,
        .confidence = .confirmed,
        .hostname = "service.example",
        .transport = "tcp",
        .port = 443,
        .service = "https",
        .source_id = "source-endpoint",
    });
    defer confirmed_without_version.deinit();
    try graph.addObservation(confirmed_without_version);

    var confirmed_v2 = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .service,
        .confidence = .confirmed,
        .hostname = "service.example",
        .transport = "tcp",
        .port = 443,
        .service = "https",
        .version = "2.0",
        .source_id = "source-v2",
    });
    defer confirmed_v2.deinit();
    try graph.addObservation(confirmed_v2);

    try std.testing.expectEqual(@as(usize, 1), graph.assets.items.len);
    try std.testing.expectEqual(@as(usize, 2), graph.assets.items[0].endpoints.items.len);
    try std.testing.expectEqualStrings("1.0", graph.assets.items[0].endpoints.items[0].version);
    try std.testing.expectEqualStrings("2.0", graph.assets.items[0].endpoints.items[1].version);
    try std.testing.expectEqual(network.Confidence.confirmed, graph.assets.items[0].endpoints.items[0].confidence);
    try std.testing.expectEqual(network.Confidence.observed, graph.assets.items[0].endpoints.items[0].version_confidence.?);
    try std.testing.expectEqual(network.Confidence.confirmed, graph.assets.items[0].endpoints.items[1].version_confidence.?);
    try std.testing.expectEqual(@as(usize, 2), graph.assets.items[0].endpoints.items[0].sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items[1].sources.items.len);
    try std.testing.expectEqualStrings("source-v1", graph.assets.items[0].endpoints.items[0].sources.items[0]);
    try std.testing.expectEqualStrings("source-v2", graph.assets.items[0].endpoints.items[1].sources.items[0]);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items[0].version_sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].endpoints.items[1].version_sources.items.len);
    try std.testing.expectEqualStrings("source-v1", graph.assets.items[0].endpoints.items[0].version_sources.items[0]);
    try std.testing.expectEqualStrings("source-v2", graph.assets.items[0].endpoints.items[1].version_sources.items[0]);
}

test "preferred asset name uses the strongest identity evidence" {
    var graph = AssetGraph.init(std.testing.allocator);
    defer graph.deinit();

    var confirmed_address = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .confirmed,
        .address = "192.0.2.40",
        .source_id = "confirmed-address",
    });
    defer confirmed_address.deinit();
    try graph.addObservation(confirmed_address);

    var weak_hostname = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .inferred,
        .address = "192.0.2.40",
        .hostname = "possible-name.local",
        .source_id = "weak-hostname",
    });
    defer weak_hostname.deinit();
    try graph.addObservation(weak_hostname);

    const asset = graph.assets.items[0];
    try std.testing.expectEqualStrings("192.0.2.40", asset.preferredName());
    try std.testing.expectEqual(network.Confidence.confirmed, asset.identities.items[0].confidence);
    try std.testing.expectEqual(network.Confidence.inferred, asset.identities.items[1].confidence);
    try std.testing.expectEqual(@as(usize, 2), asset.identities.items[0].sources.items.len);
    try std.testing.expectEqual(@as(usize, 1), asset.identities.items[1].sources.items.len);
    try std.testing.expectEqualStrings("weak-hostname", asset.identities.items[1].sources.items[0]);
}

test "name queries do not alias requester and queried host" {
    var graph = AssetGraph.init(std.testing.allocator);
    defer graph.deinit();
    var query = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .name_query,
        .confidence = .observed,
        .address = "192.0.2.30",
        .hostname = "server.local",
        .source_id = "pcap:mdns:query",
    });
    defer query.deinit();
    try graph.addObservation(query);

    try std.testing.expectEqual(@as(usize, 1), graph.assets.items.len);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items[0].identities.items.len);
    try std.testing.expectEqual(IdentityKind.address, graph.assets.items[0].identities.items[0].kind);
}

test "asset graph canonicalizes equivalent IPv6 text" {
    var graph = AssetGraph.init(std.testing.allocator);
    defer graph.deinit();
    var first = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .observed,
        .address = "2001:0db8:0:0:0:0:0:1",
        .source_id = "one",
    });
    defer first.deinit();
    try graph.addObservation(first);
    var second = try network.NetworkObservation.init(std.testing.allocator, .{
        .kind = .host,
        .confidence = .observed,
        .address = "2001:db8::1",
        .source_id = "two",
    });
    defer second.deinit();
    try graph.addObservation(second);
    try std.testing.expectEqual(@as(usize, 1), graph.assets.items.len);
}
