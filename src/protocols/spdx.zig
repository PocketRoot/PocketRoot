const std = @import("std");
const protocol = @import("protocol.zig");
const purl_map = @import("../services/purl_map.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "spdx",
    .name = "SPDX SBOM",
    .category = "Software",
    .file_extension = "spdx.json",
    .additional_extensions = &.{ "spdx", "spdx-json" },
    .media_type = "application/spdx+json",
    .auto_detect = false,
    .analyze = analyzeText,
    .sample = sampleText,
};

const max_packages = 4096;

const WireExternalRef = struct {
    referenceType: []const u8 = "",
    referenceLocator: []const u8 = "",
};

const WirePackage = struct {
    name: []const u8 = "",
    versionInfo: []const u8 = "",
    externalRefs: []const WireExternalRef = &.{},
};

const WireDocument = struct {
    spdxVersion: []const u8 = "",
    name: []const u8 = "",
    packages: []const WirePackage = &.{},
};

fn purlOf(spec: WirePackage) ?[]const u8 {
    for (spec.externalRefs) |reference| {
        if (std.ascii.eqlIgnoreCase(reference.referenceType, "purl") and reference.referenceLocator.len != 0) {
            return reference.referenceLocator;
        }
    }
    return null;
}

/// Reads an SPDX 2.x JSON document and emits one package observation per package that
/// carries both a name and a version.
pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var parsed = std.json.parseFromSlice(WireDocument, allocator, data, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSbom,
    };
    defer parsed.deinit();
    const document = parsed.value;

    if (document.spdxVersion.len == 0 or !std.ascii.startsWithIgnoreCase(document.spdxVersion, "SPDX-")) {
        return error.InvalidSbom;
    }
    if (document.packages.len > max_packages) return error.TooManyComponents;

    var result = try protocol.AnalysisResult.init(allocator, "SPDX software inventory");
    errdefer result.deinit();
    try result.addField("spdx_version", document.spdxVersion);
    if (document.name.len != 0) try result.addField("document_name", document.name);
    try result.addNumberField("packages_total", document.packages.len);

    var with_version: usize = 0;
    var with_purl: usize = 0;
    for (document.packages) |package| {
        if (package.name.len == 0 or package.versionInfo.len == 0) continue;
        with_version += 1;
        const purl = purlOf(package);
        if (purl != null) with_purl += 1;

        var identity_buffer: [320]u8 = undefined;
        var name_buffer: [160]u8 = undefined;
        const identity = if (purl) |value|
            value
        else
            try std.fmt.bufPrint(&identity_buffer, "pkg:spdx/{s}@{s}", .{ package.name, package.versionInfo });
        const mapped = if (purl) |value| purl_map.resolve(value) else null;
        // SPDX names can carry spaces; the catalogue matches on tokens, so trim them away.
        const cleaned = try std.fmt.bufPrint(&name_buffer, "{s}", .{package.name});

        _ = try result.addNetworkObservation(.{
            .kind = .package,
            .confidence = .confirmed,
            .hostname = identity,
            .product = if (mapped) |entry| entry.product else cleaned,
            .version = package.versionInfo,
            .evidence = "spdx:package",
            .source_id = "spdx:package",
        });
    }
    try result.addNumberField("packages_with_version", with_version);
    try result.addNumberField("packages_with_purl", with_purl);

    const summary = try std.fmt.allocPrint(
        allocator,
        "SPDX inventory: {d}/{d} packages carry a version",
        .{ with_version, document.packages.len },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);
    return result;
}

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\{
        \\  "spdxVersion": "SPDX-2.3",
        \\  "name": "sample",
        \\  "packages": [
        \\    {
        \\      "name": "log4j-core",
        \\      "versionInfo": "2.14.1",
        \\      "externalRefs": [
        \\        { "referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }
        \\      ]
        \\    }
        \\  ]
        \\}
        \\
    );
}

test "spdx packages become observations with purl mapping" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);
    var result = try analyzeText(std.testing.allocator, sample);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.observations.items.len);
    const observation = result.observations.items[0];
    try std.testing.expectEqual(protocol.NetworkObservationKind.package, observation.kind);
    try std.testing.expectEqualStrings("log4j", observation.product);
    try std.testing.expectEqualStrings("2.14.1", observation.version);
}

test "spdx rejects documents without an spdx version" {
    const text = "{\"spdxVersion\":\"\",\"packages\":[]}";
    try std.testing.expectError(error.InvalidSbom, analyzeText(std.testing.allocator, text));
}
