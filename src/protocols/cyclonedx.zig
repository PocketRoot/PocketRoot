const std = @import("std");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "cyclonedx",
    .name = "CycloneDX SBOM",
    .category = "Software",
    .file_extension = "cdx.json",
    .additional_extensions = &.{ "bom.json", "cyclonedx.json" },
    .media_type = "application/vnd.cyclonedx+json",
    .auto_detect = false,
    .analyze = analyzeText,
    .sample = sampleText,
};

const max_components = 4096;

const WireComponent = struct {
    name: []const u8 = "",
    version: []const u8 = "",
    purl: []const u8 = "",
    group: []const u8 = "",
    type: []const u8 = "",
};

const WireBom = struct {
    bomFormat: []const u8 = "",
    specVersion: []const u8 = "",
    components: []const WireComponent = &.{},
};

/// Reads a CycloneDX JSON bill of materials and emits one package observation per
/// component that carries both a name and a version.
pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var parsed = std.json.parseFromSlice(WireBom, allocator, data, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidSbom,
    };
    defer parsed.deinit();
    const bom = parsed.value;

    if (bom.bomFormat.len != 0 and !std.ascii.eqlIgnoreCase(bom.bomFormat, "CycloneDX")) {
        return error.InvalidSbom;
    }
    if (bom.components.len > max_components) return error.TooManyComponents;

    var result = try protocol.AnalysisResult.init(allocator, "CycloneDX software inventory");
    errdefer result.deinit();
    try result.addField("bom_format", if (bom.bomFormat.len == 0) "CycloneDX" else bom.bomFormat);
    if (bom.specVersion.len != 0) try result.addField("spec_version", bom.specVersion);
    try result.addNumberField("components_total", bom.components.len);

    var with_version: usize = 0;
    var with_purl: usize = 0;
    for (bom.components) |component| {
        if (component.name.len == 0 or component.version.len == 0) continue;
        with_version += 1;
        const purl = if (component.purl.len != 0) component.purl else "";
        if (purl.len != 0) with_purl += 1;

        var identity_buffer: [320]u8 = undefined;
        const identity = if (purl.len != 0)
            purl
        else
            try std.fmt.bufPrint(&identity_buffer, "pkg:generic/{s}@{s}", .{ component.name, component.version });

        _ = try result.addNetworkObservation(.{
            .kind = .package,
            .confidence = .confirmed,
            .hostname = identity,
            .product = component.name,
            .version = component.version,
            .evidence = if (component.group.len != 0) component.group else "cyclonedx",
            .source_id = "cyclonedx:component",
        });
    }
    try result.addNumberField("components_with_version", with_version);
    try result.addNumberField("components_with_purl", with_purl);

    const summary = try std.fmt.allocPrint(
        allocator,
        "CycloneDX inventory: {d}/{d} components carry a version",
        .{ with_version, bom.components.len },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);
    return result;
}

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\{
        \\  "bomFormat": "CycloneDX",
        \\  "specVersion": "1.5",
        \\  "components": [
        \\    {
        \\      "type": "library",
        \\      "group": "org.apache.logging.log4j",
        \\      "name": "log4j-core",
        \\      "version": "2.14.1",
        \\      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        \\    }
        \\  ]
        \\}
    );
}

test "cyclonedx components become package observations" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);
    var result = try analyzeText(std.testing.allocator, sample);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.observations.items.len);
    const observation = result.observations.items[0];
    try std.testing.expectEqual(protocol.NetworkObservationKind.package, observation.kind);
    try std.testing.expectEqualStrings("log4j-core", observation.product);
    try std.testing.expectEqualStrings("2.14.1", observation.version);
    try std.testing.expect(std.mem.startsWith(u8, observation.hostname, "pkg:maven/"));
}

test "cyclonedx rejects documents that are not bills of materials" {
    const text = "{\"bomFormat\":\"SPDX\",\"components\":[]}";
    try std.testing.expectError(error.InvalidSbom, analyzeText(std.testing.allocator, text));
}
