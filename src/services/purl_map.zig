const std = @import("std");

/// Maps a purl namespace to the catalogue product it belongs to.
///
/// Package managers name artefacts, not products: "log4j-core" and "log4j-api" are both
/// the product log4j. A namespace entry makes that mapping deterministic instead of
/// relying on the leading-token heuristic.
pub const Entry = struct {
    /// Prefix of the purl, including the trailing slash of the namespace.
    prefix: []const u8,
    vendor: []const u8,
    product: []const u8,
};

pub const entries = [_]Entry{
    .{ .prefix = "pkg:maven/org.apache.logging.log4j/", .vendor = "apache", .product = "log4j" },
    .{ .prefix = "pkg:maven/org.apache.tomcat/", .vendor = "apache", .product = "tomcat" },
    .{ .prefix = "pkg:maven/org.apache.tomcat.embed/", .vendor = "apache", .product = "tomcat" },
    .{ .prefix = "pkg:maven/org.apache.struts/", .vendor = "apache", .product = "struts" },
    .{ .prefix = "pkg:maven/org.jenkins-ci.main/", .vendor = "jenkins", .product = "jenkins" },
    .{ .prefix = "pkg:pypi/django/", .vendor = "djangoproject", .product = "django" },
    .{ .prefix = "pkg:pypi/flask/", .vendor = "palletsprojects", .product = "flask" },
};

/// Returns the catalogue product for a purl, if the namespace is known.
pub fn resolve(purl: []const u8) ?Entry {
    for (entries) |entry| {
        if (purl.len < entry.prefix.len) continue;
        if (std.ascii.eqlIgnoreCase(purl[0..entry.prefix.len], entry.prefix)) return entry;
    }
    return null;
}

test "known namespaces map to their product" {
    const entry = resolve("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("log4j", entry.product);
    try std.testing.expectEqualStrings("apache", entry.vendor);
}

test "unknown namespaces stay unresolved" {
    try std.testing.expect(resolve("pkg:npm/express@4.18.2") == null);
    try std.testing.expect(resolve("") == null);
}
