const std = @import("std");

/// Recorded observations captured while reproducing catalogue entries in the lab.
///
/// The targets are synthetic names: a script cannot silently depend on a real host, and
/// the values are the exact product and version strings the reproduction recorded.
pub const Fixture = struct {
    target: []const u8,
    response: []const u8,
};

pub const builtin = [_]Fixture{
    .{
        .target = "lab-apache-249.lan:18080",
        .response =
        \\host=lab-apache-249.lan
        \\port=18080
        \\product=Apache httpd
        \\version=2.4.49
        \\banner=Apache/2.4.49 (Unix) OpenSSL/1.1.1
        ,
    },
    .{
        .target = "lab-apache-250.lan:18082",
        .response =
        \\host=lab-apache-250.lan
        \\port=18082
        \\product=Apache httpd
        \\version=2.4.50
        \\banner=Apache/2.4.50 (Unix) OpenSSL/1.1.1
        ,
    },
    .{
        .target = "lab-apache-251.lan:18084",
        .response =
        \\host=lab-apache-251.lan
        \\port=18084
        \\product=Apache httpd
        \\version=2.4.51
        \\banner=Apache/2.4.51 (Unix) OpenSSL/1.1.1
        ,
    },
    .{
        .target = "lab-apache-267.lan:18086",
        .response =
        \\host=lab-apache-267.lan
        \\port=18086
        \\product=Apache httpd
        \\version=2.4.67
        \\banner=Apache/2.4.67 (Unix) OpenSSL/3.0.13
        ,
    },
    .{
        .target = "lab-redis-725.lan:6379",
        .response =
        \\host=lab-redis-725.lan
        \\port=6379
        \\product=Redis
        \\version=7.2.5
        \\banner=redis_version:7.2.5
        ,
    },
    .{
        .target = "lab-redis-726.lan:6379",
        .response =
        \\host=lab-redis-726.lan
        \\port=6379
        \\product=Redis
        \\version=7.2.6
        \\banner=redis_version:7.2.6
        ,
    },
};

/// Returns the recorded observation whose target occurs in the request payload.
pub fn lookup(payload: []const u8) ?*const Fixture {
    for (&builtin) |*fixture| {
        if (std.mem.indexOf(u8, payload, fixture.target) != null) return fixture;
    }
    return null;
}

test "fixture lookup resolves a recorded host" {
    const fixture = lookup("target=lab-apache-249.lan:18080") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, fixture.response, "version=2.4.49") != null);
}

test "fixture lookup ignores unknown targets" {
    try std.testing.expect(lookup("target=unknown.lan:1") == null);
}
