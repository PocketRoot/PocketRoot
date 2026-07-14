const std = @import("std");
const protocol = @import("../protocols/protocol.zig");
const tls_certificate = @import("../formats/tls_certificate.zig");
const tcp_scan = @import("tcp_scan.zig");

pub const max_target_bytes = 255;
pub const max_handshake_bytes = tls_certificate.max_handshake_bytes;

pub const Options = struct {
    timeout_ms: u32 = 750,
};

const CertificateOutcome = union(enum) {
    available: tls_certificate.Metadata,
    unavailable: []const u8,
};

const HostnameMatch = enum {
    yes,
    no,
    not_checked_ip_literal,
};

const CaTrust = union(enum) {
    trusted,
    untrusted: []const u8,
    unavailable: []const u8,
};

const HandshakeMetadata = struct {
    version: std.crypto.tls.ProtocolVersion,
    cipher: []const u8,
    certificate: CertificateOutcome,
    hostname_match: HostnameMatch,
    ca_trust: CaTrust,
};

const HandshakeOutcome = union(enum) {
    success: HandshakeMetadata,
    failure: anyerror,
};

const HandshakeEvent = union(enum) {
    handshake: HandshakeOutcome,
    timer: std.Io.Cancelable!void,
};

const HostResolveEvent = union(enum) {
    resolve: anyerror!std.Io.net.IpAddress,
    timer: std.Io.Cancelable!void,
};

pub fn inspect(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    port: u16,
    options: Options,
) !protocol.AnalysisResult {
    if (!validTarget(target)) return error.InvalidTarget;
    if (port == 0) return error.InvalidPort;
    if (options.timeout_ms < 50 or options.timeout_ms > 2000) return error.InvalidTimeout;

    const timeout: std.Io.Timeout = .{ .deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = std.Io.Duration.fromMilliseconds(options.timeout_ms),
        .clock = .awake,
    }) };
    var address = (if (isIpLiteral(target))
        tcp_scan.resolveWithTimeout(io, target, port, timeout)
    else
        resolveHostWithTimeout(io, target, port, timeout)) catch |err| switch (err) {
        error.Canceled, error.Timeout => return err,
        else => return error.InvalidTarget,
    };
    address.setPort(port);
    const stream = try tcp_scan.connectWithTimeout(io, &address, timeout);
    defer stream.close(io);

    const verify_hostname = !isIpLiteral(target);
    const outcome = try handshakeWithTimeout(allocator, io, stream, target, verify_hostname, timeout);
    return buildResult(allocator, target, port, verify_hostname, outcome);
}

fn performHandshake(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    target: []const u8,
    verify_hostname: bool,
) HandshakeOutcome {
    const now = std.Io.Timestamp.now(io, .real);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    const ca_unavailable_reason: ?[]const u8 = load: {
        ca_bundle.rescan(allocator, io, now) catch |err| switch (err) {
            error.Canceled => return .{ .failure = error.Canceled },
            else => break :load @errorName(err),
        };
        if (ca_bundle.bytes.items.len == 0) break :load "empty_system_ca_bundle";
        break :load null;
    };

    var socket_read_buffer: [0]u8 = .{};
    // Extra capacity prevents Reader.rebase from overwriting captured bytes; Limited remains the 64 KiB hard limit.
    var limited_read_buffer: [max_handshake_bytes + std.crypto.tls.Client.min_buffer_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &limited_read_buffer);
    var socket_write_buffer: [4096]u8 = undefined;
    var application_read_buffer: [1]u8 = undefined;
    var application_write_buffer: [1]u8 = undefined;
    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &entropy);
    io.random(&entropy);

    var key_log_buffer: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_log_buffer);
    var key_log_writer: std.Io.Writer = .fixed(&key_log_buffer);
    var key_log: std.crypto.tls.Client.SslKeyLog = .{
        .client_key_seq = 0,
        .server_key_seq = 0,
        .client_random = undefined,
        .writer = &key_log_writer,
    };

    var socket_reader = stream.reader(io, &socket_read_buffer);
    var limited_reader = socket_reader.interface.limited(.limited(max_handshake_bytes), &limited_read_buffer);
    var socket_writer = stream.writer(io, &socket_write_buffer);
    var hostname_match: HostnameMatch = if (verify_hostname) .yes else .not_checked_ip_literal;
    var client: ?std.crypto.tls.Client = std.crypto.tls.Client.init(
        &limited_reader.interface,
        &socket_writer.interface,
        .{
            .host = if (verify_hostname) .{ .explicit = target } else .no_verification,
            .ca = .no_verification,
            .read_buffer = &application_read_buffer,
            .write_buffer = &application_write_buffer,
            .entropy = &entropy,
            .realtime_now = now,
            .ssl_key_log = &key_log,
        },
    ) catch |err| client_error: {
        if (err == error.CertificateHostMismatch) {
            hostname_match = .no;
            break :client_error null;
        }
        if (limited_reader.remaining == .nothing) return .{ .failure = error.HandshakeByteLimitExceeded };
        return .{ .failure = switch (err) {
            error.ReadFailed => socket_reader.err orelse err,
            error.WriteFailed => socket_writer.err orelse err,
            else => err,
        } };
    };
    defer if (client) |*established| {
        std.crypto.secureZero(u8, std.mem.asBytes(&established.application_cipher));
    };

    const raw_records = limited_read_buffer[0..limited_reader.interface.end];
    const negotiated = tls_certificate.parseNegotiated(raw_records) catch |err| {
        if (client) |*established| return .{ .success = .{
            .version = established.tls_version,
            .cipher = @tagName(std.meta.activeTag(established.application_cipher)),
            .certificate = .{ .unavailable = @errorName(err) },
            .hostname_match = hostname_match,
            .ca_trust = if (ca_unavailable_reason) |reason|
                .{ .unavailable = reason }
            else
                .{ .unavailable = @errorName(err) },
        } };
        return .{ .failure = err };
    };
    var ca_trust: CaTrust = if (ca_unavailable_reason) |reason|
        .{ .unavailable = reason }
    else
        .{ .untrusted = "certificate_chain_unavailable" };
    const certificate: CertificateOutcome = certificate: {
        if (ca_unavailable_reason == null) {
            const verified = tls_certificate.extractVerified(
                raw_records,
                key_log_buffer[0..key_log_writer.end],
                negotiated,
                now.toSeconds(),
                &ca_bundle,
            ) catch |err| {
                ca_trust = .{ .unavailable = @errorName(err) };
                break :certificate .{ .unavailable = @errorName(err) };
            };
            ca_trust = switch (verified.trust) {
                .trusted => .trusted,
                .untrusted => |err| .{ .untrusted = @errorName(err) },
            };
            break :certificate .{ .available = verified.metadata };
        }
        const metadata = tls_certificate.extract(
            raw_records,
            key_log_buffer[0..key_log_writer.end],
            negotiated,
            now.toSeconds(),
        ) catch |err| break :certificate .{ .unavailable = @errorName(err) };
        break :certificate .{ .available = metadata };
    };

    return .{ .success = .{
        .version = negotiated.version,
        .cipher = @tagName(negotiated.cipher_suite),
        .certificate = certificate,
        .hostname_match = hostname_match,
        .ca_trust = ca_trust,
    } };
}

fn resolveHostWithTimeout(
    io: std.Io,
    target: []const u8,
    port: u16,
    timeout: std.Io.Timeout,
) !std.Io.net.IpAddress {
    var event_buffer: [2]HostResolveEvent = undefined;
    var select: std.Io.Select(HostResolveEvent) = .init(io, &event_buffer);
    defer select.cancelDiscard();

    try select.concurrent(.resolve, resolveHost, .{ io, target, port });
    try select.concurrent(.timer, std.Io.Timeout.sleep, .{ timeout, io });
    return switch (try select.await()) {
        .resolve => |result| try result,
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    };
}

fn resolveHost(io: std.Io, target: []const u8, port: u16) !std.Io.net.IpAddress {
    const host = try std.Io.net.HostName.init(target);
    var storage: [16]std.Io.net.HostName.LookupResult = undefined;
    var resolved: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&storage);
    try host.lookup(io, &resolved, .{ .port = port });

    // ponytail: one resolved address preserves the single-connection budget; add bounded fallback only if needed.
    var first_address: ?std.Io.net.IpAddress = null;
    while (resolved.getOneUncancelable(io)) |item| switch (item) {
        .address => |address| if (first_address == null) {
            first_address = address;
        },
        .canonical_name => {},
    } else |err| switch (err) {
        error.Closed => return first_address orelse error.NoAddressReturned,
    }
}

fn handshakeWithTimeout(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    target: []const u8,
    verify_hostname: bool,
    timeout: std.Io.Timeout,
) !HandshakeOutcome {
    var event_buffer: [2]HandshakeEvent = undefined;
    var select: std.Io.Select(HandshakeEvent) = .init(io, &event_buffer);
    defer select.cancelDiscard();

    try select.concurrent(.handshake, performHandshake, .{ allocator, io, stream, target, verify_hostname });
    try select.concurrent(.timer, std.Io.Timeout.sleep, .{ timeout, io });

    return switch (try select.await()) {
        .handshake => |outcome| switch (outcome) {
            .failure => |err| return err,
            else => outcome,
        },
        .timer => |result| {
            try result;
            return error.Timeout;
        },
    };
}

fn buildResult(
    allocator: std.mem.Allocator,
    target: []const u8,
    port: u16,
    verify_hostname: bool,
    outcome: HandshakeOutcome,
) !protocol.AnalysisResult {
    var result = try protocol.AnalysisResult.init(allocator, "TLS inspection");
    errdefer result.deinit();
    try result.addField("target", target);
    try result.addNumberField("port", port);
    try result.addNumberField("handshake_read_limit_bytes", max_handshake_bytes);
    const metadata = switch (outcome) {
        .success => |success| success,
        .failure => unreachable,
    };
    const version = versionText(metadata.version);
    try result.addField("tls_version", version);
    try result.addField("cipher_suite", metadata.cipher);
    try result.addField("hostname_match", @tagName(metadata.hostname_match));
    try result.addField("ca_trust", caTrustText(metadata.ca_trust));
    try result.addField("ca_trust_detail", caTrustDetail(metadata.ca_trust));
    try result.addField("handshake", if (metadata.hostname_match == .no) "certificate_hostname_mismatch" else "complete");
    switch (metadata.certificate) {
        .available => |certificate| {
            try result.addField("certificate_metadata", "available");
            try result.addField("certificate_common_name", if (certificate.commonName().len == 0) "none" else certificate.commonName());
            try result.addField("certificate_subject_der_content_sha256", &certificate.subject_hash);
            try result.addField("certificate_issuer_common_name", if (certificate.issuerCommonName().len == 0) "none" else certificate.issuerCommonName());
            try result.addField("certificate_issuer_der_content_sha256", &certificate.issuer_hash);
            try result.addField("certificate_leaf_sha256", &certificate.leaf_hash);
            try result.addField("certificate_san_summary", certificate.sanSummary());
            try result.addNumberField("certificate_not_before_unix", certificate.not_before);
            try result.addNumberField("certificate_not_after_unix", certificate.not_after);
            try result.addField("certificate_validity", @tagName(certificate.validity));
            try result.addNumberField("certificate_chain_count", certificate.chain_count);
        },
        .unavailable => |reason| try result.addField("certificate_metadata", reason),
    }

    var evidence_buffer: [256]u8 = undefined;
    const evidence = try std.fmt.bufPrint(
        &evidence_buffer,
        "{s} handshake completed with {s}; CA trust {s}; hostname {s}",
        .{ version, metadata.cipher, caTrustText(metadata.ca_trust), @tagName(metadata.hostname_match) },
    );
    if (metadata.hostname_match == .no) {
        var endpoint_buffer: [320]u8 = undefined;
        const endpoint = try formatEndpoint(&endpoint_buffer, target, port);
        try result.addDetailedFinding(
            .warning,
            "TLS certificate hostname mismatch",
            "The peer certificate does not identify the requested DNS name. CA trust is reported separately.",
            endpoint,
            "tls-inspect:hostname",
        );
    }
    switch (metadata.ca_trust) {
        .untrusted => |reason| {
            var endpoint_buffer: [320]u8 = undefined;
            const endpoint = try formatEndpoint(&endpoint_buffer, target, port);
            var detail_buffer: [256]u8 = undefined;
            const detail = try std.fmt.bufPrint(
                &detail_buffer,
                "The peer certificate chain was not validated by the system CA roots ({s}).",
                .{reason},
            );
            try result.addDetailedFinding(
                .warning,
                "TLS certificate chain not trusted",
                detail,
                endpoint,
                "tls-inspect:ca-trust",
            );
        },
        .trusted, .unavailable => {},
    }

    _ = try result.addNetworkObservation(.{
        .kind = .host,
        .confidence = .confirmed,
        .address = if (verify_hostname) "" else target,
        .hostname = if (verify_hostname) target else "",
        .evidence = evidence,
        .source_id = "tls-inspect:response",
    });
    _ = try result.addNetworkObservation(.{
        .kind = .endpoint,
        .confidence = .confirmed,
        .address = if (verify_hostname) "" else target,
        .hostname = if (verify_hostname) target else "",
        .transport = "tcp",
        .port = port,
        .evidence = evidence,
        .source_id = "tls-inspect:response",
    });
    _ = try result.addNetworkObservation(.{
        .kind = .service,
        .confidence = .confirmed,
        .address = if (verify_hostname) "" else target,
        .hostname = if (verify_hostname) target else "",
        .transport = "tcp",
        .port = port,
        .service = "tls",
        .version = version,
        .evidence = evidence,
        .source_id = "tls-inspect:response",
    });

    const summary = if (metadata.hostname_match == .no)
        try std.fmt.allocPrint(
            allocator,
            "TLS certificate hostname mismatch on {s}:{d}",
            .{ target, port },
        )
    else
        try std.fmt.allocPrint(allocator, "{s} on {s}:{d}", .{ version, target, port });
    defer allocator.free(summary);
    try result.setSummary(summary);
    return result;
}

fn validTarget(target: []const u8) bool {
    if (target.len == 0 or target.len > max_target_bytes) return false;
    for (target) |byte| if (byte == 0 or byte == '\r' or byte == '\n') return false;
    return true;
}

fn isIpLiteral(target: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(target, 0) catch return std.mem.indexOfScalar(u8, target, ':') != null;
    return true;
}

fn versionText(version: std.crypto.tls.ProtocolVersion) []const u8 {
    return switch (version) {
        .tls_1_2 => "TLS 1.2",
        .tls_1_3 => "TLS 1.3",
        else => "unknown TLS version",
    };
}

fn caTrustText(trust: CaTrust) []const u8 {
    return switch (trust) {
        .trusted => "trusted",
        .untrusted => "untrusted",
        .unavailable => "unavailable",
    };
}

fn caTrustDetail(trust: CaTrust) []const u8 {
    return switch (trust) {
        .trusted => "system_ca_bundle",
        .untrusted => |reason| reason,
        .unavailable => |reason| reason,
    };
}

fn formatEndpoint(buffer: *[320]u8, target: []const u8, port: u16) ![]const u8 {
    if (std.mem.indexOfScalar(u8, target, ':') != null) {
        return std.fmt.bufPrint(buffer, "[{s}]:{d}", .{ target, port });
    }
    return std.fmt.bufPrint(buffer, "{s}:{d}", .{ target, port });
}

test "TLS inspection validates bounds and metadata labels" {
    try std.testing.expectEqualStrings("TLS 1.2", versionText(.tls_1_2));
    try std.testing.expectEqualStrings("TLS 1.3", versionText(.tls_1_3));
    try std.testing.expect(isIpLiteral("127.0.0.1"));
    try std.testing.expect(isIpLiteral("fe80::1%3"));
    try std.testing.expect(!isIpLiteral("example.com"));

    try std.testing.expectError(
        error.InvalidTimeout,
        inspect(std.testing.allocator, std.testing.io, "127.0.0.1", 443, .{ .timeout_ms = 49 }),
    );
    try std.testing.expectError(
        error.InvalidPort,
        inspect(std.testing.allocator, std.testing.io, "127.0.0.1", 0, .{}),
    );
    try std.testing.expectError(
        error.InvalidTarget,
        inspect(std.testing.allocator, std.testing.io, "bad\nname", 443, .{}),
    );

    var result = try buildResult(std.testing.allocator, "example.com", 443, true, .{ .success = .{
        .version = .tls_1_3,
        .cipher = "AES_128_GCM_SHA256",
        .certificate = .{ .unavailable = "test_fixture_has_no_certificate" },
        .hostname_match = .yes,
        .ca_trust = .trusted,
    } });
    defer result.deinit();
    try std.testing.expectEqualStrings("TLS 1.3 on example.com:443", result.summary);
    try std.testing.expectEqual(@as(usize, 3), result.observations.items.len);
    try std.testing.expectEqualStrings("", result.observations.items[0].address);
    try std.testing.expectEqualStrings("example.com", result.observations.items[0].hostname);
    var saw_hostname_match = false;
    var saw_unavailable_metadata = false;
    for (result.fields.items) |field| {
        if (std.mem.eql(u8, field.name, "hostname_match")) {
            try std.testing.expectEqualStrings("yes", field.value);
            saw_hostname_match = true;
        } else if (std.mem.eql(u8, field.name, "certificate_metadata")) {
            try std.testing.expectEqualStrings("test_fixture_has_no_certificate", field.value);
            saw_unavailable_metadata = true;
        }
    }
    try std.testing.expect(saw_hostname_match);
    try std.testing.expect(saw_unavailable_metadata);
    try std.testing.expectEqualStrings("trusted", fieldValue(&result, "ca_trust").?);
    try std.testing.expectEqualStrings("system_ca_bundle", fieldValue(&result, "ca_trust_detail").?);
    try std.testing.expectEqualStrings("TLS 1.3", result.observations.items[2].version);

    var untrusted = try buildResult(std.testing.allocator, "example.com", 443, true, .{ .success = .{
        .version = .tls_1_2,
        .cipher = "AES_128_GCM_SHA256",
        .certificate = .{ .unavailable = "fixture" },
        .hostname_match = .yes,
        .ca_trust = .{ .untrusted = "CertificateIssuerNotFound" },
    } });
    defer untrusted.deinit();
    try std.testing.expectEqualStrings("untrusted", fieldValue(&untrusted, "ca_trust").?);
    try std.testing.expectEqual(@as(usize, 1), untrusted.findings.items.len);

    var unavailable = try buildResult(std.testing.allocator, "127.0.0.1", 443, false, .{ .success = .{
        .version = .tls_1_2,
        .cipher = "AES_128_GCM_SHA256",
        .certificate = .{ .unavailable = "fixture" },
        .hostname_match = .not_checked_ip_literal,
        .ca_trust = .{ .unavailable = "mock_system_ca_unavailable" },
    } });
    defer unavailable.deinit();
    try std.testing.expectEqualStrings("unavailable", fieldValue(&unavailable, "ca_trust").?);
    try std.testing.expectEqualStrings("mock_system_ca_unavailable", fieldValue(&unavailable, "ca_trust_detail").?);
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}
