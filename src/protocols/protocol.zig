const std = @import("std");
const network_observation = @import("../core/network_observation.zig");

pub const NetworkObservation = network_observation.NetworkObservation;
pub const NetworkObservationSpec = network_observation.Spec;
pub const NetworkObservationKind = network_observation.Kind;
pub const ObservationConfidence = network_observation.Confidence;

pub const max_summary_bytes = 4 * 1024;
pub const max_fields = 512;
pub const max_field_name_bytes = 256;
pub const max_field_value_bytes = 4 * 1024;
pub const max_findings = 256;
pub const max_finding_message_bytes = 1024;
pub const max_finding_detail_bytes = 8 * 1024;
pub const max_finding_target_bytes = 2 * 1024;
pub const max_finding_source_id_bytes = 512;
pub const max_observations = 1024;
pub const max_observation_address_bytes = 256;
pub const max_observation_hostname_bytes = 512;
pub const max_observation_transport_bytes = 32;
pub const max_observation_service_bytes = 256;
pub const max_observation_product_bytes = 256;
pub const max_observation_version_bytes = 256;
pub const max_observation_evidence_bytes = 4 * 1024;
pub const max_observation_source_id_bytes = 512;

pub const AnalysisField = struct {
    name: []u8,
    value: []u8,
};

pub const FindingSeverity = enum {
    info,
    warning,
    @"error",
    unknown,
    low,
    medium,
    high,
    critical,
};

pub const Finding = struct {
    severity: FindingSeverity,
    message: []u8,
    detail: []u8,
    target: []u8,
    source_id: []u8,
};

pub const AnalysisResult = struct {
    allocator: std.mem.Allocator,
    summary: []u8,
    fields: std.ArrayList(AnalysisField) = .empty,
    findings: std.ArrayList(Finding) = .empty,
    observations: std.ArrayList(NetworkObservation) = .empty,

    pub fn init(allocator: std.mem.Allocator, summary: []const u8) !AnalysisResult {
        if (summary.len > max_summary_bytes) return error.SummaryTooLong;
        return .{
            .allocator = allocator,
            .summary = try allocator.dupe(u8, summary),
        };
    }

    pub fn deinit(self: *AnalysisResult) void {
        self.allocator.free(self.summary);

        for (self.fields.items) |field| {
            self.allocator.free(field.name);
            self.allocator.free(field.value);
        }
        self.fields.deinit(self.allocator);

        for (self.findings.items) |finding| {
            self.allocator.free(finding.message);
            self.allocator.free(finding.detail);
            self.allocator.free(finding.target);
            self.allocator.free(finding.source_id);
        }
        self.findings.deinit(self.allocator);

        for (self.observations.items) |*observation| observation.deinit();
        self.observations.deinit(self.allocator);

        self.* = undefined;
    }

    pub fn setSummary(self: *AnalysisResult, summary: []const u8) !void {
        if (summary.len > max_summary_bytes) return error.SummaryTooLong;
        const owned_summary = try self.allocator.dupe(u8, summary);
        self.allocator.free(self.summary);
        self.summary = owned_summary;
    }

    pub fn addField(self: *AnalysisResult, name: []const u8, value: []const u8) !void {
        if (self.fields.items.len >= max_fields) return error.TooManyFields;
        if (name.len > max_field_name_bytes) return error.FieldNameTooLong;
        if (value.len > max_field_value_bytes) return error.FieldValueTooLong;

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        try self.fields.append(self.allocator, .{
            .name = owned_name,
            .value = owned_value,
        });
    }

    pub fn addNumberField(self: *AnalysisResult, name: []const u8, value: anytype) !void {
        var buffer: [64]u8 = undefined;
        try self.addField(name, try std.fmt.bufPrint(&buffer, "{d}", .{value}));
    }

    pub fn addFinding(self: *AnalysisResult, severity: FindingSeverity, message: []const u8) !void {
        try self.addDetailedFinding(severity, message, "", "", "");
    }

    pub fn addDetailedFinding(
        self: *AnalysisResult,
        severity: FindingSeverity,
        message: []const u8,
        detail: []const u8,
        target: []const u8,
        source_id: []const u8,
    ) !void {
        if (self.findings.items.len >= max_findings) return error.TooManyFindings;
        if (message.len > max_finding_message_bytes) return error.FindingMessageTooLong;
        if (detail.len > max_finding_detail_bytes) return error.FindingDetailTooLong;
        if (target.len > max_finding_target_bytes) return error.FindingTargetTooLong;
        if (source_id.len > max_finding_source_id_bytes) return error.FindingSourceIdTooLong;

        const owned_message = try self.allocator.dupe(u8, message);
        errdefer self.allocator.free(owned_message);

        const owned_detail = try self.allocator.dupe(u8, detail);
        errdefer self.allocator.free(owned_detail);

        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);

        const owned_source_id = try self.allocator.dupe(u8, source_id);
        errdefer self.allocator.free(owned_source_id);

        try self.findings.append(self.allocator, .{
            .severity = severity,
            .message = owned_message,
            .detail = owned_detail,
            .target = owned_target,
            .source_id = owned_source_id,
        });
    }

    pub fn addNetworkObservation(self: *AnalysisResult, spec: NetworkObservationSpec) !bool {
        if (spec.address.len > max_observation_address_bytes) return error.ObservationAddressTooLong;
        if (spec.hostname.len > max_observation_hostname_bytes) return error.ObservationHostnameTooLong;
        if (spec.transport.len > max_observation_transport_bytes) return error.ObservationTransportTooLong;
        if (spec.service.len > max_observation_service_bytes) return error.ObservationServiceTooLong;
        if (spec.product.len > max_observation_product_bytes) return error.ObservationProductTooLong;
        if (spec.version.len > max_observation_version_bytes) return error.ObservationVersionTooLong;
        if (spec.evidence.len > max_observation_evidence_bytes) return error.ObservationEvidenceTooLong;
        if (spec.source_id.len > max_observation_source_id_bytes) return error.ObservationSourceIdTooLong;

        var observation = try NetworkObservation.init(self.allocator, spec);
        errdefer observation.deinit();

        for (self.observations.items) |existing| {
            if (NetworkObservation.eql(existing, observation)) {
                observation.deinit();
                return false;
            }
        }
        if (self.observations.items.len >= max_observations) return error.TooManyObservations;
        try self.observations.append(self.allocator, observation);
        return true;
    }
};

pub const AnalyzeFn = *const fn (allocator: std.mem.Allocator, data: []const u8) anyerror!AnalysisResult;

/// Analysis parameters that cannot be derived from the bytes alone (firmware needs a
/// load address and architecture; captures will need snaplen later). Descriptors that
/// do not opt in keep using the parameter-less AnalyzeFn.
pub const AnalyzeOptions = struct {
    architecture: ?[]const u8 = null,
    base_address: u32 = 0,
};

pub const AnalyzeWithFn = *const fn (
    allocator: std.mem.Allocator,
    data: []const u8,
    options: AnalyzeOptions,
) anyerror!AnalysisResult;
pub const SampleFn = *const fn (allocator: std.mem.Allocator) anyerror![]u8;

pub const ProtocolDescriptor = struct {
    id: []const u8,
    name: []const u8,
    category: []const u8,
    file_extension: []const u8,
    additional_extensions: []const []const u8 = &.{},
    media_type: []const u8 = "application/octet-stream",
    auto_detect: bool = true,
    analyze: AnalyzeFn,
    /// Optional parameterised entry point. When present, run() prefers it.
    analyze_with: ?AnalyzeWithFn = null,
    sample: ?SampleFn = null,

    pub fn validatedCopy(
        self: ProtocolDescriptor,
        allocator: std.mem.Allocator,
        data: []const u8,
    ) ![]u8 {
        var analysis = try self.analyze(allocator, data);
        defer analysis.deinit();
        return allocator.dupe(u8, data);
    }

    /// Single entry point for callers: uses analyze_with when the descriptor opted in.
    pub fn run(
        self: ProtocolDescriptor,
        allocator: std.mem.Allocator,
        data: []const u8,
        options: AnalyzeOptions,
    ) !AnalysisResult {
        if (self.analyze_with) |analyze_with| return analyze_with(allocator, data, options);
        return self.analyze(allocator, data);
    }
};

test "analysis result owns fields and findings" {
    var result = try AnalysisResult.init(std.testing.allocator, "valid capture");
    defer result.deinit();

    try result.addField("protocol", "NEC");
    try result.addFinding(.warning, "timing is outside tolerance");

    try std.testing.expectEqualStrings("valid capture", result.summary);
    try std.testing.expectEqualStrings("protocol", result.fields.items[0].name);
    try std.testing.expectEqualStrings("NEC", result.fields.items[0].value);
    try std.testing.expectEqual(FindingSeverity.warning, result.findings.items[0].severity);
    try std.testing.expectEqualStrings("timing is outside tolerance", result.findings.items[0].message);
}

test "analysis result owns detailed findings" {
    var result = try AnalysisResult.init(std.testing.allocator, "scan results");
    defer result.deinit();

    try result.addDetailedFinding(
        .critical,
        "default credentials accepted",
        "The service accepted a documented vendor password.",
        "192.0.2.10:22",
        "nmap:ssh-auth",
    );

    const finding = result.findings.items[0];
    try std.testing.expectEqual(FindingSeverity.critical, finding.severity);
    try std.testing.expectEqualStrings("default credentials accepted", finding.message);
    try std.testing.expectEqualStrings("The service accepted a documented vendor password.", finding.detail);
    try std.testing.expectEqualStrings("192.0.2.10:22", finding.target);
    try std.testing.expectEqualStrings("nmap:ssh-auth", finding.source_id);
}

test "analysis result owns and deduplicates network observations" {
    var result = try AnalysisResult.init(std.testing.allocator, "network");
    defer result.deinit();

    const spec = NetworkObservationSpec{
        .kind = .service,
        .confidence = .confirmed,
        .address = "192.0.2.10",
        .transport = "tcp",
        .port = 22,
        .service = "ssh",
        .source_id = "test",
    };
    try std.testing.expect(try result.addNetworkObservation(spec));
    try std.testing.expect(!try result.addNetworkObservation(spec));
    try std.testing.expectEqual(@as(usize, 1), result.observations.items.len);
}

test "analysis result enforces summary limits and owns replacements" {
    const too_long = [_]u8{'x'} ** (max_summary_bytes + 1);
    try std.testing.expectError(error.SummaryTooLong, AnalysisResult.init(std.testing.allocator, &too_long));

    var result = try AnalysisResult.init(std.testing.allocator, "original");
    defer result.deinit();

    var replacement = [_]u8{ 'o', 'w', 'n', 'e', 'd' };
    try result.setSummary(&replacement);
    replacement[0] = 'x';
    try std.testing.expectEqualStrings("owned", result.summary);
    try std.testing.expectError(error.SummaryTooLong, result.setSummary(&too_long));
    try std.testing.expectEqualStrings("owned", result.summary);
}

test "analysis result enforces field limits" {
    var result = try AnalysisResult.init(std.testing.allocator, "fields");
    defer result.deinit();

    const long_name = [_]u8{'n'} ** (max_field_name_bytes + 1);
    const long_value = [_]u8{'v'} ** (max_field_value_bytes + 1);
    try std.testing.expectError(error.FieldNameTooLong, result.addField(&long_name, "value"));
    try std.testing.expectError(error.FieldValueTooLong, result.addField("name", &long_value));

    for (0..max_fields) |_| try result.addField("name", "value");
    try std.testing.expectError(error.TooManyFields, result.addField("name", "value"));
}

test "analysis result enforces finding limits" {
    var result = try AnalysisResult.init(std.testing.allocator, "findings");
    defer result.deinit();

    const long_message = [_]u8{'m'} ** (max_finding_message_bytes + 1);
    const long_detail = [_]u8{'d'} ** (max_finding_detail_bytes + 1);
    const long_target = [_]u8{'t'} ** (max_finding_target_bytes + 1);
    const long_source_id = [_]u8{'s'} ** (max_finding_source_id_bytes + 1);
    try std.testing.expectError(error.FindingMessageTooLong, result.addDetailedFinding(.warning, &long_message, "", "", ""));
    try std.testing.expectError(error.FindingDetailTooLong, result.addDetailedFinding(.warning, "message", &long_detail, "", ""));
    try std.testing.expectError(error.FindingTargetTooLong, result.addDetailedFinding(.warning, "message", "", &long_target, ""));
    try std.testing.expectError(error.FindingSourceIdTooLong, result.addDetailedFinding(.warning, "message", "", "", &long_source_id));

    for (0..max_findings) |_| try result.addFinding(.info, "message");
    try std.testing.expectError(error.TooManyFindings, result.addFinding(.info, "message"));
}

test "analysis result enforces observation limits" {
    var result = try AnalysisResult.init(std.testing.allocator, "observations");
    defer result.deinit();

    const long_address = [_]u8{'a'} ** (max_observation_address_bytes + 1);
    const long_hostname = [_]u8{'h'} ** (max_observation_hostname_bytes + 1);
    const long_transport = [_]u8{'t'} ** (max_observation_transport_bytes + 1);
    const long_service = [_]u8{'s'} ** (max_observation_service_bytes + 1);
    const long_version = [_]u8{'v'} ** (max_observation_version_bytes + 1);
    const long_evidence = [_]u8{'e'} ** (max_observation_evidence_bytes + 1);
    const long_source_id = [_]u8{'i'} ** (max_observation_source_id_bytes + 1);
    try std.testing.expectError(error.ObservationAddressTooLong, result.addNetworkObservation(.{ .kind = .host, .confidence = .observed, .address = &long_address }));
    try std.testing.expectError(error.ObservationHostnameTooLong, result.addNetworkObservation(.{ .kind = .host, .confidence = .observed, .hostname = &long_hostname }));
    try std.testing.expectError(error.ObservationTransportTooLong, result.addNetworkObservation(.{ .kind = .host, .confidence = .observed, .transport = &long_transport }));
    try std.testing.expectError(error.ObservationServiceTooLong, result.addNetworkObservation(.{ .kind = .host, .confidence = .observed, .service = &long_service }));
    try std.testing.expectError(error.ObservationVersionTooLong, result.addNetworkObservation(.{ .kind = .host, .confidence = .observed, .version = &long_version }));
    try std.testing.expectError(error.ObservationEvidenceTooLong, result.addNetworkObservation(.{ .kind = .host, .confidence = .observed, .evidence = &long_evidence }));
    try std.testing.expectError(error.ObservationSourceIdTooLong, result.addNetworkObservation(.{ .kind = .host, .confidence = .observed, .source_id = &long_source_id }));

    for (0..max_observations) |index| {
        try std.testing.expect(try result.addNetworkObservation(.{
            .kind = .endpoint,
            .confidence = .observed,
            .port = @as(u16, @intCast(index)),
        }));
    }
    try std.testing.expect(!try result.addNetworkObservation(.{
        .kind = .endpoint,
        .confidence = .observed,
        .port = 0,
    }));
    try std.testing.expectError(error.TooManyObservations, result.addNetworkObservation(.{
        .kind = .endpoint,
        .confidence = .observed,
        .port = @as(u16, @intCast(max_observations)),
    }));
}

test "analysis result owns all caller-provided text" {
    var summary = [_]u8{'s'};
    var result = try AnalysisResult.init(std.testing.allocator, &summary);
    defer result.deinit();

    var field_name = [_]u8{'n'};
    var field_value = [_]u8{'v'};
    var message = [_]u8{'m'};
    var detail = [_]u8{'d'};
    var target = [_]u8{'t'};
    var finding_source = [_]u8{'f'};
    var address = [_]u8{'a'};
    var hostname = [_]u8{'h'};
    var transport = [_]u8{'u'};
    var service = [_]u8{'r'};
    var version = [_]u8{'v'};
    var evidence = [_]u8{'e'};
    var observation_source = [_]u8{'o'};

    try result.addField(&field_name, &field_value);
    try result.addDetailedFinding(.info, &message, &detail, &target, &finding_source);
    try std.testing.expect(try result.addNetworkObservation(.{
        .kind = .service,
        .confidence = .confirmed,
        .address = &address,
        .hostname = &hostname,
        .transport = &transport,
        .service = &service,
        .version = &version,
        .evidence = &evidence,
        .source_id = &observation_source,
    }));

    summary[0] = 'x';
    field_name[0] = 'x';
    field_value[0] = 'x';
    message[0] = 'x';
    detail[0] = 'x';
    target[0] = 'x';
    finding_source[0] = 'x';
    address[0] = 'x';
    hostname[0] = 'x';
    transport[0] = 'x';
    service[0] = 'x';
    version[0] = 'x';
    evidence[0] = 'x';
    observation_source[0] = 'x';

    try std.testing.expectEqualStrings("s", result.summary);
    try std.testing.expectEqualStrings("n", result.fields.items[0].name);
    try std.testing.expectEqualStrings("v", result.fields.items[0].value);
    try std.testing.expectEqualStrings("m", result.findings.items[0].message);
    try std.testing.expectEqualStrings("d", result.findings.items[0].detail);
    try std.testing.expectEqualStrings("t", result.findings.items[0].target);
    try std.testing.expectEqualStrings("f", result.findings.items[0].source_id);
    try std.testing.expectEqualStrings("a", result.observations.items[0].address);
    try std.testing.expectEqualStrings("h", result.observations.items[0].hostname);
    try std.testing.expectEqualStrings("u", result.observations.items[0].transport);
    try std.testing.expectEqualStrings("r", result.observations.items[0].service);
    try std.testing.expectEqualStrings("v", result.observations.items[0].version);
    try std.testing.expectEqualStrings("e", result.observations.items[0].evidence);
    try std.testing.expectEqualStrings("o", result.observations.items[0].source_id);
}

test "descriptor run falls back to the parameter-less analyze" {
    const fake = struct {
        fn analyze(allocator: std.mem.Allocator, _: []const u8) !AnalysisResult {
            return AnalysisResult.init(allocator, "fallback");
        }
    }.analyze;
    const descriptor = ProtocolDescriptor{
        .id = "x",
        .name = "X",
        .category = "Test",
        .file_extension = "x",
        .analyze = fake,
    };
    var result = try descriptor.run(std.testing.allocator, "bytes", .{});
    defer result.deinit();
    try std.testing.expectEqualStrings("fallback", result.summary);
}
