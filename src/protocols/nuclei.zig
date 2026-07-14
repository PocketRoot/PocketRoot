const std = @import("std");
const protocol = @import("protocol.zig");

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "nuclei",
    .name = "Nuclei Results",
    .category = "Network",
    .file_extension = "jsonl",
    .media_type = "application/x-ndjson",
    .auto_detect = false,
    .analyze = analyzeText,
    .sample = sampleText,
};

const Stats = struct {
    lines: usize = 0,
    records: usize = 0,
    invalid_records: usize = 0,
    unknown_count: usize = 0,
    info_count: usize = 0,
    low_count: usize = 0,
    medium_count: usize = 0,
    high_count: usize = 0,
    critical_count: usize = 0,

    fn countSeverity(self: *Stats, severity: protocol.FindingSeverity) void {
        switch (severity) {
            .info => self.info_count += 1,
            .low => self.low_count += 1,
            .medium => self.medium_count += 1,
            .high => self.high_count += 1,
            .critical => self.critical_count += 1,
            else => self.unknown_count += 1,
        }
    }
};

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8,
        \\{"template-id":"http-missing-security-headers","info":{"name":"Missing security headers","severity":"medium","description":"One or more recommended HTTP response headers are absent."},"host":"https://example.test","matched-at":"https://example.test/","ip":"192.0.2.10","matcher-name":"headers"}
        \\
    );
}

/// Imports existing Nuclei JSONL output. It never launches or controls a scan.
pub fn analyzeText(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    var result = try protocol.AnalysisResult.init(allocator, "Nuclei JSONL results");
    errdefer result.deinit();

    var stats = Stats{};
    var lines = std.mem.splitScalar(u8, data, '\n');
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        stats.lines += 1;

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch |err| {
            stats.invalid_records += 1;
            const reason = try std.fmt.allocPrint(allocator, "invalid JSON: {s}", .{@errorName(err)});
            defer allocator.free(reason);
            try warnInvalid(&result, line_number, reason);
            continue;
        };
        defer parsed.deinit();

        const object = switch (parsed.value) {
            .object => |object| object,
            else => {
                stats.invalid_records += 1;
                try warnInvalid(&result, line_number, "root value must be an object");
                continue;
            },
        };

        const template_id = stringField(&object, "template-id") orelse stringField(&object, "templateID") orelse {
            stats.invalid_records += 1;
            try warnInvalid(&result, line_number, "missing string field template-id/templateID");
            continue;
        };
        const info_value = object.get("info") orelse {
            stats.invalid_records += 1;
            try warnInvalid(&result, line_number, "missing object field info");
            continue;
        };
        const info = switch (info_value) {
            .object => |info| info,
            else => {
                stats.invalid_records += 1;
                try warnInvalid(&result, line_number, "field info must be an object");
                continue;
            },
        };
        const name = stringField(&info, "name") orelse {
            stats.invalid_records += 1;
            try warnInvalid(&result, line_number, "missing string field info.name");
            continue;
        };
        const severity_text = stringField(&info, "severity") orelse {
            stats.invalid_records += 1;
            try warnInvalid(&result, line_number, "missing string field info.severity");
            continue;
        };

        const host = stringField(&object, "host") orelse "";
        const matched_at = stringField(&object, "matched-at") orelse "";
        const ip = stringField(&object, "ip") orelse "";
        const target = if (matched_at.len != 0) matched_at else if (host.len != 0) host else ip;
        if (target.len == 0) {
            stats.invalid_records += 1;
            try warnInvalid(&result, line_number, "missing target field matched-at/host/ip");
            continue;
        }

        const severity = parseSeverity(severity_text);
        const description = stringField(&info, "description") orelse "";
        const matcher_name = stringField(&object, "matcher-name") orelse "";
        const detail = try std.fmt.allocPrint(
            allocator,
            "{s}{s}Matcher: {s}\nHost: {s}\nIP: {s}",
            .{ description, if (description.len == 0) "" else "\n", matcher_name, host, ip },
        );
        defer allocator.free(detail);

        try result.addDetailedFinding(severity, name, detail, target, template_id);
        stats.records += 1;
        stats.countSeverity(severity);
    }

    const summary = try std.fmt.allocPrint(
        allocator,
        "Nuclei JSONL: {d} record{s} from {d} line{s}, {d} invalid; unknown={d}, info={d}, low={d}, medium={d}, high={d}, critical={d}",
        .{
            stats.records,
            if (stats.records == 1) "" else "s",
            stats.lines,
            if (stats.lines == 1) "" else "s",
            stats.invalid_records,
            stats.unknown_count,
            stats.info_count,
            stats.low_count,
            stats.medium_count,
            stats.high_count,
            stats.critical_count,
        },
    );
    defer allocator.free(summary);
    try result.setSummary(summary);

    try result.addNumberField("lines", stats.lines);
    try result.addNumberField("records", stats.records);
    try result.addNumberField("invalid_records", stats.invalid_records);
    try result.addNumberField("unknown_count", stats.unknown_count);
    try result.addNumberField("info_count", stats.info_count);
    try result.addNumberField("low_count", stats.low_count);
    try result.addNumberField("medium_count", stats.medium_count);
    try result.addNumberField("high_count", stats.high_count);
    try result.addNumberField("critical_count", stats.critical_count);
    return result;
}

fn parseSeverity(value: []const u8) protocol.FindingSeverity {
    inline for (.{
        .{ "unknown", protocol.FindingSeverity.unknown },
        .{ "info", protocol.FindingSeverity.info },
        .{ "low", protocol.FindingSeverity.low },
        .{ "medium", protocol.FindingSeverity.medium },
        .{ "high", protocol.FindingSeverity.high },
        .{ "critical", protocol.FindingSeverity.critical },
    }) |entry| {
        if (std.ascii.eqlIgnoreCase(value, entry[0])) return entry[1];
    }
    return .unknown;
}

fn stringField(object: *const std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

fn warnInvalid(result: *protocol.AnalysisResult, line: usize, reason: []const u8) !void {
    const message = try std.fmt.allocPrint(result.allocator, "Line {d}: invalid Nuclei record", .{line});
    defer result.allocator.free(message);
    try result.addDetailedFinding(.warning, message, reason, "", "nuclei");
}

fn fieldValue(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

test "nuclei analyzes the sample without executing a scan" {
    const text = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(text);

    var result = try descriptor.analyze(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqualStrings("1", fieldValue(&result, "records").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "medium_count").?);
    try std.testing.expectEqual(@as(usize, 1), result.findings.items.len);
    try std.testing.expectEqual(protocol.FindingSeverity.medium, result.findings.items[0].severity);
    try std.testing.expectEqualStrings("https://example.test/", result.findings.items[0].target);
    try std.testing.expectEqualStrings("http-missing-security-headers", result.findings.items[0].source_id);
}

test "nuclei imports multiple records and continues after bad lines" {
    const text =
        \\{"template-id":"title","info":{"name":"HTTP title","severity":"info","description":"A title was detected."},"host":"https://one.test","matched-at":"https://one.test/","ip":"192.0.2.1","matcher-name":"title"}
        \\not json
        \\{"templateID":"cve-2099-0001","info":{"name":"Example issue","severity":"CRITICAL"},"host":"https://two.test"}
        \\{"template-id":"custom","info":{"name":"Custom result","severity":"experimental"},"ip":"192.0.2.3"}
        \\{"template-id":"missing-info","host":"https://bad.test"}
    ;

    var result = try analyzeText(std.testing.allocator, text);
    defer result.deinit();

    try std.testing.expectEqualStrings("5", fieldValue(&result, "lines").?);
    try std.testing.expectEqualStrings("3", fieldValue(&result, "records").?);
    try std.testing.expectEqualStrings("2", fieldValue(&result, "invalid_records").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "unknown_count").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "info_count").?);
    try std.testing.expectEqualStrings("1", fieldValue(&result, "critical_count").?);
    try std.testing.expectEqual(@as(usize, 5), result.findings.items.len);
    try std.testing.expectEqualStrings("cve-2099-0001", result.findings.items[2].source_id);
    try std.testing.expectEqual(protocol.FindingSeverity.unknown, result.findings.items[3].severity);
    try std.testing.expectEqual(protocol.FindingSeverity.warning, result.findings.items[4].severity);
}
