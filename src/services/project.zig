const std = @import("std");
const artifact_mod = @import("../core/artifact.zig");
const protocol = @import("../protocols/protocol.zig");
const workbench = @import("workbench.zig");

pub const default_max_analyses = 256;
pub const default_max_issues = 256;

pub const ImportIssue = struct {
    path: []u8,
    message: []u8,
};

pub const Project = struct {
    allocator: std.mem.Allocator,
    analyses: std.ArrayList(workbench.Analysis) = .empty,
    duplicate_artifacts: usize = 0,
    skipped_files: usize = 0,
    issues: std.ArrayList(ImportIssue) = .empty,
    max_analyses: usize = default_max_analyses,
    max_issues: usize = default_max_issues,

    pub fn init(allocator: std.mem.Allocator) Project {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Project) void {
        for (self.analyses.items) |*analysis| analysis.deinit();
        self.analyses.deinit(self.allocator);

        for (self.issues.items) |issue| {
            self.allocator.free(issue.path);
            self.allocator.free(issue.message);
        }
        self.issues.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addAnalysis(self: *Project, analysis: workbench.Analysis) !bool {
        var owned = analysis;
        errdefer owned.deinit();

        for (self.analyses.items) |existing| {
            if (std.mem.eql(u8, existing.protocol.id, owned.protocol.id) and
                std.mem.eql(u8, existing.artifact.digest[0..], owned.artifact.digest[0..]))
            {
                self.duplicate_artifacts += 1;
                owned.deinit();
                return false;
            }
        }

        if (self.analyses.items.len == self.max_analyses) return error.TooManyProjectAnalyses;
        try self.analyses.append(self.allocator, owned);
        return true;
    }

    pub fn addIssue(self: *Project, path: []const u8, message: []const u8) !void {
        if (self.issues.items.len == self.max_issues) return error.TooManyProjectIssues;
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        const owned_message = try self.allocator.dupe(u8, message);
        errdefer self.allocator.free(owned_message);
        try self.issues.append(self.allocator, .{
            .path = owned_path,
            .message = owned_message,
        });
    }

    pub fn skipFile(self: *Project) void {
        self.skipped_files += 1;
    }

    pub fn findingIsFirst(
        self: *const Project,
        analysis_index: usize,
        finding_index: usize,
    ) bool {
        const candidate = self.analyses.items[analysis_index].result.findings.items[finding_index];

        // ponytail: O(n²) is fine for field reports; add a hash index at thousands of findings.
        for (self.analyses.items[0..analysis_index]) |analysis| {
            for (analysis.result.findings.items) |finding| {
                if (sameFinding(candidate, finding)) return false;
            }
        }
        for (self.analyses.items[analysis_index].result.findings.items[0..finding_index]) |finding| {
            if (sameFinding(candidate, finding)) return false;
        }
        return true;
    }

    pub fn uniqueFindingCount(self: *const Project) usize {
        var total: usize = 0;
        for (self.analyses.items, 0..) |analysis, analysis_index| {
            for (analysis.result.findings.items, 0..) |_, finding_index| {
                if (self.findingIsFirst(analysis_index, finding_index)) total += 1;
            }
        }
        return total;
    }

    pub fn duplicateFindingCount(self: *const Project) usize {
        var total: usize = 0;
        for (self.analyses.items) |analysis| {
            total += analysis.result.findings.items.len;
        }
        return total - self.uniqueFindingCount();
    }

    pub fn observationIsFirst(
        self: *const Project,
        analysis_index: usize,
        observation_index: usize,
    ) bool {
        const candidate = self.analyses.items[analysis_index].result.observations.items[observation_index];

        // ponytail: keep the borrowed O(n²) view until projects hold thousands of observations.
        for (self.analyses.items[0..analysis_index]) |analysis| {
            for (analysis.result.observations.items) |observation| {
                if (protocol.NetworkObservation.eql(candidate, observation)) return false;
            }
        }
        for (self.analyses.items[analysis_index].result.observations.items[0..observation_index]) |observation| {
            if (protocol.NetworkObservation.eql(candidate, observation)) return false;
        }
        return true;
    }

    pub fn uniqueObservationCount(self: *const Project) usize {
        var total: usize = 0;
        for (self.analyses.items, 0..) |analysis, analysis_index| {
            for (analysis.result.observations.items, 0..) |_, observation_index| {
                if (self.observationIsFirst(analysis_index, observation_index)) total += 1;
            }
        }
        return total;
    }

    pub fn duplicateObservationCount(self: *const Project) usize {
        var total: usize = 0;
        for (self.analyses.items) |analysis| total += analysis.result.observations.items.len;
        return total - self.uniqueObservationCount();
    }

    pub fn countSeverity(self: *const Project, severity: protocol.FindingSeverity) usize {
        var total: usize = 0;
        for (self.analyses.items, 0..) |analysis, analysis_index| {
            for (analysis.result.findings.items, 0..) |finding, finding_index| {
                if (finding.severity == severity and self.findingIsFirst(analysis_index, finding_index)) {
                    total += 1;
                }
            }
        }
        return total;
    }
};

fn sameFinding(left: protocol.Finding, right: protocol.Finding) bool {
    return left.severity == right.severity and
        std.mem.eql(u8, left.source_id, right.source_id) and
        std.mem.eql(u8, left.target, right.target) and
        std.mem.eql(u8, left.message, right.message);
}

fn unusedAnalyze(allocator: std.mem.Allocator, _: []const u8) !protocol.AnalysisResult {
    return protocol.AnalysisResult.init(allocator, "unused");
}

const test_descriptor_a = protocol.ProtocolDescriptor{
    .id = "test-a",
    .name = "Test A",
    .category = "Test",
    .file_extension = "a",
    .analyze = unusedAnalyze,
};

const test_descriptor_b = protocol.ProtocolDescriptor{
    .id = "test-b",
    .name = "Test B",
    .category = "Test",
    .file_extension = "b",
    .analyze = unusedAnalyze,
};

fn testAnalysis(
    allocator: std.mem.Allocator,
    descriptor: protocol.ProtocolDescriptor,
    path: []const u8,
    bytes: []const u8,
    finding_message: []const u8,
    target: []const u8,
) !workbench.Analysis {
    var artifact = try artifact_mod.Artifact.fromBytes(
        allocator,
        path,
        descriptor.media_type,
        .imported,
        bytes,
        null,
    );
    errdefer artifact.deinit();

    var result = try protocol.AnalysisResult.init(allocator, "test");
    errdefer result.deinit();
    if (finding_message.len != 0) {
        try result.addDetailedFinding(.medium, finding_message, "detail", target, "test-rule");
    }

    return .{
        .protocol = descriptor,
        .artifact = artifact,
        .result = result,
    };
}

test "project deduplicates artifacts per protocol" {
    var project = Project.init(std.testing.allocator);
    defer project.deinit();

    try std.testing.expect(try project.addAnalysis(try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "a.bin",
        "same",
        "",
        "",
    )));
    try std.testing.expect(!try project.addAnalysis(try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "copy.bin",
        "same",
        "",
        "",
    )));
    try std.testing.expect(try project.addAnalysis(try testAnalysis(
        std.testing.allocator,
        test_descriptor_b,
        "other.bin",
        "same",
        "",
        "",
    )));

    try std.testing.expectEqual(@as(usize, 2), project.analyses.items.len);
    try std.testing.expectEqual(@as(usize, 1), project.duplicate_artifacts);
}

test "project deduplicates findings" {
    var project = Project.init(std.testing.allocator);
    defer project.deinit();

    _ = try project.addAnalysis(try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "one.bin",
        "one",
        "Repeated issue",
        "example.test",
    ));
    _ = try project.addAnalysis(try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "two.bin",
        "two",
        "Repeated issue",
        "example.test",
    ));
    _ = try project.addAnalysis(try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "three.bin",
        "three",
        "Repeated issue",
        "other.test",
    ));

    try std.testing.expectEqual(@as(usize, 2), project.uniqueFindingCount());
    try std.testing.expectEqual(@as(usize, 1), project.duplicateFindingCount());
    try std.testing.expectEqual(@as(usize, 2), project.countSeverity(.medium));
}

test "project exposes an exact-deduplicated observation view" {
    var project = Project.init(std.testing.allocator);
    defer project.deinit();

    var first = try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "one.bin",
        "one",
        "",
        "",
    );
    _ = try first.result.addNetworkObservation(.{
        .kind = .service,
        .confidence = .confirmed,
        .address = "192.0.2.10",
        .transport = "tcp",
        .port = 22,
        .service = "ssh",
        .evidence = "SSH-2.0",
        .source_id = "test",
    });
    _ = try project.addAnalysis(first);

    var second = try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "two.bin",
        "two",
        "",
        "",
    );
    _ = try second.result.addNetworkObservation(.{
        .kind = .service,
        .confidence = .confirmed,
        .address = "192.0.2.10",
        .transport = "tcp",
        .port = 22,
        .service = "ssh",
        .evidence = "SSH-2.0",
        .source_id = "test",
    });
    _ = try project.addAnalysis(second);

    var third = try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "three.bin",
        "three",
        "",
        "",
    );
    _ = try third.result.addNetworkObservation(.{
        .kind = .service,
        .confidence = .observed,
        .address = "192.0.2.10",
        .transport = "tcp",
        .port = 22,
        .service = "ssh",
        .source_id = "other-source",
    });
    _ = try project.addAnalysis(third);

    try std.testing.expectEqual(@as(usize, 2), project.uniqueObservationCount());
    try std.testing.expectEqual(@as(usize, 1), project.duplicateObservationCount());
}

test "project records skipped files and import issues" {
    var project = Project.init(std.testing.allocator);
    defer project.deinit();

    project.skipFile();
    try project.addIssue("bad.xml", "MalformedXml");

    try std.testing.expectEqual(@as(usize, 1), project.skipped_files);
    try std.testing.expectEqual(@as(usize, 1), project.issues.items.len);
    try std.testing.expectEqualStrings("bad.xml", project.issues.items[0].path);
    try std.testing.expectEqualStrings("MalformedXml", project.issues.items[0].message);
}

test "project analysis and issue counts are bounded" {
    var project = Project.init(std.testing.allocator);
    defer project.deinit();
    project.max_analyses = 1;
    project.max_issues = 1;

    _ = try project.addAnalysis(try testAnalysis(
        std.testing.allocator,
        test_descriptor_a,
        "one.bin",
        "one",
        "",
        "",
    ));
    try std.testing.expectError(
        error.TooManyProjectAnalyses,
        project.addAnalysis(try testAnalysis(
            std.testing.allocator,
            test_descriptor_a,
            "two.bin",
            "two",
            "",
            "",
        )),
    );

    try project.addIssue("one", "one");
    try std.testing.expectError(error.TooManyProjectIssues, project.addIssue("two", "two"));
}
