const std = @import("std");
const artifact_mod = @import("../core/artifact.zig");
const protocol = @import("../protocols/protocol.zig");
const registry_mod = @import("../protocols/registry.zig");
const storage_mod = @import("storage.zig");

pub const Analysis = struct {
    protocol: protocol.ProtocolDescriptor,
    artifact: artifact_mod.Artifact,
    result: protocol.AnalysisResult,

    pub fn deinit(self: *Analysis) void {
        self.result.deinit();
        self.artifact.deinit();
    }
};

pub const ProtocolWorkbench = struct {
    allocator: std.mem.Allocator,
    storage: *storage_mod.StorageService,
    registry: *const registry_mod.ProtocolRegistry,

    pub fn init(
        allocator: std.mem.Allocator,
        storage: *storage_mod.StorageService,
        registry: *const registry_mod.ProtocolRegistry,
    ) ProtocolWorkbench {
        return .{
            .allocator = allocator,
            .storage = storage,
            .registry = registry,
        };
    }

    pub fn analyzePath(self: *ProtocolWorkbench, protocol_id: ?[]const u8, path: []const u8) !Analysis {
        const descriptor = if (protocol_id) |id|
            self.registry.find(id) orelse return error.UnknownProtocol
        else
            self.registry.inferFromPath(path) orelse return error.UnknownProtocol;

        const data = try self.storage.loadBytes(self.allocator, path);
        defer self.allocator.free(data);

        return self.analyzeBytes(descriptor, path, data);
    }

    pub fn analyzeBytes(
        self: *ProtocolWorkbench,
        descriptor: protocol.ProtocolDescriptor,
        path: []const u8,
        data: []const u8,
    ) !Analysis {
        var artifact = try artifact_mod.Artifact.fromBytes(
            self.allocator,
            path,
            descriptor.media_type,
            .imported,
            data,
            null,
        );
        errdefer artifact.deinit();

        var result = try descriptor.analyze(self.allocator, data);
        errdefer result.deinit();

        return .{
            .protocol = descriptor,
            .artifact = artifact,
            .result = result,
        };
    }
};

test "workbench analyzes infrared bytes" {
    var storage = storage_mod.StorageService.init(std.testing.io);
    const registry = registry_mod.ProtocolRegistry.init(registry_mod.builtinProtocols());
    var workbench = ProtocolWorkbench.init(std.testing.allocator, &storage, &registry);

    const data = try @import("../protocols/infrared.zig").sampleText(std.testing.allocator);
    defer std.testing.allocator.free(data);

    var analysis = try workbench.analyzeBytes(registry.find("infrared").?, "memory.ir", data);
    defer analysis.deinit();

    try std.testing.expectEqualStrings("infrared", analysis.protocol.id);
    try std.testing.expectEqualStrings("memory.ir", analysis.artifact.path);
    try std.testing.expectEqualStrings("application/x-flipper-ir", analysis.artifact.media_type);
    try std.testing.expect(std.mem.indexOf(u8, analysis.result.summary, "demo_power") != null);
    try std.testing.expect(analysis.result.fields.items.len > 0);
}
