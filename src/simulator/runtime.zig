const std = @import("std");
const app = @import("../apps/app.zig");
const event_bus = @import("../core/event_bus.zig");
const storage = @import("../services/storage.zig");
const notification = @import("../services/notification.zig");
const archive = @import("../services/archive.zig");
const protocol = @import("../protocols/protocol.zig");
const protocol_registry = @import("../protocols/registry.zig");
const protocol_workbench = @import("../services/workbench.zig");

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    events: event_bus.EventBus,
    storage: storage.StorageService,
    notifications: notification.NotificationService,
    archive: archive.ArchiveService,
    apps: app.AppManager,
    protocols: protocol_registry.ProtocolRegistry,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        apps: []const app.AppDescriptor,
        protocols: []const protocol.ProtocolDescriptor,
    ) Runtime {
        return .{
            .allocator = allocator,
            .events = event_bus.EventBus.init(allocator),
            .storage = storage.StorageService.init(io),
            .notifications = notification.NotificationService.init(allocator),
            .archive = archive.ArchiveService.init(io),
            .apps = app.AppManager.init(apps),
            .protocols = protocol_registry.ProtocolRegistry.init(protocols),
        };
    }

    pub fn deinit(self: *Runtime) void {
        self.notifications.deinit();
        self.events.deinit();
    }

    pub fn context(self: *Runtime) app.AppContext {
        return .{
            .allocator = self.allocator,
            .events = &self.events,
            .storage = &self.storage,
            .notifications = &self.notifications,
            .protocols = self.protocols.protocols,
        };
    }

    pub fn runApp(self: *Runtime, id: []const u8) !void {
        try self.runAppArgs(id, &.{});
    }

    pub fn runAppArgs(self: *Runtime, id: []const u8, args: []const []const u8) !void {
        var ctx = self.context();
        ctx.args = args;
        try self.apps.run(id, &ctx);
    }

    pub fn workbench(self: *Runtime) protocol_workbench.ProtocolWorkbench {
        return protocol_workbench.ProtocolWorkbench.init(self.allocator, &self.storage, &self.protocols);
    }

    pub fn analyzeProtocolPath(self: *Runtime, protocol_id: ?[]const u8, path: []const u8) !protocol_workbench.Analysis {
        var analyzer = self.workbench();
        var analysis = try analyzer.analyzePath(protocol_id, path);
        errdefer analysis.deinit();

        try self.events.publish(.{
            .kind = .storage_loaded,
            .topic = analysis.protocol.id,
            .payload = analysis.artifact.path,
        });
        try self.events.publish(.{
            .kind = .protocol_loaded,
            .topic = analysis.protocol.id,
            .payload = analysis.protocol.name,
        });

        return analysis;
    }

    pub fn listArchive(self: *Runtime, root_path: []const u8) !archive.ArchiveListing {
        return self.archive.list(self.allocator, &self.protocols, root_path);
    }
};

test "runtime analyzes protocol files and records events" {
    const sample = try @import("../protocols/infrared.zig").sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);

    var runtime = Runtime.init(
        std.testing.allocator,
        std.testing.io,
        &.{},
        @import("../protocols/registry.zig").builtinProtocols(),
    );
    defer runtime.deinit();

    const path = ".zig-cache/runtime-test.ir";
    try runtime.storage.saveText(path, sample);
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    var analysis = try runtime.analyzeProtocolPath(null, path);
    defer analysis.deinit();

    try std.testing.expectEqualStrings("infrared", analysis.protocol.id);
    try std.testing.expect(runtime.events.count() >= 2);
}

test "runtime lists archive entries" {
    var runtime = Runtime.init(
        std.testing.allocator,
        std.testing.io,
        &.{},
        @import("../protocols/registry.zig").builtinProtocols(),
    );
    defer runtime.deinit();

    const root = ".zig-cache/runtime-archive-test";
    const path = ".zig-cache/runtime-archive-test/demo.ir";
    try runtime.storage.saveText(path, "name: demo\nprotocol: NEC\naddress: 0x1\ncommand: 0x2\n");
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
    defer std.Io.Dir.cwd().deleteDir(std.testing.io, root) catch {};

    var listing = try runtime.listArchive(root);
    defer listing.deinit();

    try std.testing.expectEqual(@as(usize, 1), listing.count());
    try std.testing.expectEqualStrings("infrared", listing.entries.items[0].protocol_id.?);
}
