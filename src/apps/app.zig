const std = @import("std");
const event_bus = @import("../core/event_bus.zig");
const storage = @import("../services/storage.zig");
const notification = @import("../services/notification.zig");
const protocol = @import("../protocols/protocol.zig");

pub const AppContext = struct {
    allocator: std.mem.Allocator,
    events: *event_bus.EventBus,
    storage: *storage.StorageService,
    notifications: *notification.NotificationService,
    protocols: []const protocol.ProtocolDescriptor,
    args: []const []const u8 = &.{},
};

pub const AppEntry = *const fn (*AppContext) anyerror!void;

pub const AppDescriptor = struct {
    id: []const u8,
    name: []const u8,
    category: []const u8,
    entry: AppEntry,
};

pub const AppManager = struct {
    apps: []const AppDescriptor,

    pub fn init(apps: []const AppDescriptor) AppManager {
        return .{ .apps = apps };
    }

    pub fn find(self: *const AppManager, id: []const u8) ?AppDescriptor {
        for (self.apps) |descriptor| {
            if (std.mem.eql(u8, descriptor.id, id)) return descriptor;
        }
        return null;
    }

    pub fn run(self: *const AppManager, id: []const u8, context: *AppContext) !void {
        const descriptor = self.find(id) orelse return error.UnknownApp;
        try context.events.publish(.{
            .kind = .app_started,
            .topic = descriptor.id,
            .payload = descriptor.name,
        });
        descriptor.entry(context) catch |err| {
            try context.events.publish(.{
                .kind = .app_stopped,
                .topic = descriptor.id,
                .payload = @errorName(err),
            });
            return err;
        };
        try context.events.publish(.{
            .kind = .app_stopped,
            .topic = descriptor.id,
            .payload = descriptor.name,
        });
    }
};

test "app manager finds registered apps" {
    const fake = struct {
        fn run(_: *AppContext) !void {}
    }.run;

    const apps = [_]AppDescriptor{.{
        .id = "fake",
        .name = "Fake",
        .category = "Test",
        .entry = fake,
    }};
    const manager = AppManager.init(&apps);

    try std.testing.expect(manager.find("fake") != null);
    try std.testing.expect(manager.find("missing") == null);
}
