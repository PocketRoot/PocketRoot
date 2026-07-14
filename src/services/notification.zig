const std = @import("std");

pub const Level = enum {
    info,
    warning,
    error_level,
};

pub const Notification = struct {
    level: Level,
    topic: []const u8,
    message: []const u8,
};

pub const NotificationService = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(Notification),

    pub fn init(allocator: std.mem.Allocator) NotificationService {
        return .{
            .allocator = allocator,
            .records = .empty,
        };
    }

    pub fn deinit(self: *NotificationService) void {
        for (self.records.items) |record| {
            self.allocator.free(record.topic);
            self.allocator.free(record.message);
        }
        self.records.deinit(self.allocator);
    }

    pub fn publish(self: *NotificationService, notification: Notification) !void {
        const topic = try self.allocator.dupe(u8, notification.topic);
        errdefer self.allocator.free(topic);
        const message = try self.allocator.dupe(u8, notification.message);
        errdefer self.allocator.free(message);

        try self.records.append(self.allocator, .{
            .level = notification.level,
            .topic = topic,
            .message = message,
        });
    }

    pub fn info(self: *NotificationService, topic: []const u8, message: []const u8) !void {
        try self.publish(.{
            .level = .info,
            .topic = topic,
            .message = message,
        });
    }

    pub fn warning(self: *NotificationService, topic: []const u8, message: []const u8) !void {
        try self.publish(.{
            .level = .warning,
            .topic = topic,
            .message = message,
        });
    }

    pub fn infoFmt(
        self: *NotificationService,
        topic: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        const message = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(message);
        try self.info(topic, message);
    }

    pub fn warningFmt(
        self: *NotificationService,
        topic: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        const message = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(message);
        try self.warning(topic, message);
    }

    pub fn items(self: *const NotificationService) []const Notification {
        return self.records.items;
    }
};

test "notification service records messages" {
    var service = NotificationService.init(std.testing.allocator);
    defer service.deinit();

    try service.info("infrared", "saved");

    try std.testing.expectEqual(@as(usize, 1), service.items().len);
    try std.testing.expectEqualStrings("saved", service.items()[0].message);
}
