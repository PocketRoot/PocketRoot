const std = @import("std");

pub const EventKind = enum {
    app_started,
    app_stopped,
    protocol_loaded,
    storage_saved,
    storage_loaded,
    notification,
};

pub const Event = struct {
    kind: EventKind,
    topic: []const u8,
    payload: []const u8 = "",
};

pub const EventBus = struct {
    allocator: std.mem.Allocator,
    events: std.ArrayList(Event),

    pub fn init(allocator: std.mem.Allocator) EventBus {
        return .{
            .allocator = allocator,
            .events = .empty,
        };
    }

    pub fn deinit(self: *EventBus) void {
        self.freeEvents();
        self.events.deinit(self.allocator);
    }

    pub fn publish(self: *EventBus, event: Event) !void {
        const topic = try self.allocator.dupe(u8, event.topic);
        errdefer self.allocator.free(topic);
        const payload = try self.allocator.dupe(u8, event.payload);
        errdefer self.allocator.free(payload);

        try self.events.append(self.allocator, .{
            .kind = event.kind,
            .topic = topic,
            .payload = payload,
        });
    }

    pub fn items(self: *const EventBus) []const Event {
        return self.events.items;
    }

    pub fn count(self: *const EventBus) usize {
        return self.events.items.len;
    }

    pub fn clear(self: *EventBus) void {
        self.freeEvents();
        self.events.clearRetainingCapacity();
    }

    fn freeEvents(self: *EventBus) void {
        for (self.events.items) |event| {
            self.allocator.free(event.topic);
            self.allocator.free(event.payload);
        }
    }
};

test "event bus records published events" {
    var bus = EventBus.init(std.testing.allocator);
    defer bus.deinit();

    try bus.publish(.{ .kind = .app_started, .topic = "infrared" });

    try std.testing.expectEqual(@as(usize, 1), bus.count());
    try std.testing.expectEqual(EventKind.app_started, bus.items()[0].kind);
    try std.testing.expectEqualStrings("infrared", bus.items()[0].topic);
}
