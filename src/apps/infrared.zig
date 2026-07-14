const std = @import("std");
const app = @import("app.zig");
const event_bus = @import("../core/event_bus.zig");
const infrared = @import("../protocols/infrared.zig");
const protocol_registry = @import("../protocols/registry.zig");
const protocol_workbench = @import("../services/workbench.zig");

pub fn run(context: *app.AppContext) !void {
    const command = if (context.args.len == 0) "save-demo" else context.args[0];

    if (std.mem.eql(u8, command, "save-demo")) {
        try saveDemo(context);
    } else if (std.mem.eql(u8, command, "load")) {
        if (context.args.len < 2) {
            try context.notifications.warning("infrared", "usage: run infrared load <path>");
            return;
        }
        try load(context, context.args[1]);
    } else if (std.mem.eql(u8, command, "analyze")) {
        if (context.args.len < 2) {
            try context.notifications.warning("infrared", "usage: run infrared analyze <path>");
            return;
        }
        try analyze(context, context.args[1]);
    } else {
        try context.notifications.warningFmt(
            "infrared",
            "unknown infrared command: {s}",
            .{command},
        );
    }
}

fn saveDemo(context: *app.AppContext) !void {
    const signal = infrared.demoSignal();
    const text = try infrared.descriptor.sample.?(context.allocator);
    defer context.allocator.free(text);

    const path = try context.storage.samplePath(
        context.allocator,
        infrared.descriptor.id,
        signal.name,
        infrared.descriptor.file_extension,
    );
    defer context.allocator.free(path);

    try context.storage.saveText(path, text);
    try context.events.publish(.{
        .kind = event_bus.EventKind.protocol_loaded,
        .topic = "infrared",
        .payload = signal.name,
    });
    try context.notifications.infoFmt("infrared", "saved {s}", .{path});
}

fn load(context: *app.AppContext, path: []const u8) !void {
    const data = context.storage.loadText(context.allocator, path) catch |err| switch (err) {
        error.FileNotFound => {
            try context.notifications.warningFmt("infrared", "file not found: {s}", .{path});
            return;
        },
        else => return err,
    };
    defer context.allocator.free(data);

    const signal = try infrared.parseSimpleWithAllocator(context.allocator, data);
    try context.events.publish(.{
        .kind = .storage_loaded,
        .topic = "infrared",
        .payload = path,
    });
    try context.events.publish(.{
        .kind = event_bus.EventKind.protocol_loaded,
        .topic = "infrared",
        .payload = signal.name,
    });

    try context.notifications.infoFmt(
        "infrared",
        "loaded {s} as {s}/{s}",
        .{ path, signal.protocol, signal.name },
    );
}

fn analyze(context: *app.AppContext, path: []const u8) !void {
    const registry = protocol_registry.ProtocolRegistry.init(context.protocols);
    var workbench = protocol_workbench.ProtocolWorkbench.init(
        context.allocator,
        context.storage,
        &registry,
    );
    var analysis = workbench.analyzePath("infrared", path) catch |err| switch (err) {
        error.FileNotFound => {
            try context.notifications.warningFmt("infrared", "file not found: {s}", .{path});
            return;
        },
        else => return err,
    };
    defer analysis.deinit();

    try context.events.publish(.{
        .kind = .storage_loaded,
        .topic = analysis.protocol.id,
        .payload = analysis.artifact.path,
    });
    try context.events.publish(.{
        .kind = event_bus.EventKind.protocol_loaded,
        .topic = analysis.protocol.id,
        .payload = analysis.protocol.name,
    });
    try context.notifications.infoFmt("infrared", "analysis {s}", .{analysis.result.summary});
}
