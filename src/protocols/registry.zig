const std = @import("std");
const protocol = @import("protocol.zig");
const badusb = @import("badusb.zig");
const infrared = @import("infrared.zig");
const lfrfid = @import("lfrfid.zig");
const nfc = @import("nfc.zig");
const ibutton = @import("ibutton.zig");
const nmap = @import("nmap.zig");
const nuclei = @import("nuclei.zig");
const pcap = @import("pcap.zig");
const subghz = @import("subghz.zig");
const firmware = @import("firmware.zig");
const cyclonedx = @import("cyclonedx.zig");
const spdx = @import("spdx.zig");
const npm_lock = @import("npm_lock.zig");

const builtins = [_]protocol.ProtocolDescriptor{
    badusb.descriptor,
    infrared.descriptor,
    lfrfid.descriptor,
    nfc.descriptor,
    ibutton.descriptor,
    nmap.descriptor,
    nuclei.descriptor,
    pcap.descriptor,
    subghz.descriptor,
    firmware.descriptor,
    cyclonedx.descriptor,
    spdx.descriptor,
    npm_lock.descriptor,
};

pub fn builtinProtocols() []const protocol.ProtocolDescriptor {
    return &builtins;
}

pub const ProtocolRegistry = struct {
    protocols: []const protocol.ProtocolDescriptor,

    pub fn init(protocols: []const protocol.ProtocolDescriptor) ProtocolRegistry {
        return .{ .protocols = protocols };
    }

    pub fn find(self: *const ProtocolRegistry, id: []const u8) ?protocol.ProtocolDescriptor {
        for (self.protocols) |descriptor| {
            if (std.mem.eql(u8, descriptor.id, id)) return descriptor;
        }
        return null;
    }

    pub fn findByExtension(self: *const ProtocolRegistry, extension: []const u8) ?protocol.ProtocolDescriptor {
        const normalized = if (std.mem.startsWith(u8, extension, ".")) extension[1..] else extension;
        for (self.protocols) |descriptor| {
            if (!descriptor.auto_detect) continue;
            if (std.ascii.eqlIgnoreCase(descriptor.file_extension, normalized)) return descriptor;
            for (descriptor.additional_extensions) |additional| {
                if (std.ascii.eqlIgnoreCase(additional, normalized)) return descriptor;
            }
        }
        return null;
    }

    pub fn inferFromPath(self: *const ProtocolRegistry, path: []const u8) ?protocol.ProtocolDescriptor {
        const basename = std.fs.path.basename(path);
        const index = std.mem.lastIndexOfScalar(u8, basename, '.') orelse return null;
        return self.findByExtension(basename[index + 1 ..]);
    }
};

test "protocol registry finds infrared" {
    const registry = ProtocolRegistry.init(builtinProtocols());

    try std.testing.expect(registry.find("infrared") != null);
    try std.testing.expect(registry.find("nfc") != null);
    try std.testing.expect(registry.findByExtension(".nfc") != null);
    try std.testing.expect(registry.findByExtension(".ir") != null);
    try std.testing.expect(registry.inferFromPath("samples/infrared/demo-power.ir") != null);
    try std.testing.expect(registry.find("subghz") != null);
    try std.testing.expect(registry.findByExtension(".sub") != null);
    try std.testing.expect(registry.find("lfrfid") != null);
    try std.testing.expect(registry.findByExtension(".rfid") != null);
    try std.testing.expect(registry.find("ibutton") != null);
    try std.testing.expect(registry.findByExtension(".ibtn") != null);
    try std.testing.expect(registry.find("badusb") != null);
    try std.testing.expect(registry.findByExtension(".txt") == null);
    try std.testing.expect(registry.find("nmap") != null);
    try std.testing.expect(registry.findByExtension(".xml") == null);
    try std.testing.expect(registry.find("nuclei") != null);
    try std.testing.expect(registry.findByExtension(".jsonl") == null);
    try std.testing.expect(registry.find("pcap") != null);
    try std.testing.expectEqualStrings("pcap", registry.findByExtension(".pcapng").?.id);
}

test "protocol registry supports additional extensions and manual protocols" {
    const fake_analyze = struct {
        fn run(allocator: std.mem.Allocator, _: []const u8) !protocol.AnalysisResult {
            return protocol.AnalysisResult.init(allocator, "fake");
        }
    }.run;
    const descriptors = [_]protocol.ProtocolDescriptor{
        .{
            .id = "capture",
            .name = "Capture",
            .category = "Test",
            .file_extension = "pcap",
            .additional_extensions = &.{"pcapng"},
            .analyze = fake_analyze,
        },
        .{
            .id = "manual",
            .name = "Manual",
            .category = "Test",
            .file_extension = "json",
            .additional_extensions = &.{"jsonl"},
            .auto_detect = false,
            .analyze = fake_analyze,
        },
    };
    const registry = ProtocolRegistry.init(&descriptors);

    try std.testing.expectEqualStrings("capture", registry.findByExtension(".PCAPNG").?.id);
    try std.testing.expect(registry.findByExtension("jsonl") == null);
}

test "registered samples support byte-exact validated migration" {
    for (builtinProtocols()) |registered| {
        const sample_fn = registered.sample orelse continue;
        const sample = try sample_fn(std.testing.allocator);
        defer std.testing.allocator.free(sample);
        const migrated = try registered.validatedCopy(std.testing.allocator, sample);
        defer std.testing.allocator.free(migrated);
        try std.testing.expectEqualSlices(u8, sample, migrated);
    }
}
