//! Firmware triage (stage F1).
//!
//! Container sniffing, block entropy, printable strings and a Cortex-M vector-table
//! heuristic. No disassembly here (F2/F3); everything reported is an observation with
//! an explicit offset so it can be reproduced with host tooling.

const std = @import("std");
const protocol = @import("protocol.zig");
const thumb = @import("../formats/thumb.zig");

pub const block_size = 1024;
pub const max_entropy_blocks = 4096;
pub const max_preview_strings = 8;
pub const max_string_bytes = 48;
pub const min_string_len = 4;
pub const high_entropy_x100: u32 = 700;

pub const descriptor = protocol.ProtocolDescriptor{
    .id = "firmware",
    .name = "Firmware Image",
    .category = "Firmware",
    .file_extension = "bin",
    .additional_extensions = &.{ "elf", "hex", "img" },
    .media_type = "application/octet-stream",
    .auto_detect = false,
    .analyze = analyzeDefault,
    .analyze_with = analyzeWith,
    .sample = sampleText,
};

const elf_magic = [_]u8{ 0x7f, 'E', 'L', 'F' };

fn isPrintable(byte: u8) bool {
    return byte >= 0x20 and byte <= 0x7e;
}

fn classify(data: []const u8) []const u8 {
    if (data.len >= 4 and std.mem.eql(u8, data[0..4], &elf_magic)) return "elf";
    if (data.len >= 2 and data[0] == ':' and data[1] != 0) return "intel-hex";
    return "raw";
}

pub fn blockEntropyX100(block: []const u8) u32 {
    if (block.len == 0) return 0;
    var counts = [_]u32{0} ** 256;
    for (block) |byte| counts[byte] += 1;
    const total: f64 = @floatFromInt(block.len);
    var entropy: f64 = 0;
    for (counts) |count| {
        if (count == 0) continue;
        const probability: f64 = @as(f64, @floatFromInt(count)) / total;
        entropy -= probability * @log2(probability);
    }
    const scaled = entropy * 100.0;
    if (!(scaled > 0)) return 0;
    return @intFromFloat(@round(scaled));
}

const StringStats = struct {
    ascii_count: usize = 0,
    ascii_bytes: usize = 0,
    utf16_runs: usize = 0,
    utf16_chars: usize = 0,
};

fn scanAscii(
    data: []const u8,
    stats: *StringStats,
    previews: *[max_preview_strings][]const u8,
    preview_count: *usize,
) void {
    var index: usize = 0;
    while (index < data.len) {
        if (!isPrintable(data[index])) {
            index += 1;
            continue;
        }
        const start = index;
        while (index < data.len and isPrintable(data[index])) index += 1;
        const length = index - start;
        if (length < min_string_len) continue;
        stats.ascii_count += 1;
        stats.ascii_bytes += length;
        if (preview_count.* < max_preview_strings) {
            const clipped = @min(length, max_string_bytes);
            previews[preview_count.*] = data[start .. start + clipped];
            preview_count.* += 1;
        }
    }
}

fn scanUtf16(data: []const u8, stats: *StringStats) void {
    var index: usize = 0;
    while (index + 1 < data.len) {
        if (!(isPrintable(data[index]) and data[index + 1] == 0)) {
            index += 1;
            continue;
        }
        const start = index;
        var chars: usize = 0;
        while (index + 1 < data.len and isPrintable(data[index]) and data[index + 1] == 0) : (index += 2) {
            chars += 1;
        }
        if (chars < min_string_len) continue;
        if (index == start) index += 1;
        stats.utf16_runs += 1;
        stats.utf16_chars += chars;
    }
}

pub const VectorTable = struct {
    initial_sp: u32,
    entry_point: u32,
    thumb: bool,
    sp_plausible: bool,
    entry_in_range: bool,
    valid: bool,
};

pub fn inspectVectorTable(data: []const u8, base_address: u32) ?VectorTable {
    if (data.len < 8) return null;
    const initial_sp = std.mem.readInt(u32, data[0..4], .little);
    const reset = std.mem.readInt(u32, data[4..8], .little);
    const entry_point = reset & ~@as(u32, 1);
    const thumb_bit = (reset & 1) == 1;
    const sp_plausible = (initial_sp & 3) == 0 and
        ((initial_sp >= 0x2000_0000 and initial_sp < 0x2100_0000) or
            (initial_sp >= 0x1000_0000 and initial_sp < 0x1100_0000));
    const entry_in_range = if (base_address != 0) blk: {
        const limit: u64 = @as(u64, base_address) + @as(u64, @intCast(data.len));
        break :blk entry_point >= base_address and @as(u64, entry_point) < limit;
    } else entry_point < 0x1000_0000;
    return .{
        .initial_sp = initial_sp,
        .entry_point = entry_point,
        .thumb = thumb_bit,
        .sp_plausible = sp_plausible,
        .entry_in_range = entry_in_range,
        .valid = sp_plausible and thumb_bit and entry_in_range,
    };
}

pub fn analyzeDefault(allocator: std.mem.Allocator, data: []const u8) !protocol.AnalysisResult {
    return analyzeWith(allocator, data, .{});
}

pub fn analyzeWith(
    allocator: std.mem.Allocator,
    data: []const u8,
    options: protocol.AnalyzeOptions,
) !protocol.AnalysisResult {
    if (data.len < 8) return error.FirmwareTooShort;

    const kind = classify(data);
    const total_blocks = (data.len + block_size - 1) / block_size;
    const analyzed_blocks = @min(total_blocks, max_entropy_blocks);

    var entropy_sum: u64 = 0;
    var entropy_max: u32 = 0;
    var entropy_max_offset: usize = 0;
    var high_blocks: usize = 0;
    var first_high: ?usize = null;
    var block_index: usize = 0;
    while (block_index < analyzed_blocks) : (block_index += 1) {
        const start = block_index * block_size;
        const end = @min(start + block_size, data.len);
        const value = blockEntropyX100(data[start..end]);
        entropy_sum += value;
        if (value > entropy_max) {
            entropy_max = value;
            entropy_max_offset = start;
        }
        if (value >= high_entropy_x100) {
            high_blocks += 1;
            if (first_high == null) first_high = start;
        }
    }
    const entropy_mean: u32 = if (analyzed_blocks == 0) 0 else @intCast(entropy_sum / analyzed_blocks);

    var stats = StringStats{};
    var previews: [max_preview_strings][]const u8 = @splat("");
    var preview_count: usize = 0;
    scanAscii(data, &stats, &previews, &preview_count);
    scanUtf16(data, &stats);

    const table = inspectVectorTable(data, options.base_address);

    // Stage F2: bounded Thumb decode. Start at the reset handler when the vector table
    // is usable, otherwise at file offset 0.
    const wants_thumb = if (options.architecture) |arch|
        std.mem.eql(u8, arch, "thumb") or std.mem.eql(u8, arch, "arm") or std.mem.eql(u8, arch, "cortex-m")
    else
        true;
    var listing: thumb.Listing = .{};
    defer listing.deinit(allocator);
    var decoded = false;
    if (wants_thumb and (std.mem.eql(u8, kind, "raw") or std.mem.eql(u8, kind, "elf"))) {
        var start_offset: usize = 0;
        if (table) |value| {
            if (value.valid and value.entry_point >= options.base_address) {
                const candidate = value.entry_point - options.base_address;
                if (candidate < data.len) start_offset = candidate;
            }
        }
        listing = thumb.decode(allocator, data, options.base_address, start_offset) catch .{};
        decoded = true;
    }

    var summary_buffer: [192]u8 = undefined;
    const table_text = if (table) |value|
        (if (value.valid) "vector-table ok" else "vector-table suspect")
    else
        "no vector-table";
    const summary = try std.fmt.bufPrint(&summary_buffer, "{s} {d} bytes: {d} high-entropy block(s), {d} strings, {s}", .{
        kind,
        data.len,
        high_blocks,
        stats.ascii_count,
        table_text,
    });

    var result = try protocol.AnalysisResult.init(allocator, summary);
    errdefer result.deinit();

    try result.addField("kind", kind);
    try result.addNumberField("size", data.len);
    try result.addNumberField("base_address", options.base_address);
    try result.addField("architecture", options.architecture orelse "auto");
    try result.addNumberField("entropy_blocks", analyzed_blocks);
    try result.addNumberField("entropy_block_size", block_size);
    try result.addNumberField("entropy_mean_x100", entropy_mean);
    try result.addNumberField("entropy_max_x100", entropy_max);
    try result.addNumberField("entropy_max_offset", entropy_max_offset);
    try result.addNumberField("high_entropy_blocks", high_blocks);
    if (first_high) |offset| try result.addNumberField("first_high_entropy_offset", offset);
    try result.addNumberField("ascii_strings", stats.ascii_count);
    try result.addNumberField("ascii_string_bytes", stats.ascii_bytes);
    try result.addNumberField("utf16_runs", stats.utf16_runs);
    try result.addNumberField("utf16_chars", stats.utf16_chars);

    var preview_index: usize = 0;
    while (preview_index < preview_count) : (preview_index += 1) {
        var key_buffer: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_buffer, "strings_sample_{d}", .{preview_index + 1});
        try result.addField(key, previews[preview_index]);
    }

    if (table) |value| {
        try result.addField("vector_table_valid", if (value.valid) "yes" else "no");
        var entry_buffer: [24]u8 = undefined;
        try result.addField("entry_point", try std.fmt.bufPrint(&entry_buffer, "0x{x:0>8}", .{value.entry_point}));
        var sp_buffer: [24]u8 = undefined;
        try result.addField("initial_sp", try std.fmt.bufPrint(&sp_buffer, "0x{x:0>8}", .{value.initial_sp}));
        try result.addField("thumb_entry", if (value.thumb) "yes" else "no");
        try result.addField("sp_plausible", if (value.sp_plausible) "yes" else "no");
    } else {
        try result.addField("vector_table_valid", "no");
    }

    if (decoded) {
        try result.addField("disassembly_arch", "thumb");
        try result.addNumberField("instructions", listing.instructions);
        try result.addNumberField("unknown_opcodes", listing.unknown);
        const coverage: usize = if (listing.instructions == 0)
            0
        else
            ((listing.instructions - listing.unknown) * 100) / listing.instructions;
        try result.addNumberField("decode_coverage_x100", coverage);
        try result.addNumberField("functions", listing.functions);

        var entry_index: usize = 0;
        while (entry_index < listing.entries.len and entry_index < 3) : (entry_index += 1) {
            var key_buffer: [24]u8 = undefined;
            const key = try std.fmt.bufPrint(&key_buffer, "function_{d}", .{entry_index + 1});
            var value_buffer: [16]u8 = undefined;
            const value = try std.fmt.bufPrint(&value_buffer, "0x{x:0>8}", .{listing.entries[entry_index]});
            try result.addField(key, value);
        }
        var sample_index: usize = 0;
        while (sample_index < listing.sample_count and sample_index < 4) : (sample_index += 1) {
            var key_buffer: [24]u8 = undefined;
            const key = try std.fmt.bufPrint(&key_buffer, "insn_{d}", .{sample_index + 1});
            var line_buffer: [96]u8 = undefined;
            const sample = listing.samples[sample_index];
            const line = try std.fmt.bufPrint(&line_buffer, "0x{x:0>8}: {s}", .{ sample.address, sample.slice() });
            try result.addField(key, line);
        }
    } else {
        try result.addField("disassembly_arch", "none");
    }

    if (high_blocks > 0) {
        var detail_buffer: [160]u8 = undefined;
        const detail = try std.fmt.bufPrint(
            &detail_buffer,
            "{d}/{d} blocks at or above {d}.{d:0>2} bits/byte; first at offset {d}",
            .{ high_blocks, analyzed_blocks, high_entropy_x100 / 100, high_entropy_x100 % 100, first_high orelse 0 },
        );
        try result.addDetailedFinding(.info, "High-entropy region detected", detail, kind, "firmware:entropy");
    }
    if (std.mem.eql(u8, kind, "raw") and (table == null or !table.?.valid)) {
        try result.addFinding(.warning, "No Cortex-M vector table detected");
    }
    if (decoded and listing.instructions > 0) {
        const coverage: usize = ((listing.instructions - listing.unknown) * 100) / listing.instructions;
        if (coverage < 95) {
            var detail_buffer: [128]u8 = undefined;
            const detail = try std.fmt.bufPrint(
                &detail_buffer,
                "{d}/{d} instructions decoded ({d}%), {d} unknown",
                .{ listing.instructions - listing.unknown, listing.instructions, coverage, listing.unknown },
            );
            try result.addDetailedFinding(.warning, "Thumb decode coverage below 95%", detail, "thumb", "firmware:disasm");
        }
    }
    return result;
}

pub fn sampleText(allocator: std.mem.Allocator) ![]u8 {
    // 320 bytes keeps the reset handler (0x08000100) inside a 0x08000000-based image.
    var image = [_]u8{0} ** 320;
    std.mem.writeInt(u32, image[0..4], 0x2000_1000, .little);
    std.mem.writeInt(u32, image[4..8], 0x0800_0101, .little);
    const first = "POCKETROOT F1 SAMPLE";
    @memcpy(image[8 .. 8 + first.len], first);
    const second = "firmware triage demo";
    @memcpy(image[40 .. 40 + second.len], second);
    return allocator.dupe(u8, &image);
}

fn fillPseudoRandom(buffer: []u8, seed_value: u32) void {
    var state = seed_value;
    for (buffer) |*byte| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte.* = @truncate(state);
    }
}

test "sample image looks like a Cortex-M vector table" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);

    var result = try analyzeWith(std.testing.allocator, sample, .{});
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.summary, "vector-table ok") != null);
    try std.testing.expectEqualStrings("raw", result.fields.items[0].value);
    try std.testing.expectEqualStrings("0x08000100", findField(&result, "entry_point").?);
    try std.testing.expectEqualStrings("yes", findField(&result, "vector_table_valid").?);
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
}

test "elf magic is classified without a vector table warning" {
    var image = [_]u8{0} ** 32;
    @memcpy(image[0..4], &elf_magic);
    var result = try analyzeWith(std.testing.allocator, &image, .{});
    defer result.deinit();
    try std.testing.expectEqualStrings("elf", findField(&result, "kind").?);
    try std.testing.expectEqual(@as(usize, 0), result.findings.items.len);
}

test "high entropy regions are reported with an offset" {
    var image = [_]u8{0} ** 4096;
    fillPseudoRandom(image[0..], 0xC0FFEE);
    var result = try analyzeWith(std.testing.allocator, &image, .{});
    defer result.deinit();
    const blocks = findField(&result, "high_entropy_blocks").?;
    try std.testing.expect(!std.mem.eql(u8, blocks, "0"));
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "high-entropy") != null);
    // Random bytes carry no vector table, so the entropy finding is followed by the
    // "not a recognisable Cortex-M image" warning.
    try std.testing.expectEqual(@as(usize, 2), result.findings.items.len);
    try std.testing.expectEqual(protocol.FindingSeverity.info, result.findings.items[0].severity);
    try std.testing.expectEqual(protocol.FindingSeverity.warning, result.findings.items[1].severity);
}

test "base address constrains the entry point check" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);

    var mismatched = try analyzeWith(std.testing.allocator, sample, .{ .base_address = 0x2000_0000 });
    defer mismatched.deinit();
    try std.testing.expectEqualStrings("no", findField(&mismatched, "vector_table_valid").?);

    var matched = try analyzeWith(std.testing.allocator, sample, .{ .base_address = 0x0800_0000 });
    defer matched.deinit();
    try std.testing.expectEqualStrings("yes", findField(&matched, "vector_table_valid").?);
}

test "rejects images that are too short" {
    try std.testing.expectError(error.FirmwareTooShort, analyzeWith(std.testing.allocator, "short", .{}));
}

test "block entropy bounds" {
    const zeros = [_]u8{0} ** 256;
    try std.testing.expectEqual(@as(u32, 0), blockEntropyX100(&zeros));

    var uniform: [512]u8 = undefined;
    for (0..256) |index| {
        uniform[index] = @intCast(index);
        uniform[index + 256] = @intCast(index);
    }
    const value = blockEntropyX100(&uniform);
    try std.testing.expect(value >= 795 and value <= 805);
}

test "decodes Thumb and reports coverage metrics" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);

    var result = try analyzeWith(std.testing.allocator, sample, .{ .base_address = 0x0800_0000 });
    defer result.deinit();

    try std.testing.expectEqualStrings("thumb", findField(&result, "disassembly_arch").?);
    try std.testing.expect(findField(&result, "instructions") != null);
    try std.testing.expect(findField(&result, "decode_coverage_x100") != null);
    try std.testing.expect(findField(&result, "functions") != null);
    try std.testing.expect(findField(&result, "insn_1") != null);
    // Entry point 0x08000100 => base + 0x100, so decoding starts inside the image.
    try std.testing.expect(std.mem.startsWith(u8, findField(&result, "insn_1").?, "0x08000100"));
}

test "disassembly can be disabled with an explicit architecture" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);

    var result = try analyzeWith(std.testing.allocator, sample, .{ .architecture = "none" });
    defer result.deinit();
    try std.testing.expectEqualStrings("none", findField(&result, "disassembly_arch").?);
    try std.testing.expect(findField(&result, "instructions") == null);
}

test "sample survives byte-exact validated migration" {
    const sample = try sampleText(std.testing.allocator);
    defer std.testing.allocator.free(sample);
    const copy = try descriptor.validatedCopy(std.testing.allocator, sample);
    defer std.testing.allocator.free(copy);
    try std.testing.expectEqualSlices(u8, sample, copy);
}

fn findField(result: *const protocol.AnalysisResult, name: []const u8) ?[]const u8 {
    for (result.fields.items) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}
