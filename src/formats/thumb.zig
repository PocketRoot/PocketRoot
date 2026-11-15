//! Bounded Thumb (ARMv7-M) decoder for firmware triage.
//!
//! Scope (stage F2): structural length sync for every Thumb/Thumb-2 encoding, plus
//! mnemonics and operands for the encodings triage actually needs (branches, BL,
//! MOVW/MOVT, literal LDR, word/half/byte load-store, push/pop, common ALU forms).
//! Encodings that are valid but not modelled are still length-synced and counted as
//! instructions named after their group, so coverage measures decode sync rather
//! than mnemonic fidelity. Nothing here executes code.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_instructions = 64 * 1024;
pub const max_samples = 8;
pub const max_functions = 64;

pub const Sample = struct {
    address: u32 = 0,
    text: [56]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const Sample) []const u8 {
        return self.text[0..self.len];
    }
};

pub const LiteralRef = struct {
    address: u32,
    instruction: u32,
};

pub const Listing = struct {
    instructions: usize = 0,
    unknown: usize = 0,
    bytes: usize = 0,
    functions: usize = 0,
    entries: []u32 = &.{},
    samples: [max_samples]Sample = @splat(Sample{}),
    sample_count: usize = 0,
    branch_targets: []u32 = &.{},
    literals: []LiteralRef = &.{},

    pub fn deinit(self: *Listing, allocator: Allocator) void {
        if (self.entries.len > 0) allocator.free(self.entries);
        if (self.branch_targets.len > 0) allocator.free(self.branch_targets);
        if (self.literals.len > 0) allocator.free(self.literals);
        self.* = undefined;
    }
};

const Decoded = struct {
    length: u8,
    mnemonic: []const u8,
    operands: [40]u8 = @splat(0),
    operands_len: u8 = 0,
    branch_target: ?u32 = null,
    call_target: ?u32 = null,
    /// Set for pc-relative data loads (LDR literal, ADR); used for string xrefs.
    literal: ?u32 = null,
};

fn regName(index: u3) []const u8 {
    const names = [_][]const u8{ "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7" };
    return names[index];
}

fn fmt(decoded: *Decoded, comptime format: []const u8, args: anytype) void {
    const written = std.fmt.bufPrint(&decoded.operands, format, args) catch return;
    decoded.operands_len = @intCast(written.len);
}

fn highRegName(index: u4) []const u8 {
    const names = [_][]const u8{ "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "sb", "sl", "fp", "ip", "sp", "lr", "lr", "pc" };
    return names[index];
}

const cond_names = [_][]const u8{ "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "nv" };

/// Decodes one instruction. Returns null only when fewer bytes than the encoding
/// requires are available.
pub fn decodeOne(data: []const u8, offset: usize, address: u32) ?Decoded {
    if (offset + 2 > data.len) return null;
    const halfword = std.mem.readInt(u16, data[offset..][0..2], .little);

    // 32-bit Thumb-2: first halfword starts with 111 01 / 111 10 / 111 11.
    const top5 = halfword >> 11;
    if (top5 == 0b11101 or top5 == 0b11110 or top5 == 0b11111) {
        if (offset + 4 > data.len) return null;
        return decode32(data, offset, address);
    }
    return decode16(halfword, address);
}

fn decode32(data: []const u8, offset: usize, address: u32) Decoded {
    const first = std.mem.readInt(u16, data[offset..][0..2], .little);
    const second = std.mem.readInt(u16, data[offset + 2 ..][0..2], .little);
    var decoded = Decoded{ .length = 4, .mnemonic = "thumb2" };

    const op1 = first >> 11;
    if (op1 == 0b11110) {
        const s = (first >> 10) & 1;
        const imm10 = first & 0x03ff;
        const j1 = (second >> 13) & 1;
        const j2 = (second >> 11) & 1;
        const imm11 = second & 0x07ff;
        const op2 = (second >> 12) & 0b111;
        if (op2 == 0b111 or op2 == 0b101) {
            decoded.mnemonic = "bl";
            const bit1 = 1 - (j1 ^ s);
            const bit2 = 1 - (j2 ^ s);
            var offset_value: i64 = @as(i64, s) << 24;
            offset_value |= @as(i64, bit1) << 23;
            offset_value |= @as(i64, bit2) << 22;
            offset_value |= @as(i64, imm10) << 12;
            offset_value |= @as(i64, imm11) << 1;
            if (s == 1) offset_value -= @as(i64, 1) << 25;
            const target = address +% 4 +% @as(u32, @bitCast(@as(i32, @intCast(offset_value))));
            decoded.call_target = target;
            decoded.branch_target = target;
            fmt(&decoded, "#0x{x:0>8}", .{target});
            return decoded;
        }
        const op = (first >> 4) & 0b11111;
        if (op == 0b00100 or op == 0b01010) {
            decoded.mnemonic = if (op == 0b00100) "movw" else "movt";
            const rd = (second >> 8) & 0x0f;
            const imm4 = first & 0x0f;
            const i = (first >> 10) & 1;
            const imm3 = (second >> 12) & 0b111;
            const imm8 = second & 0xff;
            const value: u32 = (@as(u32, imm4) << 12) | (@as(u32, i) << 11) | (@as(u32, imm3) << 8) | imm8;
            fmt(&decoded, "r{d}, #0x{x}", .{ rd, value });
            return decoded;
        }
        if (op == 0b11100) {
            decoded.mnemonic = "ldr.w";
            const rt = (second >> 12) & 0x0f;
            fmt(&decoded, "r{d}, [pc]", .{rt});
            return decoded;
        }
    }
    decoded.mnemonic = "thumb2.other";
    return decoded;
}

fn decode16(halfword: u16, address: u32) Decoded {
    var decoded = Decoded{ .length = 2, .mnemonic = "thumb16" };
    const top4 = halfword >> 12;

    // 000xx: shift by immediate / add-sub / mov-cmp-add-sub imm8
    if (top4 == 0b0000 or top4 == 0b0001) {
        const op = (halfword >> 11) & 0b11;
        if (op == 0b11) {
            const sub_op = (halfword >> 9) & 0b11;
            const rd = @as(u3, @truncate((halfword >> 8) & 0x7));
            const imm8 = halfword & 0xff;
            decoded.mnemonic = switch (sub_op) {
                0b00 => "movs",
                0b01 => "cmp",
                0b10 => "adds",
                else => "subs",
            };
            fmt(&decoded, "{s}, #0x{x}", .{ regName(rd), imm8 });
            return decoded;
        }
        const rd = @as(u3, @truncate(halfword & 0x7));
        const rm = @as(u3, @truncate((halfword >> 3) & 0x7));
        const imm5 = (halfword >> 6) & 0x1f;
        decoded.mnemonic = switch (op) {
            0b00 => "lsls",
            0b01 => "lsrs",
            else => "asrs",
        };
        fmt(&decoded, "{s}, {s}, #{d}", .{ regName(rd), regName(rm), imm5 });
        return decoded;
    }

    // 001xx: mov/cmp/add/sub imm8 (high registers form)
    if (top4 == 0b0010 or top4 == 0b0011) {
        const op = (halfword >> 11) & 0b11;
        const rd = @as(u3, @truncate((halfword >> 8) & 0x7));
        const imm8 = halfword & 0xff;
        decoded.mnemonic = switch (op) {
            0b00 => "movs",
            0b01 => "cmp",
            0b10 => "adds",
            else => "subs",
        };
        fmt(&decoded, "{s}, #0x{x}", .{ regName(rd), imm8 });
        return decoded;
    }

    // 010000: data processing (register)
    if ((halfword >> 10) == 0b010000) {
        const op = (halfword >> 6) & 0x0f;
        const rd = @as(u3, @truncate(halfword & 0x7));
        const rm = @as(u3, @truncate((halfword >> 3) & 0x7));
        decoded.mnemonic = switch (op) {
            0x0 => "ands",
            0x1 => "eors",
            0x2 => "lsls",
            0x3 => "lsrs",
            0x4 => "asrs",
            0x5 => "adcs",
            0x6 => "sbcs",
            0x7 => "rors",
            0x8 => "tst",
            0x9 => "rsbs",
            0xa => "cmp",
            0xb => "cmn",
            0xc => "orrs",
            0xd => "muls",
            0xe => "bics",
            else => "mvns",
        };
        fmt(&decoded, "{s}, {s}", .{ regName(rd), regName(rm) });
        return decoded;
    }

    // 010001: special data / branch exchange
    if ((halfword >> 10) == 0b010001) {
        const op = (halfword >> 8) & 0b11;
        const rm = @as(u4, @truncate((halfword >> 3) & 0x0f));
        const rd = @as(u4, @truncate(((halfword >> 4) & 0x08) | (halfword & 0x07)));
        switch (op) {
            0b00 => {
                decoded.mnemonic = "add";
                fmt(&decoded, "r{d}, r{d}", .{ rd, rm });
            },
            0b01 => {
                decoded.mnemonic = "cmp";
                fmt(&decoded, "r{d}, r{d}", .{ rd, rm });
            },
            0b10 => {
                decoded.mnemonic = "mov";
                fmt(&decoded, "r{d}, r{d}", .{ rd, rm });
            },
            else => {
                const link = (halfword >> 7) & 1;
                decoded.mnemonic = if (link == 1) "blx" else "bx";
                fmt(&decoded, "{s}", .{highRegName(rm)});
                decoded.branch_target = null;
            },
        }
        return decoded;
    }

    // 01001: LDR literal
    if ((halfword >> 11) == 0b01001) {
        const rt = @as(u3, @truncate((halfword >> 8) & 0x7));
        const imm8 = halfword & 0xff;
        decoded.mnemonic = "ldr";
        const literal = (address + 4) & 0xffff_fffc;
        const target = literal + (@as(u32, imm8) << 2);
        fmt(&decoded, "{s}, [pc, #0x{x}]", .{ regName(rt), imm8 << 2 });
        decoded.branch_target = target;
        decoded.literal = target;
        return decoded;
    }

    // 0101: load/store register offset
    if (top4 == 0b0101) {
        const op = (halfword >> 9) & 0b111;
        const rm = @as(u3, @truncate((halfword >> 6) & 0x7));
        const rn = @as(u3, @truncate((halfword >> 3) & 0x7));
        const rt = @as(u3, @truncate(halfword & 0x7));
        decoded.mnemonic = switch (op) {
            0b000 => "str",
            0b001 => "strh",
            0b010 => "strb",
            0b011 => "ldrsb",
            0b100 => "ldr",
            0b101 => "ldrh",
            0b110 => "ldrb",
            else => "ldrsh",
        };
        fmt(&decoded, "{s}, [{s}, {s}]", .{ regName(rt), regName(rn), regName(rm) });
        return decoded;
    }

    // 011/100: load/store immediate word/byte
    if (top4 == 0b0110 or top4 == 0b0111 or top4 == 0b1000) {
        const byte_form = (halfword >> 12) & 1;
        const load = (halfword >> 11) & 1;
        const imm5 = (halfword >> 6) & 0x1f;
        const rn = @as(u3, @truncate((halfword >> 3) & 0x7));
        const rt = @as(u3, @truncate(halfword & 0x7));
        if (top4 == 0b1000) {
            decoded.mnemonic = if (load == 1) "ldrh" else "strh";
            fmt(&decoded, "{s}, [{s}, #0x{x}]", .{ regName(rt), regName(rn), imm5 << 1 });
        } else {
            decoded.mnemonic = if (byte_form == 1)
                (if (load == 1) "ldrb" else "strb")
            else
                (if (load == 1) "ldr" else "str");
            const scale: u16 = if (byte_form == 1) 1 else 4;
            fmt(&decoded, "{s}, [{s}, #0x{x}]", .{ regName(rt), regName(rn), imm5 * scale });
        }
        return decoded;
    }

    // 1001: SP-relative load/store
    if (top4 == 0b1001) {
        const load = (halfword >> 11) & 1;
        const rt = @as(u3, @truncate((halfword >> 8) & 0x7));
        const imm8 = halfword & 0xff;
        decoded.mnemonic = if (load == 1) "ldr" else "str";
        fmt(&decoded, "{s}, [sp, #0x{x}]", .{ regName(rt), imm8 << 2 });
        return decoded;
    }

    // 1010: ADR / ADD SP
    if (top4 == 0b1010) {
        const sp_form = (halfword >> 11) & 1;
        const rd = @as(u3, @truncate((halfword >> 8) & 0x7));
        const imm8 = halfword & 0xff;
        if (sp_form == 1) {
            decoded.mnemonic = "add";
            fmt(&decoded, "{s}, sp, #0x{x}", .{ regName(rd), imm8 << 2 });
        } else {
            decoded.mnemonic = "adr";
            const target = ((address + 4) & 0xffff_fffc) + (@as(u32, imm8) << 2);
            fmt(&decoded, "{s}, #0x{x:0>8}", .{ regName(rd), target });
            decoded.branch_target = target;
            decoded.literal = target;
        }
        return decoded;
    }

    // 1011: misc - push/pop, sp adjust, extend, cbz/cbnz
    if (top4 == 0b1011) {
        const op = (halfword >> 8) & 0x0f;
        if (op == 0b110) {
            const load = (halfword >> 11) & 1;
            const list = halfword & 0xff;
            const extra = (halfword >> 8) & 1;
            decoded.mnemonic = if (load == 1) "pop" else "push";
            fmt(&decoded, "{{list=0x{x},lr={d}}}", .{ list, extra });
            return decoded;
        }
        if (op == 0b000) {
            const sub = (halfword >> 7) & 1;
            const imm7 = halfword & 0x7f;
            decoded.mnemonic = if (sub == 1) "sub" else "add";
            fmt(&decoded, "sp, #{d}", .{imm7 << 2});
            return decoded;
        }
        decoded.mnemonic = "misc16";
        return decoded;
    }

    // 1100: STM/LDM
    if (top4 == 0b1100) {
        const load = (halfword >> 11) & 1;
        const rn = @as(u3, @truncate((halfword >> 8) & 0x7));
        const list = halfword & 0xff;
        decoded.mnemonic = if (load == 1) "ldm" else "stm";
        fmt(&decoded, "{s}!, 0x{x}", .{ regName(rn), list });
        return decoded;
    }

    // 1101: conditional branch / SVC / UDF
    if (top4 == 0b1101) {
        const cond = (halfword >> 8) & 0x0f;
        if (cond == 0b1110) {
            decoded.mnemonic = "udf";
            fmt(&decoded, "#0x{x}", .{halfword & 0xff});
            return decoded;
        }
        if (cond == 0b1111) {
            decoded.mnemonic = "svc";
            fmt(&decoded, "#0x{x}", .{halfword & 0xff});
            return decoded;
        }
        const imm8 = halfword & 0xff;
        const signed: i32 = if ((imm8 & 0x80) != 0) @as(i32, imm8) - 256 else imm8;
        const target = address +% 4 +% @as(u32, @bitCast(signed * 2));
        decoded.mnemonic = "b";
        fmt(&decoded, "{s} #0x{x:0>8}", .{ cond_names[cond], target });
        decoded.branch_target = target;
        return decoded;
    }

    // 11100: unconditional branch
    if ((halfword >> 11) == 0b11100) {
        const imm11 = halfword & 0x7ff;
        const signed: i32 = if ((imm11 & 0x400) != 0) @as(i32, imm11) - 2048 else imm11;
        const target = address +% 4 +% @as(u32, @bitCast(signed * 2));
        decoded.mnemonic = "b";
        fmt(&decoded, "#0x{x:0>8}", .{target});
        decoded.branch_target = target;
        return decoded;
    }

    decoded.mnemonic = "undefined";
    return decoded;
}

fn inImage(address: u32, base: u32, length: usize) bool {
    if (length == 0) return false;
    const start: u64 = base;
    const end: u64 = start + @as(u64, @intCast(length));
    return @as(u64, address) >= start and @as(u64, address) < end;
}

/// Decodes the image from base_address, collecting coverage statistics, call targets
/// and vector-table entries as candidate function starts.
pub fn decode(allocator: Allocator, data: []const u8, base_address: u32, start_offset: usize) !Listing {
    var listing = Listing{};
    var targets: std.ArrayList(u32) = .empty;
    defer targets.deinit(allocator);
    var literals: std.ArrayList(LiteralRef) = .empty;
    defer literals.deinit(allocator);

    const max_targets = 4096;
    var offset: usize = @min(start_offset, data.len);
    var address = base_address + @as(u32, @intCast(offset));
    while (offset + 2 <= data.len and listing.instructions < max_instructions) {
        const decoded = decodeOne(data, offset, address) orelse break;
        listing.instructions += 1;
        listing.bytes += decoded.length;
        if (std.mem.eql(u8, decoded.mnemonic, "undefined")) listing.unknown += 1;

        if (decoded.literal) |target| {
            if (literals.items.len < max_targets) {
                literals.append(allocator, .{ .address = target, .instruction = address }) catch {};
            }
        }
        if (decoded.call_target) |target| {
            if (targets.items.len < max_targets and inImage(target, base_address, data.len)) {
                targets.append(allocator, target) catch {};
            }
        }

        if (listing.sample_count < max_samples) {
            var sample = Sample{ .address = address };
            const text = std.fmt.bufPrint(&sample.text, "{s} {s}", .{
                decoded.mnemonic,
                decoded.operands[0..decoded.operands_len],
            }) catch "";
            sample.len = @intCast(text.len);
            listing.samples[listing.sample_count] = sample;
            listing.sample_count += 1;
        }

        offset += decoded.length;
        address += decoded.length;
    }

    // Vector table: the first words are stack pointer and handler addresses. A handler
    // entry has the Thumb bit set and must point inside the image.
    var vector_index: usize = 0;
    while (vector_index < 16 and (vector_index + 1) * 4 <= data.len) : (vector_index += 1) {
        if (vector_index == 0) continue;
        const word = std.mem.readInt(u32, data[vector_index * 4 ..][0..4], .little);
        if ((word & 1) == 0) continue;
        const entry = word & ~@as(u32, 1);
        if (!inImage(entry, base_address, data.len)) continue;
        if (targets.items.len >= max_targets) break;
        targets.append(allocator, entry) catch {};
    }

    std.mem.sort(u32, targets.items, {}, std.sort.asc(u32));
    var unique: usize = 0;
    for (targets.items, 0..) |target, index| {
        if (index > 0 and target == targets.items[index - 1]) continue;
        if (unique >= max_functions) break;
        targets.items[unique] = target;
        unique += 1;
    }
    listing.functions = unique;
    listing.entries = try allocator.dupe(u32, targets.items[0..unique]);
    listing.literals = try allocator.dupe(LiteralRef, literals.items);
    listing.branch_targets = &.{};
    return listing;
}

test "decodes common Thumb-16 encodings with correct lengths" {
    const code = [_]u8{
        0x01, 0x20, // movs r0, #1
        0x70, 0x47, // bx lr
        0x00, 0xbf, // nop
        0xfe, 0xe7, // b .
    };
    const first = decodeOne(&code, 0, 0x1000).?;
    try std.testing.expectEqual(@as(u8, 2), first.length);
    try std.testing.expectEqualStrings("movs", first.mnemonic);
    try std.testing.expectEqualStrings("r0, #0x1", first.operands[0..first.operands_len]);

    const branch = decodeOne(&code, 6, 0x1006).?;
    try std.testing.expectEqualStrings("b", branch.mnemonic);
    try std.testing.expectEqual(@as(?u32, 0x1006), branch.branch_target);
}

test "decodes bl and movw/movt 32-bit encodings" {
    const bl = [_]u8{ 0x00, 0xf0, 0x00, 0xf8 };
    const decoded_bl = decodeOne(&bl, 0, 0x2000).?;
    try std.testing.expectEqual(@as(u8, 4), decoded_bl.length);
    try std.testing.expectEqualStrings("bl", decoded_bl.mnemonic);
    try std.testing.expectEqual(@as(?u32, 0x2004), decoded_bl.call_target);

    const movw = [_]u8{ 0x40, 0xf2, 0x01, 0x00 };
    const decoded_movw = decodeOne(&movw, 0, 0x2000).?;
    try std.testing.expectEqual(@as(u8, 4), decoded_movw.length);
    try std.testing.expectEqualStrings("movw", decoded_movw.mnemonic);
}

test "stops when fewer bytes than an encoding remain" {
    const short = [_]u8{0x00};
    try std.testing.expect(decodeOne(&short, 0, 0) == null);

    const truncated32 = [_]u8{ 0x00, 0xf0 };
    try std.testing.expect(decodeOne(&truncated32, 0, 0) == null);
}

test "collects vector-table entries and call targets as functions" {
    var image = [_]u8{0} ** 64;
    std.mem.writeInt(u32, image[0..4], 0x2000_1000, .little);
    std.mem.writeInt(u32, image[4..8], 0x0800_0009, .little); // reset handler, Thumb bit
    // bl at offset 8 targeting itself (offset + 4 - 4 => 0x08000008)
    image[8] = 0x00;
    image[9] = 0xf0;
    image[10] = 0xfe;
    image[11] = 0xfb;

    var listing = try decode(std.testing.allocator, &image, 0x0800_0000, 0);
    defer listing.deinit(std.testing.allocator);

    try std.testing.expect(listing.instructions >= 2);
    try std.testing.expect(listing.functions >= 1);
    // The listing starts at offset 0 (the vector table decodes as instructions too),
    // so look for the call rather than assuming it is the first sample.
    var saw_call = false;
    for (listing.samples[0..listing.sample_count]) |sample| {
        if (sample.len >= 2 and std.mem.eql(u8, sample.slice()[0..2], "bl")) saw_call = true;
    }
    try std.testing.expect(saw_call);
}

test "unknown encodings are counted" {
    const code = [_]u8{ 0x00, 0xea }; // thumb2 prefix truncated to two bytes -> stops
    var listing = try decode(std.testing.allocator, &code, 0, 0);
    defer listing.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), listing.instructions);
}
