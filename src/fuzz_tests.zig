const std = @import("std");
const dhcp = @import("formats/dhcp.zig");
const dhcpv6 = @import("formats/dhcpv6.zig");
const dns = @import("formats/dns.zig");
const flipper_format = @import("formats/flipper_format.zig");
const nbns = @import("formats/nbns.zig");
const ssdp = @import("formats/ssdp.zig");
const tls_certificate = @import("formats/tls_certificate.zig");
const badusb = @import("protocols/badusb.zig");
const ibutton = @import("protocols/ibutton.zig");
const infrared = @import("protocols/infrared.zig");
const lfrfid = @import("protocols/lfrfid.zig");
const nfc = @import("protocols/nfc.zig");
const nmap = @import("protocols/nmap.zig");
const nuclei = @import("protocols/nuclei.zig");
const pcap = @import("protocols/pcap.zig");
const subghz = @import("protocols/subghz.zig");

const empty_pcap = [_]u8{
    0xd4, 0xc3, 0xb2, 0xa1, // little-endian, microsecond timestamps
    0x02, 0x00, 0x04, 0x00, // version 2.4
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, // snaplen 65535
    0x01, 0x00, 0x00, 0x00, // Ethernet
};

const badusb_seed = fuzzSeed(
    \\REM fuzz seed
    \\STRING PocketRoot
    \\
);
const ibutton_seed = fuzzSeed(
    \\Filetype: Flipper iButton key
    \\Version: 2
    \\Protocol: DS1990
    \\Rom Data: 01 23 45 67 89 AB CD E9
    \\
);
const infrared_seed = fuzzSeed(
    \\Filetype: IR signals file
    \\Version: 1
    \\name: fuzz
    \\type: parsed
    \\protocol: NEC
    \\address: DF 20 00 00
    \\command: EF 10 00 00
    \\
);
const lfrfid_seed = fuzzSeed(
    \\Filetype: Flipper RFID key
    \\Version: 1
    \\Key type: EM4100
    \\Data: 01 23 45 67 89
    \\
);
const nfc_seed = fuzzSeed(
    \\Filetype: Flipper NFC device
    \\Version: 4
    \\Device type: ISO14443-3A
    \\UID: 04 48 6A 32 33 58 80
    \\ATQA: 00 44
    \\SAK: 00
    \\
);
const nmap_seed = fuzzSeed("<nmaprun scanner=\"nmap\"><host><status state=\"up\"/></host></nmaprun>");
const nuclei_seed = fuzzSeed("{\"template-id\":\"seed\",\"info\":{\"name\":\"seed\",\"severity\":\"info\"},\"host\":\"https://example.test\"}\n");
const subghz_seed = fuzzSeed(
    \\Filetype: Flipper SubGhz Key File
    \\Version: 1
    \\Frequency: 433920000
    \\Preset: FuriHalSubGhzPresetOok650Async
    \\Protocol: Princeton
    \\Bit: 24
    \\Key: 00 00 00 00 00 AB CD EF
    \\TE: 400
    \\
);
const pcap_seed = fuzzSeed(&empty_pcap);

const corpus = [_][]const u8{
    &badusb_seed,
    &ibutton_seed,
    &infrared_seed,
    &lfrfid_seed,
    &nfc_seed,
    &nmap_seed,
    &nuclei_seed,
    &subghz_seed,
    &pcap_seed,
};

test "untrusted parsers remain bounded under fuzz input" {
    try std.testing.fuzz({}, fuzzParsers, .{ .corpus = &corpus });
}

fn fuzzParsers(_: void, smith: *std.testing.Smith) !void {
    @disableInstrumentation();
    var storage: [4096]u8 = undefined;
    const length = smith.slice(&storage);
    const data = storage[0..length];

    _ = dhcp.decode(data) catch {};
    var dhcpv6_name_buffer: [dhcpv6.max_fqdn_text_len]u8 = undefined;
    _ = dhcpv6.decode(data, &dhcpv6_name_buffer) catch {};
    _ = ssdp.decode(data) catch {};
    _ = tls_certificate.parseNegotiated(data) catch {};
    _ = tls_certificate.parseHello(data) catch {};
    if (flipper_format.parse(std.testing.allocator, data)) |document_value| {
        var document = document_value;
        document.deinit();
    } else |_| {}

    var nbns_name_buffer: [nbns.max_name_text_len]u8 = undefined;
    _ = nbns.decodeFirstQuestion(data, &nbns_name_buffer) catch {};
    if (nbns.answers(data)) |iterator_value| {
        var iterator = iterator_value;
        while (iterator.next(&nbns_name_buffer) catch null) |_| {}
    } else |_| {}

    var name_buffer: [dns.max_name_text_len]u8 = undefined;
    _ = dns.decodeFirstQuestion(data, .dns, &name_buffer) catch {};
    if (dns.answers(data, .dns)) |iterator_value| {
        var iterator = iterator_value;
        var owner_buffer: [dns.max_name_text_len]u8 = undefined;
        var value_buffer: [dns.max_name_text_len]u8 = undefined;
        while (iterator.next(&owner_buffer, &value_buffer) catch null) |_| {}
    } else |_| {}
    if (dns.authority(data, .dns)) |iterator_value| {
        var iterator = iterator_value;
        var owner_buffer: [dns.max_name_text_len]u8 = undefined;
        var value_buffer: [dns.max_name_text_len]u8 = undefined;
        while (iterator.next(&owner_buffer, &value_buffer) catch null) |_| {}
    } else |_| {}

    fuzzAnalysis(badusb.analyzeText, data);
    fuzzAnalysis(ibutton.analyzeText, data);
    fuzzAnalysis(infrared.analyzeText, data);
    fuzzAnalysis(lfrfid.analyzeText, data);
    fuzzAnalysis(nfc.analyzeText, data);
    fuzzAnalysis(nmap.analyzeText, data);
    fuzzAnalysis(nuclei.analyzeText, data);
    fuzzAnalysis(pcap.analyzeCapture, data);
    fuzzAnalysis(subghz.analyzeText, data);
}

fn fuzzAnalysis(comptime analyze: anytype, data: []const u8) void {
    @disableInstrumentation();
    if (analyze(std.testing.allocator, data)) |result_value| {
        var result = result_value;
        result.deinit();
    } else |_| {}
}

// ponytail: Zig 0.16 Smith.slice seed encoding; replace when std exposes a corpus builder.
fn fuzzSeed(comptime data: []const u8) [4 + data.len]u8 {
    var seed: [4 + data.len]u8 = undefined;
    std.mem.writeInt(u32, seed[0..4], @intCast(data.len), .little);
    @memcpy(seed[4..], data);
    return seed;
}
