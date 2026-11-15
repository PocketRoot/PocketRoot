# Offline file analysis

All analysis here is offline, deterministic and uses no network. Input files are limited
to 64 MiB (`services/storage.zig`). Adding a format is described in
[`protocols/README.md`](../protocols/README.md).

## 1. Protocol plugins

| id | Name | Category | Extensions | Auto-detect | Implementation |
|---|---|---|---|---|---|
| `subghz` | Sub-GHz | Signal | `.sub` | yes | `protocols/subghz.zig` |
| `infrared` | Infrared | Signal | `.ir` | yes | `protocols/infrared.zig` |
| `nfc` | NFC | Credential | `.nfc` | yes | `protocols/nfc.zig` |
| `lfrfid` | 125 kHz RFID | Credential | `.rfid` | yes | `protocols/lfrfid.zig` |
| `ibutton` | iButton | Access | `.ibtn` | yes | `protocols/ibutton.zig` |
| `pcap` | Packet capture | Network | `.pcap`, `.pcapng` | yes | `protocols/pcap.zig` |
| `badusb` | BadUSB script | Script | `.txt` | manual | `protocols/badusb.zig` |
| `nmap` | Nmap results | Network | `.xml` | manual | `protocols/nmap.zig` |
| `nuclei` | Nuclei results | Network | `.jsonl` | manual | `protocols/nuclei.zig` |
| `firmware` | Firmware image | Firmware | `.bin`, `.elf`, `.hex`, `.img` | manual | `protocols/firmware.zig` |

Manual protocols require `--protocol <id>`; directory scans report them as unknown and
skip them.

## 2. Validation depth per format

Shared base: `formats/flipper_format.zig` parses line-oriented `key: value` files,
treats `#` as a comment, keeps duplicate keys (`first()` returns the first, `count()`
counts them), accepts decimal and `0x` hexadecimal values, and requires every token
passed to `parseHexBytes` to be exactly two hexadecimal digits.

| Format | Validation | Findings produced |
|---|---|---|
| `subghz` | Filetype in {Key File, RAW File}; Version=1; frequency; preset; protocol. RAW additionally requires strictly alternating timing signs, non-zero values, at most 512 timings per line and at most 128K in total | none; violations are errors |
| `infrared` | Filetype `IR signals file`; `type` must be `parsed`; single and multi-signal files are handled separately | multi-signal files report counts only |
| `nfc` | Filetype `Flipper NFC device`; version 1-4; UID of 4-10 bytes; ATQA/SAK/ATS/application data/protocol info validated per device type | version < 4: `info`; unknown device type: `warning` |
| `lfrfid` | Filetype `Flipper RFID key`; Version=1; key type; hexadecimal data | unknown key type: `warning` |
| `ibutton` | Filetype `Flipper iButton key`; version 1 or 2; v1 uses `Key type`/`Data`, v2 uses `Protocol`/`Rom Data`; Dallas ROMs must be 8 bytes | CRC-8 mismatch: `warning` (except DSGeneric); v1 legacy layout: `info` |
| `badusb` | Static Duckyscript validation: 30+ instructions, VID:PID, key names, media keys, mouse parameters, modifier combinations; `REPEAT` requires a preceding command; timing is estimated | invalid instruction or parameter: `warning` with a line number |
| `nmap` | Hand-written XML parser: single `nmaprun` root, tag pairing, attribute validation; extracts host/status/address/hostname/port/state/service/script | open port: `info`; script: `info` |
| `nuclei` | One JSON object per line; requires `template-id` (or `templateID`), `info.name`, `info.severity`; target taken from `matched-at`, then `host`, then `ip` | malformed line: `warning` and parsing continues; otherwise the record's severity |
| `pcap` | See section 3 | open ports, cleartext HTTP, TLS and similar: findings |
| `firmware` | Container detection (ELF magic, Intel HEX, raw); 1024-byte block entropy scaled by 100; ASCII and UTF-16LE string scan (4+ characters, 8 previews); Cortex-M vector table heuristic; Thumb disassembly from the reset handler reporting `instructions`, `unknown_opcodes`, `decode_coverage_x100`, `functions` and four instruction samples; literal-pool cross references as `literal_refs`, `strings_referenced`, `pointer_refs`, `xref_N` (including pointer words read from LDR literal slots) | high-entropy region: `info`; raw image without a valid vector table: `warning`; decode coverage below 95%: `warning` |

The `ibutton` CRC-8 is implemented in this repository (`maximCrc8`, reflected
polynomial 0x8C) with a test vector `01 23 45 67 89 AB CD` -> `E9`.

Firmware entropy and string fields carry offsets so the result can be reproduced with
host tools. Decode coverage counts encoding sync, not mnemonic fidelity: valid but
unmodelled encodings are named after their group and are not counted as unknown.

## 3. pcap parser (`protocols/pcap.zig`)

Container support:

- Classic pcap with four magic variants (little/big endian, microsecond/nanosecond).
- pcapng with Section Header, Interface Description, Enhanced Packet and Simple Packet
  blocks; reports mixed byte order and per-section interfaces.
- Length consistency: `snaplen >= captured`, `captured <= original`, block alignment and
  bounds checks.

Protocol layers:

| Layer | Support |
|---|---|
| Link | Ethernet, raw IP, legacy linktype name mapping |
| Network | ARP, IPv4 (including fragmentation counters), IPv6 with extension headers |
| Transport | UDP, TCP with stream reassembly, ICMPv6 with checksum verification and NDP options |
| Application | DNS, mDNS, LLMNR (separate counters and an mDNS service graph), NBNS, DHCP, DHCPv6, SSDP, HTTP direction classification, TLS ClientHello/ServerHello (SNI, ALPN, highest version) |

TCP reassembly groups segments by four-tuple, orders by sequence number, queues
out-of-order segments, and enforces stream and byte limits. Reported counters include
`tcp_reassembled_streams`, `tcp_reassembly_segments`, `tcp_reassembly_bytes` and
`tcp_out_of_order_segments`.

The parser reports more than 50 numeric fields plus structured observations. The summary
line lists packet counts per protocol and the number of malformed packets.

The parser is read-only: it never generates or repairs a capture file.

## 4. `migrate`

```
migrate [--protocol <id>] <input> <output>
  resolve the descriptor by extension or --protocol
  analyze(input)      // validation only
  copy(input bytes)   // unchanged
  write(output)
```

`migrate` proves that a file is valid and can be preserved byte for byte. It is not a
format converter. The test `registered samples support byte-exact validated migration`
asserts a round trip for every plugin that provides a sample.

## 5. `project` and `archive`

- `archive [root]` walks a directory, maps extensions to protocols and does not parse
  content. Limit: 512 entries.
- `project` analyses every input (file or directory) and deduplicates on
  `(protocol.id, artifact.sha256)`; repeats are counted as `duplicate_artifacts`.
- Findings and observations are marked first-seen or duplicate across analyses, which
  yields the unique and duplicate counts in the report.
- `--json` emits `pocketroot.project.v1`.

`project samples` reports unique and skipped totals at run time: a skipped file has no
extension match, or its protocol is manual and was not named with `--protocol`. The counts
follow the sample tree instead of a constant.
