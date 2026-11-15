# Contract reference

Limits below are hard-coded constants; changing them breaks existing tests.

## 1. Protocol plugin contract

```zig
pub const ProtocolDescriptor = struct {
    id: []const u8,                          // value for --protocol
    name: []const u8,
    category: []const u8,                    // Signal / Credential / Access / Script / Network
    file_extension: []const u8,              // no leading dot
    additional_extensions: []const []const u8 = &.{},
    media_type: []const u8 = "application/octet-stream",
    auto_detect: bool = true,                // false: only reachable through --protocol
    analyze: AnalyzeFn,                      // fn(allocator, bytes) !AnalysisResult
    analyze_with: ?AnalyzeWithFn = null,     // fn(allocator, data, options) !AnalysisResult
    sample: ?SampleFn = null,                // fn(allocator) ![]u8
};
```

(`src/protocols/protocol.zig`)

### 1.1 Parameterised entry point

Some formats cannot be analysed from bytes alone: firmware needs a load address and an
architecture.

```zig
pub const AnalyzeOptions = struct { architecture: ?[]const u8 = null, base_address: u32 = 0 };
const result = try descriptor.run(allocator, data, options);
```

`analyze` stays mandatory, so existing descriptors are unaffected. `run()` prefers
`analyze_with` when present. `ProtocolWorkbench.analyzePathWith` and `analyzeBytesWith`
forward the options, which is how the CLI passes `--base` and `--arch`.

### 1.2 `validatedCopy` semantics

`validatedCopy` runs `analyze` as validation and then copies the input bytes unchanged.
It never re-encodes and never upgrades a format. The `migrate` command relies on this
byte-exact behaviour, and `registry.zig` asserts a sample round-trip.

### 1.3 `auto_detect = false`

`archive` reports such files as unknown and `project` skips them. Current manual
protocols: `badusb` (.txt), `nmap` (.xml), `nuclei` (.jsonl).

## 2. Result model

### AnalysisResult limits (`src/protocols/protocol.zig`)

| Field | Limit | Error on overflow |
|---|---|---|
| summary | 4 KiB | `SummaryTooLong` |
| fields count | 512 | `TooManyFields` |
| field.name / field.value | 256 B / 4 KiB | `FieldNameTooLong` / `FieldValueTooLong` |
| findings count | 256 | `TooManyFindings` |
| finding.message | 1 KiB | `FindingMessageTooLong` |
| finding.detail | 8 KiB | `FindingDetailTooLong` |
| finding.target | 2 KiB | `FindingTargetTooLong` |
| finding.source_id | 512 B | `FindingSourceIdTooLong` |
| observations count | 1024 | `TooManyObservations` |
| observation.address / hostname | 256 B / 512 B | `ObservationAddressTooLong` / `ObservationHostnameTooLong` |
| observation.transport / service / product / version | 32 / 256 / 256 / 256 B | named errors |
| observation.evidence / source_id | 4 KiB / 512 B | named errors |

All text is duplicated into result-owned memory. Callers may pass temporary buffers, but
must not mutate slices returned by a result.

### FindingSeverity

`info, warning, error, unknown, low, medium, high, critical` (`src/protocols/protocol.zig`).

| Range | Meaning | Examples in the code |
|---|---|---|
| `info`, `warning`, `error` | Format review, not a security rating | `Open TCP port`, `Dallas ROM CRC-8 mismatch`, `Unknown NFC device type` |
| `unknown`, `low`..`critical` | Security rating from a catalogue or a scan result | Catalogue `severity`, nuclei `info.severity` |

The vulnerability catalogue only accepts `unknown/low/medium/high/critical`
(`services/vulnerability_matcher.zig`).

### NetworkObservation confidence

```
kind:       host | name_query | endpoint | service
confidence: inferred < observed < confirmed
```

| Confidence | When it is used | Example |
|---|---|---|
| `confirmed` | Protocol-level evidence, not just a port number | Completed TCP handshake, SSH banner, ICMP echo |
| `observed` | Observed without protocol confirmation | nmap XML import, neighbour cache hit, DHCP/SSDP/NBNS record |
| `inferred` | Pure inference | Service name guessed from a port number |

Vulnerability matching requires version confidence of at least `observed`
(`services/vulnerability_matcher.zig`), so port-guessed products do not produce matches.
Observation deduplication compares every field: the same host with different evidence is
two observations.

## 3. Capability kernel

```zig
Request { id, subject(<=128 B), kind, operation, region, payload(<=1 MiB), active_authorized }
Policy  { region, allow_active, stopped }
Result  { status, data }
```

(`src/core/capability.zig`)

Authorisation runs in this order: `stopped`, empty or oversized `subject`, oversized
`payload`, then for active operations (`write/transmit/emulate/configure/manage`) both
`allow_active` and `active_authorized` must be true; for `subghz` both regions must be
non-empty and equal, otherwise `RegionRequired` or `RegionMismatch`.

Execution records an audit entry for every outcome (denied, busy, failed, and the
backend's own status). Resource locks are exclusive per `Kind` and released on exit.
`emergencyStop()` sets `stopped` and releases all locks. The audit log holds 4096
entries and returns `AuditLogFull` beyond that.

## 4. IPC wire format (`src/device/ipc.zig`)

Little-endian frame layout:

| Offset | Size | Content |
|---|---|---|
| 0 | 4 | magic `"PKRT"` |
| 4 | 1 | version = 1 |
| 5 | 1 | kind: request(1) / response(2) / event(3) / heartbeat(4) / cancel(5) |
| 6 | 4 | sequence (must be non-zero) |
| 10 | 4 | payload length (<= 1 MiB) |
| 14 | N | payload |
| 14+N | 4 | CRC-32 (IEEE; standard vector 0xCBF43926) |

`header_size = 14`, `checksum_size = 4`. `decode` requires an exact length match; one
extra byte yields `InvalidFrameLength`. `Session` increments the send sequence and
rejects replayed frames.

Capability command payload (`src/device/command.zig`):

| Offset | Size | Content |
|---|---|---|
| 0 | 1 | capability kind |
| 1 | 1 | capability operation |
| 2 | 1 | active_authorized (0/1; other values are `InvalidAuthorizationFlag`) |
| 3 | 1 | region length (<= 8) |
| 4 | R | region |
| 4+R | ... | payload |

A response payload starts with the `capability.Status` byte followed by the data.

## 5. Schema identifiers

| Schema | Location | Purpose |
|---|---|---|
| `pocketroot.vulnerability.v1` | `services/vulnerability_catalog.zig` | One catalogue line |
| `pocketroot.vulnerability.provenance.v1` | validated by the catalogue repository script | Provenance pointer |
| `pocketroot.project.v1` | CLI JSON output | Project report |
| `pocketroot.library.v1` | `services/library.zig` | Saved library entries |

The schema identifier is the compatibility boundary. Changing fields without bumping the
version breaks consumers; `UnsupportedCatalogSchema` reports a mismatch.

## 6. Memory and ownership

- Library functions take an explicit `allocator`; every returned value has a `deinit`.
- Result objects own all of their text; only the constant strings inside a
  `ProtocolDescriptor` are borrowed.
- `AssetGraph` matches store indices into the graph and the catalogue rather than copies,
  so both must outlive the report.
- The CLI allocates from an arena, so `defer deinit` there is defensive rather than
  required.
