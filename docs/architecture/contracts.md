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
protocols: `badusb` (.txt), `nmap` (.xml), `nuclei` (.jsonl), `firmware` (.bin/.elf/.hex/.img),
`cyclonedx` (.cdx.json), `spdx` (.spdx.json) and `npm-lock` (.package-lock.json).

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

### 3.1 Host entry point

`services/device_host.zig` wires the kernel to a runnable service: policy, simulated
backend, subject, an optional JSONL sink (`pocketroot.audit.v1`) and the PKRT frame loop.
The CLI exposes it as `device info`, `device request` and `device serve`; `audit` reads the
JSONL sink back. `device serve` accepts request frames on stdin (`--transport stdio`) or
from a recorded stream (`--transport loopback --frames <path>`) and writes response frames
to stdout or `--output <path>`. Responses are byte-identical to a device's, so external
tooling can replay a session without the engine.

### 3.2 Campaign control plane

`services/control.zig` gates actions against a target rather than device operations. The
CLI exposes it through `campaign` subcommands.

```zig
Scope    { id, targets[], techniques[], expires_at_unix, approval_ttl_seconds, max_actions }
Approval { id, scope_id, action_id, target, technique, params_hash, operator, reason,
           created_at_unix, expires_at_unix, used }
ActionRequest { action_id, target, technique, params_hash }
```

`evaluate` is the single decision point: stop marker, armed phase, scope expiry, scope match,
action budget, target, technique, then a live single-use approval bound to the exact action.
The approval is consumed before the action starts; a failed action does not refund it.

The TTL is configurable per scope (`approval_ttl_seconds`, 1-86400, default 900) and the
effective expiry is the earlier of that TTL and the scope expiry. The read-only surface
(`services/surface.zig`) never calls `evaluate` and never needs an approval.

```
campaign init --scope <scope.json> [--dir <dir>]
campaign arm|stop|status [--dir <dir>]
campaign surface --catalog <catalog.jsonl> [--json] <path>...
campaign approve <ACTION-ID> --reason <text> --confirm <ACTION-ID>
campaign run <ACTION-ID> --dry-run
```

In this build `campaign run` refuses anything except `--dry-run`: the gate, consumption and
ledger are real, the executor is not.

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
rejects replayed frames. `device serve` applies the same replay rule to every incoming
request frame.

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

### 4.1 `net.http` request spec

The DSL compiles a `net.http` call into a JSON payload carried by the network capability:

```json
{"kind":"http","target":"127.0.0.1:8080","method":"GET","path":"/cgi-bin/.%2e/etc/passwd","body":"","headers":[],"timeout_ms":2000,"expect_status":200,"expect_body":"root:x:0:0","expect_absent":""}
```

A `net.udp` call compiles to `{"kind":"udp","target":...,"data":...,"timeout_ms":...,"expect_min_bytes":...,"expect_body":...,"expect_absent":...}`.

The live backend dispatches HTTP to `services/http_probe.zig`, UDP to `services/udp_probe.zig`; the capability kernel, audit
subject and workflow are unchanged. The probe result is a key=value payload with
`status`, `status_line`, `body_bytes`, `body_prefix`, `oracle` and `oracle_reason`.

### 4.2 `pocketroot.exploit.v1`

An exploit record is an ordered HTTP chain. Template variables are substituted before each
step: `{{target}}`, `{{command}}`, `{{command_raw}}`, `{{command_url}}`, `{{file}}`,
`{{file_url}}`, `{{marker_start}}`, `{{marker_end}}` and captured names. `capture` stores
the text between two delimiters; `extract` returns the effect between two delimiters.
`effect: command` requires an extract (the runner wraps the command in markers);
`effect: read_file` falls back to the final response body.

### 4.3 `exploit.plan` capability payload

```json
{"kind":"exploit","mode":"plan","surface":"samples/campaign/surface-lab.json","records":"samples/exploits","target":""}
```

It maps to `Kind.exploit` + `Operation.analyze` (passive). A run spec
`{"kind":"exploit","mode":"run","plan":"chain.json","campaign":".pocketroot"}` maps to
`Operation.manage` (active): the kernel requires active authorization and the handler
requires a live plan approval; it never mints one. The result data is the
`pocketroot.chain.v1` plan. `Operation.manage` on `Kind.exploit` is deliberately
unsupported by the simulator backend; execution stays on the campaign-gated `chain run`
path.

### 4.4 `pocketroot.chain.v1`

A plan step records `cve`, `record` path, `effect`, `target` and the record byte
digest. `chain run` re-hashes each record before executing it. The approval binds the
plan bytes (not each record), so one approval covers the chain while any plan or record
change invalidates it. STOP is checked before and after every step.

## 5. Schema identifiers

| Schema | Location | Purpose |
|---|---|---|
| `pocketroot.vulnerability.v2` | `services/vulnerability_catalog.zig` | One catalogue line (vendors, aliases, CVSS, references, inclusive ranges) |
| `pocketroot.vulnerability.v1` | `services/vulnerability_catalog.zig` | Legacy catalogue line, still accepted |
| `pocketroot.vulnerability.provenance.v1` | validated by the catalogue repository script | Provenance pointer |
| `pocketroot.audit.v1` | `services/audit_log.zig` | One exported audit line (host entry) |
| `pocketroot.analysis.v1` | CLI JSON output | One analysis |
| `pocketroot.script.v1` | `services/script.zig` | DSL source and limits |
| `pocketroot.project.v1` | CLI JSON output | Project report |
| `pocketroot.library.v1` | `services/library.zig` | Saved library entries |
| `pocketroot.scope.v1` | `services/control.zig` | Campaign scope, targets and configurable approval TTL |
| `pocketroot.approval.v1` | `services/control.zig` | One single-use human approval |
| `pocketroot.campaign.v1` | `services/control.zig` | Campaign phase and action count |
| `pocketroot.ledger.v1` | `services/control.zig` | Hash-chained campaign ledger entry |
| `pocketroot.surface.v1` | `services/surface.zig` | Attack-surface report and candidate actions |
| `pocketroot.reproduction.v1` | `samples/reproductions/*/record.json` | One reproduction record consumed by `reproduce` |
| `pocketroot.reproduction.evidence.v1` | `cli/main.zig` | One reproduction run, observed outcome and approval id when gated |
| `pocketroot.exploit.v1` | `samples/exploits/*/record.json` | Ordered HTTP steps, capture/extract delimiters and an effect |
| `pocketroot.exploit.evidence.v1` | `cli/main.zig` | Effect output, per-step status and the approval that authorised it |
| `pocketroot.observations.v1` | `samples/observations/*.json` | Target fingerprint input to chain planning |
| `pocketroot.chain.v1` | `chain plan` | Ordered, digest-bound exploit plan for one target |
| `pocketroot.chain.evidence.v1` | `chain run` | One chain execution and its per-step outputs |

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
