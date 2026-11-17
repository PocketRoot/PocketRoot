# Capability matrix

The purpose of this page is to separate "implemented in code" from "usable from the CLI".
The I/O column states where the work actually happens.

## 1. CLI commands

| Command | Platform | I/O | Implementation | Limits | Failure semantics |
|---|---|---|---|---|---|
| `help` | any | none | `cli/main.zig` | - | exit 0 |
| `list` | any | none | `printApps` | - | exit 0 |
| `protocols` | any | none | `printProtocols` | - | exit 0 |
| `archive [root]` | any | filesystem | `services/archive.zig` | 512 entries | `TooManyArchiveEntries` |
| `analyze` / `report` | any | filesystem | `ProtocolWorkbench` | file <= 64 MiB | `UnknownProtocol` and friends |
| `project [--json]` | any | filesystem | `services/project.zig` | 256 analyses, 256 issues | `TooManyProjectAnalyses` |
| `vulns <catalog>` | any | filesystem | `vulnerability_matcher` | catalogue 64 MiB, 65536 entries | version mismatch: `UnsupportedCatalogSchema` |
| `migrate` | any | filesystem | `validatedCopy` | same as analyze | rejects identical input and output paths |
| `device info` | any | none | `services/device_host.zig` | - | exit 0 |
| `device request <kind> <op>` | any | simulated | capability kernel + simulated backend | subject <= 128 B, payload <= 1 MiB | denied/failed exits 1 |
| `device serve` | any | stdin/file -> stdout/file | PKRT frame loop | 4096 frames, replay rejection | malformed frame aborts |
| `audit [--json] <path>` | any | filesystem | `services/audit_log.zig` | 8 MiB, 4096 lines | invalid line fails closed |
| `campaign init|arm|stop|status` | any | filesystem | `services/control.zig` | scope <= 64 KiB, TTL 1-86400 s | unarmed or stopped: exit 1 |
| `campaign surface` | any | filesystem (read-only) | `services/surface.zig` | 4096 actions, catalogue 64 MiB | expired scope: exit 1 |
| `campaign approve <ACTION-ID>` | any | filesystem | `services/control.zig` | single-use, scope TTL, no `--yes` | wrong `--confirm` or disarmed: exit 1 |
| `campaign run <ACTION-ID> --dry-run` | any | none | `services/control.zig` | approval consumed once, stop checked first | missing/used/expired approval or stopped: exit 1 |
| `campaign approve-repro <record.json>` | any | filesystem | `services/control.zig` | typed CVE confirmation, one record | missing approval or disarmed: exit 1 |
| `reproduce <record.json>` | any | real TCP/UDP | `http_probe`/`udp_probe` + DSL | 256 KiB response, 1-4096 B datagram, 50-5000 ms | failed oracle, invalid record or ungated exploit: exit 1 |
| `campaign approve-exploit <record.json>` | any | filesystem | `services/control.zig` | record bytes + target + params, one approval | disarmed or outside scope: exit 1 |
| `exploit run <record.json>` | any | real TCP | `services/exploit.zig` | 1-8 HTTP steps, 4 KiB effect evidence | missing approval, missing capture/extract or failed transport: exit 1 |
| `chain plan --observations <file>` | any | filesystem | `services/chain.zig` | 1-8 matched records, digest-bound plan | no match: exit 1 |
| `chain approve <plan.json>` | any | filesystem | `services/control.zig` | plan bytes + target, one approval | disarmed or outside scope: exit 1 |
| `chain run <plan.json>` | any | real TCP | `services/chain.zig` + `exploit.zig` | STOP before/after each step, record digest check | changed record/plan or failed step: exit 1 |
| `exploit.execute` (DSL) | active | real TCP | `chain_exec.zig` | kernel active gate + campaign approval | no/used approval: audited denied |
| `run <app>` | any | simulated | `apps/infrared.zig` | - | `UnknownApp` |
| `network` | Windows only | real | PowerShell `Get-NetIPConfiguration` | 10 s timeout | `UnsupportedPlatform` |
| `capture <s> <out> <comp>` | Windows only | real | `pktmon` start/stop/etl2pcap | 1-60 s, 1-64 MB, output <= 80 MiB | refuses overwrite, validates pcapng header and trailer |
| `neighbor <ip>...` | Windows only | real | ping plus `Get-NetNeighbor` | 64 targets, 100-2000 ms each, <= 60 s total | literal IP addresses only |
| `tcp-scan <ip> [ports]` | any | real TCP | `std.Io.net` plus active probes | 32 ports, 50-2000 ms, <= 30 s total | rejects port 0 |
| `discover <cidr>` | any | real TCP | sequential, 64 hosts | 64 hosts, 4 ports | `TooManyHosts` |
| `scan-cidr <cidr> [ports] [conc]` | any | real TCP | `io.concurrent` slots | 256 hosts, 64 ports, 32 workers, <= 120 s | observation overflow counted as dropped |
| `http-inspect <target> [port]` | any | real TCP | HEAD/OPTIONS plus same-origin redirects | headers <= 8 KiB, <= 3 hops | blocks cross-origin and scheme changes |
| `tls-inspect <target> [port]` | any | real handshake | `std.crypto.tls.Client` plus self-verification | handshake <= 64 KiB, chain <= 16, 50-2000 ms | fail-closed, see `capabilities/network.md` |

The commands above are exercised by the smoke checks in `build.zig`.

## 2. Analysis and automation additions

| Capability | Entry point | I/O | Notes |
|---|---|---|---|
| Firmware triage | `analyze --protocol firmware <img>` | filesystem | Container detection, block entropy, strings, Cortex-M vector table heuristic |
| Firmware disassembly | `analyze --protocol firmware --base <hex> --arch thumb <img>` | filesystem | Thumb-16 plus BL/MOVW/MOVT/LDR(pc); function starts from vector table and BL targets; reports coverage and unknown count |
| Literal-pool cross references | same command; fields `literal_refs`, `strings_referenced`, `pointer_refs`, `xref_N` | filesystem | String to loading instruction to containing function; direct (ADR/MOVW+MOVT) and pointer-table (LDR literal, slot dereferenced) references |
| Script parsing and validation | library: `PocketRoot.Script` (`services/script.zig`) | none | Lua-style block syntax, named errors, fuzz coverage |
| Script execution (CLI) | `script run [--lib a.pk,b.pk] [--authorize-active] [--region <id>] <file.pk>` | simulated | Prints status, audit entries and emitted findings; unauthorised active operations exit 1 |
| Script compilation | library: `PocketRoot.ScriptExecutor` (`services/script_builder.zig`) | simulated | Compiles to `workflow.Definition` with `if/elseif/else`, bounded `for`, `out`, pack gating and sub-script inlining |

## 3. Library modules and their CLI reachability

| Module | Content | Reachability |
|---|---|---|
| `core/capability.zig` | Capability kinds and operations (counts in [facts](facts.md)): authorisation, audit, locks, emergency stop | `device request\|serve` and `script run` |
| `device/ipc.zig` | PKRT v1 frames, CRC-32, sequence replay rejection | `device serve` and loopback tests; no hardware transport |
| `device/command.zig` | Capability command wire format | `device serve` over PKRT frames |
| `services/device_host.zig` | Policy + backend + audit sink + frame loop | `device request`, `device serve` |
| `services/audit_log.zig` | `pocketroot.audit.v1` JSONL writer/parser | `device --audit`, `audit` |
| `simulator/device.zig` | Simulated backend with a support set and a "simulated" result | `device`, `script run`; no real backend |
| `simulator/loopback.zig` | IPC to kernel to backend to response frame | Tests only |
| `services/automation.zig` | Workflow to capability adapter | Tests and the script CLI |
| `services/workflow.zig` | Steps, conditions, retries, checkpoint, cancel | Tests and the script CLI |
| `services/library.zig` | `pocketroot.library.v1` persistence | No CLI entry point |
| `services/control.zig` | Scope, single-use approvals with configurable TTL, stop, hash-chained ledger | `campaign init|arm|stop|status|approve|run` |
| `services/surface.zig` | Attack-surface report: access, capability, feasibility, candidate actions | `campaign surface` |
| `services/http_probe.zig` | Raw HTTP/1.1 request and oracle for reproduction scripts | `net.http` via `script run --live`, `reproduce` |
| `services/udp_probe.zig` | One datagram and an amplification/size oracle | `net.udp` via `script run --live`, `reproduce` |
| `services/exploit.zig` | Ordered HTTP exploit steps, capture/extract and effect evidence | `exploit run` |
| `services/chain.zig` | Observation-to-record matching and digest-bound chain plans | `chain plan/run`, `exploit.plan` |
| `services/exploit_plan.zig` | Kernel-side passive chain analysis over observations/surface | `exploit.plan` (DSL), `device request exploit analyze` |
| `services/chain_exec.zig` | Campaign-gated chain execution shared by kernel and CLI | `exploit.execute`, `chain run` |

## 4. Failure semantics

| Situation | Behaviour |
|---|---|
| `network`, `capture`, `neighbor` off Windows | `error.UnsupportedPlatform` |
| Unknown pcap magic | `error.UnsupportedCaptureFormat` |
| TLS version other than 1.2 or 1.3 | `error.UnsupportedTlsVersion` |
| TLS 1.3 with an unsupported cipher | `error.UnsupportedTls13Cipher` |
| Certificate carries nameConstraints | `error.UnsupportedNameConstraints` (refused, never downgraded) |
| Catalogue schema mismatch | `error.UnsupportedCatalogSchema` |
| Catalogue line above 64 KiB | `error.CatalogLineTooLong` |
| More than 1024 observations | `error.TooManyObservations`; `scan-cidr` drops the excess and counts it |

## 5. Where the work happens

```
file -> parse -> result/observations -> asset graph -> vulnerability match -> report
        (in process)

network / capture / neighbor / tcp-scan / discover / scan-cidr / http-inspect / tls-inspect
        (host process, Windows tools for the first three)

capability request -> policy.authorize -> locks -> backend -> audit
        (simulated backend; returns "simulated")

device request/serve -> device_host -> capability kernel -> PKRT response
        (CLI host entry; optional JSONL audit sink)
```

Active device operations (transmit, emulate, card read/write) are not on any code path
today; the capability kernel that would carry them is implemented and tested, and only
the simulated backend is wired to it.
