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
| `vulns <catalog>` | any | filesystem | `vulnerability_matcher` | catalogue 16 MiB, 4096 CVEs | version mismatch: `UnsupportedCatalogSchema` |
| `migrate` | any | filesystem | `validatedCopy` | same as analyze | rejects identical input and output paths |
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
| Literal-pool cross references | same command; fields `literal_refs`, `strings_referenced`, `xref_N` | filesystem | String to loading instruction to containing function; single-instruction data flow plus movw/movt pairing |
| Script parsing and validation | library: `PocketRoot.Script` (`services/script.zig`) | none | Lua-style block syntax, named errors, fuzz coverage |
| Script execution (CLI) | `script run [--lib a.pk,b.pk] [--authorize-active] [--region <id>] <file.pk>` | simulated | Prints status, audit entries and emitted findings; unauthorised active operations exit 1 |
| Script compilation | library: `PocketRoot.ScriptExecutor` (`services/script_builder.zig`) | simulated | Compiles to `workflow.Definition` with `if/elseif/else`, bounded `for`, `out`, pack gating and sub-script inlining |

## 3. Library modules without a CLI path

| Module | Content | Reachability |
|---|---|---|
| `core/capability.zig` | 20 kinds by 9 operations: authorisation, audit, locks, emergency stop | Used by automation and simulator tests; the CLI never imports it |
| `device/ipc.zig` | PKRT v1 frames, CRC-32, sequence replay rejection | Loopback tests only; no real transport |
| `device/command.zig` | Capability command wire format | Same as IPC |
| `simulator/device.zig` | Simulated backend with a support set and a "simulated" result | No real backend |
| `simulator/loopback.zig` | IPC to kernel to backend to response frame | Tests only |
| `services/automation.zig` | Workflow to capability adapter | Tests and the script CLI |
| `services/workflow.zig` | Steps, conditions, retries, checkpoint, cancel | Tests and the script CLI |
| `services/library.zig` | `pocketroot.library.v1` persistence | No CLI entry point |

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
```

Active device operations (transmit, emulate, card read/write) are not on any code path
today; the capability kernel that would carry them is implemented and tested, and only
the simulated backend is wired to it.
