# Architecture overview

Paths below are relative to the repository root. Behaviour is defined by the code; this
page summarises it.

## Layers

| Layer | Directory | Responsibility |
|---|---|---|
| Core model | `src/core/` | Artifact hashing, network observations, event bus, capability kernel |
| Device protocol | `src/device/` | PKRT frames and the capability command wire format |
| Format library | `src/formats/` | DNS/DHCP/DHCPv6/NBNS/SSDP, Flipper key-value files, TLS/X.509, Thumb |
| Protocol plugins | `src/protocols/` | `ProtocolDescriptor` implementations and the pcap parser |
| Services | `src/services/` | Scanning, capture, HTTP/TLS inspection, asset graph, vulnerability matching, projects, workflow, DSL |
| Runtime | `src/simulator/`, `src/apps/` | `Runtime`, app model, simulated capability backend, loopback transport |
| Shell | `src/cli/` | Argument parsing and three output projections (terminal, JSON, Markdown) |

Dependencies are one-directional: no lower layer imports the CLI, and `core/` imports no
other layer. `root.zig` therefore only re-exports.

## Execution paths

### A. File analysis (offline, deterministic)

```
path -> StorageService.loadBytes (<=64 MiB)
      -> ProtocolRegistry.inferFromPath / find(id)
      -> ProtocolDescriptor.run(bytes, options) -> AnalysisResult
      -> Artifact.fromBytes (SHA-256)
      -> printAnalysisDetails / printJsonAnalysis / printMarkdownReport
```

Implemented in `services/workbench.zig`. A new format only has to implement the
analysis function; `analyze`, `project`, `archive`, `migrate` and `report` then work
with it.

### B. Live observation (real I/O)

```
command -> services/<x>.zig entry point (validates limits)
        -> host capability: std.Io.net (TCP/TLS) or std.process.run (pktmon, PowerShell)
        -> produces both fields/findings (human) and NetworkObservation (machine)
        -> AnalysisResult
```

The observation sockets currently run on the host process, not on dedicated hardware.

### C. Asset graph and vulnerability matching

```
AnalysisResult.observations (many runs)
  -> AssetGraph.build (identity merge by address/hostname -> assets, endpoints, versions)
     -> vulnerability_matcher.match(graph, catalog)
        -> printVulnerabilityReport
```

The asset graph is the only cross-analysis aggregation point (`services/asset_graph.zig`).

## Runtime object

`simulator/runtime.zig` `Runtime` holds the allocator, event bus, storage, notification
service, archive service, app manager and protocol registry. `context()` packages them
into an `AppContext` for apps. The runtime holds no network state and no capability
service; the capability kernel is used by the scripting layer rather than by the CLI
commands.

## Extension points

| Extension point | Contract | Adding one requires |
|---|---|---|
| Protocol/format | `ProtocolDescriptor` | Implement the analysis function (and optionally a sample generator), register it in `registry.builtinProtocols`, add a test, a fuzz seed and a smoke check |
| Network service | Convention: return `AnalysisResult` and record observations | New `services/*.zig` plus a CLI branch; keep the module-top limit constants |
| App | `AppDescriptor.entry` | Implement `run(*AppContext)` and register it in `root.zig` |
| Capability backend | `capability.ExecuteFn` | Implement a real backend to replace the simulated one in `simulator/device.zig` |

## Process and platform model

- Single-process CLI: no daemon, no background service, no listening port. Loopback
  listeners exist only in tests.
- Allocation: the CLI uses `init.arena`; library functions take an explicit `allocator`
  and every result type has `deinit`.
- Platform: network services return `error.UnsupportedPlatform` off Windows
  (`services/network_environment.zig`, `services/live_capture.zig`). Analysis services
  work everywhere.
- Concurrency: only `scan-cidr` schedules work through `io.concurrent` slots
  (`services/network_scan.zig`); individual TCP probes are sequential
  (`services/tcp_scan.zig`).

## Output contract

One `AnalysisResult` supports three projections:

| Output | Entry point | Shape |
|---|---|---|
| Terminal | `printAnalysisDetails` | Indented fields, findings, observations |
| JSON | `printJsonAnalysis` | `std.json.Stringify`, stable field order |
| Markdown | `printMarkdownReport` | Report with per-artifact SHA-256 and deduplicated counts |

JSON schema identifiers: `pocketroot.project.v1`, `pocketroot.vulnerability.v1`,
`pocketroot.library.v1`.
