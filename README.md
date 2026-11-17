# PocketRoot

PocketRoot is a Zig-first portable security capability engine. It is a library plus a
CLI that performs three kinds of work:

- **Network observation** — neighbour discovery, TCP scan, CIDR scan, HTTP and TLS
  inspection, live capture, and asset graph construction.
- **Offline analysis** — protocol plugins for capture and artifact formats, including
  firmware triage with bounded Thumb disassembly and literal-pool cross references.
- **Scripted automation** — a Lua-style DSL compiled onto the workflow runner, with a
  capability kernel that gates every operation, records an audit entry, and denies
  active operations unless they are explicitly authorised.
- **Effect execution** — declarative exploit records that carry a command or file-read
  effect through ordered HTTP steps, with campaign approval, stop and evidence.

The engine has no third-party dependencies. Everything runs on the standard library.

## Build and test

Zig 0.16.0 is required.

```bash
zig build                 # build the CLI into zig-out/bin/PocketRoot
zig build test            # library and CLI tests
zig build smoke           # end-to-end CLI checks
zig build check           # format check + tests + smoke + docs facts
zig build facts           # regenerate docs/facts.json and docs/capabilities/facts.md
zig build docs-check      # fail when the generated fact sheet is stale
```

## Use the CLI

```bash
# analyse a firmware image with disassembly and cross references
PocketRoot analyze --protocol firmware --base 0x08000000 --arch thumb image.bin

# run a DSL script that inlines a library sub-script
PocketRoot script run --lib helper.pk main.pk

# drive the capability kernel through its host entry and export the audit trail
PocketRoot device info
PocketRoot device request infrared read --payload capture --audit audit.jsonl
PocketRoot device serve --transport stdio --audit audit.jsonl
PocketRoot audit audit.jsonl

# raw HTTP reproduction: record -> rendered script -> live probe -> evidence
PocketRoot reproduce samples/reproductions/CVE-2021-41773/record.json --evidence repro.json

# effect execution: approve the record, then run the exploit with an effect parameter
PocketRoot campaign approve-exploit samples/exploits/CVE-2018-7600/record.json --reason "ticket SEC-2" --confirm CVE-2018-7600 --param command=id
PocketRoot exploit run samples/exploits/CVE-2018-7600/record.json --campaign .pocketroot --param command=id --evidence exploit.json

# scope -> read-only surface -> human approval with a configurable TTL -> gated dry run
PocketRoot campaign init --scope samples/campaign/scope.json
PocketRoot campaign arm
PocketRoot campaign surface --catalog samples/campaign/catalog.jsonl --protocol nmap samples/network/lab-repro-hosts.xml
PocketRoot campaign approve ACTION-1 --reason "ticket SEC-1" --confirm ACTION-1
PocketRoot campaign run ACTION-1 --dry-run
PocketRoot campaign stop

# probe explicit TCP ports, then match observations against the catalogue
PocketRoot tcp-scan 192.0.2.10 22,80,443
PocketRoot vulns ../PocketRootVulnerabilityDb/vulndb/catalog-v1.jsonl --protocol nmap samples/network/nmap-demo.xml
```

`device serve` speaks PKRT frames on stdin/stdout; `--transport loopback --frames <path>`
replays a recorded request stream instead. The execution backend is the simulator, so this
exercises policy, locks, audit and framing rather than hardware.

`script run` compiles the DSL and executes it against the simulated backend; it prints
the final status, one audit line per capability request, and every emitted finding.

`reproduce` renders a record's `{{target}}` into a DSL script, runs it with the live HTTP
backend and writes evidence with the expected/observed outcome. The sample probes
CVE-2021-41773's raw path traversal and fails unless the response contains `root:x:0:0`.

`exploit run` is the effect layer: an exploit record executes ordered HTTP steps, captures
values such as a form build id, extracts command output between markers and writes
`pocketroot.exploit.evidence.v1`. It always needs a campaign approval; the approval binds
the record bytes, target and effective params. The sample executes a command through
CVE-2018-7600 on a Drupal 7.57 lab and returns the command output. See
[docs/product/exploits.md](docs/product/exploits.md).

`campaign surface` is read-only and needs no approval: it turns catalogued observations
into ranked candidate actions and writes `.pocketroot/surface.json`. `campaign approve`
mints a single-use approval whose TTL comes from the scope (`approval_ttl_seconds`, default
15 minutes); `campaign run` only supports `--dry-run` in this build, but the scope check,
approval consumption, stop marker and hash-chained ledger are real. `campaign stop` is
checked before any action starts. `campaign approve-exploit` is the same gate for exploit
records; `exploit run` consumes the approval before its first request. See [docs/capabilities/campaign.md](docs/capabilities/campaign.md).

## Repository layout

```
src/core/         capability kernel, audit log, IPC framing, events, artifacts
src/services/     network probing, capture, workbench, project, workflow, automation, DSL
src/protocols/    protocol plugins (subghz, nfc, infrared, firmware, nmap, pcap, ...)
src/formats/      binary format decoders (Thumb, TLS certificate, NBNS, SSDP, flipper)
src/simulator/    runtime, simulated capability backend, loopback transport
src/cli/          command line entry point
samples/          small fixtures, reproductions and exploit records
docs/             documentation
```

## Documentation

Start at [docs/README.md](docs/README.md). It indexes the architecture, capability,
protocol, verification and scripting documents.

## Optional catalogue tests

The vulnerability catalogue lives in a separate repository. Point the tests at a local
checkout with a sibling directory named `PocketRootVulnerabilityDb`; when it is absent
those tests report a skip and the catalogue smoke step is not registered.
