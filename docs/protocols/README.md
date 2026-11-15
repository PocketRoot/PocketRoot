# Protocol plugin guide

The contract is defined in [`architecture/contracts.md`](../architecture/contracts.md).
This page contains the operational steps.

## 1. What belongs in a plugin

A plugin applies when all three hold: the input is a byte slice, the output is a
deterministic structured result, and neither network nor device access is required.

Capture and scanning need I/O, so they live in `src/services/` instead.

## 2. Adding a plugin

```
1. src/protocols/<id>.zig
     pub const descriptor = protocol.ProtocolDescriptor{ ... };
     pub fn sampleText(allocator) ![]u8;                 // smallest valid sample
     fn analyzeText(allocator, data) !protocol.AnalysisResult;

2. src/protocols/registry.zig
     import it and add it to the builtins array
     (array order is the output order of the "protocols" command)
     if the format needs parameters (load address, architecture), implement analyze_with
     and set descriptor.analyze_with; callers use descriptor.run(alloc, data, options)
     and analyze remains the parameter-free wrapper

3. src/root.zig
     add one line to the protocols struct

4. Tests
     at least two test blocks: one minimal positive sample and one rejected input
     if the parser processes untrusted input, add a corpus seed to src/fuzz_tests.zig
     and call it from fuzzAnalysis

5. Documentation
     add a row to capabilities/offline-analysis.md
     register any new limit constant in architecture/contracts.md
```

## 3. Requirements for the analysis function

| Requirement | Reason |
|---|---|
| Pure: no file access, no subprocesses, no network | `project` and fuzzing call it with arbitrary input |
| Deterministic: identical output for identical input, including field order | JSON output is diffed as evidence |
| No panics: every bound violation returns a named error | Fuzzing feeds random bytes |
| Bounded: check the limit constants before looping | Large files must not stall the caller |
| Owns its text: use `addField` / `addDetailedFinding` | Callers free the input buffer |
| Named errors: `error.InvalidSubGhzRawTiming` over `error.Invalid` | The CLI prints `@errorName` directly |

## 4. Field naming conventions

| Convention | Example |
|---|---|
| snake_case field names | `device_type`, `rom_data_length`, `open_port_1_service` |
| Counts are decimal strings | `scripts`, `invalid_records`, `medium_count` |
| Ordered items use `<noun>_<n>` | `interface_1_ipv4_1`, `target_2_mac` |
| Hexadecimal in lower case; preserve the source form when it is part of the format | `address: 0x20df`, `key: 00 00 AB CD EF` |
| Booleans are `yes`/`no` strings | `scan_deadline_reached: yes` |
| The summary is one sentence with the salient numbers | `Nmap results: 1 host, 1 up, 1 open port, 1 script` |

## 5. When to emit a finding

| Situation | Severity |
|---|---|
| Valid format with something suspicious or degraded (old version, unknown enum, checksum mismatch) | `info` / `warning` |
| Internally inconsistent input that can still be parsed | `warning` |
| Invalid input | return an error; do not fabricate a finding |
| Security rating | `low`..`critical`, taken from a catalogue or a scan result, never invented |

## 6. Reference implementations

- Strict validation: `validateRaw` in `protocols/subghz.zig` (alternating signs plus
  three separate limits).
- Lenient parsing with degraded reporting: `protocols/nuclei.zig` (a malformed line
  produces a warning and parsing continues).

## 7. Anti-patterns

| Anti-pattern | Why it fails |
|---|---|
| Reading environment variables or the clock inside the analysis function | Breaks determinism and makes JSON undiffable |
| Using `std.heap.page_allocator` for large inputs | Unbounded growth; use the passed allocator |
| `@panic` on unknown fields | Fuzzing reaches it immediately |
| Writing an error message into the summary instead of returning an error | The CLI presents the summary as a successful result |
