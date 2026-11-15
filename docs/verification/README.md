# Verification

## 1. Layers

| Layer | Content | Entry point |
|---|---|---|
| Format | `zig fmt --check` over `build.zig`, `build.zig.zon`, `src` | `zig build check` |
| Unit tests | Two test targets: library and CLI | `zig build test` |
| Fuzzing | `std.testing.fuzz` with corpus seeds covering the untrusted parsers | `zig build test` |
| Smoke | CLI invocations, including negative cases that must exit non-zero (totals in [facts.md](../capabilities/facts.md)) | `zig build smoke` |
| Docs facts | Regenerated counts compared with the committed fact sheet | `zig build docs-check` |

`zig build check` runs format, tests, smoke and the docs fact check (`build.zig`).
The exact number of plugins, kinds, tests and smoke invocations is generated in
[capabilities/facts.md](../capabilities/facts.md) and verified in CI, so this page does not
repeat them.

## 2. Smoke checks

| # | Invocation | Expected exit code |
|---|---|---|
| 1 | `protocols` | 0 |
| 2 | `capture` | 2 (missing arguments) |
| 3 | `neighbor example.com` | 1 (host names rejected) |
| 4 | `scan-cidr invalid` | 1 (invalid CIDR) |
| 5 | `unknown-command` | 2 |
| 6 | `analyze samples/infrared/demo-power.ir` | 0 |
| 7 | `analyze --json samples/infrared/demo-power.ir` | 0 |
| 8 | `script run samples/scripts/reference-flow.pk` | 0 |
| 9 | `device info` | 0 |
| 10 | `device request infrared read --payload capture` | 0 |
| 11 | `device request subghz transmit --authorize-active` | 1 (denied) |
| 12 | `device serve --transport loopback --frames samples/device/request-infrared.pkrt --output .zig-cache/smoke-device.pkrt` | 0 |
| 13 | `device serve --transport stdio` with the same frame on stdin | 0 |
| 14 | `project --json samples` | 0 |
| 15 | `vulns ../PocketRootVulnerabilityDb/vulndb/catalog-v1.jsonl ...` | 0 (only when the catalogue checkout exists) |

The smoke set needs no network, no device and no container.

## 3. Running the checks

```bash
zig build check                     # format + tests + smoke + docs facts
zig build facts                     # regenerate docs/facts.json and capabilities/facts.md
zig build docs-check                # verify the fact sheet is current
zig build test                      # tests only
zig build smoke                     # CLI smoke only
zig build run -- protocols          # run the CLI through the build system
zig build -Doptimize=ReleaseSafe    # release build
```

Smoke check 15 and the `vulnerability_catalog` tests need a checkout of the catalogue
repository at `../PocketRootVulnerabilityDb` or `PocketRootVulnerabilityDb`, containing
`vulndb/catalog-v1.jsonl`. When that file is absent the tests report `SkipZigTest` and
`build.zig` does not register smoke check 15, so the engine repository can be cloned and
verified on its own.

## 4. Catalogue validation

The catalogue repository ships two validators. `tools/Validate-CatalogV2.ps1` checks the
v2 export used by `vulns`: schema, identifier uniqueness, affected products, alias and
version-rule limits, version syntax, range shape, severity values, CVSS bounds, the
reproduction tier and the SHA-256 of every line against its provenance record.
`tools/Classify-Reproducibility.ps1` assigns that tier from CVSS metrics and the product
class in `tools/products.json`. The CI workflow runs it when the
catalogue checkout is present.

`Validate.ps1` covers the original v1 catalogue: PowerShell 5.1, no dependencies,
offline and fail-closed. It never runs Docker and never executes a proof of concept.

| Section | Validated |
|---|---|
| Self-check | The script must not contain process launching or expression evaluation |
| [1] Catalogue | Line count matches provenance; schema is correct; identifiers are unique |
| [2] Provenance | Every raw CVE has `cveMetadata.state == "PUBLISHED"`; `raw_file_sha256` matches; `cve_record_sha256` is recomputed with trailing newlines removed |
| [3] Manifests | Each reproduction directory contains README, manifest, `reproduce-safe.ps1`, `verify-patch-diff.ps1`, expected output and evidence; the status enum is valid; version vectors fall inside the catalogue's dotted range using an independent comparator; source and evidence hash key sets equal the actual files; URL hosts are allow-listed |
| [4] CVE-2026-44631 | Status must be `inconclusive`; observed behaviour must not claim reproduction |
| [5] CVE-2024-31449 | Status must be `fixed_verified` with the corresponding evidence |

The script recomputes hashes from the filesystem instead of trusting the manifests'
self-description.

## 5. Verified behaviour

Recorded from the built CLI and from tests:

| Check | Result |
|---|---|
| `zig build test` | exit 0 |
| `zig build check --summary all` | All steps succeed; test and smoke totals are generated in [facts.md](../capabilities/facts.md) |
| `help` | exit 0, all commands listed |
| `protocols` | Every built-in plugin is listed; manual/auto flags match the code |
| `list` | one app: infrared |
| `archive` | Recognised files carry their plugin id; manual-extension and non-protocol files are `unknown` |
| `analyze` on infrared, subghz, badusb and nmap samples | fields match `capabilities/offline-analysis.md`, SHA-256 included |
| `project samples` | Exit 0; unique/skipped counts follow the sample tree |
| `vulns <catalogue> --protocol nmap ...` | zero matches for the demo product, one endpoint examined |
| `analyze --protocol firmware demo.bin` | `raw 320 bytes`, vector table valid, `entry_point 0x08000100`, `initial_sp 0x20001000` |
| `analyze --protocol firmware --base 0x08000000 --arch thumb thumb-demo.bin` | `instructions=43`, `unknown_opcodes=0`, `decode_coverage_x100=100`, `functions=2`, `insn_3: bl #0x08000020` |
| `analyze --protocol firmware --base 0x08000000 --arch thumb f3-demo.bin` | `literal_refs=1`, `strings_referenced=1`, `pointer_refs=1`, `xref_1: "PocketRoot-F3" <- ... slot ... -> ... [literal-load]` |
| `analyze --protocol firmware --base 0x08000000 --arch thumb pair.bin` | `literal_refs=2`, `strings_referenced=2`, `xref_2: "PairRef" <- 0x0800000a ... [movw/movt]` |
| `script run --lib helper.pk caller.pk` | `script "caller" succeeded`, two audit entries (`script:helper`, `script:caller`) |
| `script run tx.pk` (active operation, no authorisation) | `script "tx" failed`, audit status `denied`, exit code 1 |
| `device info` | Kind/operation counts (see [facts](../capabilities/facts.md)), PKRT v1 limits, both transports listed |
| `device request subghz transmit --authorize-active` | `status: denied`, `error: ActiveOperationDenied`, exit 1 |
| `device request subghz transmit --allow-active --authorize-active --region EU` | `status: succeeded`, audit line carries `region=EU active_authorized=yes` |
| `device serve --transport loopback` | three frames in, three PKRT responses out (`succeeded`, `denied`, `succeeded`) |
| `audit --json` | `pocketroot.audit.v1`, summary counts match the served frames |
| Control flow tests | A bound `protocol=Princeton` takes the then-branch; `for 1,3` unrolls into three calls with the counter left at 3; `out` makes a helper variable visible to the caller |

CI runs `.github/workflows/check.yml` on `windows-latest` with Zig 0.16.0: checkout,
optional catalogue checkout, format check, tests, smoke and `zig build docs-check`.

## 6. Coverage limits

| Not covered | Reason |
|---|---|
| Real capture and neighbour probing | `pktmon` needs administrator rights and a real adapter |
| TLS inspection against public sites | Needs network access and the system CA bundle |
| Line coverage numbers | The test runner reports pass/fail counts only |
| Performance baselines | Only upper bounds are asserted, not throughput |
