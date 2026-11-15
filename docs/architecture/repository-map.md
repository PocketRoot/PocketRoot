# Repository layout

## Repositories

| Repository | Role | Build relationship |
|---|---|---|
| Engine (this repository) | Zig engine and CLI | The only repository built with `zig build` |
| `PocketRootVulnerabilityDb` | Offline vulnerability catalogue, CVE reproduction evidence, dependency-free validation script | Referenced by optional engine tests and by one smoke step; has no build of its own |
| `references/` | Read-only reference checkouts (Flipper Zero firmware, protocols, docs, models) | Not part of the build |

On disk the three sit side by side:

```
<parent>/
  PocketRoot/                     engine repository (this one)
  PocketRootVulnerabilityDb/      catalogue repository
  references/                     read-only reference checkouts
```

## Engine repository

- Entry point: `src/cli/main.zig`; library root: `src/root.zig` (module name `PocketRoot`).
- No third-party dependencies (`build.zig.zon` declares an empty dependency set); Zig 0.16
  is required.
- Build steps: `run`, `test`, `smoke`, `check` (`check` = format check + tests + smoke).
- Single branch `master`. `.gitignore` excludes `.zig-cache/` and `zig-out/`;
  `.gitattributes` enforces `eol=lf`.

## Cross-repository coupling

| Location | Coupling | Current behaviour |
|---|---|---|
| `build.zig` smoke step | Registers the `vulns` smoke only when the catalogue directory exists | A standalone clone still passes `zig build smoke` |
| `services/vulnerability_catalog.zig` tests | Reports `SkipZigTest` when the catalogue or its `vulndb/catalog-v1.jsonl` file is missing; otherwise every line must parse under the declared schema | A standalone clone skips instead of failing; a malformed entry still fails the test |
| Catalogue `Validate.ps1` | Compares a Base64-encoded expected message | Any wording change fails validation |

The catalogue is a separate repository because it has its own release cycle, its own
validation script, and does not need the engine toolchain.

## Documentation location

Documentation lives in `docs/` inside the engine repository so a behaviour change and its
documentation land in the same commit.

## Reference checkouts

`references/` contains read-only checkouts used to verify file formats (`.sub`, `.nfc`,
`.rfid`, `.ibtn`, `.ir`) and protocol behaviour (for example Sub-GHz RAW timing
alternation).

- Used to confirm field names and value ranges.
- Not copied into the engine: licence and dependency risk.
- Not part of the build: `build.zig.zon` paths do not include `references`, and CI does
  not need them.
