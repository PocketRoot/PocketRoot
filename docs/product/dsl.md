# Script DSL reference

Schema identifier: `pocketroot.script.v1`.

The parser, validator and compiler are implemented in this repository
(`services/script.zig`, `services/script_builder.zig`). No Lua runtime, garbage
collector or standard library is embedded; only the block syntax style is borrowed.

## 1. Example

```lua
script "replay-subghz" do
    use "pack.rf"

    budget { time = "10s", steps = 500, tx = 2 }

    cap rf_capture = subghz.read
    cap rf_tx      = subghz.transmit { region = from_policy }

    step "capture" do
        sig = rf_capture { payload = "protocol=Princeton" }
        if sig.protocol == "Princeton" then
            rf_tx { payload = sig.protocol, on_error = "continue" }
            emit finding {
                severity = "info",
                message  = "replayed princeton frame",
                tag      = sig.protocol
            }
        else
            emit info "unsupported protocol"
            stop
        end
    end
end
```

## 2. Syntax rules

| Item | Rule |
|---|---|
| Blocks | `do ... end`; `if ... then ... elseif ... else ... end`; `for i = 1, N do ... end` |
| Comments | `--` to end of line; no block comments |
| Statement separator | Newline; an optional `;` is accepted |
| Strings | Double quotes; no escape sequences (the next `"` ends the string); no long-bracket strings |
| Option values | String, number, `true`/`false`, `from_policy`, or a variable reference (`sig`, `sig.field`) |
| Identifiers | `[A-Za-z_][A-Za-z0-9_]*` |
| Loops | Bounded numeric `for` only; `N` must be a literal in `1..64`; no `while` |
| Functions | No user-defined functions |
| Indentation | Not significant |
| Comparison | `==`, `~=`, `<`, `<=`, `>`, `>=`; connectors `and`, `or`; prefix `not` |

## 3. Execution model

The DSL compiles to `workflow.Definition`; it is not a second executor.

```
script(file) -> lex/parse -> AST -> validate -> workflow.Definition (+ action and condition specs)
                                                        |
                                                        v
                                       workflow.Runner (retries, conditions, checkpoints, cancel)
                                                        |
                                                        v
                                       automation.Engine -> capability.Service
                                                        |
                                                        v
                                             hardware backend or simulated backend
```

Retries, checkpoints, cancellation and auditing are the existing workflow and capability
implementations. `if` becomes condition steps with trampoline jumps, and `for` is
unrolled at compile time.

## 4. Capability binding

Every verb becomes a `capability.Request` (see
[`architecture/contracts.md`](../architecture/contracts.md)):

| DSL verb | Kind and operation | Active authorisation |
|---|---|---|
| `subghz.read`, `nfc.read`, `ir.receive`, `lfrfid.read`, `ibutton.read`, `net.capture`, `net.tls`, `net.scan`, `fs.read` | matching kind with `read`/`capture`/`analyze` | no |
| `subghz.transmit` | `subghz` + `transmit` | yes, with matching region |
| `ir.transmit` | `infrared` + `transmit` | yes |
| `nfc.emulate` | `nfc` + `emulate` | yes |
| `fs.write` | `storage` + `write` | yes |
| unregistered verb | none | rejected at parse time (`UnknownVerb`) |

## 5. Packs

`use` declares the capability surface a script may touch. Every verb belongs to exactly
one pack:

| Pack | Verbs |
|---|---|
| `pack.rf` | `subghz.read`, `subghz.transmit`, `lfrfid.read`, `ibutton.read` |
| `pack.nfc` | `nfc.read`, `nfc.emulate` |
| `pack.ir` | `ir.receive`, `ir.transmit` |
| `pack.net` | `net.capture`, `net.tls`, `net.scan` |
| `pack.fs` | `fs.read`, `fs.write` |

A `cap` whose pack was not imported fails with `PackNotImported`; an unknown pack fails
with `UnknownPack`; a verb without a pack fails with `UnknownVerb`.

## 6. Semantics

| Item | Behaviour |
|---|---|
| `on_error` | `"abort"`, `"continue"` or `"retry(n)"`; retry reuses the workflow attempt counter |
| Scoping | `sig = ...` is local to the step; crossing steps requires `out <name>` |
| Variables | A successful call binds its result payload as `name` and, for each `key=value` line, as `name.key` |
| References | `payload`, `severity`, `message`, `tag` and `note` accept a variable reference. The root must be visible at parse time; a path that is visible but has no runtime field fails the step with `UnresolvedReference` instead of sending or emitting an empty value |
| Conditions | A comparison references a variable assigned earlier in the same step, or one exported with `out`. Comparing two variables and mixing `and` with `or` are rejected with `UnsupportedCondition` |
| `stop` | Ends the enclosing statement list; later statements are not compiled |
| `emit` | Records a finding without contacting the capability service; fields may be literals or references |

## 7. Sub-scripts

```lua
-- helper.pk
script "helper" do
    use "pack.rf"
    cap rf = subghz.read
    step "capture" do
        sig = rf { payload = "protocol=Princeton" }
        out sig
    end
end

-- caller.pk
script "caller" do
    use "pack.rf"
    use "script:helper"
    step "decide" do
        run "helper"
        if sig.protocol == "Princeton" then
            rf { payload = "match" }
        end
    end
end
```

- `run` inlines the sub-script's steps at the call site, so retries, checkpoints and audit
  remain one workflow run. Inlined steps are audited under `script:<sub-script name>`.
- A sub-script's `out` names become visible in the caller at the `run` statement.
- `use "script:<name>"` and `run` require a `Library` at parse time
  (`script.parseWithLibrary`); a plain `parse` reports `UnknownScript`.
- A library must exist before the caller is parsed, so a cycle cannot be constructed;
  the compiler still enforces a depth limit of 8.

## 8. Running from the CLI

```
PocketRoot.exe script run [--lib a.pk,b.pk] [--authorize-active] [--region <id>] <file.pk>
```

- `--lib` takes a comma-separated list, parsed in order; a later library script may use an
  earlier one. A forward reference fails with `UnknownScript`.
- A library entry is named by the `script "<name>"` declaration, not by the file name.
- Without `--authorize-active`, active operations are denied and the script ends failed
  with exit code 1.
- Output is the final status, one audit line per request (subject, kind, operation,
  status) and every emitted finding.

```
$ PocketRoot.exe script run --lib helper.pk caller.pk
script "caller" succeeded
audit: 2
  1 script:helper subghz read succeeded
  2 script:caller subghz read succeeded
```

The execution backend is the simulator (`simulator/device.zig`), so the command
demonstrates compilation, execution, audit and gating; it does not drive hardware.

## 9. Limits

| Limit | Value |
|---|---|
| Script size | 256 KiB |
| Statements per step | 512 |
| Steps | 256 |
| `use` declarations | 16 |
| `cap` declarations | 128 |
| Options per call | 32 |
| Name length | 128 bytes |
| Text length | 1024 bytes |
| Loop bound | 64 |
| `budget.time` | 10 minutes |
| Sub-script nesting | 8 |

## 10. Verifying a catalogue entry

`net.scan` returns the recorded observation for a lab target when the payload names it,
so a script can decide from data instead of from constants:

```lua
script "verify-cve-2021-41773" do
    use "pack.net"
    cap scan = net.scan
    step "lookup" do
        observation = scan { payload = "target=lab-apache-249.lan:18080" }
        out observation
        if observation.version == "2.4.49" then
            emit finding {
                severity = "critical",
                message = "CVE-2021-41773 applies: Apache 2.4.49 path traversal"
            }
        else
            emit info "version does not match the reproduced build"
        end
    end
end
```

The four CVE scripts in `samples/scripts/` cover the entries that the catalogue repository
reproduced in Docker (CVE-2021-41773, CVE-2021-42013, CVE-2024-31449 and the inconclusive
CVE-2026-44631). Observations come from `src/simulator/fixtures.zig`; they are recorded
values, not live traffic, and the targets are synthetic names.

`emit` fields accept literals or variable references (see section 6), so a finding can carry a value observed in the same step. A reference whose field does not exist fails the step rather than emitting an empty field.

The catalogue repository runs these scripts, then the matcher, and compares both results
with the reproduction evidence:

```powershell
PocketRootVulnerabilityDb/tools/Invoke-CapabilityCheck.ps1              # recorded observations
PocketRootVulnerabilityDb/tools/Invoke-CapabilityCheck.ps1 -Live        # plus a real probe
PocketRootVulnerabilityDb/tools/Invoke-CapabilityCheck.ps1 -Live -WithDocker
```

### Live scanning

`net.scan` reads the recorded observation unless the run asks for a probe:

```powershell
zig-out/bin/PocketRoot script run --live samples/scripts/live-scan.pk
zig-out/bin/PocketRoot script run --live --dump-vars samples/scripts/live-scan.pk
```

The same payload drives both modes (`target=host:port`), and the result has the same
`key=value` shape:

```
host=127.0.0.1
port=8080
state=open
transport=tcp
service=http
product=Apache
version=2.4.54
```

Live mode uses the TCP scanner, so protocol probes only run for the ports it knows
(80, 443, 6379, 8080, 3306, 5432 and the other documented defaults). A host mapped to an
unusual port connects successfully but reports no product or version. `--dump-vars`
prints every bound variable and is intended for diagnostics, not for evidence.
