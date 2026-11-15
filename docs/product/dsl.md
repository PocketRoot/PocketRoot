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
        sig = rf_capture { into = "artifact" }
        if sig.protocol == "Princeton" then
            rf_tx { payload = sig.raw, on_error = "continue" }
            emit finding {
                severity = "info",
                message  = "replayed princeton frame",
                tag      = sig.name
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
| Strings | Double quotes with escapes; no long-bracket strings |
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
| Conditions | A comparison references a variable assigned earlier in the same step, or one exported with `out`. Comparing two variables and mixing `and` with `or` are rejected with `UnsupportedCondition` |
| `stop` | Ends the enclosing statement list; later statements are not compiled |
| `emit` | Records a finding without contacting the capability service |

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
