# Adaptive exploitation

A static plan lists the steps up front. An adaptive goal lists **modules** and lets the
runner choose the next one from the facts it has, including captures produced by the
previous step. The plan is recomputed after every module; the executed path is only known
at runtime.

## 1. Goal

```json
{
  "schema": "pocketroot.adaptive.v1",
  "id": "ADAPT-DISCOVER",
  "target": "127.0.0.1:8080",
  "goal": { "contains": "uid=" },
  "max_steps": 4,
  "facts": [{ "name": "service", "value": "http" }],
  "modules": [
    {
      "id": "discover",
      "record": "records/discover.json",
      "requires": [{ "fact": "service", "equals": "http" }],
      "inputs": [{ "name": "file", "fact": "target_file", "default": "/etc/passwd" }],
      "outputs": [{ "fact": "route", "capture": "route" }],
      "priority": 0
    },
    {
      "id": "cmd",
      "record": "records/cmd.json",
      "requires": [{ "fact": "route", "equals": "cmd" }],
      "priority": 10
    },
    {
      "id": "file",
      "record": "records/file.json",
      "requires": [{ "fact": "route", "equals": "file" }],
      "priority": 10
    }
  ]
}
```

- `facts` seed the fact store; `target` is always present.
- A module is eligible when every `requires` predicate matches a fact and every input can
  be resolved from a fact or a default.
- `inputs` bind record template parameters such as `{{file}}`.
- `outputs` copy a capture from the record response into a fact. The next module can
  require that fact, so the path depends on the previous output. An output can name a
  `transform`: `trim`, `lower`, `upper`, `url_decode`, `base64_decode`, `hex_decode`
  or `identity`.
- The runner picks the eligible module with the smallest `priority` (ties: declaration
  order), excludes already-executed modules unless `repeatable`, and stops on the first
  module whose effect output contains `goal.contains`.

## 1.1 Automatic module synthesis

A goal can omit `modules` and point at a record directory:

```json
{
  "schema": "pocketroot.adaptive.v1",
  "id": "ADAPT-AUTO",
  "target": "127.0.0.1:8080",
  "goal": { "contains": "uid=" },
  "max_steps": 4,
  "facts": [{ "name": "service", "value": "http" }],
  "records": "samples/adaptive/records"
}
```

When `modules` is empty, the runner walks `records` and synthesises modules. A record's
optional `module` block supplies id/requires/inputs/outputs/priority. Without it, the
synthesizer uses `match.service`/`match.product`/`match.version_prefix` as requires and
step `capture` names as outputs. The approval hash is computed **after** synthesis, so it
still binds every referenced record digest.

## 1.2 Backtracking

Selection is a bounded depth-first search, not a single greedy pick. After a module runs,
the runner tries the next eligible module recursively. If a branch cannot reach the goal,
it rolls back the facts and the executed-module mark, frees the step, and tries the next
candidate. Replayed requests have side effects that cannot be undone; backtracking only
restores the runner's state.

Example: `a` captures `route=bad`; priority 1 module `b` overwrites `route=dead` and
dead-ends; the runner rolls back to `route=bad` and tries `c`, which returns `uid=0`.
The evidence shows `a` and `c`; the server saw `/a`, `/b` and `/c`.

## 2. Approval and execution

```bash
PocketRoot campaign approve-adaptive goal.json --reason "ticket ADAPT-1" --confirm ADAPT-DISCOVER
PocketRoot chain adaptive goal.json --campaign .pocketroot --evidence adaptive.json
```

The approval binds the goal bytes **and every referenced record digest**; changing a module
record invalidates it. The runner checks STOP before and after each module, consumes the
approval before the first module, writes `adaptive-start`/`adaptive-step`/
`adaptive-result` to the ledger, and records the actual steps, outputs and facts in
`pocketroot.adaptive.evidence.v1`.

From the DSL (active kernel capability):

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

Run it with `--authorize-active`; `exploit.adaptive` maps to `Kind.exploit` +
`Operation.manage`, and the handler still requires the campaign approval.

## 3. Recorded run

Against a local fixture:

- `discover` returns `route=cmd;`, captured as `route=cmd`.
- the runner selects `cmd` (satisfied by `route=cmd`) and skips `file`
  (requires `route=file`).
- `cmd` returns `uid=0(root)`; the goal `contains uid=` is met.

```text
server /discover?f=/etc/passwd
server /exec
adaptive ADAPT-DEMO: succeeded
  discover CVE-DISCOVER oracle=pass
  cmd CVE-CMD oracle=pass
facts:
service=http
target=127.0.0.1:22180
route=cmd
```

The same goal through the DSL produced `exploit manage succeeded` and the adaptive
evidence document; a reused approval is audited as `denied`.

## 4. Boundaries

| Not provided | Consequence |
|---|---|
| No multi-target campaign | one goal targets one host |
| No concurrency | modules run sequentially |
| In-flight STOP | the HTTP read loop checks the STOP marker every ~100 ms and aborts with status `stopped`; a connect/write already in progress can still complete |
| Synthesis is metadata-driven | records without a `module` block only get match-derived requires and capture-derived outputs |
| Backtracking replays requests | rollback restores facts/selection, not target-side effects |
| HTTP + UDP records only | other transports need new primitives |
| Goal is a substring check | no complex assertions or fact transformations |

These are explicit deferrals, not claims.
