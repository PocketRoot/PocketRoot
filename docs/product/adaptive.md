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
  require that fact, so the path depends on the previous output.
- The runner picks the eligible module with the smallest `priority` (ties: declaration
  order), excludes already-executed modules unless `repeatable`, and stops on the first
  module whose effect output contains `goal.contains`.

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
| No in-flight STOP | STOP is checked between modules; a request already in flight is not cancelled |
| No automatic module synthesis | modules are authored records with declared facts |
| No backtracking | once a module is executed it is excluded; there is no search over alternatives |
| HTTP records only | transports remain the record's transport |
| Goal is a substring check | no complex assertions or fact transformations |

These are explicit deferrals, not claims.
