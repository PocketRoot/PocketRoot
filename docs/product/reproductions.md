# Reproductions

A reproduction is a PocketRoot DSL script plus a record that says which target to run it
against and what behaviour is expected. The scripts are rewritten for PocketRoot; the
research repository at `18_CVE` is read-only and none of its scripts are executed.

## 1. Record

```json
{
  "schema": "pocketroot.reproduction.v1",
  "cve": "CVE-2021-41773",
  "class": "path-traversal",
  "oracle": "http-response",
  "target": "127.0.0.1:8080",
  "script": "probe.pk",
  "expected": "vulnerable",
  "kind": "validate"
}
```

| Field | Meaning |
|---|---|
| `cve` | catalogue identity the probe is derived from |
| `class`, `oracle` | the research classification copied into the record for reporting |
| `target` | host:port rendered into the script's `{{target}}` placeholder |
| `script` | path relative to the record |
| `expected` | `vulnerable` or `fixed`; used to name the observed outcome |
| `kind` | `validate` for read-only proofs; `exploit` records require a campaign approval |

The record does not contain a payload or a shell command. The probe is the DSL script.

For an exploit record, the campaign path is mandatory:

```bash
PocketRoot campaign approve-repro samples/reproductions/.../record.json \
    --reason "ticket SEC-1" --confirm CVE-...
PocketRoot reproduce .../record.json --campaign .pocketroot --evidence repro.json
```

The approval binds the record's CVE, target and script bytes; the runner consumes it
before staging the script and records `action_id`/`approval_id` in the evidence.

## 2. Runner

```bash
PocketRoot reproduce samples/reproductions/CVE-2021-41773/record.json \
    --evidence repro.json
```

1. Read the record and the script.
2. Replace every `{{target}}` with `target`.
3. Stage the result under `.zig-cache/tmp` and run it with the live backend.
4. Print the script status, audit lines and emitted findings.
5. Write `pocketroot.reproduction.evidence.v1` when `--evidence` is given.

Exit code 0 means the script's own oracle passed; 1 means it failed or the record was
invalid. `--json` prints the evidence document instead of the summary.

```json
{
  "schema": "pocketroot.reproduction.evidence.v1",
  "cve": "CVE-2021-41773",
  "class": "path-traversal",
  "oracle": "http-response",
  "target": "127.0.0.1:8080",
  "expected": "vulnerable",
  "observed": "vulnerable",
  "script": "probe.pk",
  "status": "succeeded",
  "recorded_at_unix": 1794926440
}
```

## 3. Samples

`samples/reproductions/CVE-2021-41773/` contains:

- `probe.pk`: GET `/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`, expects 200 and
  `root:x:0:0`; fails with a message otherwise.
- `control-fixed.pk`: same path, expects 400 and the marker absent.
- `record.json`, `record-exploit.json` (same probe, `kind: exploit`) and `README.md`.

`samples/reproductions/CVE-2021-42013/` is the same shape for the double-encoded path
(`.%%32%65`), targeting httpd 2.4.50.

The target must be an httpd 2.4.49 lab instance with `<Directory />` relaxed to
`Require all granted`, as described by the research record. The repository does not start
containers.

## 4. Boundaries

| Not provided | Consequence |
|---|---|
| No Docker orchestration | the operator starts the lab target; the runner only sends requests |
| No exploit executor | exploit records are gated, but there is no payload generator, session or post-exploitation step |
| Validation records bypass scope | `kind: "validate"` runs without a campaign; only exploit records are scope/approval gated |
| HTTP only | listener, crash and compile-rejection oracles need separate primitives |
| No provenance verification | the record is a rewrite, not a byte copy of the research artifact |

## 5. Adding a record

1. Rewrite the research probe as a `.pk` script using `net.http` and `fail`.
2. Keep the request byte-exact; do not let a client normalise the path.
3. State the oracle in the call (`expect_status`, `expect_body`, `expect_absent`).
4. Add a negative control when the research record has one.
5. Add `record.json` with target, expected and class/oracle.
6. Run it against a lab target and attach the evidence document.
