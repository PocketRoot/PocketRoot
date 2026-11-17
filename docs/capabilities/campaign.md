# Campaign control plane

Status: phase A. This page documents what is implemented today: a read-only attack-surface
report, single-use human approvals with a configurable TTL, a stop control, and a
hash-chained ledger. There is no exploit executor in this build; `campaign run` refuses
anything except `--dry-run`.

## 1. Model

```
scope.json        what this campaign may touch, which techniques, when it expires, the TTL
   |
surface          read-only reasoning: target -> weakness -> feasibility -> candidate action
   |
approve          a human reads the action and types the action id; one approval is minted
   |
run              stopped? armed? target in scope? approval live, unused and bound? -> execute
   |
ledger           every decision, approval and consumption is appended and hash-chained
```

The control plane is transport-agnostic: the surface report, a future validation executor
and a future exploit executor all call `services/control.zig`. The module does not know how
an action is executed; it only decides whether one may start.

## 2. Scope document

```json
{
  "schema": "pocketroot.scope.v1",
  "scope_id": "lab-repro-hosts",
  "targets": ["192.0.2.0/24", "lab-apache-249.lan"],
  "techniques": ["validate", "exploit"],
  "expires_at_unix": 4102444800,
  "approval_ttl_seconds": 600,
  "max_actions": 16
}
```

| Field | Rule |
|---|---|
| `scope_id` | non-empty, at most 128 bytes |
| `targets` | 1-128 entries; exact hostname/IP or IPv4 CIDR |
| `techniques` | 1-8 of `validate`, `exploit`, `credential`, `lateral` |
| `expires_at_unix` | positive; the campaign refuses to arm or approve after it |
| `approval_ttl_seconds` | **configurable**, 1-86400; default 900 (15 minutes) |
| `max_actions` | 1-4096; checked before a new action starts |

The effective approval expiry is the earlier of `now + approval_ttl_seconds` and the scope
expiry, so a short campaign cannot outlive its scope.

## 3. Commands

```bash
# create .pocketroot with the scope copied in; the campaign starts disarmed
PocketRoot campaign init --scope samples/campaign/scope.json

# arm after reviewing the scope; arming clears a previous stop marker
PocketRoot campaign arm

# read-only: builds the attack surface and writes .pocketroot/surface.json
PocketRoot campaign surface --catalog samples/campaign/catalog.jsonl \
    --protocol nmap samples/network/lab-repro-hosts.xml

# human approval: no --yes, the action id must be typed twice
PocketRoot campaign approve ACTION-1 --reason "ticket SEC-1" --confirm ACTION-1

# gate + consume + ledger; only dry-run exists today
PocketRoot campaign run ACTION-1 --dry-run

# effect execution: approve the record, target and effective params
PocketRoot campaign approve-exploit samples/exploits/CVE-2018-7600/record.json \
    --reason "ticket SEC-2" --confirm CVE-2018-7600 --param command=id
PocketRoot exploit run samples/exploits/CVE-2018-7600/record.json \
    --campaign .pocketroot --param command=id

# one approval for an output-driven adaptive goal
PocketRoot campaign approve-adaptive goal.json --reason "ticket ADAPT-1" --confirm ADAPT-DEMO
PocketRoot chain adaptive goal.json --campaign .pocketroot

# one approval for a detected chain
PocketRoot chain plan --observations samples/observations/lab.json --out chain.json
PocketRoot chain approve chain.json --reason "ticket CHAIN-1" --confirm CHAIN-...
PocketRoot chain run chain.json --campaign .pocketroot

PocketRoot campaign status
PocketRoot campaign stop
```

`campaign surface` is read-only: it never sends traffic and never requires an approval. It
writes the report to `<dir>/surface.json` and prints Markdown by default (`--json` for the
document).

## 4. Approval rules

- **No `--yes`.** `campaign approve` prints the target, weakness and technique and requires
  `--confirm <ACTION-ID>`; a mismatch changes nothing.
- **Single use.** The approval is consumed *before* the action starts; a failed action does
  not refund it. A second run is denied with `approval was already consumed`.
- **Bound.** The approval records `scope_id`, `action_id`, `target`, `technique` and the
  action `params_hash`; changing any of them invalidates it.
- **Short-lived.** It expires with the scope TTL (configurable) and never outlives the scope.
- **Feasible only.** `campaign approve` refuses an action whose `feasibility` is not
  `feasible` (for example `needs_capability`, `manual` or `unknown`), so an approval cannot
  turn an unavailable technique into an available one.
- **Disarmed by default.** Approvals can only be minted while the campaign is armed; a stop
  sets the phase back to `stopped`.

## 5. Stop rules

`campaign stop` writes `<dir>/STOP`, sets the phase to `stopped` and appends a ledger
entry. `evaluate` checks the stop marker before anything else, so:

- a new action is refused with `campaign is stopped`;
- arming clears the marker only through an explicit `campaign arm`;
- `exploit run` checks the marker before the first request and after the last one; it does
  not currently check between every step, so a stop cannot interrupt a multi-step chain in
  flight.

The stop control is software-only today. A real device must add an independent hardware
inhibit line and a watchdog; the marker is not a substitute for cutting PA/VBUS/NFC power.

### 5.1 Exploit reproductions

A reproduction record with `"kind": "exploit"` is not a free-standing command. Bind it to a
campaign, approve it, then run it:

```bash
PocketRoot campaign approve-repro repro/record.json --reason "ticket SEC-1" --confirm CVE-2021-41773
PocketRoot reproduce repro/record.json --campaign .pocketroot --evidence repro.json
```

`approve-repro` binds the approval to the record's CVE, target and **script bytes**; editing
the script invalidates it. `reproduce` calls the same `evaluate`, consumes the approval
before staging the script, checks the stop marker, and writes `repro-start`/`repro-result`
to the ledger. Validation records (`kind: "validate"`) still run without a campaign.

### 5.2 Exploit records

`campaign approve-exploit <record.json>` is the equivalent gate for
`pocketroot.exploit.v1` records. It binds the approval to the record bytes, target, CVE and
the sorted effective params (`--param k=v`), then `exploit run --campaign <dir>` evaluates,
consumes the approval before its first request and writes `exploit-start`/`exploit-result`.
Changing the command, file, target or any step invalidates the approval. See
[exploits](../product/exploits.md).

### 5.3 Chain approvals

`chain approve` binds the plan bytes and target; `chain run` (CLI) and `exploit.execute` (kernel capability, active) re-check every record
digest, checks STOP before and after each step, consumes the approval before the first
step and writes `chain-start`, `chain-step` and `chain-result`. This is the single
approval path for automatic multi-step exploitation.

### 5.4 Adaptive approvals

`campaign approve-adaptive` binds the goal bytes and every referenced record digest.
`chain adaptive` / `exploit.adaptive` consume the approval before the first module,
check STOP between modules and record the actual runtime path. The approval does not
contain a step list; it authorises the module set, target and goal.

### 5.5 Fleet approvals

`fleet approve` mints one approval per target with action id
`ADAPT-<goal-id>@<target-hash>`; the goal bytes and every module record digest are bound.
`fleet run` executes targets in bounded batches, isolates failures and serializes shared
ledger writes. See [fleet](../product/fleet.md).

## 6. Ledger

`<dir>/ledger.jsonl` uses `pocketroot.ledger.v1`:

```json
{"schema":"pocketroot.ledger.v1","seq":4,"at_unix":1794765901,"event":"run-dry","action_id":"ACTION-2","approval_id":"13f3f80323bb662e","target":"192.0.2.80","technique":"exploit","result":"dry-run","detail":"no traffic sent","prev_hash":"...","hash":"..."}
```

`hash` is SHA-256 over the canonical fields including `prev_hash`, so deleting or editing a
middle entry breaks the chain. The chain is tamper-evident, not signed; anyone who can
rewrite the file can recompute it.

## 7. Surface report

`surface.json` uses `pocketroot.surface.v1`. Each action carries:

| Field | Meaning |
|---|---|
| `id` | `ACTION-N`, stable for this report |
| `target`, `target_identity` | chosen address/hostname/package identity |
| `vulnerability_id`, `title`, `severity`, `cvss` | catalogue entry |
| `access` | from the CVSS `AV:` component: network/adjacent/local/physical/unknown |
| `capability` | the primitive the action would need (`network.probe`, `radio.wifi/ble`, `host.access`, `physical.access`) |
| `feasibility` | `feasible`, `needs_capability`, `manual`, `out_of_scope`, `unknown` |
| `in_scope` | whether any identity of the asset matches the scope |
| `requires_approval` | true for every exploit action |
| `endpoint` | `transport/port` |
| `params_hash` | SHA-256 binding scope, target, weakness and endpoint |
| `reason` | why the action has this feasibility |

Feasibility is deliberately conservative. `network` only means this engine has a network
primitive; it does not mean an exploit exists or that its preconditions hold. A CVSS vector
is required: catalogue v1 entries without a vector are reported as `unknown`, which is why
the sample uses a v2 entry.

## 8. What is not provided

| Gap | Consequence |
|---|---|
| No validation executor | `feasible` actions cannot be run; `campaign run` requires `--dry-run` |
| No exploit executor or exploit knowledge base | no payload, session or post-exploitation code exists |
| No transport authentication | approvals are local files; a compromised campaign directory can mint approvals |
| Operator identity is a string | `--operator` is recorded, not authenticated; add TOTP/WebAuthn for real deployments |
| Network probes are not routed through this gate | `tcp-scan`, `http-inspect`, `tls-inspect` and `net.http`/`reproduce` predate or bypass the control plane |
| Exploit reproduction needs a campaign | `reproduce --campaign` for a `kind: "exploit"` record uses the same approval/stop/ledger path; validation records do not |
| Ledger is not signed | tamper-evident only |
| No hardware stop | no inhibit line, no watchdog, no power cut |

## 9. Verification

The end-to-end test in `src/cli/main.zig` (`campaign surface, approval and stop gate a dry
run`) covers: init with a 60 s TTL, arm, one feasible action from a synthetic v2 catalogue,
approval, a successful dry run, denial on reuse, stop, and denial after stop. `zig build
check` runs it with the rest of the suite.
