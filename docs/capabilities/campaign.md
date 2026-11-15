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
- a running executor is expected to check the same marker between actions and before each
  network call. This build does not contain such an executor, so the marker's runtime effect
  is limited to what the caller implements.

The stop control is software-only today. A real device must add an independent hardware
inhibit line and a watchdog; the marker is not a substitute for cutting PA/VBUS/NFC power.

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
| Network probes are not routed through this gate | `tcp-scan`, `http-inspect` and `tls-inspect` predate the control plane and still bypass it |
| Ledger is not signed | tamper-evident only |
| No hardware stop | no inhibit line, no watchdog, no power cut |

## 9. Verification

The end-to-end test in `src/cli/main.zig` (`campaign surface, approval and stop gate a dry
run`) covers: init with a 60 s TTL, arm, one feasible action from a synthetic v2 catalogue,
approval, a successful dry run, denial on reuse, stop, and denial after stop. `zig build
check` runs it with the rest of the suite.
