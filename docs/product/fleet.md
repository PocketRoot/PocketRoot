# Fleet campaign

A fleet runs one adaptive goal against multiple targets. It is still single-goal, but each
target gets its own approval and its own runtime result; one target failing does not abort
the others.

## 1. Fleet document

```json
{
  "schema": "pocketroot.fleet.v1",
  "id": "FLEET-DEMO",
  "goal": "samples/adaptive/goal.json",
  "targets": ["127.0.0.1:8080", "127.0.0.1:8081"],
  "max_concurrency": 2
}
```

## 2. Per-target approval

```bash
PocketRoot fleet approve fleet.json \
    --target 127.0.0.1:8080 --reason "ticket FLEET-1" --confirm 127.0.0.1:8080
PocketRoot fleet approve fleet.json \
    --target 127.0.0.1:8081 --reason "ticket FLEET-2" --confirm 127.0.0.1:8081
```

Each approval has action id `ADAPT-<goal-id>@<target-hash>`, binds the goal bytes and every
module record digest, and authorises exactly one target. A missing approval becomes a
per-target `denied` result; it does not abort the fleet.

## 3. Execution

```bash
PocketRoot fleet run fleet.json --campaign .pocketroot --concurrency 2 --evidence fleet.json
```

- Targets run in bounded batches of `min(--concurrency, max_concurrency)`.
- Each target runs its own adaptive goal with the target substituted; facts and captures
  stay inside that target.
- Each target's failure/denial is captured as its own status.
- The shared ledger is serialized with an `Io.Mutex`; approvals are per target.
- STOP is checked before each batch and inside each adaptive run at module boundaries.
- Evidence is `pocketroot.fleet.evidence.v1` with one entry per target, its status,
  approval id, actual module steps and final facts.

Recorded run against two local fixtures:

```text
fleet FLEET-DEMO: 2 target(s)
  127.0.0.1:12383: succeeded
  127.0.0.1:12384: denied
```

After approving the second target both succeeded in one batch; the two-target run took
about 700 ms while each target needed two 300 ms requests, showing the batch overlap.

## 4. Boundaries

| Not provided | Consequence |
|---|---|
| No per-target result merge | each target has its own evidence and facts |
| No retry | a failed target stays failed until rerun with a new approval |
| In-flight STOP | each target's adaptive HTTP reads check STOP every ~100 ms; batch scheduling still starts only before a stop is seen |
| Synthesis is metadata-driven | a goal can use `records`; modules come from record metadata or match/capture inference |
| Backtracking replays requests | per-target DFS restores runner state, not target-side effects |
| HTTP + UDP records only | other transports need new primitives |

These are deliberate gaps; the next work is in-flight cancellation and module synthesis.
