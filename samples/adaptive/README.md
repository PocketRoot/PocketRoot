# Adaptive fixture

A local fixture for `pocketroot.adaptive.v1`. It is not a CVE.

Serve these endpoints on `127.0.0.1:8080`:

| Request | Response |
|---|---|
| `GET /discover?f=/etc/passwd` | `route=cmd;` |
| `GET /exec` | `uid=0(root)` |
| `GET /file` | `file-content` |

Then run:

```bash
PocketRoot campaign approve-adaptive samples/adaptive/goal.json \
    --reason "ticket ADAPT-FIXTURE" --confirm ADAPT-FIXTURE
PocketRoot chain adaptive samples/adaptive/goal.json \
    --campaign .pocketroot --evidence adaptive.json
```

Expected: `discover` runs, captures `route=cmd`, the runner selects `cmd` and skips
`file`, and `uid=0` satisfies the goal. The evidence records the actual two-step path.
