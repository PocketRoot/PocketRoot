# Security model

This page describes the gating behaviour implemented in the capability kernel, the IPC
framing, the simulated backend and the host entry point. The kernel is library code: the
CLI reaches it through the automation adapter (`script run`) and through
`services/device_host.zig` (`device info|request|serve`).

## 1. Properties

| Property | Mechanism |
|---|---|
| Active operations are denied by default | `Operation.isActive()`; only observe, read, capture and analyze are passive |
| Dual authorisation | Policy `allow_active` **and** request `active_authorized` must both be true |
| Region compliance | Active `subghz` operations require non-empty, equal policy and request regions |
| Auditability | Every execution, including denial, busy and failure, appends an `AuditEntry` carrying subject, kind, operation, status, region and the authorization flag |
| Resource exclusion | One exclusive lock per `Kind`, so two requests cannot drive the same peripheral |
| Emergency stop | `emergencyStop()` sets `stopped` and releases every lock; later requests fail with `EmergencyStopped` |

## 2. Authorisation order (`core/capability.zig`)

```
stopped?                          -> EmergencyStopped
subject empty / > 128 B           -> MissingSubject / SubjectTooLong
payload > 1 MiB                   -> PayloadTooLarge
operation.isActive()?
   not policy.allow_active        -> ActiveOperationDenied
   not request.active_authorized  -> ActiveOperationDenied
   kind == subghz?
        either region empty       -> RegionRequired
        regions differ            -> RegionMismatch
```

Emergency stop takes precedence over everything else, and the region check applies only to
active radio transmission, not to passive reception.

## 3. Execution and audit

| Event | Audit status |
|---|---|
| Authorisation refusal | `denied` |
| Resource busy | `busy` |
| Backend error | `failed` |
| Backend result | the backend's own status |

The audit log holds 4096 entries and returns `AuditLogFull` when full, so a request is
refused rather than executed unaudited. Result data is owned by the result and must be
released by the caller.

`device --audit <path>` appends each new entry to a JSONL file (`pocketroot.audit.v1`)
before the next request runs, and `audit <path>` reads it back. The kernel itself stays
memory-only: a process that never configures a sink leaves no file behind. `seq` is the
durable log order (it continues across runs); `request_id` is the kernel's per-process
request id and restarts with each process, so `seq` is the field to cite as evidence.

## 4. IPC properties (`device/ipc.zig`)

| Property | Implementation |
|---|---|
| Integrity | CRC-32 (IEEE, test vector 0xCBF43926) over header and payload |
| Exact length | `bytes.len == encodedSize(payload_len)`; extra or missing bytes are rejected |
| Replay rejection | `Session.accept` rejects `sequence <= last_rx` |
| Version pinning | `version == 1`, otherwise `UnsupportedVersion` |
| Size bound | payload <= 1 MiB |

The command layer additionally requires `active_authorized` to be exactly 0 or 1 and
`region_len <= 8` with no overrun.

## 5. Simulated backend

```
kind not enabled -> Result{ .unsupported, "simulator capability unavailable" }
kind enabled     -> Result{ .succeeded, payload or "simulated" }
```

A disabled capability reports `unsupported`; it never reports success. The corresponding
test asserts that the simulator completes a request without claiming hardware.

## 6. Host entry point

`device request` executes one request and prints its status and data; it exits 1 when the
kernel denies or the backend fails.

```
PocketRoot device request infrared read --payload capture
PocketRoot device request subghz transmit --allow-active --authorize-active --region EU --payload frame
PocketRoot device request subghz transmit --authorize-active          # denied, exit 1
```

`device serve` is the frame-level path: it reads PKRT request frames (stdin, or
`--frames` for a recorded stream) and writes response frames. Every request goes through
the same policy, lock, backend and audit sequence as a library call; a replayed sequence
is answered with `ReplayedFrame` and never reaches the backend.

```
PocketRoot device serve --transport loopback --frames samples/device/request-infrared.pkrt --output responses.pkrt
```

## 7. Campaign control plane

`services/control.zig` is the authorization layer for actions that are not device
capabilities (network validation and, later, exploitation). It is separate from the
capability kernel on purpose: the kernel gates a device operation, while the campaign layer
gates an *action against a target*.

| Property | Implementation |
|---|---|
| Default deny | The campaign starts `disarmed`; `evaluate` refuses anything but `armed` |
| Scope | Exact hostname/IP or IPv4 CIDR; techniques validated against `validate/exploit/credential/lateral` |
| Approval | Single-use, bound to scope/action/target/params hash; TTL comes from the scope (`approval_ttl_seconds`, default 900 s, maximum 86400 s) and is capped by the scope expiry |
| No blanket yes | `campaign approve` requires `--reason` and a typed `--confirm <ACTION-ID>`; there is no `--yes` |
| Consumption | The approval is marked used before the action starts; a failure does not refund it |
| Stop | `campaign stop` writes `STOP`; `evaluate` checks it before the state, scope or approval |
| Ledger | `pocketroot.ledger.v1` entries are hash-chained with `prev_hash`; tamper-evident, not signed |

The read-only `campaign surface` needs no approval and sends no traffic. `campaign run`
only supports `--dry-run` in this build: the gate, consumption and ledger are real, the
execution is not. See [campaign](campaign.md) for the command flow and limits.

## 8. What the model does not provide

| Missing | Consequence |
|---|---|
| No process isolation or sandbox | The backend runs in the same process; a backend crash crashes the process |
| `subject` is an arbitrary string | It is not an authenticated identity and cannot prevent spoofing |
| Audit log is in memory by default | `--audit` exports JSONL, but entries are neither signed nor chained; a crash before the sink write loses the newest record |
| No rate limiting | Locks provide mutual exclusion, not quotas |
| No policy source | The caller constructs `Policy`; there is no signed configuration file |
| No OS permission checks | The kernel does not verify privileges such as those `pktmon` requires |
| Campaign approvals are local files | A compromised campaign directory can mint approvals; operator identity is a recorded string, not an authenticated principal |
| Campaign stop is software-only | No hardware inhibit line or watchdog exists; a real device must add both |
| Network probes bypass the campaign gate | `tcp-scan`, `http-inspect`, `tls-inspect`, `net.http`/`net.udp` scripts and validation `reproduce` records predate the control plane and do not require an approval |
| Exploit effects are not sandboxed | `exploit run` sends the approved requests only; the effect on the target (command execution, file read) is limited by the target, not by the engine |
| Stop is checked at exploit boundaries | The runner checks STOP before the first and after the last step, not between steps of an in-flight chain |
