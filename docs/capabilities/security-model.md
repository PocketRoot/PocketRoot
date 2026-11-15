# Security model

This page describes the gating behaviour implemented in the capability kernel, the IPC
framing and the simulated backend. The kernel is library code; the CLI does not call it.
The script runner does use it, through the automation adapter.

## 1. Properties

| Property | Mechanism |
|---|---|
| Active operations are denied by default | `Operation.isActive()`; only observe, read, capture and analyze are passive |
| Dual authorisation | Policy `allow_active` **and** request `active_authorized` must both be true |
| Region compliance | Active `subghz` operations require non-empty, equal policy and request regions |
| Auditability | Every execution, including denial, busy and failure, appends an `AuditEntry` |
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

## 6. What the model does not provide

| Missing | Consequence |
|---|---|
| No process isolation or sandbox | The backend runs in the same process; a backend crash crashes the process |
| `subject` is an arbitrary string | It is not an authenticated identity and cannot prevent spoofing |
| Audit log is in memory only | Entries are lost on exit; they are neither signed nor persisted |
| No rate limiting | Locks provide mutual exclusion, not quotas |
| No policy source | The caller constructs `Policy`; there is no signed configuration file |
| No OS permission checks | The kernel does not verify privileges such as those `pktmon` requires |
