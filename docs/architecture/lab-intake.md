# Lab intake

The `18_CVE` lab is an external, read-only source of reproductions. PocketRoot absorbs
*request shapes and generic primitives*, never a per-CVE command.

## 2026-11-25 batch

| Shape in the lab | PocketRoot decision |
|---|---|
| HTTP cache miss followed by a cache hit, status/body oracle | `net.http` twice; `CVE-2018-1303/exploit.pk` |
| HTTP redirect with a hostile `Location` value | `net.http` now exposes `location` and checks `expect_location_prefix`; `CVE-2025-4123/exploit.pk` |
| Authorization boundary between two resources, Basic auth | `net.http` with headers; `CVE-2026-21721/exploit.pk` |
| 700 MB request-body allocation / OOM | Deliberately not ported; needs a streaming-body primitive with explicit size and memory limits |
| HTTP/2 state, header and framing defects | Not covered yet; needs a generic HTTP/2 frame client rather than a CVE branch |
| TLS SNI/cipher/pre-handshake defects | Not covered yet; needs client-side TLS/SNI controls |
| Unix-domain socket permission bypass | Not covered yet; needs a generic `net.unix` transport |
| Node.js/Python local runtime and policy defects | Out of scope for a network DSL; represented as local verification, not a `net.*` exploit |

## Rules

- The lab stays read-only; run its verified images or local mocks, never edit its scripts.
- A new CVE gets a `.pk` script and payload resources; core code changes must be generic.
- `expect_*` options set the oracle; the script must fail when `oracle ~= "pass"`.
- A large-body DoS is not admitted until the primitive has bounded memory and an explicit operator limit.
