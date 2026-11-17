# Network capabilities

Every service declares its limits at the top of the file, validates at the entry point,
returns an `AnalysisResult`, and records results both as human-readable fields and as
`NetworkObservation` records. Confidence rules are described in
[`architecture/contracts.md`](../architecture/contracts.md).

## 1. Local environment: `network`

`services/network_environment.zig`

- Runs `powershell.exe -NoLogo -NoProfile -NonInteractive` with a fixed
  `Get-NetIPConfiguration` script and compressed JSON output.
- 10 s timeout; stdout <= 1 MiB, stderr <= 64 KiB; a non-zero exit is
  `NetworkInspectionFailed`.
- Keeps only interfaces whose status is Up and picks a primary interface by gateway
  presence, then lowest metric, then physical adapter.
- Derives `direct_scope_N` entries: skips 0.x, 127.x and >= 224 addresses, computes the
  network address per prefix and deduplicates.
- Fields: `interfaces`, `active_interfaces`, `ipv4_addresses`, `ipv6_addresses`,
  `gateways`, `dns_servers`, `direct_scopes`, `primary_interface`, `primary_scope`.

The parsing function is separable and covered by fixture tests, so the analysis can be
verified without Windows.

## 2. Neighbours and ICMP: `neighbor`

`services/neighbor_probe.zig`

- For each target it runs `PING.EXE -n 1 -w <ms>`, then `Get-NetNeighbor` (with an
  interface index for IPv6).
- Targets are validated strictly: literal addresses only; `0.0.0.0`, addresses >= 224,
  IPv6 multicast and IPv6 link-local addresses without a `%scope` suffix are rejected.
- Observation rules: a successful ping produces a `confirmed` observation with transport
  `icmp`/`icmpv6`; a neighbour-cache hit alone produces an `observed` observation with
  transport `arp`/`ndp`; a target with neither is dropped.
- Neighbour states are restricted to `Reachable/Stale/Delay/Probe/Permanent`; MAC
  addresses must be 12 or 16 hexadecimal digits.

## 3. TCP probing: `tcp-scan`, `discover`, `scan-cidr`

`services/tcp_scan.zig`

Probing is a TCP connect with a timeout, executed sequentially. Connect errors are mapped
to five states: `open`, `closed`, `filtered`, `timed_out`, `host_unreachable`.

Active probes are read-only and minimal:

| Port | Request |
|---|---|
| 80, 8000, 8080, 8888 | `OPTIONS * HTTP/1.0` with Host and `Connection: close` |
| 6379 | `INFO SERVER\r\n` |
| 5432 | PostgreSQL `SSLRequest` (8 fixed bytes) |
| 21, 22, 23, 25, 110, 143, 3306, 5900 | nothing; read the banner |
| any other port | nothing; read the banner |

Protocol evidence upgrades a port to a confirmed service: SSH identification string,
`HTTP/1.x`, `RFB `, Redis replies, MySQL handshake version, the PostgreSQL SSLRequest
`S`/`N` answer, and POP3/IMAP/FTP/SMTP greetings. Without evidence the service stays a
port-number inference at `inferred` confidence.

The three commands share one probing core; they differ in target enumeration and
concurrency:

| Command | Hosts | Ports | Workers | Total budget |
|---|---|---|---|---|
| `tcp-scan` | 1 | <= 32 | 1 | <= 30 s |
| `discover` | <= 64, sequential | <= 4 | 1 | <= 30 s |
| `scan-cidr` | <= 256 | <= 64 per batch of 32 | <= 32 | <= 120 s |

Limits:

- CIDR enumeration is IPv4 only; IPv6 ranges are rejected.
- `scan-cidr` uses the SMP allocator for per-host work after the first batch and the main
  allocator only for aggregation.
- At most 1024 observations are retained; the excess is counted in
  `observations_dropped`.

## 4. HTTP posture: `http-inspect`

`services/http_inspect.zig`

- Only `HEAD` and `OPTIONS` are issued.
- Redirects are followed for at most 3 hops and only within the same origin and scheme;
  cross-origin and scheme changes are reported as `blocked_cross_origin` and
  `blocked_scheme_change`.
- Total response bytes are capped at 8 KiB (`HttpResponseByteLimitExceeded`).
- Checks six security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy.
- Emits host, endpoint and service observations; literal IPs are recorded as `address`,
  names as `hostname`.

### 4.1 Raw probe: `net.http`

`services/http_probe.zig` is the reproduction primitive behind the DSL's `net.http`:

- Sends a raw HTTP/1.1 request with GET/POST/HEAD/PUT/DELETE, an unnormalised path, an
  optional form body and `Connection: close`.
- Caps the response at 256 KiB and the body at 64 KiB; accepts chunked and Content-Length
  bodies.
- No redirect following, no client path normalisation, no TLS (use `tls-inspect` for
  certificates).
- The spec carries an oracle: `expect_status`, `expect_body`, `expect_absent`. The
  result is `oracle=pass|fail` plus `status`, `status_line`, `body_bytes` and a
  shortened `body_prefix`.
- Timeout 50-5000 ms. Path, target and method are validated before connecting.

The live backend dispatches a JSON spec only when `--live` is set; without it the
simulator echoes the payload, so a script can be reviewed offline but not claim a probe.

### 4.2 Datagram probe: `net.udp`

`services/udp_probe.zig` sends one datagram and waits for one response:

- Bind a local UDP socket, resolve the target, send `data` (1-4096 bytes), receive one
  datagram (64 KiB cap) with a 50-5000 ms timeout.
- Oracle: `expect_min_bytes`, `expect_body`, `expect_absent`.
- Result: `bytes`, `ratio`, `body_prefix`, `oracle`, `oracle_reason`.
- A missing response is an oracle failure (`succeeded` + `oracle=fail`), not a transport
  error, so the script can decide with `fail`.

It is a measurement primitive: a large response does not prove source-address spoofing
or that a third party can trigger it.

## 5. TLS: `tls-inspect` and `formats/tls_certificate.zig`

`services/tls_inspect.zig`

1. Resolve the host name with a timeout race and use the first address.
2. Perform a real handshake with `std.crypto.tls.Client` and deliberately
   `.ca = .no_verification`, so an untrusted site still completes the handshake and can
   be examined.
3. Verify the host name separately (`.host = .explicit`); a mismatch is reported as
   `hostname_match=no` rather than failing the inspection.
4. Reconstruct the certificate chain from the raw handshake records: plaintext handshake
   records for TLS 1.2, decryption through `SslKeyLog` derived keys for TLS 1.3
   (AES-GCM, ChaCha20 and AEGIS suites).
5. Validate the chain against the system CA bundle and apply constraint checks.
6. Fields: `tls_version`, `cipher_suite`, `hostname_match`, `ca_trust`,
   `ca_trust_detail`, `handshake` plus certificate metadata.

Fail-closed cases in `formats/tls_certificate.zig`:

| Situation | Result |
|---|---|
| Intermediate certificate without `CA=true` | `CertificateIssuerIsNotCa` |
| keyUsage present without `keyCertSign` | `CertificateIssuerCannotSignCertificates` |
| EKU present without `serverAuth` | `CertificateNotValidForTlsServer` |
| pathLen exceeded | `CertificatePathLengthExceeded` |
| nameConstraints present | `UnsupportedNameConstraints` (no downgrade) |
| Issuer not found | `CertificateIssuerNotFound` (AIA is not fetched) |

Only the chain supplied by the server is used; missing intermediates cannot be fetched.
OCSP and CRL are not consulted. Certificate metadata caps SAN summaries at 16 entries and
512 bytes.

## 6. Packet capture: `capture`

`services/live_capture.zig`

```
pktmon start --capture --comp <id> --pkt-size 0 --file-name <etl> --file-size <mb> --log-mode circular
sleep <duration>                      # 1..60 s
pktmon stop
pktmon etl2pcap <etl> --out <partial.pcapng>
validate: section header magic, byte order, block length consistency, trailing block length
rename partial -> target path (refuses an existing target)
```

- `pktmon.exe` is resolved from System32 through `windows_system.executablePath`; inputs
  containing absolute paths, `:` or `..` are rejected.
- Output must be at most 80 MiB and end in `.pcapng`; temporary `.etl` and
  `.partial.pcapng` files are removed on failure.
- Administrator rights are required by `pktmon` itself; the code neither checks nor
  elevates. Failure surfaces as `CaptureStartFailed`.

## 7. Execution location

`tcp-scan` and the HTTP/TLS inspectors use the Zig standard library network stack.
`network`, `neighbor` and `capture` invoke Windows system tools. All observation traffic
therefore originates from the host process, not from dedicated hardware.
