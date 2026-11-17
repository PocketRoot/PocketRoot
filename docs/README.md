# PocketRoot documentation

PocketRoot is a Zig-first portable security capability engine. This directory documents
what the software does and how to verify it. Every behavioural claim is anchored to code
(`file:line`) or to a reproducible command.

## Documents

| Document | Contents |
|---|---|
| [architecture/overview](architecture/overview.md) | Layers, data flow, main execution paths, extension points |
| [architecture/contracts](architecture/contracts.md) | Plugin contract, result model, limits, IPC frame format |
| [architecture/repository-map](architecture/repository-map.md) | Repository layout, cross-repository coupling, read-only references |
| [capabilities/facts](capabilities/facts.md) | Generated counts: plugins, kinds, operations, tests, smoke checks, catalogue size |
| [capabilities/matrix](capabilities/matrix.md) | Capability by capability: real I/O, simulated, or not wired |
| [capabilities/campaign](capabilities/campaign.md) | Campaign control plane: scope, approvals, configurable TTL, stop, ledger, surface report |
| [capabilities/network](capabilities/network.md) | Network capabilities: implementation, limits, failure semantics |
| [capabilities/offline-analysis](capabilities/offline-analysis.md) | Offline protocol plugins and analysis depth |
| [capabilities/security-model](capabilities/security-model.md) | Capability kernel, audit log, region gating, IPC security properties |
| [protocols/README](protocols/README.md) | How to add a protocol plugin, including fuzz and smoke requirements |
| [verification/README](verification/README.md) | How to run tests, fuzzing, smoke checks and catalogue validation |
| [product/dsl](product/dsl.md) | Script DSL reference: grammar, execution model, capability binding |
| [product/reproductions](product/reproductions.md) | Reproduction records, the `reproduce` runner, evidence and limits |
| [product/exploits](product/exploits.md) | Exploit records, effect execution, approval, evidence and limits |
| [product/firmware-triage](product/firmware-triage.md) | Firmware analysis: triage fields, Thumb disassembly, literal-pool xrefs |

## Scope

- These documents describe observable behaviour of the code in this repository.
- Numbers, limits and field names are taken from the source; when they change, the
  document changes in the same commit.
- Planning notes and internal design discussions are not part of this repository.

## Reading order

- New to the code: this page, then [architecture/overview](architecture/overview.md),
  then [capabilities/matrix](capabilities/matrix.md).
- Adding a protocol plugin: [architecture/contracts](architecture/contracts.md), then
  [protocols/README](protocols/README.md).
- Running the checks locally: [verification/README](verification/README.md).
