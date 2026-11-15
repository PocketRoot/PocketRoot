# Software inventory matching

Port scans only see products that answer on the wire. Libraries such as Log4j never do,
so the engine also accepts a software inventory and matches it against the catalogue.

## Supported input

| Format | Protocol id | Notes |
|---|---|---|
| CycloneDX 1.x JSON | `cyclonedx` | `bomFormat`, `specVersion`, `components[].{group,name,version,purl}` |

```powershell
zig-out/bin/PocketRoot vulns ../PocketRootVulnerabilityDb/vulndb/catalog-v2.jsonl \
    --protocol cyclonedx samples/sbom/log4j-2.14.1.cdx.json
```

## What is read

Each component that carries both a name and a version becomes one package observation:

- `hostname` is the component's purl, or `pkg:generic/<name>@<version>` when the purl is
  missing. It identifies the component inside the asset graph.
- `product` is the component name exactly as the bill of materials spells it.
- `version` is the declared version.

Components without a version are counted but not matched: the catalogue reasons about
versions, so an unversioned package cannot be attributed.

## Matching rules

A package name is matched to a catalogue product in two steps:

1. the full name is looked up against every product name and alias, case-insensitively;
2. if that finds nothing, the leading token before the first `-`, `_` or `.` is looked up
   as well.

The second step exists because package managers suffix artefacts: `log4j-core` belongs to
the product `log4j`. It does not overreach — `log4js` has no separator, so its root token
is the full name and it stays a different product.

Version rules then apply exactly as for network endpoints: `exact` or `dotted_range` with
`introduced`, `fixed` and `last_affected`.

## Limits

- The inventory is taken at face value: no dependency resolution, no transitive closure and
  no build tool is invoked.
- Only the declared version is used; a lock file that pins a different version must be
  converted to CycloneDX first.
- No purl-to-CPE mapping is performed beyond the token rule. A component named
  `apache-commons-text` matches the product `apache`-prefixed names only if the catalogue
  lists that token, which it usually does not; those components are reported as unmatched
  rather than guessed.
- Package observations carry no address or port, so a report shows the purl where a scan
  would show an endpoint.
