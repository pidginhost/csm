# Supply-chain Advisory Database

CSM's supply-chain check (`supply_chain_vuln`) parses customer
dependency lockfiles -- `composer.lock` and `package-lock.json` -- and
matches the resolved versions against a local advisory database. The
scanner ships in the binary; the advisory data does not. With no
advisory file present the check is a silent no-op.

This mirrors the YARA-forge mirror posture (see ROADMAP item 1): CSM
carries the matching machinery, and the data is delivered out of band by
an operator or a sync job. Shipping a stale CVE snapshot inside the
binary would give false confidence and rot between releases.

## Location

```
<state_path>/advisories/supply-chain.json
```

`state_path` is the daemon's configured state directory. The file is
read on each scan; updating it requires no daemon restart and no
recompile.

## Format

OSV-subset JSON. A dependency version is flagged when it falls inside
any range: `version >= introduced AND (fixed == "" OR version < fixed)`.
`introduced: "0"` means "from the first release".

```json
{
  "advisories": [
    {
      "ecosystem": "npm",
      "package": "lodash",
      "ranges": [{ "introduced": "0", "fixed": "4.17.21" }],
      "id": "CVE-2021-23337",
      "severity": "high",
      "summary": "Command injection via template."
    },
    {
      "ecosystem": "composer",
      "package": "vendor/package",
      "ranges": [{ "introduced": "2.0.0", "fixed": "2.4.1" }],
      "id": "CVE-2024-xxxxx",
      "severity": "critical",
      "summary": "..."
    }
  ]
}
```

- `ecosystem`: `composer` (Packagist `vendor/name`) or `npm` (package
  name as it appears under `node_modules/`).
- `severity`: `critical` -> Critical finding, `high` -> High, anything
  else (`medium`/`low`/empty) -> Warning.
- Version comparison is numeric per dotted segment; a leading `v` and
  any pre-release/build suffix (`-rc1`, `+build`) are ignored.

## Populating it

Generate the file from a public feed and write it to the path above on a
schedule. Two common sources:

- **OSV** (`https://osv.dev`) for the npm/Packagist ecosystems. Export
  the relevant ecosystem ranges into the subset format above.
- **WPScan / wpvulndb** style feeds for WordPress plugin advisories
  (future ecosystem; not parsed by the current lockfile scanner).

A signed mirror job analogous to the YARA-forge mirror is the intended
long-term delivery mechanism; until then an operator cron that fetches
and transforms a feed is sufficient.

## Scope (current)

- Parsed: `composer.lock`, `package-lock.json` (npm lockfile v1, v2, v3).
- Not yet parsed: `requirements.txt` / `Pipfile.lock` (Python),
  `Gemfile.lock` (Ruby), WordPress plugin manifests. These are follow-on
  ecosystems for the same matcher.
