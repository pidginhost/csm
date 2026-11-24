# Supply-chain Advisory Database

CSM's supply-chain check (`supply_chain_vuln`) parses customer dependency lockfiles, `composer.lock` and `package-lock.json`. It matches the resolved versions against a local advisory database.

The scanner ships in the binary; the advisory data does not. With no advisory file present the check is a silent no-op. You supply the file and keep it current.

This mirrors the YARA-forge mirror posture (see ROADMAP item 1): CSM carries the matching machinery, and an operator or a sync job delivers the data out of band. Shipping a stale CVE snapshot inside the binary would give false confidence and rot between releases.

## Location

```
<state_path>/advisories/supply-chain.json
```

`state_path` is the daemon's configured state directory. CSM reads the file on each scan, so updating it requires no daemon restart and no recompile.

## Populating it

Generate the file from a public feed and write it to the path above on a schedule. Two common sources:

- OSV (`https://osv.dev`) covers the npm/Packagist ecosystems. Export the relevant ecosystem ranges into the subset format described in [Format](#format).
- WPScan / wpvulndb style feeds cover WordPress plugin advisories. This is a future ecosystem; the current lockfile scanner does not parse it.

A signed mirror job analogous to the YARA-forge mirror is the intended long-term delivery mechanism. Until then an operator cron that fetches and transforms a feed is sufficient.

## Format

The file is OSV-subset JSON:

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

CSM flags a dependency version when it falls inside any range: `version >= introduced AND (fixed == "" OR version < fixed)`. `introduced: "0"` means "from the first release".

Version comparison is numeric per dotted segment. A leading `v` and any pre-release/build suffix (`-rc1`, `+build`) are ignored.

`ecosystem` takes one of two values:

| `ecosystem` | Package name |
|-------------|--------------|
| `composer` | Packagist `vendor/name`. |
| `npm` | Package name as it appears under `node_modules/`. |

`severity` sets the severity of the finding:

| `severity` | Finding |
|------------|---------|
| `critical` | Critical |
| `high` | High |
| Anything else (`medium`/`low`/empty) | Warning |

## Scope (current)

- Parsed: `composer.lock`, `package-lock.json` (npm lockfile v1, v2, v3).
- Not yet parsed: `requirements.txt` / `Pipfile.lock` (Python), `Gemfile.lock` (Ruby), WordPress plugin manifests. These are follow-on ecosystems for the same matcher.
