# Fixture sanitisation rules

Every `.H` and `.txt` file in this directory is derived from a real
production capture with the substitutions below applied. Anything that
might leak customer data MUST be replaced before checking in.

## Substitutions (mandatory)

| Real datum                       | Replacement                          |
|----------------------------------|--------------------------------------|
| Customer email addresses         | `user@example.com`, `info@example.com`, etc. |
| External recipient addresses     | `recipient@example.org`              |
| IPv4 addresses (any non-RFC-5737)| `192.0.2.x` (RFC 5737 documentation) |
| Internal hostnames               | `cpanel.example.test`                |
| Customer domain names            | `example.com`, `attacker.example.com`|
| Exim message-IDs                 | Anonymised but format-valid (16-23 chars, [A-Za-z0-9-]) |

## CI enforcement

`make check-fixtures` runs `scripts/check-fixtures.sh`. The blocking GitLab
`check-fixtures` job runs the same scanner. It checks every tracked or unignored
file below a `testdata` or `fixtures` directory anywhere in the repository,
including JSON, cron records, and extensionless Exim records. IPv4 literals must
use 192.0.2.0/24, 198.51.100.0/24, or 203.0.113.0/24.

A violation reports its file and line without copying the address into CI logs.
Repository listing errors, unreadable or missing tracked files, symlinks, and
lines exceeding the scanner's one MiB limit fail the check. A scan that finds no
fixture files also fails. There are no per-file exemptions or skip switches.
Any future policy exception must be an explicit, reviewed source change.

This automated check covers literal IPv4 addresses. It does not certify that
email addresses, domains, message IDs, encoded content, or other customer data
have been anonymised. Review all substitutions above before adding fixtures.
