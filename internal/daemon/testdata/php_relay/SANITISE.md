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

`make check-fixtures` runs `scripts/check-fixtures.sh` which greps the
testdata directory for IPv4 addresses outside the documentation range
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). The build fails on any
match so unsanitised fixtures cannot land.
