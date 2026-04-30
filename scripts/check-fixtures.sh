#!/usr/bin/env bash
# Fail the build if any fixture file under internal/daemon/testdata/
# contains a non-RFC-5737 IPv4 literal. Conservative: matches dotted-quad
# patterns and excludes 192.0.2.x / 198.51.100.x / 203.0.113.x.

set -euo pipefail

violations=0
while IFS= read -r path; do
    while IFS= read -r ip; do
        case "$ip" in
            192.0.2.*|198.51.100.*|203.0.113.*) ;;
            *)
                echo "$path: contains non-RFC-5737 IPv4 literal: $ip"
                violations=$((violations + 1))
                ;;
        esac
    done < <(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$path" || true)
done < <(find internal -path '*/testdata/*' -type f \( -name '*.H' -o -name '*.txt' -o -name '*.yaml' -o -name '*.yml' \))

if [ "$violations" -gt 0 ]; then
    echo "Found $violations non-RFC-5737 IPv4 literal(s) in fixtures."
    exit 1
fi
echo "Fixtures clean."
