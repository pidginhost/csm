#!/usr/bin/env bash
# Scan tracked and unignored fixture files, including extensionless records.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec go run ./scripts/fixturecheck "$@"
