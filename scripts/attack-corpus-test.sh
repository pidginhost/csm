#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

output="${CSM_ATTACK_CORPUS_REPORT_DIR:-$PWD/attack-corpus-results}"
mkdir -p "$output"
output=$(cd "$output" && pwd)
# Old local reports must never satisfy the current run after a missing test.
for report in realtime.json tier.json fullscan.json engines.txt tests.jsonl; do
    : > "$output/$report"
done

expected=$(go list -m -f '{{.Version}}' github.com/VirusTotal/yara-x/go)
actual=$(pkg-config --modversion yara_x_capi)
[ "v$actual" = "$expected" ] || { echo "YARA-X C library $actual differs from Go module $expected" >&2; exit 1; }
grep -Fq -- "--branch $expected" build/Dockerfile.builder || { echo "YARA-X builder pin differs" >&2; exit 1; }
{
    go version
    echo "YARA-X C library: $actual"
    go list -m github.com/VirusTotal/yara-x/go
    git rev-parse HEAD
} > "$output/engines.txt"

export CSM_ATTACK_CORPUS_REQUIRED=1
export CSM_ATTACK_CORPUS_REPORT_DIR="$output"
chmod -R go-w configs
CGO_LDFLAGS=$(pkg-config --libs --static yara_x_capi)
export CGO_LDFLAGS
start=$(date +%s)
go test -json -count=1 -timeout=30m -tags yara ./internal/attackcorpus ./internal/daemon ./internal/checks \
    -run '^TestAttackCorpus' | tee "$output/tests.jsonl"
echo "run time: $(($(date +%s) - start)) s" | tee -a "$output/engines.txt"
for path in realtime tier fullscan; do
    test -s "$output/$path.json"
done
