#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

output="${CSM_CORPUS_REPORT_DIR:-$PWD/corpus-results}"
mkdir -p "$output" .cache
output=$(cd "$output" && pwd)
# Old local reports must never satisfy the current run after a missing test.
for report in yara.json yaml.json phptaint.json jstaint.json manifest.json inventory.json engines.txt tests.jsonl; do
    : > "$output/$report"
done
stage=$(mktemp -d "$PWD/.cache/clean-corpus.XXXXXX")
trap 'rm -rf "$stage"' EXIT

expected=$(go list -m -f '{{.Version}}' github.com/VirusTotal/yara-x/go)
actual=$(pkg-config --modversion yara_x_capi)
[ "v$actual" = "$expected" ] || { echo "YARA-X C library $actual differs from Go module $expected" >&2; exit 1; }
grep -Fq -- "--branch $expected" build/Dockerfile.builder || { echo "YARA-X builder pin differs" >&2; exit 1; }
{
    go version
    echo "YARA-X C library: $actual"
    go list -m github.com/VirusTotal/yara-x/go github.com/VKCOM/php-parser github.com/tdewolff/parse/v2
    git rev-parse HEAD
} > "$output/engines.txt"

go run ./scripts/clean-corpus \
    --cache "${CSM_CORPUS_ARCHIVE_CACHE:-.cache/clean-corpus-archives}" \
    --destination "$stage/corpus" --output "$output"
export CSM_CORPUS_REQUIRED=1 CSM_CORPUS_REPORT_DIR="$output"
export YARA_FP_CORPUS="$stage/corpus" PHPTAINT_CORPUS="$stage/corpus" CSM_JSTAINT_CORPUS="$stage/corpus"
chmod -R go-w configs
export CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)"
go test -json -count=1 -timeout=30m -tags yara \
    ./internal/corpusgate ./internal/yara ./internal/signatures ./internal/phptaint ./internal/jstaint \
    -run '^(TestRepositoryRulesAgainstCleanCorpus|TestRepositoryYAMLRulesAgainstCleanCorpus|TestYAMLGatesSoundOnCleanCorpus|TestCorpusGate|TestPreparePinnedCorpus|TestReportRejectsBadDetectorAndMissingInput|TestCleanCorpusGateRejectsAlwaysMatchingRule)$' \
    | tee "$output/tests.jsonl"
for engine in yara yaml phptaint jstaint; do
    test -s "$output/$engine.json"
done
