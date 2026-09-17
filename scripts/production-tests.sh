#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-portable}
artifacts="$PWD/production-results/$mode"
mkdir -p "$artifacts"
: > "$artifacts/tests.jsonl"
tags=yara,journal,bpf
pattern=.
packages=(./...)
required=scripts/production-required.json
case "$mode" in
  portable) ;;
  kernel)
    tags+=,nftkernel,kernelintegration
    required=scripts/kernel-required.json
    ;;
  *) echo "Unknown test mode: $mode" >&2; exit 1 ;;
esac
version=$(go list -m -f '{{.Version}}' github.com/VirusTotal/yara-x/go)
actual=$(pkg-config --modversion yara_x_capi)
[[ "$actual" == "${version#v}" ]]
grep -q -- "--branch $version " build/Dockerfile.builder
cpus=$(nproc 2>/dev/null || echo 2)
# -p bounds how many package binaries run at once. It was pinned at 2, which
# left the suite at about 1.5x parallelism: the package times sum to roughly
# 20 minutes against a 13 minute wall. Scale with the runner instead, capped
# so the deadline-sensitive tests (20ms alert batches, a 100ms /proc budget)
# keep CPU headroom rather than competing for it. Override to pin a value.
parallel=${CSM_TEST_PARALLEL_PACKAGES:-$(( cpus < 4 ? cpus : 4 ))}
{
  go version
  printf 'YARA-X C API %s\nTags %s\n' "$actual" "$tags"
  printf 'CPUs %s\nParallel packages %s\n' "$cpus" "$parallel"
  grep -m1 MemTotal /proc/meminfo 2>/dev/null || true
  uname -a
  git rev-parse HEAD
} > "$artifacts/engines.txt"
export CGO_ENABLED=1
export CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)"
go run ./scripts/queuegate -manifest scripts/queue-inventory.json -mode "$mode" -base-required "$required" -required-out "$artifacts/queue-required.json"
required="$artifacts/queue-required.json"
chmod -R go-w configs
if [[ "$mode" == kernel ]]; then
  go run ./scripts/testgate -tags "$tags" -base-tags yara,journal,bpf -required "$required" -pattern-file "$artifacts/pattern.txt" -inventory "$artifacts/inventory.json" "${packages[@]}"
  pattern=$(cat "$artifacts/pattern.txt")
else
  go run ./scripts/testgate -tags "$tags" -run "$pattern" -inventory "$artifacts/inventory.json" "${packages[@]}"
fi
# Stream the machine-readable log to the artifact, not to the job log: the
# full -json transcript exceeds GitLab's 4 MB capture limit, which truncated
# the output exactly where a failure would be reported. Print the failures.
status=0
go test -json -race -count=1 -p="$parallel" -timeout=30m -tags "$tags" -run "$pattern" "${packages[@]}" > "$artifacts/tests.jsonl" || status=$?
python3 - "$artifacts/tests.jsonl" <<'SUMMARY'
import json, sys
failed, output = [], {}
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("Action") == "fail":
        failed.append((event.get("Package", "?"), event.get("Test", "")))
    if event.get("Action") == "output" and event.get("Test"):
        key = (event.get("Package", "?"), event.get("Test"))
        output.setdefault(key, []).append(event.get("Output", ""))
for package, test in failed:
    for line in output.get((package, test), [])[-40:]:
        print(f"{package}: {line.rstrip()}")
for package, test in failed:
    print(f'FAILED {package} {test}'.rstrip())
SUMMARY
# Match the checkout's ownership before any early exit, so a root container run
# never leaves results the CI runner cannot collect or clean up on its next job.
chown -R --reference="$PWD" "$PWD/production-results" 2>/dev/null || true
[[ "$status" == 0 ]] || exit "$status"
go run ./scripts/testgate -inventory "$artifacts/inventory.json" -required "$required" -events "$artifacts/tests.jsonl"
