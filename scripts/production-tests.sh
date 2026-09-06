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
{
  go version
  printf 'YARA-X C API %s\nTags %s\n' "$actual" "$tags"
  uname -a
  git rev-parse HEAD
} > "$artifacts/engines.txt"
export CGO_ENABLED=1
export CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)"
chmod -R go-w configs
if [[ "$mode" == kernel ]]; then
  go run ./scripts/testgate -tags "$tags" -base-tags yara,journal,bpf -required "$required" -pattern-file "$artifacts/pattern.txt" -inventory "$artifacts/inventory.json" "${packages[@]}"
  pattern=$(cat "$artifacts/pattern.txt")
else
  go run ./scripts/testgate -tags "$tags" -run "$pattern" -inventory "$artifacts/inventory.json" "${packages[@]}"
fi
go test -json -race -count=1 -p=2 -timeout=30m -tags "$tags" -run "$pattern" "${packages[@]}" | tee "$artifacts/tests.jsonl"
# Match the checkout's ownership so a root container run does not leave results
# the CI runner cannot collect or clean up on its next job.
chown -R --reference="$PWD" "$PWD/production-results" 2>/dev/null || true
go run ./scripts/testgate -inventory "$artifacts/inventory.json" -required "$required" -events "$artifacts/tests.jsonl"
