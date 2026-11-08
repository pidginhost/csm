#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

output="${CSM_ATTACK_CORPUS_REPORT_DIR:-$PWD/attack-corpus-results}"
# Reports name private samples, so only the owner may open them. The umask
# stays the default: the drivers must create files as the daemon does.
mkdir -p -m 700 "$output"
chmod 700 "$output"
output=$(cd "$output" && pwd)
# Old local reports must never satisfy the current run after a missing test.
for report in realtime.json tier.json fullscan.json engines.txt tests.jsonl; do
    : > "$output/$report"
    chmod 600 "$output/$report"
done

expected=$(go list -m -f '{{.Version}}' github.com/VirusTotal/yara-x/go)
actual=$(pkg-config --modversion yara_x_capi)
[ "v$actual" = "$expected" ] || { echo "YARA-X C library $actual differs from Go module $expected" >&2; exit 1; }
builder_version=$(awk '
    $1 == "RUN" && $2 == "git" && $3 == "clone" {
        for (i = 4; i < NF; i++)
            if ($i == "--branch") print $(i + 1)
    }
' build/Dockerfile.builder)
[ "$builder_version" = "$expected" ] || { echo "YARA-X builder pin differs" >&2; exit 1; }
{
    go version
    echo "YARA-X C library: $actual"
    go list -m github.com/VirusTotal/yara-x/go
    git rev-parse HEAD
} > "$output/engines.txt"

# CI must replay the private half at the reviewed pin. The empty helper drops
# any configured one, so no helper can store the job token, and the quoted
# helper reads the token from the environment, so it never enters an argv, a
# URL or the checkout's git config.
if [ -n "${CI:-}" ]; then
    : "${CSM_ATTACK_CORPUS_PROJECT:?CSM_ATTACK_CORPUS_PROJECT must name the private corpus project}"
    pin=$(cat internal/attackcorpus/private.commit)
    private=$(mktemp -d)
    git -c credential.helper= \
        -c 'credential.helper=!f() { test "$1" = get || exit 0; echo username=gitlab-ci-token; echo "password=${CI_JOB_TOKEN}"; }; f' \
        clone --quiet --no-checkout "${CI_SERVER_URL}/${CSM_ATTACK_CORPUS_PROJECT}.git" "$private"
    git -C "$private" checkout --quiet --detach "$pin"
    [ "$(git -C "$private" rev-parse HEAD)" = "$pin" ] || { echo "private corpus checkout is not at the pinned commit" >&2; exit 1; }
    go run ./scripts/fixturecheck -root "$private" -corpus -require-terms
    export CSM_ATTACK_CORPUS_PRIVATE="$private" CSM_ATTACK_CORPUS_PRIVATE_REQUIRED=1
    echo "private corpus: $pin" >> "$output/engines.txt"
elif [ -n "${CSM_ATTACK_CORPUS_PRIVATE:-}" ]; then
    echo "private corpus: local, unpinned" >> "$output/engines.txt"
else
    echo "private corpus: none" >> "$output/engines.txt"
fi

export CSM_ATTACK_CORPUS_REQUIRED=1
export CSM_ATTACK_CORPUS_REPORT_DIR="$output"
# An inherited local debugging option must not expose sample bytes in artifacts.
unset CSM_ATTACK_CORPUS_SHOW_ERRORS
chmod -R go-w configs
CGO_LDFLAGS=$(pkg-config --libs --static yara_x_capi)
export CGO_LDFLAGS
start=$(date +%s)
record_run_time() { echo "run time: $(($(date +%s) - start)) s" | tee -a "$output/engines.txt"; }
# A failing run records its run time too; the trap keeps the exit status.
trap record_run_time EXIT
go test -json -count=1 -timeout=30m -tags yara ./internal/attackcorpus ./internal/daemon ./internal/checks \
    -run '^TestAttackCorpus' | tee "$output/tests.jsonl"
for path in realtime tier fullscan; do
    test -s "$output/$path.json"
done
