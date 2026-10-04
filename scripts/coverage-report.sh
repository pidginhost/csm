#!/usr/bin/env bash
# Render a coverage profile against the sources it was produced from.
#
# usage: coverage-report.sh <profile> <tag> <outdir>
#
# The published profile belongs to a release tag, while the docs workflow runs
# on a later main commit. go tool cover reads every source file the profile
# names, so a file deleted or moved after the release breaks the report when it
# is rendered against main. Check the tag out in a temporary worktree of the
# current repository and render from there. Writes <outdir>/coverage.html and
# <outdir>/coverage-func.txt (the per-function summary, ending with the total).
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: coverage-report.sh <profile> <tag> <outdir>" >&2
	exit 2
fi

profile=$(realpath "$1")
tag=$2
outdir=$(realpath "$3")

if ! git rev-parse --verify --quiet "refs/tags/${tag}^{commit}" >/dev/null; then
	echo "coverage-report.sh: tag ${tag} is not available locally" >&2
	exit 1
fi

src=$(mktemp -d)
cleanup() {
	git worktree remove --force "$src" >/dev/null 2>&1 || true
	rm -rf "$src"
}
trap cleanup EXIT

git worktree add --quiet --detach "$src" "refs/tags/${tag}"
(
	cd "$src"
	go tool cover -html="$profile" -o "$outdir/coverage.html"
	go tool cover -func="$profile" >"$outdir/coverage-func.txt"
)
