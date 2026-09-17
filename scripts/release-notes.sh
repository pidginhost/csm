#!/bin/sh
#
# Render the GitHub release body for one version of CHANGELOG.md.
#
#   release-notes.sh <changelog> <version> <tag> [repo-slug]
#
# The changelog is a per-change ledger: a busy cycle leaves well over a
# hundred entries under one version, and pasting that whole section onto the
# release page buries the handful of things an operator has to read before
# upgrading. So the body leads with the Highlights and Security blocks and
# collapses the ledger behind a <details> element, with a link to the full
# file at the tag.
#
# A version section written before Highlights existed has nothing to lead
# with, so it is emitted whole, exactly as the release page used to carry it.
#
# POSIX sh and awk only: this runs on the alpine image in release:github,
# where busybox provides both and GNU extensions (head -n -1) do not exist.

set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
	echo "usage: release-notes.sh <changelog> <version> <tag> [repo-slug]" >&2
	exit 2
fi

CHANGELOG="$1"
VERSION="$2"
TAG="$3"
SLUG="${4:-pidginhost/csm}"

if [ ! -f "$CHANGELOG" ]; then
	echo "release-notes: changelog not found: $CHANGELOG" >&2
	exit 1
fi

# Drop blank lines from both ends of a block, keeping the ones inside it.
trim_blank_edges() {
	awk '
		NF == 0 { if (started) pending++; next }
		{
			while (pending-- > 0) print ""
			pending = 0
			started = 1
			print
		}
	'
}

# Everything below "## [<version>]" and above the next version heading. The
# closing bracket makes the prefix match exact, so 3.2.0 cannot pick up the
# section for 3.2.01.
section() {
	awk -v heading="## [$VERSION]" '
		index($0, heading) == 1 { inside = 1; next }
		inside && index($0, "## [") == 1 { exit }
		inside { print }
	' "$CHANGELOG" | trim_blank_edges
}

# One "### <name>" block of the version section, heading included.
block() {
	printf '%s\n' "$SECTION" | awk -v heading="### $1" '
		index($0, heading) == 1 { inside = 1; print; next }
		inside && index($0, "### ") == 1 { exit }
		inside { print }
	' | trim_blank_edges
}

# Top-level entries only, and never the highlights: a wrapped or indented
# sub-point belongs to the entry above it, and a highlight restates a change
# recorded further down rather than being one.
count_entries() {
	printf '%s\n' "$SECTION" | awk '
		index($0, "### Highlights") == 1 { skipping = 1; next }
		skipping && index($0, "### ") == 1 { skipping = 0 }
		skipping { next }
		/^- / { n++ }
		END { print n + 0 }
	'
}

# "1 change", "2 changes".
changes_phrase() {
	n="$(count_entries)"
	if [ "$n" = "1" ]; then
		printf '1 change'
	else
		printf '%s changes' "$n"
	fi
}

SECTION="$(section)"
if [ -z "$SECTION" ]; then
	echo "release-notes: no section for version $VERSION in $CHANGELOG" >&2
	exit 1
fi

HIGHLIGHTS="$(block Highlights)"
if [ -z "$HIGHLIGHTS" ]; then
	printf '%s\n' "$SECTION"
	exit 0
fi

printf '%s\n' "$HIGHLIGHTS"

SECURITY="$(block Security)"
if [ -n "$SECURITY" ]; then
	printf '\n%s\n' "$SECURITY"
fi

printf '\n%s in this release. Full detail: [CHANGELOG.md](https://github.com/%s/blob/%s/CHANGELOG.md)\n' \
	"$(changes_phrase)" "$SLUG" "$TAG"

printf '\n<details>\n<summary>Full changelog</summary>\n\n%s\n\n</details>\n' "$SECTION"
