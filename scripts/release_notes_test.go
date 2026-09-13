package scripts

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeChangelog stores body as a CHANGELOG.md inside a scratch directory and
// returns its path.
func writeChangelog(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write changelog: %v", err)
	}
	return path
}

// runReleaseNotes renders the release body for one version and reports the
// script's exit code. Stdout and stderr are returned separately so a failure
// message cannot be mistaken for release copy.
func runReleaseNotes(t *testing.T, changelog, version, tag string) (string, string, int) {
	t.Helper()

	cmd := exec.Command("./release-notes.sh", changelog, version, tag, "pidginhost/csm")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running release-notes script: %v (stderr %s)", err, stderr.String())
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

const changelogWithHighlights = `# Changelog

## [Unreleased]

## [3.32.0] - 2026-09-03

### Highlights

- Database-resident PHP backdoors are now found.
- PHP Shield reports cages that cannot reach the event socket.

### Security

- Store export no longer follows a symlink planted at the destination.

### Added

- Spam floods are detected by publishing rate.

### Fixed

#### Firewall

- A firewall apply aborts when the kernel table listing fails.
- The apply-confirmed rollback restores the firewall state file.

#### Web UI

- The findings CSV export neutralises spreadsheet formula triggers.

### Internal

- The systemd service unit is replaced atomically on install.

## [3.31.0] - 2026-09-01

### Fixed

- An older fix that belongs to the previous release.
`

func TestReleaseNotesLeadsWithHighlightsAndCollapsesTheLedger(t *testing.T) {
	path := writeChangelog(t, changelogWithHighlights)

	body, stderr, code := runReleaseNotes(t, path, "3.32.0", "v3.32.0")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}

	if !strings.HasPrefix(body, "### Highlights\n") {
		t.Fatalf("body must open with the highlights heading, got:\n%s", body)
	}

	summary, details, found := strings.Cut(body, "<details>")
	if !found {
		t.Fatalf("body must collapse the ledger behind <details>, got:\n%s", body)
	}

	// The summary a reader sees before expanding anything carries the
	// highlights and the security block, and nothing else.
	for _, want := range []string{
		"- Database-resident PHP backdoors are now found.",
		"### Security",
		"- Store export no longer follows a symlink planted at the destination.",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q, got:\n%s", want, summary)
		}
	}
	for _, unwanted := range []string{
		"#### Firewall",
		"- Spam floods are detected by publishing rate.",
		"### Internal",
	} {
		if strings.Contains(summary, unwanted) {
			t.Fatalf("summary must not carry the full ledger entry %q, got:\n%s", unwanted, summary)
		}
	}

	// Six recorded changes: every top-level entry of 3.32.0 except the
	// highlights, which restate changes rather than being changes, and none
	// from the release below it.
	if !strings.Contains(summary, "6 changes in this release.") {
		t.Fatalf("summary must count the release's entries, got:\n%s", summary)
	}
	if !strings.Contains(summary, "https://github.com/pidginhost/csm/blob/v3.32.0/CHANGELOG.md") {
		t.Fatalf("summary must link the changelog at the tag, got:\n%s", summary)
	}

	// The full ledger stays available, expanded on demand.
	for _, want := range []string{
		"#### Firewall",
		"- Spam floods are detected by publishing rate.",
		"### Internal",
		"</details>",
	} {
		if !strings.Contains(details, want) {
			t.Fatalf("details missing %q, got:\n%s", want, details)
		}
	}
	if strings.Contains(details, "An older fix that belongs to the previous release.") {
		t.Fatalf("details must stop at the next version heading, got:\n%s", details)
	}

	// GitHub only renders markdown inside <details> when a blank line
	// separates it from the tags.
	if !strings.Contains(body, "<summary>Full changelog</summary>\n\n") {
		t.Fatalf("details body needs a blank line after <summary>, got:\n%s", body)
	}
	if !strings.Contains(body, "\n\n</details>") {
		t.Fatalf("details body needs a blank line before </details>, got:\n%s", body)
	}
}

func TestReleaseNotesOmitsAnAbsentSecurityBlock(t *testing.T) {
	path := writeChangelog(t, `# Changelog

## [3.32.0] - 2026-09-03

### Highlights

- One thing worth noticing.

### Fixed

- A fix.
`)

	body, stderr, code := runReleaseNotes(t, path, "3.32.0", "v3.32.0")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if strings.Contains(body, "### Security") {
		t.Fatalf("body must not carry an empty security heading, got:\n%s", body)
	}
	if !strings.Contains(body, "1 change in this release.") {
		t.Fatalf("body must count every recorded change, got:\n%s", body)
	}
}

func TestReleaseNotesFallsBackToTheWholeSectionWithoutHighlights(t *testing.T) {
	path := writeChangelog(t, `# Changelog

## [3.31.0] - 2026-09-01

### Fixed

- A fix from a release cut before highlights existed.
`)

	body, stderr, code := runReleaseNotes(t, path, "3.31.0", "v3.31.0")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if strings.Contains(body, "<details>") {
		t.Fatalf("a section without highlights has nothing to collapse behind, got:\n%s", body)
	}
	for _, want := range []string{"### Fixed", "- A fix from a release cut before highlights existed."} {
		if !strings.Contains(body, want) {
			t.Fatalf("fallback body missing %q, got:\n%s", want, body)
		}
	}
}

func TestReleaseNotesReadsTheLastSectionInTheFile(t *testing.T) {
	path := writeChangelog(t, `# Changelog

## [3.32.0] - 2026-09-03

### Highlights

- The newest thing.

### Fixed

- The last line of the file, with no version heading below it.
`)

	body, stderr, code := runReleaseNotes(t, path, "3.32.0", "v3.32.0")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if !strings.Contains(body, "- The last line of the file, with no version heading below it.") {
		t.Fatalf("body must reach the end of the file, got:\n%s", body)
	}
}

func TestReleaseNotesCountsOnlyTopLevelEntries(t *testing.T) {
	path := writeChangelog(t, `# Changelog

## [3.32.0] - 2026-09-03

### Highlights

- One highlight.

### Fixed

- A fix whose entry wraps onto
  - an indented sub-point that is not its own change
- A second fix.
`)

	body, stderr, code := runReleaseNotes(t, path, "3.32.0", "v3.32.0")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	if !strings.Contains(body, "2 changes in this release.") {
		t.Fatalf("an indented sub-point is not a change, got:\n%s", body)
	}
}

func TestReleaseNotesFailsOnAMissingVersion(t *testing.T) {
	path := writeChangelog(t, `# Changelog

## [3.31.0] - 2026-09-01

### Fixed

- A fix.
`)

	body, stderr, code := runReleaseNotes(t, path, "3.32.0", "v3.32.0")
	if code == 0 {
		t.Fatalf("a missing version must not publish a release page, got:\n%s", body)
	}
	if body != "" {
		t.Fatalf("a failed extraction must emit no body, got:\n%s", body)
	}
	if !strings.Contains(stderr, "3.32.0") {
		t.Fatalf("the failure must name the version it looked for, got %q", stderr)
	}
}

// looseEntries reports list content following a blank line within a changelog
// list. A blank before an indented continuation also makes the list loose,
// wrapping every entry in its own paragraph on the release page.
func looseEntries(body string) []int {
	var loose []int
	prevEntry, blank := false, false
	for i, line := range strings.Split(body, "\n") {
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		switch {
		case strings.TrimSpace(line) == "":
			blank = true
			continue
		case strings.HasPrefix(line, "- ") || (prevEntry && indented):
			if prevEntry && blank {
				loose = append(loose, i+1)
			}
			prevEntry = true
		default:
			prevEntry = false
		}
		blank = false
	}
	return loose
}

func TestLooseEntriesFindsOnlyBlankSeparatedEntries(t *testing.T) {
	body := `# Changelog

## [3.38.0] - 2026-09-13

### Added

- A tight entry.
- Another tight entry.
  - an indented sub-point

- A loose entry.

### Fixed

- The first entry under a new heading.
`
	got := fmt.Sprint(looseEntries(body))
	if got != "[11]" {
		t.Fatalf("want only line 11 reported, got %s", got)
	}
}

func TestLooseEntriesWithContinuations(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"tight wrapped entry", "- First.\n  Continued.\n- Second.\n", "[]"},
		{"tight tab continuation", "- First.\n\tContinued.\n- Second.\n", "[]"},
		{"blank before wrapped text", "- First.\n\n  Continued.\n- Second.\n", "[3]"},
		{"blank before tab continuation", "- First.\n\n\tContinued.\n- Second.\n", "[3]"},
		{"blank after tab continuation", "- First.\n\tContinued.\n\n- Second.\n", "[4]"},
		{"loose final entry", "- First.\n- Second.\n\n  Continued.\n", "[4]"},
		{"blank before nested list", "- First.\n\n  - Nested.\n- Second.\n", "[3]"},
		{"whitespace separator", "- First.\n \t\r\n  Continued.\n- Second.\n", "[3]"},
		{"new subsection", "- First.\n  Continued.\n\n#### Next\n\n- Second.\n", "[]"},
		{"trailing blanks", "- First.\n  Continued.\n\n", "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fmt.Sprint(looseEntries(tc.body)); got != tc.want {
				t.Fatalf("loose lines = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestChangelogEntriesAreNotSeparatedByBlankLines(t *testing.T) {
	root := repoRoot(t)
	archives, err := filepath.Glob(filepath.Join(root, "docs", "changelog", "*.md"))
	if err != nil {
		t.Fatalf("glob changelog archives: %v", err)
	}
	for _, path := range append([]string{filepath.Join(root, "CHANGELOG.md")}, archives...) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if loose := looseEntries(string(body)); len(loose) > 0 {
			t.Errorf("%s: entries separated by a blank line at lines %v; keep a section's entries on consecutive lines", path, loose)
		}
	}
}
