package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// sensitiveDiffFixture writes a real file under a temp root and returns its
// path. The watchset evaluators read the file back, so the path has to exist.
// Names must be ones classifySensitive recognises, otherwise the evaluators
// bail out early and the test passes without exercising the diff.
func sensitiveDiffFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if classifySensitive(path) == "" {
		t.Fatalf("fixture %s is not a recognised sensitive path; the test would pass vacuously", path)
	}
	return path
}

// sensitiveCronFixture writes a cron drop-in under a directory classifySensitive
// recognises as cron, so glob-style watchset entries can be exercised.
func sensitiveCronFixture(t *testing.T, dir, name string) string {
	t.Helper()
	cronDir := filepath.Join(dir, "cron.d")
	if err := os.MkdirAll(cronDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cronDir, name)
	if err := os.WriteFile(path, []byte("* * * * * root /bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if classifySensitive(path) != "cron" {
		t.Fatalf("fixture %s did not classify as cron", path)
	}
	return path
}

func findingFor(t *testing.T, findings []alert.Finding, path string) alert.Finding {
	t.Helper()
	for _, f := range findings {
		if f.FilePath == path {
			return f
		}
	}
	t.Fatalf("no finding for %s in %+v", path, findings)
	return alert.Finding{}
}

// A path the previous refresh had never seen is genuinely new, so the
// watcher must still report it. Deleting the appearance branch would make
// this fail.
func TestDiffSensitiveWatchsetReportsGenuinelyNewPath(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "passwd", "root:x:0:0::/root:/bin/bash\n")

	got := DiffSensitiveWatchset(map[string]string{}, map[string]string{path: "hash-a"}, nil)

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "New sensitive system file appeared") {
		t.Errorf("new path should report an appearance, got %q", got[0].Message)
	}
}

// The production bug: cPanel rewrites /etc/passwd by writing a temp file and
// renaming it over the target, which changes the inode. The watcher keyed its
// known-set on dev+inode, so every rewrite looked like a brand-new file and
// /etc/passwd was reported as having "appeared" 16 times in 30 days.
func TestDiffSensitiveWatchsetDoesNotReportRewriteAsNewFile(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "passwd", "root:x:0:0::/root:/bin/bash\nnew:x:1:1::/home/new:/bin/bash\n")

	got := DiffSensitiveWatchset(
		map[string]string{path: "hash-before"},
		map[string]string{path: "hash-after"},
		nil,
	)

	for _, f := range got {
		if strings.Contains(f.Message, "appeared") {
			t.Errorf("a path known to the previous refresh must not be reported as new, got %q", f.Message)
		}
	}
}

// A rewrite that changes content is a modification of a watched file. The BPF
// write hook cannot see it (the write landed on the temp inode), so the
// refresh diff is the only detector that can report it.
func TestDiffSensitiveWatchsetReportsContentChange(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "shadow", "root:!!:20000:0:99999:7:::\n")

	got := DiffSensitiveWatchset(
		map[string]string{path: "hash-before"},
		map[string]string{path: "hash-after"},
		nil,
	)

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := findingFor(t, got, path)
	if !strings.Contains(f.Message, "Content changed on sensitive system file") {
		t.Errorf("changed content should report a content change, got %q", f.Message)
	}
	if f.Check != "sensitive_file_modified" {
		t.Errorf("check = %q, want sensitive_file_modified", f.Check)
	}
	if f.Severity != alert.High {
		t.Errorf("severity = %v, want HIGH", f.Severity)
	}
}

// An atomic rewrite that leaves content byte-identical is a no-op. Reporting
// it would reintroduce the noise this fix removes.
func TestDiffSensitiveWatchsetIgnoresRewriteWithIdenticalContent(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "group", "root:x:0:\n")

	got := DiffSensitiveWatchset(
		map[string]string{path: "same-hash"},
		map[string]string{path: "same-hash"},
		nil,
	)

	if len(got) != 0 {
		t.Errorf("identical content must not produce a finding, got %+v", got)
	}
}

// A path that disappears is handled by unwatching its inode, not by an alert;
// the diff must not invent a finding for it.
func TestDiffSensitiveWatchsetIgnoresRemovedPath(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveCronFixture(t, t.TempDir(), "dropin")

	got := DiffSensitiveWatchset(map[string]string{path: "hash-a"}, map[string]string{}, nil)

	if len(got) != 0 {
		t.Errorf("removed path must not produce a finding, got %+v", got)
	}
}

// A path whose hash could not be computed this cycle carries no evidence of
// change. Treating the empty digest as a real value would emit a finding on
// every transient read error.
func TestDiffSensitiveWatchsetIgnoresUnknownDigest(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "sudoers", "root ALL=(ALL) ALL\n")

	got := DiffSensitiveWatchset(map[string]string{path: "hash-a"}, map[string]string{path: ""}, nil)

	if len(got) != 0 {
		t.Errorf("unknown digest must not produce a finding, got %+v", got)
	}
}

// The live write hook already reported this path with process attribution, so
// the refresh must absorb the new digest silently instead of describing the
// same write a second time with less detail.
func TestDiffSensitiveWatchsetSkipsPathsTheWriteHookAlreadyReported(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "sudoers", "root ALL=(ALL) ALL\n")

	got := DiffSensitiveWatchset(
		map[string]string{path: "hash-before"},
		map[string]string{path: "hash-after"},
		map[string]bool{path: true},
	)

	if len(got) != 0 {
		t.Errorf("write already reported live; refresh must stay quiet, got %+v", got)
	}
}

// Suppression is scoped to the written path: an unrelated file changing in the
// same cycle must still be reported.
func TestDiffSensitiveWatchsetStillReportsOtherPathsWhenOneWasReported(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	reported := sensitiveDiffFixture(t, "sudoers", "root ALL=(ALL) ALL\n")
	other := sensitiveDiffFixture(t, "shadow", "root:!!:20000:0:99999:7:::\n")

	got := DiffSensitiveWatchset(
		map[string]string{reported: "a", other: "a"},
		map[string]string{reported: "b", other: "b"},
		map[string]bool{reported: true},
	)

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].FilePath != other {
		t.Errorf("finding path = %q, want %q", got[0].FilePath, other)
	}
}

// A genuinely new path is reported even if the write hook fired for it: the
// hook reports the write, the diff reports that the path did not exist before.
func TestDiffSensitiveWatchsetStillReportsNewPathWhenWriteHookFired(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveCronFixture(t, t.TempDir(), "newjob")

	got := DiffSensitiveWatchset(
		map[string]string{},
		map[string]string{path: "hash"},
		map[string]bool{path: true},
	)

	if len(got) != 1 {
		t.Fatalf("want 1 appearance finding, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "New sensitive system file appeared") {
		t.Errorf("got %q, want an appearance finding", got[0].Message)
	}
}

func TestNextSensitiveDigestsDistinguishesContent(t *testing.T) {
	old := osFS
	osFS = &mockOS{readFile: func(name string) ([]byte, error) {
		return []byte("content-of-" + name), nil
	}}
	t.Cleanup(func() { osFS = old })

	got := NextSensitiveDigests(nil, []string{"/etc/passwd", "/etc/group"})

	if got["/etc/passwd"] == "" || got["/etc/group"] == "" {
		t.Fatalf("readable paths must get a digest, got %+v", got)
	}
	if got["/etc/passwd"] == got["/etc/group"] {
		t.Errorf("different content must hash differently, both = %q", got["/etc/passwd"])
	}
}

// A file that exists but cannot be read this cycle carries no evidence. Storing
// an empty digest would make the next successful read look like a change.
func TestNextSensitiveDigestsCarriesForwardWhenReadFails(t *testing.T) {
	old := osFS
	osFS = &mockOS{readFile: func(string) ([]byte, error) { return nil, os.ErrPermission }}
	t.Cleanup(func() { osFS = old })

	got := NextSensitiveDigests(map[string]string{"/etc/shadow": "known-digest"}, []string{"/etc/shadow"})

	if got["/etc/shadow"] != "known-digest" {
		t.Errorf("digest = %q, want the previous digest carried forward", got["/etc/shadow"])
	}
}

func TestNextSensitiveDigestsLeavesDigestUnknownWithoutPrior(t *testing.T) {
	old := osFS
	osFS = &mockOS{readFile: func(string) ([]byte, error) { return nil, os.ErrPermission }}
	t.Cleanup(func() { osFS = old })

	got := NextSensitiveDigests(nil, []string{"/etc/shadow"})

	if _, ok := got["/etc/shadow"]; !ok {
		t.Fatal("path must stay in the snapshot so it is not re-reported as new")
	}
	if got["/etc/shadow"] != "" {
		t.Errorf("digest = %q, want empty so the diff treats it as unknown", got["/etc/shadow"])
	}
}

// A path that no longer exists is not passed in, so it must drop out of the
// snapshot rather than linger from the previous cycle.
func TestNextSensitiveDigestsDropsPathsNotSupplied(t *testing.T) {
	old := osFS
	osFS = &mockOS{readFile: func(string) ([]byte, error) { return []byte("x"), nil }}
	t.Cleanup(func() { osFS = old })

	got := NextSensitiveDigests(map[string]string{"/etc/cron.d/gone": "d"}, []string{"/etc/passwd"})

	if _, ok := got["/etc/cron.d/gone"]; ok {
		t.Error("a path absent from this refresh must not survive in the snapshot")
	}
}

// Findings drive an alert stream operators read top-to-bottom; map iteration
// order would otherwise shuffle them between refreshes.
func TestDiffSensitiveWatchsetReturnsPathOrderedFindings(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"c-dropin", "a-dropin", "b-dropin"} {
		paths = append(paths, sensitiveCronFixture(t, dir, name))
	}
	cur := map[string]string{}
	for _, p := range paths {
		cur[p] = "hash"
	}

	got := DiffSensitiveWatchset(map[string]string{}, cur, nil)

	if len(got) != 3 {
		t.Fatalf("want 3 findings, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].FilePath > got[i].FilePath {
			t.Errorf("findings not ordered by path: %q before %q", got[i-1].FilePath, got[i].FilePath)
		}
	}
}
