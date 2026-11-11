package checks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
)

func useRemovedFilesClock(t *testing.T, now *time.Time) {
	t.Helper()
	prev := removedFilesNow
	removedFilesNow = func() time.Time { return *now }
	t.Cleanup(func() { removedFilesNow = prev })
}

func seedRemovedFileTarget(t *testing.T, content string) (string, os.FileInfo) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "index.php")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	return path, info
}

// A file CSM quarantined is remembered by the digest of what left the path,
// so the same bytes coming back can be recognised.
func TestQuarantineRemembersRemovedContent(t *testing.T) {
	withActionSink(t)
	const content = "<?php eval($_POST[0]);"
	path, info := seedRemovedFileTarget(t, content)
	want := actionlog.Stat(path)

	qPath := filepath.Join(t.TempDir(), "q", "index.php")
	if err := quarantineTarget(path, qPath, info, quarantineMetadata(path, info, "webshell_realtime")); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	got, ok := RemovedFileAt(path)
	if !ok {
		t.Fatal("quarantined file was not remembered")
	}
	if got.SHA256 != want.Digest || got.SHA256 == "" || got.Size != int64(len(content)) || got.Action != "quarantine" {
		t.Fatalf("removed = %+v, want digest %q size %d action quarantine", got, want.Digest, len(content))
	}
}

func TestFailedQuarantineIsNotRemembered(t *testing.T) {
	withActionSink(t)
	path, info := seedRemovedFileTarget(t, "<?php eval($_POST[0]);")

	orig := quarantineTargetFn
	t.Cleanup(func() { quarantineTargetFn = orig })
	quarantineTargetFn = func(string, string, os.FileInfo, []byte) error {
		return errors.New("read-only file system")
	}

	qPath := filepath.Join(t.TempDir(), "q", "index.php")
	if err := quarantineTarget(path, qPath, info, quarantineMetadata(path, info, "webshell")); err == nil {
		t.Fatal("quarantine reported success while the move failed")
	}
	if got, ok := RemovedFileAt(path); ok {
		t.Fatalf("a file still in place was remembered as removed: %+v", got)
	}
}

// Audit hashing is bounded, but a successful quarantine must rearm alerts
// even when the retained file is too large to have an audit digest.
func TestQuarantineRemembersUnhashedRemovedFile(t *testing.T) {
	withActionSink(t)
	path := filepath.Join(t.TempDir(), "large.php")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	const size = 65 << 20
	if truncateErr := f.Truncate(size); truncateErr != nil {
		t.Fatal(truncateErr)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, seq := RemovedFilesSince(0)
	qPath := filepath.Join(t.TempDir(), "large.php")
	if err := quarantineTarget(path, qPath, info, quarantineMetadata(path, info, "webshell")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("source was not removed: %v", err)
	}
	if retained := actionlog.Stat(qPath); !retained.Exists || retained.Size != size || retained.Digest != "" {
		t.Fatalf("expected an unhashed retained file: %+v", retained)
	}
	got, ok := RemovedFileAt(path)
	if !ok || got.SHA256 != "" || got.Size != size || got.Action != "quarantine" {
		t.Fatalf("successful unhashed quarantine not remembered: %+v, ok=%t", got, ok)
	}
	newer, next := RemovedFilesSince(seq)
	if len(newer) != 1 || newer[0].Path != path || next != got.Seq {
		t.Fatalf("removals = %+v, sequence = %d; want the unhashed file", newer, next)
	}
}

func TestQuarantineDoesNotRememberDirectoryOrSpool(t *testing.T) {
	withActionSink(t)
	for _, directory := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "entry")
		if directory {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("mail body"), 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		meta := quarantineMetadata(path, info, "test")
		if !directory {
			meta.SpoolDir = filepath.Dir(path)
		}
		qPath := filepath.Join(t.TempDir(), "entry")
		if err := quarantineTarget(path, qPath, info, meta); err != nil {
			t.Fatal(err)
		}
		if got, ok := RemovedFileAt(path); ok {
			t.Fatalf("directory=%t: unexpected removal entry: %+v", directory, got)
		}
	}
}

// A clean replaces the file in place. What it took away is the original
// content, which is what a restore loop writes back.
func TestCleanRemembersOriginalContent(t *testing.T) {
	withActionSink(t)
	restoreQuarantineDir(t)
	const infected = "<?php\n\x00\x0b@include(base64_decode(\"ZXZpbA==\"));\necho 'ok';\n"
	path, _ := seedRemovedFileTarget(t, infected)
	want := actionlog.Stat(path)

	if result := CleanInfectedFile(path); !result.Cleaned {
		t.Fatalf("clean did not run: %+v", result)
	}

	got, ok := RemovedFileAt(path)
	if !ok {
		t.Fatal("cleaned file was not remembered")
	}
	if got.SHA256 != want.Digest || got.Size != int64(len(infected)) || got.Action != "clean" {
		t.Fatalf("removed = %+v, want original digest %q size %d action clean", got, want.Digest, len(infected))
	}
}

func TestRefusedCleanIsNotRemembered(t *testing.T) {
	withActionSink(t)
	restoreQuarantineDir(t)
	path, _ := seedRemovedFileTarget(t, "<?php echo \"hello\";")

	if result := CleanInfectedFile(path); result.Cleaned {
		t.Fatal("a clean file was rewritten")
	}
	if got, ok := RemovedFileAt(path); ok {
		t.Fatalf("an unchanged file was remembered as removed: %+v", got)
	}
}

func TestRemovedFileLookupNormalisesThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "index.php")
	rememberRemovedFile(path, "digest", 10, "quarantine")

	if _, ok := RemovedFileAt(filepath.Dir(path) + "/./index.php"); !ok {
		t.Fatal("an equivalent spelling of the path missed the removal")
	}
}

func TestForgetRemovedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.php")
	rememberRemovedFile(path, "digest", 10, "quarantine")

	ForgetRemovedFile(path)

	if got, ok := RemovedFileAt(path); ok {
		t.Fatalf("forgotten removal still reported: %+v", got)
	}
}

func TestRemovedFileExpires(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	useRemovedFilesClock(t, &now)
	path := filepath.Join(t.TempDir(), "index.php")
	rememberRemovedFile(path, "digest", 10, "clean")

	now = now.Add(removedFileMemory - time.Second)
	if _, ok := RemovedFileAt(path); !ok {
		t.Fatal("removal forgotten before it expired")
	}
	now = now.Add(time.Second)
	if got, ok := RemovedFileAt(path); ok {
		t.Fatalf("expired removal still reported: %+v", got)
	}
}

func TestRemovedFilesSinceReturnsOnlyNewerRemovals(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.php")
	second := filepath.Join(t.TempDir(), "second.php")

	rememberRemovedFile(first, "d1", 1, "quarantine")
	_, seq := RemovedFilesSince(0)
	rememberRemovedFile(second, "d2", 2, "clean")

	newer, next := RemovedFilesSince(seq)
	if next <= seq {
		t.Fatalf("next sequence = %d, want past %d", next, seq)
	}
	paths := map[string]bool{}
	for _, r := range newer {
		paths[r.Path] = true
	}
	if !paths[second] || paths[first] {
		t.Fatalf("removals since %d = %+v, want %s and not %s", seq, newer, second, first)
	}
}
