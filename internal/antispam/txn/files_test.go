package txn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTest(t *testing.T, p, content string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
}

func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestReadFileStates(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "file")
	if st, err := readFile(p); err != nil || st.exists {
		t.Fatalf("absent file: %+v, %v", st, err)
	}
	writeTest(t, p, "text", 0o640)
	st, err := readFile(p)
	if err != nil || !st.exists || st.content != "text" || st.perm != 0o640 || st.uid != os.Getuid() {
		t.Fatalf("file: %+v, %v", st, err)
	}
	if err := os.Symlink(p, filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(filepath.Join(d, "link")); err == nil {
		t.Error("followed a symbolic link")
	}
	if _, err := readFile(d); err == nil {
		t.Error("read a directory")
	}
}

func TestReadFileBoundsSnapshots(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	writeTest(t, p, "", 0o600)
	if err := os.Truncate(p, maxFileBytes); err != nil {
		t.Fatal(err)
	}
	if st, err := readFile(p); err != nil || !st.exists || len(st.content) != maxFileBytes {
		t.Fatalf("snapshot at limit: %d bytes, %v", len(st.content), err)
	}
	if err := os.Truncate(p, maxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if st, err := readFile(p); err == nil || st.exists || st.content != "" {
		t.Fatalf("oversized snapshot returned partial state: %d bytes, %v", len(st.content), err)
	}
}

func TestReplaceFileKeepsOwnerAndMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	writeTest(t, p, "old", 0o600)
	if err := replaceFile(p, fileState{exists: true, content: "old"}, fileState{exists: true, content: "new"}); err != nil {
		t.Fatal(err)
	}
	st, err := readFile(p)
	if err != nil || st.content != "new" || st.perm != 0o600 || st.uid != os.Geteuid() || st.gid != os.Getegid() {
		t.Errorf("replaced file: %+v, %v", st, err)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".*csmtmp"))
	if len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestReplaceFilePreservesSpecialModeBits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	wantMode := os.FileMode(0o640) | os.ModeSetgid | os.ModeSticky
	writeTest(t, p, "old", wantMode)
	if err := replaceFile(p, fileState{exists: true, content: "old"}, fileState{exists: true, content: "new"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil || info.Mode() != wantMode {
		t.Fatalf("mode after replacement = %v, %v; want %v", info, err, wantMode)
	}
}

func TestWriteAtomicRejectsUnreadableSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	writeTest(t, p, "old", 0o600)
	if err := writeAtomic(p, strings.Repeat("x", maxFileBytes+1), 0o600, -1, -1); err == nil {
		t.Fatal("accepted content too large to snapshot or roll back")
	}
	if st, err := readFile(p); err != nil || st.content != "old" {
		t.Fatalf("oversized write changed the original: %+v, %v", st, err)
	}
}

func TestWriteAtomicCleansUpOnPublishFailure(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "hook")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if publishErr := writeAtomic(p, "new", 0o600, -1, -1); publishErr == nil {
		t.Fatal("replaced a directory with a file")
	}
	after, err := os.Stat(p)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("failed publication changed the destination: %v", err)
	}
	entries, err := os.ReadDir(d)
	if err != nil || len(entries) != 1 || entries[0].Name() != "hook" {
		t.Fatalf("temporary files remain after failed publication: %v, %v", entries, err)
	}
}

func TestPrivateDirRejectsSymlinkParent(t *testing.T) {
	d := realTempDir(t)
	outside := filepath.Join(d, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(filepath.Join(link, "antispam")); err == nil {
		t.Fatal("created a private directory through a symbolic link")
	}
	if _, err := os.Stat(filepath.Join(outside, "antispam")); !os.IsNotExist(err) {
		t.Fatalf("created an outside directory: %v", err)
	}
}

func TestReplaceFileCreatesAndRemoves(t *testing.T) {
	p := filepath.Join(t.TempDir(), "actions.conf")
	if err := replaceFile(p, fileState{}, fileState{exists: true, content: "x"}); err != nil {
		t.Fatal(err)
	}
	if st, err := readFile(p); err != nil || st.content != "x" || st.perm != 0o644 {
		t.Errorf("created file: %+v, %v", st, err)
	}
	if err := replaceFile(p, fileState{exists: true, content: "x"}, fileState{}); err != nil {
		t.Fatal(err)
	}
	if st, err := readFile(p); err != nil || st.exists {
		t.Errorf("file not removed: %+v, %v", st, err)
	}
}

func TestReplaceFileRefusesConcurrentEdit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	writeTest(t, p, "cpanel wrote this", 0o644)
	for name, next := range map[string]fileState{"write": {exists: true, content: "csm"}, "remove": {}} {
		err := replaceFile(p, fileState{exists: true, content: "snapshot"}, next)
		if !errors.Is(err, errConflict) {
			t.Errorf("%s: err = %v, want conflict", name, err)
		}
	}
	if st, err := readFile(p); err != nil || st.content != "cpanel wrote this" {
		t.Errorf("concurrent edit overwritten: %q, %v", st.content, err)
	}
	if err := replaceFile(p, fileState{}, fileState{exists: true, content: "csm"}); !errors.Is(err, errConflict) {
		t.Errorf("created over an existing file: %v", err)
	}
}

func TestPrivateDir(t *testing.T) {
	d := filepath.Join(realTempDir(t), "antispam")
	if err := privateDir(d); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(d); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(d); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("directory = %v, %v; want mode 0700", info, err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(link); err == nil {
		t.Error("accepted a symbolic link")
	}
}
