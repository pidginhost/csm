package txn

import (
	"errors"
	"os"
	"path/filepath"
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

func TestReplaceFileKeepsOwnerAndMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	writeTest(t, p, "old", 0o600)
	if err := replaceFile(p, fileState{exists: true, content: "old"}, fileState{exists: true, content: "new"}); err != nil {
		t.Fatal(err)
	}
	st, _ := readFile(p)
	if st.content != "new" || st.perm != 0o600 {
		t.Errorf("replaced file: %+v", st)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".*csmtmp"))
	if len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestReplaceFileCreatesAndRemoves(t *testing.T) {
	p := filepath.Join(t.TempDir(), "actions.conf")
	if err := replaceFile(p, fileState{}, fileState{exists: true, content: "x"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := readFile(p); st.content != "x" || st.perm != 0o644 {
		t.Errorf("created file: %+v", st)
	}
	if err := replaceFile(p, fileState{exists: true, content: "x"}, fileState{}); err != nil {
		t.Fatal(err)
	}
	if st, _ := readFile(p); st.exists {
		t.Error("file not removed")
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
	if st, _ := readFile(p); st.content != "cpanel wrote this" {
		t.Errorf("concurrent edit overwritten: %q", st.content)
	}
	if err := replaceFile(p, fileState{}, fileState{exists: true, content: "csm"}); !errors.Is(err, errConflict) {
		t.Errorf("created over an existing file: %v", err)
	}
}

func TestPrivateDir(t *testing.T) {
	d := filepath.Join(t.TempDir(), "antispam")
	if err := privateDir(d); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(d); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(d); info.Mode().Perm() != 0o700 {
		t.Errorf("mode %v, want 0700", info.Mode().Perm())
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(link); err == nil {
		t.Error("accepted a symbolic link")
	}
}
