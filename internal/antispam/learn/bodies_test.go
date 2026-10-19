package learn

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func testBodies(t *testing.T) *Bodies {
	t.Helper()
	return &Bodies{Dir: filepath.Join(t.TempDir(), "anchors"), owner: os.Getuid()}
}

func stageCommit(t *testing.T, b *Bodies, body []byte, id uint64) Staged {
	t.Helper()
	s, err := b.Stage(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Commit(s, id); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStageCommitRead(t *testing.T) {
	b := testBodies(t)
	body := []byte("From: a@example.com\r\n\r\nspam text\r\n")
	s, stageErr := b.Stage(body)
	if stageErr != nil {
		t.Fatal(stageErr)
	}
	if !strings.HasPrefix(s.Name, ".stage-") || s.Len != int64(len(body)) || len(s.SHA) != 64 {
		t.Fatalf("staged %+v", s)
	}
	if info, err := os.Stat(filepath.Join(b.Dir, s.Name)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged file mode %v err %v", info, err)
	}
	if dir, err := os.Stat(b.Dir); err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v err %v", dir, err)
	}
	if err := b.Commit(s, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.Dir, s.Name)); !os.IsNotExist(err) {
		t.Fatal("staging name left behind")
	}
	got, err := b.Read(7, s.Len, s.SHA)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("read %q err %v", got, err)
	}
}

func TestCommitNeverReplaces(t *testing.T) {
	b := testBodies(t)
	first := stageCommit(t, b, []byte("first"), 3)
	s, err := b.Stage([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Commit(s, 3); err == nil {
		t.Fatal("committed over an existing anchor body")
	}
	if _, err := b.Read(3, first.Len, first.SHA); err != nil {
		t.Fatalf("original body lost: %v", err)
	}
	for _, name := range []string{"../x", "1.msg", ".stage-a/b", ""} {
		if err := b.Commit(Staged{Name: name}, 4); err == nil {
			t.Fatalf("committed staging name %q", name)
		}
	}
}

func TestStageRejectsOversize(t *testing.T) {
	b := testBodies(t)
	if _, err := b.Stage(make([]byte, MaxBody+1)); err == nil {
		t.Fatal("oversized body staged")
	}
	if entries, _ := os.ReadDir(b.Dir); len(entries) != 0 {
		t.Fatalf("left %d files", len(entries))
	}
}

func TestReadDetectsCorruption(t *testing.T) {
	b := testBodies(t)
	s := stageCommit(t, b, []byte("anchor body"), 1)
	if _, err := b.Read(1, s.Len+1, s.SHA); !errors.Is(err, ErrBodyInvalid) {
		t.Fatalf("wrong length: %v", err)
	}
	if err := os.WriteFile(filepath.Join(b.Dir, BodyName(1)), []byte("anchor bodx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(1, s.Len, s.SHA); !errors.Is(err, ErrBodyInvalid) {
		t.Fatalf("changed bytes: %v", err)
	}
	if _, err := b.Read(9, s.Len, s.SHA); !errors.Is(err, ErrBodyInvalid) {
		t.Fatalf("missing body: %v", err)
	}
}

func TestReadRejectsSymlinkAndLooseMode(t *testing.T) {
	b := testBodies(t)
	s := stageCommit(t, b, []byte("anchor body"), 1)
	path := filepath.Join(b.Dir, BodyName(1))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(1, s.Len, s.SHA); !errors.Is(err, ErrBodyInvalid) {
		t.Fatalf("loose mode: %v", err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("anchor body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(1, s.Len, s.SHA); !errors.Is(err, ErrBodyInvalid) {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Chmod(b.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stage([]byte("x")); err == nil {
		t.Fatal("staged into a directory others can read")
	}
}

func TestRemoveIdempotent(t *testing.T) {
	b := testBodies(t)
	s := stageCommit(t, b, []byte("anchor body"), 1)
	for range 2 {
		if err := b.Remove(1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Read(1, s.Len, s.SHA); !errors.Is(err, ErrBodyInvalid) {
		t.Fatalf("removed body still readable: %v", err)
	}
}

func TestOrphansOnlyUnreferenced(t *testing.T) {
	b := testBodies(t)
	stageCommit(t, b, []byte("kept"), 1)
	stageCommit(t, b, []byte("crashed before its intent"), 2)
	staged, err := b.Stage([]byte("staged only"))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := b.Stage([]byte("referenced by an intent"))
	if err != nil {
		t.Fatal(err)
	}
	referenced := func(name string) bool { return name == BodyName(1) || name == pending.Name }
	got, err := b.Orphans(referenced)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{BodyName(2): true, staged.Name: true}
	if len(got) != len(want) || !want[got[0]] || !want[got[1]] {
		t.Fatalf("orphans %v", got)
	}
	for _, name := range got {
		if err := b.RemoveOrphan(name); err != nil {
			t.Fatal(err)
		}
	}
	if left, err := b.Orphans(referenced); err != nil || len(left) != 0 {
		t.Fatalf("left %v err %v", left, err)
	}
	if err := b.RemoveOrphan("../" + BodyName(1)); err == nil {
		t.Fatal("removed a path outside the anchor directory")
	}
}

func TestStageBodyENOSPCSendsNothing(t *testing.T) {
	b := testBodies(t)
	b.writeFile = func(*os.File, []byte) error { return syscall.ENOSPC }
	s, err := b.Stage([]byte("anchor body"))
	if !errors.Is(err, syscall.ENOSPC) || s != (Staged{}) {
		t.Fatalf("staged %+v err %v", s, err)
	}
	if entries, _ := os.ReadDir(b.Dir); len(entries) != 0 {
		t.Fatalf("left %d files", len(entries))
	}
}
