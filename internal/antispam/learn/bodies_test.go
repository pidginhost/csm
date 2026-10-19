package learn

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
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
	if entries, err := os.ReadDir(b.Dir); len(entries) != 0 || err != nil && !os.IsNotExist(err) {
		t.Fatalf("left %d files, err=%v", len(entries), err)
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
	if got, err := b.Read(1, s.Len, s.SHA); !errors.Is(err, ErrBodyInvalid) || got != nil {
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
	want := []string{BodyName(2), staged.Name}
	slices.Sort(want)
	if !slices.Equal(got, want) {
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
	if entries, err := os.ReadDir(b.Dir); err != nil || len(entries) != 0 {
		t.Fatalf("left %d files, err=%v", len(entries), err)
	}
}

func TestStageFailureCleansPinnedDirectory(t *testing.T) {
	b := testBodies(t)
	moved := b.Dir + "-moved"
	var name string
	b.writeFile = func(f *os.File, body []byte) error {
		name = filepath.Base(f.Name())
		if _, err := f.Write(body[:3]); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(b.Dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(b.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(b.Dir, name), []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		return &os.PathError{Op: "write", Path: f.Name(), Err: syscall.EIO}
	}
	s, err := b.Stage([]byte("anchor body"))
	if !errors.Is(err, syscall.EIO) || s != (Staged{}) {
		t.Fatalf("failed stage returned %+v, %v", s, err)
	}
	if _, err := os.Lstat(filepath.Join(moved, name)); !os.IsNotExist(err) {
		t.Errorf("failed stage left the partial body: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(b.Dir, name)); err != nil || string(got) != "replacement" {
		t.Errorf("cleanup changed the replacement directory: %v", err)
	}
}

func TestReadUnsafeDirectoryIsBodyInvalid(t *testing.T) {
	for _, kind := range []string{"mode", "owner", "symlink", "symlink-trailing-slash"} {
		t.Run(kind, func(t *testing.T) {
			b := testBodies(t)
			s := stageCommit(t, b, []byte("anchor body"), 1)
			switch kind {
			case "mode":
				if err := os.Chmod(b.Dir, 0o755); err != nil {
					t.Fatal(err)
				}
			case "owner":
				b.owner++
			case "symlink", "symlink-trailing-slash":
				moved := b.Dir + "-moved"
				if err := os.Rename(b.Dir, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, b.Dir); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink-trailing-slash" {
					b.Dir += string(filepath.Separator)
				}
			}
			if got, err := b.Read(1, s.Len, s.SHA); !errors.Is(err, ErrBodyInvalid) || got != nil {
				t.Fatalf("unsafe directory: returned bytes=%t, err=%v", got != nil, err)
			}
		})
	}
}

func TestStageRejectsWrongDirectoryMode(t *testing.T) {
	b := testBodies(t)
	if err := os.Mkdir(b.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(b.Dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(b.Dir, 0o300); err != nil {
		t.Fatal(err)
	}
	if s, err := b.Stage([]byte("anchor body")); err == nil || s != (Staged{}) {
		t.Fatalf("accepted a directory without mode 0700: %+v, %v", s, err)
	}
}

func TestRemoveOrphanRejectsNonBodyNames(t *testing.T) {
	for _, name := range []string{".", "..", "notes", ".stage-", "01.msg", "+1.msg", "../1.msg", ""} {
		t.Run(name, func(t *testing.T) {
			b := testBodies(t)
			if err := os.Mkdir(b.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := b.RemoveOrphan(name); err == nil {
				t.Error("accepted a non-body name")
			}
			if info, err := os.Stat(b.Dir); err != nil || !info.IsDir() {
				t.Errorf("removed the body directory: %v", err)
			}
		})
	}
}

func TestOrphansIgnoreUnrelatedEntries(t *testing.T) {
	b := testBodies(t)
	stageCommit(t, b, []byte("anchor body"), 1)
	for _, name := range []string{"notes", ".stage-", "01.msg", "+1.msg"} {
		if err := os.WriteFile(filepath.Join(b.Dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"2.msg", ".stage-directory"} {
		if err := os.Mkdir(filepath.Join(b.Dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := b.Orphans(func(string) bool { return false })
	if err != nil || !slices.Equal(got, []string{BodyName(1)}) {
		t.Fatalf("orphans = %v, err=%v", got, err)
	}
}

func TestRemoveDoesNotRemoveDirectories(t *testing.T) {
	b := testBodies(t)
	path := filepath.Join(b.Dir, BodyName(1))
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := b.Remove(1); err == nil {
		t.Fatal("removed a directory as a body")
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("body directory changed: %v", err)
	}
}

func TestStageFailuresLeaveNoBodyOrPrivateError(t *testing.T) {
	for _, kind := range []string{"ENOSPC", "EIO", "opaque", "close"} {
		t.Run(kind, func(t *testing.T) {
			b := testBodies(t)
			body := []byte("synthetic private message")
			var name string
			b.writeFile = func(f *os.File, body []byte) error {
				name = f.Name()
				if _, err := f.Write(body[:3]); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "ENOSPC":
					return &os.PathError{Op: "write", Path: name, Err: syscall.ENOSPC}
				case "EIO":
					return &os.PathError{Op: "sync", Path: name, Err: syscall.EIO}
				case "opaque":
					return errors.New(name + string(body))
				default:
					return f.Close()
				}
			}
			s, err := b.Stage(body)
			if err == nil || s != (Staged{}) {
				t.Fatal("failed staging returned success or body metadata")
			}
			if strings.Contains(err.Error(), name) || strings.Contains(err.Error(), b.Dir) || strings.Contains(err.Error(), string(body)) {
				t.Fatal("stage error exposed message data")
			}
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				t.Fatal("stage error retained a private path")
			}
			if kind == "ENOSPC" && !errors.Is(err, syscall.ENOSPC) || kind == "EIO" && !errors.Is(err, syscall.EIO) {
				t.Fatal("stage error lost its errno")
			}
			entries, err := os.ReadDir(b.Dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed staging left entries: count=%d err=%v", len(entries), err)
			}
		})
	}
}

func TestReadNeverReturnsUnverifiedBytes(t *testing.T) {
	b := testBodies(t)
	s := stageCommit(t, b, []byte("anchor body"), 1)
	for _, tc := range []struct {
		name string
		len  int64
		sha  string
	}{
		{"negative", -1, s.SHA},
		{"oversize", MaxBody + 1, s.SHA},
		{"truncated", s.Len - 1, s.SHA},
		{"longer", s.Len + 1, s.SHA},
		{"hash", s.Len, strings.Repeat("0", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := b.Read(1, tc.len, tc.sha); !errors.Is(err, ErrBodyInvalid) || got != nil {
				t.Fatalf("unverified read: returned bytes=%t, err=%v", got != nil, err)
			}
		})
	}
	if err := os.Mkdir(filepath.Join(b.Dir, BodyName(2)), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Read(2, 0, ""); !errors.Is(err, ErrBodyInvalid) || got != nil {
		t.Fatalf("directory read: returned bytes=%t, err=%v", got != nil, err)
	}
}

func TestPinnedBodyDirectoryMetadataAndListing(t *testing.T) {
	b := testBodies(t)
	s, err := b.Stage([]byte("anchor body"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := b.dir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	want, err := dir.Info()
	if err != nil {
		t.Fatal(err)
	}
	if renameErr := os.Rename(b.Dir, b.Dir+"-moved"); renameErr != nil {
		t.Fatal(renameErr)
	}
	if mkdirErr := os.Mkdir(b.Dir, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	got, err := dir.Info()
	if err != nil || !os.SameFile(want, got) {
		t.Fatalf("metadata followed the replacement directory: %v", err)
	}
	entries, err := dir.ReadDir()
	if err != nil || len(entries) != 1 || entries[0].Name() != s.Name {
		t.Fatalf("listing followed the replacement directory: count=%d, err=%v", len(entries), err)
	}
}
