package quarantinefs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestStoreDurabilityBoundaries(t *testing.T) {
	oldCopy, oldSync, oldClose := copyContent, syncFile, closeFile
	t.Cleanup(func() { copyContent, syncFile, closeFile = oldCopy, oldSync, oldClose })
	wantOrder := []string{"sync-parent", "close-parent", "write-content", "sync-content", "close-content", "sync-directory", "close-directory", "write-metadata", "sync-metadata", "close-metadata", "sync-directory", "close-directory"}
	for failAt := -1; failAt < len(wantOrder); failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			root := t.TempDir()
			original := filepath.Join(root, "original")
			if err := os.WriteFile(original, []byte("evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "quarantined")
			var events []string
			step := func(operation string, f *os.File) error {
				kind := "content"
				switch {
				case f.Name() == root:
					kind = "directory"
				case f.Name() == filepath.Dir(root):
					kind = "parent"
				case strings.HasSuffix(f.Name(), ".meta"):
					kind = "metadata"
				}
				events = append(events, operation+"-"+kind)
				if len(events)-1 == failAt {
					return syscall.EIO
				}
				return nil
			}
			copyContent = func(w io.Writer, r io.Reader) (int64, error) {
				if err := step("write", w.(*os.File)); err != nil {
					n, _ := io.CopyN(w, r, 2)
					return n, err
				}
				return oldCopy(w, r)
			}
			syncFile = func(f *os.File) error {
				if err := step("sync", f); err != nil {
					return err
				}
				return oldSync(f)
			}
			closeFile = func(f *os.File) error {
				return errors.Join(step("close", f), oldClose(f))
			}
			in, err := os.Open(original)
			if err != nil {
				t.Fatal(err)
			}
			err = Store(path, in, []byte(`{"original_path":"original"}`), 0600)
			if closeErr := in.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if failAt < 0 {
				if err != nil || !slices.Equal(events, wantOrder) {
					t.Fatalf("store order=%v, error=%v; want %v", events, err, wantOrder)
				}
				for _, entry := range []struct{ path, content string }{{path, "evidence"}, {path + ".meta", `{"original_path":"original"}`}} {
					data, readErr := os.ReadFile(entry.path)
					if readErr != nil || string(data) != entry.content {
						t.Fatalf("reopened %s=%q, error=%v", entry.path, data, readErr)
					}
				}
			} else {
				if !errors.Is(err, syscall.EIO) {
					t.Fatalf("failure %s was not reported: %v", wantOrder[failAt], err)
				}
				for _, name := range []string{path, path + ".meta"} {
					if _, statErr := os.Lstat(name); !os.IsNotExist(statErr) {
						t.Errorf("failed transaction published %s: %v", name, statErr)
					}
				}
			}
			data, readErr := os.ReadFile(original)
			if readErr != nil || string(data) != "evidence" {
				t.Fatalf("original is not recoverable: %q, error=%v", data, readErr)
			}
		})
	}
}

func TestStoreDoesNotOverwriteOlderEvidence(t *testing.T) {
	for _, oldName := range []string{"content", "metadata"} {
		t.Run(oldName, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "quarantined")
			existing := path
			if oldName == "metadata" {
				existing += ".meta"
			}
			if err := os.WriteFile(existing, []byte("older evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Store(path, strings.NewReader("new evidence"), []byte("new metadata"), 0600); !errors.Is(err, os.ErrExist) {
				t.Fatalf("older %s collision not rejected: %v", oldName, err)
			}
			data, err := os.ReadFile(existing)
			if err != nil || string(data) != "older evidence" {
				t.Fatalf("older evidence changed: %q, error=%v", data, err)
			}
		})
	}
}

func TestRemoveEvidenceKeepsMetadataOnContentFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quarantined")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "content"), []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	meta := path + ".meta"
	if err := os.WriteFile(meta, []byte("recovery metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEvidence(path, meta); err == nil || !strings.Contains(err.Error(), "content remains") {
		t.Fatalf("nonempty evidence directory removal error=%v", err)
	}
	data, err := os.ReadFile(meta)
	if err != nil || string(data) != "recovery metadata" {
		t.Fatalf("metadata lost after failed evidence removal: %q, error=%v", data, err)
	}
}

func TestEnsureDirRetriesFailedEntrySync(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "quarantine")
	oldSync := syncFile
	t.Cleanup(func() { syncFile = oldSync })
	calls := 0
	syncFile = func(f *os.File) error {
		if f.Name() == parent {
			calls++
			return syscall.EIO
		}
		return oldSync(f)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := EnsureDir(path, 0700); !errors.Is(err, syscall.EIO) {
			t.Fatalf("attempt %d accepted an unsynced directory: %v", attempt, err)
		}
	}
	if calls != 2 {
		t.Fatalf("directory entry sync attempts=%d, want 2", calls)
	}
	syncFile = oldSync
	if err := EnsureDir(path, 0700); err != nil {
		t.Fatalf("retry after storage recovery: %v", err)
	}
}
