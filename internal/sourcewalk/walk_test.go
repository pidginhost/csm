package sourcewalk

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
)

func TestWalkContinuesAfterDirectoryRemoval(t *testing.T) {
	for _, scratch := range []string{"shieldtest1", "dropper-webroot-1", "eventfilter-1", "other"} {
		t.Run(scratch, func(t *testing.T) {
			root := t.TempDir()
			gone := filepath.Join(root, scratch)
			if err := os.Mkdir(gone, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package example\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var files []string
			err := filepath.WalkDir(root, IgnoreVanished(root, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if path == gone {
					// WalkDir has already listed this directory in its parent,
					// but has not tried to read the directory itself yet.
					return os.Remove(gone)
				}
				if !d.IsDir() {
					files = append(files, filepath.Base(path))
				}
				return nil
			}))
			if err != nil {
				t.Fatalf("walk failed after scratch removal: %v", err)
			}
			if !slices.Equal(files, []string{"source.go"}) {
				t.Fatalf("files = %v, want the surviving source", files)
			}
		})
	}
}

type readDirErrorFS struct {
	fstest.MapFS
	name string
	err  error
}

func (f readDirErrorFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.name {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: f.err}
	}
	return f.MapFS.ReadDir(name)
}

func TestWalkPreservesRootAndReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		err        error
	}{
		{"missing root", ".", fs.ErrNotExist},
		{"unreadable root", ".", fs.ErrPermission},
		{"unreadable child", "child", fs.ErrPermission},
		{"invalid child", "child", fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := readDirErrorFS{
				MapFS: fstest.MapFS{"child/source.go": {Data: []byte("package example\n")}},
				name:  tc.path,
				err:   tc.err,
			}
			err := fs.WalkDir(root, ".", IgnoreVanished(".", func(_ string, _ fs.DirEntry, err error) error {
				return err
			}))
			if !errors.Is(err, tc.err) {
				t.Fatalf("walk error = %v, want %v", err, tc.err)
			}
		})
	}
	root := t.TempDir()
	err := filepath.WalkDir(filepath.Join(root, "missing"), IgnoreVanished(filepath.Join(root, "missing"), func(_ string, _ fs.DirEntry, err error) error {
		return err
	}))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing root error = %v, want not-exist", err)
	}
}

func TestWalkPreservesVisitorErrors(t *testing.T) {
	root := fstest.MapFS{"source.go": {Data: []byte("package example\n")}}
	err := fs.WalkDir(root, ".", IgnoreVanished(".", func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "source.go" {
			return &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return nil
	}))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("source read error = %v, want not-exist", err)
	}
}
