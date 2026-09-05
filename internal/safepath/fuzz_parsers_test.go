package safepath

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzRestoreRelativePath(f *testing.F) {
	for _, path := range []string{"file", "account/file", "../outside", "/absolute", "a/../b", "", ".", "a\x00b"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		root := t.TempDir()
		target, err := OpenTarget(root, path, false)
		if err != nil {
			return
		}
		defer target.Close()
		if !filepath.IsLocal(path) || filepath.Clean(path) != path || path == "." {
			t.Fatalf("accepted nonlocal or unclean path %q", path)
		}
		file, err := target.Parent.OpenFile(target.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("created file is not in the root: %v", err)
		}
	})
}
