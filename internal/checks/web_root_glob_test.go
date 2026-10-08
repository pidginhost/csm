package checks

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestCheckedWebRootGlobPreservesMatches(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"site-a/public", "site-b/public", "site[1]/public", "back\\slash/public"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "site-a"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{
		"site-a/public", "site-a/./public/", "site-?/public", "site-[ab]/public",
		"*/public", "*/*", `site\[1\]/public`, `back\\slash/public`,
		"link/public", "missing/public", "file/public", "*/missing", "[bad", "*/[bad", "site-*/[bad",
	} {
		t.Run(pattern, func(t *testing.T) {
			pattern = root + string(filepath.Separator) + pattern
			want, err := filepath.Glob(pattern)
			got, complete := checkedWebRootGlob(pattern)
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) || complete != (err == nil) {
				t.Fatalf("matches=%q complete=%v, want matches=%q complete=%v", got, complete, want, err == nil)
			}
		})
	}
}

func TestCheckedWebRootGlobRejectsExcessiveDepth(t *testing.T) {
	pattern := t.TempDir() + string(filepath.Separator) + strings.Repeat("*/", 10001) + "public"
	if _, err := filepath.Glob(pattern); err != filepath.ErrBadPattern {
		t.Fatalf("filepath.Glob error=%v, want ErrBadPattern", err)
	}
	if matches, complete := checkedWebRootGlob(pattern); complete || len(matches) != 0 {
		t.Fatalf("matches=%q complete=%v, want incomplete discovery", matches, complete)
	}
}

// A partial directory read still names usable roots. Losing its siblings
// would stall their coverage even though only discovery's proof is incomplete.
func TestResolveWebRootsKeepsPartialDirectoryResults(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a", "public")
	second := filepath.Join(root, "z", "public")
	for _, dir := range []string{first, second} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	prev := osFS
	osFS = &faultingYARADeepOS{OS: prev, readDir: func(path string) ([]os.DirEntry, error) {
		entries, err := prev.ReadDir(path)
		if path == root && err == nil {
			return entries[:1], os.ErrPermission
		}
		return entries, err
	}}
	t.Cleanup(func() { osFS = prev })
	roots, complete := resolveWebRootsChecked(&config.Config{AccountRoots: []string{
		filepath.Join(root, "*", "public"), second,
	}})
	if complete || !reflect.DeepEqual(roots, []string{first, second}) {
		t.Fatalf("roots=%q complete=%v, want both discovered roots and incomplete", roots, complete)
	}
}
