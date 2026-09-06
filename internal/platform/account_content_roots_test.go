package platform

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestValidateAccountRootPattern(t *testing.T) {
	for _, pattern := range []string{"", "/", "/srv", "relative/*", "/*/public", "/srv/../etc", "/srv/a\nReadWritePaths=/", "/srv/[", "/srv/./site", "/srv/site/", "/srv/a\\b"} {
		if err := ValidateAccountRootPattern(pattern); err == nil {
			t.Errorf("accepted unsafe pattern %q", pattern)
		}
	}
	for _, pattern := range []string{"/srv/accounts/*/public", "/var/www/site", "/home[2-9]/*/public_html"} {
		if err := ValidateAccountRootPattern(pattern); err != nil {
			t.Errorf("valid pattern %q: %v", pattern, err)
		}
	}
}

func TestResolveAccountRootsConfinesGlobs(t *testing.T) {
	root, resolveErr := filepath.EvalSymlinks(t.TempDir())
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	first, second := filepath.Join(root, "alice", "public"), filepath.Join(root, "bob", "public")
	for _, path := range []string{first, second} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ResolveAccountRoots([]string{filepath.Join(root, "*", "public"), first, filepath.Join(root, "missing")})
	if err != nil || !slices.Equal(got, []string{first, second}) {
		t.Fatalf("resolved roots=%v error=%v", got, err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAccountRoots([]string{link}); err == nil {
		t.Fatal("accepted symlink root")
	}
	partial, partialErr := ResolveAccountRoots([]string{first, link})
	if partialErr == nil || !slices.Equal(partial, []string{first}) {
		t.Fatalf("unsafe root did not remain isolated: roots=%v error=%v", partial, partialErr)
	}
	if err := os.Symlink(filepath.Dir(first), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAccountRoots([]string{filepath.Join(root, "alias", "public")}); err == nil {
		t.Fatal("accepted symlink ancestor")
	}
}
