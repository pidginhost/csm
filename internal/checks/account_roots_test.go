package checks

import (
	"context"
	"os"
	"slices"
	"testing"
)

// withAccountHomeRoots points every account-root helper at roots for the
// duration of a test.
func withAccountHomeRoots(t *testing.T, roots ...string) {
	t.Helper()
	old := accountHomeRoots
	accountHomeRoots = func() []string { return roots }
	t.Cleanup(func() { accountHomeRoots = old })
}

// The checks package hardcoded /home in roughly eighty places: account
// enumeration, per-account joins, host-wide globs, path-prefix tests and
// the remediation allow-lists. One seam now answers "where do accounts
// live", so a Plesk host (/var/www/vhosts) is scanned and remediated
// like a cPanel one.
func TestGetScanHomeDirsEnumeratesEveryAccountRoot(t *testing.T) {
	withAccountHomeRoots(t, "/srv/vhosts")
	var listed []string
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			listed = append(listed, name)
			if name == "/srv/vhosts" {
				return []os.DirEntry{fakeDirEntry{fakeFileInfo{name: "alice"}}}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	entries, err := GetScanHomeDirs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "alice" {
		t.Fatalf("entries = %v, want alice under /srv/vhosts", entries)
	}
	if !slices.Contains(listed, "/srv/vhosts") || slices.Contains(listed, "/home") {
		t.Fatalf("directories listed = %v, want the configured root only", listed)
	}
}

func TestAccountHomeDirResolvesUnderConfiguredRoot(t *testing.T) {
	withAccountHomeRoots(t, "/srv/vhosts", "/home")
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/bob" {
				return fakeFileInfo{name: "bob"}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	if got := accountHomeDir("bob"); got != "/home/bob" {
		t.Fatalf("accountHomeDir(bob) = %q, want the root that holds it", got)
	}
	if got := accountHomeDir("carol"); got != "/srv/vhosts/carol" {
		t.Fatalf("accountHomeDir(carol) = %q, want the first root when absent", got)
	}
}

func TestHomeGlobUsesEveryAccountRoot(t *testing.T) {
	withAccountHomeRoots(t, "/srv/vhosts", "/home")
	var patterns []string
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			patterns = append(patterns, pattern)
			if pattern == "/srv/vhosts/*/public_html/wp-config.php" {
				return []string{"/srv/vhosts/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
	})
	got, err := homeGlob(context.Background(), "public_html", "wp-config.php")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("matches = %v", got)
	}
	want := []string{"/srv/vhosts/*/public_html/wp-config.php", "/home/*/public_html/wp-config.php"}
	if !slices.Equal(patterns, want) {
		t.Fatalf("glob patterns = %v, want %v", patterns, want)
	}
}

func TestAccountRootOfRecognisesConfiguredRoots(t *testing.T) {
	withAccountHomeRoots(t, "/srv/vhosts")
	root, account, ok := accountRootOf("/srv/vhosts/alice/public_html/x.php")
	if !ok || root != "/srv/vhosts" || account != "alice" {
		t.Fatalf("accountRootOf = (%q, %q, %v)", root, account, ok)
	}
	if _, _, ok := accountRootOf("/home/alice/public_html/x.php"); ok {
		t.Fatal("/home must not be an account root when not configured")
	}
	if _, _, ok := accountRootOf("/srv/vhosts/alice"); ok {
		t.Fatal("an account home itself is not inside an account")
	}
}

func TestFixRootsFollowAccountRoots(t *testing.T) {
	withAccountHomeRoots(t, "/srv/vhosts")
	if got := effectiveFixRoots(nil); !slices.Equal(got, []string{"/srv/vhosts"}) {
		t.Fatalf("effectiveFixRoots(nil) = %v", got)
	}
	if got := effectiveFixRoots(nil, "/tmp"); !slices.Equal(got, []string{"/srv/vhosts", "/tmp"}) {
		t.Fatalf("effectiveFixRoots(nil, /tmp) = %v", got)
	}
	if got := effectiveFixRoots([]string{"/override"}); !slices.Equal(got, []string{"/override"}) {
		t.Fatalf("an explicit override must win: %v", got)
	}
	if fixTargetMinDepth("/srv/vhosts") != 2 {
		t.Fatal("an account root needs depth 2 so a whole home is never a fix target")
	}
	if fixTargetMinDepth("/tmp") != 1 {
		t.Fatal("non-account roots keep depth 1")
	}
}
