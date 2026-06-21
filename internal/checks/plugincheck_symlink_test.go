package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On cPanel, ~/www is a symlink to ~/public_html. The plugin scanner's
// "/home/*/*/wp-config.php" glob matches the same physical install through both
// names; findAllWPInstalls must collapse them to the canonical public_html path
// so the install is not scanned twice and the finding it produces carries a
// non-symlinked path the Re-check can resolve.
func TestFindAllWPInstalls_CollapsesWWWSymlink(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch {
			case strings.Contains(pattern, "/public_html/wp-config.php"):
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			case strings.HasSuffix(pattern, "/home/*/*/wp-config.php"):
				return []string{
					"/home/alice/www/wp-config.php",
					"/home/alice/shop/wp-config.php",
				}, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice/www":
				return accountScanFakeInfo{name: "www", mode: os.ModeSymlink}, nil
			case "/home/alice/public_html", "/home/alice/shop":
				return accountScanFakeInfo{name: filepath.Base(name), mode: os.ModeDir | 0755, isDir: true}, nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) {
			if name == "/home/alice/www" {
				return "public_html", nil
			}
			return "", os.ErrNotExist
		},
	})

	results := findAllWPInstalls()
	want := map[string]bool{
		"/home/alice/public_html/wp-config.php": true,
		"/home/alice/shop/wp-config.php":        true,
	}
	if len(results) != len(want) {
		t.Fatalf("expected %d installs (www collapsed into public_html), got %d: %v", len(want), len(results), results)
	}
	for _, r := range results {
		if !want[r] {
			t.Errorf("unexpected install path %q (www should canonicalize to public_html)", r)
		}
	}
}

// A document-root symlink that escapes the account home must never redirect the
// discovered path; the original path is kept so wp-cli is not pointed outside
// the account.
func TestCanonicalWPInstallPath_EscapeSymlinkNotRedirected(t *testing.T) {
	withMockOS(t, &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice/www" {
				return accountScanFakeInfo{name: "www", mode: os.ModeSymlink}, nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) {
			if name == "/home/alice/www" {
				return "/etc", nil
			}
			return "", os.ErrNotExist
		},
	})
	const in = "/home/alice/www/wp-config.php"
	if got := canonicalWPInstallPath(in); got != in {
		t.Errorf("escape symlink must keep original path, got %q", got)
	}
}

// A real (non-symlink) addon directory is returned unchanged.
func TestCanonicalWPInstallPath_RealDirUnchanged(t *testing.T) {
	withMockOS(t, &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice/shop" {
				return accountScanFakeInfo{name: "shop", mode: os.ModeDir | 0755, isDir: true}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	const in = "/home/alice/shop/wp-config.php"
	if got := canonicalWPInstallPath(in); got != in {
		t.Errorf("real directory must be unchanged, got %q", got)
	}
}
