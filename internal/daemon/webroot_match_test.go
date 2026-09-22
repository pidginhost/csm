package daemon

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// referenceWebRootMatch is the matcher as it stood before it skipped globs
// that cannot match a directory: every glob against every ancestor.
func referenceWebRootMatch(path string, patterns []string) bool {
	dir := filepath.Clean(filepath.Dir(path))
	for {
		for _, pattern := range patterns {
			matched, err := filepath.Match(filepath.Clean(pattern), dir)
			if err == nil && matched {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

var webRootMatchGlobs = []string{
	"/home/*", "/home2/*", "/home/*/public_html", "/var/www/vhosts/*/httpdocs",
	"/srv/vhosts/external", "/usr/local/directadmin/data/users/*/domains/*/public_html",
	"/", "/*", "*", "", ".", "..", "home/*", "/home/", "/home//*/", "/home/*/../x",
	"/home/?", "/h?me/*", "/home/*/*", "/home/[a-c]*", "/home/[/]x", "/home[/]*",
	"/home/\\*", "/home\\/x/*", "/home/[", "/home/\\", "/home/[^a]", "/home/a*/*b",
}

var webRootMatchPaths = []string{
	"/home/alice/public_html/wp-config.php", "/home/alice/public_html", "/home/alice",
	"/home", "/", "", ".", "x", "home/alice/f", "/home2/bob/x.php", "/home/b/x",
	"/home/*/f", "/home/[/]x/f", "/home/a/x/y/z/f.php", "/homex/y", "/home/abc/xyzb/f",
	"/var/www/vhosts/example.com/httpdocs/index.php", "/srv/vhosts/external/a/b",
	"/usr/local/directadmin/data/users/u/domains/d/public_html/p/q.php",
	"/home/alice/../bob/x", "//home//alice//f", "/home/alice/", "/tmp/sess_1",
	"/var/lib/mysql/db/table.ibd", "/home/\\*/f", "/home/x/../x/f", "/home/a/b/c/d/e/f/g/h/i/j",
	"..", "../..", "../f", "../../f", "../../home/alice/f", "./home/../f",
}

func TestPathMatchesWebRootPatternsAgreesWithReference(t *testing.T) {
	sets := [][]string{nil, {}}
	for _, g := range webRootMatchGlobs {
		sets = append(sets, []string{g})
	}
	for i := 0; i+2 < len(webRootMatchGlobs); i += 3 {
		sets = append(sets, webRootMatchGlobs[i:i+3])
	}
	sets = append(sets, webRootMatchGlobs)
	for _, patterns := range sets {
		for _, path := range webRootMatchPaths {
			want := referenceWebRootMatch(path, patterns)
			if got := pathMatchesWebRootPatterns(path, patterns); got != want {
				t.Errorf("pathMatchesWebRootPatterns(%q, %q) = %v, reference %v", path, patterns, got, want)
			}
		}
	}
}

func TestPathMatchesWebRootPatternsGlobTableBounds(t *testing.T) {
	// Keep the boundary values explicit: these must exercise both the full
	// stack table and its fallback, with no broad glob hiding a missed entry.
	for _, count := range []int{15, 16, 17, 32} {
		t.Run(fmt.Sprintf("patterns=%d", count), func(t *testing.T) {
			for _, tc := range []struct {
				path string
				glob string
			}{
				{"/home/alice/public_html/index.php", "/home/*"},
				{"/home/alice/public_html/index.php", "/home[/]alice"},
				{"/home/alice/public_html/index.php", "/home[^a]alice"},
				{"/home/alice/public_html/index.php", `/home\/alice`},
				{"/home/alice/public_html/index.php", "/home//*/ignored/../"},
				{"../../home/alice/index.php", "../.."},
				{"/index.php", "/"},
				{"", ""},
			} {
				patterns := make([]string, count)
				for i := range patterns {
					patterns[i] = "/unrelated/["
				}
				check := func(want bool) {
					t.Helper()
					if referenceWebRootMatch(tc.path, patterns) != want {
						t.Fatalf("invalid test case: path=%q patterns=%q want=%v", tc.path, patterns, want)
					}
					if got := pathMatchesWebRootPatterns(tc.path, patterns); got != want {
						t.Fatalf("pathMatchesWebRootPatterns(%q, %q) = %v, want %v", tc.path, patterns, got, want)
					}
				}
				check(false)
				for i := range patterns {
					patterns[i] = tc.glob
					check(true)
					patterns[i] = "/unrelated/["
				}
			}
		})
	}
}

func FuzzPathMatchesWebRootPatterns(f *testing.F) {
	for i, g := range webRootMatchGlobs {
		f.Add(g, webRootMatchPaths[i%len(webRootMatchPaths)])
	}
	for _, count := range []int{16, 17, 32} {
		prefix := strings.Repeat("[\x00", count-1)
		f.Add(prefix+"/home/*", "/home/alice/public_html/index.php")
		f.Add(prefix+"[", "/home/alice/public_html/index.php")
	}
	f.Fuzz(func(t *testing.T, glob, path string) {
		// Retain the unsplit glob so NUL bytes are still tested literally,
		// while the split form lets fuzzing vary the length and order of lists.
		for _, patterns := range [][]string{{glob}, {"/home/*", glob}, strings.Split(glob, "\x00")} {
			want := referenceWebRootMatch(path, patterns)
			if got := pathMatchesWebRootPatterns(path, patterns); got != want {
				t.Fatalf("pathMatchesWebRootPatterns(%q, %q) = %v, reference %v", path, patterns, got, want)
			}
		}
	})
}

// BenchmarkPathMatchesWebRootPatterns measures the account and document root
// tests a watched write goes through, on a path several levels deep.
func BenchmarkPathMatchesWebRootPatterns(b *testing.B) {
	patterns := []string{"/home/*", "/home2/*", "/var/www/vhosts/*/httpdocs"}
	for name, path := range map[string]string{
		"discarded": "/var/lib/mysql/shop/wp_postmeta.ibd",
		"account":   "/home/alice/public_html/wp-content/plugins/woocommerce/includes/class-wc-order.php",
	} {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				pathMatchesWebRootPatterns(path, patterns)
			}
		})
	}
}
