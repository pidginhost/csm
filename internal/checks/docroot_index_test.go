package checks

import (
	"strconv"
	"testing"
)

func TestDocrootIndexLookup(t *testing.T) {
	docroots := []string{
		"/home/alice/public_html",
		"/home/alice/public_html/sub.example.com",
		"/home/bob/public_html",
	}
	cases := []struct {
		name string
		path string
		want string
	}{
		{"inside primary docroot", "/home/alice/public_html/wp-content/plugins/x/x.php", "/home/alice/public_html"},
		{"longest docroot wins for addon subdir", "/home/alice/public_html/sub.example.com/a.php", "/home/alice/public_html/sub.example.com"},
		{"outside any docroot", "/home/alice/mail/x.php", ""},
		{"sibling dir sharing docroot prefix", "/home/alice/public_html_old/x.php", ""},
		{"path equal to docroot is not under it", "/home/bob/public_html", ""},
		{"other account docroot", "/home/bob/public_html/index.php", "/home/bob/public_html"},
		{"unclean event path", "/home/bob/public_html/a/../index.php", "/home/bob/public_html"},
		{"relative event path", "home/bob/public_html/index.php", ""},
		{"filesystem root", "/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewDocrootIndex(docroots).Lookup(tc.path); got != tc.want {
				t.Errorf("lookup(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}

	t.Run("root directory as docroot", func(t *testing.T) {
		idx := NewDocrootIndex([]string{"/"})
		if got := idx.Lookup("/srv/index.php"); got != "/" {
			t.Fatalf("lookup() = %q, want /", got)
		}
		if got := idx.Lookup("/"); got != "" {
			t.Fatalf("lookup(/) = %q, want empty", got)
		}
	})

	t.Run("no docroots", func(t *testing.T) {
		var missing *DocrootIndex
		if got := missing.Lookup("/home/bob/public_html/index.php"); got != "" {
			t.Fatalf("nil index lookup = %q", got)
		}
	})

	t.Run("normalizes configured roots", func(t *testing.T) {
		idx := NewDocrootIndex([]string{"relative/public_html", "/home/carol/public_html/"})
		got := idx.Lookup("/home/carol/public_html/index.php")
		if got != "/home/carol/public_html" {
			t.Fatalf("lookup() = %q, want normalized absolute root", got)
		}
	})
}

// manyDocroots models a shared host: every account has a primary
// docroot plus addon domains, so the list runs to hundreds of entries.
func manyDocroots(n int) []string {
	roots := make([]string, 0, n)
	for i := 0; len(roots) < n; i++ {
		home := "/home/user" + strconv.Itoa(i)
		roots = append(roots, home+"/public_html", home+"/public_html/addon.example.com")
	}
	return roots[:n]
}

// The lookup runs on every fanotify event and process start, so its cost must
// not grow with the number of docroots on the host.
func TestDocrootLookupDoesNotAllocate(t *testing.T) {
	idx := NewDocrootIndex(manyDocroots(600))
	for _, path := range []string{
		"/home/user42/public_html/addon.example.com/wp-content/uploads/x.php",
		"/home/user42/mail/new/1700000000.M1.host",
		"/tmp/php-upload-x",
	} {
		allocs := testing.AllocsPerRun(100, func() {
			_ = idx.Lookup(path)
		})
		if allocs != 0 {
			t.Errorf("lookup of %q allocated %.0f times per event", path, allocs)
		}
	}
}

func BenchmarkDocrootLookup(b *testing.B) {
	idx := NewDocrootIndex(manyDocroots(600))
	path := "/home/user42/public_html/wp-content/plugins/x/x.php"
	b.ReportAllocs()
	for b.Loop() {
		_ = idx.Lookup(path)
	}
}
