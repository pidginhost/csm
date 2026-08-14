package checks

import (
	"context"
	"strings"
	"testing"
)

// mockOSGlobRoots answers wp-config globs from a fixed filesystem layout.
type mockOSGlobRoots struct {
	mockOS
	files []string
}

func (m *mockOSGlobRoots) Glob(pattern string) ([]string, error) {
	// Two path segments between /home/<user>/ and the file means one
	// directory level; matching is good enough for the patterns under test.
	var out []string
	for _, f := range m.files {
		if globMatchesTest(pattern, f) {
			out = append(out, f)
		}
	}
	return out, nil
}

// globMatchesTest is a minimal stand-in for filepath.Match over full paths.
func globMatchesTest(pattern, path string) bool {
	pp := strings.Split(pattern, "/")
	fp := strings.Split(path, "/")
	if len(pp) != len(fp) {
		return false
	}
	for i := range pp {
		if pp[i] != "*" && pp[i] != fp[i] {
			return false
		}
	}
	return true
}

// A production compromise sat in an addon-domain root for months. The database
// scan only globbed public_html, so that install was never read at all.
func TestWPConfigPaths_IncludesAddonDomainRoots(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
		"/home/alice/shop.example.com/wp-config.php",
		"/home/bob/karmaboutique.ro/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	got := wpConfigPaths(context.Background())
	for _, want := range []string{
		"/home/alice/public_html/wp-config.php",
		"/home/alice/shop.example.com/wp-config.php",
		"/home/bob/karmaboutique.ro/wp-config.php",
	} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("wp-config not discovered: %s (got %v)", want, got)
		}
	}
}

// Mail spools and account metadata are not document roots. Reading a
// wp-config out of them would scan a database the site does not serve.
func TestWPConfigPaths_SkipsNonDocumentRoots(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/mail/wp-config.php",
		"/home/alice/etc/wp-config.php",
		"/home/alice/logs/wp-config.php",
		"/home/alice/tmp/wp-config.php",
		"/home/alice/ssl/wp-config.php",
		"/home/alice/.trash/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	if got := wpConfigPaths(context.Background()); len(got) != 0 {
		t.Errorf("non-document-root wp-configs discovered: %v", got)
	}
}

// public_html appears in both globs; it must be read once.
func TestWPConfigPaths_DoesNotDuplicatePublicHTML(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}}
	t.Cleanup(func() { osFS = old })

	if got := wpConfigPaths(context.Background()); len(got) != 1 {
		t.Errorf("public_html wp-config returned %d times: %v", len(got), got)
	}
}
