package checks

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// mockOSGlobRoots answers wp-config globs from a fixed filesystem layout.
type mockOSGlobRoots struct {
	mockOS
	files []string
}

func (m *mockOSGlobRoots) Lstat(name string) (os.FileInfo, error) {
	if m.lstat != nil {
		return m.lstat(name)
	}
	for _, file := range m.files {
		if file == name {
			return fakeFileInfo{name: "wp-config.php"}, nil
		}
	}
	return nil, os.ErrNotExist
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
	want := []string{
		"/home/alice/public_html/wp-config.php",
		"/home/alice/shop.example.com/wp-config.php",
		"/home/bob/karmaboutique.ro/wp-config.php",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wp-config paths = %v, want %v", got, want)
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
		"/home/alice/access-logs/wp-config.php",
		"/home/alice/access_logs/wp-config.php",
		"/home/alice/backups/wp-config.php",
		"/home/alice/cgi-bin/wp-config.php",
		"/home/alice/perl5/wp-config.php",
		"/home/alice/spamassassin/wp-config.php",
		"/home/alice/var/wp-config.php",
		"/home/alice/www/wp-config.php",
		"/home/alice/.cpanel/wp-config.php",
		"/home/alice/.trash/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	if got := wpConfigPaths(context.Background()); len(got) != 0 {
		t.Errorf("non-document-root wp-configs discovered: %v", got)
	}
}

// cPanel's domain map is authoritative. A backup directory can contain a
// complete WordPress tree, but it is not served and must not trigger live
// database queries merely because a wp-config.php exists there.
func TestWPConfigPaths_UsesCPanelDocumentRoots(t *testing.T) {
	const vhosts = "example.com: alice==root==main==example.com==/home/alice/public_html\n" +
		"shop.example.com: alice==root==addon==example.com==/home/alice/shop.example.com\n"
	old := osFS
	osFS = &mockOSGlobRoots{
		mockOS: mockOS{
			readFile: func(name string) ([]byte, error) {
				if name == userdataDomainsPath {
					return []byte(vhosts), nil
				}
				return nil, os.ErrNotExist
			},
			lstat: func(name string) (os.FileInfo, error) {
				if strings.HasSuffix(name, "/wp-config.php") {
					return fakeFileInfo{name: "wp-config.php"}, nil
				}
				return nil, os.ErrNotExist
			},
		},
		files: []string{
			"/home/alice/public_html/wp-config.php",
			"/home/alice/shop.example.com/wp-config.php",
			"/home/alice/backups/wp-config.php",
			"/home/bob/public_html/wp-config.php",
		},
	}
	t.Cleanup(func() { osFS = old })

	got := wpConfigPaths(context.Background())
	want := []string{
		"/home/alice/public_html/wp-config.php",
		"/home/alice/shop.example.com/wp-config.php",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wp-config paths = %v, want authoritative roots %v", got, want)
	}
}

func TestWPConfigPaths_RejectsCrossAccountCPanelRoot(t *testing.T) {
	const vhosts = "shop.example.com: alice==root==addon==example.com==/home/bob/shop.example.com\n"
	old := osFS
	osFS = &mockOSGlobRoots{
		mockOS: mockOS{
			readFile: func(name string) ([]byte, error) {
				if name == userdataDomainsPath {
					return []byte(vhosts), nil
				}
				return nil, os.ErrNotExist
			},
			lstat: func(string) (os.FileInfo, error) {
				return fakeFileInfo{name: "wp-config.php"}, nil
			},
		},
		files: []string{"/home/bob/shop.example.com/wp-config.php"},
	}
	t.Cleanup(func() { osFS = old })

	if got := wpConfigPaths(context.Background()); len(got) != 0 {
		t.Errorf("cross-account map root discovered: %v", got)
	}
}

func TestWPConfigPaths_SkipsSpecialConfigFile(t *testing.T) {
	const vhosts = "example.com: alice==root==main==example.com==/home/alice/public_html\n" +
		"shop.example.com: alice==root==addon==example.com==/home/alice/shop.example.com\n"
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipeReader.Close(); _ = pipeWriter.Close() })
	pipeInfo, err := pipeReader.Stat()
	if err != nil {
		t.Fatal(err)
	}

	old := osFS
	osFS = &mockOSGlobRoots{
		mockOS: mockOS{
			readFile: func(name string) ([]byte, error) {
				if name == userdataDomainsPath {
					return []byte(vhosts), nil
				}
				return nil, os.ErrNotExist
			},
			lstat: func(string) (os.FileInfo, error) { return pipeInfo, nil },
		},
		files: []string{
			"/home/alice/public_html/wp-config.php",
			"/home/alice/shop.example.com/wp-config.php",
		},
	}
	t.Cleanup(func() { osFS = old })

	if got := wpConfigPaths(context.Background()); len(got) != 0 {
		t.Errorf("special wp-config.php discovered: %v", got)
	}
}

func TestWPConfigPaths_AcceptsNumberedCPanelHome(t *testing.T) {
	const vhosts = "shop.example.com: alice==root==addon==example.com==/home2/alice/shop.example.com\n"
	old := osFS
	osFS = &mockOSGlobRoots{
		mockOS: mockOS{
			readFile: func(name string) ([]byte, error) {
				if name == userdataDomainsPath {
					return []byte(vhosts), nil
				}
				return nil, os.ErrNotExist
			},
		},
		files: []string{"/home2/alice/shop.example.com/wp-config.php"},
	}
	t.Cleanup(func() { osFS = old })

	got := wpConfigPaths(context.Background())
	want := []string{"/home2/alice/shop.example.com/wp-config.php"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wp-config paths = %v, want numbered-home root %v", got, want)
	}
	if user := wpConfigUser(filepath.Dir(got[0])); user != "alice" {
		t.Errorf("addon root account = %q, want alice", user)
	}
}

func TestWPConfigPaths_EmptyCPanelMapIsIncomplete(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{mockOS: mockOS{readFile: func(name string) ([]byte, error) {
		if name == userdataDomainsPath {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}}}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	if got := wpConfigPaths(ctx); len(got) != 0 {
		t.Fatalf("empty cPanel map returned wp-config paths: %v", got)
	}
	if !incomplete.contains("db_content") {
		t.Fatal("empty cPanel map did not mark the database scan incomplete")
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
