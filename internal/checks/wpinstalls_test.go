package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// wpInstallPaths projects discovered installs to their config paths so a
// failure message names files rather than struct dumps.
func wpInstallPaths(installs []wpInstall) []string {
	out := make([]string, 0, len(installs))
	for _, in := range installs {
		out = append(out, in.ConfigPath)
	}
	return out
}

func hasWPInstallPath(installs []wpInstall, path string) bool {
	for _, in := range installs {
		if in.ConfigPath == path {
			return true
		}
	}
	return false
}

func wpInstallState(installs []wpInstall, path string) servedState {
	for _, in := range installs {
		if in.ConfigPath == path {
			return in.Served
		}
	}
	return servedUnknown
}

func collectorMarked(c *incompleteCheckCollector, name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.names[name]
	return ok
}

// userdataFS answers the domain map from content and globs from files.
func wpUserdataFS(content string, files ...string) *mockOSGlobRoots {
	fs := &mockOSGlobRoots{files: files}
	fs.readFile = func(name string) ([]byte, error) {
		if name == userdataDomainsPath && content != "" {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	}
	return fs
}

// A WordPress install one level under public_html is the exact shape that
// CheckDatabaseContent finds through the panel map and every fixer then fails
// to re-locate, leaving the finding unresolvable for the life of the install.
func TestWPInstalls_FindsNestedUnderPublicHTML(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
		"/home/alice/public_html/blog/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	got := wpInstalls(context.Background(), "db_objects")
	if !hasWPInstallPath(got, "/home/alice/public_html/blog/wp-config.php") {
		t.Errorf("nested install missing from %v", wpInstallPaths(got))
	}
}

// The panel map reaches document roots no home walk can see.
func TestWPInstalls_UsesPanelMappedRootOutsideHomeLayout(t *testing.T) {
	old := osFS
	osFS = wpUserdataFS(
		"shop.example.com: alice==alice==sub==shop.example.com==/home/alice/sites/live\n",
		"/home/alice/sites/live/wp-config.php",
	)
	t.Cleanup(func() { osFS = old })

	got := wpInstalls(context.Background(), "db_objects")
	if !hasWPInstallPath(got, "/home/alice/sites/live/wp-config.php") {
		t.Fatalf("panel-mapped root missing from %v", wpInstallPaths(got))
	}
	if state := wpInstallState(got, "/home/alice/sites/live/wp-config.php"); state != servedByPanel {
		t.Errorf("served state = %v, want servedByPanel", state)
	}
}

// Account data, backups and staging copies are not document roots.
func TestWPInstalls_SkipsNonDocumentRoots(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/mail/wp-config.php",
		"/home/alice/backups/wp-config.php",
		"/home/alice/.trash/wp-config.php",
		"/home/alice/public_html/staging/wp-config.php",
		"/home/alice/public_html/cache/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	if got := wpInstalls(context.Background(), "db_objects"); len(got) != 0 {
		t.Errorf("non-document-root installs discovered: %v", wpInstallPaths(got))
	}
}

// A root absent from the panel map is dormant, not gone: it holds a live
// database. Dropping it would hide the compromise this scan was widened for.
func TestWPInstalls_KeepsUnmappedRootAsNotServed(t *testing.T) {
	old := osFS
	osFS = wpUserdataFS(
		"live.example.com: alice==alice==main==live.example.com==/home/alice/public_html\n",
		"/home/alice/old.example.com/wp-config.php",
	)
	t.Cleanup(func() { osFS = old })

	got := wpInstalls(context.Background(), "db_objects")
	if state := wpInstallState(got, "/home/alice/old.example.com/wp-config.php"); state != notServed {
		t.Errorf("served state = %v, want notServed", state)
	}
}

// An unreadable domain map is not "nothing is served", and the resulting
// coverage gap belongs to the check that asked, not to db_content.
func TestWPInstalls_UnreadableMapMarksCallersGap(t *testing.T) {
	old := osFS
	fs := &mockOSGlobRoots{files: []string{"/home/alice/public_html/wp-config.php"}}
	fs.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	osFS = fs
	t.Cleanup(func() { osFS = old })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	got := wpInstalls(ctx, "wp_core")
	if state := wpInstallState(got, "/home/alice/public_html/wp-config.php"); state != servedUnknown {
		t.Errorf("served state = %v, want servedUnknown", state)
	}
	if !collectorMarked(collector, "wp_core") {
		t.Error("coverage gap not credited to the calling check")
	}
	if collectorMarked(collector, "db_content") {
		t.Error("coverage gap wrongly credited to db_content")
	}
}

// Map and walk find the same file; the panel's declaration wins.
func TestWPInstalls_DedupsKeepingPanelState(t *testing.T) {
	old := osFS
	osFS = wpUserdataFS(
		"live.example.com: alice==alice==main==live.example.com==/home/alice/public_html\n",
		"/home/alice/public_html/wp-config.php",
	)
	t.Cleanup(func() { osFS = old })

	got := wpInstalls(context.Background(), "db_objects")
	if len(got) != 1 {
		t.Fatalf("installs = %v, want one entry", wpInstallPaths(got))
	}
	if got[0].Served != servedByPanel {
		t.Errorf("served state = %v, want servedByPanel", got[0].Served)
	}
	if got[0].Account != "alice" {
		t.Errorf("account = %q, want alice", got[0].Account)
	}
	if got[0].DocRoot != "/home/alice/public_html" {
		t.Errorf("docroot = %q, want /home/alice/public_html", got[0].DocRoot)
	}
}

// The account scope in the context restricts discovery to one account.
func TestWPInstalls_HonoursAccountScope(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
		"/home/bob/public_html/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	ctx := ContextWithAccountScope(context.Background(), "alice")
	got := wpInstalls(ctx, "db_objects")
	if len(got) != 1 || got[0].Account != "alice" {
		t.Errorf("scoped discovery = %v, want alice only", wpInstallPaths(got))
	}
}

func TestWPInstalls_RejectsInvalidAccountScope(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{"/bob/public_html/wp-config.php"}}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	ctx = ContextWithAccountScope(ctx, "../bob")
	if got := wpInstalls(ctx, "db_objects"); len(got) != 0 {
		t.Fatalf("invalid account scope escaped its home: %v", wpInstallPaths(got))
	}
	if !incomplete.contains("db_objects") {
		t.Fatal("invalid account scope did not mark discovery incomplete")
	}
}

// wpInstallsForAccount serves fixers that run outside a scan context and must
// still be restricted to the account whose finding they are acting on.
func TestWPInstallsForAccount_RestrictsToAccount(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
		"/home/bob/public_html/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	got := wpInstallsForAccount(context.Background(), "db_clean", "bob")
	if len(got) != 1 || got[0].Account != "bob" {
		t.Errorf("account discovery = %v, want bob only", wpInstallPaths(got))
	}
}

func TestWPInstalls_UnresolvedAliasMarksGapAndIsNotScanned(t *testing.T) {
	const wpConfig = "/home/alice/www/wp-config.php"
	old := osFS
	osFS = &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/*/wp-config.php" {
				return []string{wpConfig}, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice/www":
				return accountScanFakeInfo{name: "www", mode: os.ModeSymlink}, nil
			case wpConfig:
				return fakeFileInfo{name: "wp-config.php"}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		readlink: func(string) (string, error) { return "", os.ErrPermission },
	}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	if got := wpInstalls(ctx, "db_objects"); len(got) != 0 {
		t.Fatalf("unresolved alias was scanned: %v", wpInstallPaths(got))
	}
	if !incomplete.contains("db_objects") {
		t.Fatal("unresolved alias did not mark discovery incomplete")
	}
}

func TestWPInstalls_RejectsPanelAliasOutsideAccount(t *testing.T) {
	const wpConfig = "/home/alice/www/wp-config.php"
	old := osFS
	osFS = &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte("alice.example: alice==alice==main==alice.example==/home/alice/www\n"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(string) ([]string, error) { return nil, nil },
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice/www":
				return accountScanFakeInfo{name: "www", mode: os.ModeSymlink}, nil
			case wpConfig:
				return fakeFileInfo{name: "wp-config.php"}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		readlink: func(name string) (string, error) {
			if name == "/home/alice/www" {
				return "/home/bob/public_html", nil
			}
			return "", os.ErrNotExist
		},
	}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	ctx = ContextWithAccountScope(ctx, "alice")
	if got := wpInstalls(ctx, "db_objects"); len(got) != 0 {
		t.Fatalf("cross-account panel alias entered alice's scan: %v", wpInstallPaths(got))
	}
	if !incomplete.contains("db_objects") {
		t.Fatal("cross-account panel alias did not mark discovery incomplete")
	}
}

func TestWPInstalls_RejectsAncestorAliasOutsideAccount(t *testing.T) {
	const wpConfig = "/home/alice/public_html/blog/wp-config.php"
	old := osFS
	osFS = &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/*/wp-config.php" {
				return []string{wpConfig}, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice/public_html":
				return accountScanFakeInfo{name: "public_html", mode: os.ModeSymlink}, nil
			case "/home/alice/public_html/blog", "/home/bob/public_html", wpConfig:
				if name == wpConfig {
					return fakeFileInfo{name: "wp-config.php"}, nil
				}
				return accountScanFakeInfo{name: filepath.Base(name), mode: os.ModeDir | 0o755, isDir: true}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		readlink: func(name string) (string, error) {
			if name == "/home/alice/public_html" {
				return "/home/bob/public_html", nil
			}
			return "", os.ErrNotExist
		},
	}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	if got := wpInstalls(ctx, "db_objects"); len(got) != 0 {
		t.Fatalf("ancestor alias crossed account boundary: %v", wpInstallPaths(got))
	}
	if !incomplete.contains("db_objects") {
		t.Fatal("rejected ancestor alias did not mark discovery incomplete")
	}
}

func TestWPInstalls_RejectsScopedPrimaryAliasOutsideAccount(t *testing.T) {
	const wpConfig = "/home/alice/public_html/wp-config.php"
	old := osFS
	osFS = &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice" {
				return accountScanFakeInfo{name: "alice", mode: os.ModeDir | 0o755, isDir: true}, nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice/public_html":
				return accountScanFakeInfo{name: "public_html", mode: os.ModeSymlink}, nil
			case wpConfig:
				return fakeFileInfo{name: "wp-config.php"}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		readlink: func(name string) (string, error) {
			if name == "/home/alice/public_html" {
				return "/home/bob/public_html", nil
			}
			return "", os.ErrNotExist
		},
	}
	t.Cleanup(func() { osFS = old })

	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	ctx = ContextWithAccountScope(ctx, "alice")
	if got := wpInstalls(ctx, "db_objects"); len(got) != 0 {
		t.Fatalf("scoped primary alias crossed account boundary: %v", wpInstallPaths(got))
	}
	if !incomplete.contains("db_objects") {
		t.Fatal("rejected scoped primary alias did not mark discovery incomplete")
	}
}

func TestWPInstalls_CanonicalizesAliasInNumberedCPanelHome(t *testing.T) {
	const (
		alias  = "/home2/alice/www/wp-config.php"
		target = "/home2/alice/public_html/wp-config.php"
	)
	old := osFS
	osFS = &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte("alice.example: alice==alice==main==alice.example==/home2/alice/www\n"), nil
			}
			return nil, os.ErrNotExist
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home2/alice/www":
				return accountScanFakeInfo{name: "www", mode: os.ModeSymlink}, nil
			case "/home2/alice/public_html":
				return accountScanFakeInfo{name: "public_html", mode: os.ModeDir | 0o755, isDir: true}, nil
			case target:
				return fakeFileInfo{name: "wp-config.php"}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		readlink: func(name string) (string, error) {
			if name == filepath.Dir(alias) {
				return "public_html", nil
			}
			return "", os.ErrNotExist
		},
	}
	t.Cleanup(func() { osFS = old })

	got := wpInstalls(context.Background(), "db_objects")
	if len(got) != 1 || got[0].ConfigPath != target {
		t.Fatalf("numbered-home alias was not canonicalized: %v", wpInstallPaths(got))
	}
}

func TestWPInstalls_CanonicalizesPanelAliasBeforeDedup(t *testing.T) {
	const (
		alias  = "/home/alice/www/wp-config.php"
		target = "/home/alice/public_html/wp-config.php"
	)
	old := osFS
	osFS = &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte("alice.example: alice==alice==main==alice.example==/home/alice/www\n"), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/*/public_html/wp-config.php":
				return []string{target}, nil
			case "/home/*/*/wp-config.php":
				return []string{alias}, nil
			default:
				return nil, nil
			}
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home/alice/www":
				return accountScanFakeInfo{name: "www", mode: os.ModeSymlink}, nil
			case "/home/alice/public_html":
				return accountScanFakeInfo{name: "public_html", mode: os.ModeDir | 0o755, isDir: true}, nil
			case alias, target:
				return fakeFileInfo{name: "wp-config.php"}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		readlink: func(name string) (string, error) {
			if name == "/home/alice/www" {
				return "public_html", nil
			}
			return "", os.ErrNotExist
		},
	}
	t.Cleanup(func() { osFS = old })

	got := wpInstalls(context.Background(), "db_objects")
	if len(got) != 1 || got[0].ConfigPath != target {
		t.Fatalf("panel alias was not deduplicated: %v", wpInstallPaths(got))
	}
	if got[0].Served != servedByPanel {
		t.Fatalf("canonical install state = %v, want servedByPanel", got[0].Served)
	}
}

// A symlinked wp-config.php is refused, not scanned: wp-cli runs as root and
// follows the link, so an account aiming its config at another account's would
// have that tenant's database inventoried under its own name. Discovery drops
// the install and records the gap so nothing is silently retired.
func TestWPInstalls_RefusesSymlinkedConfigAndMarksGap(t *testing.T) {
	const wpConfig = "/home/alice/public_html/wp-config.php"
	old := osFS
	osFS = &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/home/*/public_html/wp-config.php" {
				return []string{wpConfig}, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case filepath.Dir(wpConfig):
				return accountScanFakeInfo{name: "public_html", mode: os.ModeDir | 0o755, isDir: true}, nil
			case wpConfig:
				return accountScanFakeInfo{name: "wp-config.php", mode: os.ModeSymlink}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
	}
	t.Cleanup(func() { osFS = old })

	ctx, collector := withIncompleteCheckCollector(context.Background())
	if got := wpInstalls(ctx, "wp_core"); len(got) != 0 {
		t.Fatalf("symlinked wp-config.php entered discovery: %v", wpInstallPaths(got))
	}
	if !collectorMarked(collector, "wp_core") {
		t.Error("refused install did not record a coverage gap")
	}
}

func TestWPInstalls_DoesNotSkipDirectoryWithBackupPrefix(t *testing.T) {
	const wpConfig = "/home/alice/backup-shop.example/wp-config.php"
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{wpConfig}}
	t.Cleanup(func() { osFS = old })

	got := wpInstalls(context.Background(), "db_objects")
	if len(got) != 1 || got[0].ConfigPath != wpConfig {
		t.Fatalf("ordinary document root with backup prefix was skipped: %v", wpInstallPaths(got))
	}
}

func TestWPInstalls_DoesNotTreatAccountNameAsSkippedDirectory(t *testing.T) {
	for _, account := range []string{"backup", "backups", "cache", "staging"} {
		t.Run(account, func(t *testing.T) {
			wpConfig := filepath.Join("/home", account, "public_html", "wp-config.php")
			old := osFS
			osFS = &mockOSGlobRoots{files: []string{wpConfig}}
			t.Cleanup(func() { osFS = old })

			got := wpInstalls(context.Background(), "db_objects")
			if len(got) != 1 || got[0].ConfigPath != wpConfig {
				t.Fatalf("account name excluded its WordPress install: %v", wpInstallPaths(got))
			}
		})
	}
}
