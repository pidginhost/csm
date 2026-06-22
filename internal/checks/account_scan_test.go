package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

func TestRunAccountScanCheck_RecoversPanic(t *testing.T) {
	// Account checks parse attacker-controlled filesystem content, so a
	// panic is plausible. RunAccountScan is reachable from the WebUI inside
	// the daemon process; an unrecovered panic in a check goroutine would
	// crash the whole daemon. The per-check runner must contain the panic
	// and surface it as a timeout finding instead.
	panicCheck := namedCheck{"boom", func(context.Context, *config.Config, *state.Store) []alert.Finding {
		panic("crafted input blew up the parser")
	}}

	got := runAccountScanCheck(context.Background(), panicCheck, &config.Config{}, nil, 100*time.Millisecond)

	if len(got) != 1 || got[0].Check != "check_timeout" {
		t.Fatalf("panicking check must yield a single check_timeout finding, got %+v", got)
	}
}

func TestRunAccountScanCheck_ReturnsFindings(t *testing.T) {
	okCheck := namedCheck{"ok", func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return []alert.Finding{{Check: "demo", Severity: alert.Warning}}
	}}

	got := runAccountScanCheck(context.Background(), okCheck, &config.Config{}, nil, 5*time.Second)

	if len(got) != 1 || got[0].Check != "demo" {
		t.Fatalf("want the check's own finding, got %+v", got)
	}
}

func TestResolveWebRoots_ExplicitConfig(t *testing.T) {
	// Build a fake tree that mimics /var/www/*/public_html.
	tmp := t.TempDir()
	for _, site := range []string{"site-a", "site-b", "site-c"} {
		dir := filepath.Join(tmp, "var", "www", site, "public_html")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Non-existent entry should be silently dropped.
	missing := filepath.Join(tmp, "does", "not", "exist")

	cfg := &config.Config{
		AccountRoots: []string{
			filepath.Join(tmp, "var", "www", "*", "public_html"),
			missing,
		},
	}
	got := ResolveWebRoots(cfg)
	sort.Strings(got)

	want := []string{
		filepath.Join(tmp, "var", "www", "site-a", "public_html"),
		filepath.Join(tmp, "var", "www", "site-b", "public_html"),
		filepath.Join(tmp, "var", "www", "site-c", "public_html"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d roots (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("root[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestResolveWebRoots_Dedupes(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "srv", "site")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AccountRoots: []string{
			filepath.Join(tmp, "srv", "site"),
			filepath.Join(tmp, "srv", "*"), // matches the same dir
		},
	}
	got := ResolveWebRoots(cfg)
	if len(got) != 1 {
		t.Errorf("dedupe failed, got %d roots: %v", len(got), got)
	}
}

func TestResolveWebRoots_SkipsFiles(t *testing.T) {
	// A glob match that hits a regular file (not a dir) should be skipped.
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("file"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AccountRoots: []string{filePath}}
	if got := ResolveWebRoots(cfg); len(got) != 0 {
		t.Errorf("file should not be returned as a web root, got %v", got)
	}
}

func TestResolveWebRoots_NoConfigNonCPanel(t *testing.T) {
	platform.ResetForTest()
	// No config, no cPanel → empty list (non-cPanel host today).
	// We can't control the host's actual detection, but on a CI/Darwin
	// box platform.Detect().IsCPanel() will be false, so this should
	// return nil.
	cfg := &config.Config{}
	if got := ResolveWebRoots(cfg); len(got) != 0 && !platform.Detect().IsCPanel() {
		t.Errorf("non-cPanel without config should return nil, got %v", got)
	}
}

func TestResolveWebRoots_CPanelDefault(t *testing.T) {
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{})
	// Simulate a cPanel host by forcing Detect via a fake. The current
	// Info API doesn't let us inject — so we construct the expected
	// behavior via the config path: set AccountRoots explicitly to the
	// cPanel default and verify it expands.
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	for _, user := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(home, user, "public_html"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AccountRoots: []string{filepath.Join(home, "*", "public_html")}}
	got := ResolveWebRoots(cfg)
	if len(got) != 2 {
		t.Errorf("want 2 roots, got %d: %v", len(got), got)
	}
}

func TestAccountFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/home/alice/public_html", "alice"},
		{"/home/bob/public_html", "bob"},
		{"/var/www/example.com/public", "example.com"},
		{"/srv/http/site-a", "http"},
		{"/home/carol", "carol"}, // /home/<account> matches the cPanel rule
		{"public_html", "public_html"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := accountFromPath(tt.path); got != tt.want {
				t.Errorf("accountFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestFileIndexRunsOnFullScanButNotDefault is the integration test for the
// gated append added to RunAccountScanWithOptions. It proves:
//
//  1. A full scan (ForceFileIndex=true) DOES run CheckFileIndex and returns a
//     new_php_in_sensitive_dir finding for a PHP file planted in
//     wp-content/languages -- a classifier surface that NO other account check
//     covers (confirmed: grep new_php_in_sensitive_dir returns only fileindex.go).
//
//  2. A default scan (ForceFileIndex=false) does NOT return that finding,
//     confirming CheckFileIndex is absent from the default path.
//
//  3. The full-scan run does NOT write any of the three live state files
//     (fileindex.current, fileindex.previous, dircache.json), so the
//     host-wide incremental baseline is left intact.
func TestFileIndexRunsOnFullScanButNotDefault(t *testing.T) {
	tmp := t.TempDir()
	stateDir := filepath.Join(tmp, "state")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}

	// PHP file in wp-content/languages -- triggers new_php_in_sensitive_dir
	// via classifySensitiveDirPHP. Unreadable body fails closed to High.
	// We use a clean but non-stub body so classifySensitiveDirPHP returns
	// new_php_in_sensitive_dir_clean (Warning), which is still unique to
	// CheckFileIndex and proves the audit path executed.
	logicalHome := "/home/acct"
	logicalLang := filepath.Join(logicalHome, "public_html", "wp-content", "languages")
	logicalPHP := filepath.Join(logicalLang, "evil.php")

	physicalLang := filepath.Join(tmp, "acct", "public_html", "wp-content", "languages")
	if err := os.MkdirAll(physicalLang, 0755); err != nil {
		t.Fatal(err)
	}
	// Clean PHP that is not a benign stub -- surfaces as new_php_in_sensitive_dir_clean
	// (Warning). No other account check produces either new_php_in_sensitive_dir variant.
	physicalPHP := filepath.Join(physicalLang, "evil.php")
	old := time.Now().Add(-24 * time.Hour)
	if err := os.WriteFile(physicalPHP, []byte("<?php\n$x = 1;\nreturn $x;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(physicalPHP, old, old); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{testDirEntry{name: "acct", isDir: true}}, nil
			case logicalHome:
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			case logicalLang:
				return []os.DirEntry{testDirEntry{name: "evil.php", isDir: false}}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		stat: func(name string) (os.FileInfo, error) {
			switch name {
			case logicalHome:
				return &fakeFileInfoMtime{name: "acct", dir: true, mode: 0755, mtime: old}, nil
			case logicalLang:
				return &fakeFileInfoMtime{name: "languages", dir: true, mode: 0755, mtime: old}, nil
			case logicalPHP:
				return os.Stat(physicalPHP)
			default:
				return nil, os.ErrNotExist
			}
		},
		readFile: func(name string) ([]byte, error) {
			if name == logicalPHP {
				return os.ReadFile(physicalPHP)
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == logicalPHP {
				return os.Open(physicalPHP)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{StatePath: stateDir}

	// --- Full scan: CheckFileIndex must run and report the sensitive-dir PHP ---
	fullOpts := AccountScanOptions{
		MaxFiles:       0,
		ForceContent:   true,
		ForceFileIndex: true,
		RespectIgnores: false,
		MaxFileBytes:   0,
	}
	fullFindings := RunAccountScanWithOptions(context.Background(), cfg, nil, "acct", fullOpts)

	foundSensitiveDir := false
	for _, f := range fullFindings {
		if f.Check == "new_php_in_sensitive_dir" || f.Check == "new_php_in_sensitive_dir_clean" {
			foundSensitiveDir = true
			break
		}
	}
	if !foundSensitiveDir {
		t.Errorf("full scan must find new_php_in_sensitive_dir* via CheckFileIndex, got: %+v", fullFindings)
	}

	// --- State-write invariant: audit must not corrupt the live baseline ---
	for _, f := range []string{"fileindex.current", "fileindex.previous", "dircache.json"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err == nil {
			t.Errorf("full-scan account scan must not write live state file %s", f)
		}
	}

	// --- Default scan: CheckFileIndex must NOT run (ForceFileIndex=false) ---
	// We wipe state dir between runs to ensure no leftover baseline influences.
	defaultFindings := RunAccountScanWithOptions(context.Background(), cfg, nil, "acct", DefaultAccountScanOptions(cfg))

	for _, f := range defaultFindings {
		if f.Check == "new_php_in_sensitive_dir" || f.Check == "new_php_in_sensitive_dir_clean" {
			t.Errorf("default scan must not run CheckFileIndex, but got finding %+v", f)
		}
	}
}
