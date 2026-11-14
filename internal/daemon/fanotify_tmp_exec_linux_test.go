//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Configuration basenames must not hide an executable from the temp check,
// including names recovered from an editor's atomic-save staging file.
func TestTmpExecutableConfigNames(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned executable; run through scripts/go-linux.sh")
	}
	oldWindow, oldAncestry, oldRoots := tmpExecPkgWindow, tmpExecAncestry, panelToolRoots
	t.Cleanup(func() {
		tmpExecPkgWindow, tmpExecAncestry, panelToolRoots = oldWindow, oldAncestry, oldRoots
	})
	panelToolRoots = func() []string { return nil }
	tmpExecAncestry = func(int32) ancestryEvidence { return ancestryEvidence{packageManager: true} }
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		t.Run(root, func(t *testing.T) {
			t.Setenv("TMPDIR", root)
			dir := t.TempDir()
			for _, name := range []string{".htaccess", ".user.ini", "php.ini", ".temp.123..htaccess", ".temp.123..user.ini", ".temp.123.php.ini"} {
				for _, maintenance := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/maintenance=%v", name, maintenance), func(t *testing.T) {
						tmpExecPkgWindow = func(time.Time) bool { return maintenance }
						path := filepath.Join(dir, name)
						if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
							t.Fatal(err)
						}
						fd := openRawFd(t, path)
						ch := make(chan alert.Finding, 4)
						fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
						event, admitted := fm.classifyEvent(path, fd)
						if !admitted {
							t.Fatal("executable was not admitted")
						}
						event.pid = 4242
						fm.analyzeFile(event)
						findings := drainFindings(ch)
						if len(findings) != 1 {
							t.Fatalf("findings = %+v, want exactly one", findings)
						}
						want := alert.Critical
						if maintenance {
							want = alert.Warning
						}
						got := findings[0]
						if got.Check != "executable_in_tmp_realtime" || got.FilePath != path || got.Severity != want {
							t.Fatalf("finding = %+v, want temp executable at %s with severity %v", got, path, want)
						}
						if strings.Contains(got.Details, "[demoted:") != maintenance {
							t.Errorf("incorrect provenance annotation: %s", got.Details)
						}
						if err := os.Chmod(path, 0o644); err != nil {
							t.Fatal(err)
						}
						fm = &FileMonitor{cfg: &config.Config{}, alertCh: ch}
						fm.analyzeFile(event)
						if got := drainFindings(ch); len(got) != 0 {
							t.Fatalf("non-executable configuration raised findings: %+v", got)
						}
						if err := os.Chmod(path, 0o755); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		})
	}
}

// An initramfs-sized burst uses per-file dedup and the shared bounded ingest
// queue. This pins loss accounting without hiding maintenance executables.
func TestTmpExecutableBurstAccounting(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	dir := filepath.Join(t.TempDir(), "dracut.work")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 500)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: ch}
	for i := 0; i < 600; i++ {
		path := filepath.Join(dir, fmt.Sprintf("tool%d", i))
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		fm.analyzeFile(fileEvent{path: path, fd: int(f.Fd())})
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(ch) != 500 || atomic.LoadInt64(&fm.droppedAlerts) != 100 {
		t.Fatalf("queued = %d, dropped = %d; want 500 and 100", len(ch), atomic.LoadInt64(&fm.droppedAlerts))
	}
	entries := 0
	fm.alertDedup.Range(func(_, _ any) bool { entries++; return true })
	if entries != 600 {
		t.Fatalf("dedup entries = %d, want 600 including dropped findings", entries)
	}
	for _, got := range drainFindings(ch) {
		if got.Check != "executable_in_tmp_realtime" || got.Severity != alert.Critical {
			t.Fatalf("unexpected burst finding: %+v", got)
		}
	}
}

func TestTmpExecutableConfigContentAndSuppression(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	for _, tc := range []struct {
		name, body string
		checks     []string
	}{
		{".htaccess", "php_value auto_prepend_file /tmp/payload.php\n", []string{"executable_in_tmp_realtime", "htaccess_injection_realtime", "htaccess_auto_prepend"}},
		{".user.ini", "allow_url_include = On\n", []string{"executable_in_tmp_realtime", "php_config_realtime"}},
		{"php.ini", "allow_url_include = On\n", []string{"executable_in_tmp_realtime", "php_config_realtime"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, []byte(tc.body), 0o755); err != nil {
				t.Fatal(err)
			}
			fd := openRawFd(t, path)
			ch := make(chan alert.Finding, 4)
			cfg := &config.Config{}
			fm := &FileMonitor{cfg: cfg, alertCh: ch}
			fm.analyzeFile(fileEvent{path: path, fd: fd})
			findings := drainFindings(ch)
			var gotChecks []string
			for _, finding := range findings {
				gotChecks = append(gotChecks, finding.Check)
			}
			if !reflect.DeepEqual(gotChecks, tc.checks) {
				t.Fatalf("checks = %v, want %v", gotChecks, tc.checks)
			}
			cfg.Suppressions.IgnorePaths = []string{path}
			fm = &FileMonitor{cfg: cfg, alertCh: ch}
			fm.analyzeFile(fileEvent{path: path, fd: fd})
			if got := drainFindings(ch); len(got) != 0 {
				t.Fatalf("operator suppression ignored: %+v", got)
			}
		})
	}
}
