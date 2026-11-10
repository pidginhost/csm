package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

func TestWPCronFixRearmsOnlyItsSnapshot(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "resolved", true: "refreshed"}[refresh], func(t *testing.T) {
			d := newTestDaemon(t)
			f := perfWPCronFinding("alice", "/home/alice/public_html/wp-config.php")
			d.store.Update([]alert.Finding{f})
			d.store.SetLatestFindings([]alert.Finding{f})
			defer stubAutoFixWPCron(func(*config.Config, []alert.Finding) ([]alert.Finding, []string) {
				if refresh {
					newer := f
					newer.Timestamp = f.Timestamp.Add(time.Second)
					d.store.SetLatestFindings([]alert.Finding{newer})
				}
				return nil, []string{f.Key()}
			})()
			d.applyWPCronAutoFix(&config.Config{}, []alert.Finding{f})
			wantLatest, wantNew := 0, 1
			if refresh {
				wantLatest, wantNew = 1, 0
			}
			if got := len(d.store.LatestFindings()); got != wantLatest {
				t.Fatalf("latest count=%d, refresh=%v", got, refresh)
			}
			if got := len(d.store.FilterNew([]alert.Finding{f})); got != wantNew {
				t.Fatalf("new count=%d, refresh=%v", got, refresh)
			}
		})
	}
}

func TestPermissionAutoFixRearmsOnReturn(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(map[bool]string{false: "dispatch", true: "initial"}[initial], func(t *testing.T) {
			d := newTestDaemon(t)
			cfg := d.currentCfg()
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.EnforcePermissions = true
			root := t.TempDir()
			t.Cleanup(checks.SetAccountHomeRootsForTest([]string{root}))
			path := filepath.Join(root, "alice", "public_html", "index.php")
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("<?php echo 'test';"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0666); err != nil {
				t.Fatal(err)
			}
			f := alert.Finding{Check: "world_writable_php", Message: "World-writable PHP file: " + path, FilePath: path, Severity: alert.High, Timestamp: time.Now()}
			prior := f
			prior.Timestamp = f.Timestamp.Add(-time.Hour)
			d.store.Update([]alert.Finding{prior})
			d.store.SetLatestFindings([]alert.Finding{prior})
			if initial {
				d.respondToInitialScan(cfg, []alert.Finding{f})
			} else {
				d.dispatchBatch([]alert.Finding{f})
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0644 {
				t.Fatalf("permissions=%o; fix did not run", info.Mode().Perm())
			}
			if len(d.store.LatestFindings()) != 0 {
				t.Fatal("fixed permission finding still listed")
			}
			if len(d.store.FilterNew([]alert.Finding{f})) != 1 {
				t.Fatal("fixed permission finding not rearmed")
			}
		})
	}
}
