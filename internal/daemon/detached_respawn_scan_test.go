package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A detached shell that keeps coming back queues a scan of its account, which
// quarantines only when auto-response would.
func TestRequestAccountScanFollowsQuarantine(t *testing.T) {
	for _, tc := range []struct {
		quarantineFiles bool
		mode            string
		want            bool
	}{{false, "", false}, {true, "", true}, {true, config.ModeObserve, false}} {
		t.Run(fmt.Sprintf("quarantine_files=%v mode=%q", tc.quarantineFiles, tc.mode), func(t *testing.T) {
			st, _ := openTestScanJobStores(t)
			m, err := NewScanJobManager(st, &config.Config{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(m.Stop)
			m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
				return nil
			}
			cfg := &config.Config{}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = tc.quarantineFiles
			cfg.Mode = tc.mode
			prev := config.Active()
			t.Cleanup(func() { config.SetActive(prev) })
			config.SetActive(cfg)
			d := &Daemon{cfg: cfg, scanJobs: m}
			id, err := d.requestAccountScan("alice")
			if err != nil {
				t.Fatal(err)
			}
			rec, ok := m.Progress(id)
			if !ok || rec.Scope != "account" || rec.Target != "alice" || rec.Options["quarantine"] != tc.want {
				t.Fatalf("job = %+v, want an account scan of alice with quarantine %v", rec, tc.want)
			}
		})
	}
}

// Automatic scans must not inherit manual remediation authority, including
// when the operator changes policy while a scan is running.
func TestRespawnScanUsesAutomaticQuarantine(t *testing.T) {
	for _, mode := range []string{"missing safety state", "observe after enqueue", "disabled after enqueue", "quarantine disabled after enqueue", "enabled after enqueue", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			st, _ := openTestScanJobStores(t)
			cfg := &config.Config{}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.QuarantineFiles = mode != "enabled after enqueue"
			// Each case needs a distinct unavailable state root: refusal
			// notices are deduplicated by state root across the process.
			cfg.StatePath = filepath.Join(t.TempDir(), "unavailable")
			prev := config.Active()
			defer config.SetActive(prev)
			config.SetActive(cfg)
			m, err := NewScanJobManager(st, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Stop()
			path := filepath.Join(t.TempDir(), "evidence.php")
			if writeErr := os.WriteFile(path, []byte("test evidence"), 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			m.runAccountScan = func(context.Context, *config.Config, *state.Store, string, checks.AccountScanOptions) []alert.Finding {
				<-release
				return []alert.Finding{{Check: "webshell", Severity: alert.Critical, FilePath: path}}
			}
			var manual atomic.Int32
			m.quarantineFile = func(alert.Finding) (checks.RemediationResult, bool) {
				manual.Add(1)
				return checks.RemediationResult{Success: true}, true
			}
			d := &Daemon{cfg: cfg, scanJobs: m}
			id, err := d.requestAccountScan("alice")
			if err != nil {
				t.Fatal(err)
			}
			next := *cfg
			want := "done"
			switch mode {
			case "observe after enqueue":
				next.Mode = config.ModeObserve
			case "disabled after enqueue":
				next.AutoResponse.Enabled = false
			case "quarantine disabled after enqueue":
				next.AutoResponse.QuarantineFiles = false
			case "enabled after enqueue":
				next.AutoResponse.QuarantineFiles = true
			case "canceled":
				if err := m.Cancel(id); err != nil {
					t.Fatal(err)
				}
				want = "canceled"
			}
			config.SetActive(&next)
			once.Do(func() { close(release) })
			waitForState(t, m, id, want, 5*time.Second)
			if manual.Load() != 0 {
				t.Fatal("automatic scan used manual quarantine")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("protected evidence changed: %v", err)
			}
			if mode == "missing safety state" || mode == "enabled after enqueue" {
				findings, _, err := m.ListFindings(id, 0, 0)
				if err != nil || len(findings) != 1 || !strings.Contains(findings[0].RemediationDetail, "safety state") {
					t.Fatalf("missing automatic safety refusal: %+v, %v", findings, err)
				}
			}
		})
	}
}
