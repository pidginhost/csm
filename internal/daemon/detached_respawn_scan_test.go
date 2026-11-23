package daemon

import (
	"context"
	"fmt"
	"testing"

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
