package daemon

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

type alertSuppressionBlocker struct {
	blocked map[string]bool
}

func (b *alertSuppressionBlocker) BlockIP(ip string, _ string, _ time.Duration) error {
	b.blocked[ip] = true
	return nil
}

func (b *alertSuppressionBlocker) UnblockIP(ip string) error {
	delete(b.blocked, ip)
	return nil
}

func (b *alertSuppressionBlocker) IsBlocked(ip string) bool {
	return b.blocked[ip]
}

func TestDispatchBatchSuppressesReputationAfterSameBatchBlock(t *testing.T) {
	previousActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(previousActive) })

	previousStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previousStore) })

	previousBlockedIPsFunc := alert.BlockedIPsFunc
	alert.BlockedIPsFunc = nil
	t.Cleanup(func() { alert.BlockedIPsFunc = previousBlockedIPsFunc })

	blocker := &alertSuppressionBlocker{blocked: make(map[string]bool)}
	checks.SetIPBlocker(blocker)
	t.Cleanup(func() { checks.SetIPBlocker(nil) })

	var webhookCalls atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		webhookCalls.Add(1)
	}))
	t.Cleanup(webhook.Close)

	stateDir := t.TempDir()
	// Prevent blocked_ips.json from persisting so this test proves the action
	// finding is present in the slice passed to alert.Dispatch, rather than
	// passing because FilterBlockedAlerts reloads the just-written state file.
	if err := os.Mkdir(filepath.Join(stateDir, "blocked_ips.json"), 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{StatePath: stateDir}
	cfg.Suppressions.SuppressBlockedAlerts = true
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.BlockExpiry = "24h"
	cfg.AutoResponse.MaxBlocksPerHour = 100
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = webhook.URL
	if err := alert.Dispatch(cfg, []alert.Finding{{
		Severity:  alert.Critical,
		Check:     "test_control",
		Message:   "prove webhook delivery is active",
		Timestamp: time.Now(),
	}}); err != nil {
		t.Fatalf("control dispatch: %v", err)
	}
	if got := webhookCalls.Load(); got != 1 {
		t.Fatalf("control webhook calls = %d, want 1", got)
	}
	webhookCalls.Store(0)

	findingState, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = findingState.Close() })

	d := New(cfg, findingState, nil, "")
	d.dispatchBatch([]alert.Finding{{
		Severity:  alert.High,
		Check:     "ip_reputation",
		Message:   "Known malicious IP accessing server: 203.0.113.40",
		SourceIP:  "203.0.113.40",
		Timestamp: time.Now(),
	}})

	if !blocker.IsBlocked("203.0.113.40") {
		t.Fatal("reputation IP was not blocked during the daemon batch")
	}
	if got := webhookCalls.Load(); got != 0 {
		t.Fatalf("webhook calls = %d, want 0 after same-batch live block", got)
	}
}
