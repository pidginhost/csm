package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// Without a firewall, or in observe mode, the owner stays comparison-only:
// it previews and never reads an execution policy.
func TestAdmissionOwnerPreviewsWithoutAFirewall(t *testing.T) {
	observe := &config.Config{Firewall: &firewall.FirewallConfig{Enabled: true}}
	observe.Mode = "observe"
	for name, cfg := range map[string]*config.Config{
		"no firewall section": {},
		"firewall off":        {Firewall: &firewall.FirewallConfig{}},
		"observe mode":        observe,
	} {
		d := &Daemon{cfg: cfg}
		if d.admissionOptions(nil).Blocks != nil {
			t.Errorf("%s: the owner got an engine provider", name)
		}
	}
}

// Spec 3.6: while an admission owner keeps the dry_run_blocks bucket, the
// legacy engine's dry-run recorder writes nothing to it; without one it
// records as before.
func TestLegacyDryRunRecorderLeavesAnOwnedBucket(t *testing.T) {
	db, restore := openTestBoltStore(t, t.TempDir())
	defer restore()
	t.Cleanup(func() { ownerKeepsDryRunExamples.Store(false) })
	ownerKeepsDryRunExamples.Store(true)
	recordLegacyDryRunBlock("198.51.100.60", "CSM auto-block: ftp_bruteforce", time.Hour)
	if got := db.DryRunBlocksCount(); got != 0 {
		t.Fatalf("dry_run_blocks under an owner = %d, want 0", got)
	}
	ownerKeepsDryRunExamples.Store(false)
	recordLegacyDryRunBlock("198.51.100.61", "CSM auto-block: ftp_bruteforce", time.Hour)
	if got := db.DryRunBlocksCount(); got != 1 {
		t.Fatalf("dry_run_blocks without an owner = %d, want 1", got)
	}
}

// Spec 3.8: the owner's dry-run summary is recorded in history only; a
// delivery cancelled before its write records nothing and says so.
func TestAdmissionSummaryGoesToHistory(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	d := New(&config.Config{StatePath: dir}, st, nil, "")
	previousHook := alert.CentralHook
	dispatched := 0
	alert.SetCentralHook(func(alert.Finding) { dispatched++ })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	d.alertCh = make(chan alert.Finding, 1)
	deliver := d.admissionOptions(nil).DeliverSummary
	if deliver == nil {
		t.Fatal("no summary sink")
	}
	f := alert.Finding{Severity: alert.Warning, Check: "auto_block", Message: "Dry-run capacity forecast: 3 responses passed modelled capacity checks", Timestamp: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := deliver(ctx, f); err == nil || db.HistoryCount() != 0 {
		t.Fatalf("a cancelled delivery = %v, history %d", err, db.HistoryCount())
	}
	if err := deliver(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if dispatched != 0 || len(d.alertCh) != 0 {
		t.Fatalf("summary escaped history: dispatch=%d feedback=%d", dispatched, len(d.alertCh))
	}
	if got, _ := db.ReadHistory(10, 0); len(got) != 1 || got[0].Message != f.Message {
		t.Fatalf("history = %+v", got)
	}
}

// A failed forecasting owner keeps ownership. Its storage error must not
// silently restart the legacy writer alongside an owner retry.
func TestFailedForecastOwnerKeepsExampleOwnership(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	previous := config.Active()
	t.Cleanup(func() { config.SetActive(previous) })
	cfg := publishTestConfig(t, "firewall:\n  enabled: true\nauto_response:\n  dry_run: true\n")
	cfg.StatePath = dir
	d := New(cfg, st, nil, "")
	opts := testAdmissionOptions(d, nil)
	d.startAdmissionWith(opts)
	defer d.stopAdmission()
	if status := d.AdmissionStatus(); status.Owner.Error == "" || !ownerKeepsDryRunExamples.Load() {
		t.Fatalf("failed owner lost ownership: %+v", status)
	}
	recordLegacyDryRunBlock("198.51.100.62", "CSM auto-block: ftp_bruteforce", time.Hour)
	if db.DryRunBlocksCount() != 0 {
		t.Fatal("failed owner reactivated the legacy example writer")
	}
}
