package daemon

import (
	"context"
	"os"
	"path/filepath"
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

// Design C7: the owner's live start reads legacy blocking's state from the
// daemon's state directory.
func TestAdmissionOptionsReadTheLegacyHandover(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 4, 14, 20, 0, 0, time.UTC)
	body := `{"ips":[],"pending":[{"ip":"192.0.2.1","reason":"r"}],"blocks_this_hour":2,"hour_key":"2026-10-04T14"}`
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := (&Daemon{cfg: &config.Config{StatePath: dir}}).admissionOptions(nil)
	h, err := opts.LegacyHandover(opts.StatePath, now)
	if err != nil || h.Pending != 1 || h.Spend.Units != 2 {
		t.Fatalf("handover = %+v, %v", h, err)
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
	previousOwnership := ownerKeepsDryRunExamples.Load()
	t.Cleanup(func() { ownerKeepsDryRunExamples.Store(previousOwnership) })
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

// Startup publishes the policy before starting admission. A live firewall
// host must leave old examples for the owner's bounded purge even if the
// owner cannot open its ledger yet.
func TestStartupPublicationLeavesForecastExamplesToOwner(t *testing.T) {
	for _, tc := range []struct {
		name     string
		firewall bool
		observe  bool
		failed   bool
	}{
		{name: "forecast owner", firewall: true},
		{name: "failed forecast owner", firewall: true, failed: true},
		{name: "firewall disabled"},
		{name: "observe mode", firewall: true, observe: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			db, restore := openTestBoltStore(t, dir)
			defer restore()
			previousConfig := config.Active()
			previousOwnership := ownerKeepsDryRunExamples.Swap(false)
			t.Cleanup(func() {
				config.SetActive(previousConfig)
				ownerKeepsDryRunExamples.Store(previousOwnership)
			})
			cfg, err := config.LoadBytes([]byte("auto_response:\n  dry_run: false\n"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.StatePath = dir
			cfg.Firewall.Enabled = tc.firewall
			if tc.observe {
				cfg.Mode = "observe"
			}
			db.RecordDryRunBlock("198.51.100.63", "CSM auto-block: ftp_bruteforce", time.Hour)
			if got := db.DryRunBlocksCount(); got != 1 {
				t.Fatalf("seeded examples = %d, want 1", got)
			}
			publishActiveConfig(cfg, "startup")
			want := 0
			if tc.firewall && !tc.observe {
				want = 1
			}
			if got := db.DryRunBlocksCount(); got != want {
				t.Fatalf("examples after startup publication = %d, want %d", got, want)
			}
			if want == 0 {
				return
			}
			d := New(cfg, nil, nil, "")
			opts := testAdmissionOptions(d, db)
			if tc.failed {
				opts.DB = nil
			} else {
				opts.ScheduleEvery = time.Millisecond
			}
			d.startAdmissionWith(opts)
			defer d.stopAdmission()
			if !ownerKeepsDryRunExamples.Load() {
				t.Fatal("the forecast owner did not take example ownership")
			}
			if tc.failed {
				if status := d.AdmissionStatus(); status.Owner.Error == "" {
					t.Fatal("the unavailable ledger was not reported")
				}
				publishActiveConfig(cfg, "reload")
				if got := db.DryRunBlocksCount(); got != 1 {
					t.Fatalf("examples while the owner retries = %d, want 1", got)
				}
				return
			}
			deadline := time.Now().Add(5 * time.Second)
			for db.DryRunBlocksCount() != 0 {
				if time.Now().After(deadline) {
					t.Fatal("the owner never purged examples from the previous dry run")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
