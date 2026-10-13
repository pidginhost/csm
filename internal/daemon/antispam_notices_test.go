package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

const antispamScanOKLine = `2026-10-13 09:00:01 1xF5ol-00000000SdL-2TMA CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`

func TestAntispamDismissalRearmsBetweenProbes(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	usePing(t, nil)
	cfg := d.currentCfg()
	now := time.Now()
	first := d.handleEximLine(scanErrorLine, alert.Observation{ObservedAt: now}, cfg)
	d.dispatchBatch(first)
	d.probeAntispam(context.Background(), now)
	if len(first) != 1 {
		t.Fatalf("first scan failure: %+v", first)
	}
	dismissed := false
	for _, f := range d.store.LatestFindings() {
		if f.Check == reconcile.CheckScanError {
			dismissed = d.store.DismissFindingIfLatest(f)
		}
	}
	if !dismissed {
		t.Fatal("could not dismiss the first episode")
	}

	// Both messages arrive before the next probe can observe recovery.
	d.handleEximLine(antispamScanOKLine, alert.Observation{ObservedAt: now.Add(time.Second)}, cfg)
	second := d.handleEximLine(scanErrorLine, alert.Observation{ObservedAt: now.Add(2 * time.Second)}, cfg)
	if len(second) != 1 || len(d.store.FilterNew(second)) != 1 {
		t.Fatalf("dismissal silenced a new episode between probes: %+v", second)
	}
}

func TestAntispamStartupRearmsOldDismissals(t *testing.T) {
	usePanel(t, platform.PanelCPanel)
	passes := useAntispamHost(t)
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	scan := alert.Finding{Check: reconcile.CheckScanError, DedupKey: "scan"}
	unrelated := alert.Finding{Check: "other", DedupKey: "condition"}
	d.store.SetBaseline([]alert.Finding{scan, unrelated})
	stop := antispamTestShutdown(t, d)
	d.startAntispam()
	waitPass(t, passes)
	stop()
	if got := d.store.FilterNew([]alert.Finding{scan, unrelated}); len(got) != 1 || got[0].Key() != scan.Key() {
		t.Fatalf("startup rearmed %+v, want only the old scan-error dismissal", got)
	}
}

func TestAntispamActiveDismissalSurvivesHealthUpdates(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	usePing(t, nil, nil, nil)
	now := time.Now()
	first := d.handleEximLine(scanErrorLine, alert.Observation{ObservedAt: now}, d.currentCfg())
	d.dispatchBatch(first)
	d.probeAntispam(context.Background(), now)
	if len(first) != 1 {
		t.Fatalf("first scan failure: %+v", first)
	}
	for _, f := range d.store.LatestFindings() {
		if f.Check == reconcile.CheckScanError && !d.store.DismissFindingIfLatest(f) {
			t.Fatal("could not dismiss the active failure")
		}
	}
	assertDismissed := func() {
		t.Helper()
		entry, ok := d.store.EntryForKey(first[0].Key())
		if !ok || !entry.IsBaseline {
			t.Fatal("health update rearmed a still-active failure")
		}
	}
	assertDismissed()
	for _, line := range []string{antispamScanOKLine + " forged", scanErrorLine} {
		d.handleEximLine(line, alert.Observation{ObservedAt: now.Add(time.Second)}, d.currentCfg())
		d.probeAntispam(context.Background(), now.Add(2*time.Second))
		assertDismissed()
	}
	cfg := *d.currentCfg()
	cfg.EmailProtection.Antispam.RspamdSocket = "/run/rspamd/other.sock"
	config.SetActive(&cfg)
	d.syncAntispamHealth()
	assertDismissed()
}

func TestAntispamHealthNoticesHonorSuppressions(t *testing.T) {
	for _, check := range []string{reconcile.CheckRspamdDown, reconcile.CheckRspamdRecovered} {
		t.Run(check, func(t *testing.T) {
			var posts atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { posts.Add(1) }))
			t.Cleanup(srv.Close)
			d := newTestDaemon(t)
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.Alerts.MaxPerHour = 1
			cfg.Alerts.Webhook.Enabled = true
			cfg.Alerts.Webhook.URL = srv.URL
			useActiveConfig(t, cfg)
			if err := d.store.SaveSuppressions([]state.SuppressionRule{{Check: check}}); err != nil {
				t.Fatal(err)
			}
			previous := alert.FindingBus
			observer := &scanJobDispatchObserver{}
			alert.FindingBus = observer
			t.Cleanup(func() { alert.FindingBus = previous })
			finding := alert.Finding{Check: check, Severity: alert.Warning, Message: "rspamd health changed", Timestamp: time.Now()}
			d.reportAntispamHealth([]alert.Finding{finding})
			if got := posts.Load(); got != 0 {
				t.Errorf("suppressed notice sent %d webhook requests", got)
			}
			if got := observer.calls.Load(); got != 1 {
				t.Errorf("suppression hid health from the event stream: %d events", got)
			}
			history, _ := d.store.ReadHistory(10, 0)
			if len(history) != 1 || history[0].Check != check {
				t.Errorf("suppression hid health history: %+v", history)
			}
			if err := d.store.SaveSuppressions(nil); err != nil {
				t.Fatal(err)
			}
			d.reportAntispamHealth([]alert.Finding{finding})
			if got := posts.Load(); got != 1 {
				t.Errorf("unmuted notice sent %d webhook requests, want 1", got)
			}
			if err := alert.Dispatch(cfg, []alert.Finding{{Check: "routine", Severity: alert.Warning, Message: "routine alert"}}); err != nil {
				t.Fatal(err)
			}
			if got := posts.Load(); got != 2 {
				t.Errorf("notice spent the routine budget: %d requests, want 2", got)
			}
		})
	}
}
