package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// Realtime producers (mail geo, sensitive file writes, mail AV degradation)
// hand the daemon findings without a Timestamp. Every path that records or
// dispatches a batch stamps them, so history, incidents and the audit log
// never carry the zero time.
func TestBatchPathsStampMissingTimestamps(t *testing.T) {
	resetIncidentForTest()
	t.Cleanup(resetIncidentForTest)

	previousActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(previousActive) })
	previousStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previousStore) })

	paths := []struct {
		name string
		run  func(d *Daemon, f alert.Finding)
	}{
		{"dispatchBatch", func(d *Daemon, f alert.Finding) { d.dispatchBatch([]alert.Finding{f}) }},
		{"persistPendingFindingsOnShutdown", func(d *Daemon, f alert.Finding) { d.persistPendingFindingsOnShutdown([]alert.Finding{f}) }},
		{"recordAppliedBlocks", func(d *Daemon, f alert.Finding) { d.recordAppliedBlocks([]alert.Finding{f}) }},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			cfg := &config.Config{StatePath: t.TempDir()}
			cfg.Alerts.MaxPerHour = 10
			d := &Daemon{cfg: cfg, store: st}

			before := time.Now().Add(-time.Second)
			tc.run(d, alert.Finding{Severity: alert.High, Check: "email_suspicious_geo", Message: "login from elsewhere"})
			after := time.Now().Add(time.Second)

			hist, _ := st.ReadHistory(10, 0)
			if len(hist) != 1 {
				t.Fatalf("history entries = %d, want 1", len(hist))
			}
			got := hist[0].Timestamp
			if got.IsZero() || got.Before(before) || got.After(after) {
				t.Fatalf("history timestamp %v outside [%v, %v]", got, before, after)
			}
		})
	}
}
