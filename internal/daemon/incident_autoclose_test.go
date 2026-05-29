package daemon

import (
	"strconv"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

func TestRunIncidentAutoCloseReportsLiveBacklogOnly(t *testing.T) {
	old := time.Now().Add(-25 * time.Hour)
	cfg := &config.Config{}

	live := incident.NewCorrelator(incident.CorrelatorConfig{})
	live.Restore(staleMailboxIncidents(incidentAutoCloseMaxPerSweep+1, old))
	if more := runIncidentAutoClose(live, cfg); !more {
		t.Fatal("live capped sweep must report remaining stale backlog")
	}
	if resolved, open := countDaemonIncidentStatuses(live.Snapshot()); resolved != incidentAutoCloseMaxPerSweep || open != 1 {
		t.Fatalf("live capped sweep statuses = resolved:%d open:%d, want resolved:%d open:1",
			resolved, open, incidentAutoCloseMaxPerSweep)
	}
	if more := runIncidentAutoClose(live, cfg); more {
		t.Fatal("final live sweep must clear backlog without scheduling fast drain")
	}
	if resolved, open := countDaemonIncidentStatuses(live.Snapshot()); resolved != incidentAutoCloseMaxPerSweep+1 || open != 0 {
		t.Fatalf("final live sweep statuses = resolved:%d open:%d, want resolved:%d open:0",
			resolved, open, incidentAutoCloseMaxPerSweep+1)
	}

	dryRunCfg := &config.Config{}
	dryRunCfg.Incidents.AutoClose.DryRun = true
	dryRun := incident.NewCorrelator(incident.CorrelatorConfig{})
	dryRun.Restore(staleMailboxIncidents(incidentAutoCloseMaxPerSweep+1, old))
	if more := runIncidentAutoClose(dryRun, dryRunCfg); more {
		t.Fatal("dry-run sweep must not report backlog or enter fast drain")
	}
	if resolved, open := countDaemonIncidentStatuses(dryRun.Snapshot()); resolved != 0 || open != incidentAutoCloseMaxPerSweep+1 {
		t.Fatalf("dry-run statuses = resolved:%d open:%d, want resolved:0 open:%d",
			resolved, open, incidentAutoCloseMaxPerSweep+1)
	}
}

func staleMailboxIncidents(count int, at time.Time) []incident.Incident {
	incidents := make([]incident.Incident, 0, count)
	for i := 0; i < count; i++ {
		mailbox := "autoclose" + strconv.Itoa(i)
		incidents = append(incidents, incident.Incident{
			ID:             "inc_autoclose_" + strconv.Itoa(i),
			Kind:           incident.KindMailboxTakeover,
			Status:         incident.StatusOpen,
			Severity:       alert.High,
			Mailbox:        mailbox,
			CorrelationKey: &incident.Key{Mailbox: mailbox},
			CreatedAt:      at,
			UpdatedAt:      at,
		})
	}
	return incidents
}

func countDaemonIncidentStatuses(incidents []incident.Incident) (resolved int, open int) {
	for _, inc := range incidents {
		switch inc.Status {
		case incident.StatusResolved:
			resolved++
		case incident.StatusOpen:
			open++
		}
	}
	return resolved, open
}
