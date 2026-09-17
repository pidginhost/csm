package incident_test

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
)

func TestBinaryConfigTamperUsesHostIncidentIdentity(t *testing.T) {
	// Startup and periodic binary/config verification emit no tenant or IP.
	// Losing host classification gives this Critical finding an empty key.
	finding := alert.Finding{Check: "integrity", Severity: alert.Critical}
	if got := incident.ClassifyKind(finding); got != incident.KindHostIntegrityRisk {
		t.Errorf("binary/config tamper kind = %s, want host_integrity_risk", got)
	}
	if got := incident.KeyFor(finding); got != (incident.Key{Host: "host"}) {
		t.Errorf("binary/config tamper key = %+v, want the local host", got)
	}
}

func TestBinaryConfigTamperOpensAndJoinsHostIncident(t *testing.T) {
	blocks := 0
	c := incident.NewCorrelator(incident.CorrelatorConfig{
		OpenThreshold: 3,
		AutoBlock: incident.IncidentAutoBlockConfig{
			Enabled: true, BlockAtSeverity: "high",
		},
		OnIncidentBlock: func(_, _ string, _ time.Duration, _ string) bool { blocks++; return true },
	})
	f := alert.Finding{Check: "integrity", Severity: alert.Critical, Message: "Binary changed", Timestamp: time.Now()}
	id, created, err := c.OnFinding(f)
	if err != nil || !created || id == "" {
		t.Fatalf("binary tamper failed to open an incident: id=%q created=%v err=%v", id, created, err)
	}
	f.Check, f.Message = "shadow_change", "Host credential store changed"
	mergedID, created, err := c.OnFinding(f)
	if err != nil || created || mergedID != id {
		t.Fatalf("host evidence did not merge: id=%q created=%v err=%v", mergedID, created, err)
	}
	inc, ok := c.Get(id)
	if !ok || inc.Kind != incident.KindHostIntegrityRisk || inc.CorrelationKey == nil || *inc.CorrelationKey != (incident.Key{Host: "host"}) {
		t.Fatalf("host incident missing or misclassified: %+v", inc)
	}
	var findings []string
	for _, event := range inc.Timeline {
		if event.Kind == "finding" {
			findings = append(findings, event.Check)
		}
	}
	if len(findings) != 2 || findings[0] != "integrity" || findings[1] != "shadow_change" {
		t.Errorf("host evidence = %v, want [integrity shadow_change]", findings)
	}
	if blocks != 0 {
		t.Errorf("unattributed host evidence requested %d IP blocks", blocks)
	}
}
