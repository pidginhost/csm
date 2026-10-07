package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestLoginUpgradeRestoredSSHIncidentRemainsBlockable(t *testing.T) {
	var ids []string
	cfg := CorrelatorConfig{
		AddressEvidence: func(check string, _ alert.Severity) bool {
			return check == "ssh_login_realtime" || check == "ssh_login_unknown_ip"
		},
		OpenThreshold: 1,
		AutoBlock:     IncidentAutoBlockConfig{BlockAtSeverity: "critical"},
		OnIncidentBlock: func(_, _ string, _ time.Duration, id string, _ PreparedRoot) bool {
			ids = append(ids, id)
			return true
		},
	}
	now := time.Now()
	c := NewCorrelator(cfg)
	c.now = func() time.Time { return now }
	ssh := alert.Finding{
		Check: "ssh_login_realtime", Severity: alert.Critical,
		SourceIP: "192.0.2.50", Timestamp: now,
	}
	if _, _, err := c.OnFinding(ssh); err != nil {
		t.Fatal(err)
	}
	retained := c.Snapshot()
	if len(retained) != 1 || len(ids) != 0 {
		t.Fatalf("seed incident: %+v", retained)
	}
	cfg.AutoBlock.Enabled = true
	c = NewCorrelator(cfg)
	c.now = func() time.Time { return now.Add(time.Minute) }
	c.Restore(retained)
	// New informational FTP evidence cannot authorize a block by itself;
	// the retained SSH event must still carry the blocking decision.
	if _, _, err := c.OnFinding(alert.Finding{
		Check: "ftp_login", Severity: alert.Warning,
		SourceIP: "192.0.2.50", Timestamp: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != alert.FindingID(ssh) {
		t.Fatalf("restored SSH evidence authorized blocks %q, want only %s", ids, alert.FindingID(ssh))
	}
	retained[0].RemoteIPEvidence = false
	retained[0].RemoteIPEvidenceFinding = ""
	retained[0].Timeline = nil
	c = NewCorrelator(cfg)
	c.now = func() time.Time { return now.Add(time.Minute) }
	c.Restore(retained)
	if _, _, err := c.OnFinding(alert.Finding{
		Check: "ftp_login", Severity: alert.Warning,
		SourceIP: "192.0.2.50", Timestamp: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("FTP advisory authorized a block without retained SSH evidence: %q", ids)
	}
}
