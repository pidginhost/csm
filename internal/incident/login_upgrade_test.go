package incident

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestLoginUpgradeRestoredSSHIncidentRemainsBlockable(t *testing.T) {
	var captured blockCapture
	cfg := CorrelatorConfig{
		OpenThreshold:   1,
		AutoBlock:       IncidentAutoBlockConfig{BlockAtSeverity: "critical"},
		OnIncidentBlock: captured.recordOK,
	}
	now := time.Now()
	c := NewCorrelator(cfg)
	c.now = func() time.Time { return now }
	if _, _, err := c.OnFinding(alert.Finding{
		Check: "ssh_login_realtime", Severity: alert.Critical,
		SourceIP: "192.0.2.50", Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}
	retained := c.Snapshot()
	if len(retained) != 1 || captured.len() != 0 {
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
	if captured.len() != 1 {
		t.Fatalf("restored SSH evidence authorized %d blocks, want 1", captured.len())
	}
}
