package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
)

// Sub-threshold findings wait in the correlator's pending map with a full
// Finding each. They were pruned only by the daily retention compaction, so
// a host with sustained one-shot scanner traffic held a day of stale entries.
// The periodic auto-close tick prunes them too.
func TestIncidentAutoCloseTickPrunesStalePending(t *testing.T) {
	c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 2})
	if _, created, err := c.OnFinding(alert.Finding{
		Check:     "wp_login_bruteforce",
		Severity:  alert.High,
		TenantID:  "alice",
		SourceIP:  "198.51.100.77",
		Message:   "one sighting",
		Timestamp: time.Now(),
	}); err != nil || created {
		t.Fatalf("first sighting should wait for the threshold: created=%v err=%v", created, err)
	}
	if c.PendingCount() != 1 {
		t.Fatalf("pending = %d, want 1", c.PendingCount())
	}

	runIncidentAutoCloseAt(c, &config.Config{}, time.Now().Add(48*time.Hour))

	if c.PendingCount() != 0 {
		t.Fatalf("pending = %d after the auto-close tick, want 0", c.PendingCount())
	}
}
