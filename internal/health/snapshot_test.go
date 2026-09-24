package health

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSnapshot_Severities(t *testing.T) {
	snap := Snapshot{
		Severities: map[string]int{"high": 2, "low": 5},
	}
	if snap.TotalFindings() != 7 {
		t.Fatalf("expected 7, got %d", snap.TotalFindings())
	}
}

func TestSnapshot_AllWatchersAttached(t *testing.T) {
	snap := Snapshot{Watchers: map[string]bool{"fanotify": true, "audit": true}}
	if !snap.AllWatchersAttached() {
		t.Fatal("expected all attached")
	}
	snap.Watchers["audit"] = false
	if snap.AllWatchersAttached() {
		t.Fatal("expected not all attached")
	}
}

func TestSnapshot_DegradedWhenStoreUnhealthy(t *testing.T) {
	snap := Snapshot{
		StoreHealthy: false,
		Watchers:     map[string]bool{"fanotify": true},
	}
	if snap.OverallStatus() != "degraded" {
		t.Fatalf("expected degraded, got %s", snap.OverallStatus())
	}
}

func TestSnapshot_OKWhenAllGreen(t *testing.T) {
	snap := Snapshot{
		StoreHealthy: true,
		Watchers:     map[string]bool{"fanotify": true, "audit": true},
		StartedAt:    time.Now().Add(-1 * time.Hour),
	}
	if snap.OverallStatus() != "ok" {
		t.Fatalf("expected ok, got %s", snap.OverallStatus())
	}
}

// A duration goes out in seconds under a key that ends in _seconds, like
// every other duration the API sends.
func TestAutomationStatusRollbackSecondsKey(t *testing.T) {
	raw, err := json.Marshal(AutomationStatus{FirewallRollbackPending: true, FirewallRollbackSecondsRemain: 42})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"firewall_rollback_remaining_seconds":42`) {
		t.Fatalf("got %s", raw)
	}
}
