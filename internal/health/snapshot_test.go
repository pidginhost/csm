package health

import (
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
