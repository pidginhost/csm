package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Cached scores use a different finding builder from local threat feeds.
// Both must keep the local sighting that brought the address into the scan.
func TestCachedReputationFindingNamesItsSighting(t *testing.T) {
	const ip = "203.0.113.60"
	at := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	cfg := listIPs(t)
	line := sightingLines(ip, at)["HTTP request"]
	paths := sightingLogs(t, map[string]string{sightingAccessLog: line + "\n"})
	cache := loadReputationCache(cfg.StatePath)
	cache.set(ip, &reputationEntry{Score: 100, Category: "test", CheckedAt: at})
	if !saveReputationCache(cfg.StatePath, cache) {
		t.Fatal("save reputation cache")
	}
	f := reputationFindingFor(t, CheckIPReputation(context.Background(), cfg, nil), ip)
	if !strings.Contains(f.Message, "AbuseIPDB score:") || f.Attribution != admission.AttributionDerived {
		t.Fatalf("finding = %+v, want the cached score with derived attribution", f)
	}
	wantScanObservation(t, f, ProducerReputationScan, syslogTestRef(t, paths[sightingAccessLog], 0, line), at)
}
