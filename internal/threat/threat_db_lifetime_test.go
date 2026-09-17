package threat

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// An IP that is no longer blocked but still carries permanent local threat
// evidence must say so, or the lookup screen reads "malicious, in threat DB,
// not blocked" with no explanation of why it scores 100.
func TestLookupReportsThreatEvidenceLifetime(t *testing.T) {
	statePath := t.TempDir()
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	tdb := checks.GetThreatDB()
	tdb.AddPermanent("192.0.2.70", "Permanently blocked via CSM Web UI")
	tdb.AddOperatorTemporary("192.0.2.71", "Manually blocked via CSM Web UI", 24*time.Hour)

	permanent := Lookup("192.0.2.70", statePath)
	if !permanent.InThreatDB || !permanent.ThreatDBPermanent {
		t.Fatalf("permanent evidence not reported: %+v", permanent)
	}
	if permanent.ThreatDBExpiresAt != nil {
		t.Fatalf("permanent evidence carries an expiry: %v", permanent.ThreatDBExpiresAt)
	}

	timed := Lookup("192.0.2.71", statePath)
	if !timed.InThreatDB || timed.ThreatDBPermanent {
		t.Fatalf("timed evidence reported as permanent: %+v", timed)
	}
	if timed.ThreatDBExpiresAt == nil || !timed.ThreatDBExpiresAt.After(time.Now()) {
		t.Fatalf("timed evidence missing a live expiry: %+v", timed.ThreatDBExpiresAt)
	}

	clean := LookupBatch([]string{"192.0.2.72"}, statePath)[0]
	if clean.InThreatDB || clean.ThreatDBPermanent {
		t.Fatalf("unknown IP flagged: %+v", clean)
	}

	batch := LookupBatch([]string{"192.0.2.70"}, statePath)[0]
	if !batch.ThreatDBPermanent {
		t.Fatal("batch lookup lost the permanent-evidence flag")
	}
}
