package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// A timed operator block writes operator evidence that lapses with the
// firewall block instead of flagging the address forever.
func TestThreatDBAddOperatorTemporaryPersistsExpiringOperatorRow(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)

	before := time.Now()
	db.AddOperatorTemporary("192.0.2.60", "Manually blocked via CSM Web UI", 24*time.Hour)

	if src, ok := db.Lookup("192.0.2.60"); !ok || src != "Manually blocked via CSM Web UI" {
		t.Fatalf("Lookup after AddOperatorTemporary = (%q, %v)", src, ok)
	}
	entry, found := store.Global().GetPermanentBlock("192.0.2.60")
	if !found {
		t.Fatal("store entry missing after AddOperatorTemporary")
	}
	if entry.Source != store.ThreatSourceOperator {
		t.Fatalf("Source = %q, want %q", entry.Source, store.ThreatSourceOperator)
	}
	if entry.ExpiresAt.Before(before.Add(23*time.Hour)) || entry.ExpiresAt.After(before.Add(25*time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want ~24h from %v", entry.ExpiresAt, before)
	}
	if entry.Expired(before.Add(23 * time.Hour)) {
		t.Fatal("row expired while the block is still live")
	}
	if !entry.Expired(before.Add(25 * time.Hour)) {
		t.Fatal("row outlived the firewall block")
	}
}

func TestThreatDBAddOperatorTemporaryKeepsPermanentEvidence(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)

	db.AddPermanent("192.0.2.61", "Permanently blocked via CSM Web UI")
	db.AddOperatorTemporary("192.0.2.61", "Manually blocked via CSM Web UI", 24*time.Hour)

	if exp, ok := db.badIPExpiry["192.0.2.61"]; ok {
		t.Fatalf("permanent evidence gained an expiry: %v", exp)
	}
	entry, found := store.Global().GetPermanentBlock("192.0.2.61")
	if !found || !entry.ExpiresAt.IsZero() || entry.Source != store.ThreatSourceOperator {
		t.Fatalf("permanent operator row downgraded: found=%v entry=%+v", found, entry)
	}
}

func TestThreatDBAddOperatorTemporarySkipsNonPositiveTTL(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)

	db.AddOperatorTemporary("192.0.2.62", "Manually blocked via CSM Web UI", 0)

	if _, ok := db.Lookup("192.0.2.62"); ok {
		t.Fatal("non-positive TTL operator block became reputation evidence")
	}
	if _, found := store.Global().GetPermanentBlock("192.0.2.62"); found {
		t.Fatal("non-positive TTL operator block persisted to store")
	}
}

// LookupMatch tells the UI whether a flagged IP carries permanent local
// evidence (re-flagged on every future sighting) or evidence that lapses.
func TestThreatDBLookupMatchReportsLifetime(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)

	db.AddPermanent("192.0.2.63", "Permanently blocked via CSM Web UI")
	db.AddOperatorTemporary("192.0.2.64", "Manually blocked via CSM Web UI", 24*time.Hour)
	db.feedIPs = map[string]map[string]struct{}{"cins-army": {"192.0.2.65": {}}}
	db.badIPs["192.0.2.65"] = "cins-army"

	match, ok := db.LookupMatch("192.0.2.63")
	if !ok || !match.Permanent || !match.ExpiresAt.IsZero() {
		t.Fatalf("permanent row match = %+v, ok=%v", match, ok)
	}
	match, ok = db.LookupMatch("192.0.2.64")
	if !ok || match.Permanent || match.ExpiresAt.IsZero() {
		t.Fatalf("timed row match = %+v, ok=%v", match, ok)
	}
	match, ok = db.LookupMatch("192.0.2.65")
	if !ok || match.Permanent || match.Source != "cins-army" {
		t.Fatalf("feed row match = %+v, ok=%v", match, ok)
	}
	if _, ok = db.LookupMatch("192.0.2.66"); ok {
		t.Fatal("unknown IP reported as a threat match")
	}
}

func TestOperatorTemporarySurvivesFeedRemoval(t *testing.T) {
	withTestThreatStore(t)
	db := newTestThreatDB(t)
	const ip = "192.0.2.70"
	db.feedIPs = map[string]map[string]struct{}{"cins-army": {ip: {}}}
	db.badIPs[ip] = "cins-army"
	db.AddOperatorTemporary(ip, "Manually blocked via CSM Web UI", 24*time.Hour)
	entry, found := store.Global().GetPermanentBlock(ip)
	if !found || entry.Source != store.ThreatSourceOperator || entry.ExpiresAt.IsZero() {
		t.Fatalf("operator evidence missing behind feed: found=%v entry=%+v", found, entry)
	}
	delete(db.feedIPs["cins-army"], ip)
	db.rebuildFeedLookup(map[string]bool{"cins-army": true})
	if match, ok := db.LookupMatch(ip); !ok || match.ExpiresAt.IsZero() {
		t.Fatalf("feed withdrawal erased timed operator evidence: %+v, %v", match, ok)
	}
	restarted := newTestThreatDB(t)
	restarted.loadPermanentBlocklist()
	if match, ok := restarted.LookupMatch(ip); !ok || !match.ExpiresAt.Equal(entry.ExpiresAt) {
		t.Fatalf("restart lost original expiry: %+v, %v", match, ok)
	}
	db.badIPExpiry[ip] = time.Now().Add(-time.Second)
	if _, ok := db.LookupMatch(ip); ok {
		t.Fatal("operator evidence survived its deadline")
	}
}
