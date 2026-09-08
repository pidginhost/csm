package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/control"
)

// seedAttackRecord installs a global attack database holding one IP with
// enough evidence to clear the local_threat_score reporting threshold.
func seedAttackRecord(t *testing.T, ip string) *attackdb.DB {
	t.Helper()
	db := attackdb.NewForTest(nil)
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(nil) })
	for i := 0; i < 20; i++ {
		for _, check := range []string{"webshell", "user_outbound_connection"} {
			db.RecordFinding(alert.Finding{Check: check, SourceIP: ip, Timestamp: time.Now()})
		}
	}
	return db
}

// A detection bug that attributes attacks to the wrong address poisons that
// address's attack record. Fixing the detection stops new events but leaves
// the accumulated ones: ComputeScore has no recency term, records are only
// pruned after 90 days, and local_threat_score re-reports the stale score on
// every daemon start.
//
// The only existing way to clear a record is the Web UI's whitelist-ip
// action, which also unblocks the address, adds it to the firewall allow
// list and whitelists it in the threat DB. Whitelisting an address to
// silence a stale score is far more than the operator wanted, and there is
// no CLI path at all. This handler clears the scoring state and nothing
// else.
func TestHandleThreatForgetClearsStaleScore(t *testing.T) {
	const ip = "198.51.100.23"
	db := seedAttackRecord(t, ip)
	if db.LookupIP(ip) == nil {
		t.Fatal("seed did not create a record")
	}

	c := newListenerForTest(t)
	raw, err := c.handleThreatForget([]byte(`{"ip":"` + ip + `"}`))
	if err != nil {
		t.Fatalf("handleThreatForget: %v", err)
	}

	res, ok := raw.(control.ThreatForgetResult)
	if !ok {
		t.Fatalf("result type = %T, want control.ThreatForgetResult", raw)
	}
	if !res.Found {
		t.Error("Found=false for an IP that had a record")
	}
	if res.Events != 40 {
		t.Errorf("Events = %d, want the 40 recorded findings", res.Events)
	}
	if res.Score < 70 {
		t.Errorf("Score = %d, want the reporting-threshold score that was cleared", res.Score)
	}
	if db.LookupIP(ip) != nil {
		t.Error("record still present after forget")
	}
}

// Reporting "cleared" for an address that was never scored would let an
// operator believe they had fixed something they had not.
func TestHandleThreatForgetUnknownIPReportsNothingCleared(t *testing.T) {
	seedAttackRecord(t, "198.51.100.23")

	c := newListenerForTest(t)
	raw, err := c.handleThreatForget([]byte(`{"ip":"203.0.113.99"}`))
	if err != nil {
		t.Fatalf("handleThreatForget: %v", err)
	}
	res := raw.(control.ThreatForgetResult)
	if res.Found {
		t.Error("Found=true for an address with no record")
	}
	if res.Score != 0 || res.Events != 0 {
		t.Errorf("Score=%d Events=%d, want zero for an address with no record", res.Score, res.Events)
	}
}

// The address is the whole request. A malformed one must fail loudly rather
// than silently clear nothing, which would read as success.
func TestHandleThreatForgetRejectsInvalidIP(t *testing.T) {
	seedAttackRecord(t, "198.51.100.23")
	c := newListenerForTest(t)

	for _, args := range []string{`{"ip":"not-an-ip"}`, `{"ip":""}`, `{"ip":"198.51.100.0/24"}`} {
		if _, err := c.handleThreatForget([]byte(args)); err == nil {
			t.Errorf("handleThreatForget(%s) returned no error", args)
		}
	}
}

// Without a database there is nothing to clear; the handler must say so
// instead of reporting a successful removal.
func TestHandleThreatForgetWithoutDatabase(t *testing.T) {
	attackdb.SetGlobal(nil)
	c := newListenerForTest(t)

	if _, err := c.handleThreatForget([]byte(`{"ip":"198.51.100.23"}`)); err == nil {
		t.Error("handleThreatForget returned no error with no attack database")
	}
}
