package daemon

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

func TestHandleThreatForgetCanonicalizesIP(t *testing.T) {
	for _, tc := range []struct{ input, canonical string }{
		{"2001:0DB8:0000:0000:0000:0000:0000:0023", "2001:db8::23"},
		{"::ffff:198.51.100.23", "198.51.100.23"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			db := seedAttackRecord(t, tc.canonical)
			c := newListenerForTest(t)
			resp := c.dispatch([]byte(`{"cmd":"threat.forget","args":{"ip":"` + tc.input + `"}}`))
			if !resp.OK {
				t.Fatal(resp.Error)
			}
			var res control.ThreatForgetResult
			if err := json.Unmarshal(resp.Result, &res); err != nil {
				t.Fatal(err)
			}
			if !res.Found || res.IP != tc.canonical || res.Events != 40 {
				t.Fatalf("forget result = %+v", res)
			}
			if db.LookupIP(tc.canonical) != nil {
				t.Fatal("canonical record survived forget")
			}
		})
	}
}

// Two requests must not both claim the same removed evidence.
func TestHandleThreatForgetConcurrentRequests(t *testing.T) {
	db := seedAttackRecord(t, "198.51.100.23")
	c := newListenerForTest(t)
	for round := 0; round < 100; round++ {
		db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "198.51.100.23"})
		start := make(chan struct{})
		results := make(chan control.ThreatForgetResult, 16)
		var wg sync.WaitGroup
		for i := 0; i < cap(results); i++ {
			wg.Go(func() {
				<-start
				raw, err := c.handleThreatForget([]byte(`{"ip":"198.51.100.23"}`))
				if err != nil {
					t.Error(err)
					return
				}
				results <- raw.(control.ThreatForgetResult)
			})
		}
		close(start)
		wg.Wait()
		close(results)
		found := 0
		for res := range results {
			if res.Found {
				found++
			}
		}
		if found != 1 {
			t.Fatalf("round %d: %d requests claimed the same record, want 1", round, found)
		}
	}
}

// seedAttackRecord installs a global attack database holding one IP with
// enough evidence to clear the local_threat_score reporting threshold.
func seedAttackRecord(t *testing.T, ip string) *attackdb.DB {
	t.Helper()
	db := attackdb.NewForTest(nil)
	previous := attackdb.Global()
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	for i := 0; i < 20; i++ {
		for _, check := range []string{"webshell", "user_outbound_connection"} {
			db.RecordFinding(alert.Finding{Check: check, SourceIP: ip, Timestamp: time.Now()})
		}
	}
	return db
}

// A detection bug that attributes attacks to the wrong address poisons that
// address's attack record. Fixing the detection stops new events but leaves
// the accumulated ones: most score contributions last until the record is
// pruned after 90 days, and local_threat_score re-reports the stale score on
// every daemon start.
//
// Unlike the Web UI's clear and whitelist actions, this handler clears
// scoring state without changing enforcement.
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
	previous := attackdb.Global()
	attackdb.SetGlobal(nil)
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	c := newListenerForTest(t)

	if _, err := c.handleThreatForget([]byte(`{"ip":"198.51.100.23"}`)); err == nil {
		t.Error("handleThreatForget returned no error with no attack database")
	}
}

func TestHandleThreatForgetPersistsRemovalAndRetainsHistory(t *testing.T) {
	const ip = "198.51.100.23"
	dir := t.TempDir()
	sdb, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	previous := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() { store.SetGlobal(previous); _ = sdb.Close() })
	db := seedAttackRecord(t, ip)
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, found := sdb.LoadIPRecord(ip); !found {
		t.Fatal("seed was not persisted")
	}
	// The command must flush pending evidence too, without deleting either
	// previously persisted events or records for other addresses.
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: ip, Timestamp: time.Now()})
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "203.0.113.23", Timestamp: time.Now()})
	c := newListenerForTest(t)
	if _, err := c.handleThreatForget([]byte(`{"ip":"` + ip + `"}`)); err != nil {
		t.Fatal(err)
	}
	if err := sdb.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sdb = reopened
	store.SetGlobal(sdb)
	if _, found := sdb.LoadIPRecord(ip); found {
		t.Fatal("forgotten record survived store reopen")
	}
	if events := db.QueryEvents(ip, 100); len(events) != 41 {
		t.Fatalf("event history after forget = %d, want 41", len(events))
	}
	if rec, found := sdb.LoadIPRecord("203.0.113.23"); !found || rec.EventCount != 1 {
		t.Fatalf("unrelated record changed: %+v, found=%v", rec, found)
	}
	db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: ip, Timestamp: time.Now()})
	if rec := db.LookupIP(ip); rec == nil || rec.EventCount != 1 {
		t.Fatalf("new finding did not start fresh scoring: %+v", rec)
	}
}
