package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A concurrent sweep can commit between ObserveHeld's read and write
// transactions. A second miss that then marks nothing needs no new schema.
func TestAdmissionLedgerGoneSchemaOnlyFollowsStoredMarks(t *testing.T) {
	f := liveLedgerFixture(t)
	a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
	asked, err := f.l.HeldEffects(1)
	if err != nil || len(asked) != 1 {
		t.Fatalf("held effects: %+v, %v", asked, err)
	}
	f.observeHeld(asked, false)
	_, _, schemaBefore := f.effectRecords()
	tx, err := f.db.bolt.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if err := sweepEffects(tx, admission.ClockTick{Now: a.ExpiresAt}); err != nil {
		t.Fatal(err)
	}
	reads := f.db.bolt.Stats().TxN
	done := make(chan error, 1)
	go func() {
		n, err := markedCount(f.l.ObserveHeld(asked, []bool{false}))
		if err == nil && n != 0 {
			err = fmt.Errorf("marked %d swept effects", n)
		}
		done <- err
	}()
	// The pending writer leaves the old record visible to the read but
	// prevents the gone write until the sweep commits.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		stats := f.db.bolt.Stats()
		if stats.TxN > reads && stats.OpenTxN == 0 {
			break
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("observation did not finish reading before the sweep")
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if records, tally, schema := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) || schema != schemaBefore {
		t.Fatalf("no gone record stored: records %+v, tally %+v, schema %d (was %d)", records, tally, schema, schemaBefore)
	}
}

// Sweeping the last gone record keeps schema 14, its empty effect storage
// and the live start. Losing either part of that layout is still damage.
func TestAdmissionLedgerGoneSchemaRequiresLiveEffects(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		dropBucket, dropTally, dropLive bool
	}{
		{name: "empty effects"},
		{name: "missing bucket", dropBucket: true},
		{name: "missing tally", dropTally: true},
		{name: "missing bucket and tally", dropBucket: true, dropTally: true},
		{name: "missing live start", dropLive: true},
		{name: "missing live effects", dropBucket: true, dropTally: true, dropLive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			a := f.verifiedWith("192.0.2.10", admission.SeverityWarning, time.Hour)
			asked, err := f.l.HeldEffects(1)
			if err != nil || len(asked) != 1 {
				t.Fatalf("held effects: %+v, %v", asked, err)
			}
			f.observeHeld(asked, false)
			if n := f.observeHeld(asked, false); n != 1 {
				t.Fatalf("marked %d gone, want 1", n)
			}
			f.tickAt(a.ExpiresAt)
			if records, tally, schema := f.effectRecords(); len(records) != 0 || tally != (admission.EffectTally{}) || schema != admissionSchemaEffectGone {
				t.Fatalf("swept records %+v, tally %+v, schema %d", records, tally, schema)
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				if tc.dropBucket {
					if deleteErr := tx.DeleteBucket([]byte(admissionEffectsBucket)); deleteErr != nil {
						return deleteErr
					}
				}
				state := tx.Bucket([]byte(admissionQueueStateBucket))
				if tc.dropTally {
					if deleteErr := state.Delete(effectTallyKey); deleteErr != nil {
						return deleteErr
					}
				}
				if tc.dropLive {
					return state.Delete(liveStartKey)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			check := func(name string, err error, corrupt bool) {
				t.Helper()
				if corrupt && !isCorrupt(err) || !corrupt && err != nil {
					t.Errorf("%s: %v, want corrupt=%v", name, err, corrupt)
				}
			}
			corrupt := tc.dropBucket || tc.dropTally || tc.dropLive
			_, err = OpenAdmissionLedger(f.db, f.reg)
			check("open", err, corrupt)
			for name, read := range map[string]func(*DB, []string) ([]string, error){
				"unproven": ReadUnprovenBlockActions,
				"settled":  ReadSettledBlockActions,
			} {
				_, err := read(f.db, []string{string(a.Attempt.ID)})
				check(name, err, corrupt)
			}
			if err := f.db.bolt.View(func(tx *bolt.Tx) error {
				check("effects", proveEffects(tx), corrupt)
				_, _, err := loadLiveStart(tx)
				check("live start", err, tc.dropLive)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("reading the layout changed the ledger")
			}
		})
	}
}
