package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

func (f *ledgerFixture) setSchema(n byte) {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{n})
	}); err != nil {
		f.t.Fatal(err)
	}
}

// verifiedBlock reserves, runs and verifies a block of a new candidate.
func (f *ledgerFixture) verifiedBlock() admission.ActionID {
	f.t.Helper()
	_, a, _, err := f.l.Reserve(f.queued(), admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		f.t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		f.t.Fatal(err)
	}
	return a.Attempt.ID
}

// Schema 13 records nothing of the live start or the effect records: a
// ledger at 13 opens with or without them, startup reads accept it, and
// opening rewrites nothing.
func TestAdmissionLedgerSchemaThirteenOpensEveryLayout(t *testing.T) {
	for _, tc := range []struct {
		name          string
		live, effects bool
	}{
		{"before the live start", false, false},
		{"live without effects", true, false},
		{"live with effects", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			// Keep a settled action even without effect records, so the
			// startup reader actually enters the layout check.
			ids := []string{string(f.verifiedBlock())}
			if tc.live {
				if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.effects {
				f.nextGeneration()
				ids = append(ids, string(f.verifiedBlock()))
			}
			f.setSchema(admissionSchemaEpisodeElapsed)
			before := f.snapshot()
			l, err := OpenAdmissionLedger(f.db, f.reg)
			if err != nil || l.LiveStarted() != tc.live {
				t.Fatalf("open: live %v, %v", l != nil && l.LiveStarted(), err)
			}
			if _, err = ReadUnresolvedIntents(f.db); err != nil {
				t.Fatalf("startup intents: %v", err)
			}
			if _, err = ReadAdmissionClock(f.db); err != nil {
				t.Fatalf("startup clock: %v", err)
			}
			if got, err := ReadSettledBlockActions(f.db, ids); err != nil || len(got) != 0 {
				t.Fatalf("startup settled blocks: %v, %v", got, err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("opening or startup reads changed the layout")
			}
		})
	}
}

// A schema 13 ledger still takes its live start and its first effect
// record, and keeps its schema: a write never lowers it.
func TestAdmissionLedgerSchemaThirteenStartsLiveAndHoldsEffects(t *testing.T) {
	f := newLedgerFixture(t)
	f.setSchema(admissionSchemaEpisodeElapsed)
	l, err := OpenAdmissionLedger(f.db, f.reg)
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	f.tickAt(f.wall)
	if err = f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	f.verifiedBlock()
	if records, tally, schema := f.effectRecords(); len(records) != 1 || tally != (admission.EffectTally{General: 1}) || schema != admissionSchemaEpisodeElapsed {
		t.Fatalf("effects %+v tally %+v schema %d", records, tally, schema)
	}
	if l, err = OpenAdmissionLedger(f.db, f.reg); err != nil || !l.LiveStarted() {
		t.Fatalf("reopen: %v", err)
	}
}

// At schema 13 the effect records prove themselves: a bucket without its
// tally, a tally without its bucket, or records without a live start are
// damage, for the owner's open and for startup reads alike.
func TestAdmissionLedgerSchemaThirteenRefusesInconsistentLayouts(t *testing.T) {
	for name, damage := range map[string]func(*bolt.Tx) error{
		"effects without a tally": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(effectTallyKey)
		},
		"a tally without effects": func(tx *bolt.Tx) error {
			return tx.DeleteBucket([]byte(admissionEffectsBucket))
		},
		"effects without a live start": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(liveStartKey)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			ids := []string{string(f.verifiedBlock())}
			f.setSchema(admissionSchemaEpisodeElapsed)
			if err := f.db.bolt.Update(damage); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened: %v", err)
			}
			if _, err := ReadSettledBlockActions(f.db, ids); !isCorrupt(err) {
				t.Fatalf("startup read: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a refused open changed the ledger")
			}
		})
	}
}

// Each reader checks its own format boundary, including internal readers
// normally reached through another reader's guard.
func TestAdmissionLedgerSchemaThirteenReaderBounds(t *testing.T) {
	for _, schema := range []byte{13, 14} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			f := liveLedgerFixture(t)
			id := f.verifiedBlock()
			a, err := f.l.Attempt(id)
			if err != nil {
				t.Fatal(err)
			}
			f.setSchema(schema)
			before := f.snapshot()
			check := func(name string, err error) {
				t.Helper()
				if schema == 13 && err != nil || schema == 14 && err != ErrAdmissionSchema {
					t.Errorf("%s schema %d: %v", name, schema, err)
				}
			}
			_, err = OpenAdmissionLedger(f.db, f.reg)
			check("owner", err)
			if err := f.db.bolt.View(func(tx *bolt.Tx) error {
				check("effects", proveEffects(tx))
				_, err := currentLedger(tx)
				check("current ledger", err)
				_, err = evictedBlock(tx, a)
				check("evicted block", err)
				_, _, err = loadLiveStart(tx)
				check("live start", err)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("schema readers changed the ledger")
			}
		})
	}
}

// An effect bucket whose records have all left still needs its tally, at
// schemas 12 and 13 alike: with no record left to count, only the layout
// rule sees that the tally is gone.
func TestAdmissionLedgerEmptyEffectsNeedTheirTally(t *testing.T) {
	for _, schema := range []byte{admissionSchemaEffects, admissionSchemaEpisodeElapsed} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			f := liveLedgerFixture(t)
			ids := []string{string(f.verifiedBlock())}
			f.tickAt(f.wall.Add(time.Hour))
			if records, _, _ := f.effectRecords(); records == nil || len(records) != 0 {
				t.Fatalf("records after the expiry: %+v", records)
			}
			f.setSchema(schema)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(effectTallyKey)
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !isCorrupt(err) {
				t.Fatalf("opened: %v", err)
			}
			if _, err := ReadSettledBlockActions(f.db, ids); !isCorrupt(err) {
				t.Fatalf("startup read: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a refused open changed the ledger")
			}
		})
	}
}

// Startup can read a verified attempt before the owner checks the ledger's
// required buckets. Missing queue state must follow the unreadable-ledger
// error path, whether or not that attempt ever held an effect record.
func TestReadBlockActionsRejectsMissingQueueState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema byte
		live   bool
	}{
		{"preview", admissionSchemaVersion, false},
		{"live", admissionSchemaEffects, true},
		{"elapsed preview", admissionSchemaEpisodeElapsed, false},
		{"elapsed live", admissionSchemaEpisodeElapsed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, read := range map[string]func(*DB, []string) ([]string, error){
				"unproven": ReadUnprovenBlockActions,
				"settled":  ReadSettledBlockActions,
			} {
				t.Run(name, func(t *testing.T) {
					f := newLedgerFixture(t)
					if tc.live {
						if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
							t.Fatal(err)
						}
					}
					ids := []string{string(f.verifiedBlock())}
					f.setSchema(tc.schema)
					if got, err := read(f.db, ids); err != nil || len(got) != 0 {
						t.Fatalf("intact ledger: %v, %v", got, err)
					}
					if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
						return tx.DeleteBucket([]byte(admissionQueueStateBucket))
					}); err != nil {
						t.Fatal(err)
					}
					before := f.snapshot()
					if got, err := read(f.db, ids); !isCorrupt(err) || got != nil {
						t.Fatalf("missing queue state: %v, %v; want no rows and a corrupt-record error", got, err)
					}
					if !reflect.DeepEqual(before, f.snapshot()) {
						t.Fatal("startup read changed the damaged ledger")
					}
				})
			}
		})
	}
}
