package store

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// admitted queues a fresh candidate at 192.0.2.10 and reserves it on the
// general lane with the given effect lifetime.
func (f *ledgerFixture) admitted(lifetime time.Duration) (admission.CandidateID, admission.AttemptRecord) {
	f.t.Helper()
	f.nextGeneration()
	id := f.queued()
	_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(lifetime))
	if err != nil {
		f.t.Fatal(err)
	}
	return id, a
}

func (f *ledgerFixture) applied(lifetime time.Duration) admission.CandidateID {
	f.t.Helper()
	id, a := f.admitted(lifetime)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		f.t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func retireKeysIn(t *testing.T, db *DB) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionRetireBucket)).ForEach(func(k, _ []byte) error {
			out[string(k)] = true
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every way an admitted candidate ends dates its history: a verified effect
// is kept for as long as it can last and at least the review window, other
// outcomes and queue endings for the review window, and an unresolved
// outcome is pinned in the recovery reserve.
func TestAdmissionLedgerEndingsDateTheirHistory(t *testing.T) {
	f := newLedgerFixture(t)
	short := f.applied(time.Hour)
	long := f.applied(10 * 24 * time.Hour)
	unknownID, a := f.admitted(time.Hour)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	recovery, used := f.storageState().Recovery, f.storageState().General.Used
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionUnknown); err != nil {
		t.Fatal(err)
	}
	// A failure has no effect to outlast, however long it would have been.
	failedID, a := f.admitted(10 * 24 * time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.Terminate(failedID, admission.ReasonPolicy); err != nil {
		t.Fatal(err)
	}
	now := f.wall
	for _, tc := range []struct {
		id   admission.CandidateID
		want admission.HistoryEntry
	}{
		{short, admission.HistoryEntry{RootMask: 1, General: f.cost(short), Ended: now, Eligible: now.Add(admission.HistoryRetention)}},
		{long, admission.HistoryEntry{RootMask: 1, General: f.cost(long), Ended: now, Eligible: now.Add(10 * 24 * time.Hour)}},
		{unknownID, admission.HistoryEntry{RootMask: 1, General: f.cost(unknownID), Ended: now, Pinned: true}},
		{failedID, admission.HistoryEntry{RootMask: 1, General: f.cost(failedID), Ended: now, Eligible: now.Add(admission.HistoryRetention)}},
	} {
		if h, found := f.historyEntry(tc.id); !found || h != tc.want {
			t.Errorf("history of %s = %+v (found %t), want %+v", tc.id, h, found, tc.want)
		}
	}
	s := f.storageState()
	if s.Recovery != recovery+uint64(f.cost(unknownID)) || s.General.Used != used-uint64(f.cost(unknownID))+uint64(f.cost(failedID)) {
		t.Fatalf("storage after the endings = %+v", s)
	}
	keys := retireKeysIn(t, f.db)
	if len(keys) != 6 {
		t.Fatalf("retirement keys = %d, want two for each of three ended entries", len(keys))
	}
	for _, id := range []admission.CandidateID{short, long, failedID} {
		h, _ := f.historyEntry(id)
		want, _ := h.RetireKeys(id)
		for _, k := range want {
			if !keys[string(k)] {
				t.Errorf("missing retirement key for %s", id)
			}
		}
	}
	// A retry that follows a proven failure is not an ending.
	retry, a := f.admitted(time.Hour)
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	if h, _ := f.historyEntry(retry); !h.Ended.IsZero() {
		t.Fatalf("a requeued candidate's history ended: %+v", h)
	}
}

// A full allowance retires history that may be retired, oldest first, to
// make room for a new charge. History still in its review window is never
// retired, and a lane short of credit retires nothing. Retirement removes
// the candidate, its attempts and its history rows, and releases its roots:
// a root another stored candidate names keeps a reference, and a root that
// is too old to support anything is removed.
func TestAdmissionLedgerPressureRetiresEligibleHistory(t *testing.T) {
	general, _ := admission.HistoryLanes()
	f := newLedgerFixture(t)
	f.nextGeneration()
	own := f.published(evidenceSpec{cursor: "older"})
	intel := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "older-intel"})
	_, older := f.enqueue(f.request("192.0.2.10", own, intel))
	_, a, _, err := f.l.Reserve(older, admission.LaneGeneral, f.wall.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	olderCost := f.cost(older)
	f.nextGeneration()
	f.enqueue(f.request("192.0.2.10", own))
	f.tickAt(f.wall.Add(time.Minute))
	newer := f.applied(time.Hour)
	full := func(cost uint32) {
		f.adjustStorage(func(s *admission.StorageState) { s.General.Used = general - uint64(cost) + 1 })
	}
	f.nextGeneration()
	early := f.queued()
	full(f.cost(early))
	before := f.snapshot()
	_, _, _, err = f.l.Reserve(early, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "full allowance inside the review window", err, admission.ReasonStorageShare)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused reservation retired history")
	}
	f.tickAt(f.wall.Add(admission.HistoryRetention))
	f.nextGeneration()
	late := f.queued()
	full(f.cost(late))
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = 0 })
	before = f.snapshot()
	_, _, _, err = f.l.Reserve(late, admission.LaneGeneral, f.wall.Add(time.Hour))
	wantLedgerReason(t, "no credit", err, admission.ReasonStorageShare)
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a lane short of credit retired history")
	}
	f.adjustStorage(func(s *admission.StorageState) { s.General.Credit = admission.NewStorageState().General.Credit })
	if _, _, _, err = f.l.Reserve(late, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil {
		t.Fatalf("after the review window: %v", err)
	}
	if got := f.storageState().General.Used; got != general+1-uint64(olderCost) {
		t.Fatalf("general usage = %d, want %d", got, general+1-uint64(olderCost))
	}
	if _, err = f.l.Candidate(older); err != errCandidateMissing {
		t.Fatalf("oldest eligible history: %v", err)
	}
	if _, err = f.l.Candidate(newer); err != nil {
		t.Fatalf("newer history was retired too: %v", err)
	}
	if _, found := f.historyEntry(older); found {
		t.Fatal("a retired candidate kept its history entry")
	}
	if _, err = f.l.Attempt(a.Attempt.ID); err == nil {
		t.Fatal("a retired candidate kept its attempt")
	}
	for k := range retireKeysIn(t, f.db) {
		if _, _, id, keyErr := admission.ParseRetireKey([]byte(k)); keyErr != nil || id == older {
			t.Fatalf("retirement key %q: %v", k, keyErr)
		}
	}
	if _, err = f.l.LoadEvidence(intel); err != admission.ErrEvidenceUnpublished {
		t.Fatalf("a retired candidate's week-old root: %v", err)
	}
	if r, _ := refsIn(t, f.db, own); r != (admission.EvidenceRefs{Refs: 1}) {
		t.Fatalf("a root another candidate names = %+v", r)
	}
}

// Retirement keys must lead to an ended, unpinned entry of an ended
// candidate; anything else refuses the change and leaves the ledger as it
// was.
func TestAdmissionLedgerRefusesDamagedRetirement(t *testing.T) {
	general, _ := admission.HistoryLanes()
	for name, damage := range map[string]func(tx *bolt.Tx, id admission.CandidateID) error{
		"missing entry": func(tx *bolt.Tx, id admission.CandidateID) error {
			return tx.Bucket([]byte(admissionHistoryBucket)).Delete([]byte(id))
		},
		"missing candidate": func(tx *bolt.Tx, id admission.CandidateID) error {
			return tx.Bucket([]byte(admissionCandidatesBucket)).Delete([]byte(id))
		},
		"stale key of an entry retired later": func(tx *bolt.Tx, id admission.CandidateID) error {
			h, _, err := loadHistoryEntry(tx, id)
			if err != nil {
				return err
			}
			h.Eligible = h.Eligible.Add(admission.HistoryTarget)
			return putHistoryEntry(tx, id, h)
		},
		"entry of another time": func(tx *bolt.Tx, id admission.CandidateID) error {
			h, _, err := loadHistoryEntry(tx, id)
			if err != nil {
				return err
			}
			h.Eligible = h.Eligible.Add(time.Second)
			data, err := h.MarshalBinary()
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(admissionHistoryBucket)).Put([]byte(id), data)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLedgerFixture(t)
			id := f.applied(time.Hour)
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return damage(tx, id) }); err != nil {
				t.Fatal(err)
			}
			f.tickAt(f.wall.Add(admission.HistoryRetention))
			f.nextGeneration()
			next := f.queued()
			f.adjustStorage(func(s *admission.StorageState) { s.General.Used = general })
			before := f.snapshot()
			if _, _, _, err := f.l.Reserve(next, admission.LaneGeneral, f.wall.Add(time.Hour)); !isCorrupt(err) {
				t.Fatalf("err = %v, want a corrupt record", err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("a refused retirement changed the ledger")
			}
		})
	}
}

// Roots added while a failed attempt waits are queue data until another
// reservation pays for them. Ending that wait cannot retain them as history.
func TestAdmissionLedgerEndingDropsUnreservedRoots(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			f := newLedgerFixture(t)
			root := f.published(evidenceSpec{})
			_, id := f.enqueue(f.request("192.0.2.10", root))
			_, a, _, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.l.Finish(a.Attempt.ID, admission.DispositionFailed); err != nil {
				t.Fatal(err)
			}
			extra := f.published(evidenceSpec{producer: f.rep, check: "reputation", cursor: "retry-support"})
			if _, _, err = f.l.Enqueue(f.request("192.0.2.10", root, extra)); err != nil {
				t.Fatal(err)
			}
			charged := f.storageState().General.Used
			before := f.snapshot()
			f.failNext("terminate")
			if _, err = f.l.Terminate(id, admission.ReasonProtected); err == nil {
				t.Fatal("injected ending committed")
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("failed ending changed roots or accounting")
			}
			f.l.failBeforeCommit = nil
			if explicit {
				c, endErr := f.l.Terminate(id, admission.ReasonProtected)
				if endErr != nil || len(c.Roots) != 1 || c.Roots[0] != root {
					t.Fatalf("ending readback: %+v %v", c, endErr)
				}
			} else {
				f.tickAt(f.wall.Add(admission.QueueAgeLimit))
				f.schedule(admission.ScheduleLimits{General: 1, Members: 1})
			}
			c, err := f.l.Candidate(id)
			if err != nil || len(c.Roots) != 1 || c.Roots[0] != root {
				t.Fatalf("retained roots: %+v %v", c.Roots, err)
			}
			if f.storageState().General.Used != charged || uint64(f.cost(id)) > charged {
				t.Fatal("ending retained unpaid history")
			}
			r, found := refsIn(t, f.db, extra)
			if !found || r.Refs != 0 || r.Loose == 0 {
				t.Fatalf("unused support references: %+v %v", r, found)
			}
		})
	}
}

// Retirement must prove the attempt chain before deleting it, including
// predecessors of a successful retry. Otherwise it hides damaged history.
func TestAdmissionLedgerRetirementPreservesDamagedAttempts(t *testing.T) {
	for _, pressure := range []bool{false, true} {
		for _, damage := range []string{"missing predecessor", "malformed predecessor", "conflicting outcome"} {
			t.Run(fmt.Sprintf("pressure=%t/%s", pressure, damage), func(t *testing.T) {
				f := newLedgerFixture(t)
				id, first := f.admitted(time.Hour)
				if _, _, err := f.l.Finish(first.Attempt.ID, admission.DispositionFailed); err != nil {
					t.Fatal(err)
				}
				f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
				_, last, _, err := f.l.Reserve(id, admission.LaneGeneral, time.Time{})
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, err = f.l.Execute(last.Attempt.ID); err != nil {
					t.Fatal(err)
				}
				if _, _, err = f.l.Finish(last.Attempt.ID, admission.DispositionApplied); err != nil {
					t.Fatal(err)
				}
				if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
					attempts := tx.Bucket([]byte(admissionAttemptsBucket))
					switch damage {
					case "missing predecessor":
						return attempts.Delete([]byte(first.Attempt.ID))
					case "malformed predecessor":
						return attempts.Put([]byte(first.Attempt.ID), []byte("damaged"))
					default:
						a, loadErr := loadAttempt(tx, last.Attempt.ID)
						if loadErr != nil {
							return loadErr
						}
						a.Disposition = admission.DispositionNarrowed
						return putAttempt(tx, a)
					}
				}); err != nil {
					t.Fatal(err)
				}
				var next admission.CandidateID
				if pressure {
					f.tickAt(f.wall.Add(admission.HistoryRetention))
					f.nextGeneration()
					next = f.queued()
					general, _ := admission.HistoryLanes()
					f.adjustStorage(func(s *admission.StorageState) { s.General.Used = general })
				}
				before := f.snapshot()
				if pressure {
					_, _, _, err = f.l.Reserve(next, admission.LaneGeneral, f.wall.Add(time.Hour))
				} else {
					_, err = f.l.Tick(admission.ClockReading{Wall: f.wall.Add(admission.HistoryTarget), BootID: ledgerBoot, SinceBoot: f.since + admission.HistoryTarget})
				}
				if !isCorrupt(err) {
					t.Errorf("retirement over damaged attempts = %v, want a corrupt record", err)
				}
				if !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatal("retirement erased damaged history or changed accounting")
				}
			})
		}
	}
}
