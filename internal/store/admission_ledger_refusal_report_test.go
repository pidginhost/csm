package store

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/pidginhost/csm/internal/admission"
)

// queuedUnboundPrefixes queues one prefix response per target, revalidates
// them together while they are valid, and then rewrites them in one
// transaction to the stored shape accepted before target binding, which
// every later check refuses as an attribution target mismatch. The
// revalidation leaves them assessed, so a schedule or preview rechecks
// them as picks, not in its own first revalidation.
func queuedUnboundPrefixes(t *testing.T, f *ledgerFixture, targets ...string) []admission.CandidateID {
	t.Helper()
	var ids []admission.CandidateID
	var legacy []admission.Candidate
	for i, target := range targets {
		root := f.published(evidenceSpec{target: target, cursor: fmt.Sprintf("prefix=%d", i)})
		addr, err := netip.ParseAddr(target)
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := admission.CanonicalPrefix(netip.PrefixFrom(addr, 24).Masked().String(), admission.Caps{})
		if err != nil {
			t.Fatal(err)
		}
		req := f.request(target, root)
		req.Kind, req.Target, req.Entry = admission.KindBlockSubnet, prefix, admission.EntryMailSubnet
		c, id := f.enqueue(req)
		ids, legacy = append(ids, id), append(legacy, c)
	}
	if err := f.l.Revalidate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if got, err := f.l.Candidate(id); err != nil || got.State != admission.StateQueued {
			t.Fatalf("permitted range did not stay queued: %+v, err=%v", got, err)
		}
	}
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		for _, c := range legacy {
			c.Entry = admission.EntryScan
			if err := putCandidate(tx, c); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ids
}

// queuedUnboundPrefix is queuedUnboundPrefixes for one response.
func queuedUnboundPrefix(t *testing.T, f *ledgerFixture) admission.CandidateID {
	t.Helper()
	return queuedUnboundPrefixes(t, f, "192.0.2.7")[0]
}

// laterRefusal is one report of a queued candidate a later check ended.
type laterRefusal struct {
	key admission.CandidateKey
	err error
	at  time.Time
}

// stageCheck runs the later check stage names on f.
func stageCheck(t *testing.T, f *ledgerFixture, stage string) error {
	t.Helper()
	switch stage {
	case "revalidate":
		return f.l.Revalidate()
	case "inventory":
		return f.l.RefreshInventory(admission.InventoryObservation{Accounts: []string{"alice", "bob"}})
	case "schedule":
		_, err := f.l.Schedule(oneEach, nil)
		return err
	case "preview":
		_, err := f.l.SchedulePreview(nil)
		return err
	}
	t.Fatalf("unknown stage %s", stage)
	return nil
}

// A queued candidate that a later check ends is reported once the ending
// commits, with the refusal, its attribution cause and the ledger time: at
// revalidation, at an inventory refresh, and when a schedule or preview pick
// is rechecked. Later checks never report it again. A refused reservation
// ends nothing in the ledger; it returns the cause and reports nothing.
func TestAdmissionLedgerReportsLaterRefusalsWithTheirCause(t *testing.T) {
	for _, stage := range []string{"revalidate", "inventory", "schedule", "preview", "reserve"} {
		t.Run(stage, func(t *testing.T) {
			f := newLedgerFixture(t)
			var reported []laterRefusal
			hookRan := false
			f.l.ObserveRefusals(func(c admission.Candidate, err error, at time.Time) {
				if !hookRan {
					t.Errorf("observer ran before the transaction's precommit hook")
					return
				}
				var state admission.State
				if viewErr := f.db.bolt.View(func(tx *bolt.Tx) error {
					id, idErr := c.Key.ID()
					if idErr != nil {
						return idErr
					}
					stored, loadErr := loadCandidate(tx, id)
					state = stored.State
					return loadErr
				}); viewErr != nil || state == admission.StateQueued {
					t.Errorf("observer saw the ending uncommitted: state %s, err %v", state, viewErr)
				}
				reported = append(reported, laterRefusal{key: c.Key, err: err, at: at})
			})
			id := queuedUnboundPrefix(t, f)
			queued, loadErr := f.l.Candidate(id)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if stage == "reserve" {
				_, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Hour))
				if reason, _ := admission.ReasonOf(err); granted || reason != admission.ReasonAttribution || admission.CauseOf(err) != admission.CauseTargetMismatch {
					t.Fatalf("reservation: granted=%v, err=%v, cause %s", granted, err, admission.CauseOf(err))
				}
				if got, err := f.l.Candidate(id); err != nil || got.State != admission.StateQueued || len(reported) != 0 {
					t.Fatalf("a refused reservation left %+v (err %v) and reported %+v", got, err, reported)
				}
				return
			}
			f.l.failBeforeCommit = func(string) error {
				if len(reported) != 0 {
					t.Errorf("reported %+v before the precommit hook", reported)
				}
				hookRan = true
				return nil
			}
			if err := stageCheck(t, f, stage); err != nil {
				t.Fatal(err)
			}
			f.l.failBeforeCommit, hookRan = nil, false
			got, err := f.l.Candidate(id)
			if err != nil || got.State != admission.StateRefused || got.Reason != admission.ReasonAttribution {
				t.Fatalf("candidate after %s: %+v, err=%v", stage, got, err)
			}
			if len(reported) != 1 || reported[0].key != queued.Key || !reported[0].at.Equal(f.wall) {
				t.Fatalf("reported %+v, want the one ending of %v at %v", reported, queued.Key, f.wall)
			}
			if reason, _ := admission.ReasonOf(reported[0].err); reason != admission.ReasonAttribution || admission.CauseOf(reported[0].err) != admission.CauseTargetMismatch {
				t.Fatalf("reported %v (cause %s), want an attribution target mismatch", reported[0].err, admission.CauseOf(reported[0].err))
			}
			for _, again := range []string{"revalidate", "inventory", "schedule", "preview"} {
				hookRan = true
				if err := stageCheck(t, f, again); err != nil {
					t.Fatal(err)
				}
			}
			if len(reported) != 1 {
				t.Fatalf("later checks reported the ending again: %+v", reported)
			}
		})
	}
}

// An ending whose transaction fails is never reported: both candidates
// stay queued, the successful retry reports each once, and a later
// unrelated transaction replays nothing.
func TestAdmissionLedgerReportsNoUncommittedRefusal(t *testing.T) {
	for _, stage := range []string{"revalidate", "inventory", "schedule", "preview"} {
		t.Run(stage, func(t *testing.T) {
			f := newLedgerFixture(t)
			reported := map[admission.CandidateKey]int{}
			f.l.ObserveRefusals(func(c admission.Candidate, _ error, _ time.Time) { reported[c.Key]++ })
			ids := queuedUnboundPrefixes(t, f, "192.0.2.7", "198.51.100.7")
			if len(ids) != 2 || ids[0] == ids[1] {
				t.Fatalf("queued %v, want two distinct candidates", ids)
			}
			f.failNext(stage)
			if err := stageCheck(t, f, stage); err == nil {
				t.Fatalf("injected failure did not fail the %s transaction", stage)
			}
			for _, id := range ids {
				if got, err := f.l.Candidate(id); err != nil || got.State != admission.StateQueued {
					t.Fatalf("failed %s ended %+v, err=%v", stage, got, err)
				}
			}
			if len(reported) != 0 {
				t.Fatalf("failed %s reported %+v", stage, reported)
			}
			if err := stageCheck(t, f, stage); err != nil {
				t.Fatal(err)
			}
			for _, id := range ids {
				got, err := f.l.Candidate(id)
				if err != nil || got.State != admission.StateRefused || reported[got.Key] != 1 {
					t.Fatalf("after the retry %+v (err %v) reported %d times, want once", got, err, reported[got.Key])
				}
			}
			f.tickAt(f.wall.Add(time.Minute))
			if err := f.l.Revalidate(); err != nil {
				t.Fatal(err)
			}
			if len(reported) != 2 {
				t.Fatalf("reports after an unrelated transaction: %+v", reported)
			}
			for key, n := range reported {
				if n != 1 {
					t.Fatalf("%v reported %d times", key, n)
				}
			}
		})
	}
}

// Every later ending of a queued candidate is reported with its reason, not
// only attribution ones: an aged-out candidate and one whose check's policy
// no longer accepts its evidence, both with no attribution cause.
func TestAdmissionLedgerReportsEveryLaterEndingReason(t *testing.T) {
	check := func(t *testing.T, f *ledgerFixture, id admission.CandidateID, want admission.Reason, reported []laterRefusal) {
		t.Helper()
		got, err := f.l.Candidate(id)
		if err != nil || got.State == admission.StateQueued || got.Reason != want {
			t.Fatalf("candidate %+v, err=%v, want it ended for %s", got, err, want)
		}
		if len(reported) != 1 || reported[0].key != got.Key || !reported[0].at.Equal(f.wall) {
			t.Fatalf("reported %+v, want one ending at %v", reported, f.wall)
		}
		if reason, _ := admission.ReasonOf(reported[0].err); reason != want || admission.CauseOf(reported[0].err) != 0 {
			t.Fatalf("reported %v (cause %s), want %s with no cause", reported[0].err, admission.CauseOf(reported[0].err), want)
		}
	}
	t.Run("stale", func(t *testing.T) {
		f := newLedgerFixture(t)
		var reported []laterRefusal
		f.l.ObserveRefusals(func(c admission.Candidate, err error, at time.Time) {
			reported = append(reported, laterRefusal{key: c.Key, err: err, at: at})
		})
		id := f.queued()
		f.tickAt(f.candidateOf(id).AgeOut)
		if err := f.l.Revalidate(); err != nil {
			t.Fatal(err)
		}
		check(t, f, id, admission.ReasonStale, reported)
	})
	t.Run("policy", func(t *testing.T) {
		f, raise := newFloorLedger(t)
		var reported []laterRefusal
		f.l.ObserveRefusals(func(c admission.Candidate, err error, at time.Time) {
			reported = append(reported, laterRefusal{key: c.Key, err: err, at: at})
		})
		id := f.queued()
		raise(admission.SeverityCritical)
		if err := f.l.Revalidate(); err != nil {
			t.Fatal(err)
		}
		check(t, f, id, admission.ReasonPolicy, reported)
	})
}
