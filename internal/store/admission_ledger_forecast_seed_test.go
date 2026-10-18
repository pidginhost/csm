package store

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// Admission-gates section 8, row 3: a forecast session starts from the
// committed ceiling without the charges of observe previews. Their units
// leave the window and their credit returns, up to the bucket's cap; a
// genuine attempt's charge stays, and the committed ceiling is unchanged.
func TestAdmissionLedgerForecastSeedLeavesPreviewsOut(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	_, preview := f.observedArrival("192.0.2.10", "offset=1")
	f.reservedAt("192.0.2.11", f.wall.Add(time.Hour))
	f.unknownAt("192.0.2.12", f.wall.Add(time.Hour))
	committed, charges := f.ceilingState(), f.charges()
	before := f.snapshot()
	stats := f.db.bolt.Stats()
	seed, kept, err := f.l.ForecastSeed()
	afterStats := f.db.bolt.Stats()
	if afterStats.TxN-stats.TxN != 1 || afterStats.TxStats.GetWrite() != stats.TxStats.GetWrite() {
		t.Fatal("the seed must read ceiling, charges and attempts in one read-only transaction")
	}
	if err != nil {
		t.Fatal(err)
	}
	named := func(id admission.ActionID) func(admission.Charge) bool {
		return func(c admission.Charge) bool { return c.Action == id }
	}
	wantKept := slices.DeleteFunc(slices.Clone(charges), named(preview.Attempt.ID))
	if !reflect.DeepEqual(kept, wantKept) {
		t.Fatalf("seed charges = %+v, want unchanged records in order %+v", kept, wantKept)
	}
	want, err := committed.Uncharge(admission.LaneGeneral, 1)
	if err != nil || seed != want || seed.General.Used != committed.General.Used-1 {
		t.Fatalf("seed = %+v, want %+v (%v)", seed, want, err)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("the seed changed committed state, charges or unknown holds")
	}
	again, repeated, err := f.l.ForecastSeed()
	if err != nil || again != seed || !reflect.DeepEqual(repeated, kept) {
		t.Fatalf("repeated seed changed: %+v %+v, %v", again, repeated, err)
	}
}

// Admission-gates section 8, row 3: while previews do not answer (an owner
// forecasts), an address an observe preview answered queues its next
// generation on a new observation, whether the line still names the
// preview's candidate or only remembers its answer. A verified block's
// remembered answer keeps answering, a previewed challenge still answers its
// line, and previews answer again once turned back on.
func TestAdmissionLedgerPreviewAnswersEndWhileForecasting(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	first, _ := f.observedArrival("192.0.2.10", "offset=1")
	wantLedgerReason(t, "answered by a preview", f.arrive(f.arrival(evidenceSpec{target: "192.0.2.10", cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)
	// A queued challenge keeps the row while the block line only remembers
	// its preview's answer, as when that candidate is deleted.
	challenge := f.arrival(evidenceSpec{target: "192.0.2.20", cursor: "challenge=1"})
	challenge.Request.Kind = admission.KindChallenge
	if res := f.arrive(challenge)[0]; res.Err != nil || !res.Created {
		t.Fatalf("challenge = %+v", res)
	}
	remembered, _ := f.observedArrival("192.0.2.20", "offset=1")
	row, _ := f.episodeAt("192.0.2.20")
	row, _ = row.WithoutCandidate(remembered, true)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisode(tx, f.candidateOf(remembered).Key.Target.Key(), row) }); err != nil {
		t.Fatal(err)
	}
	// A verified block's remembered answer keeps answering until its expiry.
	held := f.arrival(evidenceSpec{target: "192.0.2.30", cursor: "challenge=1"})
	held.Request.Kind = admission.KindChallenge
	if res := f.arrive(held)[0]; res.Err != nil || !res.Created {
		t.Fatalf("challenge = %+v", res)
	}
	verified := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.30", cursor: "offset=1"}))[0].Candidate
	f.finishArrival(verified, f.wall.Add(time.Hour), admission.DispositionApplied)
	row, _ = f.episodeAt("192.0.2.30")
	row, _ = row.WithoutCandidate(verified, true)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisode(tx, f.candidateOf(verified).Key.Target.Key(), row) }); err != nil {
		t.Fatal(err)
	}

	// A previewed challenge: no forecast models challenges.
	asked := f.arrival(evidenceSpec{target: "192.0.2.50", cursor: "challenge=1"})
	asked.Request.Kind = admission.KindChallenge
	res := f.arrive(asked)[0]
	if res.Err != nil || !res.Created {
		t.Fatalf("challenge = %+v", res)
	}
	if _, _, granted, err := f.l.Observe(res.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("challenge preview: %v %v", granted, err)
	}

	// Keep a block line queued while only the challenge's answer remains.
	block := f.arrive(f.arrival(evidenceSpec{target: "192.0.2.60", cursor: "offset=1"}))[0]
	if block.Err != nil || !block.Created {
		t.Fatalf("block beside remembered challenge = %+v", block)
	}
	asked = f.arrival(evidenceSpec{target: "192.0.2.60", cursor: "challenge=1"})
	asked.Request.Kind = admission.KindChallenge
	res = f.arrive(asked)[0]
	if res.Err != nil || !res.Created {
		t.Fatalf("remembered challenge = %+v", res)
	}
	if _, _, granted, err := f.l.Observe(res.Candidate, admission.LaneGeneral, f.wall.Add(time.Hour)); err != nil || !granted {
		t.Fatalf("remembered challenge preview: %v %v", granted, err)
	}
	row, _ = f.episodeAt("192.0.2.60")
	row, _ = row.WithoutCandidate(res.Candidate, true)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return putEpisode(tx, f.candidateOf(res.Candidate).Key.Target.Key(), row) }); err != nil {
		t.Fatal(err)
	}

	f.l.PreviewsAnswer(false)
	f.tickAt(f.wall.Add(time.Second))
	rememberedChallenge := f.arrival(evidenceSpec{target: "192.0.2.60", cursor: "challenge=2"})
	rememberedChallenge.Request.Kind = admission.KindChallenge
	wantLedgerReason(t, "remembered challenge", f.arrive(rememberedChallenge)[0].Err, admission.ReasonExistingEffect)
	again := f.arrival(evidenceSpec{target: "192.0.2.50", cursor: "challenge=2"})
	again.Request.Kind = admission.KindChallenge
	wantLedgerReason(t, "previewed challenge", f.arrive(again)[0].Err, admission.ReasonExistingEffect)
	for _, tc := range []struct {
		target string
		after  admission.CandidateID
	}{{"192.0.2.10", first}, {"192.0.2.20", remembered}} {
		next := f.arrive(f.arrival(evidenceSpec{target: tc.target, cursor: "offset=3"}))[0]
		if next.Err != nil || !next.Created {
			t.Fatalf("%s while forecasting = %+v", tc.target, next)
		}
		c := f.candidateOf(next.Candidate)
		if next.Err != nil || !next.Created || c.Key.Episode != f.candidateOf(tc.after).Key.Episode || c.Key.Generation != 2 {
			t.Fatalf("%s while forecasting = %+v %+v", tc.target, next, c.Key)
		}
	}
	wantLedgerReason(t, "verified block", f.arrive(f.arrival(evidenceSpec{target: "192.0.2.30", cursor: "offset=3"}))[0].Err, admission.ReasonExistingEffect)

	f.l.PreviewsAnswer(true)
	f.observedArrival("192.0.2.40", "offset=1")
	wantLedgerReason(t, "answered again", f.arrive(f.arrival(evidenceSpec{target: "192.0.2.40", cursor: "offset=2"}))[0].Err, admission.ReasonExistingEffect)
}

// A seed refuses unreadable or mismatched state instead of turning it into
// free capacity. Failures return no partial ceiling or retained-charge list.
func TestAdmissionLedgerForecastSeedRejectsDamagedState(t *testing.T) {
	for _, damage := range []string{"ceiling", "charge", "attempt", "attempt identity", "closed"} {
		t.Run(damage, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.begin()
			_, preview := f.observedArrival("192.0.2.10", "offset=1")
			live := f.unknownAt("192.0.2.11", f.wall.Add(time.Hour))
			if damage == "closed" {
				if err := f.db.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				switch damage {
				case "ceiling":
					return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ceilingStateKey, []byte("damaged"))
				case "charge":
					b := tx.Bucket([]byte(admissionChargesBucket))
					k, _ := b.Cursor().First()
					return b.Put(k, []byte("damaged"))
				case "attempt":
					return tx.Bucket([]byte(admissionAttemptsBucket)).Put([]byte(preview.Attempt.ID), []byte("damaged"))
				case "attempt identity":
					b := tx.Bucket([]byte(admissionAttemptsBucket))
					return b.Put([]byte(live.Attempt.ID), b.Get([]byte(preview.Attempt.ID)))
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			var before map[string]string
			if damage != "closed" {
				before = f.snapshot()
			}
			seed, kept, err := f.l.ForecastSeed()
			if err == nil || seed != (admission.CeilingState{}) || kept != nil {
				t.Fatalf("damaged %s returned a seed: %+v %+v, %v", damage, seed, kept, err)
			}
			if damage == "closed" {
				if !errors.Is(err, bolterrors.ErrDatabaseNotOpen) {
					t.Fatalf("closed database error = %v", err)
				}
			} else if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("failed seed changed stored state")
			}
		})
	}
}

// A decodable charge can still disagree with its attempt. Neither a preview
// refund nor a retained genuine charge may seed a forecast from that damage.
func TestAdmissionLedgerForecastSeedRejectsMismatchedCharges(t *testing.T) {
	for _, state := range []string{"preview", "unknown"} {
		for _, mismatch := range []string{"time", "lane", "cost"} {
			t.Run(state+"/"+mismatch, func(t *testing.T) {
				f := newLedgerFixture(t)
				f.begin()
				if state == "preview" {
					f.observedArrival("192.0.2.10", "offset=1")
				} else {
					f.unknownAt("192.0.2.10", f.wall.Add(time.Hour))
				}
				charges := f.charges()
				if len(charges) != 1 {
					t.Fatalf("fixture charges = %+v", charges)
				}
				charge := charges[0]
				if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
					s, err := loadCeiling(tx)
					if err != nil {
						return err
					}
					if s, err = s.Release(charge.Lane, charge.Cost); err != nil {
						return err
					}
					if err = putCeilingState(tx, s); err != nil {
						return err
					}
					key, err := charge.Key()
					if err != nil {
						return err
					}
					if err = tx.Bucket([]byte(admissionChargesBucket)).Delete(key); err != nil {
						return err
					}
					switch mismatch {
					case "time":
						charge.At = charge.At.Add(time.Nanosecond)
					case "lane":
						charge.Lane = admission.LaneDirect
					case "cost":
						charge.Cost++
					}
					return putCharge(tx, charge, true)
				}); err != nil {
					t.Fatal(err)
				}
				before := f.snapshot()
				seed, kept, err := f.l.ForecastSeed()
				if !errors.Is(err, admission.ErrCorruptRecord) || seed != (admission.CeilingState{}) || kept != nil {
					t.Fatalf("mismatched charge returned a seed: %+v %+v, %v", seed, kept, err)
				}
				if !reflect.DeepEqual(before, f.snapshot()) {
					t.Fatal("failed seed changed stored state")
				}
			})
		}
	}
}
