package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// A refused clock reading stops new work, but a verified result still
// commits using the last recorded clock, without repairing damaged state.
func TestAdmissionLedgerFinishesEpisodeWithDamagedCeiling(t *testing.T) {
	for _, tc := range []struct {
		name         string
		live, reopen bool
	}{
		{name: "running"},
		{name: "reopened", reopen: true},
		{name: "live", live: true},
		{name: "live reopened", live: true, reopen: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			if tc.live {
				if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
					t.Fatal(err)
				}
			}
			f.begin()
			f.tickAt(f.wall.Add(5 * time.Minute))
			first := f.arrive(f.arrival(evidenceSpec{cursor: "first"}))[0].Candidate
			expires := f.wall.Add(20 * time.Minute)
			_, a, _, err := f.l.Reserve(first, admission.LaneGeneral, expires)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err = f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			f.tickAt(f.wall.Add(time.Minute))
			if tc.reopen {
				if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
					t.Fatal(err)
				}
			}
			f.failNext("tick")
			if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall.Add(10 * time.Minute), BootID: ledgerBoot, SinceBoot: f.since + time.Minute}); err == nil {
				t.Fatal("injected failure did not abort the tick")
			}
			if err = f.db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(admissionQueueStateBucket)).Put(ceilingStateKey, []byte("damaged"))
			}); err != nil {
				t.Fatal(err)
			}
			if _, err = f.l.Tick(admission.ClockReading{Wall: f.wall.Add(time.Minute), BootID: ledgerBoot, SinceBoot: f.since + time.Minute}); !isCorrupt(err) {
				t.Fatalf("tick over damaged ceiling: %v", err)
			}
			c, ended, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied)
			if err != nil || c.State != admission.StateVerified || ended.State != admission.StateVerified || !ended.Finished.Equal(f.wall) {
				t.Fatalf("finish over damaged ceiling: candidate %s, attempt %s, error %v", c.State, ended.State, err)
			}
			_, err = f.l.QueueSnapshot()
			wantLedgerReason(t, "new work after a failed tick", err, admission.ReasonEngineUnavailable)
			row, found := f.episodeAt("192.0.2.10")
			if !found || !row.Verified.Equal(expires) || row.EndElapsed != 25*time.Minute {
				t.Fatalf("verified episode: %+v, found %v", row, found)
			}
			if tc.live {
				records, _, _ := f.effectRecords()
				if len(records) != 1 || !records[0].Applied.Equal(f.wall) || records[0].Elapsed != 6*time.Minute {
					t.Fatalf("verified effect: %+v", records)
				}
			}
			if err = f.db.bolt.View(func(tx *bolt.Tx) error {
				if !bytes.Equal(tx.Bucket([]byte(admissionQueueStateBucket)).Get(ceilingStateKey), []byte("damaged")) {
					t.Error("finishing rewrote the damaged ceiling")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
