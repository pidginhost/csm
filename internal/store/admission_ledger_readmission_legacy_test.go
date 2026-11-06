package store

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Episodes written before verified generations still use retained block
// history to admit fresh evidence, and never admit support from before
// removal. Opening such a ledger remains read-only.
func TestAdmissionLedgerReadmissionWithoutVerifiedGeneration(t *testing.T) {
	for _, state := range []string{"verified", "queued", "ended"} {
		t.Run(state, func(t *testing.T) {
			f, _, gone := goneArrival(t)
			var queued admission.CandidateID
			if state != "verified" {
				f.tickAt(f.wall.Add(time.Minute))
				res := f.arrive(f.arrival(evidenceSpec{cursor: "return"}))[0]
				if res.Err != nil || !res.Created {
					t.Fatalf("return: %+v", res)
				}
				queued = res.Candidate
				if state == "ended" {
					if _, err := f.l.Terminate(queued, admission.ReasonStale); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(admissionEpisodesBucket))
				key := []byte(f.target("192.0.2.10").Key())
				raw := b.Get(key)
				body := bytes.ReplaceAll(raw[:len(raw)-8], []byte(`,"verified_generation":1`), nil)
				sum := sha256.Sum256(body)
				if err := b.Put(key, append(body, sum[:8]...)); err != nil {
					return err
				}
				return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaEffectGone})
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			var err error
			if f.l, err = OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("opening rewrote the legacy episode")
			}
			f.begin()
			f.tickAt(f.wall.Add(time.Minute))
			old := f.published(evidenceSpec{cursor: "old-support", age: f.wall.Sub(gone)})
			e := f.mint(evidenceSpec{cursor: "fresh-with-old-support"})
			req := f.request("192.0.2.10", e.ID(), old)
			req.Episode, req.Generation = admission.EpisodeID{}, 0
			wantLedgerReason(t, "old support in legacy episode", f.arrive(admission.Arrival{Request: req, Evidence: e})[0].Err, admission.ReasonStale)
			res := f.arrive(f.arrival(evidenceSpec{cursor: "fresh"}))[0]
			if res.Err != nil || res.Created != (state != "queued") {
				t.Fatalf("legacy return: %+v", res)
			}
			if state == "queued" && res.Candidate != queued {
				t.Fatalf("coalesced into %s, want %s", res.Candidate, queued)
			}
			row, _ := f.episodeAt("192.0.2.10")
			line, _ := row.Line(admission.KindBlockIP)
			if line.VerifiedGeneration != 1 || f.schema() != admissionSchemaEpisodeRetained {
				t.Fatalf("return did not retain its verified predecessor: %+v schema %d", line, f.schema())
			}
			if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
				t.Fatalf("reopen after anchoring the predecessor: %v", err)
			}
		})
	}
}
