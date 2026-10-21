package store

import (
	"fmt"
	"math"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// previewHistoryFixture is historyFixture with every verified candidate
// turned into an observe preview: the most history a live start releases.
func previewHistoryFixture(b *testing.B) *ledgerFixture {
	b.Helper()
	f := historyFixture(b, false, math.MaxUint32)
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		var previews []admission.Candidate
		if err := tx.Bucket([]byte(admissionCandidatesBucket)).ForEach(func(k, _ []byte) error {
			c, err := loadCandidate(tx, admission.CandidateID(k))
			if err == nil && c.State == admission.StateVerified {
				previews = append(previews, c)
			}
			return err
		}); err != nil {
			return err
		}
		for _, c := range previews {
			a, err := currentAttempt(tx, c)
			if err != nil {
				return err
			}
			c.State, c.Disposition, c.Transitions = admission.StateObserved, admission.DispositionObserve, 3
			a.State, a.Disposition = admission.StateObserved, admission.DispositionObserve
			if err = putCandidate(tx, c); err != nil {
				return err
			}
			if err = putAttempt(tx, a); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		b.Fatal(err)
	}
	return f
}

// The live start traverses a full history allowance and releases its
// preview portion in one transaction.
func BenchmarkAdmissionLedgerLiveStartFullPreviewHistory(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f := previewHistoryFixture(b)
		b.ReportMetric(float64(bucketKeys(b, f.db, admissionHistoryBucket)), "history/op")
		b.StartTimer()
		if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

func bucketKeys(b *testing.B, db *DB, name string) (n int) {
	b.Helper()
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		n = tx.Bucket([]byte(name)).Stats().KeyN
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	return n
}

// previewEpisodesFixture previews n arrivals at distinct documentation
// addresses through the real transitions: one episode row, history entry
// and charge each, anchored only by its preview. Setup refills ceiling and
// history credit between them.
func previewEpisodesFixture(b *testing.B, n int) *ledgerFixture {
	b.Helper()
	f := newLedgerFixture(b)
	if err := f.l.SetCeiling(admission.MaxCeiling); err != nil {
		b.Fatal(err)
	}
	f.begin()
	general, reserved := admission.CeilingLanes(admission.MaxCeiling)
	for i := range n {
		if i%256 == 0 {
			f.leaveCeilingCredit(admission.BucketCap(general), admission.BucketCap(reserved))
		}
		// History bytes are paced: at most a minute of credit is saved.
		f.adjustStorage(func(s *admission.StorageState) { *s, _ = s.Advance(admission.HistoryBurst) })
		f.observedArrival(fmt.Sprintf("2001:db8::%x", i+1), "offset=1")
	}
	return f
}

// The live start ends the episodes of previews at distinct targets, with
// their history and charges, in its one transaction.
func BenchmarkAdmissionLedgerLiveStartPreviewEpisodes(b *testing.B) {
	const previews = 2048
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f := previewEpisodesFixture(b, previews)
		if got := bucketKeys(b, f.db, admissionEpisodesBucket); got != previews {
			b.Fatalf("fixture holds %d episode rows, want %d", got, previews)
		}
		b.StartTimer()
		if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if got := bucketKeys(b, f.db, admissionEpisodesBucket); got != 0 {
			b.Fatalf("%d episode rows outlived the live start", got)
		}
		if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
	b.ReportMetric(previews, "episodes/op")
}
