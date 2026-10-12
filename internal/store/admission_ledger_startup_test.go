package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Startup asks which firewall rows the ledger has not proven applied:
// rows of running, unknown and failed attempts are held back; a verified
// attempt, an action the ledger never recorded and a name that is no
// action at all leave their rows enforced.
func TestReadUnprovenBlockActions(t *testing.T) {
	f := newLedgerFixture(t)
	expires := ledgerT0.Add(time.Hour)
	running, unknown := f.reservedAt("192.0.2.20", expires), f.reservedAt("192.0.2.21", expires)
	failed, applied := f.reservedAt("192.0.2.22", expires), f.reservedAt("192.0.2.23", expires)
	for _, a := range []admission.AttemptRecord{running, unknown, failed, applied} {
		if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	for a, d := range map[admission.AttemptRecord]admission.Disposition{
		unknown: admission.DispositionUnknown, failed: admission.DispositionFailed, applied: admission.DispositionApplied,
	} {
		if _, _, err := f.l.Finish(a.Attempt.ID, d); err != nil {
			t.Fatal(err)
		}
	}
	const unrecorded = "act_00000000000000000000000000000000"
	ids := []string{
		string(applied.Attempt.ID), string(failed.Attempt.ID), "not-an-action",
		string(running.Attempt.ID), unrecorded, string(unknown.Attempt.ID),
	}
	want := []string{string(failed.Attempt.ID), string(running.Attempt.ID), string(unknown.Attempt.ID)}
	got, err := ReadUnprovenBlockActions(f.db, ids)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("unproven = %v, %v; want %v", got, err, want)
	}

	empty, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = empty.Close() })
	if got, err = ReadUnprovenBlockActions(empty, ids); err != nil || got != nil {
		t.Fatalf("no ledger: %v, %v", got, err)
	}
	older := f.copyDatabase()
	if err = older.bolt.Update(func(tx *bolt.Tx) error {
		if dropErr := dropIntents(tx); dropErr != nil {
			return dropErr
		}
		return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{6})
	}); err != nil {
		t.Fatal(err)
	}
	if got, err = ReadUnprovenBlockActions(older, ids); err != nil || got != nil {
		t.Fatalf("schema 6 ledger: %v, %v", got, err)
	}
	for name, damage := range map[string]func(*bolt.Tx) error{
		"future schema": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaVersion + 1})
		},
		"intents without a ledger": func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(admissionMetaBucket)) },
		"no attempts":              func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(admissionAttemptsBucket)) },
		"attempt is a nested bucket": func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(admissionAttemptsBucket))
			if deleteErr := b.Delete([]byte(applied.Attempt.ID)); deleteErr != nil {
				return deleteErr
			}
			_, bucketErr := b.CreateBucket([]byte(applied.Attempt.ID))
			return bucketErr
		},
		"undecodable attempt": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionAttemptsBucket)).Put([]byte(applied.Attempt.ID), []byte("{}"))
		},
		"attempt under another action": func(tx *bolt.Tx) error {
			raw := tx.Bucket([]byte(admissionAttemptsBucket)).Get([]byte(failed.Attempt.ID))
			return tx.Bucket([]byte(admissionAttemptsBucket)).Put([]byte(applied.Attempt.ID), append([]byte(nil), raw...))
		},
	} {
		db := f.copyDatabase()
		if err = db.bolt.Update(damage); err != nil {
			t.Fatal(err)
		}
		if got, err = ReadUnprovenBlockActions(db, ids); err == nil || got != nil {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
	// A failed owner-open proof must not prevent the independent startup read.
	unopenable := f.copyDatabase()
	if err = unopenable.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionCandidatesBucket)).Put([]byte(running.Attempt.Candidate), []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenAdmissionLedger(unopenable, f.reg); !isCorrupt(err) {
		t.Fatalf("owner open = %v", err)
	}
	if got, err = ReadUnprovenBlockActions(unopenable, ids); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("independent read = %v, %v", got, err)
	}
}

func TestReadUnprovenBlockActionsAcrossAttemptLifetimes(t *testing.T) {
	f := newLedgerFixture(t)
	f.begin()
	expires := f.wall.Add(time.Hour)
	reserved := f.reservedAt("192.0.2.24", expires)
	_, observed := f.observedArrival("192.0.2.25", "offset=25")
	failed := f.reservedAt("192.0.2.26", expires)
	if _, _, _, err := f.l.Execute(failed.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(failed.Attempt.ID, admission.DispositionFailed); err != nil {
		t.Fatal(err)
	}
	f.tickAt(f.wall.Add(admission.RetryBackoff(1)))
	_, applied, granted, err := f.l.Reserve(failed.Attempt.Candidate, admission.LaneGeneral, expires)
	if err != nil || !granted || applied.Attempt.ID == failed.Attempt.ID {
		t.Fatalf("retry = %+v, %v, %v", applied, granted, err)
	}
	if _, _, _, err = f.l.Execute(applied.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.l.Finish(applied.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	retired := f.unknownAt("192.0.2.27", f.wall.Add(time.Second))
	f.ackAll()
	f.tickAt(retired.ExpiresAt)
	if _, _, granted, err = f.l.RetireUnproven(retired.Attempt.ID); err != nil || !granted {
		t.Fatalf("retire unknown: %v, %v", granted, err)
	}
	ids := []string{string(reserved.Attempt.ID), string(observed.Attempt.ID), string(failed.Attempt.ID), string(applied.Attempt.ID), string(retired.Attempt.ID)}
	want := []string{ids[0], ids[1], ids[2], ids[4]}
	before := f.snapshot()
	got, err := ReadUnprovenBlockActions(f.db, ids)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("attempt lifetimes = %v, %v; want %v", got, err, want)
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("startup read changed the ledger")
	}
}

func TestStartupVerifiedProofOutlivesHistoryReviewWindow(t *testing.T) {
	f := newLedgerFixture(t)
	expires := f.wall.Add(2 * admission.HistoryTarget)
	a := f.reservedAt("192.0.2.28", expires)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.Finish(a.Attempt.ID, admission.DispositionApplied); err != nil {
		t.Fatal(err)
	}
	f.ackAll()
	f.tickAt(f.wall.Add(admission.HistoryTarget + time.Hour))
	stored, err := f.l.Attempt(a.Attempt.ID)
	if err != nil || stored.State != admission.StateVerified || !f.wall.Before(stored.ExpiresAt) {
		t.Fatalf("unexpired proof retired: %+v, %v", stored, err)
	}
	if got, err := ReadUnprovenBlockActions(f.db, []string{string(a.Attempt.ID)}); err != nil || got != nil {
		t.Fatalf("unexpired verified row held back: %v, %v", got, err)
	}
}
