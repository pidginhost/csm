package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Startup reads without an open ledger handle. Unreadable eviction state
// must report an error so the caller uses its unreadable-ledger policy
// instead of trusting an incomplete set of proven evictions.
func TestReadBlockActionsRejectsDamagedEvictionState(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
		t.Fatal(err)
	}
	key, err := effectKey(low)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{string(low.Attempt.ID), string(a.Attempt.ID)}
	readers := map[string]func(*DB, []string) ([]string, error){
		"unproven": ReadUnprovenBlockActions,
		"settled":  ReadSettledBlockActions,
	}
	for name, read := range readers {
		if got, readErr := read(f.db, ids); readErr != nil || !reflect.DeepEqual(got, ids[:1]) {
			t.Fatalf("%s before damage = %v, %v; want the evicted victim", name, got, readErr)
		}
	}
	for name, damage := range map[string]func(*bolt.Tx) error{
		"missing effects bucket": func(tx *bolt.Tx) error {
			return tx.DeleteBucket([]byte(admissionEffectsBucket))
		},
		"unannounced effects bucket": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaEffects - 1})
		},
		"nested effect bucket": func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(admissionEffectsBucket))
			if err := b.Delete(key); err != nil {
				return err
			}
			_, err := b.CreateBucket(key)
			return err
		},
		"undecodable effect": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionEffectsBucket)).Put(key, []byte("{}"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := f.copyDatabase()
			if err := db.bolt.Update(damage); err != nil {
				t.Fatal(err)
			}
			for reader, read := range readers {
				if got, err := read(db, ids); !isCorrupt(err) || got != nil {
					t.Errorf("%s = %v, %v; want no rows and a corrupt-record error", reader, got, err)
				}
			}
		})
	}
}

// Sweeping an expired member must not hide its victim's eviction. Once
// the victim also expires, its legitimately missing record is no error.
func TestReadBlockActionsAfterEvictionExpiry(t *testing.T) {
	f := liveLedgerFixture(t)
	f.l.SetOccupants(&fullGeneral)
	low := f.verifiedWith("192.0.2.10", admission.SeverityWarning, 3*time.Hour)
	a := f.evicting("192.0.2.11", low)
	if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.l.FinishEviction(a.Attempt.ID, admission.DispositionApplied, admission.VictimRemoved, 0); err != nil {
		t.Fatal(err)
	}
	ids := []string{string(low.Attempt.ID), string(a.Attempt.ID)}
	for _, step := range []struct {
		at   time.Time
		want []string
	}{
		{a.ExpiresAt, ids[:1]},
		{low.ExpiresAt, nil},
	} {
		f.tickAt(step.at)
		before := f.snapshot()
		for name, read := range map[string]func(*DB, []string) ([]string, error){
			"unproven": ReadUnprovenBlockActions,
			"settled":  ReadSettledBlockActions,
		} {
			if got, err := read(f.db, ids); err != nil || !reflect.DeepEqual(got, step.want) {
				t.Fatalf("%s at %v = %v, %v; want %v", name, step.at, got, err, step.want)
			}
		}
		if !reflect.DeepEqual(before, f.snapshot()) {
			t.Fatal("startup reads changed the ledger")
		}
	}
}
