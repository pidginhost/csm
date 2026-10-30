package store

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// Status must expose damage anywhere in the effect state, even when the
// first expiry still decodes. Doctor must not report that ledger healthy.
func TestAdmissionLedgerEffectsStatusRejectsDamage(t *testing.T) {
	for name, damage := range map[string]func(*bolt.Tx) error{
		"missing bucket": func(tx *bolt.Tx) error {
			return tx.DeleteBucket([]byte(admissionEffectsBucket))
		},
		"missing tally": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionQueueStateBucket)).Delete(effectTallyKey)
		},
		"wrong tally": func(tx *bolt.Tx) error {
			return putEffectTally(tx, admission.EffectTally{General: 1})
		},
		"damaged later record": func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(admissionEffectsBucket))
			k, _ := b.Cursor().Last()
			return b.Put(k, []byte("damaged"))
		},
		"unannounced effects": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaLive})
		},
		"missing schema": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Delete(admissionSchemaKey)
		},
		"malformed schema": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaEffects, 0})
		},
		"future schema": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(admissionMetaBucket)).Put(admissionSchemaKey, []byte{admissionSchemaEffects + 1})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := liveLedgerFixture(t)
			for i, target := range []string{"192.0.2.10", "192.0.2.11"} {
				root := f.published(evidenceSpec{target: target, cursor: target})
				_, id := f.enqueue(f.request(target, root))
				if _, _, granted, err := f.l.Reserve(id, admission.LaneGeneral, f.wall.Add(time.Duration(i+1)*time.Hour)); err != nil || !granted {
					t.Fatalf("reserve %s: granted=%v error=%v", target, granted, err)
				}
			}
			healthy := f.l.Status()
			if healthy.Effects != (admission.EffectsStatus{General: 2, Next: f.wall.Add(time.Hour)}) {
				t.Fatalf("intact effects: %+v", healthy.Effects)
			}
			if err := f.db.bolt.Update(damage); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			s := f.l.Status()
			if s.Effects.Error == "" {
				t.Errorf("damaged effects reported healthy: %+v", s.Effects)
			}
			for _, executing := range []bool{false, true} {
				row := admission.DoctorChecks(&s, nil, f.wall, executing)[0]
				want := admission.DoctorWarn
				if executing {
					want = admission.DoctorFail
				}
				if row.Status != want || !strings.Contains(row.Message, "effects:") {
					t.Errorf("doctor executing=%v: %+v", executing, row)
				}
			}
			s.Effects = healthy.Effects
			if !reflect.DeepEqual(s, healthy) {
				t.Error("effect damage changed an independent status section")
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("status changed the ledger")
			}
		})
	}
}
