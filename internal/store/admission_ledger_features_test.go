package store

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// metaFeatures reads the ledger's feature bits as stored, or false when the
// key is absent.
func (f *ledgerFixture) metaFeatures() (uint64, bool) {
	f.t.Helper()
	var raw []byte
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		raw = append([]byte(nil), tx.Bucket([]byte(admissionMetaBucket)).Get([]byte("features"))...)
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	if len(raw) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(raw), true
}

func (f *ledgerFixture) putMetaFeatures(raw []byte) {
	f.t.Helper()
	if err := f.db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(admissionMetaBucket)).Put([]byte("features"), raw)
	}); err != nil {
		f.t.Fatal(err)
	}
}

// The live start records a live-only feature bit that every earlier build
// refuses as an unknown meta key, so a binary rolled back across the live
// start cannot open a ledger it would misread. A ledger that has not
// started live records none, and the marked ledger reopens.
func TestAdmissionLedgerLiveStartRecordsTheLiveFeature(t *testing.T) {
	f := newLedgerFixture(t)
	if _, found := f.metaFeatures(); found {
		t.Fatal("a ledger that never started live records features")
	}
	if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
		t.Fatal(err)
	}
	bits, found := f.metaFeatures()
	if !found || bits != 1 {
		t.Fatalf("features after the live start = %#x, recorded %v; want the live bit", bits, found)
	}
	if _, err := OpenAdmissionLedger(f.db, f.reg); err != nil {
		t.Fatalf("reopening a ledger with the live feature: %v", err)
	}
}

// A feature this binary does not know means a newer layout: the ledger is
// refused as a newer schema is. A malformed record is damage.
func TestAdmissionLedgerRefusesUnknownFeatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"unknown bit", binary.BigEndian.AppendUint64(nil, 1|1<<5), ErrAdmissionSchema},
		{"malformed", []byte{1}, admission.ErrCorruptRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			f.putMetaFeatures(tc.raw)
			if _, err := OpenAdmissionLedger(f.db, f.reg); !errors.Is(err, tc.want) {
				t.Fatalf("opening = %v, want %v", err, tc.want)
			}
		})
	}
}
