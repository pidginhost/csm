package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// rawFeatures are the feature bytes exactly as stored, and whether the key
// exists at all: a malformed value is present, not absent.
func (f *ledgerFixture) rawFeatures() ([]byte, bool) {
	f.t.Helper()
	var raw []byte
	if err := f.db.bolt.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket([]byte(admissionMetaBucket)).Get([]byte("features")); v != nil {
			raw = append([]byte{}, v...)
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return raw, raw != nil
}

// featuresIn reads the feature bytes of the bbolt file at path.
func featuresIn(t *testing.T, path string) []byte {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var raw []byte
	if err = db.View(func(tx *bolt.Tx) error {
		raw = append([]byte(nil), tx.Bucket([]byte(admissionMetaBucket)).Get([]byte("features"))...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

// Opening a ledger reads its feature bits: none, zero and the live bit
// open, a bit this binary does not know is a newer schema and a malformed
// value is damage. A refused open rewrites nothing. The readers the
// firewall uses at startup take no ledger handle and read the ledger
// whatever the bits say, so a build that predates a feature still restores
// its blocks.
func TestAdmissionLedgerFeatureReaderCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		open error
	}{
		{"absent", nil, nil},
		{"zero", binary.BigEndian.AppendUint64(nil, 0), nil},
		{"live", binary.BigEndian.AppendUint64(nil, 1), nil},
		{"unknown bit", binary.BigEndian.AppendUint64(nil, 1|1<<5), ErrAdmissionSchema},
		{"malformed", []byte{1}, admission.ErrCorruptRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			if raw, found := f.rawFeatures(); found {
				t.Fatalf("a ledger that never started live stores features %x", raw)
			}
			if tc.raw != nil {
				f.putMetaFeatures(tc.raw)
			}
			before := f.snapshot()
			if _, err := OpenAdmissionLedger(f.db, f.reg); !errors.Is(err, tc.open) {
				t.Fatalf("opening = %v, want %v", err, tc.open)
			}
			if !reflect.DeepEqual(before, f.snapshot()) {
				t.Fatal("opening rewrote the ledger")
			}
			if _, err := ReadUnresolvedIntents(f.db); err != nil {
				t.Errorf("reading intents: %v", err)
			}
			if _, err := ReadAdmissionClock(f.db); err != nil {
				t.Errorf("reading the clock: %v", err)
			}
			if _, err := ReadUnprovenBlockActions(f.db, []string{"act_missing"}); err != nil {
				t.Errorf("reading unproven actions: %v", err)
			}
			if _, err := ReadSettledBlockActions(f.db, []string{"act_missing"}); err != nil {
				t.Errorf("reading settled actions: %v", err)
			}
		})
	}
}

// The feature bits travel with every copy of the database, byte for byte:
// an export, the import of it onto a fresh host and a compaction. A copy
// that dropped them would hand a live ledger to a build that cannot run
// it. A bit this binary does not know is copied as it is and still refused
// at open. Merging only the firewall part changes no admission record of
// the target.
func TestAdmissionLedgerFeaturesSurviveCopies(t *testing.T) {
	for _, tc := range []struct {
		name string
		bits uint64
		open error
	}{
		{"live", 1, nil},
		{"unknown bit", 1 | 1<<5, ErrAdmissionSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedgerFixture(t)
			_, a := f.admitted(time.Hour)
			if _, _, _, err := f.l.Execute(a.Attempt.ID); err != nil {
				t.Fatal(err)
			}
			if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
				t.Fatal(err)
			}
			if raw, found := f.rawFeatures(); !found || !bytes.Equal(raw, binary.BigEndian.AppendUint64(nil, 1)) {
				t.Fatalf("the live start stored features %x (present %v), want the live bit", raw, found)
			}
			want := binary.BigEndian.AppendUint64(nil, tc.bits)
			f.putMetaFeatures(want)
			clock, err := ReadAdmissionClock(f.db)
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Dir(f.db.Path())
			archive := filepath.Join(t.TempDir(), "snapshot.csmbak")
			res, err := f.db.Export(ExportOptions{StatePath: state, DstPath: archive, Manifest: defaultManifest()})
			if err != nil {
				t.Fatal(err)
			}
			staged := filepath.Join(t.TempDir(), "staged.db")
			snapshot := archiveEntryBytes(t, archive, bboltSnapshotEntry)
			if err = os.WriteFile(staged, snapshot, 0o600); err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(snapshot); hex.EncodeToString(sum[:]) != res.BboltSHA256 {
				t.Fatal("the manifest does not describe the exported database")
			}
			if got := featuresIn(t, staged); !bytes.Equal(got, want) {
				t.Fatalf("exported features = %x, want %x", got, want)
			}
			compacted := filepath.Join(t.TempDir(), "compacted.db")
			if _, _, err = f.db.CompactInto(compacted, 0); err != nil {
				t.Fatal(err)
			}
			if got := featuresIn(t, compacted); !bytes.Equal(got, want) {
				t.Fatalf("compacted features = %x, want %x", got, want)
			}
			fresh := t.TempDir()
			if _, err = Import(ImportOptions{SrcPath: archive, StatePath: fresh, RulesPath: t.TempDir(), Only: "all", CurrentPlatform: defaultPlatform()}); err != nil {
				t.Fatal(err)
			}
			if got := featuresIn(t, filepath.Join(fresh, "csm.db")); !bytes.Equal(got, want) {
				t.Fatalf("imported features = %x, want %x", got, want)
			}
			restored, err := Open(fresh)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = restored.Close() }()
			l, err := OpenAdmissionLedger(restored, f.reg)
			if !errors.Is(err, tc.open) {
				t.Fatalf("opening the imported ledger = %v, want %v", err, tc.open)
			}
			if tc.open == nil && !l.LiveStarted() {
				t.Fatal("the imported ledger forgot its live start")
			}
			if got, readErr := ReadAdmissionClock(restored); readErr != nil || got != clock {
				t.Fatalf("imported clock = %+v (%v), want %+v", got, readErr, clock)
			}
			if intents, readErr := ReadUnresolvedIntents(restored); readErr != nil || len(intents) != 1 {
				t.Fatalf("imported unresolved intents = %d (%v), want the running attempt's", len(intents), readErr)
			}

			target := newLedgerFixture(t)
			target.begin()
			target.observedArrival("192.0.2.77", "offset=77")
			untouched := target.snapshot()
			targetState := filepath.Dir(target.db.Path())
			if err = target.db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = Import(ImportOptions{SrcPath: archive, StatePath: targetState, RulesPath: t.TempDir(), Only: "firewall", CurrentPlatform: defaultPlatform()}); err != nil {
				t.Fatal(err)
			}
			if target.db, err = Open(targetState); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = target.db.Close() }()
			if !reflect.DeepEqual(untouched, target.snapshot()) {
				t.Fatal("a firewall-only import changed the target's admission records")
			}
		})
	}
}
