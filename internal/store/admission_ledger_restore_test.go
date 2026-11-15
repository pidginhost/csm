package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	bolt "go.etcd.io/bbolt"
)

// restoreLedger is a ledger fixture whose clock reads wall, started live
// when live is set, with a firewall state file holding fwState beside it.
// Its database is closed, as a stopped daemon leaves it.
func restoreLedger(t *testing.T, wall time.Time, live bool, fwState string) *ledgerFixture {
	t.Helper()
	f := newLedgerFixture(t)
	if wall.After(f.wall) {
		f.tickAt(wall)
	}
	if live {
		if err := f.l.StartLive(admission.LegacyHandover{}); err != nil {
			t.Fatal(err)
		}
	}
	if fwState != "" {
		dir := filepath.Join(filepath.Dir(f.db.Path()), "firewall")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(fwState), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// exportLedger writes f's state directory to an archive and closes f.
func exportLedger(t *testing.T, f *ledgerFixture) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "snapshot.csmbak")
	if _, err := f.db.Export(ExportOptions{StatePath: filepath.Dir(f.db.Path()), DstPath: archive, Manifest: defaultManifest()}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	return archive
}

// closeLedger closes f and returns its state directory.
func closeLedger(t *testing.T, f *ledgerFixture) string {
	t.Helper()
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(f.db.Path())
}

func readStateFiles(t *testing.T, dir string) (db, fw []byte) {
	t.Helper()
	db, err := os.ReadFile(filepath.Join(dir, "csm.db"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	fw, err = os.ReadFile(filepath.Join(dir, "firewall", "state.json"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return db, fw
}

// An import that would put an older ledger, or firewall state saved beside
// one, over a ledger that started live is refused unless forced, and the
// refusal leaves the target as it was. The firewall-only part touches
// neither and is not refused.
func TestImportRefusesALedgerBehindALiveTarget(t *testing.T) {
	later := ledgerT0.Add(time.Hour)
	for _, tc := range []struct {
		name                  string
		archiveAt, targetAt   time.Time
		archiveLive, targetOn bool
		only                  string
		force                 bool
		want                  string
	}{
		{"target live and archive not", ledgerT0, ledgerT0, false, true, "all", false, "never started live"},
		{"archive clock behind", ledgerT0, later, true, true, "all", false, "clock reads 2024-01-02T12:00:00Z, this host's 2024-01-02T13:00:00Z"},
		{"same clock", ledgerT0, ledgerT0, true, true, "all", false, ""},
		{"archive newer", later, ledgerT0, true, true, "all", false, ""},
		{"target not live", ledgerT0, later, false, false, "all", false, ""},
		{"forced", ledgerT0, later, false, true, "all", true, ""},
		{"baseline behind", ledgerT0, later, true, true, "baseline", false, "clock reads"},
		{"baseline forced", ledgerT0, ledgerT0, false, true, "baseline", true, ""},
		{"firewall buckets only", ledgerT0, later, false, true, "firewall", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := exportLedger(t, restoreLedger(t, tc.archiveAt, tc.archiveLive, "archive"))
			target := closeLedger(t, restoreLedger(t, tc.targetAt, tc.targetOn, "target"))
			beforeDB, beforeFW := readStateFiles(t, target)
			_, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: tc.only, Force: tc.force, CurrentPlatform: defaultPlatform()})
			afterDB, afterFW := readStateFiles(t, target)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("import refused: %v", err)
				}
				if tc.only != "firewall" && string(afterFW) != "archive" {
					t.Fatalf("firewall state after import = %q, want the archive's", afterFW)
				}
				return
			}
			if !errors.Is(err, ErrLedgerBehind) || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "--force") {
				t.Fatalf("import error = %v, want a behind refusal naming %q and --force", err, tc.want)
			}
			if !bytes.Equal(beforeDB, afterDB) || !bytes.Equal(beforeFW, afterFW) {
				t.Fatal("a refused import changed the target")
			}
		})
	}
}

// Disaster recovery onto a host without a ledger, and a baseline archive
// that carries no firewall state, have nothing to put behind.
func TestImportWithoutALiveLedgerToProtect(t *testing.T) {
	t.Run("no target database", func(t *testing.T) {
		archive := exportLedger(t, restoreLedger(t, ledgerT0, false, "archive"))
		target := t.TempDir()
		if _, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: "all", CurrentPlatform: defaultPlatform()}); err != nil {
			t.Fatalf("import onto an empty host: %v", err)
		}
	})
	t.Run("baseline without firewall state", func(t *testing.T) {
		archive := exportLedger(t, restoreLedger(t, ledgerT0, false, ""))
		target := closeLedger(t, restoreLedger(t, ledgerT0.Add(time.Hour), true, "target"))
		if _, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: "baseline", CurrentPlatform: defaultPlatform()}); err != nil {
			t.Fatalf("baseline without firewall state: %v", err)
		}
		if _, fw := readStateFiles(t, target); string(fw) != "target" {
			t.Fatalf("firewall state = %q, want the target's", fw)
		}
	})
}

// A target ledger this binary cannot read does not block the import that
// repairs it. An archive ledger it cannot read counts as behind a live
// target.
func TestImportUnreadableLedgers(t *testing.T) {
	unknown := binary.BigEndian.AppendUint64(nil, featureLive|1<<5)
	t.Run("unreadable target", func(t *testing.T) {
		archive := exportLedger(t, restoreLedger(t, ledgerT0, false, "archive"))
		f := restoreLedger(t, ledgerT0.Add(time.Hour), true, "target")
		f.putMetaFeatures(unknown)
		target := closeLedger(t, f)
		if _, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: "all", CurrentPlatform: defaultPlatform()}); err != nil {
			t.Fatalf("import over an unreadable ledger: %v", err)
		}
	})
	t.Run("unreadable archive", func(t *testing.T) {
		f := restoreLedger(t, ledgerT0.Add(time.Hour), true, "archive")
		f.putMetaFeatures(unknown)
		archive := exportLedger(t, f)
		target := closeLedger(t, restoreLedger(t, ledgerT0, true, "target"))
		beforeDB, _ := readStateFiles(t, target)
		_, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: "all", CurrentPlatform: defaultPlatform()})
		if !errors.Is(err, ErrLedgerBehind) || !strings.Contains(err.Error(), "cannot be read") || !strings.Contains(err.Error(), "--force") {
			t.Fatalf("import error = %v, want a refusal for an unreadable archive ledger", err)
		}
		if afterDB, _ := readStateFiles(t, target); !bytes.Equal(beforeDB, afterDB) {
			t.Fatal("a refused import changed the target database")
		}
	})
}

// treeOf is every path under dir with its mode and, for a file, its bytes.
func treeOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		entry := info.Mode().String()
		if info.Mode().IsRegular() {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			entry += ":" + string(data)
		}
		out[rel] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// A refused import writes nothing anywhere: every file of the state
// directory and the rules directory keeps its bytes and mode, and no
// staging file is left beside them.
func TestLedgerRestoreGuardLeavesTargetsUntouched(t *testing.T) {
	malformed := []byte{1}
	for _, tc := range []struct {
		name     string
		only     string
		features []byte
	}{
		{"all", "all", nil},
		{"baseline", "baseline", nil},
		{"archive features malformed", "all", malformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := restoreLedger(t, ledgerT0, tc.features != nil, "archive")
			if tc.features != nil {
				src.putMetaFeatures(tc.features)
			}
			archive := exportLedger(t, src)
			target := closeLedger(t, restoreLedger(t, ledgerT0.Add(time.Hour), true, "target"))
			rules := t.TempDir()
			for path, body := range map[string]string{
				filepath.Join(target, "integrity.json"): "kept state",
				filepath.Join(rules, "local.yar"):       "kept rule",
			} {
				if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			state, ruleTree := treeOf(t, target), treeOf(t, rules)
			_, err := Import(ImportOptions{SrcPath: archive, StatePath: target, RulesPath: rules, Only: tc.only, CurrentPlatform: defaultPlatform()})
			if !errors.Is(err, ErrLedgerBehind) {
				t.Fatalf("import error = %v, want a behind refusal", err)
			}
			if !sameTree(state, treeOf(t, target)) || !sameTree(ruleTree, treeOf(t, rules)) {
				t.Fatalf("a refused import changed the target:\nstate %v\nrules %v", treeOf(t, target), treeOf(t, rules))
			}
		})
	}
}

// ledgerPositionOf opens the ledger in the state directory dir and reports
// whether it started live and its clock.
func ledgerPositionOf(t *testing.T, dir string) (bool, time.Time) {
	t.Helper()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	reg, _, _, _ := newLedgerRegistry(t)
	l, err := OpenAdmissionLedger(db, reg)
	if err != nil {
		t.Fatal(err)
	}
	clock, err := ReadAdmissionClock(db)
	if err != nil {
		t.Fatal(err)
	}
	return l.LiveStarted(), clock.Now()
}

// A forced import really replaces what it says: the database and its
// clock for the whole archive, the firewall state file for the baseline
// part, which leaves the database alone.
func TestImportForcedRestoresTheArchive(t *testing.T) {
	for _, only := range []string{"all", "baseline"} {
		t.Run(only, func(t *testing.T) {
			archive := exportLedger(t, restoreLedger(t, ledgerT0, false, "archive"))
			target := closeLedger(t, restoreLedger(t, ledgerT0.Add(time.Hour), true, "target"))
			beforeDB, _ := readStateFiles(t, target)
			if _, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: only, Force: true, CurrentPlatform: defaultPlatform()}); err != nil {
				t.Fatal(err)
			}
			afterDB, fw := readStateFiles(t, target)
			if string(fw) != "archive" {
				t.Fatalf("firewall state = %q, want the archive's", fw)
			}
			live, clock := ledgerPositionOf(t, target)
			if only == "baseline" {
				if !bytes.Equal(beforeDB, afterDB) || !live {
					t.Fatal("a baseline import changed the database")
				}
				return
			}
			if live || !clock.Equal(ledgerT0) {
				t.Fatalf("ledger after a forced import: live %t, clock %v; want the archive's", live, clock)
			}
		})
	}
}

// The firewall part merges firewall buckets beside a live ledger without
// touching an admission record or the firewall state file, however old
// the archive is.
func TestImportFirewallOnlyBesideALiveLedger(t *testing.T) {
	src := restoreLedger(t, ledgerT0, false, "archive")
	if err := src.db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("fw:blocked"))
		if err != nil {
			return err
		}
		return b.Put([]byte("203.0.113.9"), []byte("merged"))
	}); err != nil {
		t.Fatal(err)
	}
	archive := exportLedger(t, src)
	f := restoreLedger(t, ledgerT0.Add(time.Hour), true, "target")
	admissionRows := f.snapshot()
	target := closeLedger(t, f)
	if _, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: "firewall", CurrentPlatform: defaultPlatform()}); err != nil {
		t.Fatal(err)
	}
	if _, fw := readStateFiles(t, target); string(fw) != "target" {
		t.Fatalf("firewall state file = %q, want the target's", fw)
	}
	var err error
	if f.db, err = Open(target); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.db.Close() }()
	if !reflect.DeepEqual(admissionRows, f.snapshot()) {
		t.Fatal("a firewall-only import changed admission records")
	}
	var merged []byte
	if err = f.db.bolt.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte("fw:blocked")); b != nil {
			merged = append([]byte(nil), b.Get([]byte("203.0.113.9"))...)
		}
		return nil
	}); err != nil || string(merged) != "merged" {
		t.Fatalf("firewall bucket after the import = %q (%v), want the archive's entry", merged, err)
	}
}

// --force lifts only the ledger comparison. An archive that is not one,
// and an archive from another platform, are refused as before.
func TestImportForceKeepsOtherRefusals(t *testing.T) {
	target := closeLedger(t, restoreLedger(t, ledgerT0.Add(time.Hour), true, "target"))
	garbage := filepath.Join(t.TempDir(), "garbage.csmbak")
	if err := os.WriteFile(garbage, []byte("not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(ImportOptions{SrcPath: garbage, StatePath: target, Only: "all", Force: true, CurrentPlatform: defaultPlatform()}); err == nil || errors.Is(err, ErrLedgerBehind) {
		t.Fatalf("forced import of garbage = %v, want the archive error", err)
	}
	archive := exportLedger(t, restoreLedger(t, ledgerT0, false, "archive"))
	other := map[string]string{"os": "linux", "panel": "cpanel", "webserver": "apache"}
	before := treeOf(t, target)
	if _, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: "all", Force: true, CurrentPlatform: other}); err == nil || errors.Is(err, ErrLedgerBehind) {
		t.Fatalf("forced import across platforms = %v, want the platform refusal", err)
	}
	if !sameTree(before, treeOf(t, target)) {
		t.Fatal("a refused forced import changed the target")
	}
}

// A damaged target never panics the comparison and never blocks its own
// repair: a live ledger that lost its queue-state bucket, and one whose
// feature bytes are malformed, both take the import.
func TestImportOverADamagedLiveLedger(t *testing.T) {
	for name, damage := range map[string]func(*ledgerFixture){
		"no queue state": func(f *ledgerFixture) {
			if err := f.db.bolt.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(admissionQueueStateBucket)) }); err != nil {
				t.Fatal(err)
			}
		},
		"malformed features": func(f *ledgerFixture) { f.putMetaFeatures([]byte{1}) },
	} {
		t.Run(name, func(t *testing.T) {
			archive := exportLedger(t, restoreLedger(t, ledgerT0, false, "archive"))
			f := restoreLedger(t, ledgerT0.Add(time.Hour), true, "target")
			damage(f)
			target := closeLedger(t, f)
			if _, err := Import(ImportOptions{SrcPath: archive, StatePath: target, Only: "all", CurrentPlatform: defaultPlatform()}); err != nil {
				t.Fatalf("import over a damaged ledger: %v", err)
			}
			if _, fw := readStateFiles(t, target); string(fw) != "archive" {
				t.Fatalf("firewall state = %q, want the archive's", fw)
			}
		})
	}
}
