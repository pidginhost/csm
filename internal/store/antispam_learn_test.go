package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestOpenCreatesLearningBuckets(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, name := range LearnBuckets {
		if !db.HasBucket(name) {
			t.Errorf("missing bucket %q", name)
		}
	}
	if len(LearnBuckets) != 8 {
		t.Fatalf("%d learning buckets", len(LearnBuckets))
	}
}

func TestLearnTxStaysInLearningBuckets(t *testing.T) {
	db, openErr := Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer func() { _ = db.Close() }()
	if err := db.LearnUpdate(func(tx LearnTx) error {
		if err := tx.Put("meta", []byte("k"), []byte("v")); err == nil {
			t.Error("wrote outside the learning buckets")
		}
		if err := tx.Put(LearnTargetsBucket, []byte("d"), []byte("t")); err != nil {
			return err
		}
		first, err := tx.NextSequence(LearnClustersBucket)
		if err != nil || first != 1 {
			t.Errorf("first sequence %d err %v", first, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.LearnView(func(tx LearnTx) error {
		v, getErr := tx.Get(LearnTargetsBucket, []byte("d"))
		if getErr != nil || string(v) != "t" {
			t.Errorf("read %q err %v", v, getErr)
		}
		if err := tx.Put(LearnTargetsBucket, []byte("x"), []byte("y")); err == nil {
			t.Error("wrote in a read transaction")
		}
		n := 0
		if err := tx.ForEach(LearnTargetsBucket, func(k, v []byte) error { n++; return nil }); err != nil || n != 1 {
			t.Errorf("iterated %d err %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// CSM's state archive carries no learning ledger: without the anchor bodies
// and hash keys it cannot restore learning, and an old ledger merged over a
// live namespace would steer audits back to stale targets (spec 7.4).
func TestArchiveExportOmitsLearningLedger(t *testing.T) {
	statePath := t.TempDir()
	db, openErr := Open(statePath)
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedLearningRecords(t, db)
	archivePath := filepath.Join(t.TempDir(), "snapshot.csmbak")
	if _, err := db.Export(ExportOptions{StatePath: statePath, DstPath: archivePath, Manifest: defaultManifest()}); err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(archiveEntryBytes(t, archivePath, manifestEntry), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, bucket := range LearnBuckets {
		if slices.Contains(manifest.BboltBuckets, bucket) {
			t.Errorf("export manifest contains %s", bucket)
		}
	}
	snapshotDir := t.TempDir()
	snapshotBytes := archiveEntryBytes(t, archivePath, bboltSnapshotEntry)
	if bytes.Contains(snapshotBytes, []byte("learning-test-record")) {
		t.Error("exported snapshot retained learning data in its pages")
	}
	if err := os.WriteFile(filepath.Join(snapshotDir, "csm.db"), snapshotBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, snapErr := Open(snapshotDir)
	if snapErr != nil {
		t.Fatal(snapErr)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	assertNoLearningRecords(t, snapshot)
	if err := db.LearnView(func(tx LearnTx) error {
		for _, bucket := range LearnBuckets {
			v, err := tx.Get(bucket, []byte("record"))
			if err != nil || string(v) != "learning-test-record" {
				t.Errorf("export changed live learning data in %s: %v", bucket, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveImportOmitsLearningFromOlderArchive(t *testing.T) {
	statePath := t.TempDir()
	db, openErr := Open(statePath)
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedLearningRecords(t, db)
	archivePath := filepath.Join(t.TempDir(), "snapshot.csmbak")
	if _, err := db.Export(ExportOptions{StatePath: statePath, DstPath: archivePath, Manifest: defaultManifest()}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	unsanitized, readErr := os.ReadFile(filepath.Join(statePath, "csm.db"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	hash := sha256.Sum256(unsanitized)
	legacyArchive := filepath.Join(t.TempDir(), "legacy.csmbak")
	rewriteArchive(t, archivePath, legacyArchive, func(name string, data []byte) ([]byte, bool) {
		switch name {
		case manifestEntry:
			var manifest Manifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.BboltSHA256 = hex.EncodeToString(hash[:])
			manifest.BboltBuckets = append(manifest.BboltBuckets, LearnBuckets...)
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			return encoded, true
		case bboltSnapshotEntry:
			return unsanitized, true
		default:
			return data, true
		}
	})
	restoredState := t.TempDir()
	result, err := Import(ImportOptions{SrcPath: legacyArchive, StatePath: restoredState, Only: "all", CurrentPlatform: defaultPlatform()})
	if err != nil {
		t.Fatal(err)
	}
	for _, bucket := range LearnBuckets {
		if slices.Contains(result.BucketsRestored, bucket) {
			t.Errorf("import reported stripped bucket %s as restored", bucket)
		}
	}
	restoredBytes, err := os.ReadFile(filepath.Join(restoredState, "csm.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(restoredBytes, []byte("learning-test-record")) {
		t.Error("import retained learning data in its pages")
	}
	restoredDB, err := Open(restoredState)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restoredDB.Close() })
	assertNoLearningRecords(t, restoredDB)
}

func seedLearningRecords(t *testing.T, db *DB) {
	t.Helper()
	if err := db.LearnUpdate(func(tx LearnTx) error {
		for _, bucket := range LearnBuckets {
			if err := tx.Put(bucket, []byte("record"), []byte("learning-test-record")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertNoLearningRecords(t *testing.T, db *DB) {
	t.Helper()
	if err := db.LearnView(func(tx LearnTx) error {
		for _, bucket := range LearnBuckets {
			if err := tx.ForEach(bucket, func(_, _ []byte) error {
				t.Errorf("snapshot kept a learning record in %s", bucket)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
