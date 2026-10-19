package store

import (
	"os"
	"path/filepath"
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
	if err := db.LearnUpdate(func(tx LearnTx) error { return tx.Put(LearnClustersBucket, []byte("c"), []byte("cluster")) }); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "snapshot.csmbak")
	if _, err := db.Export(ExportOptions{StatePath: statePath, DstPath: archivePath, Manifest: defaultManifest()}); err != nil {
		t.Fatal(err)
	}
	snapshotDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(snapshotDir, "csm.db"), archiveEntryBytes(t, archivePath, bboltSnapshotEntry), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, snapErr := Open(snapshotDir)
	if snapErr != nil {
		t.Fatal(snapErr)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	if err := snapshot.LearnView(func(tx LearnTx) error {
		v, err := tx.Get(LearnClustersBucket, []byte("c"))
		if err != nil || v != nil {
			t.Errorf("exported snapshot kept a learning record: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
