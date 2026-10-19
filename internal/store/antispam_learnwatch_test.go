package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The watcher's folder and seen state follows the learning ledger: created
// on open, reachable through LearnTx, and never carried by an export.
func TestWatchBucketsCreatedAndOmittedFromExport(t *testing.T) {
	statePath := t.TempDir()
	db, err := Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if len(WatchBuckets) != 2 {
		t.Fatalf("%d watcher buckets", len(WatchBuckets))
	}
	if err = db.LearnUpdate(func(tx LearnTx) error {
		for _, b := range WatchBuckets {
			if !db.HasBucket(b) {
				t.Errorf("missing bucket %q", b)
			}
			if putErr := tx.Put(b, []byte("k"), []byte("watch-test-record")); putErr != nil {
				return putErr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "snapshot.csmbak")
	if _, err = db.Export(ExportOptions{StatePath: statePath, DstPath: archivePath, Manifest: defaultManifest()}); err != nil {
		t.Fatal(err)
	}
	snapshotBytes := archiveEntryBytes(t, archivePath, bboltSnapshotEntry)
	if bytes.Contains(snapshotBytes, []byte("watch-test-record")) {
		t.Fatal("exported snapshot retained watcher state")
	}
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "csm.db"), snapshotBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snap.Close() })
	if err = snap.LearnView(func(tx LearnTx) error {
		for _, b := range WatchBuckets {
			if iterErr := tx.ForEach(b, func(_, _ []byte) error {
				t.Errorf("snapshot kept a record in %s", b)
				return nil
			}); iterErr != nil {
				return iterErr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
