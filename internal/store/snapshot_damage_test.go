package store

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// writeSnapshot writes a stopped database at path holding a browser session,
// a pending firewall rollback and one firewall row, every bucket the snapshot
// readers visit, plus a bucket nested on a page of its own. Without a synced
// freelist, bbolt rebuilds it on open by walking the pages.
func writeSnapshot(t *testing.T, path string, noFreelistSync bool) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, NoFreelistSync: noFreelistSync})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, row := range [][3]string{
			{browserSessionsBucket, "session", "verifier"},
			{fwRollbackBucket, fwRollbackKey, "{}"},
			{"fw:blocked", "192.0.2.1", "{}"},
		} {
			bucket, createErr := tx.CreateBucketIfNotExists([]byte(row[0]))
			if createErr != nil {
				return createErr
			}
			if putErr := bucket.Put([]byte(row[1]), []byte(row[2])); putErr != nil {
				return putErr
			}
		}
		parent, createErr := tx.CreateBucketIfNotExists([]byte("parent"))
		if createErr != nil {
			return createErr
		}
		nested, createErr := parent.CreateBucketIfNotExists([]byte("nested"))
		if createErr != nil {
			return createErr
		}
		for i := range 2 * os.Getpagesize() / 8 {
			if putErr := nested.Put(fmt.Appendf(nil, "%08d", i), []byte("row")); putErr != nil {
				return putErr
			}
		}
		return nil
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
}

// truncatePages cuts the database at path after its two meta pages, so the
// mapped pages past the end fault instead of reading garbage.
func truncatePages(t *testing.T, path string) {
	t.Helper()
	if err := os.Truncate(path, int64(2*os.Getpagesize())); err != nil {
		t.Fatal(err)
	}
}

// lastPage returns the offset of the last page the database at path uses,
// which bbolt writes the freelist to on commit.
func lastPage(t *testing.T, path string) int64 {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var used int64
	err = db.View(func(tx *bolt.Tx) error {
		used = tx.Size()
		return nil
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return used - int64(os.Getpagesize())
}

// truncateLastPage cuts the freelist page and leaves the bucket pages whole.
func truncateLastPage(t *testing.T, path string) {
	t.Helper()
	if err := os.Truncate(path, lastPage(t, path)); err != nil {
		t.Fatal(err)
	}
}

// corruptLastPage damages the freelist page and leaves the bucket pages whole.
func corruptLastPage(t *testing.T, path string) {
	t.Helper()
	corruptPageAt(t, path, lastPage(t, path))
}

// corruptPageAt overwrites the page at offset in the database at path.
func corruptPageAt(t *testing.T, path string, offset int64) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := offset; i < offset+int64(os.Getpagesize()); i++ {
		data[i] = 0xa5
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// corruptNestedPage damages only the first page of the nested bucket, so
// the root and every top-level bucket still read cleanly.
func corruptNestedPage(t *testing.T, path string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var page int64
	err = db.View(func(tx *bolt.Tx) error {
		page = int64(tx.Bucket([]byte("parent")).Bucket([]byte("nested")).Root())
		return nil
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	corruptPageAt(t, path, page*int64(os.Getpagesize()))
}

// A damaged snapshot reaches these readers from an archive being imported
// or restored, or from a damaged live database being exported. Each must
// refuse it with an error: no crash, no change to the snapshot or to the
// merge target, no file left beside it and no lock held.
func checkDamagedSnapshotReaders(t *testing.T, noFreelistSync bool, damage func(*testing.T, string)) {
	readers := []struct {
		name string
		read func(snapshot, target string) error
	}{
		{"list buckets", func(snapshot, _ string) error {
			_, err := listSnapshotBuckets(snapshot)
			return err
		}},
		{"merge firewall buckets", func(snapshot, target string) error {
			_, err := mergeFirewallBucketsFromSnapshot(snapshot, target)
			return err
		}},
		{"disarm firewall rollback", func(snapshot, _ string) error {
			return DisarmFirewallRollbackSnapshot(snapshot)
		}},
		{"disarm browser sessions", func(snapshot, _ string) error {
			return DisarmBrowserSessionsSnapshot(snapshot)
		}},
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			dir := t.TempDir()
			snapshot := filepath.Join(dir, "snapshot.db")
			writeSnapshot(t, snapshot, noFreelistSync)
			damage(t, snapshot)
			target := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			writeSnapshot(t, filepath.Join(target, "csm.db"), false)
			before, beforeTarget := treeOf(t, dir), treeOf(t, target)

			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("crashed on a damaged snapshot: %v", r)
					}
				}()
				return reader.read(snapshot, target)
			}()
			if err == nil {
				t.Fatal("read a damaged snapshot without an error")
			}
			if after := treeOf(t, dir); !sameTree(before, after) {
				t.Fatalf("refusal changed the snapshot directory: %v, was %v", after, before)
			}
			if after := treeOf(t, target); !sameTree(beforeTarget, after) {
				t.Fatal("refusal changed the merge target")
			}
			f, openErr := os.OpenFile(snapshot, os.O_RDWR, 0)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer func() { _ = f.Close() }()
			if lockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lockErr != nil {
				t.Fatalf("refusal kept a lock on the snapshot: %v", lockErr)
			}
		})
	}
}

func TestSnapshotReadersRefuseDamagedPages(t *testing.T) {
	t.Run("every page", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, corruptPages) })
	t.Run("freelist page", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, corruptLastPage) })
}

// bbolt rebuilds a missing freelist on a goroutine of its own, where a
// damaged page cannot be recovered. Run in a child for the same reason as
// the truncated test.
func TestSnapshotReadersRefuseDamagedPagesWithoutFreelist(t *testing.T) {
	inChild(t, "TestSnapshotReadersRefuseDamagedPagesWithoutFreelist", func() {
		t.Run("every page", func(t *testing.T) { checkDamagedSnapshotReaders(t, true, corruptPages) })
		t.Run("nested bucket page", func(t *testing.T) { checkDamagedSnapshotReaders(t, true, corruptNestedPage) })
	})
}

// Reading a page past the end of a truncated file raises a memory fault,
// which kills the process. Run in a child so that shows as a failure
// instead of ending the test binary.
func TestSnapshotReadersRefuseTruncatedPages(t *testing.T) {
	inChild(t, "TestSnapshotReadersRefuseTruncatedPages", func() {
		t.Run("after the meta pages", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, truncatePages) })
		t.Run("last page", func(t *testing.T) { checkDamagedSnapshotReaders(t, false, truncateLastPage) })
	})
}

// inChild runs check in a child test process, so a crash the process cannot
// recover from fails this test instead of ending the test binary.
func inChild(t *testing.T, name string, check func()) {
	t.Helper()
	if os.Getenv("CSM_TEST_SNAPSHOT_CHILD") == name {
		check()
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), "CSM_TEST_SNAPSHOT_CHILD="+name)
	output, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name)) {
		t.Fatalf("%s in a child: %v\n%s", name, err, output)
	}
}
