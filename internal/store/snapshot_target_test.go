package store

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestLedgerGuardRejectsLeakedArchivePages(t *testing.T) {
	archive := filepath.Join(closeLedger(t, restoreLedger(t, ledgerT0, true, "")), "csm.db")
	target := filepath.Join(closeLedger(t, restoreLedger(t, ledgerT0, true, "")), "csm.db")
	if err := CheckLedgerRestore(archive, target); err != nil {
		t.Fatal(err)
	}
	leakFreePages(t, archive)
	if err := CheckLedgerRestore(archive, target); !errors.Is(err, ErrLedgerBehind) {
		t.Fatalf("comparison with a damaged archive = %v, want ErrLedgerBehind", err)
	}
}

func TestFirewallImportRefusesDanglingTarget(t *testing.T) {
	snapshot := filepath.Join(t.TempDir(), "snapshot.db")
	writeSnapshot(t, snapshot, false)
	state := t.TempDir()
	missing := filepath.Join(t.TempDir(), "missing.db")
	if err := os.Symlink(missing, filepath.Join(state, "csm.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := mergeFirewallBucketsFromSnapshot(snapshot, state); err == nil {
		t.Error("firewall import accepted a dangling database link")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("stat after refusal = %v, want absent database", err)
	}
}

// bbolt needs a full first metadata probe to discover a custom page size.
// An initial file with tiny pages has a valid checksum but cannot be reopened.
func TestVerifyDatabaseRequiresReadableMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.db")
	db, err := bolt.Open(path, 0600, &bolt.Options{PageSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDatabase(path); err == nil {
		t.Fatal("accepted metadata bbolt cannot use to open the database")
	}
}

func TestVerifyDatabaseLimitsInlineBucketSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, createErr := tx.CreateBucket([]byte("rows"))
		if createErr != nil {
			return createErr
		}
		return b.Put([]byte("k"), []byte("v"))
	})
	if err = errors.Join(err, db.Close()); err != nil {
		t.Fatal(err)
	}
	if err = VerifyDatabase(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	order := binary.NativeEndian
	pageSize := os.Getpagesize()
	meta := data[16:80]
	if order.Uint64(data[pageSize+64:]) > order.Uint64(meta[48:]) {
		meta = data[pageSize+16 : pageSize+80]
	}
	page := data[order.Uint64(meta[16:])*uint64(pageSize):]
	bucket := page[16+order.Uint32(page[20:])+order.Uint32(page[24:]):]
	if order.Uint64(bucket) != 0 || order.Uint16(page[10:]) != 1 {
		t.Fatal("fixture needs a single inline bucket")
	}
	// Both values still fit inside the outer leaf.
	order.PutUint32(bucket[16+28:], uint32(pageSize/2))
	order.PutUint32(page[28:], order.Uint32(page[28:])+uint32(pageSize/2)-1)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDatabase(path); err == nil {
		t.Fatal("accepted an oversized inline bucket")
	}
}

func TestVerifyDatabaseChecksBranchChildren(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.db")
	const pageSize = 1024
	db, err := bolt.Open(path, 0600, &bolt.Options{PageSize: pageSize})
	if err != nil {
		t.Fatal(err)
	}
	var root uint64
	err = db.Update(func(tx *bolt.Tx) error {
		b, createErr := tx.CreateBucket([]byte("rows"))
		if createErr != nil {
			return createErr
		}
		var key [4]byte
		value := make([]byte, pageSize/8)
		for i := uint32(1); i <= 1000; i++ {
			binary.BigEndian.PutUint32(key[:], i)
			if putErr := b.Put(key[:], value); putErr != nil {
				return putErr
			}
		}
		return nil
	})
	if err == nil {
		err = db.View(func(tx *bolt.Tx) error {
			root = uint64(tx.Bucket([]byte("rows")).Root())
			return nil
		})
	}
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if err = VerifyDatabase(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	order := binary.NativeEndian
	branch := data[root*pageSize:]
	child := data[order.Uint64(branch[24:])*pageSize:]
	leaf := data[order.Uint64(child[24:])*pageSize:]
	if order.Uint16(branch[8:]) != snapshotBranch || order.Uint16(child[8:]) != snapshotBranch || order.Uint16(leaf[8:]) != snapshotLeaf {
		t.Fatal("fixture needs two branch levels above a leaf")
	}
	for _, tc := range []struct {
		name string
		edit func()
	}{
		{"branch with one child", func() { order.PutUint16(child[10:], 1) }},
		{"empty child leaf", func() { order.PutUint16(leaf[10:], 0) }},
		{"stale separator", func() { clear(branch[16+order.Uint32(branch[16:]):][:4]) }},
		{"mixed child levels", func() { copy(branch[24:32], child[24:32]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]byte(nil), data...)
			tc.edit()
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			copy(data, original)
			if err := VerifyDatabase(path); err == nil {
				t.Fatal("accepted malformed branch children")
			}
		})
	}
}
