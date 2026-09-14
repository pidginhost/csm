package store

import (
	"fmt"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestFreeBytesWhileDatabaseGrows(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	initialSize, err := db.Size()
	if err != nil {
		t.Fatal(err)
	}

	// Keep sampling while writes force bbolt to replace its memory mapping.
	stop := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for samples := 0; ; samples++ {
			free, sampleErr := db.FreeBytes()
			if sampleErr != nil || free < 0 {
				t.Errorf("FreeBytes = %d, %v", free, sampleErr)
			}
			if samples == 0 {
				close(started)
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()
	<-started

	value := make([]byte, 4096)
	for batch := range 32 {
		if updateErr := db.bolt.Update(func(tx *bolt.Tx) error {
			b, bucketErr := tx.CreateBucketIfNotExists([]byte("growth"))
			if bucketErr != nil {
				return bucketErr
			}
			for i := range 100 {
				if putErr := b.Put([]byte(fmt.Sprintf("%04d", batch*100+i)), value); putErr != nil {
					return putErr
				}
			}
			return nil
		}); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	size, err := db.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size <= initialSize {
		t.Fatalf("database did not grow: before=%d after=%d", initialSize, size)
	}
}

func TestFreeBytesPendingPagesSurviveReopen(t *testing.T) {
	for _, pageSize := range []int{4096, 16384} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			statePath := t.TempDir()
			// A state file can originate on a host with a different page size.
			seed, err := bolt.Open(filepath.Join(statePath, "csm.db"), 0600, &bolt.Options{PageSize: pageSize})
			if err != nil {
				t.Fatal(err)
			}
			if closeErr := seed.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			db, err := Open(statePath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			value := make([]byte, 4096)
			if updateErr := db.bolt.Update(func(tx *bolt.Tx) error {
				b, bucketErr := tx.CreateBucket([]byte("pending"))
				if bucketErr != nil {
					return bucketErr
				}
				for i := range 1000 {
					if putErr := b.Put([]byte(fmt.Sprintf("%04d", i)), value); putErr != nil {
						return putErr
					}
				}
				return nil
			}); updateErr != nil {
				t.Fatal(updateErr)
			}
			// Hold an older snapshot so deleted pages remain pending, as they
			// can during a retention sweep alongside readers in the daemon.
			reader, err := db.bolt.Begin(false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Rollback() }()
			if updateErr := db.bolt.Update(func(tx *bolt.Tx) error {
				return tx.DeleteBucket([]byte("pending"))
			}); updateErr != nil {
				t.Fatal(updateErr)
			}
			st := db.bolt.Stats()
			if st.PendingPageN*pageSize < 1000*len(value) {
				t.Fatalf("deleted data is not pending: %+v", st)
			}
			free, err := db.FreeBytes()
			if err != nil {
				t.Fatal(err)
			}
			if want := int64(st.FreePageN+st.PendingPageN) * int64(pageSize); free != want {
				t.Fatalf("FreeBytes = %d, want %d including pending pages", free, want)
			}
			if rollbackErr := reader.Rollback(); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			if closeErr := db.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			reopened, err := Open(statePath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			reopenedFree, err := reopened.FreeBytes()
			if err != nil {
				t.Fatal(err)
			}
			if reopenedFree != free {
				t.Fatalf("FreeBytes changed across restart: live=%d reopened=%d", free, reopenedFree)
			}
		})
	}
}
