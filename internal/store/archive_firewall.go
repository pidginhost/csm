package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// The durable firewall journal and its committed snapshot validate each
// other, so they move as one unit and are never merged key by key with
// another database's.
func firewallDurableBucket(name string) bool {
	switch name {
	case firewallActionsBucket, firewallBudgetBucket, firewallAuditBucket, firewallActionIndexBucket, firewallBudgetIndexBucket,
		firewallActionHistoryBucket, firewallMemberIndexBucket, firewallBatchMembersBucket, firewallSnapshotBucket:
		return true
	}
	for _, rows := range firewallSnapshotBuckets {
		if name == rows {
			return true
		}
	}
	return false
}

// firewallImportJournal reports whether tx holds a durable journal or
// snapshot. It refuses one that cannot be read or still has unresolved or
// undelivered work: an import must not replace or carry recovery evidence.
func firewallImportJournal(tx *bolt.Tx) (bool, error) {
	index, err := readFirewallJournalIndex(tx)
	if err != nil {
		return true, err
	}
	if index.PendingID != "" || len(index.Audit) > 0 {
		return true, fmt.Errorf("%w: firewall journal has outstanding work", firewall.ErrStateConflict)
	}
	if tx.Bucket([]byte(firewallSnapshotBucket)) == nil {
		if index.Initialized {
			return true, fmt.Errorf("%w: firewall journal has no snapshot", firewall.ErrStateCorrupt)
		}
		return false, nil
	}
	meta, err := readFirewallSnapshotMeta(tx)
	if err != nil {
		return true, err
	}
	rows, err := readFirewallSnapshotRows(tx, meta)
	if err != nil {
		return true, err
	}
	if _, err = decodeFirewallSnapshot(rows, meta); err != nil {
		return true, err
	}
	return true, nil
}

// Firewall buckets contain flat rows. Nested data must neither be copied as
// an empty value nor silently discarded when replacing a target journal.
func validateFirewallImportBuckets(tx *bolt.Tx) error {
	return tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
		if !isFirewallBucket(string(name)) {
			return nil
		}
		return bucket.ForEach(func(_, value []byte) error {
			if value == nil {
				return fmt.Errorf("%w: nested firewall bucket", firewall.ErrStateCorrupt)
			}
			return nil
		})
	})
}

// mergeFirewallBucketsFromSnapshot copies the snapshot's fw:* buckets into
// the target bbolt at statePath/csm.db in one transaction. A durable journal
// in the snapshot replaces the target's as a whole; a target journal the
// snapshot lacks is kept. Every other firewall bucket merges key by key,
// keeping destination-only keys. Returns the bucket names copied.
func mergeFirewallBucketsFromSnapshot(snapshotPath, statePath string) ([]string, error) {
	src, err := bolt.Open(snapshotPath, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("opening snapshot: %w", err)
	}
	defer func() { _ = src.Close() }()

	var merged []string
	err = src.View(func(stx *bolt.Tx) error {
		incoming, archiveErr := firewallImportJournal(stx)
		if archiveErr != nil {
			return fmt.Errorf("archive firewall journal: %w", archiveErr)
		}
		if shapeErr := validateFirewallImportBuckets(stx); shapeErr != nil {
			return shapeErr
		}
		// Refuse the source before creating a destination; general store
		// startup would commit unrelated initialization before validation.
		if mkdirErr := os.MkdirAll(statePath, 0700); mkdirErr != nil {
			return fmt.Errorf("creating target directory: %w", mkdirErr)
		}
		// bbolt otherwise commits during Open if the file has no persisted
		// freelist. Defer that write to the import's validated transaction.
		dst, openErr := bolt.Open(filepath.Join(statePath, "csm.db"), 0600, &bolt.Options{Timeout: 5 * time.Second, NoFreelistSync: true})
		if openErr != nil {
			return fmt.Errorf("opening target: %w", openErr)
		}
		defer func() { _ = dst.Close() }()
		dst.NoFreelistSync = false
		return dst.Update(func(dtx *bolt.Tx) error {
			local, localErr := firewallImportJournal(dtx)
			if localErr != nil {
				return fmt.Errorf("local firewall journal: %w", localErr)
			}
			if shapeErr := validateFirewallImportBuckets(dtx); shapeErr != nil {
				return fmt.Errorf("local firewall buckets: %w", shapeErr)
			}
			if incoming {
				// Collect names first: deleting while visiting the root cursor
				// can skip buckets after the tree changes.
				var names [][]byte
				if listErr := dtx.ForEach(func(name []byte, _ *bolt.Bucket) error {
					if firewallDurableBucket(string(name)) {
						names = append(names, append([]byte(nil), name...))
					}
					return nil
				}); listErr != nil {
					return listErr
				}
				for _, name := range names {
					if deleteErr := dtx.DeleteBucket(name); deleteErr != nil {
						return deleteErr
					}
				}
			}
			if mergeErr := stx.ForEach(func(name []byte, sb *bolt.Bucket) error {
				if !isFirewallBucket(string(name)) || local && !incoming && firewallDurableBucket(string(name)) {
					return nil
				}
				bucket, createErr := dtx.CreateBucketIfNotExists(name)
				if createErr != nil {
					return createErr
				}
				if copyErr := sb.ForEach(func(k, v []byte) error {
					return bucket.Put(append([]byte(nil), k...), append([]byte(nil), v...))
				}); copyErr != nil {
					return copyErr
				}
				merged = append(merged, string(name))
				return nil
			}); mergeErr != nil {
				return mergeErr
			}
			// Tentative config rollback is process-lifetime state. Disarm it
			// in this transaction so a late refusal cannot leave a partial import.
			if rollback := dtx.Bucket([]byte(fwRollbackBucket)); rollback != nil {
				return rollback.Delete([]byte(fwRollbackKey))
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(merged)
	return merged, nil
}
