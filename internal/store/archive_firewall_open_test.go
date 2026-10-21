package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

func TestArchiveImportFirewallWithoutPersistedFreelist(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "accepted"
		if pending {
			name = "refused"
		}
		t.Run(name, func(t *testing.T) {
			sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
			archive := exportFirewallArchive(t, source, sourcePath)
			targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", !pending, !pending, "member-8", "member-9")
			target.bolt.NoFreelistSync = true
			if err := target.bolt.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte(fwRollbackBucket)).Put([]byte(fwRollbackKey), []byte("local pending"))
			}); err != nil {
				t.Fatal(err)
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			before := readFirewallImportImage(t, targetPath)
			err := importFirewallArchive(archive, targetPath)
			if pending {
				if !errors.Is(err, firewall.ErrStateConflict) {
					t.Fatalf("pending target refusal = %v", err)
				}
				assertFirewallImportUnchanged(t, targetPath, before)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			after := readFirewallImportImage(t, targetPath)
			if after.txid != before.txid+1 {
				t.Errorf("import committed %d transactions, want one", after.txid-before.txid)
			}
			// A successful import must persist the freelist in its own commit,
			// rather than making the next ordinary writer finish the import.
			reopened, err := bolt.Open(filepath.Join(targetPath, "csm.db"), 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
			assertFirewallImportUnchanged(t, targetPath, after)
		})
	}
}
