package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

type firewallImportImage struct {
	bytes []byte
	txid  int
}

// Measure the stopped file without running store startup or migrations.
func readFirewallImportImage(t *testing.T, statePath string) firewallImportImage {
	t.Helper()
	path := filepath.Join(statePath, "csm.db")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.View(func(tx *bolt.Tx) error { id = tx.ID(); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return firewallImportImage{bytes: raw, txid: id}
}

func assertFirewallImportUnchanged(t *testing.T, statePath string, before firewallImportImage) {
	t.Helper()
	after := readFirewallImportImage(t, statePath)
	if after.txid != before.txid || !bytes.Equal(after.bytes, before.bytes) {
		t.Fatalf("refused import changed destination bytes or transaction ID: %d, want %d", after.txid, before.txid)
	}
}

func rawFirewallImportTarget(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	db, err := bolt.Open(filepath.Join(path, "csm.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("sentinel"))
		if err != nil {
			return err
		}
		return b.Put([]byte("untouched"), []byte("value"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestArchiveImportFirewallRefusalDoesNotInitialize(t *testing.T) {
	for _, kind := range []string{"raw", "initialized"} {
		t.Run(kind, func(t *testing.T) {
			sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
			archive := exportFirewallArchive(t, source, sourcePath)
			var targetPath string
			if kind == "raw" {
				targetPath = rawFirewallImportTarget(t)
				db, err := bolt.Open(filepath.Join(targetPath, "csm.db"), 0600, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Update(func(tx *bolt.Tx) error {
					_, err := tx.CreateBucket([]byte(firewallActionIndexBucket))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				path, target := firewallJournalHost(t, targetFirewallState(), "batch-t", false, false, "member-8", "member-9")
				targetPath = path
				if err := target.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before := readFirewallImportImage(t, targetPath)
			want := firewall.ErrStateConflict
			if kind == "raw" {
				want = firewall.ErrStateCorrupt
			}
			if err := importFirewallArchive(archive, targetPath); !errors.Is(err, want) {
				t.Fatalf("local refusal = %v, want %v", err, want)
			}
			assertFirewallImportUnchanged(t, targetPath, before)
		})
	}
}

func TestArchiveImportFirewallRefusesIncompleteUnits(t *testing.T) {
	cases := []struct{ name, bucket string }{
		{"orphan actions", firewallActionsBucket},
		{"orphan audit", firewallAuditBucket},
		{"orphan budget", firewallBudgetBucket},
		{"orphan budget index", firewallBudgetIndexBucket},
		{"orphan history", firewallActionHistoryBucket},
		{"orphan member index", firewallMemberIndexBucket},
		{"orphan member list", firewallBatchMembersBucket},
		{"missing snapshot", ""},
	}
	for _, side := range []string{"source", "destination"} {
		for _, c := range cases {
			t.Run(side+"/"+c.name, func(t *testing.T) {
				sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
				targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", true, true, "member-8", "member-9")
				damaged := source
				if side == "destination" {
					damaged = target
				}
				if err := damaged.bolt.Update(func(tx *bolt.Tx) error {
					if c.bucket == "" {
						return tx.DeleteBucket([]byte(firewallSnapshotBucket))
					}
					for _, name := range []string{firewallSnapshotBucket, firewallActionIndexBucket, firewallActionsBucket, firewallAuditBucket, firewallBudgetBucket, firewallBudgetIndexBucket, firewallActionHistoryBucket, firewallMemberIndexBucket, firewallBatchMembersBucket} {
						if tx.Bucket([]byte(name)) != nil {
							if err := tx.DeleteBucket([]byte(name)); err != nil {
								return err
							}
						}
					}
					_, err := tx.CreateBucket([]byte(c.bucket))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				archive := exportFirewallArchive(t, source, sourcePath)
				if err := target.Close(); err != nil {
					t.Fatal(err)
				}
				before := readFirewallImportImage(t, targetPath)
				if err := importFirewallArchive(archive, targetPath); !errors.Is(err, firewall.ErrStateCorrupt) {
					t.Fatalf("incomplete durable unit imported: %v, want corruption refusal", err)
				}
				assertFirewallImportUnchanged(t, targetPath, before)
			})
		}
	}
}

func TestArchiveImportFirewallRejectsSourceBeforeCreatingTarget(t *testing.T) {
	sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", false, false, "member-1", "member-2")
	archive := exportFirewallArchive(t, source, sourcePath)
	targetPath := filepath.Join(t.TempDir(), "absent")
	if err := importFirewallArchive(archive, targetPath); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("pending archive refusal = %v", err)
	}
	if _, err := os.Stat(targetPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused source created destination: %v", err)
	}
	existingPath := rawFirewallImportTarget(t)
	before := readFirewallImportImage(t, existingPath)
	if err := importFirewallArchive(archive, existingPath); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("pending archive refusal over raw destination = %v", err)
	}
	assertFirewallImportUnchanged(t, existingPath, before)
}

func TestArchiveImportFirewallMalformedTargetPreservesRollback(t *testing.T) {
	for _, failure := range []string{"copy", "disarm"} {
		t.Run(failure, func(t *testing.T) {
			sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
			if err := source.bolt.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucket([]byte("fw:zz-late"))
				if err != nil {
					return err
				}
				return b.Put([]byte("collision"), []byte("incoming"))
			}); err != nil {
				t.Fatal(err)
			}
			archive := exportFirewallArchive(t, source, sourcePath)
			targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", true, true, "member-8", "member-9")
			if err := target.bolt.Update(func(tx *bolt.Tx) error {
				rollback := tx.Bucket([]byte(fwRollbackBucket))
				if failure == "disarm" {
					_, err := rollback.CreateBucket([]byte(fwRollbackKey))
					return err
				}
				if err := rollback.Put([]byte(fwRollbackKey), []byte("local pending")); err != nil {
					return err
				}
				b, err := tx.CreateBucket([]byte("fw:zz-late"))
				if err != nil {
					return err
				}
				_, err = b.CreateBucket([]byte("collision"))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			before := readFirewallImportImage(t, targetPath)
			if err := importFirewallArchive(archive, targetPath); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("malformed %s target = %v, want corruption refusal", failure, err)
			}
			assertFirewallImportUnchanged(t, targetPath, before)
		})
	}
}

func TestArchiveImportFirewallCommitsOnce(t *testing.T) {
	sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
	archive := exportFirewallArchive(t, source, sourcePath)
	targetPath := rawFirewallImportTarget(t)
	target, openErr := bolt.Open(filepath.Join(targetPath, "csm.db"), 0600, nil)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := target.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte(fwRollbackBucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(fwRollbackKey), []byte("local pending"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	before := readFirewallImportImage(t, targetPath)
	if err := importFirewallArchive(archive, targetPath); err != nil {
		t.Fatal(err)
	}
	after := readFirewallImportImage(t, targetPath)
	if after.txid != before.txid+1 {
		t.Fatalf("import committed %d transactions, want one", after.txid-before.txid)
	}
	db, err := bolt.Open(filepath.Join(targetPath, "csm.db"), 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("meta")) != nil {
			t.Error("firewall import initialized unrelated store state")
		}
		if got := string(tx.Bucket([]byte("sentinel")).Get([]byte("untouched"))); got != "value" {
			t.Errorf("sentinel = %q", got)
		}
		if tx.Bucket([]byte(fwRollbackBucket)).Get([]byte(fwRollbackKey)) != nil {
			t.Error("import kept local pending rollback")
		}
		if _, err := readFirewallAction(tx, "batch-a"); err != nil {
			t.Fatalf("imported action unreadable: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveImportFirewallAcceptsLegacyAndSnapshotOnly(t *testing.T) {
	for _, sourceSnapshot := range []bool{false, true} {
		for _, targetKind := range []string{"absent", "legacy", "snapshot", "journal"} {
			name := targetKind
			if sourceSnapshot {
				name += "/source snapshot"
			} else {
				name += "/source legacy"
			}
			t.Run(name, func(t *testing.T) {
				sourcePath := t.TempDir()
				source, openErr := Open(sourcePath)
				if openErr != nil {
					t.Fatal(openErr)
				}
				t.Cleanup(func() { _ = source.Close() })
				if sourceSnapshot {
					if _, err := source.ReplaceFirewallState(0, completeFirewallState()); err != nil {
						t.Fatal(err)
					}
				} else if err := source.BlockIP("192.0.2.42", "legacy", time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				archive := exportFirewallArchive(t, source, sourcePath)
				targetPath := filepath.Join(t.TempDir(), "absent")
				targetRevision := uint64(1)
				if targetKind == "journal" {
					path, target := firewallJournalHost(t, targetFirewallState(), "batch-t", true, true, "member-8", "member-9")
					targetPath = path
					_, revision, readErr := target.ReadFirewallState()
					if readErr != nil {
						t.Fatal(readErr)
					}
					targetRevision = revision
					if err := target.Close(); err != nil {
						t.Fatal(err)
					}
				} else if targetKind != "absent" {
					targetPath = t.TempDir()
					target, err := Open(targetPath)
					if err != nil {
						t.Fatal(err)
					}
					if targetKind == "snapshot" {
						if _, err := target.ReplaceFirewallState(0, targetFirewallState()); err != nil {
							t.Fatal(err)
						}
					}
					if err := target.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if err := importFirewallArchive(archive, targetPath); err != nil {
					t.Fatal(err)
				}
				db, err := Open(targetPath)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				switch {
				case sourceSnapshot:
					assertFirewallSnapshot(t, db, completeFirewallState(), 1)
					if _, err := db.ReadFirewallAction("batch-t"); !errors.Is(err, ErrFirewallActionMissing) {
						t.Fatalf("snapshot-only import kept old journal: %v", err)
					}
				case targetKind == "snapshot" || targetKind == "journal":
					assertFirewallSnapshot(t, db, targetFirewallState(), targetRevision)
					if targetKind == "journal" {
						if _, err := db.ReadFirewallAction("batch-t"); err != nil {
							t.Fatal(err)
						}
					}
				default:
					row, found := db.GetBlockedIP("192.0.2.42")
					if !found || row.IP != "192.0.2.42" {
						t.Fatalf("legacy row = %#v, found %v", row, found)
					}
				}
			})
		}
	}
}

func TestArchiveImportFirewallRejectsNestedSourceBuckets(t *testing.T) {
	for _, bucket := range []string{"fw:extra", firewallActionsBucket, firewallMemberIndexBucket, firewallBatchMembersBucket, firewallBudgetBucket} {
		t.Run(bucket, func(t *testing.T) {
			sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
			if err := source.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(bucket))
				if b == nil {
					t.Fatal("source bucket missing before damage")
				}
				nested, err := b.CreateBucket([]byte("nested"))
				if err != nil {
					return err
				}
				return nested.Put([]byte("evidence"), []byte("must not disappear"))
			}); err != nil {
				t.Fatal(err)
			}
			archive := exportFirewallArchive(t, source, sourcePath)
			targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", true, true, "member-8", "member-9")
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			before := readFirewallImportImage(t, targetPath)
			if err := importFirewallArchive(archive, targetPath); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Errorf("nested source imported: %v, want corruption refusal", err)
			}
			assertFirewallImportUnchanged(t, targetPath, before)
			absent := filepath.Join(t.TempDir(), "absent")
			if err := importFirewallArchive(archive, absent); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Errorf("nested source imported into absent target: %v", err)
			}
			if _, err := os.Stat(absent); !errors.Is(err, os.ErrNotExist) {
				t.Error("nested source created destination")
			}
		})
	}
}

func TestArchiveImportFirewallRejectsNestedTargetBuckets(t *testing.T) {
	for _, bucket := range []string{"fw:extra", firewallActionsBucket, firewallMemberIndexBucket, firewallBatchMembersBucket, firewallBudgetBucket, firewallBudgetIndexBucket, firewallActionHistoryBucket, firewallSnapshotBucket} {
		t.Run(bucket, func(t *testing.T) {
			sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
			archive := exportFirewallArchive(t, source, sourcePath)
			targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", true, true, "member-8", "member-9")
			if err := target.bolt.Update(func(tx *bolt.Tx) error {
				nested, err := tx.Bucket([]byte(bucket)).CreateBucket([]byte("nested"))
				if err != nil {
					return err
				}
				return nested.Put([]byte("evidence"), []byte("must not disappear"))
			}); err != nil {
				t.Fatal(err)
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			before := readFirewallImportImage(t, targetPath)
			if err := importFirewallArchive(archive, targetPath); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Errorf("nested target imported: %v, want corruption refusal", err)
			}
			assertFirewallImportUnchanged(t, targetPath, before)
		})
	}
}
