package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// firewallJournalHost opens a store with a committed snapshot, one admitted
// batch and a firewall bucket outside the durable journal. settled ends the
// batch and delivers its audit; acknowledged false leaves the audit pending.
func firewallJournalHost(t *testing.T, state firewall.FirewallState, batch string, settled, acknowledged bool, members ...string) (string, *DB) {
	t.Helper()
	path := t.TempDir()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ReplaceFirewallState(0, state); err != nil {
		t.Fatal(err)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, batch, 64, members...))
	if settled {
		a, err := db.TransitionFirewallAction(batch, "failed", "not applied", batchFixture().CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		if acknowledged {
			if err := db.AcknowledgeFirewallAudit(batch, a.AuditVersion); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("fw:extra"))
		if err != nil {
			return err
		}
		return b.Put([]byte(batch), []byte("kept"))
	}); err != nil {
		t.Fatal(err)
	}
	return path, db
}

func exportFirewallArchive(t *testing.T, db *DB, statePath string) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "snapshot.csmbak")
	if _, err := db.Export(ExportOptions{StatePath: statePath, RulesPath: t.TempDir(), DstPath: archive, Manifest: defaultManifest()}); err != nil {
		t.Fatal(err)
	}
	return archive
}

func importFirewallArchive(archive, statePath string) error {
	_, err := Import(ImportOptions{SrcPath: archive, StatePath: statePath, RulesPath: filepath.Dir(archive), Only: "firewall", CurrentPlatform: defaultPlatform()})
	return err
}

func targetFirewallState() firewall.FirewallState {
	state := completeFirewallState()
	state.Blocked = state.Blocked[1:]
	return state
}

func TestArchiveImportFirewallReplacesTheDurableJournal(t *testing.T) {
	sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", true, true, "member-1", "member-2")
	archive := exportFirewallArchive(t, source, sourcePath)
	wantState, wantRevision, err := source.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", true, true, "member-8", "member-9")
	_ = target.Close()
	if err = importFirewallArchive(archive, targetPath); err != nil {
		t.Fatalf("import = %v", err)
	}
	db, err := Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	state, revision, err := db.ReadFirewallState()
	if err != nil || revision != wantRevision || !reflect.DeepEqual(state, wantState) {
		t.Fatalf("imported state = %#v, revision %d, %v", state, revision, err)
	}
	if a, err := db.ReadFirewallAction("batch-a"); err != nil || len(a.Members) != 2 {
		t.Fatalf("imported batch = %#v, %v", a.Members, err)
	}
	if _, err := db.ReadFirewallAction("batch-t"); !errors.Is(err, ErrFirewallActionMissing) {
		t.Fatalf("the replaced journal kept its batch: %v", err)
	}
	if _, err := db.PendingFirewallActions(); err != nil {
		t.Fatalf("imported journal index = %v", err)
	}
	if pending, err := db.FirewallAuditPending(); err != nil || len(pending) != 0 {
		t.Fatalf("imported audit = %d, %v", len(pending), err)
	}
	if _, _, err := db.AdmitFirewallAction(firewallBatchOf(t, db, "batch-b", 64, "member-3", "member-1")); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("an imported member ID was reused: %v", err)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-c", 64, "member-8", "member-9"))
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:extra"))
		if string(b.Get([]byte("batch-a"))) != "kept" || string(b.Get([]byte("batch-t"))) != "kept" {
			t.Error("firewall buckets outside the journal were not merged")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveImportFirewallRefusesOutstandingWork(t *testing.T) {
	damage := func(bucket, key string) func(*DB) {
		return func(db *DB) {
			if err := db.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(bucket)).Put([]byte(key), []byte("{}")) }); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := map[string]struct {
		sourceSettled, sourceAcked, targetSettled, targetAcked bool
		damageSource                                           func(*DB)
	}{
		"source pending":           {targetSettled: true, targetAcked: true},
		"source audit undelivered": {sourceSettled: true, targetSettled: true, targetAcked: true},
		"target pending":           {sourceSettled: true, sourceAcked: true},
		"target audit undelivered": {sourceSettled: true, sourceAcked: true, targetSettled: true},
		"source journal damaged":   {sourceSettled: true, sourceAcked: true, targetSettled: true, targetAcked: true, damageSource: damage(firewallActionIndexBucket, "index")},
		"source snapshot damaged":  {sourceSettled: true, sourceAcked: true, targetSettled: true, targetAcked: true, damageSource: damage(firewallSnapshotBucket, firewallSnapshotKey)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sourcePath, source := firewallJournalHost(t, completeFirewallState(), "batch-a", c.sourceSettled, c.sourceAcked, "member-1", "member-2")
			if c.damageSource != nil {
				c.damageSource(source)
			}
			archive := exportFirewallArchive(t, source, sourcePath)
			targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", c.targetSettled, c.targetAcked, "member-8", "member-9")
			wantState, wantRevision, err := target.ReadFirewallState()
			if err != nil {
				t.Fatal(err)
			}
			want, err := target.ReadFirewallAction("batch-t")
			if err != nil {
				t.Fatal(err)
			}
			_ = target.Close()
			if err = importFirewallArchive(archive, targetPath); err == nil {
				t.Fatal("import over outstanding or damaged journal work succeeded")
			}
			db, err := Open(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			state, revision, err := db.ReadFirewallState()
			if err != nil || revision != wantRevision || !reflect.DeepEqual(state, wantState) {
				t.Fatalf("refused import changed the state: %#v, revision %d, %v", state, revision, err)
			}
			if got, err := db.ReadFirewallAction("batch-t"); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("refused import changed the journal: %v", err)
			}
			if _, err := db.ReadFirewallAction("batch-a"); !errors.Is(err, ErrFirewallActionMissing) {
				t.Fatalf("refused import copied a source action: %v", err)
			}
			if err := db.bolt.View(func(tx *bolt.Tx) error {
				if tx.Bucket([]byte("fw:extra")).Get([]byte("batch-a")) != nil {
					t.Error("refused import merged other firewall buckets")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestArchiveImportFirewallKeepsALocalJournal(t *testing.T) {
	sourcePath := t.TempDir()
	source, err := Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if err = source.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("fw:blocked")).Put([]byte("legacy-row"), []byte("legacy"))
	}); err != nil {
		t.Fatal(err)
	}
	archive := exportFirewallArchive(t, source, sourcePath)
	targetPath, target := firewallJournalHost(t, targetFirewallState(), "batch-t", true, true, "member-8", "member-9")
	wantState, wantRevision, err := target.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	_ = target.Close()
	if err = importFirewallArchive(archive, targetPath); err != nil {
		t.Fatalf("import = %v", err)
	}
	db, err := Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	state, revision, err := db.ReadFirewallState()
	if err != nil || revision != wantRevision || !reflect.DeepEqual(state, wantState) {
		t.Fatalf("a legacy archive changed the local snapshot: %#v, revision %d, %v", state, revision, err)
	}
	if _, err := db.ReadFirewallAction("batch-t"); err != nil {
		t.Fatalf("a legacy archive dropped the local journal: %v", err)
	}
}
