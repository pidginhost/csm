package store

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// firewallBatchOf builds an automatic batch over the committed state, one member per
// ID, each charged to the same scan window.
func firewallBatchOf(t *testing.T, db *DB, id string, limit int, members ...string) firewall.FirewallAction {
	t.Helper()
	state, revision, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	a := batchFixture()
	a.Request.ID, a.Before, a.After, a.Revision = id, state, state, revision
	a.Members = nil
	for i, member := range members {
		a.Members = append(a.Members, firewall.ActionMember{
			Request: firewall.ActionRequest{ID: member, Operation: "block", Target: fmt.Sprintf("203.0.113.%d", 20+i), Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour},
			Budget:  &firewall.ScanAdmission{Window: "2026-01-02T03", Limit: limit},
		})
	}
	return a
}

// settleFirewallAction ends an admitted action as failed and delivers its audit, so later
// admissions meet neither the pending interlock nor undelivered history.
func settleFirewallAction(t *testing.T, db *DB, id string) {
	t.Helper()
	a, err := db.TransitionFirewallAction(id, "failed", "not applied", time.Date(2026, 1, 2, 3, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AcknowledgeFirewallAudit(id, a.AuditVersion); err != nil {
		t.Fatal(err)
	}
}

func admitFirewallBatch(t *testing.T, db *DB, a firewall.FirewallAction) {
	t.Helper()
	if _, fresh, err := db.AdmitFirewallAction(a); err != nil || !fresh {
		t.Fatalf("admit %s = %v, %v", a.Request.ID, fresh, err)
	}
}

func firewallScanCount(t *testing.T, db *DB) int {
	t.Helper()
	count, err := db.ReadFirewallScanBudget("2026-01-02T03")
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestFirewallBatchMemberIDsBelongToOneBatch(t *testing.T) {
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
	settleFirewallAction(t, db, "batch-a")
	single := admissionFixture()
	state, revision, err := db.ReadFirewallState()
	if err != nil {
		t.Fatal(err)
	}
	single.Request.ID, single.Before, single.After, single.Revision, single.Budget = "single-1", state, state, revision, nil
	admitFirewallBatch(t, db, single)
	settleFirewallAction(t, db, "single-1")
	charged := firewallScanCount(t, db)
	reuses := map[string]firewall.FirewallAction{
		"a member of another batch":   firewallBatchOf(t, db, "batch-b", 64, "member-3", "member-2"),
		"another batch's ID":          firewallBatchOf(t, db, "batch-c", 64, "member-4", "batch-a"),
		"a one-request action's ID":   firewallBatchOf(t, db, "batch-d", 64, "member-5", "single-1"),
		"a header naming a member":    firewallBatchOf(t, db, "member-1", 64, "member-6", "member-7"),
		"one request naming a member": func() firewall.FirewallAction { a := single; a.Request.ID = "member-2"; a.Revision++; return a }(),
	}
	for name, a := range reuses {
		if _, _, err := db.AdmitFirewallAction(a); !errors.Is(err, firewall.ErrStateConflict) {
			t.Errorf("%s: admission = %v, want conflict", name, err)
		}
		if _, err := db.ReadFirewallAction(a.Request.ID); !errors.Is(err, ErrFirewallActionMissing) {
			t.Errorf("%s: refused admission left a record: %v", name, err)
		}
	}
	if got := firewallScanCount(t, db); got != charged {
		t.Fatalf("refused admissions charged the scan budget: %d, want %d", got, charged)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-e", 64, "member-8", "member-9"))
}

func TestFirewallBatchChargesEveryMember(t *testing.T) {
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 4, "member-1", "member-2"))
	if got := firewallScanCount(t, db); got != 2 {
		t.Fatalf("two members charged %d", got)
	}
	settleFirewallAction(t, db, "batch-a")
	over := firewallBatchOf(t, db, "batch-b", 4, "member-3", "member-4", "member-5")
	if _, _, err := db.AdmitFirewallAction(over); !errors.Is(err, firewall.ErrScanBudget) {
		t.Fatalf("batch over the window = %v, want the scan budget refusal", err)
	}
	if got := firewallScanCount(t, db); got != 2 {
		t.Fatalf("refused batch charged the window: %d", got)
	}
	partial := firewallBatchOf(t, db, "batch-c", 4, "member-6", "member-7", "member-8")
	partial.Members[2].Budget = nil
	admitFirewallBatch(t, db, partial)
	if got := firewallScanCount(t, db); got != 4 {
		t.Fatalf("charged members counted %d, want 4", got)
	}
	settleFirewallAction(t, db, "batch-c")
	one := firewallBatchOf(t, db, "batch-d", 9, "batch-d")
	one.Request = one.Members[0].Request
	one.Budget = one.Members[0].Budget
	admitFirewallBatch(t, db, one)
	if got := firewallScanCount(t, db); got != 5 {
		t.Fatalf("a one-member manifest charged %d, want one charge", got-4)
	}
}

func TestFirewallRetentionReleasesBatchMemberIDs(t *testing.T) {
	t.Run("sweep", func(t *testing.T) {
		db := openSnapshotDB(t)
		if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
			t.Fatal(err)
		}
		admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
		settleFirewallAction(t, db, "batch-a")
		if deleted, err := db.SweepFirewallActionsOlderThan(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil || deleted != 1 {
			t.Fatalf("sweep = %d, %v", deleted, err)
		}
		// The sweep also retires the hour's counter, so the reuse is uncharged.
		again := firewallBatchOf(t, db, "batch-b", 64, "member-1", "member-2")
		for i := range again.Members {
			again.Members[i].Budget = nil
		}
		admitFirewallBatch(t, db, again)
		settleFirewallAction(t, db, "batch-b")
		// The released batch ID is free again, and removing its new owner
		// finds no member list left over from the old batch.
		single := firewallBatchOf(t, db, "batch-a", 64, "batch-a")
		single.Request, single.Members = single.Members[0].Request, nil
		admitFirewallBatch(t, db, single)
		settleFirewallAction(t, db, "batch-a")
		if deleted, err := db.SweepFirewallActionsOlderThan(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil || deleted != 2 {
			t.Fatalf("second sweep = %d, %v", deleted, err)
		}
	})
	t.Run("cap", func(t *testing.T) {
		db := openSnapshotDB(t)
		if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
			t.Fatal(err)
		}
		previous := firewallActionRetention
		t.Cleanup(func() { firewallActionRetention = previous })
		firewallActionRetention = firewallActionRetentionCaps{Actions: 1, Bytes: previous.Bytes, BudgetWindows: previous.BudgetWindows}
		admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
		settleFirewallAction(t, db, "batch-a")
		admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-b", 64, "member-3", "member-4"))
		settleFirewallAction(t, db, "batch-b")
		if _, err := db.ReadFirewallAction("batch-a"); !errors.Is(err, ErrFirewallActionMissing) {
			t.Fatalf("capped batch kept: %v", err)
		}
		if _, _, err := db.AdmitFirewallAction(firewallBatchOf(t, db, "batch-d", 64, "member-3", "member-9")); !errors.Is(err, firewall.ErrStateConflict) {
			t.Fatalf("a retained batch's member was reused: %v", err)
		}
		admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-c", 64, "member-1", "member-2"))
	})
}

func TestFirewallBatchIndexDamageFailsClosed(t *testing.T) {
	damage := map[string]func(*bolt.Tx) error{
		"member list": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(firewallBatchMembersBucket)).Put([]byte("batch-a"), []byte("{}"))
		},
		"empty member list": func(tx *bolt.Tx) error {
			raw, err := encodeFirewallJournal(firewallBatchMembers{Members: []string{}})
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(firewallBatchMembersBucket)).Put([]byte("batch-a"), raw)
		},
		"member names another batch": func(tx *bolt.Tx) error {
			raw, err := encodeFirewallJournal(firewallMemberIndexEntry{Batch: "batch-z"})
			if err != nil {
				return err
			}
			return tx.Bucket([]byte(firewallMemberIndexBucket)).Put([]byte("member-2"), raw)
		},
		"member entry missing": func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(firewallMemberIndexBucket)).Delete([]byte("member-1"))
		},
	}
	for name, change := range damage {
		t.Run(name, func(t *testing.T) {
			db := openSnapshotDB(t)
			if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
				t.Fatal(err)
			}
			admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
			settleFirewallAction(t, db, "batch-a")
			if err := db.bolt.View(func(tx *bolt.Tx) error {
				for _, name := range []string{firewallMemberIndexBucket, firewallBatchMembersBucket} {
					if tx.Bucket([]byte(name)) == nil {
						t.Fatalf("admitted batch has no %s bucket", name)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := db.bolt.Update(change); err != nil {
				t.Fatal(err)
			}
			if _, err := db.SweepFirewallActionsOlderThan(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Fatalf("sweep over a damaged member index = %v", err)
			}
			if _, err := db.ReadFirewallAction("batch-a"); err != nil {
				t.Fatalf("refused sweep deleted the batch: %v", err)
			}
		})
	}
	t.Run("index without journal", func(t *testing.T) {
		db := openSnapshotDB(t)
		if err := db.bolt.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(firewallMemberIndexBucket))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.PendingFirewallActions(); !errors.Is(err, firewall.ErrStateCorrupt) {
			t.Fatalf("member index without a journal index read as %v", err)
		}
	})
}

func TestFirewallBatchAdmissionSurvivesCommitFaults(t *testing.T) {
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	previous := boltUpdate
	t.Cleanup(func() { boltUpdate = previous })
	refused := errors.New("forced rollback")
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		return b.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return refused
		})
	}
	in := firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2")
	before := batchIndexImage(t, db)
	if _, _, err := db.AdmitFirewallAction(in); !errors.Is(err, refused) {
		t.Fatalf("refused commit = %v", err)
	}
	boltUpdate = previous
	if !bytes.Equal(before, batchIndexImage(t, db)) {
		t.Fatal("refused commit left partial reservations, inventory or charges")
	}
	if _, err := db.ReadFirewallAction("batch-a"); !errors.Is(err, ErrFirewallActionMissing) {
		t.Fatalf("a refused commit left the batch: %v", err)
	}
	if got := firewallScanCount(t, db); got != 0 {
		t.Fatalf("a refused commit charged %d", got)
	}
	lost := errors.New("lost durable commit acknowledgement")
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		if err := b.Update(fn); err != nil {
			return err
		}
		return lost
	}
	if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, firewall.ErrStateCommitUncertain) {
		t.Fatalf("lost acknowledgement = %v, %v", fresh, err)
	}
	boltUpdate = previous
	retry, fresh, err := db.AdmitFirewallAction(in)
	if err != nil || fresh || !retry.SameManifest(in) {
		t.Fatalf("retry after a lost acknowledgement = %v, %v", fresh, err)
	}
	if got := firewallScanCount(t, db); got != 2 {
		t.Fatalf("a retried batch charged %d, want each member once", got)
	}
	settleFirewallAction(t, db, "batch-a")
	if _, _, err := db.AdmitFirewallAction(firewallBatchOf(t, db, "batch-b", 64, "member-3", "member-1")); !errors.Is(err, firewall.ErrStateConflict) {
		t.Fatalf("a member of the committed batch was reused: %v", err)
	}
}

func batchIndexImage(t *testing.T, db *DB) []byte {
	t.Helper()
	var image bytes.Buffer
	if err := db.bolt.View(func(tx *bolt.Tx) error { _, err := tx.WriteTo(&image); return err }); err != nil {
		t.Fatal(err)
	}
	return image.Bytes()
}

func TestFirewallBatchMemberIDsRejectNestedReservations(t *testing.T) {
	for _, c := range []struct{ name, bucket, key, role string }{
		{"member as single", firewallMemberIndexBucket, "member-2", "single"},
		{"member as header", firewallMemberIndexBucket, "member-2", "header"},
		{"member as member", firewallMemberIndexBucket, "member-2", "member"},
		{"action as member", firewallActionsBucket, "batch-a", "member"},
		{"action as header", firewallActionsBucket, "batch-a", "header"},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := openSnapshotDB(t)
			if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
				t.Fatal(err)
			}
			admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
			settleFirewallAction(t, db, "batch-a")
			if err := db.bolt.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(c.bucket))
				if b == nil || b.Get([]byte(c.key)) == nil {
					t.Fatal("reservation missing before damage")
				}
				if err := b.Delete([]byte(c.key)); err != nil {
					return err
				}
				_, err := b.CreateBucket([]byte(c.key))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			in := firewallBatchOf(t, db, "batch-b", 64, "member-3", "member-4")
			switch c.role {
			case "single":
				in.Request, in.Budget, in.Members = in.Members[0].Request, in.Members[0].Budget, nil
				in.Request.ID = c.key
			case "header":
				in.Request.ID = c.key
			case "member":
				in.Members[1].Request.ID = c.key
			}
			before := batchIndexImage(t, db)
			if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, firewall.ErrStateCorrupt) {
				t.Errorf("nested reservation admitted or misclassified: fresh %v, %v", fresh, err)
			}
			if !bytes.Equal(before, batchIndexImage(t, db)) {
				t.Error("refused reservation changed journal or charges")
			}
		})
	}
}

func TestFirewallBatchIndexDamageNestedListFailsClosed(t *testing.T) {
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
	settleFirewallAction(t, db, "batch-a")
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(firewallBatchMembersBucket))
		if b == nil || b.Get([]byte("batch-a")) == nil {
			t.Fatal("member list missing before damage")
		}
		if err := b.Delete([]byte("batch-a")); err != nil {
			return err
		}
		_, err := b.CreateBucket([]byte("batch-a"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := batchIndexImage(t, db)
	if count, err := db.SweepFirewallActionsOlderThan(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); count != 0 || !errors.Is(err, firewall.ErrStateCorrupt) {
		t.Errorf("nested member list swept: count %d, %v", count, err)
	}
	if !bytes.Equal(before, batchIndexImage(t, db)) {
		t.Error("refused sweep changed journal or reservations")
	}
}

func TestFirewallBatchIndexDamageNewerEntryIsUnsupported(t *testing.T) {
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
	settleFirewallAction(t, db, "batch-a")
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(firewallMemberIndexBucket))
		if b == nil || b.Get([]byte("member-2")) == nil {
			t.Fatal("member reservation missing before version change")
		}
		raw, err := encodeFirewallJournalVersion(firewallMemberIndexEntry{Batch: "batch-a"}, 2)
		if err != nil {
			return err
		}
		return b.Put([]byte("member-2"), raw)
	}); err != nil {
		t.Fatal(err)
	}
	before := batchIndexImage(t, db)
	if count, err := db.SweepFirewallActionsOlderThan(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); count != 0 || !errors.Is(err, firewall.ErrStateUnsupported) {
		t.Errorf("member release lost unsupported cause: count %d, %v", count, err)
	}
	if !bytes.Equal(before, batchIndexImage(t, db)) {
		t.Error("unsupported member release changed journal or reservations")
	}
}

// Retention frees an ID only through an intact entry that names the batch
// being removed. Lost reservations are not reconstructed at admission: that
// needs a scan of every retained batch, and an earlier build's sweep leaves
// reservations without their record on purpose.
func TestFirewallBatchDamagedReleaseFailsClosed(t *testing.T) {
	cases := map[string][]string{"admit": {"nested member"}}
	for _, operation := range []string{"sweep", "cap"} {
		cases[operation] = []string{"missing member", "missing member bucket", "duplicate member", "header as member", "unsupported list", "unsupported member", "nested member"}
	}
	for operation, damages := range cases {
		for _, damage := range damages {
			t.Run(damage+"/"+operation, func(t *testing.T) {
				db := openSnapshotDB(t)
				if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
					t.Fatal(err)
				}
				original := firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2", "member-3")
				admitFirewallBatch(t, db, original)
				settleFirewallAction(t, db, "batch-a")
				next := firewallBatchOf(t, db, "batch-b", 64, "member-4", "member-3")
				if operation == "cap" {
					next.Members[1].Request.ID = "member-5"
					admitFirewallBatch(t, db, next)
					previous := firewallActionRetention
					t.Cleanup(func() { firewallActionRetention = previous })
					firewallActionRetention.Actions = 1
				}
				want := firewall.ErrStateCorrupt
				if err := db.bolt.Update(func(tx *bolt.Tx) error {
					batches := tx.Bucket([]byte(firewallBatchMembersBucket))
					members := tx.Bucket([]byte(firewallMemberIndexBucket))
					switch damage {
					case "missing member":
						return members.Delete([]byte("member-3"))
					case "nested member":
						if err := members.Delete([]byte("member-3")); err != nil {
							return err
						}
						_, err := members.CreateBucket([]byte("member-3"))
						return err
					case "missing member bucket":
						return tx.DeleteBucket([]byte(firewallMemberIndexBucket))
					case "duplicate member", "header as member":
						ids := []string{"member-1", "member-2"}
						if damage == "duplicate member" {
							ids = append(ids, "member-2")
						}
						if damage == "header as member" {
							ids = append(ids, "batch-a")
						}
						raw, err := encodeFirewallJournal(firewallBatchMembers{Members: ids})
						if err != nil {
							return err
						}
						return batches.Put([]byte("batch-a"), raw)
					case "unsupported list":
						want = firewall.ErrStateUnsupported
						return batches.Put([]byte("batch-a"), []byte(`{"version":2}`))
					case "unsupported member":
						want = firewall.ErrStateUnsupported
						return members.Put([]byte("member-3"), []byte(`{"version":2}`))
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				before := batchIndexImage(t, db)
				var err error
				switch operation {
				case "admit":
					var fresh bool
					_, fresh, err = db.AdmitFirewallAction(next)
					if fresh {
						t.Error("damaged index admitted new work")
					}
				case "sweep":
					var deleted int
					deleted, err = db.SweepFirewallActionsOlderThan(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
					if deleted != 0 {
						t.Errorf("damaged index deleted %d actions", deleted)
					}
				case "cap":
					_, err = db.TransitionFirewallAction("batch-b", "failed", "not applied", original.CreatedAt.Add(time.Hour))
				}
				if !errors.Is(err, want) {
					t.Errorf("operation = %v, want %v", err, want)
				}
				if !bytes.Equal(before, batchIndexImage(t, db)) {
					t.Error("refused operation changed journal, reservations or charges")
				}
			})
		}
	}
}

func TestFirewallBatchMultipleWindowsAreAtomic(t *testing.T) {
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	in := firewallBatchOf(t, db, "batch-a", 1, "member-1", "member-2", "member-3")
	in.Members[0].Budget.Window = "2026-01-02T02"
	before := batchIndexImage(t, db)
	if _, fresh, err := db.AdmitFirewallAction(in); fresh || !errors.Is(err, firewall.ErrScanBudget) {
		t.Fatalf("over-budget batch = %v, %v", fresh, err)
	}
	if !bytes.Equal(before, batchIndexImage(t, db)) {
		t.Fatal("later window refusal kept an earlier window's charge or reservations")
	}
	in.Members[2].Budget = nil
	admitFirewallBatch(t, db, in)
	for _, window := range []string{"2026-01-02T02", "2026-01-02T03"} {
		if count, err := db.ReadFirewallScanBudget(window); err != nil || count != 1 {
			t.Fatalf("window %s = %d, %v", window, count, err)
		}
	}
	for i := range in.Members {
		in.Members[i].Budget = &firewall.ScanAdmission{Window: "2026-01-02T04", Limit: 1}
	}
	if _, fresh, err := db.AdmitFirewallAction(in); err != nil || fresh {
		t.Fatalf("replay compares charges: %v, %v", fresh, err)
	}
	if count, err := db.ReadFirewallScanBudget("2026-01-02T04"); err != nil || count != 0 {
		t.Fatalf("replay charged a new window: %d, %v", count, err)
	}
}

func TestFirewallBatchReusePrecedesPendingAndCharges(t *testing.T) {
	db := openSnapshotDB(t)
	if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
		t.Fatal(err)
	}
	admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 2, "member-1", "member-2"))
	next := firewallBatchOf(t, db, "batch-b", 2, "member-3", "member-2")
	before := batchIndexImage(t, db)
	if _, fresh, err := db.AdmitFirewallAction(next); fresh || !errors.Is(err, firewall.ErrStateConflict) || err.Error() != "firewall state revision conflict: member ID reused" {
		t.Fatalf("reuse hidden by pending action or exhausted budget: fresh %v, %v", fresh, err)
	}
	if !bytes.Equal(before, batchIndexImage(t, db)) {
		t.Fatal("reused ID changed journal or charges")
	}
}

func TestFirewallBatchRetentionRollbackKeepsReservations(t *testing.T) {
	for _, operation := range []string{"sweep", "cap"} {
		t.Run(operation, func(t *testing.T) {
			db := openSnapshotDB(t)
			if _, err := db.ReplaceFirewallState(0, completeFirewallState()); err != nil {
				t.Fatal(err)
			}
			admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-a", 64, "member-1", "member-2"))
			settleFirewallAction(t, db, "batch-a")
			if operation == "cap" {
				admitFirewallBatch(t, db, firewallBatchOf(t, db, "batch-b", 64, "member-3", "member-4"))
				previous := firewallActionRetention
				t.Cleanup(func() { firewallActionRetention = previous })
				firewallActionRetention.Actions = 1
			}
			previous := boltUpdate
			t.Cleanup(func() { boltUpdate = previous })
			refused := errors.New("forced retention rollback")
			boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
				return b.Update(func(tx *bolt.Tx) error {
					if err := fn(tx); err != nil {
						return err
					}
					return refused
				})
			}
			before := batchIndexImage(t, db)
			prune := func() error {
				if operation == "cap" {
					_, err := db.TransitionFirewallAction("batch-b", "failed", "not applied", time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC))
					return err
				}
				deleted, err := db.SweepFirewallActionsOlderThan(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
				if err != nil && deleted != 0 {
					t.Errorf("failed sweep reports %d deleted actions", deleted)
				}
				return err
			}
			if err := prune(); !errors.Is(err, refused) {
				t.Fatalf("prune = %v, want commit fault", err)
			}
			if !bytes.Equal(before, batchIndexImage(t, db)) {
				t.Fatal("failed retention released reservations or changed journal")
			}
			boltUpdate = previous
			if err := prune(); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ReadFirewallAction("batch-a"); !errors.Is(err, ErrFirewallActionMissing) {
				t.Fatalf("successful retry did not prune the batch: %v", err)
			}
			again := firewallBatchOf(t, db, "batch-c", 64, "member-1", "member-2")
			for i := range again.Members {
				again.Members[i].Budget = nil
			}
			admitFirewallBatch(t, db, again)
		})
	}
}
