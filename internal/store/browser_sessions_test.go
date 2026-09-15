package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/session"
	bolt "go.etcd.io/bbolt"
)

func TestBrowserSessionExpiryRevocationAndRestart(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	now := time.Now().UTC()
	manager, err := session.New(db, time.Hour, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secret, record, err := manager.Create("operator", "credential-fingerprint", "", "192.0.2.1", "browser", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Access(secret, now.Add(9*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Access(secret, now.Add(18*time.Minute), false); err != nil {
		t.Fatal("activity did not extend idle timeout")
	}
	if _, err = manager.Access(secret, now.Add(19*time.Minute), false); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("idle boundary: %v", err)
	}
	secret, record, err = manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Revoke(record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Access(secret, now, false); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("revoked session authenticated")
	}
	secret, _, err = manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = session.New(db, time.Hour, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Access(secret, now, false); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("session survived server restart")
	}
}

func TestBrowserSessionAbsoluteExpiryAndConcurrentRevocation(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret, rec, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Access(secret, now.Add(59*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Access(secret, now.Add(time.Hour), false); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("absolute expiry extended by activity")
	}
	secret, rec, err = manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() { _, _ = manager.Access(secret, now.Add(time.Minute), true) })
	}
	if err = manager.Revoke(rec.ID); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err = manager.Access(secret, now.Add(time.Minute), false); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("concurrent touch resurrected revoked session")
	}
}

func TestBrowserSessionStorageFailureAndSecretAtRest(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.New(db, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "csm.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("raw session secret persisted")
	}
	if _, err = manager.Access(secret, now, true); err == nil {
		t.Fatal("closed store authorized a session")
	}
	if raw, _, createErr := manager.Create("operator", "credential-fingerprint", "", "", "", now); createErr == nil || raw != "" {
		t.Fatal("failed persistence issued a credential")
	}
	if err = manager.RevokeAll(); err == nil {
		t.Fatal("failed revocation reported success")
	}
}

func TestBrowserSessionExportDoesNotCopySessions(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "snapshot.csmbak")
	if _, err = db.Export(ExportOptions{StatePath: dir, DstPath: archive, Manifest: defaultManifest()}); err != nil {
		t.Fatal(err)
	}
	snapshotBytes := archiveEntryBytes(t, archive, bboltSnapshotEntry)
	if bytes.Contains(snapshotBytes, []byte(session.Hash(secret))) || bytes.Contains(snapshotBytes, []byte("credential-fingerprint")) {
		t.Fatal("export retained session metadata in free pages")
	}
	// A full import reports the manifest's buckets as restored, so the
	// manifest must describe the sanitized snapshot, not the live database.
	var manifest Manifest
	if err = json.Unmarshal(archiveEntryBytes(t, archive, manifestEntry), &manifest); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(manifest.BboltBuckets, browserSessionsBucket) {
		t.Fatal("export manifest lists browser sessions the snapshot does not contain")
	}
	if !slices.Contains(manifest.BboltBuckets, "history") {
		t.Fatalf("export manifest lost snapshot buckets: %v", manifest.BboltBuckets)
	}
	snapshotDir := t.TempDir()
	if err = os.WriteFile(filepath.Join(snapshotDir, "csm.db"), snapshotBytes, 0600); err != nil {
		t.Fatal(err)
	}
	copyDB, err := Open(snapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = copyDB.Close() }()
	records, err := copyDB.ListBrowserSessions(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatal("export retained browser session verifiers")
	}
	if _, err = manager.Access(secret, now, false); err != nil {
		t.Fatal("export revoked live session")
	}
}

func TestBrowserSessionFailedCommitDoesNotIssueRotateOrRevive(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret, rec, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	original := boltUpdate
	t.Cleanup(func() { boltUpdate = original })
	failure := errors.New("injected session commit failure")
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		return b.Update(func(tx *bolt.Tx) error {
			if callbackErr := fn(tx); callbackErr != nil {
				return callbackErr
			}
			return failure
		})
	}
	if raw, _, createErr := manager.Create("operator", "credential-fingerprint", secret, "", "", now); !errors.Is(createErr, failure) || raw != "" {
		t.Fatal("failed rotation issued a session")
	}
	if _, err = manager.Access(secret, now.Add(time.Minute), true); !errors.Is(err, failure) {
		t.Fatal("failed activity commit authorized request")
	}
	if err = manager.Revoke(rec.ID); !errors.Is(err, failure) {
		t.Fatal("failed revocation reported success")
	}
	if _, err = session.New(db, time.Hour, time.Hour); !errors.Is(err, failure) {
		t.Fatal("startup accepted failed invalidation")
	}
	boltUpdate = original
	stored, err := manager.Access(secret, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.LastSeen.Equal(now) {
		t.Fatal("failed activity commit changed session")
	}
}

func TestBrowserSessionCapacityDoesNotEvictActiveLogins(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first := ""
	for i := 0; i < session.MaxSessions; i++ {
		secret, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = secret
		}
	}
	if secret, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now); !errors.Is(err, session.ErrFull) || secret != "" {
		t.Fatal("unbounded session admission")
	}
	if _, err := manager.Access(first, now, false); err != nil {
		t.Fatal("active session evicted at capacity")
	}
	if _, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now.Add(time.Minute)); err != nil {
		t.Fatal("expired sessions retained capacity")
	}
}

func TestBrowserSessionCorruptRecordFailsClosed(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret, rec, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(browserSessionsBucket)).Put([]byte(rec.Verifier), []byte("invalid"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Access(secret, now, false); err == nil {
		t.Fatal("corrupt session authenticated")
	}
	if _, err := manager.List(now); err == nil {
		t.Fatal("corrupt session list reported success")
	}
}

func TestBrowserSessionConcurrentRotationHasOneSuccessor(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	original, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	var issued atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			if _, _, err := manager.Create("operator", "credential-fingerprint", original, "", "", now); err == nil {
				issued.Add(1)
			} else if !errors.Is(err, session.ErrInvalid) {
				t.Errorf("rotation failed: %v", err)
			}
		})
	}
	wg.Wait()
	if issued.Load() != 1 {
		t.Fatalf("one session rotation issued %d successors", issued.Load())
	}
	if _, err := manager.Access(original, now, false); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("original session survived rotation")
	}
}

func TestBrowserSessionOutOfOrderActivity(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	if _, err = manager.Access(secret, later, true); err != nil {
		t.Fatal(err)
	}
	// Requests sample their clocks before entering the store. A delayed
	// request must accept a more recent committed touch without undoing it.
	earlier := later.Add(-time.Millisecond)
	if _, err = manager.Access(secret, earlier, true); err != nil {
		t.Errorf("older request rejected after concurrent activity: %v", err)
	}
	listed, err := manager.List(earlier)
	if err != nil || len(listed) != 1 {
		t.Errorf("older listing lost active session: count=%d err=%v", len(listed), err)
	}
	if _, _, err = manager.Create("operator", "credential-fingerprint", "", "", "", earlier); err != nil {
		t.Fatal(err)
	}
	record, err := manager.Access(secret, later, false)
	if err != nil {
		t.Fatalf("concurrent login deleted active session: %v", err)
	}
	if !record.LastSeen.Equal(later) {
		t.Fatal("older request moved activity backwards")
	}
}

func TestBrowserSessionConcurrentTouchKeepsLatestActivity(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	manager, err := session.New(db, time.Hour, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret, _, err := manager.Create("operator", "credential-fingerprint", "", "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	original := boltUpdate
	t.Cleanup(func() { boltUpdate = original })
	earlier, later := now.Add(time.Minute), now.Add(2*time.Minute)
	// Commit the newer request after the older request's read but before
	// its write transaction. This deterministically exercises the race.
	boltUpdate = func(b *bolt.DB, fn func(*bolt.Tx) error) error {
		boltUpdate = original
		if _, err = manager.Access(secret, later, true); err != nil {
			t.Fatal(err)
		}
		return original(b, fn)
	}
	if _, err = manager.Access(secret, earlier, true); err != nil {
		t.Fatalf("concurrent touch rejected: %v", err)
	}
	record, err := manager.Access(secret, later, false)
	if err != nil {
		t.Fatal(err)
	}
	if !record.LastSeen.Equal(later) {
		t.Fatal("delayed touch overwrote more recent activity")
	}
	if _, err = manager.Access(secret, later.Add(10*time.Minute), false); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("idle deadline no longer enforced")
	}
}

func TestBrowserSessionRotationAfterExpiredRecord(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	now := time.Now().UTC()
	// Order the expired record immediately before the session to rotate.
	for _, rec := range []session.Record{
		{ID: "expired", Verifier: "a", Credential: "fingerprint", Created: now, LastSeen: now, Expires: now.Add(time.Minute)},
		{ID: "previous", Verifier: "b", Credential: "fingerprint", Created: now, LastSeen: now, Expires: now.Add(time.Hour)},
	} {
		if err = db.ReplaceBrowserSession(rec, "", now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	later := now.Add(2 * time.Minute)
	replacement := session.Record{ID: "replacement", Verifier: "c", Credential: "fingerprint", Created: later, LastSeen: later, Expires: later.Add(time.Hour)}
	if err = db.ReplaceBrowserSession(replacement, "b", later, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err = db.AccessBrowserSession("b", later, time.Hour, false); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("rotation retained the old session after pruning an expired neighbor")
	}
	records, err := db.ListBrowserSessions(later, time.Hour)
	if err != nil || len(records) != 1 || records[0].ID != "replacement" {
		t.Fatalf("rotation did not leave exactly the successor: count=%d err=%v", len(records), err)
	}
}
