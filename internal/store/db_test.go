package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// A failed flat-file migration leaves bbolt half-populated and does not set
// the "migrated" sentinel, so the daemon would otherwise boot on partial
// security state and retry the same broken migration every restart. Open must
// surface the error instead of logging a warning and proceeding.
func TestOpenFailsWhenMigrationErrors(t *testing.T) {
	dir := t.TempDir()
	attackDir := filepath.Join(dir, "attack_db")
	if err := os.MkdirAll(attackDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Malformed records.json makes migrateAttackDB return a hard error.
	if err := os.WriteFile(filepath.Join(attackDir, "records.json"), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err == nil {
		if db != nil {
			_ = db.Close()
		}
		t.Fatal("Open must fail when migration returns an error; got nil")
	}

	if writeErr := os.WriteFile(filepath.Join(attackDir, "records.json"), []byte("{}"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	db, err = Open(dir)
	if err != nil {
		t.Fatalf("Open after fixing migration input: %v", err)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestOpenSeedsDefaultModSecNoEscalateRulesOnce(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := db.GetModSecNoEscalateRules(); !got[defaultModSecNoEscalateWPEnumerationID] {
		t.Fatalf("default ModSecurity no-escalate rule was not seeded: %v", got)
	}
	if setErr := db.SetModSecNoEscalateRules(map[int]bool{}); setErr != nil {
		t.Fatal(setErr)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if got := db.GetModSecNoEscalateRules(); len(got) != 0 {
		t.Fatalf("operator-cleared ModSecurity no-escalate rules were re-seeded: %v", got)
	}
}

func TestOpenDoesNotClobberExistingModSecNoEscalateRules(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{900500: true}
	if setErr := db.SetModSecNoEscalateRules(want); setErr != nil {
		t.Fatal(setErr)
	}
	if updateErr := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Delete([]byte(modsecNoEscalateSeededKey))
	}); updateErr != nil {
		t.Fatal(updateErr)
	}
	if closeErr := db.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	got := db.GetModSecNoEscalateRules()
	if len(got) != len(want) || !got[900500] {
		t.Fatalf("existing ModSecurity no-escalate rules were clobbered: %v", got)
	}
}

func TestOpenCreatesStateDirWithRestrictedPerms(t *testing.T) {
	// The bbolt file holds firewall rules, attack history, threat-intel
	// cache, and other state that's private to the CSM daemon. The
	// containing directory must not be world-readable — other local
	// users shouldn't be able to enumerate the database files.
	parent := t.TempDir()
	statePath := filepath.Join(parent, "state")

	db, err := Open(statePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Errorf("state dir mode = %04o, want 0700", got)
	}
}

func TestOpenClose(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if db.bolt == nil {
		t.Fatal("bolt handle is nil")
	}
	if cerr := db.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	// Reopen - should succeed without re-creating buckets
	db2, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if err := db2.Close(); err != nil {
		t.Fatalf("Close2: %v", err)
	}
}

func TestTimeKeyOrdering(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC)
	t3 := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	t4 := time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.UTC)

	k1 := TimeKey(t1, 0)
	k2 := TimeKey(t2, 0)
	k3 := TimeKey(t3, 0)
	k4 := TimeKey(t4, 0)

	if len(k1) != len(k2) || len(k2) != len(k3) || len(k3) != len(k4) {
		t.Errorf("keys are not fixed-width: %q %q %q %q", k1, k2, k3, k4)
	}

	if k1 >= k2 {
		t.Errorf("k1 should be before k2: %q >= %q", k1, k2)
	}
	if k2 >= k3 {
		t.Errorf("k2 should be before k3: %q >= %q", k2, k3)
	}
	if k3 >= k4 {
		t.Errorf("k3 should be before k4: %q >= %q", k3, k4)
	}

	// Same timestamp, different counters
	k1c0 := TimeKey(t1, 0)
	k1c1 := TimeKey(t1, 1)
	k1c99 := TimeKey(t1, 99)

	if k1c0 >= k1c1 || k1c1 >= k1c99 {
		t.Errorf("counter ordering broken: %q %q %q", k1c0, k1c1, k1c99)
	}
}

func TestTimeKeyFixedWidth(t *testing.T) {
	times := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.UTC),
		time.Date(2026, 4, 1, 14, 29, 8, 123456789, time.UTC),
	}

	for _, ts := range times {
		key := TimeKey(ts, 0)
		if len(key) != 28 {
			t.Errorf("TimeKey(%v, 0) = %q (len %d), want 28 bytes", ts, key, len(key))
		}
	}
}

func TestGlobalSingleton(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	SetGlobal(db)
	if Global() != db {
		t.Error("Global() should return the db set by SetGlobal()")
	}

	SetGlobal(nil)
}

func TestEnsureOpen(t *testing.T) {
	dir := t.TempDir()

	// First call opens the DB
	if err := EnsureOpen(dir); err != nil {
		t.Fatalf("EnsureOpen: %v", err)
	}

	g := Global()
	if g == nil {
		t.Fatal("Global() is nil after EnsureOpen")
	}

	// Second call is a no-op (returns nil, same global)
	if err := EnsureOpen(dir); err != nil {
		t.Fatalf("second EnsureOpen: %v", err)
	}
	if Global() != g {
		t.Error("second EnsureOpen changed the global")
	}

	// Clean up
	_ = g.Close()
	SetGlobal(nil)
	// Reset ensureOnce for other tests - we can't easily, so this test should be last
}

func TestOpen_PHPRelayBuckets(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	for _, name := range []string{
		"phprelay:meta",
		"phprelay:msgindex",
		"phprelay:ignore",
		"phprelay:settings",
	} {
		if !db.HasBucket(name) {
			t.Errorf("missing bucket %q", name)
		}
	}
}
