package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// clearMigratedSentinel deletes meta:migrated so runMigration runs again.
func clearMigratedSentinel(db *DB) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Delete([]byte("migrated"))
	})
}

// migrationSentinelSet reports whether meta:migrated is present.
func migrationSentinelSet(db *DB) bool {
	var set bool
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket([]byte("meta")).Get([]byte("migrated")); v != nil {
			set = true
		}
		return nil
	})
	return set
}

// TestRunMigrationMalformedReputationReturnsError verifies that a malformed
// reputation_cache.json surfaces as a partial-migration error from runMigration.
func TestRunMigrationMalformedReputationReturnsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "reputation_cache.json"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open should succeed even when migration fails: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Clear the sentinel so runMigration re-runs end-to-end.
	if cerr := clearMigratedSentinel(db); cerr != nil {
		t.Fatal(cerr)
	}
	rerr := db.runMigration(dir)
	if rerr == nil {
		t.Fatal("runMigration should return a partial-migration error")
	}
	if !strings.Contains(rerr.Error(), "reputation") {
		t.Errorf("error should mention reputation, got: %v", rerr)
	}
	// Failed run must not stamp the sentinel.
	if migrationSentinelSet(db) {
		t.Error("sentinel should not be set after a failed migration")
	}
}

// TestRunMigrationMalformedFirewallReturnsError triggers the firewall
// migration error branch via an invalid state.json.
func TestRunMigrationMalformedFirewallReturnsError(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte("{bad"), 0600); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if cerr := clearMigratedSentinel(db); cerr != nil {
		t.Fatal(cerr)
	}
	rerr := db.runMigration(dir)
	if rerr == nil {
		t.Fatal("runMigration should surface firewall migration error")
	}
	if !strings.Contains(rerr.Error(), "firewall") {
		t.Errorf("error should mention firewall, got: %v", rerr)
	}
}

// TestRunMigrationMalformedAttackRecordsReturnsError triggers the attackdb
// migration error branch via invalid records.json.
func TestRunMigrationMalformedAttackRecordsReturnsError(t *testing.T) {
	dir := t.TempDir()
	atkDir := filepath.Join(dir, "attack_db")
	if err := os.MkdirAll(atkDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(atkDir, "records.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if cerr := clearMigratedSentinel(db); cerr != nil {
		t.Fatal(cerr)
	}
	rerr := db.runMigration(dir)
	if rerr == nil {
		t.Fatal("runMigration should surface attackdb migration error")
	}
	if !strings.Contains(rerr.Error(), "attackdb") {
		t.Errorf("error should mention attackdb, got: %v", rerr)
	}
}

// TestRunMigrationMultipleErrorsCombined confirms that when several
// migrations fail, runMigration aggregates their messages into one error.
func TestRunMigrationMultipleErrorsCombined(t *testing.T) {
	dir := t.TempDir()

	// Malformed reputation file.
	if err := os.WriteFile(filepath.Join(dir, "reputation_cache.json"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// Malformed firewall file.
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte("y"), 0600); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if cerr := clearMigratedSentinel(db); cerr != nil {
		t.Fatal(cerr)
	}
	rerr := db.runMigration(dir)
	if rerr == nil {
		t.Fatal("expected combined migration error")
	}
	// Both subsystems should be named in the combined error message.
	if !strings.Contains(rerr.Error(), "reputation") || !strings.Contains(rerr.Error(), "firewall") {
		t.Errorf("combined error should mention both failures, got: %v", rerr)
	}
}

// TestRunMigrationCleanRunNoFiles runs runMigration against an empty state
// dir — every sub-migration should short-circuit cleanly and the meta
// "migrated" sentinel should be written.
func TestRunMigrationCleanRunNoFiles(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if cerr := clearMigratedSentinel(db); cerr != nil {
		t.Fatal(cerr)
	}
	if rerr := db.runMigration(dir); rerr != nil {
		t.Fatalf("runMigration on empty dir should succeed, got: %v", rerr)
	}
	if !migrationSentinelSet(db) {
		t.Error("meta:migrated sentinel should be set after a clean run")
	}
}

// TestRunMigrationWritesMigratedSentinelOnSuccess verifies that a successful
// runMigration over real files writes the meta:migrated key.
func TestRunMigrationWritesMigratedSentinelOnSuccess(t *testing.T) {
	dir := t.TempDir()

	// Drop a valid history.jsonl to ensure the happy path does real work.
	hist := []map[string]any{
		{
			"severity":  "warning",
			"check":     "test",
			"message":   "x",
			"timestamp": time.Now().Format(time.RFC3339Nano),
		},
	}
	f, err := os.Create(filepath.Join(dir, "history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, h := range hist {
		if werr := enc.Encode(h); werr != nil {
			t.Fatal(werr)
		}
	}
	_ = f.Close()

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// Clear and re-run migration to cover the success-with-data path.
	if cerr := clearMigratedSentinel(db); cerr != nil {
		t.Fatal(cerr)
	}
	if rerr := db.runMigration(dir); rerr != nil {
		t.Fatalf("runMigration should succeed, got: %v", rerr)
	}

	if !migrationSentinelSet(db) {
		t.Error("meta:migrated sentinel should be set after successful run")
	}
}
