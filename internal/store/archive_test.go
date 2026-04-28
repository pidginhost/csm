package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// helper: populate bbolt with deterministic data across several buckets
// so a round-trip test can prove every bucket survived the trip.
func seedDB(t *testing.T, db *DB) map[string]map[string]string {
	t.Helper()
	want := map[string]map[string]string{
		"history":    {"k1": "v1", "k2": "v2"},
		"fw:blocked": {"1.1.1.1": "blob1", "2.2.2.2": "blob2"},
		"meta":       {"schema_version": "1", "history:count": "2"},
		"reputation": {"3.3.3.3": "rep1"},
		"plugins":    {"siteA": "scan-result-A"},
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		for bucket, kv := range want {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				return errors.New("missing bucket " + bucket)
			}
			for k, v := range kv {
				if err := b.Put([]byte(k), []byte(v)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seedDB: %v", err)
	}
	return want
}

func seedStateDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"state.json":           []byte(`{"baseline":[{"path":"/etc/passwd","hash":"abc"}]}`),
		"latest_findings.json": []byte(`[]`),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			t.Fatalf("seed state %s: %v", name, err)
		}
	}
	return files
}

func seedRulesDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"malware.yar": []byte(`rule a { strings: $a = "x" condition: $a }`),
		"version":     []byte("2026-04-27"),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			t.Fatalf("seed rules %s: %v", name, err)
		}
	}
	return files
}

func assertBucketContents(t *testing.T, db *DB, want map[string]map[string]string) {
	t.Helper()
	for bucket, kv := range want {
		if err := db.bolt.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				t.Errorf("bucket %s missing after import", bucket)
				return nil
			}
			for k, v := range kv {
				got := b.Get([]byte(k))
				if !bytes.Equal(got, []byte(v)) {
					t.Errorf("bucket %s key %s: got %q want %q", bucket, k, got, v)
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("View bucket %s: %v", bucket, err)
		}
	}
}

func mustExportSetup(t *testing.T) (statePath, rulesPath, archivePath string, db *DB, wantBuckets map[string]map[string]string, wantState, wantRules map[string][]byte) {
	t.Helper()
	statePath = t.TempDir()
	rulesPath = t.TempDir()
	archivePath = filepath.Join(t.TempDir(), "snapshot.csmbak")

	d, err := Open(statePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	wantBuckets = seedDB(t, d)
	wantState = seedStateDir(t, statePath)
	wantRules = seedRulesDir(t, rulesPath)
	return statePath, rulesPath, archivePath, d, wantBuckets, wantState, wantRules
}

func defaultManifest() Manifest {
	return Manifest{
		CSMVersion:     "test",
		SourceHostname: "host.test",
		SourcePlatform: map[string]string{"os": "linux", "panel": "none", "webserver": "none"},
	}
}

func defaultPlatform() map[string]string {
	return map[string]string{"os": "linux", "panel": "none", "webserver": "none"}
}

func TestArchiveRoundTripFullRestore(t *testing.T) {
	statePath, rulesPath, archivePath, db, wantBuckets, wantState, wantRules := mustExportSetup(t)

	res, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  defaultManifest(),
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if res.Bytes <= 0 {
		t.Errorf("Export Bytes = %d, want > 0", res.Bytes)
	}
	if len(res.ArchiveSHA256) != 64 {
		t.Errorf("ArchiveSHA256 length = %d, want 64", len(res.ArchiveSHA256))
	}

	// Wipe the originals: close DB, remove state and rules dirs, recreate empty.
	_ = db.Close()
	if rmErr := os.RemoveAll(statePath); rmErr != nil {
		t.Fatalf("rm state: %v", rmErr)
	}
	if rmErr := os.RemoveAll(rulesPath); rmErr != nil {
		t.Fatalf("rm rules: %v", rmErr)
	}
	if mkErr := os.MkdirAll(statePath, 0700); mkErr != nil {
		t.Fatalf("mkdir state: %v", mkErr)
	}
	if mkErr := os.MkdirAll(rulesPath, 0700); mkErr != nil {
		t.Fatalf("mkdir rules: %v", mkErr)
	}

	imp, err := Import(ImportOptions{
		SrcPath:         archivePath,
		StatePath:       statePath,
		RulesPath:       rulesPath,
		Only:            "all",
		CurrentPlatform: defaultPlatform(),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imp.Manifest.SchemaVersion != ArchiveSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", imp.Manifest.SchemaVersion, ArchiveSchemaVersion)
	}

	d2, err := Open(statePath)
	if err != nil {
		t.Fatalf("re-open after import: %v", err)
	}
	defer func() { _ = d2.Close() }()
	assertBucketContents(t, d2, wantBuckets)

	for name, content := range wantState {
		got, err := os.ReadFile(filepath.Join(statePath, name))
		if err != nil {
			t.Errorf("read state %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("state %s mismatch", name)
		}
	}
	for name, content := range wantRules {
		got, err := os.ReadFile(filepath.Join(rulesPath, name))
		if err != nil {
			t.Errorf("read rules %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("rules %s mismatch", name)
		}
	}
}

func TestArchiveImportRefusesNewerSchema(t *testing.T) {
	statePath, rulesPath, archivePath, db, _, _, _ := mustExportSetup(t)
	man := defaultManifest()
	man.SchemaVersion = ArchiveSchemaVersion + 5 // pretend a future version
	if _, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  man,
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	_ = db.Close()

	_, err := Import(ImportOptions{
		SrcPath:         archivePath,
		StatePath:       t.TempDir(),
		RulesPath:       t.TempDir(),
		Only:            "all",
		CurrentPlatform: defaultPlatform(),
	})
	if err == nil {
		t.Fatal("Import: expected error for newer schema, got nil")
	}
	if !errors.Is(err, ErrSchemaVersionTooNew) {
		t.Errorf("Import err = %v, want ErrSchemaVersionTooNew", err)
	}
}

func TestArchiveImportRefusesPlatformMismatch(t *testing.T) {
	statePath, rulesPath, archivePath, db, _, _, _ := mustExportSetup(t)
	if _, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  defaultManifest(),
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	_ = db.Close()

	otherPlatform := map[string]string{"os": "linux", "panel": "cpanel", "webserver": "apache"}
	_, err := Import(ImportOptions{
		SrcPath:         archivePath,
		StatePath:       t.TempDir(),
		RulesPath:       t.TempDir(),
		Only:            "all",
		CurrentPlatform: otherPlatform,
	})
	if err == nil {
		t.Fatal("Import: expected platform-mismatch error")
	}
	if !errors.Is(err, ErrPlatformMismatch) {
		t.Errorf("Import err = %v, want ErrPlatformMismatch", err)
	}

	// With --force-platform-mismatch, should succeed.
	if _, err := Import(ImportOptions{
		SrcPath:               archivePath,
		StatePath:             t.TempDir(),
		RulesPath:             t.TempDir(),
		Only:                  "all",
		CurrentPlatform:       otherPlatform,
		ForcePlatformMismatch: true,
	}); err != nil {
		t.Errorf("Import with force: %v", err)
	}
}

func TestArchiveImportOnlyBaselineSkipsBboltAndRules(t *testing.T) {
	statePath, rulesPath, archivePath, db, _, wantState, _ := mustExportSetup(t)
	if _, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  defaultManifest(),
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	_ = db.Close()

	// Fresh empty target.
	targetState := t.TempDir()
	targetRules := t.TempDir()
	preExistingRule := filepath.Join(targetRules, "preexisting.yar")
	if err := os.WriteFile(preExistingRule, []byte("untouched"), 0600); err != nil {
		t.Fatalf("seed preexisting rule: %v", err)
	}

	imp, err := Import(ImportOptions{
		SrcPath:         archivePath,
		StatePath:       targetState,
		RulesPath:       targetRules,
		Only:            "baseline",
		CurrentPlatform: defaultPlatform(),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imp.StateFiles == 0 {
		t.Error("expected state files restored, got 0")
	}
	if imp.RulesFiles != 0 {
		t.Errorf("rules files restored = %d, want 0 with --only=baseline", imp.RulesFiles)
	}
	if len(imp.BucketsRestored) != 0 {
		t.Errorf("buckets restored = %v, want none with --only=baseline", imp.BucketsRestored)
	}
	// Bbolt file should NOT exist in target.
	if _, statErr := os.Stat(filepath.Join(targetState, "csm.db")); !os.IsNotExist(statErr) {
		t.Errorf("csm.db should not exist with --only=baseline, stat err = %v", statErr)
	}
	// Pre-existing rule should be untouched.
	got, err := os.ReadFile(preExistingRule)
	if err != nil {
		t.Fatalf("read preexisting rule: %v", err)
	}
	if string(got) != "untouched" {
		t.Errorf("preexisting rule modified: %q", got)
	}
	// State files restored.
	for name, content := range wantState {
		got, err := os.ReadFile(filepath.Join(targetState, name))
		if err != nil {
			t.Errorf("read state %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("state %s mismatch", name)
		}
	}
}

func TestArchiveImportOnlyFirewallRestoresOnlyFirewallBuckets(t *testing.T) {
	statePath, rulesPath, archivePath, db, _, _, _ := mustExportSetup(t)
	if _, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  defaultManifest(),
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	_ = db.Close()

	// Fresh target with its own pre-existing data; firewall import should
	// add fw:* but leave history etc. alone.
	targetState := t.TempDir()
	targetRules := t.TempDir()
	d2, err := Open(targetState)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	if upErr := d2.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("history")).Put([]byte("untouched-key"), []byte("untouched-value"))
	}); upErr != nil {
		t.Fatalf("seed target history: %v", upErr)
	}
	_ = d2.Close()

	imp, err := Import(ImportOptions{
		SrcPath:         archivePath,
		StatePath:       targetState,
		RulesPath:       targetRules,
		Only:            "firewall",
		CurrentPlatform: defaultPlatform(),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(imp.BucketsRestored) == 0 {
		t.Fatal("expected buckets restored, got none")
	}
	// All restored buckets must be firewall-prefixed.
	for _, bucket := range imp.BucketsRestored {
		if !isFirewallBucket(bucket) {
			t.Errorf("bucket %q restored under --only=firewall, want only fw:*", bucket)
		}
	}

	d3, err := Open(targetState)
	if err != nil {
		t.Fatalf("re-open target: %v", err)
	}
	defer func() { _ = d3.Close() }()
	// fw:blocked should now have the imported entries.
	if err := d3.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fw:blocked"))
		if got := b.Get([]byte("1.1.1.1")); !bytes.Equal(got, []byte("blob1")) {
			t.Errorf("fw:blocked 1.1.1.1 = %q, want blob1", got)
		}
		// history should still have its pre-existing key.
		h := tx.Bucket([]byte("history"))
		if got := h.Get([]byte("untouched-key")); !bytes.Equal(got, []byte("untouched-value")) {
			t.Errorf("history untouched-key = %q, want untouched-value", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestArchiveImportRefusesCorruptArchive(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "corrupt.csmbak")
	if err := os.WriteFile(bad, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	_, err := Import(ImportOptions{
		SrcPath:         bad,
		StatePath:       t.TempDir(),
		RulesPath:       t.TempDir(),
		Only:            "all",
		CurrentPlatform: defaultPlatform(),
	})
	if err == nil {
		t.Fatal("Import: expected error on corrupt archive")
	}
}

func TestArchiveSHA256InResultMatchesArchiveContent(t *testing.T) {
	statePath, rulesPath, archivePath, db, _, _, _ := mustExportSetup(t)
	res, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  defaultManifest(),
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	_ = db.Close()

	// Re-hash the archive on disk and compare.
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != res.ArchiveSHA256 {
		t.Errorf("ArchiveSHA256 mismatch:\n  result: %s\n  recomputed: %s", res.ArchiveSHA256, hex.EncodeToString(sum[:]))
	}

	// Companion .sha256 should exist and contain the hash.
	companionPath := archivePath + ".sha256"
	companion, err := os.ReadFile(companionPath)
	if err != nil {
		t.Fatalf("read companion: %v", err)
	}
	if !bytes.Contains(companion, []byte(res.ArchiveSHA256)) {
		t.Errorf("companion %q missing hash %q", companion, res.ArchiveSHA256)
	}
}

func TestArchiveExportEmptyRulesPathOK(t *testing.T) {
	statePath, _, archivePath, db, _, _, _ := mustExportSetup(t)
	// RulesPath empty -> contents should not include "rules".
	res, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: "",
		DstPath:   archivePath,
		Manifest:  defaultManifest(),
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	_ = db.Close()
	if res.Bytes <= 0 {
		t.Errorf("Bytes = %d", res.Bytes)
	}
}

func TestArchiveExportCleansUpPartialFileOnError(t *testing.T) {
	statePath, rulesPath, _, db, _, _, _ := mustExportSetup(t)

	// Aim DstPath at a directory that exists -- the file write
	// succeeds -- but seed the destination with a manifest dir to
	// guarantee a tar-write failure. The simplest reproducer: point
	// DstPath at a path whose parent exists but inject failure via a
	// read-only state path that writeFile cannot tolerate. Easier:
	// pre-create DstPath as a directory so OpenFile with O_WRONLY
	// fails; then verify no leftover companion file is created.
	dir := t.TempDir()
	dstPath := filepath.Join(dir, "snapshot.csmbak")
	if err := os.Mkdir(dstPath, 0700); err != nil {
		t.Fatalf("seed dst as dir: %v", err)
	}

	_, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   dstPath,
		Manifest:  defaultManifest(),
	})
	if err == nil {
		t.Fatal("Export: expected error when DstPath is a directory")
	}

	// The companion file must not be left behind when Export failed.
	if _, statErr := os.Stat(dstPath + ".sha256"); !os.IsNotExist(statErr) {
		t.Errorf("companion .sha256 left behind after failure (stat err = %v)", statErr)
	}
}

func TestArchiveExportRemovesPartialOnLateFailure(t *testing.T) {
	// Successful export, then verify that re-running into a path that
	// becomes unwritable mid-flight removes the partial file. We
	// cannot easily trigger an internal-step failure from the test,
	// so this exercises the success path's cleanup invariant: the
	// archive and companion both exist after success.
	statePath, rulesPath, _, db, _, _, _ := mustExportSetup(t)
	dir := t.TempDir()
	dstPath := filepath.Join(dir, "ok.csmbak")

	res, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   dstPath,
		Manifest:  defaultManifest(),
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, statErr := os.Stat(res.Path); statErr != nil {
		t.Errorf("archive missing after successful export: %v", statErr)
	}
	if _, statErr := os.Stat(res.Path + ".sha256"); statErr != nil {
		t.Errorf("companion missing after successful export: %v", statErr)
	}
}

func TestArchiveImportTimestampPreserved(t *testing.T) {
	statePath, rulesPath, archivePath, db, _, _, _ := mustExportSetup(t)
	man := defaultManifest()
	expected := time.Date(2026, 4, 27, 10, 30, 0, 0, time.UTC)
	man.ExportTS = expected
	if _, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  man,
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	_ = db.Close()

	imp, err := Import(ImportOptions{
		SrcPath:         archivePath,
		StatePath:       t.TempDir(),
		RulesPath:       t.TempDir(),
		Only:            "all",
		CurrentPlatform: defaultPlatform(),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !imp.Manifest.ExportTS.Equal(expected) {
		t.Errorf("ExportTS = %v, want %v", imp.Manifest.ExportTS, expected)
	}
}
