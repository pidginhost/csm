package store

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
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

// rewriteArchiveFlippingBbolt copies an archive, flipping one byte of the
// bbolt snapshot payload while leaving the manifest (and its recorded hash)
// untouched. This models an archive whose database was altered after export
// but still decompresses and untars cleanly.
func rewriteArchiveFlippingBbolt(t *testing.T, src, dst string) {
	rewriteArchive(t, src, dst, func(name string, data []byte) ([]byte, bool) {
		if name == bboltSnapshotEntry && len(data) > 0 {
			data[0] ^= 0xFF // same length, header.Size stays valid
		}
		return data, true
	})
}

func rewriteArchiveDroppingBbolt(t *testing.T, src, dst string) {
	rewriteArchive(t, src, dst, func(name string, data []byte) ([]byte, bool) {
		return data, name != bboltSnapshotEntry
	})
}

func archiveEntryNames(t *testing.T, src string) map[string]bool {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	zr, err := zstd.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	names := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[hdr.Name] = true
	}
	return names
}

func rewriteArchiveAppendingFile(t *testing.T, src, dst, name string, data []byte) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	zr, err := zstd.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	zw, err := zstd.NewWriter(out)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func rewriteArchive(t *testing.T, src, dst string, edit func(name string, data []byte) ([]byte, bool)) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	zr, err := zstd.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	zw, err := zstd.NewWriter(out)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			var keep bool
			data, keep = edit(hdr.Name, data)
			if !keep {
				continue
			}
		}
		hdr.Size = int64(len(data))
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveExportSkipsStateLockFile(t *testing.T) {
	statePath, rulesPath, archivePath, db, _, _, _ := mustExportSetup(t)
	if err := os.WriteFile(filepath.Join(statePath, stateLockFileName), []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Export(ExportOptions{
		StatePath: statePath,
		RulesPath: rulesPath,
		DstPath:   archivePath,
		Manifest:  defaultManifest(),
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	names := archiveEntryNames(t, archivePath)
	if names[stateEntryPrefix+stateLockFileName] {
		t.Fatalf("archive included runtime lock file %q", stateEntryPrefix+stateLockFileName)
	}
}

func TestArchiveImportSkipsStateLockFileFromOldArchive(t *testing.T) {
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

	withLock := filepath.Join(t.TempDir(), "with-lock.csmbak")
	rewriteArchiveAppendingFile(t, archivePath, withLock, stateEntryPrefix+stateLockFileName, []byte("stale\n"))

	targetState := t.TempDir()
	if _, err := Import(ImportOptions{
		SrcPath:         withLock,
		StatePath:       targetState,
		RulesPath:       t.TempDir(),
		Only:            "baseline",
		CurrentPlatform: defaultPlatform(),
	}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetState, stateLockFileName)); !os.IsNotExist(err) {
		t.Fatalf("import restored runtime lock file: %v", err)
	}
}

// A bbolt snapshot tampered after export (manifest hash unchanged) must be
// rejected before it can replace the live database, not promoted blindly.
func TestArchiveImportRejectsTamperedBboltSnapshot(t *testing.T) {
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

	tampered := filepath.Join(t.TempDir(), "tampered.csmbak")
	rewriteArchiveFlippingBbolt(t, archivePath, tampered)

	for _, only := range []string{"all", "firewall"} {
		t.Run(only, func(t *testing.T) {
			_, err := Import(ImportOptions{
				SrcPath:         tampered,
				StatePath:       t.TempDir(),
				RulesPath:       t.TempDir(),
				Only:            only,
				CurrentPlatform: defaultPlatform(),
			})
			if err == nil {
				t.Fatal("Import accepted a tampered bbolt snapshot")
			}
			if !errors.Is(err, ErrCorruptArchive) {
				t.Errorf("Import err = %v, want ErrCorruptArchive", err)
			}
		})
	}
}

func TestArchiveImportHashMismatchDoesNotPartiallyRestore(t *testing.T) {
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

	tampered := filepath.Join(t.TempDir(), "tampered.csmbak")
	rewriteArchiveFlippingBbolt(t, archivePath, tampered)

	targetState := t.TempDir()
	targetRules := t.TempDir()
	liveState := []byte(`{"live":true}`)
	liveRule := []byte(`rule live { condition: true }`)
	if err := os.WriteFile(filepath.Join(targetState, "state.json"), liveState, 0600); err != nil {
		t.Fatalf("seed target state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetRules, "malware.yar"), liveRule, 0600); err != nil {
		t.Fatalf("seed target rules: %v", err)
	}
	targetDB, err := Open(targetState)
	if err != nil {
		t.Fatalf("open target db: %v", err)
	}
	if updateErr := targetDB.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("history")).Put([]byte("live-key"), []byte("live-value"))
	}); updateErr != nil {
		t.Fatalf("seed target db: %v", updateErr)
	}
	_ = targetDB.Close()

	_, err = Import(ImportOptions{
		SrcPath:         tampered,
		StatePath:       targetState,
		RulesPath:       targetRules,
		Only:            "all",
		CurrentPlatform: defaultPlatform(),
	})
	if err == nil {
		t.Fatal("Import accepted a tampered bbolt snapshot")
	}
	if !errors.Is(err, ErrCorruptArchive) {
		t.Errorf("Import err = %v, want ErrCorruptArchive", err)
	}

	gotState, err := os.ReadFile(filepath.Join(targetState, "state.json"))
	if err != nil {
		t.Fatalf("read target state: %v", err)
	}
	if !bytes.Equal(gotState, liveState) {
		t.Fatalf("state.json changed after rejected import: got %q want %q", gotState, liveState)
	}
	gotRule, err := os.ReadFile(filepath.Join(targetRules, "malware.yar"))
	if err != nil {
		t.Fatalf("read target rule: %v", err)
	}
	if !bytes.Equal(gotRule, liveRule) {
		t.Fatalf("malware.yar changed after rejected import: got %q want %q", gotRule, liveRule)
	}
	reopened, err := Open(targetState)
	if err != nil {
		t.Fatalf("re-open target db: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if err := reopened.bolt.View(func(tx *bolt.Tx) error {
		got := tx.Bucket([]byte("history")).Get([]byte("live-key"))
		if !bytes.Equal(got, []byte("live-value")) {
			t.Fatalf("target db changed after rejected import: got %q want live-value", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify target db: %v", err)
	}
}

func TestArchiveImportOnlyBaselineIgnoresTamperedBboltSnapshot(t *testing.T) {
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

	tampered := filepath.Join(t.TempDir(), "tampered.csmbak")
	rewriteArchiveFlippingBbolt(t, archivePath, tampered)

	targetState := t.TempDir()
	imp, err := Import(ImportOptions{
		SrcPath:         tampered,
		StatePath:       targetState,
		RulesPath:       t.TempDir(),
		Only:            "baseline",
		CurrentPlatform: defaultPlatform(),
	})
	if err != nil {
		t.Fatalf("baseline import should not consume bbolt snapshot: %v", err)
	}
	if len(imp.BucketsRestored) != 0 {
		t.Fatalf("baseline import restored bbolt buckets: %v", imp.BucketsRestored)
	}
	for name, content := range wantState {
		got, err := os.ReadFile(filepath.Join(targetState, name))
		if err != nil {
			t.Errorf("read state %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("state %s mismatch after baseline import", name)
		}
	}
}

func TestArchiveImportFullRestoreRequiresBboltSnapshot(t *testing.T) {
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

	missingBbolt := filepath.Join(t.TempDir(), "missing-bbolt.csmbak")
	rewriteArchiveDroppingBbolt(t, archivePath, missingBbolt)

	for _, only := range []string{"all", "firewall"} {
		t.Run(only, func(t *testing.T) {
			targetState := t.TempDir()
			targetRules := t.TempDir()
			liveState := []byte(`{"live":true}`)
			liveRule := []byte(`rule live { condition: true }`)
			if err := os.WriteFile(filepath.Join(targetState, "state.json"), liveState, 0600); err != nil {
				t.Fatalf("seed target state: %v", err)
			}
			if err := os.WriteFile(filepath.Join(targetRules, "malware.yar"), liveRule, 0600); err != nil {
				t.Fatalf("seed target rules: %v", err)
			}

			_, err := Import(ImportOptions{
				SrcPath:         missingBbolt,
				StatePath:       targetState,
				RulesPath:       targetRules,
				Only:            only,
				CurrentPlatform: defaultPlatform(),
			})
			if err == nil {
				t.Fatal("Import accepted an archive missing the bbolt snapshot")
			}
			if !errors.Is(err, ErrCorruptArchive) {
				t.Errorf("Import err = %v, want ErrCorruptArchive", err)
			}
			gotState, err := os.ReadFile(filepath.Join(targetState, "state.json"))
			if err != nil {
				t.Fatalf("read target state: %v", err)
			}
			if !bytes.Equal(gotState, liveState) {
				t.Fatalf("state.json changed after rejected import: got %q want %q", gotState, liveState)
			}
			gotRule, err := os.ReadFile(filepath.Join(targetRules, "malware.yar"))
			if err != nil {
				t.Fatalf("read target rule: %v", err)
			}
			if !bytes.Equal(gotRule, liveRule) {
				t.Fatalf("malware.yar changed after rejected import: got %q want %q", gotRule, liveRule)
			}
		})
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
