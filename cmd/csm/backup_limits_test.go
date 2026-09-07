package main

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func TestBackupRestoreLargeStateArchive(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(source, "csm.db")
	db, openErr := bolt.Open(dbPath, 0600, nil)
	if openErr != nil {
		t.Fatal(openErr)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, createErr := tx.CreateBucket([]byte("restore-size-test"))
		if createErr != nil {
			return createErr
		}
		return bucket.Put([]byte("key"), []byte("retained"))
	}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// A bbolt file may retain unused space after deletions. Extend a valid
	// database sparsely so the round trip has to stream it rather than hold
	// it. The size only has to stand well clear of the allocation bound
	// asserted below, because an implementation that buffered would allocate
	// the whole file: at 256 MiB against a 64 MiB bound that is still a
	// four-fold margin. Size drives the runtime directly, since -race walks
	// every byte of the tar and gzip loops -- this test took 90s at 1 GiB and
	// takes 22s here.
	const size = 256<<20 + 4096
	if err := os.Truncate(dbPath, size); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.tar.gz")
	destination := filepath.Join(root, "restored")
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := WriteBackupArchive(archive, BackupSources{StateDir: source}); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackupArchive(archive, BackupSources{StateDir: destination}); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("streaming round-trip allocated %d bytes for a %d-byte database", allocated, size)
	}
	restored := filepath.Join(destination, "csm.db")
	info, err := os.Stat(restored)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != size {
		t.Fatalf("restored database size=%d, want %d", info.Size(), size)
	}
	db, openErr = bolt.Open(restored, 0600, &bolt.Options{ReadOnly: true})
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	if err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("restore-size-test"))
		if bucket == nil || string(bucket.Get([]byte("key"))) != "retained" {
			t.Error("restored database lost its committed value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func backupUncompressedSize(t *testing.T, archive string) int64 {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		_ = r.Close()
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return n
}

func backupLimitFixture(t *testing.T, root, content string) BackupSources {
	t.Helper()
	paths := BackupSources{ConfigPath: filepath.Join(root, "csm.yaml"), ConfDir: filepath.Join(root, "conf.d"), StateDir: filepath.Join(root, "state")}
	for _, path := range []string{paths.ConfDir, paths.StateDir} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{paths.ConfigPath, filepath.Join(paths.ConfDir, "settings.yaml"), filepath.Join(paths.StateDir, "retained")} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func assertBackupLimitFixture(t *testing.T, paths BackupSources, content string) {
	t.Helper()
	for _, path := range []string{paths.ConfigPath, filepath.Join(paths.ConfDir, "settings.yaml"), filepath.Join(paths.StateDir, "retained")} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != content {
			t.Errorf("%s=%q, error=%v; want %q", path, data, err, content)
		}
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(paths.ConfigPath), ".csm-restore-*"))
	if err != nil || len(leftovers) != 0 {
		t.Errorf("restore staging remains: %v, error=%v", leftovers, err)
	}
}

func TestBackupRestoreTotalSizeBoundaries(t *testing.T) {
	src := backupLimitFixture(t, t.TempDir(), strings.Repeat("new", 201))
	archive := filepath.Join(t.TempDir(), "reference.tar.gz")
	if err := WriteBackupArchive(archive, src); err != nil {
		t.Fatal(err)
	}
	size := backupUncompressedSize(t, archive)
	for _, delta := range []int64{-1, 0, 1} {
		t.Run(fmt.Sprintf("limit=%d", size+delta), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "backup.tar.gz")
			if err := os.WriteFile(out, []byte("previous-backup"), 0600); err != nil {
				t.Fatal(err)
			}
			src.MaxBytes = size + delta
			backupErr := WriteBackupArchive(out, src)
			dst := backupLimitFixture(t, t.TempDir(), "original")
			dst.MaxBytes = src.MaxBytes
			restoreArchive := archive
			if backupErr == nil {
				restoreArchive = out
			}
			restoreErr := RestoreBackupArchive(restoreArchive, dst)
			if delta < 0 {
				if !errors.Is(backupErr, errBackupSizeLimit) || !errors.Is(restoreErr, errBackupSizeLimit) {
					t.Fatalf("over-limit errors: backup=%v restore=%v", backupErr, restoreErr)
				}
				data, err := os.ReadFile(out)
				if err != nil || string(data) != "previous-backup" {
					t.Fatalf("failed backup replaced previous archive: %q, error=%v", data, err)
				}
				assertBackupLimitFixture(t, dst, "original")
			} else {
				if backupErr != nil || restoreErr != nil {
					t.Fatalf("in-limit errors: backup=%v restore=%v", backupErr, restoreErr)
				}
				assertBackupLimitFixture(t, dst, strings.Repeat("new", 201))
				if got := backupUncompressedSize(t, out); got != size {
					t.Fatalf("new backup uncompressed size=%d, want %d", got, size)
				}
			}
			leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(out), ".csm-backup-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("backup staging remains: %v, error=%v", leftovers, err)
			}
		})
	}
}

func TestRestoreBudgetCountsSkippedEntries(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "unknown.tar.gz")
	if err := writeArchiveEntries(archive, []archiveTestEntry{
		{name: "csm.yaml", size: 3, body: []byte("new")},
		{name: "unknown", size: 4096, body: make([]byte, 4096)},
	}); err != nil {
		t.Fatal(err)
	}
	dst := backupLimitFixture(t, t.TempDir(), "original")
	dst.MaxBytes = 2048
	if err := RestoreBackupArchive(archive, dst); !errors.Is(err, errBackupSizeLimit) {
		t.Fatalf("unknown archive content bypassed size budget: %v", err)
	}
	assertBackupLimitFixture(t, dst, "original")
}

func TestRestoreManifestSizeBoundaries(t *testing.T) {
	for _, size := range []int{maxRestoreManifestSize - 1, maxRestoreManifestSize, maxRestoreManifestSize + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			manifest := "schema=1\n" + strings.Repeat("x", size-len("schema=1\n"))
			archive := filepath.Join(t.TempDir(), "manifest.tar.gz")
			if err := writeArchiveEntries(archive, []archiveTestEntry{
				{name: "csm.yaml", size: 3, body: []byte("new")},
				{name: "manifest.txt", size: int64(size), body: []byte(manifest)},
			}); err != nil {
				t.Fatal(err)
			}
			dst := backupLimitFixture(t, t.TempDir(), "original")
			err := RestoreBackupArchive(archive, dst)
			if size > maxRestoreManifestSize {
				if err == nil || !strings.Contains(err.Error(), "manifest exceeds") {
					t.Fatalf("oversized manifest error=%v", err)
				}
				assertBackupLimitFixture(t, dst, "original")
			} else {
				if err != nil {
					t.Fatal(err)
				}
				data, readErr := os.ReadFile(dst.ConfigPath)
				if readErr != nil || string(data) != "new" {
					t.Fatalf("valid manifest restore=%q, error=%v", data, readErr)
				}
			}
		})
	}
}

func TestRestoreInsufficientSpaceLeavesDestinationsUnchanged(t *testing.T) {
	src := backupLimitFixture(t, t.TempDir(), "new")
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := WriteBackupArchive(archive, src); err != nil {
		t.Fatal(err)
	}
	oldFree := backupFreeBytes
	t.Cleanup(func() { backupFreeBytes = oldFree })
	for _, failure := range []error{unix.ENOSPC, unix.EIO} {
		// Three extraction writes, then three replacement copies on their
		// destination filesystems. Every failure must precede live replacement.
		for failAt := 1; failAt <= 6; failAt++ {
			t.Run(fmt.Sprintf("%s/check-%d", failure, failAt), func(t *testing.T) {
				calls := 0
				backupFreeBytes = func(string) (uint64, error) {
					calls++
					if calls == failAt {
						if failure == unix.ENOSPC {
							return 0, nil
						}
						return 0, failure
					}
					return 1 << 40, nil
				}
				dst := backupLimitFixture(t, t.TempDir(), "original")
				if err := RestoreBackupArchive(archive, dst); !errors.Is(err, failure) {
					t.Fatalf("restore error=%v, want %v", err, failure)
				}
				if calls != failAt {
					t.Fatalf("space checks=%d, want %d", calls, failAt)
				}
				assertBackupLimitFixture(t, dst, "original")
			})
		}
	}
}

func TestBackupSnapshotSpaceAndSizeFailuresKeepPreviousArchive(t *testing.T) {
	stateDir := t.TempDir()
	createBackupTestDB(t, stateDir)
	oldFree := backupFreeBytes
	t.Cleanup(func() { backupFreeBytes = oldFree })
	for _, failure := range []error{unix.ENOSPC, errBackupSizeLimit} {
		t.Run(failure.Error(), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "backup.tar.gz")
			if err := os.WriteFile(out, []byte("previous"), 0600); err != nil {
				t.Fatal(err)
			}
			src := BackupSources{StateDir: stateDir}
			if failure == unix.ENOSPC {
				backupFreeBytes = func(string) (uint64, error) { return 0, nil }
			} else {
				backupFreeBytes = oldFree
				src.MaxBytes = 1024
			}
			if err := WriteBackupArchive(out, src); !errors.Is(err, failure) {
				t.Fatalf("backup error=%v, want %v", err, failure)
			}
			data, err := os.ReadFile(out)
			if err != nil || string(data) != "previous" {
				t.Fatalf("previous backup=%q, error=%v", data, err)
			}
			entries, err := os.ReadDir(filepath.Dir(out))
			if err != nil || len(entries) != 1 || entries[0].Name() != "backup.tar.gz" {
				t.Fatalf("failed snapshot left staging: %v, error=%v", entries, err)
			}
		})
	}
}

func TestBackupSpaceReserveBoundary(t *testing.T) {
	oldFree := backupFreeBytes
	t.Cleanup(func() { backupFreeBytes = oldFree })
	const payload = 4096
	for _, delta := range []int{-1, 0, 1} {
		backupFreeBytes = func(string) (uint64, error) { return uint64(backupSpaceReserve + payload + delta), nil }
		err := requireBackupSpace("unused", payload)
		if delta < 0 && !errors.Is(err, unix.ENOSPC) || delta >= 0 && err != nil {
			t.Fatalf("reserve boundary delta=%d error=%v", delta, err)
		}
	}
}

func TestParseBackupRestoreArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		path string
		max  int64
	}{
		{[]string{"backup.tar.gz"}, "backup.tar.gz", 0},
		{[]string{"--max-bytes", "1", "backup.tar.gz"}, "backup.tar.gz", 1},
		{[]string{"backup.tar.gz", "--max-bytes=17179869184"}, "backup.tar.gz", defaultBackupMaxBytes},
		{[]string{"--config", "/etc/csm/csm.yaml", "--config-dir", "/etc/csm/conf.d", "--max-bytes=9223372036854775807", "backup.tar.gz"}, "backup.tar.gz", 1<<63 - 1},
		{[]string{"--", "--archive.tar.gz"}, "--archive.tar.gz", 0},
	} {
		path, maxBytes, err := parseBackupRestoreArgs(tc.args)
		if err != nil || path != tc.path || maxBytes != tc.max {
			t.Errorf("parse %v=(%q, %d, %v), want (%q, %d)", tc.args, path, maxBytes, err, tc.path, tc.max)
		}
	}
	for _, args := range [][]string{
		nil, {"one", "two"}, {"--max-bytes"}, {"--config"}, {"--unknown", "archive"}, {"-x", "archive"},
		{"archive", "--max-bytes=0"}, {"archive", "--max-bytes=-1"}, {"archive", "--max-bytes=9223372036854775808"},
		{"archive", "--max-bytes=garbage"}, {"archive", "--max-bytes="},
		{"archive", "--config=/etc/csm/csm.yaml"}, {"archive", "--config-dir=/etc/csm/conf.d"},
	} {
		if _, _, err := parseBackupRestoreArgs(args); err == nil {
			t.Errorf("invalid arguments accepted: %v", args)
		}
	}
	if n, err := backupArchiveLimit(0); err != nil || n != defaultBackupMaxBytes {
		t.Fatalf("default limit=%d, error=%v", n, err)
	}
	if _, err := backupArchiveLimit(-1); err == nil {
		t.Fatal("negative archive limit accepted")
	}
}
