package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	csmstore "github.com/pidginhost/csm/internal/store"
)

// A learning-only restore copies the live database to hold the restored
// keys. A damaged live database must refuse the restore with an error,
// never crash it, and leave the live files as they were. Damage past the
// end of a truncated file faults instead of panicking, so the cases run in
// a child process where a crash fails the test instead of the binary.
func TestRestoreLearningOnlyRefusesDamagedLiveDatabase(t *testing.T) {
	const child = "CSM_TEST_RESTORE_DAMAGED_LIVE"
	if os.Getenv(child) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRestoreLearningOnlyRefusesDamagedLiveDatabase$", "-test.v")
		cmd.Env = append(os.Environ(), child+"=1")
		if output, err := cmd.CombinedOutput(); err != nil || !bytes.Contains(output, []byte("--- PASS")) {
			t.Fatalf("damaged live database in a child: %v\n%s", err, output)
		}
		return
	}
	page := int64(os.Getpagesize())
	for name, damage := range map[string]func(t *testing.T, path string){
		"damaged pages": func(t *testing.T, path string) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for i := 2 * page; i < int64(len(data)); i++ {
				data[i] = 0xa5
			}
			if err = os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"truncated after the meta pages": func(t *testing.T, path string) {
			if err := os.Truncate(path, 2*page); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			srcLearning := filepath.Join(dir, "source-learning")
			writeLearningTree(t, srcLearning, "csmfz_restored")
			archive := filepath.Join(dir, "backup.tar.gz")
			if err := WriteBackupArchive(archive, BackupSources{LearningDir: srcLearning}); err != nil {
				t.Fatal(err)
			}
			dst := BackupSources{StateDir: filepath.Join(dir, "state"), LearningDir: filepath.Join(dir, "learning")}
			bindLedger(t, dst.StateDir)
			writeLearningTree(t, dst.LearningDir, "csmfz_current")
			live := filepath.Join(dst.StateDir, "csm.db")
			damage(t, live)
			before, err := os.ReadFile(live)
			if err != nil {
				t.Fatal(err)
			}
			if err = RestoreBackupArchive(archive, dst); err == nil || !strings.Contains(err.Error(), "bbolt snapshot is damaged") {
				t.Fatalf("restore error = %v, want database damage", err)
			}
			if after, readErr := os.ReadFile(live); readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("refused restore changed the live database: %v", readErr)
			}
			if got, readErr := os.ReadFile(filepath.Join(dst.LearningDir, "keys/prefix")); readErr != nil || string(got) != "csmfz_current" {
				t.Fatalf("refused restore changed keys: %q, %v", got, readErr)
			}
		})
	}
}

func TestStageLearningOnlyDatabaseChecksCopiedBytes(t *testing.T) {
	stateDir := t.TempDir()
	bindLedger(t, stateDir)
	// Shorten the source after the copier has opened and measured it.
	// An empty copy would be initialized as a fresh database by bbolt.
	original := backupFreeBytes
	t.Cleanup(func() { backupFreeBytes = original })
	backupFreeBytes = func(path string) (uint64, error) {
		if err := os.Truncate(filepath.Join(stateDir, "csm.db"), 0); err != nil {
			t.Fatal(err)
		}
		return original(path)
	}
	if err := stageLearningOnlyDatabase(t.TempDir(), stateDir); err == nil || !strings.Contains(err.Error(), "bbolt snapshot is damaged") {
		t.Fatalf("staging error = %v, want database damage", err)
	}
}

func TestRestoreLearningOnlyAcceptsLeakedLivePages(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source-learning")
	writeLearningTree(t, source, "csmfz_restored")
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{LearningDir: source}); err != nil {
		t.Fatal(err)
	}
	dst := BackupSources{StateDir: filepath.Join(dir, "state"), LearningDir: filepath.Join(dir, "learning")}
	bindLedger(t, dst.StateDir)
	live := filepath.Join(dst.StateDir, "csm.db")
	data, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	// Drop the free page IDs from the active transaction's freelist.
	order := binary.NativeEndian
	page := os.Getpagesize()
	meta := data[:page]
	if order.Uint64(data[page+64:]) > order.Uint64(meta[64:]) {
		meta = data[page:]
	}
	freelist := order.Uint64(meta[48:]) * uint64(page)
	order.PutUint16(data[freelist+10:], 0)
	if err := os.WriteFile(live, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := csmstore.DisarmFirewallRollbackSnapshot(live); err == nil || !strings.Contains(err.Error(), "unreachable unfreed pages") {
		t.Fatalf("snapshot verification = %v, want leaked pages", err)
	}
	if err := RestoreBackupArchive(archive, dst); err != nil {
		t.Fatal(err)
	}
	if !declaredRestore(t, dst.StateDir) {
		t.Fatal("learning was not held after restore")
	}
}
