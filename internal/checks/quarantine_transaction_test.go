package checks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/safepath"
)

func TestQuarantineUnlinkFailuresRetainRecoverableCopy(t *testing.T) {
	oldUnlink, oldSync := quarantineUnlinkSource, quarantineSyncSourceDir
	t.Cleanup(func() { quarantineUnlinkSource, quarantineSyncSourceDir = oldUnlink, oldSync })
	for _, phase := range []string{"unlink", "source-sync"} {
		t.Run(phase, func(t *testing.T) {
			quarantineUnlinkSource, quarantineSyncSourceDir = oldUnlink, oldSync
			root := t.TempDir()
			source, qPath := filepath.Join(root, "source"), filepath.Join(root, "quarantine", "captured")
			if err := os.WriteFile(source, []byte("evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			info, statErr := os.Stat(source)
			if statErr != nil {
				t.Fatal(statErr)
			}
			meta := QuarantineMeta{OriginalPath: source, Size: info.Size(), Reason: "test recovery"}
			verifyRecovery := func() {
				data, readErr := os.ReadFile(qPath)
				if readErr != nil || string(data) != "evidence" {
					t.Fatalf("recovery copy=%q, error=%v", data, readErr)
				}
				data, readErr = os.ReadFile(qPath + ".meta")
				var stored QuarantineMeta
				if readErr != nil || json.Unmarshal(data, &stored) != nil || stored != meta {
					t.Fatalf("recovery metadata=%q, error=%v", data, readErr)
				}
			}
			unlinkCalled := false
			quarantineUnlinkSource = func(path string) error {
				unlinkCalled = true
				verifyRecovery()
				if phase == "unlink" {
					return syscall.EACCES
				}
				return oldUnlink(path)
			}
			quarantineSyncSourceDir = func(path string) error {
				if !unlinkCalled {
					t.Error("source sync preceded unlink")
				}
				verifyRecovery()
				return syscall.EIO
			}
			err := quarantineTarget(source, qPath, info, meta)
			want := syscall.EIO
			if phase == "unlink" {
				want = syscall.EACCES
			}
			if !errors.Is(err, want) || !strings.Contains(err.Error(), qPath) || !unlinkCalled {
				t.Fatalf("partial completion not reported: %v", err)
			}
			verifyRecovery()
			data, readErr := os.ReadFile(source)
			if phase == "unlink" {
				if readErr != nil || string(data) != "evidence" {
					t.Fatalf("failed unlink changed original: %q, error=%v", data, readErr)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("source sync test did not exercise a completed unlink: %v", readErr)
			}
		})
	}
}

func TestQuarantineDirectoryDurability(t *testing.T) {
	oldTree, oldSync, oldRename := syncQuarantineTree, syncQuarantineDirectory, renameQuarantineDirectory
	t.Cleanup(func() {
		syncQuarantineTree, syncQuarantineDirectory, renameQuarantineDirectory = oldTree, oldSync, oldRename
	})
	for _, phase := range []string{"success", "tree-sync", "metadata", "rename", "destination-sync", "source-sync"} {
		t.Run(phase, func(t *testing.T) {
			syncQuarantineTree, syncQuarantineDirectory, renameQuarantineDirectory = oldTree, oldSync, oldRename
			root := t.TempDir()
			source, qPath := filepath.Join(root, "directory"), filepath.Join(root, "quarantine", "captured")
			if err := os.MkdirAll(filepath.Join(source, "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "nested", "content"), []byte("directory evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			info, statErr := os.Stat(source)
			if statErr != nil {
				t.Fatal(statErr)
			}
			meta := QuarantineMeta{OriginalPath: source, Reason: "directory recovery"}
			if phase == "metadata" {
				if err := os.MkdirAll(qPath+".meta", 0700); err != nil {
					t.Fatal(err)
				}
			}
			treeSynced, renamed := false, false
			syncQuarantineTree = func(path string, expected os.FileInfo) error {
				if phase == "tree-sync" {
					return syscall.EIO
				}
				treeSynced = true
				return oldTree(path, expected)
			}
			renameQuarantineDirectory = func(src *safepath.Dir, name string, dst *safepath.Dir, dstName string) error {
				data, readErr := os.ReadFile(qPath + ".meta")
				var stored QuarantineMeta
				if !treeSynced || readErr != nil || json.Unmarshal(data, &stored) != nil || stored != meta {
					t.Fatal("directory rename preceded content and metadata preparation")
				}
				if phase == "rename" {
					return syscall.EACCES
				}
				if err := oldRename(src, name, dst, dstName); err != nil {
					return err
				}
				renamed = true
				return nil
			}
			syncs := 0
			syncQuarantineDirectory = func(dir *safepath.Dir) error {
				syncs++
				if !renamed {
					t.Error("directory transition sync preceded rename")
				}
				if phase == "destination-sync" && syncs == 1 || phase == "source-sync" && syncs == 2 {
					return syscall.EIO
				}
				return oldSync(dir)
			}
			err := quarantineTarget(source, qPath, info, meta)
			if phase == "success" {
				if err != nil || syncs != 2 {
					t.Fatalf("successful directory quarantine error=%v, transition syncs=%d", err, syncs)
				}
			} else if err == nil {
				t.Fatalf("directory storage failure %s reported success", phase)
			}
			recovery := source
			if renamed {
				recovery = qPath
				data, readErr := os.ReadFile(qPath + ".meta")
				var stored QuarantineMeta
				if readErr != nil || json.Unmarshal(data, &stored) != nil || stored != meta {
					t.Fatalf("moved directory lacks recovery metadata: %q, error=%v", data, readErr)
				}
				if err != nil && !strings.Contains(err.Error(), qPath) {
					t.Fatalf("partial directory result omits recovery path: %v", err)
				}
			}
			data, readErr := os.ReadFile(filepath.Join(recovery, "nested", "content"))
			if readErr != nil || string(data) != "directory evidence" {
				t.Fatalf("directory is not recoverable after %s: %q, error=%v", phase, data, readErr)
			}
		})
	}
}
