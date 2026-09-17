package quarantinefs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestSyncTreePersistsChildrenBeforeParentsWithoutFollowingLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "content"), []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	// A dangling external target would fail traversal if the link were followed.
	if err := os.Symlink(filepath.Join(t.TempDir(), "absent"), filepath.Join(root, "external")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	oldSync := syncFile
	t.Cleanup(func() { syncFile = oldSync })
	var synced []string
	syncFile = func(f *os.File) error {
		stat, statErr := f.Stat()
		if statErr != nil {
			return statErr
		}
		synced = append(synced, stat.Name())
		return oldSync(f)
	}
	if err := SyncTree(root, info); err != nil {
		t.Fatal(err)
	}
	if want := []string{"content", "nested", "."}; !reflect.DeepEqual(synced, want) {
		t.Fatalf("sync order=%v, want=%v", synced, want)
	}
}

func TestSyncTreeRejectsChangedRootAndPropagatesStorageFailure(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := SyncTree(t.TempDir(), info); err == nil {
		t.Fatal("accepted a different root inode")
	}
	oldSync, oldClose := syncFile, closeFile
	t.Cleanup(func() { syncFile, closeFile = oldSync, oldClose })
	for _, phase := range []string{"sync", "close"} {
		t.Run(phase, func(t *testing.T) {
			syncFile, closeFile = oldSync, oldClose
			if phase == "sync" {
				syncFile = func(*os.File) error { return syscall.EIO }
			} else {
				closeFile = func(f *os.File) error { return errors.Join(oldClose(f), syscall.EIO) }
			}
			if err := SyncTree(root, info); !errors.Is(err, syscall.EIO) {
				t.Fatalf("%s failure lost: %v", phase, err)
			}
		})
	}
}
