package checks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/safepath"
)

func virtualPatchRestoreTarget(t *testing.T, path string) *safepath.Target {
	t.Helper()
	target, err := safepath.OpenTarget(filepath.Dir(path), filepath.Base(path), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	return target
}

func TestVirtualPatchRestorePreservesConcurrentReplacement(t *testing.T) {
	for _, action := range []string{QuarantineRestoreReplaceIfUnchanged, QuarantineRestoreRemoveIfUnchanged} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			live := filepath.Join(root, ".htaccess")
			backup := filepath.Join(t.TempDir(), "backup")
			patched := []byte("Require all denied\n")
			edit := []byte("# later customer edit\n")
			if opErr := os.WriteFile(live, patched, 0600); opErr != nil {
				t.Fatal(opErr)
			}
			if opErr := os.WriteFile(backup, []byte("Options -Indexes\n"), 0600); opErr != nil {
				t.Fatal(opErr)
			}
			info, err := os.Stat(live)
			if err != nil {
				t.Fatal(err)
			}
			uid, gid, err := ownerFromInfo(info)
			if err != nil {
				t.Fatal(err)
			}
			meta := QuarantineMeta{Owner: uid, Group: gid, Mode: "-rw-------", RestoreAction: action, ExpectedCurrentSHA256: virtualPatchSHA256(patched)}
			oldHook := virtualPatchRestoreAfterMoveForTest
			virtualPatchRestoreAfterMoveForTest = func() {
				replacement := filepath.Join(root, "replacement")
				if opErr := os.WriteFile(replacement, edit, 0600); opErr != nil {
					t.Fatal(opErr)
				}
				if opErr := os.Rename(replacement, live); opErr != nil {
					t.Fatal(opErr)
				}
			}
			t.Cleanup(func() { virtualPatchRestoreAfterMoveForTest = oldHook })
			err = RestoreVirtualPatchBackup(backup, virtualPatchRestoreTarget(t, live), meta)
			if !errors.Is(err, ErrVirtualPatchRestoreConflict) {
				t.Fatalf("restore = %v, want conflict", err)
			}
			if got, readErr := os.ReadFile(live); readErr != nil || string(got) != string(edit) {
				t.Errorf("concurrent edit lost: %q, %v", got, readErr)
			}
			if got, readErr := os.ReadFile(backup); readErr != nil || string(got) != "Options -Indexes\n" {
				t.Errorf("backup changed: %q, %v", got, readErr)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			recovered := 0
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				dir := filepath.Join(root, entry.Name())
				files, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range files {
					path := filepath.Join(dir, file.Name())
					saved, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if os.SameFile(info, saved) {
						recovered++
						if got, err := os.ReadFile(path); err != nil || string(got) != string(patched) {
							t.Errorf("recovery content changed: %q, %v", got, err)
						}
					}
				}
			}
			if recovered != 1 {
				t.Errorf("retained original inodes = %d, want 1", recovered)
			}
		})
	}
}

func TestVirtualPatchRestoreRollsBackChangedParent(t *testing.T) {
	for _, action := range []string{QuarantineRestoreReplaceIfUnchanged, QuarantineRestoreRemoveIfUnchanged} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			parent := filepath.Join(root, "parent")
			outside := filepath.Join(root, "outside")
			for _, dir := range []string{parent, outside} {
				if opErr := os.Mkdir(dir, 0700); opErr != nil {
					t.Fatal(opErr)
				}
				if opErr := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("Require all denied\n"), 0600); opErr != nil {
					t.Fatal(opErr)
				}
			}
			backup := filepath.Join(t.TempDir(), "backup")
			if opErr := os.WriteFile(backup, []byte("Options -Indexes\n"), 0600); opErr != nil {
				t.Fatal(opErr)
			}
			target, err := safepath.OpenTarget(root, "parent/.htaccess", false)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			state, err := readRestoreHtaccess(target.Parent, target.Name)
			if err != nil {
				t.Fatal(err)
			}
			outsideInfo, err := os.Stat(filepath.Join(outside, ".htaccess"))
			if err != nil {
				t.Fatal(err)
			}
			meta := QuarantineMeta{Owner: state.uid, Group: state.gid, Mode: "-rw-------", RestoreAction: action, ExpectedCurrentSHA256: virtualPatchSHA256(state.content)}
			oldHook := virtualPatchRestoreAfterMoveForTest
			virtualPatchRestoreAfterMoveForTest = func() {
				if opErr := os.Rename(parent, parent+".moved"); opErr != nil {
					t.Fatal(opErr)
				}
				if opErr := os.Symlink(outside, parent); opErr != nil {
					t.Fatal(opErr)
				}
			}
			t.Cleanup(func() { virtualPatchRestoreAfterMoveForTest = oldHook })
			if err := RestoreVirtualPatchBackup(backup, target, meta); !errors.Is(err, ErrVirtualPatchRestoreConflict) {
				t.Fatalf("changed parent: %v, want conflict", err)
			}
			for _, dir := range []string{parent + ".moved", outside} {
				if got, err := os.ReadFile(filepath.Join(dir, ".htaccess")); err != nil || string(got) != string(state.content) {
					t.Errorf("rollback changed content in %s: %q, %v", dir, got, err)
				}
			}
			if got, err := os.Stat(filepath.Join(parent+".moved", ".htaccess")); err != nil || !os.SameFile(state.info, got) {
				t.Errorf("rollback did not recover original inode: %v", err)
			}
			if got, err := os.Stat(filepath.Join(outside, ".htaccess")); err != nil || !os.SameFile(outsideInfo, got) || got.Mode() != outsideInfo.Mode() {
				t.Errorf("rollback touched outside inode: %v", err)
			}
		})
	}
}
