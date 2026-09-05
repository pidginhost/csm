package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/safepath"
)

func TestQuarantineRestoreAncestorSwap(t *testing.T) {
	for _, kind := range []string{"file", "missing parents", "directory", "virtual replace", "virtual remove"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			allowed := filepath.Join(base, "allowed")
			parent := filepath.Join(allowed, "account")
			outside := filepath.Join(base, "outside")
			qdir := filepath.Join(base, "quarantine")
			for _, dir := range []string{parent, outside, filepath.Join(qdir, "pre_clean")} {
				if opErr := os.MkdirAll(dir, 0700); opErr != nil {
					t.Fatal(opErr)
				}
			}
			withQuarantineDir(t, qdir)
			withQuarantineRestoreRoots(t, allowed)
			name := "restored.php"
			id := "restore-item"
			item := filepath.Join(qdir, id)
			meta := checks.QuarantineMeta{Owner: os.Getuid(), Group: os.Getgid(), Mode: "-rw-r--r--"}
			payload := []byte("quarantined content")
			switch kind {
			case "missing parents":
				name = "missing/deep/restored.php"
			case "directory":
				meta.Mode = "drwxr-xr-x"
				if opErr := os.Mkdir(item, 0700); opErr != nil {
					t.Fatal(opErr)
				}
				if opErr := os.WriteFile(filepath.Join(item, "child"), payload, 0600); opErr != nil {
					t.Fatal(opErr)
				}
			case "virtual replace", "virtual remove":
				name = ".htaccess"
				id = "pre_clean:" + id
				item = filepath.Join(qdir, "pre_clean", "restore-item")
				meta.RestoreAction = checks.QuarantineRestoreReplaceIfUnchanged
				if kind == "virtual remove" {
					meta.RestoreAction = checks.QuarantineRestoreRemoveIfUnchanged
				}
				patched := []byte("Require all denied\n")
				meta.ExpectedCurrentSHA256 = restoreTestSHA256(patched)
				for _, dir := range []string{parent, outside} {
					if opErr := os.WriteFile(filepath.Join(dir, name), patched, 0644); opErr != nil {
						t.Fatal(opErr)
					}
				}
				owner := fileOwner(t, filepath.Join(parent, name))
				meta.Owner, meta.Group = owner.uid, owner.gid
			}
			if kind != "directory" {
				if opErr := os.WriteFile(item, payload, 0600); opErr != nil {
					t.Fatal(opErr)
				}
			}
			meta.OriginalPath = filepath.Join(parent, name)
			data, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			if opErr := os.WriteFile(item+".meta", data, 0600); opErr != nil {
				t.Fatal(opErr)
			}
			oldHook := quarantineRestoreAfterValidateForTest
			quarantineRestoreAfterValidateForTest = func(string) {
				if opErr := os.Rename(parent, parent+".old"); opErr != nil {
					t.Fatal(opErr)
				}
				if opErr := os.Symlink(outside, parent); opErr != nil {
					t.Fatal(opErr)
				}
			}
			t.Cleanup(func() { quarantineRestoreAfterValidateForTest = oldHook })
			w := httptest.NewRecorder()
			newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code != http.StatusConflict {
				t.Errorf("replaced ancestor: status %d, body %s", w.Code, w.Body.String())
			}
			if kind == "virtual replace" || kind == "virtual remove" {
				got, err := os.ReadFile(filepath.Join(outside, name))
				if err != nil || string(got) != "Require all denied\n" {
					t.Errorf("outside file changed: %q, %v", got, err)
				}
			} else {
				entries, err := os.ReadDir(outside)
				if err != nil || len(entries) != 0 {
					t.Errorf("restore wrote outside root: entries=%v, err=%v", entries, err)
				}
			}
			for _, path := range []string{item, item + ".meta"} {
				if _, opErr := os.Lstat(path); opErr != nil {
					t.Errorf("quarantine evidence lost: %s: %v", path, opErr)
				}
			}
		})
	}
}

func TestQuarantineDirectoryRollbackPreservesReplacement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	qdir := filepath.Join(base, "quarantine")
	item := filepath.Join(qdir, "item")
	for _, dir := range []string{root, item} {
		if opErr := os.MkdirAll(dir, 0700); opErr != nil {
			t.Fatal(opErr)
		}
	}
	if opErr := os.WriteFile(filepath.Join(item, "original"), []byte("quarantined"), 0600); opErr != nil {
		t.Fatal(opErr)
	}
	target, err := safepath.OpenTarget(root, "restored", false)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	live := filepath.Join(root, target.Name)
	oldHook := quarantineRestoreAfterDirectoryMoveForTest
	quarantineRestoreAfterDirectoryMoveForTest = func() {
		if opErr := os.Rename(live, live+".moved"); opErr != nil {
			t.Fatal(opErr)
		}
		if opErr := os.Symlink("restored.moved", live); opErr != nil {
			t.Fatal(opErr)
		}
	}
	t.Cleanup(func() { quarantineRestoreAfterDirectoryMoveForTest = oldHook })
	owner := fileOwner(t, item)
	if err := restoreQuarantineDirectory(item, target, 0700, owner.uid, owner.gid); err == nil {
		t.Fatal("replaced directory passed restore")
	}
	if info, err := os.Lstat(item); !os.IsNotExist(err) {
		t.Errorf("replacement imported into quarantine: %v, %v", info, err)
	}
	if got, err := os.Readlink(live); err != nil || got != "restored.moved" {
		t.Errorf("replacement lost: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(live+".moved", "original")); err != nil || string(got) != "quarantined" {
		t.Errorf("original directory content lost: %q, %v", got, err)
	}
}

func TestQuarantineRestoreAncestorSwapAfterCreate(t *testing.T) {
	for _, phase := range []string{"after create", "before finalize"} {
		t.Run(phase, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			parent := filepath.Join(root, "account")
			outside := filepath.Join(base, "outside")
			qdir := filepath.Join(base, "quarantine")
			for _, dir := range []string{parent, outside, qdir} {
				if opErr := os.MkdirAll(dir, 0700); opErr != nil {
					t.Fatal(opErr)
				}
			}
			withQuarantineDir(t, qdir)
			withQuarantineRestoreRoots(t, root)
			id := "restore-item"
			item := filepath.Join(qdir, id)
			payload := []byte("quarantine content")
			if opErr := os.WriteFile(item, payload, 0600); opErr != nil {
				t.Fatal(opErr)
			}
			meta := checks.QuarantineMeta{
				OriginalPath: filepath.Join(parent, "file"), Owner: os.Getuid(), Group: os.Getgid(), Mode: "-rw-r--r--",
			}
			data, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			if opErr := os.WriteFile(item+".meta", data, 0600); opErr != nil {
				t.Fatal(opErr)
			}
			outsideFile := filepath.Join(outside, "file")
			if opErr := os.WriteFile(outsideFile, []byte("survivor"), 0600); opErr != nil {
				t.Fatal(opErr)
			}
			before, err := os.Stat(outsideFile)
			if err != nil {
				t.Fatal(err)
			}
			ownerBefore := fileOwner(t, outsideFile)
			swap := func(string) {
				if opErr := os.Rename(parent, parent+".old"); opErr != nil {
					t.Fatal(opErr)
				}
				if opErr := os.Symlink(outside, parent); opErr != nil {
					t.Fatal(opErr)
				}
			}
			if phase == "after create" {
				withQuarantineRestoreAfterCreateHook(t, swap)
			} else {
				old := quarantineRestoreBeforeFinalizeForTest
				quarantineRestoreBeforeFinalizeForTest = swap
				t.Cleanup(func() { quarantineRestoreBeforeFinalizeForTest = old })
			}
			w := httptest.NewRecorder()
			newRestoreServer(t).apiQuarantineRestore(w, newRestoreRequest(t, map[string]string{"id": id}))
			if w.Code != http.StatusConflict {
				t.Fatalf("replaced parent: status %d, body %s", w.Code, w.Body.String())
			}
			got, err := os.ReadFile(outsideFile)
			if err != nil || string(got) != "survivor" {
				t.Errorf("outside content changed: %q, %v", got, err)
			}
			after, err := os.Stat(outsideFile)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Errorf("outside inode or permissions changed: %v, %v", after, err)
			}
			if ownerAfter := fileOwner(t, outsideFile); ownerAfter != ownerBefore {
				t.Errorf("outside ownership changed: got %v, want %v", ownerAfter, ownerBefore)
			}
			got, err = os.ReadFile(item)
			if err != nil || string(got) != string(payload) {
				t.Errorf("quarantine content lost: %q, %v", got, err)
			}
			if _, opErr := os.Stat(item + ".meta"); opErr != nil {
				t.Errorf("quarantine metadata lost: %v", opErr)
			}
		})
	}
}
