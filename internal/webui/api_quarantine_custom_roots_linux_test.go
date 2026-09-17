//go:build linux

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func TestQuarantineRestoreConfiguredAccountRoot(t *testing.T) {
	base := t.TempDir()
	legacy, custom := filepath.Join(base, "legacy"), filepath.Join(base, "accounts", "alice", "public")
	for _, path := range []string{legacy, custom} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	withQuarantineRestoreRoots(t, legacy)
	qdir := t.TempDir()
	withQuarantineDir(t, qdir)
	destination := filepath.Join(custom, "restored.php")
	meta := checks.QuarantineMeta{OriginalPath: destination, Owner: os.Getuid(), Group: os.Getgid(), Mode: "-rw-r-----"}
	data, marshalErr := json.Marshal(meta)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if err := os.WriteFile(filepath.Join(qdir, "item"), []byte("original bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(qdir, "item.meta"), data, 0600); err != nil {
		t.Fatal(err)
	}
	server := newRestoreServer(t)
	server.cfg.AccountRoots = []string{filepath.Join(base, "accounts", "*", "public")}
	// Another tenant's alias is excluded without denying this recovery.
	other := filepath.Join(base, "accounts", "other")
	if mkdirErr := os.Mkdir(other, 0755); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	if linkErr := os.Symlink(t.TempDir(), filepath.Join(other, "public")); linkErr != nil {
		t.Fatal(linkErr)
	}
	response := httptest.NewRecorder()
	server.apiQuarantineRestore(response, newRestoreRequest(t, map[string]string{"id": "item"}))
	if response.Code != http.StatusOK {
		t.Fatalf("configured root restore=%d %s", response.Code, response.Body.String())
	}
	got, err := os.ReadFile(destination)
	if err != nil || string(got) != "original bytes" {
		t.Fatalf("restored bytes=%q error=%v", got, err)
	}
}

func TestQuarantineRestoreConfiguredRootBoundaries(t *testing.T) {
	for _, attack := range []string{"sibling", "symlink", "ancestor swap"} {
		t.Run(attack, func(t *testing.T) {
			base := t.TempDir()
			custom, outside := filepath.Join(base, "accounts", "alice", "public"), filepath.Join(base, "outside")
			for _, path := range []string{custom, outside} {
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			guard := filepath.Join(outside, "guard")
			if err := os.WriteFile(guard, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			destination := guard
			want := http.StatusBadRequest
			if attack != "sibling" {
				parent := filepath.Join(custom, "sub")
				destination = filepath.Join(parent, "guard")
				if attack == "symlink" {
					if err := os.Symlink(outside, parent); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(parent, 0755); err != nil {
						t.Fatal(err)
					}
					quarantineRestoreAfterValidateForTest = func(string) {
						if err := os.Rename(parent, parent+"-moved"); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(outside, parent); err != nil {
							t.Fatal(err)
						}
					}
					t.Cleanup(func() { quarantineRestoreAfterValidateForTest = nil })
					want = http.StatusConflict
				}
			}
			withQuarantineRestoreRoots(t, filepath.Join(base, "legacy"))
			qdir := t.TempDir()
			withQuarantineDir(t, qdir)
			metadata, marshalErr := json.Marshal(checks.QuarantineMeta{OriginalPath: destination, Mode: "-rw-------", Owner: os.Getuid(), Group: os.Getgid()})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			for name, data := range map[string][]byte{"item": []byte("replacement"), "item.meta": metadata} {
				if err := os.WriteFile(filepath.Join(qdir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			server := newRestoreServer(t)
			server.cfg.AccountRoots = []string{custom}
			response := httptest.NewRecorder()
			server.apiQuarantineRestore(response, newRestoreRequest(t, map[string]string{"id": "item"}))
			if response.Code != want {
				t.Fatalf("restore=%d want=%d %s", response.Code, want, response.Body.String())
			}
			data, err := os.ReadFile(guard)
			if err != nil || string(data) != "untouched" {
				t.Fatalf("outside guard changed: %q %v", data, err)
			}
			for _, name := range []string{"item", "item.meta"} {
				if _, statErr := os.Stat(filepath.Join(qdir, name)); statErr != nil {
					t.Fatalf("failed recovery lost %s: %v", name, statErr)
				}
			}
		})
	}
}

func TestQuarantineRestoreDoesNotFollowReplacedConfiguredRoot(t *testing.T) {
	base := t.TempDir()
	custom, outside := filepath.Join(base, "custom"), filepath.Join(base, "outside")
	for _, path := range []string{custom, outside} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	roots := []string{custom}
	if err := os.Rename(custom, custom+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, custom); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(outside, "guard"), filepath.Join(custom, "guard")} {
		target, err := openQuarantineRestoreTarget(path, roots, true)
		if err == nil {
			target.Close()
			t.Errorf("accepted replaced configured root for %s", path)
		}
	}
}
