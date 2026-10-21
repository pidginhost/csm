package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// A permission change the owner makes while the replacement is staged must
// not be overwritten with the mode read before it.
func TestCleanRefusesChangedPermissions(t *testing.T) {
	root := realTempDir(t)
	path := filepath.Join(root, ".user.ini")
	const original = "display_errors = On\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	withCleanAfterTempCreated(t, func(string) {
		if err := os.Chmod(path, 0600); err != nil {
			t.Errorf("chmod: %v", err)
		}
	})
	res := FixDisplayErrorsOnInRoots(path, []string{root})
	if res.Success || res.Error == "" {
		t.Errorf("permission change was ignored: %+v", res)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("private permissions were lost: %v, %v", info, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != original {
		t.Fatalf("private file was changed: %q, %v", got, err)
	}
}

func TestErrorLogFixRefusesChangedAncestor(t *testing.T) {
	root := realTempDir(t)
	site := filepath.Join(root, "site")
	if err := os.Mkdir(site, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(site, "error_log")
	if err := os.WriteFile(path, []byte("original log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	withFixAfterPathResolved(t, func(string) {
		if err := os.Rename(site, site+".moved"); err != nil {
			t.Errorf("rename: %v", err)
			return
		}
		if err := os.Symlink(site+".moved", site); err != nil {
			t.Errorf("symlink: %v", err)
		}
	})
	res := FixErrorLogBloatInRoots(path, []string{root})
	if res.Success {
		t.Fatalf("changed ancestor accepted: %+v", res)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "original log\n" {
		t.Fatalf("relocated log changed: %q, %v", got, err)
	}
}

func TestHtaccessCleanPinsValidatedFile(t *testing.T) {
	for _, kind := range []string{"clean", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			root := setupHtaccessCleanRoots(t)
			path := writeHtaccess(t, root, "site", "# original\nAddHandler cgi-script .alfa\n")
			const replacement = "# replacement\nAddHandler cgi-script .alfa\n"
			withFixAfterPathResolved(t, func(string) {
				if err := os.Rename(path, path+".old"); err != nil {
					t.Errorf("rename: %v", err)
					return
				}
				if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
					t.Errorf("write: %v", err)
				}
			})
			var res RemediationResult
			if kind == "clean" {
				res = CleanHtaccessFile(path)
			} else {
				res = fixHtaccess(path, "")
			}
			if res.Success || !res.Refused {
				t.Errorf("replacement not refused: %+v", res)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != replacement {
				t.Fatalf("replacement changed: %q, %v", got, err)
			}
		})
	}
}
