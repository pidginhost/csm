package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A path taken from finding text must be the path the finding names. A known
// root that only appears inside a longer path names a different file.
func TestFindingPathInMessageNeverNamesAnotherFile(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	extractors := map[string]func(string) string{
		"extractFilePath":            extractFilePath,
		"extractFilePathFromMessage": extractFilePathFromMessage,
	}
	cases := []struct {
		name, msg, want string
	}{
		{"account root inside a path on another volume", "World-writable PHP file: /home2/bob/public_html/home/alice/index.php", ""},
		{"file on another home volume", "World-writable PHP file: /home2/bob/public_html/index.php", ""},
		{"temp root inside an account path on another volume", "World-writable PHP file: /home2/bob/tmp/x.php", ""},
		{"temp root inside a system path", "Found: /usr/local/tmp/x.php", ""},
		{"account root inside a temp path", "Found: /var/tmp/home/alice/index.php", "/var/tmp/home/alice/index.php"},
		{"short temp root inside the long one", "file at /var/tmp/z.php, severity high", "/var/tmp/z.php"},
		{"second path after a space in a directory name", "Found: /home/bob/x /home/alice/f.php", "/home/bob/x"},
		{"other absolute path first", "Process /usr/bin/php wrote /home/alice/x.php", ""},
		{"temp path before account path", "Found: /tmp/x.php and /home/alice/x.php", "/tmp/x.php"},
		{"path at the start", "/dev/shm/staged.bin at size 100", "/dev/shm/staged.bin"},
		{"relative mention before the path", "rule a/b matched /home/alice/x.php", "/home/alice/x.php"},
	}
	for name, extract := range extractors {
		for _, tc := range cases {
			if got := extract(tc.msg); got != tc.want {
				t.Errorf("%s, %s: %q gave %q, want %q", name, tc.name, tc.msg, got, tc.want)
			}
		}
	}
}

// The permission fix acts on the file the finding carries, not on what the
// message text can be cut down to.
func TestAutoFixPermissionsUsesFindingFilePath(t *testing.T) {
	dir := t.TempDir()
	withFixPermissionsAllowedRoots(t, dir)

	decoy := filepath.Join(dir, "a")
	target := filepath.Join(dir, "a b.php")
	for path, mode := range map[string]os.FileMode{decoy: 0666, target: 0666} {
		if err := os.WriteFile(path, []byte("<?php"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = true
	finding := alert.Finding{
		Check:    "world_writable_php",
		Message:  "World-writable PHP file: " + target,
		FilePath: target,
	}
	actions, fixed := AutoFixPermissions(cfg, []alert.Finding{finding})

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("target mode = %o, want 644 (actions %v, fixed %v)", info.Mode().Perm(), actions, fixed)
	}
	if len(actions) != 1 || len(fixed) != 1 {
		t.Fatalf("actions = %v, fixed = %v, want one of each", actions, fixed)
	}
	if fixed[0] != finding.Key() {
		t.Fatalf("fixed key = %q, want %q", fixed[0], finding.Key())
	}
	info, err = os.Stat(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0666 {
		t.Fatalf("decoy mode = %o, want unchanged 666", info.Mode().Perm())
	}
}

// A configured content root authorizes remediation outside the default account
// roots. An earlier absolute path still makes message-only selection refuse.
func TestPermissionFindingOutsideDefaultRoots(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	root := mustEvalSymlinks(t, t.TempDir())
	contentRoot := filepath.Join(root, "alice", "public")
	if err := os.MkdirAll(contentRoot, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AccountRoots: []string{filepath.Join(root, "*", "public")}}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.EnforcePermissions = true
	previous := config.Active()
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(previous) })

	for _, check := range []string{"world_writable_php", "group_writable_php"} {
		for _, automatic := range []bool{false, true} {
			for _, explicit := range []bool{false, true} {
				name := check + "/manual/message"
				if automatic {
					name = check + "/automatic/message"
				}
				if explicit {
					name += "/explicit"
				}
				t.Run(name, func(t *testing.T) {
					path := filepath.Join(contentRoot, "a b.php")
					if err := os.WriteFile(path, []byte("<?php"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0666); err != nil {
						t.Fatal(err)
					}
					f := alert.Finding{Check: check, Message: "Process /usr/bin/php wrote writable PHP file: " + path}
					if explicit {
						f.FilePath = path
					}
					if automatic {
						actions, fixed := AutoFixPermissions(cfg, []alert.Finding{f})
						if explicit {
							if len(actions) != 1 || len(fixed) != 1 || fixed[0] != f.Key() {
								t.Fatalf("actions = %v, fixed = %v, want one action and the exact finding key", actions, fixed)
							}
						} else if len(actions) != 0 || len(fixed) != 0 {
							t.Fatalf("message-only finding was acted on: %v, %v", actions, fixed)
						}
					} else {
						result := ApplyFix(context.Background(), check, f.Message, "", f.FilePath)
						if result.Success != explicit || (!explicit && result.Error == "") {
							t.Fatalf("explicit = %v, result = %+v", explicit, result)
						}
					}
					wantMode := os.FileMode(0666)
					if explicit {
						wantMode = 0644
					}
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != wantMode {
						t.Fatalf("mode = %o, want %o", info.Mode().Perm(), wantMode)
					}
				})
			}
		}
	}
}
