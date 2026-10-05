package ci

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The exim forward-guard holds copies under the state root and exim delivers
// them as its own non-root user, so the root must be searchable by others.
// The state database below it stays private. The package and the unit must
// agree, or systemd resets the root to its own mode on every start.
func TestStateRootIsSearchableButStateStaysPrivate(t *testing.T) {
	data, err := os.ReadFile("../../build/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	nfpm := string(data)
	for dst, want := range map[string]string{
		"/var/lib/csm\n":       "0711",
		"/var/lib/csm/state\n": "0700",
	} {
		mode, ok := nfpmFileMode(nfpm, dst)
		if !ok {
			t.Errorf("%s ships without an explicit file_info.mode", strings.TrimSpace(dst))
			continue
		}
		if mode != want {
			t.Errorf("%s ships mode %s, want %s", strings.TrimSpace(dst), mode, want)
		}
	}

	unit, err := os.ReadFile("../../build/packaging/systemd/csm.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "\nStateDirectoryMode=0711\n") {
		t.Error("csm.service must declare StateDirectoryMode=0711 to match the packaged state root")
	}
}

func TestPackageScriptsKeepStateRootSearchable(t *testing.T) {
	for _, name := range []string{"postinstall.sh", "posttrans.sh"} {
		for _, initial := range []os.FileMode{0, 0700, 0711} {
			t.Run(fmt.Sprintf("%s/%#o", name, initial), func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "csm")
				if initial != 0 {
					if err := os.Mkdir(root, initial); err != nil {
						t.Fatal(err)
					}
				}
				body, err := os.ReadFile(filepath.Join("../../build/packaging/scripts", name))
				if err != nil {
					t.Fatal(err)
				}
				// Run the shipped state-directory commands in an isolated tree;
				// the rest of these scripts starts services and installs config.
				var commands []string
				for _, line := range strings.Split(string(body), "\n") {
					if strings.Contains(line, "/var/lib/csm") &&
						(strings.HasPrefix(line, "install -d ") || strings.HasPrefix(line, "mkdir -p ")) {
						commands = append(commands, strings.ReplaceAll(line, "/var/lib/csm", `"${CSM_TEST_ROOT}"`))
					}
				}
				if len(commands) == 0 {
					t.Fatal("no state-directory creation commands tested")
				}
				cmd := exec.Command("bash", "-c", "set -e\numask 077\n"+strings.Join(commands, "\n"))
				cmd.Env = append(os.Environ(), "CSM_TEST_ROOT="+root)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("directory setup failed: %v\n%s", err, out)
				}
				wantModes := map[string]os.FileMode{root: 0711}
				if name == "postinstall.sh" {
					wantModes[filepath.Join(root, "state")] = 0700
				}
				for path, want := range wantModes {
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if got := info.Mode().Perm(); got != want {
						t.Errorf("%s mode = %#o, want %#o", path, got, want)
					}
				}
			})
		}
	}
}
