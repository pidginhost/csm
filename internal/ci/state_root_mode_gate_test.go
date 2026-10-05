package ci

import (
	"os"
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
