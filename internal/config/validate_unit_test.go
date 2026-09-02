package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validate --deep probed state_path from the unsandboxed CLI process, so a
// state_path outside the service unit's ReadWritePaths passed validation
// and the daemon, under ProtectSystem=strict, crash-looped on its first
// write. The deep probe now reads the installed unit and checks coverage.
const sampleUnit = `[Service]
ProtectSystem=strict
StateDirectory=csm
ReadWritePaths=/var/lib/csm -/opt/csm/state /var/log/csm
ReadWritePaths=/etc/csm
`

func TestUnitCoversStatePath(t *testing.T) {
	cases := []struct {
		name      string
		unit      string
		statePath string
		covered   bool
		known     bool
	}{
		{"state directory", sampleUnit, "/var/lib/csm/state", true, true},
		{"optional grant", sampleUnit, "/opt/csm/state/sub", true, true},
		{"second line", sampleUnit, "/etc/csm/state", true, true},
		{"outside", sampleUnit, "/srv/csm-state", false, true},
		{"prefix is not a parent", sampleUnit, "/var/lib/csm-other", false, true},
		{"no protect system", "[Service]\nReadWritePaths=/var/lib/csm\n", "/srv/csm-state", true, true},
		{"quoted grant", "[Service]\nProtectSystem=strict\nReadWritePaths=\"/srv/csm state\"\n", "/srv/csm state/db", true, true},
		{"continued grants", "[Service]\nProtectSystem=strict\nReadWritePaths=/var/lib/csm \\\n /srv/csm-state\n", "/srv/csm-state/db", true, true},
		{"root grant", "[Service]\nProtectSystem=strict\nReadWritePaths=/\n", "/srv/csm-state", true, true},
		{"wrong section grant", "[Unit]\nReadWritePaths=/srv/csm-state\n[Service]\nProtectSystem=strict\n", "/srv/csm-state", false, true},
		{"unterminated quoted grant", "[Service]\nProtectSystem=strict\nReadWritePaths=\"/srv/csm-state\n", "/srv/csm-state", false, true},
		{"full protects etc", "[Service]\nProtectSystem=full\n", "/etc/csm/state", false, true},
		{"full leaves srv writable", "[Service]\nProtectSystem=full\n", "/srv/csm-state", true, true},
		{"true leaves etc writable", "[Service]\nProtectSystem=true\n", "/etc/csm/state", true, true},
		{"true protects usr", "[Service]\nProtectSystem=true\n", "/usr/lib/csm/state", false, true},
		{"later protect override", "[Service]\nProtectSystem=strict\nProtectSystem=false\n", "/usr/lib/csm/state", true, true},
		{"empty paths reset", "[Service]\nProtectSystem=strict\nReadWritePaths=/srv/csm-state\nReadWritePaths=\n", "/srv/csm-state", false, true},
		{"empty unit", "", "/srv/csm-state", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			covered, known := unitCoversStatePath(tc.unit, tc.statePath)
			if covered != tc.covered || known != tc.known {
				t.Fatalf("unitCoversStatePath = (%v, %v), want (%v, %v)", covered, known, tc.covered, tc.known)
			}
		})
	}
}

func TestValidateDeepAppliesSystemdDropInOverrides(t *testing.T) {
	dir := t.TempDir()
	unitPath := filepath.Join(dir, "csm.service")
	if err := os.WriteFile(unitPath, []byte("[Service]\nProtectSystem=strict\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dropInDir := unitPath + ".d"
	if err := os.Mkdir(dropInDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropInDir, "10-state.conf"), []byte("[Service]\nReadWritePaths=/srv/csm-state\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := systemdUnitFile
	systemdUnitFile = unitPath
	t.Cleanup(func() { systemdUnitFile = old })

	for _, result := range probeStatePathSandbox("/srv/csm-state") {
		if result.Field == "state_path" && result.Level == "error" {
			t.Fatalf("drop-in grant was ignored: %+v", result)
		}
	}
}

func TestValidateDeepFlagsStatePathOutsideUnitGrants(t *testing.T) {
	unitPath := filepath.Join(t.TempDir(), "csm.service")
	if err := os.WriteFile(unitPath, []byte(sampleUnit), 0o644); err != nil {
		t.Fatal(err)
	}
	old := systemdUnitFile
	systemdUnitFile = unitPath
	t.Cleanup(func() { systemdUnitFile = old })

	cfg := &Config{Hostname: "test", StatePath: t.TempDir()}
	found := false
	for _, r := range ValidateDeep(cfg) {
		if r.Field == "state_path" && r.Level == "error" && strings.Contains(r.Message, "ReadWritePaths") {
			found = true
		}
	}
	if !found {
		t.Fatal("state_path outside the unit's ReadWritePaths passed the deep probe")
	}
}
