package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The YARA loader refuses any rules file that is group- or world-writable
// (internal/yara/rulesdir_safe.go). Shipping the rules without an explicit
// mode leaves them at whatever the build host's umask produced, which has
// already shipped 0664 in a release: the scanner then rejects its own
// packaged rules on every buffer and the host runs with no YARA coverage at
// all. Pin the mode in the package definition so the build environment cannot
// decide it.
func TestPackagedYARARulesAreNotGroupWritable(t *testing.T) {
	data, err := os.ReadFile("../../build/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	nfpm := string(data)

	for _, rules := range []string{"/opt/csm/rules/malware.yar", "/opt/csm/rules/malware.yml"} {
		mode, ok := nfpmFileMode(nfpm, rules)
		if !ok {
			t.Errorf("%s ships without an explicit file_info.mode; it will inherit the build host umask", rules)
			continue
		}
		if !modeIsGroupAndWorldReadOnly(mode) {
			t.Errorf("%s ships mode %s; the YARA loader rejects group- or world-writable rules", rules, mode)
		}
	}
}

// Run the installer's rules-copy block with a permissive umask and unsafe
// existing paths. Checking only the file modes misses an untrusted directory.
func TestStandaloneInstallerHardensRulesPerms(t *testing.T) {
	data, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	end := strings.Index(script, `info "Assets OK"`)
	if end < 0 {
		t.Fatal("missing asset installation boundary")
	}
	start := strings.LastIndex(script[:end], "\ndone\n")
	if start < 0 {
		t.Fatal("missing required-assets check boundary")
	}
	block := script[start+len("\ndone\n") : end]
	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "configs"), 0750); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"malware.yar", "malware.yml"} {
				if err := os.WriteFile(filepath.Join(dir, "configs", file), []byte("test rule"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(dir, "configs", file), 0664); err != nil {
					t.Fatal(err)
				}
			}
			if existing {
				if err := os.Mkdir(filepath.Join(dir, "rules"), 0750); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(dir, "rules"), 0777); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", "set -eu\numask 0002\n"+block)
			cmd.Env = append(os.Environ(), "INSTALL_DIR="+dir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("install rules: %v: %s", err, out)
			}
			for _, file := range []string{"rules", "rules/malware.yar", "rules/malware.yml"} {
				info, err := os.Stat(filepath.Join(dir, file))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm()&0022 != 0 {
					t.Errorf("%s mode %04o is rejected by the loader", file, info.Mode().Perm())
				}
				if info.Mode().Perm()&0400 == 0 {
					t.Errorf("%s is unreadable by its owner", file)
				}
			}
		})
	}
}

// nfpmFileMode returns the mode declared for a destination path in the nfpm
// contents list. The block is indentation-based, so the mode must appear
// before the next entry's "- src:"/"- dst:" line.
func nfpmFileMode(nfpm, dst string) (string, bool) {
	idx := strings.Index(nfpm, "dst: "+dst)
	if idx < 0 {
		return "", false
	}
	rest := nfpm[idx:]
	if next := strings.Index(rest[1:], "\n  - "); next >= 0 {
		rest = rest[:next+1]
	}
	m := regexp.MustCompile(`mode:\s*(0[0-7]{3})`).FindStringSubmatch(rest)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func modeIsGroupAndWorldReadOnly(mode string) bool {
	if len(mode) != 4 {
		return false
	}
	group := mode[2] - '0'
	world := mode[3] - '0'
	const write = 2
	return group&write == 0 && world&write == 0
}
