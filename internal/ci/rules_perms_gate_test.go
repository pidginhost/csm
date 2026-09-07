package ci

import (
	"os"
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

// The standalone installer copies the same rules with plain cp, which
// preserves the source mode, so it needs the same guarantee.
func TestStandaloneInstallerHardensRulesPerms(t *testing.T) {
	data, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)

	if !strings.Contains(script, "configs/malware.yar") {
		t.Fatal("installer no longer places malware.yar; update this gate")
	}
	if !regexp.MustCompile(`chmod\s+0?6[04]0\s+.*rules/`).MatchString(script) {
		t.Error("installer must chmod the rules directory contents to 0640 or stricter after copying")
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
