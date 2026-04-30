package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func TestEvaluateDistroEOL_SupportedUbuntu(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, OSVersion: "24.04"}
	results := evaluateDistroEOL(info, "Ubuntu 24.04 LTS")
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Status != "pass" {
		t.Errorf("Ubuntu 24.04 should pass, got %q (msg: %s)", r.Status, r.Message)
	}
	if r.Message != "Ubuntu 24.04 LTS" {
		t.Errorf("message = %q, want PRETTY_NAME", r.Message)
	}
}

func TestEvaluateDistroEOL_EOLUbuntu(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, OSVersion: "18.04"}
	results := evaluateDistroEOL(info, "Ubuntu 18.04 LTS")
	r := results[0]
	if r.Status != "fail" {
		t.Errorf("Ubuntu 18.04 should fail, got %q", r.Status)
	}
	if !strings.Contains(r.Fix, "LTS") {
		t.Errorf("Fix should mention LTS for Debian family: %q", r.Fix)
	}
	if !strings.Contains(r.Message, "18") {
		t.Errorf("Message should contain major version, got %q", r.Message)
	}
}

func TestEvaluateDistroEOL_SupportedAlma(t *testing.T) {
	info := platform.Info{OS: platform.OSAlma, OSVersion: "10.0"}
	results := evaluateDistroEOL(info, "AlmaLinux 10.0")
	r := results[0]
	if r.Status != "pass" {
		t.Errorf("Alma 10 should pass, got %q", r.Status)
	}
}

func TestEvaluateDistroEOL_EOLCentOS(t *testing.T) {
	info := platform.Info{OS: platform.OSCentOS, OSVersion: "7"}
	results := evaluateDistroEOL(info, "CentOS Linux 7 (Core)")
	r := results[0]
	if r.Status != "fail" {
		t.Errorf("CentOS 7 should fail, got %q", r.Status)
	}
}

func TestEvaluateDistroEOL_CentOS8StillFails(t *testing.T) {
	info := platform.Info{OS: platform.OSCentOS, OSVersion: "8"}
	results := evaluateDistroEOL(info, "CentOS Linux 8")
	r := results[0]
	if r.Status != "fail" {
		t.Errorf("CentOS 8 should fail, got %q", r.Status)
	}
	if !strings.Contains(r.Message, "CentOS") {
		t.Errorf("expected CentOS-specific message, got %q", r.Message)
	}
}

func TestEvaluateDistroEOL_UnknownOS(t *testing.T) {
	results := evaluateDistroEOL(platform.Info{}, "")
	r := results[0]
	if r.Status != "warn" {
		t.Errorf("unknown OS should warn, got %q", r.Status)
	}
	if r.Message != "Unable to determine distribution version" {
		t.Errorf("unexpected message: %q", r.Message)
	}
}

func TestEvaluateDistroEOL_UnparseableVersion(t *testing.T) {
	info := platform.Info{OS: platform.OSUbuntu, OSVersion: "jammy"}
	results := evaluateDistroEOL(info, "Ubuntu jammy")
	r := results[0]
	if r.Status != "warn" {
		t.Errorf("unparseable version should warn, got %q", r.Status)
	}
}

func TestEvaluateDistroEOL_UnknownDistroFallback(t *testing.T) {
	// Use an OS value not in distroEOLPolicy (e.g. an empty placeholder
	// we can't hit without adding new OS constants, so simulate with Debian
	// after clearing policy — instead just assert the path by using an OS
	// we haven't added to policy).
	info := platform.Info{OS: platform.OSFamily("openbsd"), OSVersion: "7.5"}
	results := evaluateDistroEOL(info, "OpenBSD 7.5")
	r := results[0]
	if r.Status != "warn" {
		t.Errorf("unknown distro should warn, got %q", r.Status)
	}
}

func TestParseSSHDConfig_BasicFirstMatchWins(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")
	content := `Port 2222
PasswordAuthentication no
PasswordAuthentication yes
PermitRootLogin prohibit-password
`
	if err := os.WriteFile(cfg, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	effective := make(map[string]string)
	parseSSHDFile(cfg, effective)

	if effective["port"] != "2222" {
		t.Errorf("expected port 2222, got %q", effective["port"])
	}
	// First-match-wins: first PasswordAuthentication value should be kept
	if effective["passwordauthentication"] != "no" {
		t.Errorf("expected passwordauthentication no, got %q", effective["passwordauthentication"])
	}
	if effective["permitrootlogin"] != "prohibit-password" {
		t.Errorf("expected permitrootlogin prohibit-password, got %q", effective["permitrootlogin"])
	}
}

func TestParseSSHDConfig_MatchBlockSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")
	// Match block with non-indented directives (valid sshd_config syntax)
	content := `PasswordAuthentication no
Match Address 10.0.0.0/8
PasswordAuthentication yes
PermitRootLogin yes
X11Forwarding yes
`
	if err := os.WriteFile(cfg, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	effective := make(map[string]string)
	parseSSHDFile(cfg, effective)

	// PasswordAuthentication should be "no" (from global), not "yes" (from Match)
	if effective["passwordauthentication"] != "no" {
		t.Errorf("expected passwordauthentication no, got %q", effective["passwordauthentication"])
	}
	// PermitRootLogin and X11Forwarding are inside Match — should not appear
	if _, ok := effective["permitrootlogin"]; ok {
		t.Errorf("permitrootlogin should not be in effective config (it's inside a Match block)")
	}
	if _, ok := effective["x11forwarding"]; ok {
		t.Errorf("x11forwarding should not be in effective config (it's inside a Match block)")
	}
}

func TestParseSSHDConfig_MatchBlockEndsAtNextMatch(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")
	content := `Port 2222
Match User admin
PermitRootLogin yes
Match Address 192.168.0.0/16
X11Forwarding yes
`
	if err := os.WriteFile(cfg, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	effective := make(map[string]string)
	parseSSHDFile(cfg, effective)

	if effective["port"] != "2222" {
		t.Errorf("expected port 2222, got %q", effective["port"])
	}
	// Both PermitRootLogin and X11Forwarding are inside Match blocks
	if _, ok := effective["permitrootlogin"]; ok {
		t.Error("permitrootlogin should not be in effective config")
	}
	if _, ok := effective["x11forwarding"]; ok {
		t.Error("x11forwarding should not be in effective config")
	}
}

func TestParseSSHDConfig_IncludeDirective(t *testing.T) {
	dir := t.TempDir()
	dropin := filepath.Join(dir, "50-custom.conf")
	if err := os.WriteFile(dropin, []byte("Port 3333\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := filepath.Join(dir, "sshd_config")
	content := "Include " + filepath.Join(dir, "*.conf") + "\nPort 4444\n"
	if err := os.WriteFile(cfg, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	effective := make(map[string]string)
	parseSSHDFile(cfg, effective)

	// Include is processed first, so Port from dropin should win (first-match)
	if effective["port"] != "3333" {
		t.Errorf("expected port 3333 from include, got %q", effective["port"])
	}
}

func TestParseSSHDConfig_CommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")
	content := `# This is a comment
Port 5555

# Another comment
   # Indented comment
UseDNS no
`
	if err := os.WriteFile(cfg, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	effective := make(map[string]string)
	parseSSHDFile(cfg, effective)

	if effective["port"] != "5555" {
		t.Errorf("expected port 5555, got %q", effective["port"])
	}
	if effective["usedns"] != "no" {
		t.Errorf("expected usedns no, got %q", effective["usedns"])
	}
}

func TestSshdEffective_Defaults(t *testing.T) {
	empty := make(map[string]string)

	if v := sshdEffective(empty, "port"); v != "22" {
		t.Errorf("expected default port 22, got %q", v)
	}
	if v := sshdEffective(empty, "passwordauthentication"); v != "yes" {
		t.Errorf("expected default passwordauthentication yes, got %q", v)
	}
	if v := sshdEffective(empty, "permitrootlogin"); v != "prohibit-password" {
		t.Errorf("expected default permitrootlogin prohibit-password, got %q", v)
	}
}

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		{"8.8.8.8", false},
		{"0.0.0.0", false},
		{"fd12:3456::1", true},
		{"fc00::1", true},
	}
	for _, c := range cases {
		got := isPrivateOrLoopback(c.ip)
		if got != c.want {
			t.Errorf("isPrivateOrLoopback(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestEvaluateAlgifAEAD_BlockedAndNotLoaded(t *testing.T) {
	confs := map[string]string{
		"/etc/modprobe.d/csm-disable-algif.conf": "install algif_aead /bin/false\n",
	}
	r := evaluateAlgifAEAD(false, confs)
	if r.Status != "pass" {
		t.Errorf("status = %q, want pass (msg: %s)", r.Status, r.Message)
	}
	if r.Name != "os_algif_aead_blocked" {
		t.Errorf("name = %q, want os_algif_aead_blocked", r.Name)
	}
}

func TestEvaluateAlgifAEAD_BlacklistDirectiveAlsoCounts(t *testing.T) {
	confs := map[string]string{
		"/etc/modprobe.d/local.conf": "blacklist algif_aead\n",
	}
	r := evaluateAlgifAEAD(false, confs)
	if r.Status != "pass" {
		t.Errorf("blacklist directive should pass, got %q", r.Status)
	}
}

func TestEvaluateAlgifAEAD_NotBlockedAndNotLoaded(t *testing.T) {
	r := evaluateAlgifAEAD(false, nil)
	if r.Status != "fail" {
		t.Errorf("status = %q, want fail", r.Status)
	}
	if !strings.Contains(r.Fix, "modprobe.d") {
		t.Errorf("fix should mention modprobe.d, got %q", r.Fix)
	}
	if !strings.Contains(r.Fix, "algif_aead") {
		t.Errorf("fix should name the module, got %q", r.Fix)
	}
}

func TestEvaluateAlgifAEAD_LoadedIsAlwaysFail(t *testing.T) {
	// Even if a blacklist file is present, a currently-loaded module is a fail —
	// the operator must unload it for the mitigation to take effect this boot.
	confs := map[string]string{
		"/etc/modprobe.d/csm-disable-algif.conf": "install algif_aead /bin/false\n",
	}
	r := evaluateAlgifAEAD(true, confs)
	if r.Status != "fail" {
		t.Errorf("loaded module should fail regardless of blacklist, got %q", r.Status)
	}
	if !strings.Contains(r.Fix, "modprobe -r") {
		t.Errorf("fix should include modprobe -r, got %q", r.Fix)
	}
}

func TestEvaluateAlgifAEAD_CommentedDirectiveDoesNotCount(t *testing.T) {
	confs := map[string]string{
		"/etc/modprobe.d/local.conf": "# blacklist algif_aead\n",
	}
	r := evaluateAlgifAEAD(false, confs)
	if r.Status != "fail" {
		t.Errorf("commented directive should not count as blacklisted, got %q", r.Status)
	}
}

func TestEvaluateAlgifAEAD_InstallReloadDirectiveDoesNotCount(t *testing.T) {
	// `install algif_aead /sbin/modprobe --ignore-install algif_aead` is the
	// idiomatic re-load form: it overrides the default load path but still
	// loads the module. It must NOT be treated as blocking.
	confs := map[string]string{
		"/etc/modprobe.d/local.conf": "install algif_aead /sbin/modprobe --ignore-install algif_aead\n",
	}
	r := evaluateAlgifAEAD(false, confs)
	if r.Status != "fail" {
		t.Errorf("install-via-modprobe re-load should NOT count as blocked, got %q", r.Status)
	}
}

func TestEvaluateAlgifAEAD_InstallWithoutReplacementIsIgnored(t *testing.T) {
	// Half-written `install algif_aead` (no replacement command) is malformed
	// and must not be claimed as a pass.
	confs := map[string]string{
		"/etc/modprobe.d/local.conf": "install algif_aead\n",
	}
	r := evaluateAlgifAEAD(false, confs)
	if r.Status != "fail" {
		t.Errorf("malformed install directive should not count as blocked, got %q", r.Status)
	}
}
