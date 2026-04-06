package checks

import (
	"os"
	"path/filepath"
	"testing"
)

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
