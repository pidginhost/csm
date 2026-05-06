package checks

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestEvaluateConnection(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.0/8"}}
	cases := []struct {
		name        string
		uid         uint32
		dstIP       net.IP
		dstPort     uint16
		localPort   uint16
		proto       string
		user        string
		wantFinding bool
	}{
		{"root_skipped", 0, net.ParseIP("8.8.8.8"), 1234, 50000, "tcp", "root", false},
		{"loopback_skipped", 1000, net.ParseIP("127.0.0.1"), 1234, 50000, "tcp", "alice", false},
		{"unspecified_skipped", 1000, net.ParseIP("0.0.0.0"), 1234, 50000, "tcp", "alice", false},
		{"infra_skipped", 1000, net.ParseIP("10.1.2.3"), 1234, 50000, "tcp", "alice", false},
		{"safe_remote_port_443_ok", 1000, net.ParseIP("8.8.8.8"), 443, 50000, "tcp", "alice", false},
		{"safe_remote_port_53_ok", 1000, net.ParseIP("8.8.8.8"), 53, 50000, "tcp", "alice", false},
		{"server_local_port_80", 1000, net.ParseIP("8.8.8.8"), 1234, 80, "tcp", "alice", false},
		{"server_local_port_2087", 1000, net.ParseIP("8.8.8.8"), 1234, 2087, "tcp", "alice", false},
		{"safe_user_named", 0, net.ParseIP("8.8.8.8"), 1234, 50000, "tcp", "named", false}, // root anyway
		{"safe_user_mysql_nonroot", 1000, net.ParseIP("8.8.8.8"), 1234, 50000, "tcp", "mysql", false},
		{"non_root_unusual_port", 1000, net.ParseIP("8.8.8.8"), 4444, 50000, "tcp", "alice", true},
		{"non_root_v6", 1000, net.ParseIP("2001:db8::1"), 4444, 50000, "tcp6", "alice", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := EvaluateConnection(cfg, tc.uid, tc.dstIP, tc.dstPort, tc.localPort, tc.proto, tc.user)
			if ok != tc.wantFinding {
				t.Fatalf("got finding=%v, want %v (finding=%+v)", ok, tc.wantFinding, f)
			}
			if ok && f.Check != "user_outbound_connection" {
				t.Fatalf("Check = %q, want user_outbound_connection", f.Check)
			}
		})
	}
}

func TestCheckSSHDConfigIgnoresCommentedDefaults(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `PermitRootLogin without-password
#PermitRootLogin yes
#PasswordAuthentication yes
PasswordAuthentication no
X11Forwarding no
`)

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}

	writeSSHDConfig(t, cfgPath, `PermitRootLogin without-password
#PermitRootLogin yes
#PasswordAuthentication yes
PasswordAuthentication no
X11Forwarding yes
`)

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 generic change alert", findings)
	}
	if findings[0].Message != "sshd_config modified" {
		t.Fatalf("message = %q, want generic sshd_config change", findings[0].Message)
	}
}

func TestCheckSSHDConfigAlertsOnEffectivePasswordAuthChange(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `PermitRootLogin without-password
PasswordAuthentication no
X11Forwarding no
`)

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}

	writeSSHDConfig(t, cfgPath, `PermitRootLogin without-password
PasswordAuthentication yes
X11Forwarding no
`)

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 critical alert", findings)
	}
	if findings[0].Message != "PasswordAuthentication changed to 'yes' in sshd_config" {
		t.Fatalf("message = %q, want PasswordAuthentication alert", findings[0].Message)
	}
}

func TestCheckSSHDConfigIgnoresMatchBlockOverrides(t *testing.T) {
	cfgPath, st := testSSHDConfigStore(t, `PermitRootLogin without-password
PasswordAuthentication no
X11Forwarding no
`)

	if findings := CheckSSHDConfig(context.Background(), nil, st); len(findings) != 0 {
		t.Fatalf("initial baseline findings = %v, want none", findings)
	}

	writeSSHDConfig(t, cfgPath, `PermitRootLogin without-password
PasswordAuthentication no
X11Forwarding no

Match User root
    PermitRootLogin yes
    PasswordAuthentication yes
    X11Forwarding yes
`)

	findings := CheckSSHDConfig(context.Background(), nil, st)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 generic change alert", findings)
	}
	if findings[0].Message != "sshd_config modified" {
		t.Fatalf("message = %q, want generic sshd_config change", findings[0].Message)
	}
	for _, f := range findings {
		if strings.Contains(f.Message, "PasswordAuthentication changed") || strings.Contains(f.Message, "PermitRootLogin changed") {
			t.Fatalf("unexpected dangerous ssh finding from Match block: %v", findings)
		}
	}
}

func testSSHDConfigStore(t *testing.T, content string) (string, *state.Store) {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")
	writeSSHDConfig(t, cfgPath, content)

	st, err := state.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})

	oldPath := sshdConfigPath
	sshdConfigPath = cfgPath
	t.Cleanup(func() {
		sshdConfigPath = oldPath
	})

	return cfgPath, st
}

func writeSSHDConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("os.WriteFile(%s): %v", path, err)
	}
}
