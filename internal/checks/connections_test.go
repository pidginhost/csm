package checks

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// Regression: pure-ftpd PASV data sockets look like high-port user traffic
// in /proc/net/tcp. The ESTABLISHED row is the accepted side of an inbound
// connection when the same local socket also has a LISTEN row.
func TestScanProcNetTCPSkipsEstablishedOnListenerLocalPort(t *testing.T) {
	cfg := &config.Config{}

	// 203.0.113.56 little-endian = 387100CB. Listener at
	// 0.0.0.0:49904 (0xC2F0), then ESTABLISHED on the same local port.
	data := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:C2F0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 11111 1 0000000000000000
   1: 0A0200C0:C2F0 387100CB:115C 01 00000000:00000000 00:00000000 00000000  1001        0 22222 1 0000000000000000
`)

	findings := scanProcNetTCP(cfg, data, false)
	for _, f := range findings {
		if f.Check == "user_outbound_connection" {
			t.Fatalf("listener-backed local port should suppress finding, got %+v", f)
		}
	}
}

// Regression: an ESTABLISHED row with no matching LISTEN row must still
// flag. The listener cross-reference must not silence real outbound
// connections.
func TestScanProcNetTCPStillFlagsRealOutboundConnect(t *testing.T) {
	cfg := &config.Config{}

	// No listener; just an ESTABLISHED row to a non-infra non-safe port.
	data := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A0200C0:C350 387100CB:115C 01 00000000:00000000 00:00000000 00000000  1001        0 33333 1 0000000000000000
`)

	findings := scanProcNetTCP(cfg, data, false)
	hasFinding := false
	for _, f := range findings {
		if f.Check == "user_outbound_connection" {
			hasFinding = true
		}
	}
	if !hasFinding {
		t.Fatalf("real outbound connect must still flag; findings=%+v", findings)
	}
}

func TestScanProcNetTCPDoesNotSuppressSamePortDifferentLocalAddress(t *testing.T) {
	cfg := &config.Config{}

	// Listener on 192.0.2.10:49904 must not suppress an ESTABLISHED
	// outbound row from 192.0.2.11:49904.
	data := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A0200C0:C2F0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 11111 1 0000000000000000
   1: 0B0200C0:C2F0 387100CB:115C 01 00000000:00000000 00:00000000 00000000  1001        0 22222 1 0000000000000000
`)

	findings := scanProcNetTCP(cfg, data, false)
	hasFinding := false
	for _, f := range findings {
		if f.Check == "user_outbound_connection" {
			hasFinding = true
		}
	}
	if !hasFinding {
		t.Fatalf("different local address with same port must still flag; findings=%+v", findings)
	}
}

// Regression: emitted findings must have a non-zero Timestamp so the
// renderer doesn't print `Time: 0001-01-01 00:00:00`.
func TestScanProcNetTCPStampsTimestamp(t *testing.T) {
	cfg := &config.Config{}
	data := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A0200C0:C350 387100CB:115C 01 00000000:00000000 00:00000000 00000000  1001        0 44444 1 0000000000000000
`)
	before := time.Now()
	findings := scanProcNetTCP(cfg, data, false)
	if len(findings) == 0 {
		t.Fatalf("expected one finding, got 0")
	}
	if findings[0].Timestamp.Before(before) || findings[0].Timestamp.IsZero() {
		t.Fatalf("Timestamp = %v, want set to ~now", findings[0].Timestamp)
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
