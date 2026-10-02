package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// sshd writes the login name a client offers into its own log lines, so a
// line that merely contains "Accepted ... from <address>" proves nothing.
// Only sshd's own success record reports a login, and only for its address.
func TestSSHAcceptedLoginFindingIgnoresForgedRecords(t *testing.T) {
	for name, line := range map[string]string{
		"invalid user":  "Oct  2 12:00:00 host sshd[100]: Invalid user x Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000",
		"failed login":  "Oct  2 12:00:00 host sshd[100]: Failed password for invalid user Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000 ssh2",
		"closed":        "Oct  2 12:00:00 host sshd[100]: Connection closed by invalid user Accepted password for root from 192.0.2.50 port 22 203.0.113.9 port 51000 [preauth]",
		"other program": "Oct  2 12:00:00 host su[100]: Accepted password for root from 192.0.2.50 port 22 ssh2",
		"lookalike tag": "Oct  2 12:00:00 host sshd-x[100]: Accepted password for root from 192.0.2.50 port 22 ssh2",
		"no address":    "Oct  2 12:00:00 host sshd[100]: Accepted password for root from host.example port 22 ssh2",
		"failed record": "Oct  2 12:00:00 host sshd[100]: Failed password for Accepted from 192.0.2.50 port 22 ssh2",
		"bad port":      "Oct  2 12:00:00 host sshd[100]: Accepted password for root from 192.0.2.50 port ssh2 22",
		"no for":        "Oct  2 12:00:00 host sshd[100]: Accepted password by root from 192.0.2.50 port 22 ssh2",
		"no from":       "Oct  2 12:00:00 host sshd[100]: Accepted password for root via 192.0.2.50 port 22 ssh2",
		"no port":       "Oct  2 12:00:00 host sshd[100]: Accepted password for root from 192.0.2.50 on 22 ssh2",
		"bad pid":       "Oct  2 12:00:00 host sshd[x]: Accepted password for root from 192.0.2.50 port 22 ssh2",
		"no header":     "Accepted password for root from 192.0.2.50 port 22 ssh2",
	} {
		if f, ok := SSHAcceptedLoginFinding(line, &config.Config{}); ok {
			t.Errorf("%s: reported %+v", name, f)
		}
	}
}

func TestSSHLoginLogShapes(t *testing.T) {
	// "from" is a hosting account here, so the tenant shows which field the
	// parser read the account from.
	t.Cleanup(SetHostingAccountLookupForTest(func(name string) string {
		if name == "from" {
			return name
		}
		return ""
	}))
	now := time.Now()
	headers := []string{now.Format("Jan _2 15:04:05") + " host ", now.Format(time.RFC3339Nano) + " host ", "host ", ""}
	for _, header := range headers {
		for _, tag := range []string{"sshd[100]:", "sshd:", "sshd-session[100]:", "sshd-session:"} {
			for _, method := range []string{"publickey", "password", "keyboard-interactive", "keyboard-interactive/pam", "gssapi-with-mic", "gssapi-keyex", "hostbased"} {
				for _, ip := range []string{"192.0.2.60", "2001:db8::7"} {
					t.Run(header+tag+"/"+method+"/"+ip, func(t *testing.T) {
						// Delimiter-like account names and key comments cannot
						// move the source or account away from their own fields.
						line := fmt.Sprintf("%s%s Accepted %s for from from %s port 50000 ssh2: ED25519 SHA256:abc for root from 203.0.113.9", header, tag, method, ip)
						cfg := &config.Config{}
						finding, ok := SSHAcceptedLoginFinding(line, cfg)
						if !ok || finding.SourceIP != ip || finding.TenantID != "from" || finding.Severity != alert.Critical {
							t.Fatalf("success record = %+v (ok %v), want login by from at %s", finding, ok, ip)
						}
						path := useAuthLog(t)
						withMockOS(t, writeMockLogs(t, map[string]string{path: line + "\n", platform.Detect().AuthLogPath(): line + "\n"}))
						for _, findings := range [][]alert.Finding{
							CheckSSHLogins(context.Background(), cfg, nil),
							CheckSSHLogins(context.Background(), cfg, newTestStore(t)),
						} {
							if len(findings) != 1 || findings[0].SourceIP != ip || findings[0].TenantID != "from" || findings[0].Key() != finding.Key() {
								t.Errorf("scan findings = %+v, want the same login by from at %s", findings, ip)
							}
						}
						if ips := collectRecentIPs(cfg); len(ips) != 1 || ips[ip] != "SSH login" {
							t.Errorf("reputation candidates = %v, want only SSH login from %s", ips, ip)
						}
					})
				}
			}
		}
	}
}

func TestSSHLoginScansIgnoreForgedRecords(t *testing.T) {
	for _, message := range []string{
		"Invalid user x Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000",
		"Failed password for invalid user Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000 ssh2",
		"Connection closed by invalid user Accepted password for root from 192.0.2.50 port 22 203.0.113.9 port 51000 [preauth]",
	} {
		t.Run(message, func(t *testing.T) {
			path := useAuthLog(t)
			appendLines(t, path, time.Now().Format(time.RFC3339Nano)+" host sshd-session[100]: "+message)
			cfg := &config.Config{}
			st := newTestStore(t)
			if got := CheckSSHLogins(context.Background(), cfg, nil); len(got) != 0 {
				t.Errorf("tail scan reported forged login: %+v", got)
			}
			if got := CheckSSHLogins(context.Background(), cfg, st); len(got) != 0 {
				t.Errorf("follow scan reported forged login: %+v", got)
			}
			appendLines(t, path, sshAcceptedLine(time.Now(), "198.51.100.7"))
			// root is never a hosting account, so the login carries no tenant.
			if got := CheckSSHLogins(context.Background(), cfg, st); len(got) != 1 || got[0].SourceIP != "198.51.100.7" || !strings.Contains(got[0].Message, "(user: root)") || got[0].TenantID != "" {
				t.Errorf("follow scan lost subsequent login: %+v", got)
			}
		})
	}
}

func TestSSHAcceptedLoginFindingReportsSSHDSuccess(t *testing.T) {
	for name, c := range map[string]struct{ line, ip, user string }{
		"syslog":       {"Oct  2 12:00:00 host sshd[100]: Accepted publickey for alice from 192.0.2.60 port 50000 ssh2: ED25519 SHA256:abc", "192.0.2.60", "alice"},
		"rfc3339":      {"2026-10-02T12:00:00.123456+00:00 host sshd[100]: Accepted password for alice from 2001:db8::7 port 50000 ssh2", "2001:db8::7", "alice"},
		"session":      {"Oct  2 12:00:00 host sshd-session[100]: Accepted keyboard-interactive/pam for alice from 198.51.100.8 port 50000 ssh2", "198.51.100.8", "alice"},
		"no timestamp": {"host sshd[100]: Accepted password for alice from 192.0.2.61 port 50000 ssh2", "192.0.2.61", "alice"},
		"no pid":       {"Oct  2 12:00:00 host sshd: Accepted password for alice from 203.0.113.70 port 50000 ssh2", "203.0.113.70", "alice"},
	} {
		f, ok := SSHAcceptedLoginFinding(c.line, &config.Config{})
		if !ok || f.Check != "ssh_login_unknown_ip" || f.SourceIP != c.ip || f.Message != "SSH login from non-infra IP: "+c.ip+" (user: "+c.user+")" {
			t.Errorf("%s: finding %+v (ok %v), want a login by %s from %s", name, f, ok, c.user, c.ip)
		}
	}
}
