package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
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
