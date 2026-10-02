package daemon

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The realtime authentication log watcher uses the same rule: a client-chosen
// login name that embeds a success record reports nothing.
func TestSecureLogIgnoresForgedAcceptedRecord(t *testing.T) {
	for _, message := range []string{
		"Invalid user x Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000",
		"Failed password for invalid user Accepted password for root from 192.0.2.50 port 22 from 203.0.113.9 port 51000 ssh2",
		"Connection closed by invalid user Accepted password for root from 192.0.2.50 port 22 203.0.113.9 port 51000 [preauth]",
	} {
		line := "Oct  2 12:00:00 host sshd[100]: " + message
		if got := parseSecureLogLine(line, &config.Config{}); len(got) != 0 {
			t.Errorf("forged record reported %+v", got)
		}
	}
}

func TestSecureLogSSHRecordShapes(t *testing.T) {
	for _, header := range []string{"Oct  2 12:00:00 host ", "2026-10-02T12:00:00.123456+00:00 host ", "host ", ""} {
		for _, tag := range []string{"sshd[100]:", "sshd:", "sshd-session[100]:", "sshd-session:"} {
			for _, method := range []string{"publickey", "password", "keyboard-interactive", "keyboard-interactive/pam", "gssapi-with-mic", "gssapi-keyex", "hostbased"} {
				for _, ip := range []string{"192.0.2.60", "2001:db8::7"} {
					t.Run(header+tag+"/"+method+"/"+ip, func(t *testing.T) {
						line := fmt.Sprintf("%s%s Accepted %s for from from %s port 50000 ssh2: ED25519 SHA256:abc for root from 203.0.113.9", header, tag, method, ip)
						got := parseSecureLogLine(line, &config.Config{})
						if len(got) != 1 || got[0].SourceIP != ip || got[0].TenantID != "from" || got[0].Check != "ssh_login_unknown_ip" || got[0].Severity != alert.Critical {
							t.Errorf("success record = %+v, want login by from at %s", got, ip)
						}
					})
				}
			}
		}
	}
}
