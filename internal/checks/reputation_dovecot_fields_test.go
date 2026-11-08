package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestReputationDovecotUsesServerFields(t *testing.T) {
	for _, success := range []bool{false, true} {
		line := dovecotLoginLine("x, rip=198.51.100.7, y", "203.0.113.50")
		if success {
			line = strings.Replace(line, "Login aborted: Logged out (auth failed, 1 attempts in 17 secs) (auth_failed)", "Logged in", 1)
		}
		for _, missing := range []bool{false, true} {
			content := line
			if missing {
				content = strings.Replace(content, ", rip=203.0.113.50", "", 1)
			}
			cfg := &config.Config{}
			cfg.MailLogs.File = "/custom/mail.log"
			withMockOS(t, mockOSWithMailLog(t, cfg.MailLogs.File, content+"\n"))
			ips := collectRecentIPs(cfg)
			authed := collectAuthenticatedIPs(cfg)
			if _, forged := ips["198.51.100.7"]; forged || authed["198.51.100.7"] {
				t.Fatalf("success=%v missing=%v: client text selected: %v, %v", success, missing, ips, authed)
			}
			wantRecent, wantAuthed := 0, 0
			if !missing {
				if success {
					wantAuthed = 1
				} else {
					wantRecent = 1
				}
			}
			if len(ips) != wantRecent || len(authed) != wantAuthed {
				t.Fatalf("success=%v missing=%v: unexpected address sets: %v, %v", success, missing, ips, authed)
			}
			if wantAuthed == 1 && !authed["203.0.113.50"] {
				t.Fatal("successful connecting address was lost")
			}
			if wantRecent == 1 && ips["203.0.113.50"] != reputationViaMailLogin {
				t.Fatal("failed connecting address was lost")
			}
		}
	}
}

func TestReputationDovecotRequiresRealSuccess(t *testing.T) {
	for _, line := range []string{
		dovecotLoginLine("x imap-login: Logged in: user=<victim@example.com", "203.0.113.50"),
		"dovecot: auth: sql(x imap-login: Logged in: user=<a>, rip=198.51.100.7, y,203.0.113.50): unknown user",
	} {
		cfg := &config.Config{}
		cfg.MailLogs.File = "/custom/mail.log"
		withMockOS(t, mockOSWithMailLog(t, cfg.MailLogs.File, line+"\n"))
		if got := collectAuthenticatedIPs(cfg); len(got) != 0 {
			t.Errorf("failed login earned reputation exemption: %v", got)
		}
	}
}

func TestReputationDovecotIgnoresOtherMessages(t *testing.T) {
	cfg := &config.Config{}
	cfg.MailLogs.File = "/custom/mail.log"
	line := "dovecot: auth: sql(x auth failed rip=198.51.100.7 ,203.0.113.50): unknown user\n"
	withMockOS(t, mockOSWithMailLog(t, cfg.MailLogs.File, line))
	if got := collectRecentIPs(cfg); len(got) != 0 {
		t.Fatalf("auth request text selected an address: %v", got)
	}
}

func TestReputationDovecotSuccessFormats(t *testing.T) {
	for _, protocol := range []string{"imap", "pop3", "managesieve"} {
		for _, status := range []string{"Login", "Logged in"} {
			cfg := &config.Config{}
			cfg.MailLogs.File = "/custom/mail.log"
			line := "host dovecot[12]: " + protocol + "-login: " + status + ": user=<a@example.com>, rip=2001:db8::5, lip=2001:db8::1, session=<S>\n"
			withMockOS(t, mockOSWithMailLog(t, cfg.MailLogs.File, line))
			if got := collectAuthenticatedIPs(cfg); len(got) != 1 || !got["2001:db8::5"] {
				t.Errorf("%s %s: got %v, want only the successful client", protocol, status, got)
			}
		}
	}
}
