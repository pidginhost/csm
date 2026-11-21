package checks

import (
	"strings"
	"testing"
	"time"

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
			if _, forged := ips["198.51.100.7"]; forged {
				t.Fatalf("success=%v missing=%v: client text selected: %v", success, missing, ips)
			}
			wantRecent := 0
			if !missing && !success {
				wantRecent = 1
			}
			if len(ips) != wantRecent {
				t.Fatalf("success=%v missing=%v: unexpected sightings: %v", success, missing, ips)
			}
			if wantRecent == 1 && ips["203.0.113.50"] != reputationViaMailLogin {
				t.Fatal("failed connecting address was lost")
			}
			// A mail log file line is never a login: any local user can
			// write one, so it excuses no address.
			if recentlyAuthenticated("203.0.113.50", time.Now()) {
				t.Fatalf("success=%v missing=%v: a file line excused its address", success, missing)
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
		if recentlyAuthenticated("203.0.113.50", time.Now()) || recentlyAuthenticated("198.51.100.7", time.Now()) {
			t.Error("a mail log file line earned a reputation exemption")
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
			if recentlyAuthenticated("2001:db8::5", time.Now()) {
				t.Errorf("%s %s: a mail log file line excused its client", protocol, status)
			}
		}
	}
}

// Only a login the mail service recorded, which the daemon looks up, excuses
// an address, and only a recent one.
func TestReputationExcuseNeedsATrustedLogin(t *testing.T) {
	t.Cleanup(func() { SetTrustedMailLoginLookup(nil) })
	now := time.Now()
	logins := map[string]time.Time{"203.0.113.50": now.Add(-time.Hour), "203.0.113.51": now.Add(-48 * time.Hour)}
	SetTrustedMailLoginLookup(func(ip string, since time.Time) bool {
		at, ok := logins[ip]
		return ok && !at.Before(since)
	})
	for ip, want := range map[string]bool{"203.0.113.50": true, "203.0.113.51": false, "203.0.113.52": false} {
		if got := recentlyAuthenticated(ip, now); got != want {
			t.Errorf("%s excused %v, want %v", ip, got, want)
		}
	}
}
