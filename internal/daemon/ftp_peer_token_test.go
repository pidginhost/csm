package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestParseFTPLogLineHostnamePeerIgnoresUsernameAddress(t *testing.T) {
	for _, user := range []string{"x 198.51.100.7", "x (a@198.51.100.7) y", "198.51.100.7"} {
		line := `Apr 11 10:00:00 host pure-ftpd: (?@client.example.com) [WARNING] Authentication failed for user [` + user + `]`
		if got := parseFTPLogLine(line, &config.Config{}); got != nil {
			t.Errorf("username %q produced %+v", user, got)
		}
	}
}

func TestParseFTPLogLineRequiresPeerPosition(t *testing.T) {
	for _, peer := range []string{"", "(unknown)", "(?@)", "(?@client.example.com)", "(?@203.0.113.5", "(?@203.0.113.5)junk"} {
		for _, user := range []string{"x 198.51.100.7 y", "x (a@198.51.100.7) y"} {
			line := "Apr 11 10:00:00 192.0.2.1 pure-ftpd[1]: " + peer + " [WARNING] Authentication failed for user [" + user + "]"
			if got := parseFTPLogLine(line, &config.Config{}); len(got) != 0 {
				t.Errorf("line %q produced %+v", line, got)
			}
		}
	}
}

func TestParseFTPLogLineRequiresProgramTag(t *testing.T) {
	for _, line := range []string{
		"Apr 11 10:00:00 host other[1]: USER pure-ftpd: (?@198.51.100.7) Authentication failed",
		"Apr 11 10:00:00 host not-pure-ftpd: (?@198.51.100.7) Authentication failed",
		"Apr 11 10:00:00 host pure-ftpd[bad]: (?@198.51.100.7) Authentication failed",
		"(x@198.51.100.7) pure-ftpd: Authentication failed",
	} {
		if got := parseFTPLogLine(line, &config.Config{}); len(got) != 0 {
			t.Errorf("line %q produced %+v", line, got)
		}
	}
}

func TestParseFTPLogLinePeerFormats(t *testing.T) {
	for _, prefix := range []string{"pure-ftpd: ", "Apr 11 10:00:00 192.0.2.1 pure-ftpd[42]: ", "2026-04-11T10:00:00Z 192.0.2.1 pure-ftpd[42]: "} {
		for _, ip := range []string{"203.0.113.5", "2001:db8::5", "::ffff:203.0.113.5"} {
			line := prefix + "(?@" + ip + ") [WARNING] Authentication failed for user [x (a@198.51.100.7) y]"
			findings := parseFTPLogLine(line, &config.Config{})
			if len(findings) != 1 || findings[0].SourceIP != ip || findings[0].Check != "ftp_auth_failure_realtime" {
				t.Errorf("line %q produced %+v, want failure from %s", line, findings, ip)
			}
		}
	}
}
