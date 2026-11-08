package checks

import (
	"strings"
	"testing"
)

// dovecotLoginLine is a Dovecot 2.4 login summary. Dovecot logs the login
// name as the client sent it, so user= can hold any text.
func dovecotLoginLine(user, rip string) string {
	return "Nov  8 08:40:00 host dovecot[1]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 17 secs) (auth_failed): user=<" +
		user + ">, method=PLAIN, rip=" + rip + ", lip=192.0.2.1, secured, session=<S>"
}

func TestDovecotRemoteIPIgnoresAddressInLoginName(t *testing.T) {
	for _, user := range []string{
		"x, rip=198.51.100.7, y",
		"x rip=198.51.100.7 y",
		"rip=198.51.100.7",
		"x@rip=198.51.100.7",
		"x, rip=2001:db8::7, y",
	} {
		if got := DovecotRemoteIP(dovecotLoginLine(user, "203.0.113.50")); got != "203.0.113.50" {
			t.Errorf("user %q: got %q, want the connecting address 203.0.113.50", user, got)
		}
	}
}

func TestDovecotRemoteIPReadsEveryLoginShape(t *testing.T) {
	cases := map[string]string{
		"Nov  8 08:40:00 host dovecot: imap-login: Login: user=<a@example.com>, method=PLAIN, rip=203.0.113.5, lip=192.0.2.1, mpid=1, TLS":                                       "203.0.113.5",
		"Nov  8 08:40:00 host dovecot: pop3-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<a@example.com>, method=PLAIN, rip=2001:db8::5, lip=2001:db8::1, TLS": "2001:db8::5",
		"Nov  8 08:40:00 host dovecot: imap-login: Disconnected (no auth attempts in 0 secs): rip=203.0.113.6, lip=192.0.2.1":                                                    "203.0.113.6",
		"Nov  8 08:40:00 host dovecot: imap-login: Login: user=<a@example.com>, method=PLAIN, rip=not-an-ip, lip=192.0.2.1":                                                      "",
		"Nov  8 08:40:00 host dovecot: imap-login: Login: user=<a@example.com>, method=PLAIN":                                                                                    "",
		"Nov  8 08:40:00 host dovecot: imap-login: Login: user=<a@example.com>, method=PLAIN, xrip=203.0.113.7":                                                                  "",
	}
	for line, want := range cases {
		if got := DovecotRemoteIP(line); got != want {
			t.Errorf("DovecotRemoteIP(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestDovecotRemoteIPRequiresAddressOutsideUser(t *testing.T) {
	for _, fields := range []string{
		"user=<x, rip=198.51.100.7, y>, method=PLAIN",
		"user=<x, rip=198.51.100.7>",
		"user=<x, rip=198.51.100.7, y",
		"user=<x>, rip=198.51.100.7, y>, method=PLAIN",
		"user=<x, rip=198.51.100.7, session=<Forged>>, method=PLAIN, lip=192.0.2.1",
	} {
		if got := DovecotRemoteIP("dovecot: imap-login: Aborted login (auth failed): " + fields); got != "" {
			t.Errorf("%q chose client text %q", fields, got)
		}
	}
}

func TestDovecotRemoteIPFieldBoundaries(t *testing.T) {
	for _, separator := range []string{", ", " ", "\t"} {
		for _, user := range []string{"", "user=<a@example.com>" + separator} {
			line := "dovecot: imap-login: Disconnected (no auth attempts): " + user + "method=PLAIN" + separator + "rip=2001:db8::5\r\n"
			if got := DovecotRemoteIP(line); got != "2001:db8::5" {
				t.Errorf("%q: got %q, want 2001:db8::5", line, got)
			}
		}
	}
}

func TestDovecotRemoteIPWithSessionSeparators(t *testing.T) {
	for _, separator := range []string{", ", " ", "\t"} {
		line := "dovecot: imap-login: Login: user=<a@example.com>" + separator + "rip=203.0.113.50" + separator + "session=<S>"
		if got := DovecotRemoteIP(line); got != "203.0.113.50" {
			t.Errorf("separator %q: got %q, want 203.0.113.50", separator, got)
		}
	}
}

func TestDovecotRemoteIPIgnoresFieldTextInSession(t *testing.T) {
	for _, session := range []string{"trip=", "clip=", "method="} {
		line := strings.Replace(dovecotLoginLine("alice@example.com", "203.0.113.50"), "session=<S>", "session=<"+session+">", 1)
		if got := DovecotRemoteIP(line); got != "203.0.113.50" {
			t.Errorf("session %q: got %q, want 203.0.113.50", session, got)
		}
	}
}
