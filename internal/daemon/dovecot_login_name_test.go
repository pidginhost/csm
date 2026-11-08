package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A Dovecot 2.4 failure summary whose login name carries another address.
const forgedDovecotFailure = "Nov  8 08:40:00 host dovecot[1]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 17 secs) (auth_failed): user=<x, rip=198.51.100.7, y>, method=PLAIN, rip=203.0.113.50, lip=192.0.2.1, secured, session=<S>"

func TestMailLoginFailureCountsConnectingAddressNotLoginName(t *testing.T) {
	ip, _, success := currentAccountExtractor().extractMailLoginEvent(forgedDovecotFailure)
	if ip != "203.0.113.50" || success {
		t.Fatalf("extractMailLoginEvent = %q, success %v; want 203.0.113.50, false", ip, success)
	}
	d, clock := newPairingDaemon(t, &config.Config{})
	var findings []alert.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, feed(d, clock, forgedDovecotFailure)...)
	}
	if len(findings) != 1 || findings[0].Check != "mail_bruteforce" || findings[0].SourceIP != "203.0.113.50" {
		t.Fatalf("got %+v, want one brute-force finding for the connecting address", findings)
	}
}

func TestDovecotLoginFieldsReadConnectingAddress(t *testing.T) {
	user, ip := parseDovecotLoginFields("Nov  8 08:40:00 host dovecot: imap-login: Login: user=<x, rip=198.51.100.7, y>, method=PLAIN, rip=203.0.113.50, lip=192.0.2.1, mpid=1, TLS")
	if user != "x, rip=198.51.100.7, y" || ip != "203.0.113.50" {
		t.Fatalf("parseDovecotLoginFields = %q, %q; want the login name and 203.0.113.50", user, ip)
	}
}

func TestDovecotReadersPreserveWholeLoginName(t *testing.T) {
	ex, err := NewAccountExtractor("")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"alice@example.com>, user=<other@example.com",
		"alice@example.com>, rip=198.51.100.7, lip=192.0.2.7, session=<Forged>",
		"x, session=<Forged",
	} {
		line := "dovecot: imap-login: Login: user=<" + name + ">, method=PLAIN, rip=203.0.113.50, lip=192.0.2.1, session=<Real>"
		if got := ex.Extract(line); got != name {
			t.Errorf("account key = %q, want %q", got, name)
		}
		user, ip := parseDovecotLoginFields(line)
		if user != name || ip != "203.0.113.50" {
			t.Errorf("geo fields = %q, %q, want %q, 203.0.113.50", user, ip, name)
		}
	}
}

func TestDovecotSessionCannotComeFromLoginName(t *testing.T) {
	line := "dovecot: imap-login: Aborted login (auth failed): user=<x, rip=198.51.100.7, session=<Forged>, y>, method=PLAIN"
	if got := dovecotLoginSession(line); got != "" {
		t.Fatalf("session = %q from client text", got)
	}
}

func TestDovecotSessionMayContainFieldText(t *testing.T) {
	for _, session := range []string{"trip=", "clip=", "method="} {
		line := strings.Replace(forgedDovecotFailure, "session=<S>", "session=<"+session+">", 1)
		if got := dovecotLoginSession(line); got != session {
			t.Errorf("got %q, want session %q", got, session)
		}
	}
}

func TestDovecotReadersRejectMissingRemoteAddress(t *testing.T) {
	line := "dovecot: imap-login: Aborted login (auth failed): user=<x, rip=198.51.100.7, y>, method=PLAIN"
	ip, _, _ := currentAccountExtractor().extractMailLoginEvent(line)
	if ip != "" {
		t.Errorf("brute force selected %q from client text", ip)
	}
	_, ip = parseDovecotLoginFields(strings.Replace(line, "Aborted login (auth failed)", "Login", 1))
	if ip != "" {
		t.Errorf("geo selected %q from client text", ip)
	}
}
