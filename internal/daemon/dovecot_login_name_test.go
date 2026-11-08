package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// A Dovecot 2.4 failure summary whose login name carries another address.
const forgedDovecotFailure = "Nov  8 08:40:00 host dovecot[1]: imap-login: Login aborted: Logged out (auth failed, 1 attempts in 17 secs) (auth_failed): user=<x, rip=198.51.100.7, y>, method=PLAIN, rip=203.0.113.50, lip=192.0.2.1, secured, session=<S>"

func TestMailLoginFailureCountsConnectingAddressNotLoginName(t *testing.T) {
	ip, _, success := currentAccountExtractor().extractMailLoginEvent(forgedDovecotFailure)
	if ip != "203.0.113.50" || success {
		t.Fatalf("extractMailLoginEvent = %q, success %v; want 203.0.113.50, false", ip, success)
	}
	cfg := &config.Config{}
	tr := newTestMailTracker(t, &staticClock{t: time.Date(2026, 11, 8, 8, 40, 0, 0, time.UTC)})
	h := buildMailHandler(cfg, tr)
	for i := 0; i < 5; i++ {
		for _, f := range h(forgedDovecotFailure, cfg) {
			if f.SourceIP == "198.51.100.7" {
				t.Fatalf("%s blamed the address named in the login: %+v", f.Check, f)
			}
		}
	}
}

func TestDovecotLoginFieldsReadConnectingAddress(t *testing.T) {
	user, ip := parseDovecotLoginFields("Nov  8 08:40:00 host dovecot: imap-login: Login: user=<x, rip=198.51.100.7, y>, method=PLAIN, rip=203.0.113.50, lip=192.0.2.1, mpid=1, TLS")
	if user != "x, rip=198.51.100.7, y" || ip != "203.0.113.50" {
		t.Fatalf("parseDovecotLoginFields = %q, %q; want the login name and 203.0.113.50", user, ip)
	}
}
