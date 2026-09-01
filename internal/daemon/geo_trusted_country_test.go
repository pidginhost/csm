package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/store"
)

func withGeoCountries(t *testing.T, byIP map[string]string) {
	t.Helper()
	prev := geoLookup
	geoLookup = func(ip string) geoip.Info { return geoip.Info{Country: byIP[ip]} }
	t.Cleanup(func() { geoLookup = prev })
}

func dovecotLoginLine(user, ip string) string {
	return "Apr 14 10:00:00 host dovecot: imap-login: Login: user=<" + user + ">, method=PLAIN, rip=" + ip + ", lip=10.0.0.1, mpid=1, TLS, session=<x>"
}

// trusted_countries suppresses alerts for logins from home; it must not stop
// those logins from counting. Otherwise a mailbox whose owner always logs in
// from a trusted country never reaches the login floor, the first foreign
// login is recorded as an already-known country, and the detector is blind
// for that mailbox forever.
func TestGeoAlertFiresAfterTrustedCountryLogins(t *testing.T) {
	withGeoCountries(t, map[string]string{
		"203.0.113.5":  "RO",
		"198.51.100.7": "CN",
	})
	cfg := &config.Config{}
	cfg.Suppressions.TrustedCountries = []string{"RO"}

	withGlobalStore(t, func(_ *store.DB) {
		for i := 0; i < geoMinLoginCount+1; i++ {
			if got := parseDovecotLogLine(dovecotLoginLine("alice@example.com", "203.0.113.5"), cfg); len(got) != 0 {
				t.Fatalf("trusted-country login %d produced findings: %+v", i, got)
			}
		}
		findings := parseDovecotLogLine(dovecotLoginLine("alice@example.com", "198.51.100.7"), cfg)
		if len(findings) != 1 || findings[0].Check != "email_suspicious_geo" {
			t.Fatalf("first foreign login after trusted history: findings = %+v, want one email_suspicious_geo", findings)
		}
	})
}

// A mailbox that has not reached the login floor stays in its learning
// period regardless of where the logins come from.
func TestGeoAlertStillWaitsForLoginFloor(t *testing.T) {
	withGeoCountries(t, map[string]string{
		"203.0.113.5":  "RO",
		"198.51.100.7": "CN",
	})
	cfg := &config.Config{}
	cfg.Suppressions.TrustedCountries = []string{"RO"}

	withGlobalStore(t, func(_ *store.DB) {
		for i := 0; i < geoMinLoginCount-2; i++ {
			parseDovecotLogLine(dovecotLoginLine("bob@example.com", "203.0.113.5"), cfg)
		}
		if got := parseDovecotLogLine(dovecotLoginLine("bob@example.com", "198.51.100.7"), cfg); len(got) != 0 {
			t.Fatalf("foreign login below the login floor produced findings: %+v", got)
		}
	})
}
