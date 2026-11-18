package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func sessionLogDaemon(cfg *config.Config) *Daemon {
	d := New(cfg, nil, nil, "")
	d.hijackDetector = NewPasswordHijackDetector(cfg, d.alertCh, d.stopCh)
	d.staleSession401 = newStaleSession401s()
	return d
}

// Webmail logins were only noted as known customers, so a thief logging in
// to Roundcube from abroad was never geo-checked and its addresses became
// trusted. They now go through the same new-country check as IMAP.
func TestWebmailLoginFromNewCountryIsEvidence(t *testing.T) {
	db, calls := evidenceCase(t)
	resetPurgeTrackerState()
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "198.51.100.7": "DE", "192.0.2.9": "BR"})
	cfg := eximAutoHoldConfig()
	d := sessionLogDaemon(cfg)

	for range geoMinLoginCount {
		if got := findingsOf(d.cpanelSessionLogHandler(sessionNewLine("webmaild", "203.0.113.5", "real@victim.example"), cfg), "email_suspicious_geo"); len(got) != 0 {
			t.Fatalf("home login reported %+v", got)
		}
	}
	got := d.cpanelSessionLogHandler(sessionNewLine("webmaild", "198.51.100.7", "real@victim.example"), cfg)
	geo := findingsOf(got, "email_suspicious_geo")
	if len(geo) != 1 || !strings.Contains(geo[0].Message, "webmail login") || geo[0].SourceIP != "198.51.100.7" {
		t.Fatalf("first foreign webmail login: %+v, want one email_suspicious_geo naming webmail", got)
	}
	if !checks.IsSummaryNotice(geo[0]) {
		t.Fatalf("email_suspicious_geo must be summary class: %+v", geo[0])
	}
	if len(findingsOf(got, "email_mailbox_compromise")) != 0 || len(*calls) != 0 {
		t.Fatalf("one new country acted: %+v, uapi %v", got, *calls)
	}
	h, _ := db.GetGeoHistory("real@victim.example")
	if h.Webmail == nil || h.Webmail.IP != "198.51.100.7" || h.Webmail.Country != "DE" || h.Webmail.At.IsZero() {
		t.Fatalf("last webmail login = %+v", h.Webmail)
	}

	// A second new country within a day completes the incident, even
	// though the per-mailbox geo finding is still in its cooldown.
	got = d.cpanelSessionLogHandler(sessionNewLine("webmaild", "192.0.2.9", "real@victim.example"), cfg)
	onlyIncident(t, findingsOf(got, "email_mailbox_compromise"))
	if len(*calls) != 2 {
		t.Fatalf("uapi calls = %v, want one suspension", *calls)
	}
}

func TestDovecotNewCountryIsEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "198.51.100.7": "DE"})
	cfg := eximAutoHoldConfig()
	for range geoMinLoginCount {
		parseDovecotLogLine(dovecotLoginLine("real@victim.example", "203.0.113.5"), cfg)
	}
	got := parseDovecotLogLine(dovecotLoginLine("real@victim.example", "198.51.100.7"), cfg)
	if len(got) != 1 || got[0].Check != "email_suspicious_geo" {
		t.Fatalf("findings = %+v", got)
	}
	e, err := db.UpdateMailboxEvidence("real@victim.example", func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 1 || e.Signals[0].Kind != signalNewCountry || e.Signals[0].Key != "DE" {
		t.Fatalf("ledger = %+v, %v", e, err)
	}
	h, _ := db.GetGeoHistory("real@victim.example")
	if h.Webmail != nil {
		t.Fatalf("an IMAP login was stored as the last webmail login: %+v", h.Webmail)
	}
}

// A session a panel opened through the API is not a login the user made.
func TestWebmailAPISessionIsNotALogin(t *testing.T) {
	db, _ := evidenceCase(t)
	resetPurgeTrackerState()
	withGeoCountries(t, map[string]string{"198.51.100.7": "DE"})
	cfg := eximAutoHoldConfig()
	d := sessionLogDaemon(cfg)
	line := strings.Replace(sessionNewLine("webmaild", "198.51.100.7", "real@victim.example"), "method=handle_form_login", "method=create_user_session", 1)
	d.cpanelSessionLogHandler(line, cfg)
	if h, found := db.GetGeoHistory("real@victim.example"); found {
		t.Fatalf("API session counted as a login: %+v", h)
	}
}
