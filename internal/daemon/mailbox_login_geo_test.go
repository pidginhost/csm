package daemon

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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

func geoSessionLine(at time.Time, ip, account string) string {
	line := sessionNewLine("webmaild", ip, account)
	return "[" + at.Format("2006-01-02 15:04:05 -0700") + line[strings.IndexByte(line, ']'):]
}

func geoDovecotLine(at time.Time, ip, account string) string {
	_, msg, _ := strings.Cut(dovecotLoginLine(account, ip), " host ")
	return at.Format(time.RFC3339) + " host " + msg
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
		if got := findingsOf(d.cpanelSessionLogHandler(geoSessionLine(time.Now(), "203.0.113.5", "real@victim.example"), cfg), "email_suspicious_geo"); len(got) != 0 {
			t.Fatalf("home login reported %+v", got)
		}
	}
	got := d.cpanelSessionLogHandler(geoSessionLine(time.Now(), "198.51.100.7", "real@victim.example"), cfg)
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
	got = d.cpanelSessionLogHandler(geoSessionLine(time.Now(), "192.0.2.9", "real@victim.example"), cfg)
	onlyIncident(t, got)
	if len(*calls) != 2 {
		t.Fatalf("uapi calls = %v, want one suspension", *calls)
	}
}

func TestDovecotNewCountryIsEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "198.51.100.7": "DE"})
	cfg := eximAutoHoldConfig()
	for range geoMinLoginCount {
		parseDovecotLogLine(geoDovecotLine(time.Now(), "203.0.113.5", "real@victim.example"), cfg, true)
	}
	got := parseDovecotLogLine(geoDovecotLine(time.Now(), "198.51.100.7", "real@victim.example"), cfg, true)
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
	line := strings.Replace(geoSessionLine(time.Now(), "198.51.100.7", "real@victim.example"), "method=handle_form_login", "method=create_user_session", 1)
	d.cpanelSessionLogHandler(line, cfg)
	if h, found := db.GetGeoHistory("real@victim.example"); found {
		t.Fatalf("API session counted as a login: %+v", h)
	}
}

func TestGeoLoginUsesEventTimeAcrossReaders(t *testing.T) {
	db, calls := evidenceCase(t)
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "198.51.100.7": "DE", "192.0.2.9": "BR"})
	cfg := eximAutoHoldConfig()
	d := sessionLogDaemon(cfg)
	const account = "real@victim.example"
	now := time.Now().UTC().Truncate(time.Second)
	older := now.Add(-48 * time.Hour)
	for range geoMinLoginCount {
		d.cpanelSessionLogHandler(geoSessionLine(older.Add(-time.Hour), "203.0.113.5", account), cfg)
	}
	d.cpanelSessionLogHandler(geoSessionLine(now, "198.51.100.7", account), cfg)
	got := parseDovecotLogLine(geoDovecotLine(older, "192.0.2.9", account), cfg, true)
	if len(got) != 0 || len(*calls) != 0 {
		t.Errorf("logins two days apart produced %+v, calls %v", got, *calls)
	}
	d.cpanelSessionLogHandler(geoSessionLine(older, "203.0.113.5", account), cfg)
	h, _ := db.GetGeoHistory(account)
	if h.Webmail == nil || !h.Webmail.At.Equal(now) || h.Webmail.Country != "DE" || h.Countries["BR"] != older.Unix() {
		t.Errorf("history after delayed logins = %+v, last webmail = %+v", h, h.Webmail)
	}
	e, err := db.UpdateMailboxEvidence(account, func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 2 || !e.LastNewCountry.Equal(now) || e.ReportedAt != nil {
		t.Fatalf("ledger after delayed logins = %+v, %v", e, err)
	}
}

func TestLatestWebmailWithoutCountryReplacesLocation(t *testing.T) {
	db, _ := evidenceCase(t)
	cfg := eximAutoHoldConfig()
	cfg.InfraIPs = []string{"192.0.2.18"}
	d := sessionLogDaemon(cfg)
	const account = "real@victim.example"
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "192.0.2.18": "DE"})
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for i, ip := range []string{"198.51.100.7", "192.0.2.18"} {
		at = at.Add(time.Minute)
		d.cpanelSessionLogHandler(geoSessionLine(at, "203.0.113.5", account), cfg)
		at = at.Add(time.Minute)
		d.cpanelSessionLogHandler(geoSessionLine(at, ip, account), cfg)
		h, _ := db.GetGeoHistory(account)
		if h.Webmail == nil || h.Webmail.IP != ip || h.Webmail.Country != "" || !h.Webmail.At.Equal(at) || h.LoginCount != i+1 || len(h.Countries) != 1 {
			t.Fatalf("unlocated login from %s: history %+v, webmail %+v", ip, h, h.Webmail)
		}
	}
}

func TestConcurrentMailboxLoginsShareHistoryAndCooldown(t *testing.T) {
	db, _ := evidenceCase(t)
	cfg := dryRunConfig()
	const account = "real@victim.example"
	if err := db.SetGeoHistory(account, store.GeoHistory{Countries: map[string]int64{"RO": time.Now().Unix()}, LoginCount: geoMinLoginCount}); err != nil {
		t.Fatal(err)
	}
	withGeoCountries(t, map[string]string{"198.51.100.7": "DE", "192.0.2.9": "BR"})
	d := sessionLogDaemon(cfg)
	const pairs = 16
	gate := make(chan struct{})
	results := make(chan []alert.Finding, 2*pairs)
	var wg sync.WaitGroup
	for range pairs {
		for _, webmail := range []bool{false, true} {
			wg.Go(func() {
				<-gate
				if webmail {
					line := geoSessionLine(time.Now(), "198.51.100.7", "Real@Victim.Example")
					results <- d.cpanelSessionLogHandler(line, cfg)
				} else {
					results <- parseDovecotLogLine(geoDovecotLine(time.Now(), "192.0.2.9", account), cfg, true)
				}
			})
		}
	}
	close(gate)
	wg.Wait()
	close(results)
	var findings []alert.Finding
	for fs := range results {
		findings = append(findings, fs...)
	}
	h, _ := db.GetGeoHistory(account)
	if h.LoginCount != geoMinLoginCount+2*pairs || len(h.Countries) != 3 || h.Webmail == nil || h.Webmail.Country != "DE" {
		t.Errorf("concurrent history = %+v", h)
	}
	if len(findingsOf(findings, "email_suspicious_geo")) != 1 || len(findingsOf(findings, "email_mailbox_compromise")) != 1 {
		t.Errorf("concurrent findings = %+v", findings)
	}
	e, err := db.UpdateMailboxEvidence(account, func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 2 || e.Signals[0].Count != 1 || e.Signals[1].Count != 1 {
		t.Fatalf("ledger = %+v, %v", e, err)
	}
}

func TestWebmailPossessedSessionDoesNotLocateMailbox(t *testing.T) {
	db, _ := evidenceCase(t)
	withGeoCountries(t, map[string]string{"198.51.100.7": "DE"})
	cfg := eximAutoHoldConfig()
	d := sessionLogDaemon(cfg)
	const mailbox = "real@victim.example"
	line := strings.Replace(geoSessionLine(time.Now(), "198.51.100.7", mailbox), "possessed=0", "possessed=1", 1)
	d.cpanelSessionLogHandler(line, cfg)
	if h, ok := db.GetGeoHistory(mailbox); ok {
		t.Fatalf("a session opened on behalf of the mailbox changed its history: %+v", h)
	}
}

// A mail server can authenticate internationalized addresses. Only the ASCII
// case aliases may share a mailbox's history, ledger and response target.
func TestGeoLedgerKeepsAuthenticatedMailboxIdentity(t *testing.T) {
	db, _ := evidenceCase(t)
	withGeoCountries(t, map[string]string{"203.0.113.5": "RO", "198.51.100.7": "DE", "192.0.2.9": "BR"})
	cfg := dryRunConfig()
	const mailbox = "\u212Aim@victim.example"
	for range geoMinLoginCount {
		parseDovecotLogLine(geoDovecotLine(time.Now(), "203.0.113.5", mailbox), cfg, true)
	}
	parseDovecotLogLine(geoDovecotLine(time.Now(), "198.51.100.7", mailbox), cfg, true)
	got := parseDovecotLogLine(geoDovecotLine(time.Now(), "192.0.2.9", mailbox), cfg, true)
	if len(got) != 1 || got[0].Check != "email_mailbox_compromise" || got[0].Mailbox != mailbox {
		t.Fatalf("foreign logins for %q produced %+v", mailbox, got)
	}
	for account, want := range map[string]int{mailbox: 2, "kim@victim.example": 0} {
		e, err := db.UpdateMailboxEvidence(account, func(*store.MailboxEvidence) {})
		if err != nil || len(e.Signals) != want {
			t.Errorf("ledger for %q = %+v, %v", account, e, err)
		}
	}
}

func TestMailboxSuspensionFlagsDistinguishUnicodeMailboxes(t *testing.T) {
	evidenceCase(t)
	stubUAPI(t, func([]string) ([]byte, error) {
		return listPopsReply(`{"email":"\u212aim@victim.example","suspended_login":1,"suspended_outgoing":1}`, `{"email":"kim@victim.example","suspended_login":0,"suspended_outgoing":0}`)
	})
	flags, err := cpanelMailboxFlags("owner")
	if err != nil || !flags["\u212Aim@victim.example"].login || flags["kim@victim.example"].login {
		t.Fatalf("mailbox flags = %+v, %v", flags, err)
	}
}
