package daemon

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/store"
)

// homeHistory gives user an established login history from RO.
func homeHistory(t *testing.T, db *store.DB, user string, webmail *store.WebmailLogin) {
	t.Helper()
	h := store.GeoHistory{Countries: map[string]int64{"RO": time.Now().Unix()}, LoginCount: geoMinLoginCount + 1, Webmail: webmail}
	if webmail != nil {
		h.Countries[webmail.Country] = webmail.At.Unix()
	}
	if err := db.SetGeoHistory(user, h); err != nil {
		t.Fatal(err)
	}
}

func todaysSendCountries(t *testing.T, db *store.DB, user string, at time.Time) []string {
	t.Helper()
	flushSenderProfiles()
	p, err := db.GetSenderProfile(user)
	if err != nil {
		t.Fatal(err)
	}
	day := p.Days[senderDayKey(at)]
	if day == nil {
		t.Fatalf("no sends recorded for %s", user)
	}
	return day.Countries
}

func ledgerSignal(t *testing.T, db *store.DB, mailbox, kind, key string) (store.MailboxSignal, bool) {
	t.Helper()
	e, err := db.UpdateMailboxEvidence(mailbox, func(*store.MailboxEvidence) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range e.Signals {
		if s.Kind == kind && s.Key == key {
			return s, true
		}
	}
	return store.MailboxSignal{}, false
}

// Webmail submits over loopback, so its sends had no country and the
// sender profile could never see a webmail thief abroad.
func TestLoopbackSendTakesWebmailCountry(t *testing.T) {
	for _, loopback := range []string{netip.IPv6Loopback().String(), netip.AddrFrom4([4]byte{127, 0, 0, 1}).String()} {
		t.Run(loopback, func(t *testing.T) {
			db, _ := evidenceCase(t)
			resetSenderProfileState()
			at := time.Now()
			homeHistory(t, db, "real@victim.example", &store.WebmailLogin{IP: "198.51.100.7", Country: "DE", At: at.Add(-90 * time.Minute)})

			senderProfileObserve(eximAutoHoldConfig(), "real@victim.example", loopback, []string{"a@friend.example"}, at)
			if got := todaysSendCountries(t, db, "real@victim.example", at); !slices.Equal(got, []string{"DE"}) {
				t.Fatalf("send countries = %v, want the webmail login's DE", got)
			}
		})
	}
}

func TestLoopbackSendIgnoresOldWebmailLogin(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	at := time.Now()
	homeHistory(t, db, "real@victim.example", &store.WebmailLogin{IP: "198.51.100.7", Country: "DE", At: at.Add(-3 * time.Hour)})

	parseEximLogLine(geoSendAt("real@victim.example", netip.IPv6Loopback().String(), at), eximAutoHoldConfig())
	if got := todaysSendCountries(t, db, "real@victim.example", at); len(got) != 0 {
		t.Fatalf("send countries = %v, want none from a login three hours old", got)
	}
}

// The incident's webmail path: a foreign webmail login, then the loopback
// send it makes. Both are evidence of the same new country.
func TestWebmailLoginThenLoopbackSendIsNewCountryEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetPurgeTrackerState()
	withGeoCountries(t, map[string]string{"198.51.100.7": "DE"})
	homeHistory(t, db, "real@victim.example", nil)
	cfg := eximAutoHoldConfig()
	d := sessionLogDaemon(cfg)

	d.cpanelSessionLogHandler(geoSessionLine(time.Now(), "198.51.100.7", "real@victim.example"), cfg)
	parseEximLogLine(geoSendAt("real@victim.example", netip.IPv6Loopback().String(), time.Now()), cfg)

	s, ok := ledgerSignal(t, db, "real@victim.example", signalNewCountry, "DE")
	if !ok || s.Count != 2 {
		t.Fatalf("new-country evidence = %+v (found %v), want the login and the send", s, ok)
	}
	if got := todaysSendCountries(t, db, "real@victim.example", time.Now()); !slices.Equal(got, []string{"DE"}) {
		t.Fatalf("send countries = %v, want DE", got)
	}
}

// Direct SMTP AUTH from a country the mailbox never logged in from is
// evidence too, even for a mailbox exempt from volume profiling.
func TestSMTPSendFromNewCountryIsEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	withGeoCountries(t, map[string]string{"192.0.2.9": "BR", "203.0.113.5": "RO"})
	homeHistory(t, db, "real@victim.example", nil)
	cfg := eximAutoHoldConfig()
	cfg.EmailProtection.HighVolumeSenders = []string{"real@victim.example"}

	parseEximLogLine(geoSendAt("real@victim.example", "203.0.113.5", time.Now()), cfg)
	if _, ok := ledgerSignal(t, db, "real@victim.example", signalNewCountry, "RO"); ok {
		t.Fatal("a send from the home country counted as new")
	}
	parseEximLogLine(geoSendAt("real@victim.example", "192.0.2.9", time.Now()), cfg)
	s, ok := ledgerSignal(t, db, "real@victim.example", signalNewCountry, "BR")
	if !ok || !strings.Contains(s.Detail, "authenticated send from BR (192.0.2.9)") {
		t.Fatalf("new-country evidence = %+v (found %v)", s, ok)
	}
}

// A mailbox still learning its logins has no new country yet.
func TestSMTPSendNeedsLoginHistory(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	withGeoCountries(t, map[string]string{"192.0.2.9": "BR"})
	parseEximLogLine(geoSendAt("real@victim.example", "192.0.2.9", time.Now()), eximAutoHoldConfig())
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalNewCountry, "BR"); ok {
		t.Fatalf("unlearned mailbox reported %+v", s)
	}
}

func geoSendAt(user, ip string, at time.Time) string {
	line := senderSendLine(user, ip, "a@friend.example")
	return at.Format("2006-01-02 15:04:05 -0700") + line[len("2006-01-02 15:04:05"):]
}

func TestWebmailSendUsesLoggedTimeAndLastLogin(t *testing.T) {
	const user = "real@victim.example"
	at := time.Now().UTC().Truncate(24 * time.Hour).Add(-12 * time.Hour)
	for _, tc := range []struct {
		name    string
		delay   time.Duration
		newerIP string
		want    string
	}{
		{"before login", -time.Second, "", ""},
		{"at expiry", webmailSendWindow, "", "DE"},
		{"past expiry", webmailSendWindow + time.Second, "", ""},
		{"unlocated login", time.Minute, "192.0.2.1", ""},
		{"known login", time.Minute, "203.0.113.5", "RO"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := evidenceCase(t)
			resetSenderProfileState()
			resetPurgeTrackerState()
			withGeoCountries(t, map[string]string{"198.51.100.7": "DE", "203.0.113.5": "RO"})
			homeHistory(t, db, user, nil)
			cfg := eximAutoHoldConfig()
			d := sessionLogDaemon(cfg)
			d.cpanelSessionLogHandler(geoSessionLine(at, "198.51.100.7", user), cfg)
			if tc.newerIP != "" {
				d.cpanelSessionLogHandler(geoSessionLine(at.Add(time.Second), tc.newerIP, user), cfg)
			}
			parseEximLogLine(geoSendAt(user, netip.IPv6Loopback().String(), at.Add(tc.delay)), cfg)
			got := todaysSendCountries(t, db, user, time.Now())
			if (tc.want == "" && len(got) != 0) || (tc.want != "" && !slices.Equal(got, []string{tc.want})) {
				t.Errorf("profile countries = %v, want %q", got, tc.want)
			}
			wantCount := 1
			if tc.want == "DE" {
				wantCount++
			}
			if s, ok := ledgerSignal(t, db, user, signalNewCountry, "DE"); !ok || s.Count != wantCount {
				t.Errorf("DE evidence = %+v, want %d observations", s, wantCount)
			}
			if s, ok := ledgerSignal(t, db, user, signalNewCountry, "RO"); ok {
				t.Errorf("known-country send recorded %+v", s)
			}
		})
	}
}

func TestSMTPSendSharesLoginHistoryAndCountry(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	const mailbox = "real@victim.example"
	homeHistory(t, db, mailbox, nil)
	saved := geoLookup
	t.Cleanup(func() { geoLookup = saved })
	lookups := 0
	geoLookup = func(ip string) geoip.Info {
		lookups++
		return geoip.Info{Country: "BR"}
	}
	parseEximLogLine(geoSendAt("Real@Victim.example", "192.0.2.9", time.Now()), eximAutoHoldConfig())
	if lookups != 1 {
		t.Errorf("country lookups = %d, want one per send", lookups)
	}
	if s, ok := ledgerSignal(t, db, mailbox, signalNewCountry, "BR"); !ok || s.Count != 1 {
		t.Errorf("mixed-case SMTP login recorded %+v, want one BR observation", s)
	}
}

func TestUndatedWebmailLoginDoesNotPlaceNextSend(t *testing.T) {
	const user = "real@victim.example"
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetPurgeTrackerState()
	withGeoCountries(t, map[string]string{"198.51.100.7": "DE", "203.0.113.5": "RO"})
	homeHistory(t, db, user, nil)
	cfg := eximAutoHoldConfig()
	d := sessionLogDaemon(cfg)
	at := time.Now().Add(-time.Minute)
	d.cpanelSessionLogHandler(geoSessionLine(at, "198.51.100.7", user), cfg)
	line := geoSessionLine(at, "203.0.113.5", user)
	d.cpanelSessionLogHandler("[unknown time"+line[strings.IndexByte(line, ']'):], cfg)
	parseEximLogLine(geoSendAt(user, netip.IPv6Loopback().String(), time.Now()), cfg)
	if got := todaysSendCountries(t, db, user, time.Now()); len(got) != 0 {
		t.Fatalf("undated login left the send attributed to %v", got)
	}
}

func TestExemptWebmailAndSMTPDuringLoginCooldown(t *testing.T) {
	const user = "real@victim.example"
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetPurgeTrackerState()
	withGeoCountries(t, map[string]string{"198.51.100.7": "DE", "192.0.2.9": "BR"})
	homeHistory(t, db, user, nil)
	cfg := dryRunConfig()
	cfg.EmailProtection.HighVolumeSenders = []string{user}
	d := sessionLogDaemon(cfg)
	at := time.Now().Add(-time.Minute)
	first := d.cpanelSessionLogHandler(geoSessionLine(at, "198.51.100.7", user), cfg)
	if len(findingsOf(first, "email_suspicious_geo")) != 1 {
		t.Fatalf("first country findings = %+v", first)
	}
	parseEximLogLine(geoSendAt(user, netip.IPv6Loopback().String(), at.Add(time.Second)), cfg)
	second := parseEximLogLine(geoSendAt(user, "192.0.2.9", at.Add(2*time.Second)), cfg)
	onlyIncident(t, findingsOf(second, "email_mailbox_compromise"))
	for country, want := range map[string]int{"DE": 2, "BR": 1} {
		if s, ok := ledgerSignal(t, db, user, signalNewCountry, country); !ok || s.Count != want {
			t.Fatalf("%s evidence = %+v, want %d observations", country, s, want)
		}
	}
	if _, profiled := senderWindows.Load(user); profiled {
		t.Fatal("volume exemption was lost")
	}
}

// Each sign is reported once in the daily summary.
func TestSMTPSendFromNewCountryIsReportedOnce(t *testing.T) {
	_, _ = evidenceCase(t)
	resetSenderProfileState()
	resetBulkRecipientState()
	withGeoCountries(t, map[string]string{"192.0.2.9": "BR"})
	cfg := eximAutoHoldConfig()
	homeHistory(t, store.Global(), "real@victim.example", nil)

	got := findingsOf(parseEximLogLine(geoSendAt("real@victim.example", "192.0.2.9", time.Now()), cfg), "email_suspicious_geo")
	if len(got) != 1 || got[0].SourceIP != "192.0.2.9" || got[0].Mailbox != "real@victim.example" || got[0].TenantID != "cpuser" ||
		!strings.Contains(got[0].Message, "authenticated send from BR") {
		t.Fatalf("geo findings = %+v", got)
	}
	if again := findingsOf(parseEximLogLine(geoSendAt("real@victim.example", "192.0.2.9", time.Now()), cfg), "email_suspicious_geo"); len(again) != 0 {
		t.Fatalf("second send reported again: %+v", again)
	}
}
