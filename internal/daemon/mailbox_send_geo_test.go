package daemon

import (
	"slices"
	"strings"
	"testing"
	"time"

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
	for _, loopback := range []string{"::1", "127.0.0.1"} {
		t.Run(loopback, func(t *testing.T) {
			db, _ := evidenceCase(t)
			resetSenderProfileState()
			at := time.Now()
			homeHistory(t, db, "real@victim.example", &store.WebmailLogin{IP: "198.51.100.7", Country: "DE", At: at.Add(-90 * time.Minute)})

			parseSenderProfileFinding(senderSendLine("real@victim.example", loopback, "a@friend.example"), eximAutoHoldConfig(), at)
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

	parseSenderProfileFinding(senderSendLine("real@victim.example", "::1", "a@friend.example"), eximAutoHoldConfig(), at)
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

	d.cpanelSessionLogHandler(sessionNewLine("webmaild", "198.51.100.7", "real@victim.example"), cfg)
	parseEximLogLine(senderSendLine("real@victim.example", "::1", "a@friend.example"), cfg)

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

	parseEximLogLine(senderSendLine("real@victim.example", "203.0.113.5", "a@friend.example"), cfg)
	if _, ok := ledgerSignal(t, db, "real@victim.example", signalNewCountry, "RO"); ok {
		t.Fatal("a send from the home country counted as new")
	}
	parseEximLogLine(senderSendLine("real@victim.example", "192.0.2.9", "a@friend.example"), cfg)
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
	parseEximLogLine(senderSendLine("real@victim.example", "192.0.2.9", "a@friend.example"), eximAutoHoldConfig())
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalNewCountry, "BR"); ok {
		t.Fatalf("unlearned mailbox reported %+v", s)
	}
}
