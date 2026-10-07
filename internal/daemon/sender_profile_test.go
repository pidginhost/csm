package daemon

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/store"
)

var senderTestNow = time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

func resetSenderProfileState() { senderWindows = sync.Map{} }

// senderSendLine is an authenticated Exim arrival for user from ip to rcpts.
func senderSendLine(user, ip string, rcpts ...string) string {
	return "2026-01-10 12:00:00 1abc-0000-AB <= " + user +
		" H=(helo.example) [" + ip + "]:4000 P=esmtpsa X=TLS1.3:TLS_AES_256_GCM_SHA384:256" +
		" A=dovecot_login:" + user + ` S=1200 id=x@example.com T="Regular mail" for ` + strings.Join(rcpts, " ")
}

func stubGeo(t *testing.T, byIP map[string]string) {
	t.Helper()
	prev := geoLookup
	geoLookup = func(ip string) geoip.Info { return geoip.Info{Country: byIP[ip]} }
	t.Cleanup(func() { geoLookup = prev })
}

// seedSenderBaseline stores `days` prior active days for user, counting back
// from base, each shaped by shape(i) where i is the number of days back.
func seedSenderBaseline(t *testing.T, db *store.DB, base time.Time, user string, days int, shape func(i int) *store.SenderDay) {
	t.Helper()
	p := store.SenderProfile{Days: map[string]*store.SenderDay{}}
	for i := 1; i <= days; i++ {
		p.Days[base.UTC().AddDate(0, 0, -i).Format("2006-01-02")] = shape(i)
	}
	if err := db.SetSenderProfile(user, p); err != nil {
		t.Fatal(err)
	}
}

func compromiseFindings(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == "email_compromised_account" {
			out = append(out, f)
		}
	}
	return out
}

func sendAt(t *testing.T, cfg *config.Config, at time.Time, user, ip string, rcpts ...string) []alert.Finding {
	t.Helper()
	return compromiseFindings(parseSenderProfileFinding(senderSendLine(user, ip, rcpts...), cfg, at))
}

func manyRecipients(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("r%d@example.net", i)
	}
	return out
}

func TestSenderProfile_SteadySingleSourceStaysSilent(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, map[string]string{"203.0.113.5": "RO"})
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		for i := 0; i < 80; i++ {
			at := senderTestNow.Add(time.Duration(i) * time.Minute)
			if got := sendAt(t, cfg, at, "user@example.com", "203.0.113.5", fmt.Sprintf("r%d@example.net", i%10)); len(got) != 0 {
				t.Fatalf("send %d from one address: unexpected %+v", i, got)
			}
		}
	})
}

func TestSenderProfile_ThreeCountriesInAnHourIsCritical(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, map[string]string{"203.0.113.5": "LK", "198.51.100.7": "IN", "192.0.2.9": "NG"})
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		if got := sendAt(t, cfg, senderTestNow, "user@example.com", "203.0.113.5", "a@example.net"); len(got) != 0 {
			t.Fatalf("one country: unexpected %+v", got)
		}
		if got := sendAt(t, cfg, senderTestNow.Add(time.Minute), "user@example.com", "198.51.100.7", "b@example.net"); len(got) != 0 {
			t.Fatalf("two countries: unexpected %+v", got)
		}
		got := sendAt(t, cfg, senderTestNow.Add(2*time.Minute), "user@example.com", "192.0.2.9", "c@example.net")
		if len(got) != 1 || got[0].Severity != alert.Critical {
			t.Fatalf("three countries in an hour: want one Critical, got %+v", got)
		}
		f := got[0]
		if !strings.Contains(f.Message, "3 countries") {
			t.Errorf("message does not explain the countries: %q", f.Message)
		}
		if f.Mailbox != "user@example.com" || f.Domain != "example.com" {
			t.Errorf("mailbox=%q domain=%q", f.Mailbox, f.Domain)
		}
		if f.SourceIP != "" {
			t.Errorf("source IP %q would let the response block the owner's own address", f.SourceIP)
		}
	})
}

func TestSenderProfile_HourChurnFloor(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, nil)
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		for i := 1; i <= 3; i++ {
			if got := sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*time.Minute), "user@example.com", fmt.Sprintf("203.0.113.%d", i), "a@example.net"); len(got) != 0 {
				t.Fatalf("%d addresses in an hour: unexpected %+v", i, got)
			}
		}
		got := sendAt(t, cfg, senderTestNow.Add(4*time.Minute), "user@example.com", "203.0.113.4", "a@example.net")
		if len(got) != 1 || got[0].Severity != alert.High {
			t.Fatalf("four addresses in an hour: want High, got %+v", got)
		}
		if !strings.Contains(got[0].Message, "4 addresses") {
			t.Errorf("message does not explain the churn: %q", got[0].Message)
		}
	})
}

func TestSenderProfile_BaselineRaisesThresholds(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, nil)
	withGlobalStore(t, func(db *store.DB) {
		seedSenderBaseline(t, db, senderTestNow, "user@example.com", 5, func(int) *store.SenderDay {
			return &store.SenderDay{Sends: 20, IPs: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, MaxHourIPs: 3, Recipients: []string{"a@example.net"}}
		})
		cfg := cloudRelayTestConfig()
		for i := 1; i <= 6; i++ {
			if got := sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*time.Minute), "user@example.com", fmt.Sprintf("198.51.100.%d", i), "a@example.net"); len(got) != 0 {
				t.Fatalf("%d addresses within twice the mailbox's own churn must stay silent, got %+v", i, got)
			}
		}
		got := sendAt(t, cfg, senderTestNow.Add(7*time.Minute), "user@example.com", "198.51.100.7", "a@example.net")
		if len(got) != 1 || got[0].Severity != alert.High {
			t.Fatalf("seven addresses against a baseline of three: want High, got %+v", got)
		}
	})
}

func TestSenderProfile_ChurnFromNovelCountryIsCriticalAndSuspends(t *testing.T) {
	resetSenderProfileState()
	resetEmailRateState()
	stubGeo(t, map[string]string{"198.51.100.1": "DE", "198.51.100.2": "DE", "198.51.100.3": "DE", "198.51.100.4": "DE"})
	withUserdomains(t, "example.com: cpuser\n")
	calls := stubUAPI(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	captureActionRecords(t)
	withGlobalStore(t, func(db *store.DB) {
		seedSenderBaseline(t, db, time.Now(), "user@example.com", 5, func(int) *store.SenderDay {
			return &store.SenderDay{Sends: 3, IPs: []string{"203.0.113.5"}, MaxHourIPs: 1, Countries: []string{"RO"}, Recipients: []string{"a@example.net"}}
		})
		cfg := eximAutoHoldConfig()
		var got []alert.Finding
		for i := 1; i <= 4; i++ {
			got = compromiseFindings(parseEximLogLine(senderSendLine("user@example.com", fmt.Sprintf("198.51.100.%d", i), "a@example.net"), cfg))
			if i < 4 && len(got) != 0 {
				t.Fatalf("send %d: unexpected %+v", i, got)
			}
		}
		if len(got) != 1 || got[0].Severity != alert.Critical {
			t.Fatalf("churn from a country the mailbox never sent from: want Critical, got %+v", got)
		}
		if !strings.Contains(got[0].Message, "DE") {
			t.Errorf("message does not name the new country: %q", got[0].Message)
		}
		if len(*calls) != 2 || len(*holds) != 0 {
			t.Fatalf("a Critical compromise must suspend the mailbox itself: uapi=%v holds=%v", *calls, *holds)
		}
		if !hasRecentCompromisedFinding("example.com") {
			t.Fatal("domain must be marked compromised so rate alerts stay quiet")
		}
	})
}

func TestSenderProfile_DayChurnAcrossHours(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, nil)
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		var got []alert.Finding
		for i := 0; i < 6; i++ {
			got = sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*90*time.Minute), "user@example.com", fmt.Sprintf("203.0.113.%d", i+1), "a@example.net")
			if i < 5 && len(got) != 0 {
				t.Fatalf("%d addresses spread over the day: unexpected %+v", i+1, got)
			}
		}
		if len(got) != 1 || got[0].Severity != alert.High {
			t.Fatalf("six addresses in a day, one per send: want High, got %+v", got)
		}
	})
}

func TestSenderProfile_RecipientFanOut(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, nil)
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		if got := sendAt(t, cfg, senderTestNow, "list@example.com", "203.0.113.5", manyRecipients(50)...); len(got) != 0 {
			t.Fatalf("one message to fifty recipients is an announcement, got %+v", got)
		}
		var got []alert.Finding
		for i := 0; i < 50; i++ {
			got = sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*time.Minute), "user@example.com", "203.0.113.5", fmt.Sprintf("r%d@example.net", i))
			if i < 49 && len(got) != 0 {
				t.Fatalf("message %d: unexpected %+v", i+1, got)
			}
		}
		if len(got) != 1 || got[0].Severity != alert.High {
			t.Fatalf("fifty messages to fifty recipients: want High, got %+v", got)
		}
		if !strings.Contains(got[0].Message, "50 recipients") {
			t.Errorf("message does not explain the fan-out: %q", got[0].Message)
		}
	})
}

func TestSenderProfile_DedupThenEscalation(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, map[string]string{
		"203.0.113.1": "RO", "203.0.113.2": "RO", "203.0.113.3": "RO", "203.0.113.4": "RO", "203.0.113.5": "RO",
		"198.51.100.1": "LK", "198.51.100.2": "IN",
	})
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		var got []alert.Finding
		for i := 1; i <= 4; i++ {
			got = sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*time.Minute), "user@example.com", fmt.Sprintf("203.0.113.%d", i), "a@example.net")
		}
		if len(got) != 1 || got[0].Severity != alert.High {
			t.Fatalf("want High after four addresses, got %+v", got)
		}
		if got = sendAt(t, cfg, senderTestNow.Add(5*time.Minute), "user@example.com", "203.0.113.5", "a@example.net"); len(got) != 0 {
			t.Fatalf("a second High inside the cooldown must be suppressed, got %+v", got)
		}
		if got = sendAt(t, cfg, senderTestNow.Add(6*time.Minute), "user@example.com", "198.51.100.1", "a@example.net"); len(got) != 0 {
			t.Fatalf("two countries: unexpected %+v", got)
		}
		got = sendAt(t, cfg, senderTestNow.Add(7*time.Minute), "user@example.com", "198.51.100.2", "a@example.net")
		if len(got) != 1 || got[0].Severity != alert.Critical {
			t.Fatalf("escalation to Critical must pass the cooldown, got %+v", got)
		}
		if got = sendAt(t, cfg, senderTestNow.Add(8*time.Minute), "user@example.com", "198.51.100.2", "a@example.net"); len(got) != 0 {
			t.Fatalf("a repeat Critical inside the cooldown must be suppressed, got %+v", got)
		}
	})
}

func TestSenderProfile_HighVolumeSenderSkipped(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, map[string]string{"203.0.113.5": "LK", "198.51.100.7": "IN", "192.0.2.9": "NG"})
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		cfg.EmailProtection.HighVolumeSenders = []string{"Bulk@Example.com"}
		for i, ip := range []string{"203.0.113.5", "198.51.100.7", "192.0.2.9"} {
			if got := sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*time.Minute), "bulk@example.com", ip, "a@example.net"); len(got) != 0 {
				t.Fatalf("allowlisted sender produced %+v", got)
			}
		}
	})
}

func TestSenderProfile_DayCountsSurviveRestart(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, nil)
	withGlobalStore(t, func(_ *store.DB) {
		cfg := cloudRelayTestConfig()
		for i := 1; i <= 3; i++ {
			if got := sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*time.Minute), "user@example.com", fmt.Sprintf("203.0.113.%d", i), "a@example.net"); len(got) != 0 {
				t.Fatalf("send %d: unexpected %+v", i, got)
			}
		}
		// A daemon restart loses the in-memory hour window but not the day.
		resetSenderProfileState()
		var got []alert.Finding
		for i := 4; i <= 6; i++ {
			got = sendAt(t, cfg, senderTestNow.Add(time.Duration(10+i)*time.Minute), "user@example.com", fmt.Sprintf("203.0.113.%d", i), "a@example.net")
			if i < 6 && len(got) != 0 {
				t.Fatalf("send %d: unexpected %+v", i, got)
			}
		}
		if len(got) != 1 || got[0].Severity != alert.High {
			t.Fatalf("sixth address of the day after a restart: want High, got %+v", got)
		}
	})
}

func TestSenderProfile_TrustedCountryIsNeverNovel(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, map[string]string{"203.0.113.1": "RO", "203.0.113.2": "RO", "203.0.113.3": "RO", "203.0.113.4": "RO"})
	withGlobalStore(t, func(db *store.DB) {
		seedSenderBaseline(t, db, senderTestNow, "user@example.com", 5, func(int) *store.SenderDay {
			return &store.SenderDay{Sends: 3, IPs: []string{"198.51.100.5"}, MaxHourIPs: 1, Countries: []string{"DE"}, Recipients: []string{"a@example.net"}}
		})
		cfg := cloudRelayTestConfig()
		cfg.Suppressions.TrustedCountries = []string{"ro"}
		var got []alert.Finding
		for i := 1; i <= 4; i++ {
			got = sendAt(t, cfg, senderTestNow.Add(time.Duration(i)*time.Minute), "user@example.com", fmt.Sprintf("203.0.113.%d", i), "a@example.net")
		}
		if len(got) != 1 || got[0].Severity != alert.High {
			t.Fatalf("churn from a trusted country stays High, got %+v", got)
		}
	})
}

func TestSenderProfile_EvictsIdleWindows(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, nil)
	withGlobalStore(t, func(_ *store.DB) {
		sendAt(t, cloudRelayTestConfig(), senderTestNow, "user@example.com", "203.0.113.5", "a@example.net")
		if _, ok := senderWindows.Load("user@example.com"); !ok {
			t.Fatal("window missing after a send")
		}
		evictSenderWindows(senderTestNow.Add(90 * time.Minute))
		if _, ok := senderWindows.Load("user@example.com"); !ok {
			t.Fatal("window evicted while still inside the idle allowance")
		}
		evictSenderWindows(senderTestNow.Add(3 * time.Hour))
		if _, ok := senderWindows.Load("user@example.com"); ok {
			t.Fatal("idle window was not evicted")
		}
	})
}
