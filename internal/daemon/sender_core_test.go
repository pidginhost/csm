package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// A local submission (a site sending through a loopback listener) counts
// toward volume and recipients only: no address, no country.
func TestSenderProfileObserveLocalSubmissionCountsVolumeOnly(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, map[string]string{"": "RO"})
	cfg := &config.Config{}
	for i := 0; i < 2; i++ {
		senderProfileObserve(cfg, "user@example.com", "", []string{"a@example.org", "b@example.net"}, senderTestNow)
	}
	v, ok := senderWindows.Load("user@example.com")
	if !ok {
		t.Fatal("no sender window recorded")
	}
	w := v.(*senderWindow)
	w.mu.Lock()
	defer w.mu.Unlock()
	day := w.profile.Days[senderDayKey(senderTestNow)]
	if day == nil || day.Sends != 2 || len(day.IPs) != 0 || len(day.Countries) != 0 || len(day.Recipients) != 2 {
		t.Fatalf("day = %+v, want 2 sends, 2 recipients, no address or country", day)
	}
	if len(w.events) != 0 || len(w.countries) != 0 {
		t.Fatalf("rolling hour gained sources: events=%v countries=%v", w.events, w.countries)
	}
}

func TestSenderProfileLocalSendExpiresSources(t *testing.T) {
	resetSenderProfileState()
	stubGeo(t, map[string]string{"203.0.113.10": "DE", "203.0.113.11": "FR", "203.0.113.12": "BR"})
	cfg := &config.Config{}
	for _, ip := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12"} {
		senderProfileObserve(cfg, "user@example.com", ip, []string{"a@example.org"}, senderTestNow)
	}
	now := senderTestNow.Add(senderHourWindow + senderDedupCooldown)
	if got := senderProfileObserve(cfg, "user@example.com", "", []string{"a@example.org"}, now); len(got) != 0 {
		t.Fatalf("local send raised a finding from expired sources: %+v", got)
	}
	v, ok := senderWindows.Load("user@example.com")
	if !ok {
		t.Fatal("missing sender profile")
	}
	w := v.(*senderWindow)
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.events) != 0 || len(w.countries) != 0 {
		t.Fatalf("expired sources remain: events=%v countries=%v", w.events, w.countries)
	}
}

func TestCloudRelayObserveNeedsCloudPTR(t *testing.T) {
	resetCloudRelayState()
	cfg := &config.Config{}
	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.5"} {
		if got := cloudRelayObserve(cfg, "user@example.com", ip, "mail.example.net", senderTestNow); len(got) != 0 {
			t.Fatalf("a non-cloud PTR raised %+v", got)
		}
	}
	resetCloudRelayState()
	var got []alert.Finding
	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.5"} {
		got = cloudRelayObserve(cfg, "user@example.com", ip, "ec2-203-0-113-5.compute.amazonaws.com", senderTestNow)
	}
	if len(got) != 1 || got[0].Check != "email_cloud_relay_abuse" || got[0].SourceIP != "203.0.113.5" {
		t.Fatalf("findings = %+v, want one cloud-relay finding", got)
	}
	if got := cloudRelayObserve(cfg, "other@example.com", "", "ec2-203-0-113-5.compute.amazonaws.com", senderTestNow); len(got) != 0 {
		t.Fatalf("an empty address counted: %+v", got)
	}
}

// Without a mail backend CSM cannot suspend: it records the domain for rate
// correlation and leaves the mailbox alone.
func TestRespondToMailboxCompromiseWithoutBackendRecordsDomainOnly(t *testing.T) {
	resetEmailRateState()
	withMailBackendHost(t, false)
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	holds := stubAccountHold(t, true)
	captureActionRecords(t)
	withGlobalStore(t, func(db *store.DB) {
		respondToMailboxCompromise(eximAutoHoldConfig(), "user@example.com", "email_compromised_account", "test", senderTestNow)
		if len(*calls) != 0 || len(*holds) != 0 {
			t.Fatalf("suspension attempted without a backend: uapi=%v holds=%v", *calls, *holds)
		}
		rows, err := db.ListMailboxSuspensions()
		if err != nil || len(rows) != 0 {
			t.Fatalf("suspension rows = %+v, %v; want none", rows, err)
		}
	})
	if !hasRecentCompromisedFinding("example.com") {
		t.Fatal("the domain must still be marked for rate correlation")
	}
}
