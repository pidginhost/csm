package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

func resetReputationState() {
	authSends.reset()
	reputationWindows.reset()
}

func authArrivalLine(id, login string) string {
	return time.Now().Format(time.DateTime) + " " + id + " <= " + login +
		" H=(webmail.example) [::1]:4000 P=esmtpa A=dovecot_login:" + login + ` S=1200 id=x@victim.example T="Hello" for a@outlook.example`
}

func s775Line(id, outbound string) string {
	return time.Now().Format(time.DateTime) + " " + id + " == a@outlook.example R=dkim_lookuphost T=remote_smtp defer (-45) H=mx.outlook.example [203.0.113.42]: SMTP error from remote mail server after pipelined MAIL FROM:<x@victim.example> SIZE=1234: 451 4.7.650 The mail server [" + outbound + "] has been temporarily rate limited due to IP reputation. For e-mail delivery information, see https://postmaster.example/help (S775)"
}

func msgID(n int) string { return fmt.Sprintf("1uX%03d-000AAA-1A", n) }

// Microsoft deferred everything from the domain's address for days and CSM
// said nothing: the deferral report only fed the web UI.
func TestReputationDeferralsAreEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetBulkRecipientState()
	resetReputationState()
	cfg := eximAutoHoldConfig()

	for i := range 30 {
		login := "real@victim.example"
		if i%5 == 0 {
			login = "other@victim.example"
		}
		parseEximLogLine(authArrivalLine(msgID(i), login), cfg)
	}
	for i := range reputationDeferralsPerHour - 1 {
		if got := findingsOf(parseEximLogLine(s775Line(msgID(i), "198.51.100.20"), cfg), "email_outbound_reputation"); len(got) != 0 {
			t.Fatalf("deferral %d reported %+v", i+1, got)
		}
	}
	got := findingsOf(parseEximLogLine(s775Line(msgID(reputationDeferralsPerHour), "198.51.100.20"), cfg), "email_outbound_reputation")
	if len(got) != 1 || !strings.Contains(got[0].Message, "198.51.100.20") || !strings.Contains(got[0].Message, "real@victim.example") {
		t.Fatalf("reputation findings = %+v", got)
	}
	if !checks.IsSummaryNotice(got[0]) {
		t.Fatalf("email_outbound_reputation must be summary class")
	}
	if _, ok := ledgerSignal(t, db, "real@victim.example", signalReputation, "198.51.100.20"); !ok {
		t.Fatal("top sender has no reputation evidence")
	}
	if s, ok := ledgerSignal(t, db, "other@victim.example", signalReputation, "198.51.100.20"); ok {
		t.Fatalf("a smaller sender got evidence: %+v", s)
	}

	// One report per address a day.
	for i := range reputationDeferralsPerHour {
		if again := findingsOf(parseEximLogLine(s775Line(msgID(i), "198.51.100.20"), cfg), "email_outbound_reputation"); len(again) != 0 {
			t.Fatalf("reported again: %+v", again)
		}
	}
}

func TestOtherDeferralsAreNotReputation(t *testing.T) {
	db, _ := evidenceCase(t)
	resetReputationState()
	cfg := eximAutoHoldConfig()
	parseEximLogLine(authArrivalLine(msgID(1), "real@victim.example"), cfg)
	greylist := "2026-11-18 10:05:00 " + msgID(1) + " == a@outlook.example R=dkim_lookuphost T=remote_smtp defer (-45) H=mx.outlook.example [203.0.113.42]: SMTP error from remote mail server after RCPT TO: 451 4.7.1 Greylisted by [198.51.100.20], try again later"
	for range 2 * reputationDeferralsPerHour {
		if got := findingsOf(parseEximLogLine(greylist, cfg), "email_outbound_reputation"); len(got) != 0 {
			t.Fatalf("greylisting reported %+v", got)
		}
	}
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalReputation, "198.51.100.20"); ok {
		t.Fatalf("evidence recorded: %+v", s)
	}
}

// Unattributed deferrals still count toward the address; only a known
// sender gets evidence.
func TestReputationWithoutKnownSenderReportsAddressOnly(t *testing.T) {
	_, _ = evidenceCase(t)
	resetReputationState()
	cfg := eximAutoHoldConfig()
	var got int
	for i := range reputationDeferralsPerHour {
		got += len(findingsOf(parseEximLogLine(s775Line(msgID(i), "198.51.100.20"), cfg), "email_outbound_reputation"))
	}
	if got != 1 {
		t.Fatalf("reports = %d, want 1", got)
	}
}

func TestAuthSendsMapIsBounded(t *testing.T) {
	resetReputationState()
	for i := range authSendsMax + 10 {
		authSends.note(fmt.Sprintf("id-%d", i), "real@victim.example")
	}
	if n := authSends.len(); n != authSendsMax {
		t.Fatalf("entries = %d, want %d", n, authSendsMax)
	}
	if _, ok := authSends.sender("id-0"); ok {
		t.Fatal("oldest entry not evicted")
	}
}

func TestReputationHourUsesRefusalTime(t *testing.T) {
	evidenceCase(t)
	resetReputationState()
	at := time.Now().Add(-3 * time.Hour)
	for i := range reputationDeferralsPerHour {
		line := s775Line(msgID(i), "192.0.2.17")
		line = at.Add(time.Duration(i)*8*time.Minute).Format(time.DateTime) + line[len(time.DateTime):]
		if got := parseEximLogLine(line, dryRunConfig()); len(findingsOf(got, "email_outbound_reputation")) != 0 {
			t.Fatalf("unrelated hours combined: %+v", got)
		}
	}
}

func TestAuthSendsDuplicateIDSurvivesEviction(t *testing.T) {
	var sends authSendMap
	sends.note("duplicate", "real@victim.example")
	sends.note("duplicate", "real@victim.example")
	for i := range authSendsMax - 1 {
		sends.note(msgID(i), "other@victim.example")
	}
	if _, ok := sends.sender("duplicate"); !ok {
		t.Fatal("replaying an arrival shortened its attribution window")
	}
}

func TestReputationDailyClaimExpires(t *testing.T) {
	db, _ := evidenceCase(t)
	at := time.Now().UTC()
	claim := func(ip string, at time.Time) bool {
		ok, err := db.ClaimReputationReport(ip, at.Format(time.DateOnly))
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !claim("192.0.2.20", at) || claim("192.0.2.20", at) {
		t.Fatal("daily claim was not unique")
	}
	if !claim("192.0.2.21", at.AddDate(0, 0, 1)) {
		t.Fatal("could not claim next day")
	}
	if got := db.GetMetaString("email:reputation_report:192.0.2.20"); got != "" {
		t.Fatalf("expired address retained: %q", got)
	}
}

func TestReputationTieHasNoMailbox(t *testing.T) {
	db, _ := evidenceCase(t)
	resetReputationState()
	cfg := dryRunConfig()
	for i := range reputationDeferralsPerHour {
		user := []string{"one@victim.example", "two@victim.example"}[i%2]
		authSends.note(msgID(i), user)
		got := findingsOf(parseEximLogLine(s775Line(msgID(i), "192.0.2.20"), cfg), "email_outbound_reputation")
		if i == reputationDeferralsPerHour-1 && (len(got) != 1 || got[0].Mailbox != "" || got[0].SourceIP != "") {
			t.Fatalf("ambiguous reputation attribution: %+v", got)
		}
	}
	for _, user := range []string{"one@victim.example", "two@victim.example"} {
		if _, ok := ledgerSignal(t, db, user, signalReputation, "192.0.2.20"); ok {
			t.Fatalf("ambiguous evidence for %s", user)
		}
	}
}

func TestReputationDailySummaryKeepsLaterSenderEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	resetReputationState()
	cfg := dryRunConfig()
	at := time.Now().UTC().Truncate(24 * time.Hour).Add(-12 * time.Hour)
	for i, user := range []string{"one@victim.example", "two@victim.example", "three@victim.example"} {
		now := at.Add(time.Duration(2*i) * time.Hour)
		if i == 2 {
			resetReputationState()
		}
		reports := 0
		for j := range reputationDeferralsPerHour {
			id := msgID(i*reputationDeferralsPerHour + j)
			authSends.note(id, user)
			line := s775Line(id, "192.0.2.20")
			line = now.Format(time.DateTime+" -0700") + line[len(time.DateTime):]
			reports += len(findingsOf(observeReputationOutcome(cfg, line, now), "email_outbound_reputation"))
		}
		want := 0
		if i == 0 {
			want = 1
		}
		if reports != want {
			t.Fatalf("hour %d: %d reports, want %d", i, reports, want)
		}
		if s, ok := ledgerSignal(t, db, user, signalReputation, "192.0.2.20"); !ok || !s.Last.Equal(now) {
			t.Fatalf("hour %d: top sender %s evidence %+v", i, user, s)
		}
	}
}

func TestReputationIncompleteWindowDoesNotAssignMailbox(t *testing.T) {
	db, _ := evidenceCase(t)
	resetReputationState()
	now := time.Now().UTC().Truncate(time.Second)
	const ip = "192.0.2.17"
	user := "real@victim.example"
	// The first event in the retained slice will be displaced while it
	// still belongs to this hour. The omitted senders are no longer known.
	events := make([]reputationEvent, reputationEventsMax)
	for i := range events {
		events[i] = reputationEvent{at: now.Add(-time.Minute), login: []string{"other@victim.example", user}[i%2]}
	}
	reputationWindows.byIP = map[string]*reputationAddress{ip: {events: events, latest: now.Add(-time.Minute)}}
	line := s775Line(msgID(1), ip)
	line = now.Format(time.DateTime+" -0700") + line[len(time.DateTime):]
	got := findingsOf(observeReputationOutcome(dryRunConfig(), line, now), "email_outbound_reputation")
	if len(got) != 1 || got[0].Mailbox != "" || !strings.Contains(got[0].Message, "at least") {
		t.Fatalf("incomplete window: %+v", got)
	}
	if _, ok := ledgerSignal(t, db, user, signalReputation, ip); ok {
		t.Fatal("incomplete counts attributed a mailbox")
	}
}
