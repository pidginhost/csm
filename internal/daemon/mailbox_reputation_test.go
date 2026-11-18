package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func resetReputationState() {
	authSends.reset()
	reputationWindows.reset()
}

func authArrivalLine(id, login string) string {
	return "2026-11-18 10:00:00 " + id + " <= " + login +
		" H=(webmail.example) [::1]:4000 P=esmtpa A=dovecot_login:" + login + ` S=1200 id=x@victim.example T="Hello" for a@outlook.example`
}

func s775Line(id, outbound string) string {
	return "2026-11-18 10:05:00 " + id + " == a@outlook.example R=dkim_lookuphost T=remote_smtp defer (-45) H=victim-example.mail.protection.outlook.com [203.0.113.42]: SMTP error from remote mail server after pipelined MAIL FROM:<x@victim.example> SIZE=1234: 451 4.7.650 The mail server [" + outbound + "] has been temporarily rate limited due to IP reputation. For e-mail delivery information, see https://aka.ms/postmaster (S775)"
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
