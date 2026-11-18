package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

// sendAsLine is an authenticated Exim arrival by login with envelope sender
// from.
func sendAsLine(login, from, ip string) string {
	return "2026-01-10 12:00:00 1abc-0000-AB <= " + from +
		" H=(helo.example) [" + ip + "]:4000 P=esmtpsa X=TLS1.3:TLS_AES_256_GCM_SHA384:256" +
		" A=dovecot_plain:" + login + ` S=1200 id=x@example.com T="Invoice" for a@friend.example`
}

func withDomainOwners(t *testing.T, owners map[string]string) {
	t.Helper()
	t.Cleanup(checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
		owner, ok := owners[strings.ToLower(domain)]
		return owner, ok
	}))
}

// A thief sent as an unrelated domain from the stolen mailbox; nothing
// compared the login with the sender.
func TestForgedSenderIsEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetBulkRecipientState()
	withDomainOwners(t, map[string]string{"victim.example": "cpuser", "neighbour.example": "otheruser"})

	for _, from := range []string{"billing@unrelated.example", "ceo@neighbour.example"} {
		got := findingsOf(parseEximLogLine(sendAsLine("real@victim.example", from, "203.0.113.5"), eximAutoHoldConfig()), "email_forged_sender")
		domain := from[strings.IndexByte(from, '@')+1:]
		if len(got) != 1 || !strings.Contains(got[0].Message, from) || got[0].Mailbox != "real@victim.example" || got[0].TenantID != "cpuser" {
			t.Fatalf("send as %s: findings = %+v", from, got)
		}
		if !checks.IsSummaryNotice(got[0]) {
			t.Fatalf("email_forged_sender must be summary class")
		}
		if _, ok := ledgerSignal(t, db, "real@victim.example", signalForgedSender, domain); !ok {
			t.Fatalf("send as %s left no evidence", from)
		}
	}
}

func TestOwnSendersAreNotForged(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetBulkRecipientState()
	withDomainOwners(t, map[string]string{"victim.example": "cpuser", "alias.example": "cpuser"})

	for name, line := range map[string]string{
		"own address":        sendAsLine("real@victim.example", "real@victim.example", "203.0.113.5"),
		"other mailbox":      sendAsLine("real@victim.example", "sales@Victim.Example", "203.0.113.5"),
		"same-account alias": sendAsLine("real@victim.example", "info@alias.example", "203.0.113.5"),
		"subdomain":          sendAsLine("real@victim.example", "bounce@news.victim.example", "203.0.113.5"),
		"bounce":             sendAsLine("real@victim.example", "<>", "203.0.113.5"),
		"cPanel user login":  sendAsLine("cpuser", "info@alias.example", "203.0.113.5"),
	} {
		if got := findingsOf(parseEximLogLine(line, eximAutoHoldConfig()), "email_forged_sender"); len(got) != 0 {
			t.Errorf("%s: reported %+v", name, got)
		}
	}
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalForgedSender, ""); ok {
		t.Fatalf("evidence recorded: %+v", s)
	}
}

// Without an owner for the login's own domain there is nothing to compare.
func TestForgedSenderNeedsKnownLoginOwner(t *testing.T) {
	_, _ = evidenceCase(t)
	resetBulkRecipientState()
	withDomainOwners(t, map[string]string{})
	if got := findingsOf(parseEximLogLine(sendAsLine("real@victim.example", "x@unrelated.example", "203.0.113.5"), eximAutoHoldConfig()), "email_forged_sender"); len(got) != 0 {
		t.Fatalf("reported %+v", got)
	}
}

func TestHighVolumeSenderIsNotForged(t *testing.T) {
	_, _ = evidenceCase(t)
	resetBulkRecipientState()
	withDomainOwners(t, map[string]string{"victim.example": "cpuser"})
	cfg := eximAutoHoldConfig()
	cfg.EmailProtection.HighVolumeSenders = []string{"real@victim.example"}
	if got := findingsOf(parseEximLogLine(sendAsLine("real@victim.example", "x@unrelated.example", "203.0.113.5"), cfg), "email_forged_sender"); len(got) != 0 {
		t.Fatalf("exempt sender reported %+v", got)
	}
}

// A thief rotating sender domains gets a bounded number of reports.
func TestRotatingForgedDomainsReportBounded(t *testing.T) {
	_, _ = evidenceCase(t)
	resetBulkRecipientState()
	withDomainOwners(t, map[string]string{"victim.example": "cpuser"})
	reports := 0
	for i := range 3 * mailboxSignalKeysPerKind {
		line := sendAsLine("real@victim.example", fmt.Sprintf("x@d%d.example", i), "203.0.113.5")
		reports += len(findingsOf(parseEximLogLine(line, dryRunConfig()), "email_forged_sender"))
	}
	if reports != mailboxSignalKeysPerKind {
		t.Fatalf("reports = %d, want %d", reports, mailboxSignalKeysPerKind)
	}
}
