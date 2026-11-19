package daemon

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

func resetBulkRecipientState() { bulkRecipientWindows = sync.Map{} }

func recipientList(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d@victims.example", prefix, i)
	}
	return out
}

// One authenticated message to a hundred recipients was invisible: the
// fan-out rule counts only individually addressed mail and the rate rule
// counts messages.
func TestBulkMessageIsEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetBulkRecipientState()
	cfg := eximAutoHoldConfig()

	got := findingsOf(parseEximLogLine(senderSendLine("real@victim.example", "203.0.113.5", recipientList("a", 100)...), cfg), "email_bulk_recipients")
	if len(got) != 1 || !strings.Contains(got[0].Message, "100 recipients") || got[0].Mailbox != "real@victim.example" || got[0].TenantID != "cpuser" {
		t.Fatalf("bulk findings = %+v", got)
	}
	if !checks.IsSummaryNotice(got[0]) {
		t.Fatalf("email_bulk_recipients must be summary class")
	}
	if again := findingsOf(parseEximLogLine(senderSendLine("real@victim.example", "203.0.113.5", recipientList("b", 100)...), cfg), "email_bulk_recipients"); len(again) != 0 {
		t.Fatalf("second bulk message reported again: %+v", again)
	}
	s, ok := ledgerSignal(t, db, "real@victim.example", signalBulkRecipients, "")
	if !ok || s.Count != 2 {
		t.Fatalf("bulk evidence = %+v (found %v), want both messages", s, ok)
	}
}

func TestSmallMessagesAreNotBulk(t *testing.T) {
	db, _ := evidenceCase(t)
	resetSenderProfileState()
	resetBulkRecipientState()
	parseEximLogLine(senderSendLine("real@victim.example", "203.0.113.5", recipientList("a", bulkRecipientsPerMessage-1)...), eximAutoHoldConfig())
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalBulkRecipients, ""); ok {
		t.Fatalf("49 recipients counted as bulk: %+v", s)
	}
}

func TestRecipientsPerHourIsEvidence(t *testing.T) {
	_, _ = evidenceCase(t)
	resetBulkRecipientState()
	cfg := eximAutoHoldConfig()
	at := time.Now()
	per := 40
	for i := range bulkRecipientsPerHour/per - 1 {
		if got := observeBulkRecipients(cfg, "real@victim.example", recipientList(fmt.Sprint(i), per), at.Add(time.Duration(i)*time.Minute)); len(got) != 0 {
			t.Fatalf("message %d: %d recipients reported %+v", i+1, (i+1)*per, got)
		}
	}
	got := observeBulkRecipients(cfg, "real@victim.example", recipientList("last", per), at.Add(10*time.Minute))
	if len(got) != 1 || !strings.Contains(got[0].Message, "200 recipients within an hour") {
		t.Fatalf("200 recipients in an hour: %+v", got)
	}
}

func TestRecipientsPerHourSlides(t *testing.T) {
	db, _ := evidenceCase(t)
	resetBulkRecipientState()
	cfg := eximAutoHoldConfig()
	at := time.Now()
	for i := range 10 {
		observeBulkRecipients(cfg, "real@victim.example", recipientList(fmt.Sprint(i), 30), at.Add(time.Duration(i)*15*time.Minute))
	}
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalBulkRecipients, ""); ok {
		t.Fatalf("120 recipients an hour counted as bulk: %+v", s)
	}
}

// The volume exemption covers fan-out: a known mailing mailbox is not bulk.
func TestHighVolumeSenderIsNotBulk(t *testing.T) {
	db, _ := evidenceCase(t)
	resetBulkRecipientState()
	cfg := eximAutoHoldConfig()
	cfg.EmailProtection.HighVolumeSenders = []string{"real@victim.example"}
	observeBulkRecipients(cfg, "real@victim.example", recipientList("a", 100), time.Now())
	if s, ok := ledgerSignal(t, db, "real@victim.example", signalBulkRecipients, ""); ok {
		t.Fatalf("exempt sender counted as bulk: %+v", s)
	}
}

func TestBulkHourSharesMailboxCase(t *testing.T) {
	_, _ = evidenceCase(t)
	resetBulkRecipientState()
	at := time.Now()
	for i := range 5 {
		user := []string{"real@victim.example", "Real@Victim.example"}[i%2]
		got := observeBulkRecipients(dryRunConfig(), user, recipientList("r", 40), at)
		if (len(got) == 1) != (i == 4) {
			t.Fatalf("send %d: findings = %+v", i, got)
		}
	}
}

func TestBulkAndForgedSendHonorRecordedTime(t *testing.T) {
	db, _ := evidenceCase(t)
	withDomainOwners(t, map[string]string{"victim.example": "owner"})
	resetBulkRecipientState()
	line := sendAsLine("user@victim.example", "info@outside.example", "192.0.2.1")
	line = time.Now().Add(-2*mailboxEvidenceTTL).Format(time.DateTime) + line[len(time.DateTime):] + " " + strings.Join(recipientList("r", 60), " ")
	parseEximLogLine(line, dryRunConfig())
	e, err := db.GetMailboxEvidence("user@victim.example")
	if err != nil || len(e.Signals) != 0 {
		t.Fatalf("expired mail recorded %+v, %v", e, err)
	}
}

func TestBulkHourIncludesOutOfOrderSends(t *testing.T) {
	db, _ := evidenceCase(t)
	resetBulkRecipientState()
	cfg := dryRunConfig()
	at := time.Now().Add(-time.Minute)
	const mailbox = "real@victim.example"
	for i := range 5 {
		got := observeBulkRecipients(cfg, mailbox, recipientList("r", 40), at.Add(-time.Duration(i)*time.Minute))
		if (len(got) == 1) != (i == 4) {
			t.Fatalf("send %d: findings = %+v", i, got)
		}
	}
	s, ok := ledgerSignal(t, db, mailbox, signalBulkRecipients, "")
	if !ok || !s.Last.Equal(at) {
		t.Fatalf("bulk evidence time = %v, want %v", s.Last, at)
	}
}

func TestBulkWindowHonorsMailboxRelease(t *testing.T) {
	db, _ := evidenceCase(t)
	resetBulkRecipientState()
	cfg := dryRunConfig()
	const mailbox = "real@victim.example"
	before := time.Now().Add(-time.Minute)
	for range 4 {
		observeBulkRecipients(cfg, mailbox, recipientList("r", 40), before)
	}
	row := store.MailboxSuspension{ID: store.MailboxSuspensionID(activeMailBackend.name(), mailbox), Backend: activeMailBackend.name(), Subject: mailbox}
	if err := db.PutMailboxSuspension(row); err != nil {
		t.Fatal(err)
	}
	if _, err := finishMailboxRelease(db, row, "operator"); err != nil {
		t.Fatal(err)
	}
	for _, restart := range []bool{false, true} {
		if restart {
			resetBulkRecipientState()
		}
		for range 4 {
			observeBulkRecipients(cfg, mailbox, recipientList("r", 40), before)
		}
		got := observeBulkRecipients(cfg, mailbox, recipientList("r", 40), time.Now())
		if len(got) != 0 {
			t.Fatalf("pre-release recipients counted after release (restart=%t): %+v", restart, got)
		}
		if s, ok := ledgerSignal(t, db, mailbox, signalBulkRecipients, ""); ok {
			t.Fatalf("pre-release recipients left evidence: %+v", s)
		}
	}
}
