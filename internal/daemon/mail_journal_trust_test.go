package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
)

// A journal line reaches the mail parsers only when a mail service wrote it:
// journald's own unit and uid, not the program name in the message.
func TestMailJournalDropsLinesNoServiceWrote(t *testing.T) {
	cfg := &config.Config{}
	cfg.MailLogs.Units = []string{"postfix", "dovecot"}
	d, _ := newPairingDaemon(t, cfg)
	var producers []string
	handler := func(_ string, obs alert.Observation, _ *config.Config) []alert.Finding {
		producers = append(producers, obs.Producer)
		return nil
	}
	pos := maillog.Position{Stream: "journal", Cursor: "s=1"}
	msg := "2026-11-21T10:00:00Z dovecot[7]: imap-login: Login: user=<a@example.test>, rip=198.51.100.7"
	for _, line := range []maillog.Line{
		{Source: "journal", Unit: "", UID: "0", Transport: "syslog", Message: msg, Position: pos},
		{Source: "journal", Unit: "dovecot.service", UID: "1000", Transport: "syslog", Message: msg, Position: pos},
		{Source: "journal", Unit: "dovecot.service", Transport: "syslog", Message: msg, Position: pos},
		{Source: "journal", Unit: "dovecot.service", UID: "0", Transport: "stdout", Message: msg, Position: pos},
	} {
		if !d.dispatchMailLogLine(line, handler) {
			t.Fatal("a dropped line stopped delivery")
		}
	}
	if len(producers) != 0 {
		t.Fatalf("lines no mail service wrote reached the parsers as %v", producers)
	}
	d.dispatchMailLogLine(maillog.Line{Source: "journal", Unit: "dovecot.service", UID: "0", Transport: "syslog", Message: msg, Position: pos}, handler)
	d.dispatchMailLogLine(maillog.Line{Source: "file", Message: msg, Position: maillog.Position{Stream: "m:1:2", Cursor: "1"}}, handler)
	if len(producers) != 2 || producers[0] != string(checks.ProducerMailJournal) || producers[1] != string(checks.ProducerMailLog) {
		t.Fatalf("producers %v, want the service's journal line as mail_journal and the file line as mail_log", producers)
	}
}
