package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/maillog"
)

// A login read from a mail log file may be a line any local user wrote: it
// alerts as before, but it earns no customer standing, no good source and
// no spray trust. The same logins from the journal, written by the mail
// services, earn all three.
func TestWritableMailSuccessIsNotALogin(t *testing.T) {
	const dovecotIP, postfixIP = "203.0.113.150", "203.0.113.141"
	lines := []struct{ unit, ident, text string }{
		{"dovecot.service", "dovecot", "imap-login: Login: user=<alice@example.net>, method=PLAIN, rip=" + dovecotIP + ", lip=198.51.100.7"},
		{"postfix.service", "postfix/smtpd", "4F2B91A0123: client=mx.example.net[" + postfixIP + "], sasl_method=PLAIN, sasl_username=bob@example.net"},
	}
	for _, journal := range []bool{false, true} {
		cfg := sprayTestConfig("off")
		cfg.MailLogs.Units = []string{"postfix", "dovecot"}
		d, clock := newPairingDaemon(t, cfg)
		d.smtpAuthTracker.SetKnownCustomers(d.knownCustomers)
		d.mailAuthTracker.SetKnownCustomers(d.knownCustomers)
		for i, l := range lines {
			clock.advance(time.Second)
			at := clock.Now()
			line := maillog.Line{Source: "file", Message: at.Format(time.Stamp) + " mail " + l.ident + "[7]: " + l.text,
				Position: maillog.Position{Stream: "m:1:2", Cursor: string(rune('a' + i)), ObservedAt: at}}
			if journal {
				line = maillog.JournalLine(map[string]string{"MESSAGE": l.text, "SYSLOG_IDENTIFIER": l.ident, "_PID": "7",
					"_SYSTEMD_UNIT": l.unit, "_UID": "0", "_TRANSPORT": "syslog"},
					maillog.Position{Stream: "journal", Cursor: string(rune('a' + i)), ObservedAt: at})
			}
			if !d.dispatchMailLogLine(line, d.handleMailLine) {
				t.Fatal("mail dispatch stopped")
			}
		}
		_, customer := d.knownCustomers.Lookup(dovecotIP)
		_, smtpCustomer := d.knownCustomers.Lookup(postfixIP)
		good := false
		d.mailAuthTracker.mu.Lock()
		if e := d.mailAuthTracker.ips[dovecotIP]; e != nil {
			good = len(e.goodFirst) > 0
		}
		d.mailAuthTracker.mu.Unlock()
		sprayTrust := smtpSuccessIPs(d)[postfixIP]
		if customer != journal || smtpCustomer != journal || good != journal || sprayTrust != journal {
			t.Errorf("journal=%v: known customer %v/%v, good source %v, spray trust %v; want all %v",
				journal, customer, smtpCustomer, good, sprayTrust, journal)
		}
	}
}

// trustedMailObs stamps a mail line as the journal entry a mail service
// wrote, for tests about parsing and tracking rather than log trust.
var trustedMailObs = alert.Observation{Producer: string(checks.ProducerMailJournal)}
