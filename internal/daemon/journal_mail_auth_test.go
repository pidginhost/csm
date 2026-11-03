package daemon

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/maillog"
)

type mailLogEntry struct {
	at                     time.Time
	unit, ident, pid, text string
}

// mailAuthSequence is one host's mail log: Postfix SMTP AUTH guesses paired
// with Dovecot rejections, an authenticated Postfix client, IMAP guesses, and
// a rejection logged too long before its Postfix failure to pair with it.
func mailAuthSequence() []mailLogEntry {
	at := time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)
	var out []mailLogEntry
	add := func(gap time.Duration, unit, ident, pid, text string) {
		at = at.Add(gap)
		out = append(out, mailLogEntry{at, unit, ident, pid, text})
	}
	for i := 0; i < 5; i++ {
		add(time.Second, "dovecot.service", "dovecot", "812", "auth: sql(alice@example.net,203.0.113.140): Password mismatch")
		add(2*time.Second, "postfix.service", "postfix/submission/smtpd", "2245421", "warning: unknown[203.0.113.140]: SASL LOGIN authentication failed: UGFzc3dvcmQ6")
	}
	add(time.Second, "postfix.service", "postfix/smtpd", "1234", "4F2B91A0123: client=mx.example.net[203.0.113.141], sasl_method=PLAIN, sasl_username=bob@example.net")
	for i := 0; i < 5; i++ {
		add(time.Second, "dovecot.service", "dovecot", "812", "imap-login: Login aborted: Logged out (auth failed, 1 attempts in 2 secs): user=<carol@example.net>, method=PLAIN, rip=203.0.113.142, lip=192.0.2.1, session=<abc>")
	}
	add(time.Second, "dovecot.service", "dovecot", "812", "auth: sql(dave@example.net,203.0.113.143): unknown user")
	add(45*time.Second, "postfix.service", "postfix/smtpd", "1235", "warning: unknown[203.0.113.143]: SASL PLAIN authentication failed: ")
	return out
}

type mailAuthResult struct {
	smtpFailures, mailFailures int64
	successes                  []string
	findings                   []string
}

// replayMailLog feeds each line through the mail log dispatcher one second
// of receipt time apart, as a reader that fell behind would deliver them.
func replayMailLog(t *testing.T, lines []maillog.Line) mailAuthResult {
	t.Helper()
	// Spray memory on, its rules off: logins earn trust, findings stay as
	// the per-IP detectors make them.
	d, clock := newPairingDaemon(t, sprayTestConfig("off"))
	var res mailAuthResult
	for _, line := range lines {
		clock.advance(time.Second)
		if !d.dispatchMailLogLine(line, d.handleMailLine) {
			t.Fatal("mail dispatch stopped")
		}
		for len(d.alertCh) > 0 {
			f := <-d.alertCh
			res.findings = append(res.findings, f.Check+" "+alert.AttackerAddress(f))
		}
	}
	res.smtpFailures, _ = d.smtpAuthTracker.Stats()
	res.mailFailures, _ = d.mailAuthTracker.Stats()
	for ip := range smtpSuccessIPs(d) {
		res.successes = append(res.successes, ip)
	}
	slices.Sort(res.successes)
	return res
}

// Mail log lines read from the journal reach the parsers with the same
// program tags and times as the file, so every detection behaves the same.
func TestJournalMailAuthMatchesFileInput(t *testing.T) {
	var file, journal []maillog.Line
	for i, e := range mailAuthSequence() {
		file = append(file, maillog.Line{Source: "file", Message: e.at.Format(time.Stamp) + " mail " + e.ident + "[" + e.pid + "]: " + e.text})
		journal = append(journal, maillog.JournalLine(map[string]string{
			"_SYSTEMD_UNIT":     e.unit,
			"SYSLOG_IDENTIFIER": e.ident,
			"_PID":              e.pid,
			"SYSLOG_PID":        e.pid,
			"MESSAGE":           e.text,
		}, maillog.Position{Stream: "journal", Cursor: fmt.Sprint(i), ObservedAt: e.at}))
	}
	want := mailAuthResult{
		smtpFailures: 5,
		mailFailures: 5,
		successes:    []string{"203.0.113.141"},
		findings:     []string{"smtp_bruteforce 203.0.113.140", "mail_bruteforce 203.0.113.142"},
	}
	for name, lines := range map[string][]maillog.Line{"file": file, "journal": journal} {
		t.Run(name, func(t *testing.T) {
			got := replayMailLog(t, lines)
			if got.smtpFailures != want.smtpFailures || got.mailFailures != want.mailFailures ||
				!slices.Equal(got.successes, want.successes) || !slices.Equal(got.findings, want.findings) {
				t.Fatalf("results = %+v, want %+v", got, want)
			}
		})
	}
}
