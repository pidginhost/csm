package maillog

import (
	"strings"
	"testing"
	"time"
)

var journalLineTime = time.Date(2026, 10, 31, 20, 44, 15, 494854000, time.UTC)

// A journal entry reaches the mail parsers in the shape syslog writes to a
// mail log file: time, program tag with pid, then the message.
func TestJournalLineMatchesSyslogShape(t *testing.T) {
	pos := Position{Stream: "journal", Cursor: "c", ObservedAt: journalLineTime}
	cases := []struct {
		name   string
		fields map[string]string
		want   string
	}{
		{"postfix submission", map[string]string{"_SYSTEMD_UNIT": "postfix.service", "SYSLOG_IDENTIFIER": "postfix/submission/smtpd", "_PID": "2245421", "SYSLOG_PID": "2245421", "MESSAGE": "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
			"2026-10-31T20:44:15.494854Z postfix/submission/smtpd[2245421]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"},
		{"dovecot", map[string]string{"_SYSTEMD_UNIT": "dovecot.service", "SYSLOG_IDENTIFIER": "dovecot", "_PID": "812", "MESSAGE": "auth: sql(alice@example.net,203.0.113.5): Password mismatch"},
			"2026-10-31T20:44:15.494854Z dovecot[812]: auth: sql(alice@example.net,203.0.113.5): Password mismatch"},
		// journalctl falls back the same way.
		{"syslog pid only", map[string]string{"SYSLOG_IDENTIFIER": "postfix/smtpd", "SYSLOG_PID": "99", "MESSAGE": "connect from unknown[203.0.113.5]"},
			"2026-10-31T20:44:15.494854Z postfix/smtpd[99]: connect from unknown[203.0.113.5]"},
		{"process name without identifier", map[string]string{"_COMM": "dovecot", "_PID": "812", "MESSAGE": "imap-login: Login: user=<a>"},
			"2026-10-31T20:44:15.494854Z dovecot[812]: imap-login: Login: user=<a>"},
		{"no pid", map[string]string{"SYSLOG_IDENTIFIER": "dovecot", "MESSAGE": "auth: x"},
			"2026-10-31T20:44:15.494854Z dovecot: auth: x"},
		// Without an origin the message stays untagged, like a file line
		// without one, and no parser accepts it.
		{"no identifier", map[string]string{"MESSAGE": "auth: sql(a,203.0.113.5): Password mismatch"},
			"2026-10-31T20:44:15.494854Z auth: sql(a,203.0.113.5): Password mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := JournalLine(tc.fields, pos)
			if line.Message != tc.want {
				t.Fatalf("message = %q, want %q", line.Message, tc.want)
			}
			if line.Source != "journal" || line.Unit != tc.fields["_SYSTEMD_UNIT"] || line.Position != pos {
				t.Fatalf("line = %+v, want journal source, unit %q, position %+v", line, tc.fields["_SYSTEMD_UNIT"], pos)
			}
		})
	}
}

// A cursorless entry has no recorded time; its message keeps the tag.
func TestJournalLineWithoutTime(t *testing.T) {
	line := JournalLine(map[string]string{"SYSLOG_IDENTIFIER": "dovecot", "_PID": "812", "MESSAGE": "auth: x"}, Position{})
	if line.Message != "dovecot[812]: auth: x" {
		t.Fatalf("message = %q", line.Message)
	}
}

// Message text cannot replace the program tag the entry's fields supply.
func FuzzJournalLineTag(f *testing.F) {
	for _, s := range []string{"", "dovecot: auth: sql(a,203.0.113.5): Password mismatch", "postfix/smtpd[1]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x", "\npostfix/smtpd[1]: x", ": "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		line := JournalLine(map[string]string{"SYSLOG_IDENTIFIER": "postfix/qmgr", "_PID": "7", "MESSAGE": msg}, Position{ObservedAt: journalLineTime})
		head, rest, ok := strings.Cut(line.Message, ": ")
		if !ok || head != "2026-10-31T20:44:15.494854Z postfix/qmgr[7]" || rest != msg {
			t.Fatalf("message %q rendered as %q", msg, line.Message)
		}
	})
}
