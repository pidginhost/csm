package maillog

import "testing"

// journald records the sending process's unit and uid itself, so a program
// that names itself sshd or postfix cannot claim them.
func TestTrustedLine(t *testing.T) {
	rules := []SenderRule{
		{Units: []string{"sshd", "ssh.service"}, UIDs: []uint32{0}},
		{Units: []string{"postfix", "postfix@-"}, UIDs: []uint32{0, 89}},
	}
	for _, tc := range []struct {
		name string
		line Line
		want bool
	}{
		{"service as root", Line{Source: "journal", Unit: "sshd.service", UID: "0", Transport: "syslog"}, true},
		{"native journal call", Line{Source: "journal", Unit: "sshd.service", UID: "0", Transport: "journal"}, true},
		{"second unit name", Line{Source: "journal", Unit: "ssh.service", UID: "0", Transport: "syslog"}, true},
		// A stdout stream keeps the credentials of the process that opened
		// it; a child that inherits it writes under them.
		{"inherited output stream", Line{Source: "journal", Unit: "sshd.service", UID: "0", Transport: "stdout"}, false},
		{"no transport", Line{Source: "journal", Unit: "sshd.service", UID: "0"}, false},
		{"program outside the unit", Line{Source: "journal", Unit: "", UID: "0", Transport: "syslog"}, false},
		{"user process inside the unit", Line{Source: "journal", Unit: "sshd.service", UID: "1000", Transport: "syslog"}, false},
		{"service user", Line{Source: "journal", Unit: "postfix@-.service", UID: "89", Transport: "syslog"}, true},
		{"pipe command inside the unit", Line{Source: "journal", Unit: "postfix.service", UID: "1001", Transport: "syslog"}, false},
		{"unit not in any rule", Line{Source: "journal", Unit: "cron.service", UID: "0", Transport: "syslog"}, false},
		{"no uid", Line{Source: "journal", Unit: "sshd.service", Transport: "syslog"}, false},
		{"bad uid", Line{Source: "journal", Unit: "sshd.service", UID: "root", Transport: "syslog"}, false},
		{"file line", Line{Source: "file", Unit: "sshd.service", UID: "0", Transport: "syslog"}, false},
	} {
		if got := TrustedLine(tc.line, rules); got != tc.want {
			t.Errorf("%s: TrustedLine = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Dovecot relays every line through its root log process; Postfix daemons
// log as the postfix user; any other unit is trusted only as root.
func TestMailSenderRules(t *testing.T) {
	prev := lookupServiceUID
	t.Cleanup(func() { lookupServiceUID = prev })
	lookupServiceUID = func(name string) (uint32, bool) {
		if name == "postfix" {
			return 89, true
		}
		return 0, false
	}
	rules := MailSenderRules([]string{"postfix", "postfix@-", "dovecot", "exim4"})
	for _, tc := range []struct {
		unit, uid string
		want      bool
	}{
		{"postfix.service", "89", true},
		{"postfix@-.service", "89", true},
		{"postfix.service", "0", true},
		{"dovecot.service", "0", true},
		{"dovecot.service", "97", false},
		{"exim4.service", "0", true},
		{"exim4.service", "89", false},
	} {
		if got := TrustedLine(Line{Source: "journal", Unit: tc.unit, UID: tc.uid, Transport: "syslog"}, rules); got != tc.want {
			t.Errorf("%s uid %s: trusted %v, want %v", tc.unit, tc.uid, got, tc.want)
		}
	}
	// Without a postfix user only root is trusted for its units.
	lookupServiceUID = func(string) (uint32, bool) { return 0, false }
	rules = MailSenderRules([]string{"postfix"})
	if TrustedLine(Line{Source: "journal", Unit: "postfix.service", UID: "89", Transport: "syslog"}, rules) {
		t.Error("a postfix uid is trusted without a postfix user")
	}
}

func TestJournalLineCarriesSenderUID(t *testing.T) {
	line := JournalLine(map[string]string{"MESSAGE": "imap-login: Login", "SYSLOG_IDENTIFIER": "dovecot", "_PID": "7",
		"_SYSTEMD_UNIT": "dovecot.service", "_UID": "0", "_TRANSPORT": "syslog"}, Position{})
	if line.Unit != "dovecot.service" || line.UID != "0" || line.Transport != "syslog" || line.Source != "journal" {
		t.Fatalf("line = %+v, want the unit and uid journald recorded", line)
	}
}
