package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
)

// Where syslog goes through journald, SSH logins come from sshd's journal
// entries and the auth log file is not watched; elsewhere the file is, and
// its findings only alert.
func TestSSHSourceFollowsJournal(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	for _, journal := range []bool{false, true} {
		d.syslogFromJournal = journal
		var auth bool
		for _, s := range d.fixedLogSpecs(platform.Info{OS: platform.OSAlma}, nil, false) {
			if s.path == "/var/log/secure" {
				auth = true
				if s.producer != checks.ProducerSSHLog {
					t.Errorf("auth log producer %s, want %s", s.producer, checks.ProducerSSHLog)
				}
			}
		}
		if auth == journal {
			t.Errorf("journal=%v: auth log watched %v", journal, auth)
		}
	}
	if sshJournal.producer != checks.ProducerSSHJournal || len(sshJournal.units) == 0 {
		t.Fatalf("ssh journal source = %+v", sshJournal)
	}
}

// Only an entry sshd wrote reaches the SSH parser, stamped as the journal
// producer; an entry naming itself sshd from anywhere else is dropped.
func TestSSHJournalLineParses(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	entry := func(unit, uid string) maillog.Line {
		return maillog.JournalLine(map[string]string{
			"MESSAGE": "Accepted publickey for root from 198.51.100.9 port 22 ssh2", "SYSLOG_IDENTIFIER": "sshd",
			"_PID": "4242", "_SYSTEMD_UNIT": unit, "_UID": uid, "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=1"})
	}
	for _, line := range []maillog.Line{entry("", "1000"), entry("sshd.service", "1000")} {
		if !d.dispatchJournalLine(sshJournal, line) {
			t.Fatal("a dropped entry stopped delivery")
		}
	}
	if n := len(d.alertCh); n != 0 {
		t.Fatalf("%d findings from entries sshd did not write", n)
	}
	for _, unit := range []string{"sshd.service", "ssh.service"} {
		if !d.dispatchJournalLine(sshJournal, entry(unit, "0")) {
			t.Fatal("delivery stopped")
		}
		f := <-d.alertCh
		if f.Check != "ssh_login_unknown_ip" || f.SourceIP != "198.51.100.9" || f.Observation.Producer != string(checks.ProducerSSHJournal) {
			t.Fatalf("%s: finding %s %s stamped %q", unit, f.Check, f.SourceIP, f.Observation.Producer)
		}
	}
}

// The scheduled login scan still reads the auth log file. A login it finds
// there and the same login read from the journal are one record, whatever
// the timestamp and host prefix each source writes.
func TestSSHLoginRecordKeyIgnoresTheLinePrefix(t *testing.T) {
	msg := "Accepted publickey for root from 198.51.100.9 port 22 ssh2"
	file, ok := checks.SSHAcceptedLoginFinding("Nov 21 12:00:00 host sshd[4242]: "+msg, nil)
	journal := maillog.JournalLine(map[string]string{"MESSAGE": msg, "SYSLOG_IDENTIFIER": "sshd", "_PID": "4242"},
		maillog.Position{Stream: "journal", Cursor: "s=1"})
	fromJournal, ok2 := checks.SSHAcceptedLoginFinding(journal.Message, nil)
	other, ok3 := checks.SSHAcceptedLoginFinding("Nov 21 12:00:00 host sshd[4243]: "+msg, nil)
	if !ok || !ok2 || !ok3 {
		t.Fatal("a login line did not parse")
	}
	if file.DedupKey != fromJournal.DedupKey {
		t.Fatalf("one login has two keys: %s and %s", file.DedupKey, fromJournal.DedupKey)
	}
	if other.DedupKey == file.DedupKey {
		t.Fatal("two sessions share one key")
	}
}

// A socket-activated sshd runs each connection in an instance unit; its
// root entries are logins, a user's entries there are not.
func TestSSHJournalTrustsSocketActivatedInstances(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	instance := "sshd@3-192.0.2.1:22-198.51.100.9:51234.service"
	for _, tc := range []struct {
		uid  string
		want int
	}{{"1000", 0}, {"0", 1}} {
		line := maillog.JournalLine(map[string]string{
			"MESSAGE": "Accepted publickey for root from 198.51.100.9 port 51234 ssh2", "SYSLOG_IDENTIFIER": "sshd-session",
			"_PID": "4242", "_SYSTEMD_UNIT": instance, "_UID": tc.uid, "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=1"})
		if !d.dispatchJournalLine(sshJournal, line) {
			t.Fatal("delivery stopped")
		}
		if got := len(d.alertCh); got != tc.want {
			t.Fatalf("uid %s: %d findings, want %d", tc.uid, got, tc.want)
		}
	}
}
