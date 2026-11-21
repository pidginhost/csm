package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
)

// Where syslog goes through journald, FTP logins come from pure-ftpd's
// journal entries and the system log file is not watched.
func TestFTPSourceFollowsJournal(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	info := platform.Info{OS: platform.OSAlma, Panel: platform.PanelCPanel}
	for _, journal := range []bool{false, true} {
		d.syslogFromJournal = journal
		var messages bool
		for _, s := range d.fixedLogSpecs(info, nil, false) {
			if s.path == "/var/log/messages" {
				messages = true
			}
		}
		if messages == journal {
			t.Errorf("journal=%v: system log file watched %v", journal, messages)
		}
	}
	if src := d.ftpJournalSource(); src.producer != checks.ProducerFTPJournal || src.handler == nil {
		t.Fatalf("ftp journal source = %+v", src)
	}
}

// pure-ftpd's own failures alert one by one and, at the threshold, raise one
// blocking brute-force finding; an entry a user's program wrote counts for
// nothing.
func TestFTPJournalBruteforceBlocks(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	src := d.ftpJournalSource()
	entry := func(uid, exe string) maillog.Line {
		return maillog.JournalLine(map[string]string{
			"MESSAGE": "(?@198.51.100.31) [WARNING] Authentication failed for user [alice]", "SYSLOG_IDENTIFIER": "pure-ftpd",
			"_PID": "77", "_SYSTEMD_UNIT": "pure-ftpd.service", "_UID": uid, "_EXE": exe, "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=1"})
	}
	for i := 0; i < checks.FTPFailThreshold; i++ {
		d.dispatchJournalLine(src, entry("1000", "/usr/bin/logger"))
	}
	if n := len(d.alertCh); n != 0 {
		t.Fatalf("%d findings from entries pure-ftpd did not write", n)
	}
	brute, failures := 0, 0
	for i := 0; i < checks.FTPFailThreshold+2; i++ {
		d.dispatchJournalLine(src, entry("0", "/usr/sbin/pure-ftpd"))
		for len(d.alertCh) > 0 {
			f := <-d.alertCh
			if f.Observation.Producer != string(checks.ProducerFTPJournal) {
				t.Fatalf("%s stamped %q", f.Check, f.Observation.Producer)
			}
			switch f.Check {
			case "ftp_bruteforce":
				brute++
			case "ftp_auth_failure_realtime":
				failures++
			}
		}
	}
	if brute != 1 || failures != checks.FTPFailThreshold+2 {
		t.Fatalf("brute-force findings %d, failure findings %d", brute, failures)
	}
}
