package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// An account can forge the message of a root failure. Its alert must not
// consume the trusted alert's batch identity or persisted notification key.
func TestFTPJournalUserAlertCannotSuppressRootAlert(t *testing.T) {
	setFTPNumericPeers(t, true)
	d := New(&config.Config{}, nil, nil, "")
	src := d.ftpJournalSource()
	at := time.Now()
	var message string
	for _, uid := range []string{"1001", "0"} {
		line := maillog.JournalLine(map[string]string{
			"MESSAGE":           "(?@198.51.100.32) [WARNING] Authentication failed for user [alice]",
			"SYSLOG_IDENTIFIER": "pure-ftpd", "_PID": "77", "_SYSTEMD_UNIT": "pure-ftpd.service",
			"_UID": uid, "_EXE": "/usr/sbin/pure-ftpd", "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=" + uid, ObservedAt: at})
		message = line.Message
		if !d.dispatchJournalLine(src, line) {
			t.Fatal("dispatch stopped")
		}
	}
	if len(d.alertCh) != 2 {
		t.Fatalf("got %d alerts, want two", len(d.alertCh))
	}
	untrusted, trusted := <-d.alertCh, <-d.alertCh
	file := parseFTPLogLine(message, d.currentCfg())
	if len(file) != 1 || file[0].Key() == trusted.Key() {
		t.Fatal("a file alert shares the root journal alert's notification identity")
	}
	if untrusted.Key() == trusted.Key() || untrusted.Fingerprint() == trusted.Fingerprint() {
		t.Fatal("a user-uid alert shares the root alert's notification identity")
	}
	if got := alert.Deduplicate([]alert.Finding{untrusted, trusted}); len(got) != 2 {
		t.Fatalf("batch deduplication suppressed a root alert: %+v", got)
	}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.Update([]alert.Finding{untrusted, file[0]})
	if got := st.FilterNew([]alert.Finding{trusted}); len(got) != 1 {
		t.Fatal("a user-uid alert suppressed a later root alert in notification history")
	}
}

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
	setFTPNumericPeers(t, true)
	d := New(&config.Config{}, nil, nil, "")
	src := d.ftpJournalSource()
	entry := func(uid, exe string) maillog.Line {
		return maillog.JournalLine(map[string]string{
			"MESSAGE": "(?@198.51.100.31) [WARNING] Authentication failed for user [alice]", "SYSLOG_IDENTIFIER": "pure-ftpd",
			"_PID": "77", "_SYSTEMD_UNIT": "pure-ftpd.service", "_UID": uid, "_EXE": exe, "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=1", ObservedAt: time.Now()})
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

// Moving FTP to the journal must preserve the cracked-password escalation.
func TestFTPJournalLoginAfterBruteforce(t *testing.T) {
	setFTPNumericPeers(t, true)
	d := New(&config.Config{}, nil, nil, "")
	src := d.ftpJournalSource()
	at := time.Now()
	entry := func(message, uid string) maillog.Line {
		return maillog.JournalLine(map[string]string{
			"MESSAGE": message, "SYSLOG_IDENTIFIER": "pure-ftpd", "_PID": "77",
			"_SYSTEMD_UNIT": "pure-ftpd.service", "_UID": uid, "_EXE": "/usr/sbin/pure-ftpd", "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=2", ObservedAt: at})
	}
	for range checks.FTPFailThreshold {
		if !d.dispatchJournalLine(src, entry("(?@203.0.113.78) [WARNING] Authentication failed for user [alice]", "0")) {
			t.Fatal("failure dispatch stopped")
		}
	}
	for len(d.alertCh) > 0 {
		<-d.alertCh
	}
	if !d.dispatchJournalLine(src, entry("(alice@203.0.113.78) [INFO] alice is now logged in", "1001")) {
		t.Fatal("login dispatch stopped")
	}
	if len(d.alertCh) != 1 {
		t.Fatalf("login findings=%d, want one", len(d.alertCh))
	}
	got := <-d.alertCh
	if got.Check != "ftp_login_after_bruteforce" || got.Severity != alert.Critical || got.LoginAccount != "alice" || got.Observation.Producer != string(checks.ProducerFTPLog) || !got.Timestamp.Equal(at) {
		t.Fatalf("login after brute force = %+v", got)
	}
}

// A delayed journal consumer must not turn scattered old failures into a burst.
func TestFTPJournalBacklogDoesNotBecomeFreshAttack(t *testing.T) {
	cfg := &config.Config{}
	cfg.Thresholds.FTPFailWindowMin = 1
	d := New(cfg, nil, nil, "")
	now := time.Now()
	for i := checks.FTPFailThreshold; i >= 0; i-- {
		at := now.Add(-time.Duration(i) * 2 * time.Minute)
		line := at.Format(time.RFC3339Nano) + " pure-ftpd: (?@203.0.113.81) [WARNING] Authentication failed for user [alice]"
		findings := d.handleFTPJournalLine(line, cfg)
		if len(findings) == 0 || findings[0].Check != "ftp_auth_failure_realtime" {
			t.Fatalf("journal failure was not parsed: %+v", findings)
		}
		for _, f := range findings {
			if f.Check == "ftp_bruteforce" {
				t.Fatalf("old failures became a current burst: %+v", f)
			}
		}
	}
	got := d.handleFTPJournalLine("pure-ftpd: (alice@203.0.113.81) [INFO] alice is now logged in", cfg)
	if len(got) != 1 || got[0].Check != "ftp_login" {
		t.Fatalf("old failures escalated a login: %+v", got)
	}
}

// pure-ftpd logs failures as root and a session's lines under the logged-in
// user's uid. journald can give an entry the unit and executable of a
// session process that user's own program replaced, so an entry under a
// user's uid alerts but neither counts toward a brute force nor makes its
// address a customer.
func TestFTPJournalUserEntriesOnlyAlert(t *testing.T) {
	setFTPNumericPeers(t, true)
	d := New(&config.Config{}, nil, nil, "")
	src := d.ftpJournalSource()
	entry := func(message, uid string) maillog.Line {
		return maillog.JournalLine(map[string]string{
			"MESSAGE": message, "SYSLOG_IDENTIFIER": "pure-ftpd", "_PID": "77",
			"_SYSTEMD_UNIT": "pure-ftpd.service", "_UID": uid, "_EXE": "/usr/sbin/pure-ftpd", "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=3", ObservedAt: time.Now()})
	}
	const failure = "(?@198.51.100.32) [WARNING] Authentication failed for user [alice]"
	for range checks.FTPFailThreshold + 2 {
		d.dispatchJournalLine(src, entry(failure, "1001"))
	}
	d.dispatchJournalLine(src, entry("(alice@198.51.100.32) [INFO] alice is now logged in", "1001"))
	var findings []alert.Finding
	for len(d.alertCh) > 0 {
		findings = append(findings, <-d.alertCh)
	}
	if len(findings) != checks.FTPFailThreshold+3 {
		t.Fatalf("%d findings, want one per entry", len(findings))
	}
	for _, f := range findings {
		if f.Check == "ftp_bruteforce" || !checks.ProducerWritableLog(admission.ProducerID(f.Observation.Producer)) {
			t.Fatalf("user-uid entry gave %s stamped %q", f.Check, f.Observation.Producer)
		}
	}
	d.noteFTPCustomers(findings)
	if _, ok := d.knownCustomers.Lookup("198.51.100.32"); ok {
		t.Fatal("a user-uid login made its address a customer")
	}
	// Root failures start from zero: the user's entries counted nothing.
	for range checks.FTPFailThreshold - 1 {
		d.dispatchJournalLine(src, entry(failure, "0"))
	}
	for len(d.alertCh) > 0 {
		if f := <-d.alertCh; f.Check == "ftp_bruteforce" {
			t.Fatal("user-uid failures counted toward a brute force")
		}
	}
}

// setFTPNumericPeers fixes whether pure-ftpd logs client addresses.
func setFTPNumericPeers(t *testing.T, numeric bool) {
	t.Helper()
	old := pureFTPDNumericPeers
	pureFTPDNumericPeers = func() bool { return numeric }
	t.Cleanup(func() { pureFTPDNumericPeers = old })
}

// Unless DontResolve is set, pure-ftpd logs a client's reverse DNS name, and
// the client's owner can make that name read as another address. Root
// failures then alert but count toward nothing.
func TestFTPJournalHostNamesOnlyAlert(t *testing.T) {
	setFTPNumericPeers(t, false)
	d := New(&config.Config{}, nil, nil, "")
	src := d.ftpJournalSource()
	failure := func() maillog.Line {
		return maillog.JournalLine(map[string]string{
			"MESSAGE":           "(?@198.51.100.33) [WARNING] Authentication failed for user [alice]",
			"SYSLOG_IDENTIFIER": "pure-ftpd", "_PID": "77", "_SYSTEMD_UNIT": "pure-ftpd.service",
			"_UID": "0", "_EXE": "/usr/sbin/pure-ftpd", "_TRANSPORT": "syslog",
		}, maillog.Position{Stream: "journal", Cursor: "s=4", ObservedAt: time.Now()})
	}
	for range checks.FTPFailThreshold + 2 {
		d.dispatchJournalLine(src, failure())
	}
	n := 0
	for len(d.alertCh) > 0 {
		f := <-d.alertCh
		n++
		if f.Check == "ftp_bruteforce" || !checks.ProducerWritableLog(admission.ProducerID(f.Observation.Producer)) {
			t.Fatalf("root entry while pure-ftpd resolves names gave %s stamped %q", f.Check, f.Observation.Producer)
		}
	}
	if n != checks.FTPFailThreshold+2 {
		t.Fatalf("%d findings, want one per entry", n)
	}
	// Once pure-ftpd logs addresses, failures count from zero.
	setFTPNumericPeers(t, true)
	for range checks.FTPFailThreshold - 1 {
		d.dispatchJournalLine(src, failure())
	}
	for len(d.alertCh) > 0 {
		if f := <-d.alertCh; f.Check == "ftp_bruteforce" {
			t.Fatal("failures logged while pure-ftpd resolved names counted toward a brute force")
		}
	}
}
