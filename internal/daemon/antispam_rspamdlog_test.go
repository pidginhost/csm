package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
)

const (
	rspamdMilter    = "inet:127.0.0.1:11332"
	rspamdLogPrefix = "2026-10-20 12:10:00 #2273(normal) <9f7812>; lua; csm_scope.lua:91: "
	// milterFailureLine is postfix smtpd failing to read rspamd's reply.
	milterFailureLine = "Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: milter inet:127.0.0.1:11332: can't read SMFIC_BODYEOB reply packet header: Connection timed out"
)

func rspamdRecord(ip string) string {
	return rspamdLogPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=229 action="reject" decision=reject ip=` + ip + ` qid=4XyZ0b1c2D`
}

func TestPostfixMilterFailure(t *testing.T) {
	milters := []string{rspamdMilter, "unix:rspamd/milter.sock"}
	for _, line := range []string{
		milterFailureLine,
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: connect to Milter service inet:127.0.0.1:11332: Connection refused",
		"Oct 20 12:10:00 mail postfix/submission/smtpd[4243]: warning: milter unix:rspamd/milter.sock: can't read SMFIC_OPTNEG reply packet header: Connection reset by peer",
		// The journal reader renders entries in the syslog shape.
		"2026-10-20T12:10:00.494854Z postfix/smtpd[99]: warning: milter inet:127.0.0.1:11332: can't read SMFIC_EOH reply packet header: Success",
		"2026-10-20T12:10:00.494854Z postfix/smtpd[99]: warning: connect to Milter service unix:rspamd/milter.sock: No such file or directory",
	} {
		if !postfixMilterFailure(line, milters) {
			t.Errorf("missed %q", line)
		}
		if postfixMilterFailure(line, nil) {
			t.Errorf("matched %q without a configured milter", line)
		}
	}
	for _, line := range []string{
		// Another milter, such as OpenDKIM, is not rspamd.
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: milter inet:127.0.0.1:8891: can't read SMFIC_BODYEOB reply packet header: Connection timed out",
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: connect to Milter service inet:127.0.0.1:8891: Connection refused",
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: milter inet:127.0.0.1:113320: can't read SMFIC_BODYEOB reply packet header: Connection timed out",
		// Postfix names a milter as smtpd_milters does, not by its path
		// outside the chroot.
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: milter unix:/var/spool/postfix/rspamd/milter.sock: can't read SMFIC_EOH reply packet header: Success",
		// cleanup runs non_smtpd_milters, mail rspamd does not scan for CSM.
		"Oct 20 12:10:00 mail postfix/cleanup[77]: warning: milter inet:127.0.0.1:11332: can't read SMFIC_BODYEOB reply packet header: Connection timed out",
		"Oct 20 12:10:00 mail rspamd[1]: warning: milter inet:127.0.0.1:11332: can't read SMFIC_BODYEOB reply packet header: Connection timed out",
		"Oct 20 12:10:00 mail postfix/smtpd[]: warning: milter inet:127.0.0.1:11332: can't read SMFIC_BODYEOB reply packet header: Connection timed out",
		// Client text smtpd echoes into its own messages.
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: Illegal address syntax from unknown[203.0.113.5] in RCPT command: <warning: milter inet:127.0.0.1:11332: x>",
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: non-SMTP command from unknown[203.0.113.5]: warning: connect to Milter service inet:127.0.0.1:11332: x",
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 450 4.7.1 <x>: Helo command rejected: Host not found; from=<a@example.com> to=<b@example.com> proto=ESMTP helo=<warning: milter inet:127.0.0.1:11332: x>",
		"Oct 20 12:10:00 mail dovecot[812]: imap-login: Aborted login: user=<postfix/smtpd[1]: warning: milter inet:127.0.0.1:11332: x>, rip=203.0.113.5",
		"Oct 20 12:10:00 mail postfix/smtpd[4242]: milter inet:127.0.0.1:11332: can't read SMFIC_BODYEOB reply packet header: Connection timed out",
		"",
	} {
		if postfixMilterFailure(line, milters) {
			t.Errorf("matched %q", line)
		}
	}
}

// A milter failure leaves no scan record, so postfix's warning raises
// antispam_scan_error like a failed Exim scan.
func TestMilterFailureRaisesScanError(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	echo := "Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: Illegal address syntax from unknown[203.0.113.5] in RCPT command: <warning: milter inet:127.0.0.1:11332: x>"
	if got := d.handleMailLine(milterFailureLine, alert.Observation{}, d.currentCfg()); len(got) != 0 {
		t.Fatalf("failure counted before a pass named rspamd's milters: %+v", got)
	}
	d.antispamScanSource.Store(&antispam.ScanSource{Milters: []string{rspamdMilter}})
	if got := d.handleMailLine(echo, alert.Observation{}, d.currentCfg()); len(got) != 0 || len(d.antispamHealth.Active()) != 0 {
		t.Fatalf("client text counted as a failure: %+v", got)
	}
	got := d.handleMailLine(milterFailureLine, alert.Observation{}, d.currentCfg())
	if len(got) != 1 || got[0].Check != reconcile.CheckScanError {
		t.Fatalf("milter failure raised %+v, want one %s", got, reconcile.CheckScanError)
	}
	if active := d.antispamHealth.Active(); len(active) != 1 || active[0].Check != reconcile.CheckScanError {
		t.Fatalf("active %+v", active)
	}
}

// Each scan record in rspamd's log counts like an Exim scan marker: spam
// evidence on the sender, the Email Security counts and scan health. The
// log is read from where it ends when CSM starts on it, and only CSM's
// records count.
func TestRspamdLogScanFeedsHealthEvidenceStats(t *testing.T) {
	now := mailStatsTestNow
	d := newMailStatsTestDaemon(t, &now)
	adb := useTestAttackDB(t)
	enableAntispam(t, d, true)
	path := filepath.Join(t.TempDir(), "rspamd.log")
	writeLog := func(lines ...string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range lines {
			if _, err := f.WriteString(line + "\n"); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	writeLog(rspamdRecord("198.51.100.79"))
	d.antispamScanSource.Store(&antispam.ScanSource{Log: path, Milters: []string{rspamdMilter}})
	d.handleMailLine(milterFailureLine, alert.Observation{}, d.currentCfg())
	if len(d.antispamHealth.Active()) != 1 {
		t.Fatalf("milter failure not tracked: %+v", d.antispamHealth.Active())
	}

	w := d.followRspamdLog(nil)
	if w == nil {
		t.Fatal("rspamd's log is not followed")
	}
	t.Cleanup(func() { w.Stop() })
	writeLog(
		"2026-10-20 12:10:00 #2273(normal) <9f7812>; lua; other.lua:12: subject: x; "+rspamdRecord("198.51.100.81")[len("2026-10-20 12:10:00 #2273(normal) <9f7812>; "):],
		"2026-10-20 12:10:00 #2273(normal) <9f7812>; task; rspamd_task_write_log: id: <x@example.com>, qid: <4XyZ0b1c2D>, ip: 198.51.100.80",
		rspamdRecord("198.51.100.80"),
	)
	if next := d.followRspamdLog(w); next != w {
		t.Fatalf("watcher replaced while the log stayed: %p, %p", next, w)
	}

	if rec := adb.LookupIP("198.51.100.80"); rec == nil || rec.Mail == nil || rec.Mail.Spam != 1 {
		t.Fatalf("record after a spam scan: %+v", rec)
	}
	for _, ip := range []string{"198.51.100.79", "198.51.100.81"} {
		if rec := adb.LookupIP(ip); rec != nil {
			t.Errorf("%s recorded: %+v", ip, rec.Mail)
		}
	}
	ov := d.mailStats.Overview(now.Add(-time.Hour), now)
	if ov.Totals.Scanned != 1 || ov.Totals.Rejected != 1 {
		t.Fatalf("totals = %+v, want one rejected scan", ov.Totals)
	}
	if len(ov.Series) != 1 || ov.Series[0].T != time.Date(2026, 10, 20, 12, 0, 0, 0, time.Local).Unix() {
		t.Fatalf("series = %+v, want one bucket at the record's own time", ov.Series)
	}
	if active := d.antispamHealth.Active(); len(active) != 0 {
		t.Fatalf("scan record left %+v", active)
	}

	// A pass that finds no file log stops reading, and so does disabling.
	d.antispamScanSource.Store(&antispam.ScanSource{Milters: []string{rspamdMilter}})
	if next := d.followRspamdLog(w); next != nil {
		t.Fatal("still reading a log rspamd no longer writes")
	}
	d.antispamScanSource.Store(&antispam.ScanSource{Log: path})
	enableAntispam(t, d, false)
	if next := d.followRspamdLog(nil); next != nil {
		next.Stop()
		t.Fatal("reading rspamd's log with antispam disabled")
	}
}

// A missing log is retried on the next poll; a file appearing later is read
// from its end like every log CSM starts on.
func TestFollowRspamdLogWaitsForTheFile(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	path := filepath.Join(t.TempDir(), "rspamd.log")
	d.antispamScanSource.Store(&antispam.ScanSource{Log: path})
	if w := d.followRspamdLog(nil); w != nil {
		t.Fatal("watching a missing file")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w := d.followRspamdLog(nil)
	if w == nil {
		t.Fatal("file not followed once it exists")
	}
	w.Stop()
}

// A pass that could not read where scan records come from keeps the last
// answer; any other pass replaces it.
func TestReportAntispamKeepsScanSource(t *testing.T) {
	d := newTestDaemon(t)
	src := &antispam.ScanSource{Log: "/var/log/rspamd/rspamd.log", Milters: []string{rspamdMilter}}
	d.reportAntispam(reconcile.Outcome{ScanSource: src})
	if got := d.antispamScanSource.Load(); got != src {
		t.Fatalf("scan source %+v, want %+v", got, src)
	}
	d.reportAntispam(reconcile.Outcome{})
	if got := d.antispamScanSource.Load(); got != src {
		t.Fatalf("an unsettled pass replaced the scan source with %+v", got)
	}
	d.reportAntispam(reconcile.Outcome{ScanSource: &antispam.ScanSource{}})
	if got := d.antispamScanSource.Load(); got == nil || got.Log != "" || len(got.Milters) != 0 {
		t.Fatalf("scan source %+v, want none", got)
	}
}
