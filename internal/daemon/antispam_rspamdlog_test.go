package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
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
// antispam_scan_error like a failed Exim scan, in Postfix's words: what
// happens to the mail is milter_default_action's choice.
func TestMilterFailureRaisesScanError(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	echo := "Oct 20 12:10:00 mail postfix/smtpd[4242]: warning: Illegal address syntax from unknown[203.0.113.5] in RCPT command: <warning: milter inet:127.0.0.1:11332: x>"
	if got := d.handleMailLine(milterFailureLine, alert.Observation{}, d.currentCfg()); len(got) != 0 {
		t.Fatalf("failure counted before a pass named rspamd's milters: %+v", got)
	}
	d.reportAntispam(reconcile.Outcome{ScanSource: &antispam.ScanSource{Stack: antispam.StackPostfix, Milters: []string{rspamdMilter}, MilterAction: "tempfail"}})
	if got := d.handleMailLine(echo, alert.Observation{}, d.currentCfg()); len(got) != 0 || len(d.antispamHealth.Active()) != 0 {
		t.Fatalf("client text counted as a failure: %+v", got)
	}
	got := d.handleMailLine(milterFailureLine, alert.Observation{}, d.currentCfg())
	if len(got) != 1 || got[0].Check != reconcile.CheckScanError {
		t.Fatalf("milter failure raised %+v, want one %s", got, reconcile.CheckScanError)
	}
	if !strings.HasPrefix(got[0].Details, "Postfix logged 1 failed scan since ") || !strings.Contains(got[0].Details, " Mail is deferred until rspamd answers; ") {
		t.Fatalf("details %q, want Postfix's wording for tempfail", got[0].Details)
	}
	if active := d.antispamHealth.Active(); len(active) != 1 || active[0].Details != got[0].Details {
		t.Fatalf("active %+v", active)
	}
}

// Each scan record in rspamd's log counts for scan health and the Email
// Security counts. It is no evidence against its sender (see
// TestRspamdLogScanIsNoSenderEvidence). The log is read from where it ends
// when CSM starts on it, and only CSM's records count.
func TestRspamdLogScanFeedsHealthAndStats(t *testing.T) {
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

	var tail rspamdLogTail
	t.Cleanup(tail.stop)
	d.followRspamdLog(&tail)
	w := tail.w
	if w == nil {
		t.Fatal("rspamd's log is not followed")
	}
	writeLog(
		"2026-10-20 12:10:00 #2273(normal) <9f7812>; lua; other.lua:12: subject: x; "+rspamdRecord("198.51.100.81")[len("2026-10-20 12:10:00 #2273(normal) <9f7812>; "):],
		"2026-10-20 12:10:00 #2273(normal) <9f7812>; task; rspamd_task_write_log: id: <x@example.com>, qid: <4XyZ0b1c2D>, ip: 198.51.100.80",
		rspamdRecord("198.51.100.80"),
	)
	if d.followRspamdLog(&tail); tail.w != w {
		t.Fatalf("watcher replaced while the log stayed: %p, %p", tail.w, w)
	}

	for _, ip := range []string{"198.51.100.79", "198.51.100.80", "198.51.100.81"} {
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
	if d.followRspamdLog(&tail); tail.w != nil {
		t.Fatal("still reading a log rspamd no longer writes")
	}
	d.antispamScanSource.Store(&antispam.ScanSource{Log: path})
	enableAntispam(t, d, false)
	if d.followRspamdLog(&tail); tail.w != nil {
		t.Fatal("reading rspamd's log with antispam disabled")
	}
}

// Any local process can have rspamd log a genuine record naming any sender,
// through rspamd's scan listeners. A Postfix record is never evidence
// against the address it names: no attack DB verdict and no spam source.
// The same rejects in Exim's log raise both, so the detector was listening.
func TestRspamdLogScanIsNoSenderEvidence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		useSpamStore(t)
		adb := useTestAttackDB(t)
		cfg := spamSourceConfig(t)
		d := startSpamDaemon(t, cfg, &spamDNS{})
		const forged, real = "198.51.100.90", "198.51.100.91"
		base := time.Now()
		for _, at := range []time.Time{base, base.Add(2 * time.Hour)} {
			d.handleRspamdLogLine(rspamdRecord(forged), alert.Observation{ObservedAt: at}, cfg)
		}
		if got := spamFindings(d); len(got) != 0 {
			t.Fatalf("rspamd records raised %+v", got)
		}
		if rec := adb.LookupIP(forged); rec != nil {
			t.Fatalf("rspamd records became evidence: %+v", rec.Mail)
		}
		eximAt(d, cfg, rejectMarker(real), base)
		eximAt(d, cfg, rejectMarker(real), base.Add(2*time.Hour))
		wantSpamFinding(t, spamFindings(d), real, base.Add(2*time.Hour))
		if rec := adb.LookupIP(real); rec == nil || rec.Mail == nil || rec.Mail.Spam != 2 {
			t.Fatalf("Exim markers lost their evidence: %+v", rec)
		}
	})
}

// A log CSM cannot open is retried on every poll and reported once; a file
// appearing later is reported once and read from its end like every log
// CSM starts on.
func TestFollowRspamdLogWaitsForTheFile(t *testing.T) {
	d := newTestDaemon(t)
	enableAntispam(t, d, true)
	path := filepath.Join(t.TempDir(), "rspamd.log")
	d.antispamScanSource.Store(&antispam.ScanSource{Log: path})
	finish := captureCSMLog(t)
	t.Cleanup(func() { finish() })
	var tail rspamdLogTail
	t.Cleanup(tail.stop)
	for range 3 {
		if d.followRspamdLog(&tail); tail.w != nil {
			t.Fatal("watching a missing file")
		}
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if d.followRspamdLog(&tail); tail.w == nil {
			t.Fatal("file not followed once it exists")
		}
	}
	got := finish()
	if strings.Count(got, "rspamd log not readable, will retry") != 1 || strings.Count(got, "watching rspamd log (appeared after retry)") != 1 || !strings.Contains(got, path) {
		t.Fatalf("log = %q, want one retry warning and one recovery for %s", got, path)
	}
}

// rspamd's user owns its log directory, so it can put a FIFO or a symlink
// where the log was. CSM opens neither, when it starts following the log or
// reopens it: a FIFO would block the open and with it daemon shutdown, and a
// symlink would point the tail at another file. A refused log is reported
// like a missing one and tried again.
func TestFollowRspamdLogRefusesFIFOAndSymlink(t *testing.T) {
	within := func(t *testing.T, what string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			fn()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s blocked", what)
		}
	}
	for name, plant := range map[string]func(t *testing.T, path string){
		"fifo": func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			other := filepath.Join(filepath.Dir(path), "other.log")
			if err := os.WriteFile(other, []byte(rspamdRecord("198.51.100.79")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newTestDaemon(t)
			enableAntispam(t, d, true)
			path := filepath.Join(t.TempDir(), "rspamd.log")
			plant(t, path)
			d.antispamScanSource.Store(&antispam.ScanSource{Log: path})
			finish := captureCSMLog(t)
			t.Cleanup(func() { finish() })
			var tail rspamdLogTail
			within(t, "following the log", func() { d.followRspamdLog(&tail) })
			if tail.w != nil {
				tail.stop()
				t.Fatalf("followed a %s", name)
			}
			if got := finish(); !strings.Contains(got, "rspamd log not readable, will retry") || !strings.Contains(got, path) {
				t.Fatalf("log = %q, want a retry warning for %s", got, path)
			}

			// The same swap after CSM opened the log is refused on reopen.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			d.followRspamdLog(&tail)
			if tail.w == nil {
				t.Fatal("regular log not followed")
			}
			t.Cleanup(tail.stop)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			plant(t, path)
			within(t, "reopening the log", tail.w.reopen)
			within(t, "reading the log", func() { d.followRspamdLog(&tail) })
			if tail.w.file != nil {
				t.Fatalf("reopened a %s", name)
			}
		})
	}
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
