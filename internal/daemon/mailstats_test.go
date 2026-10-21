package daemon

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailstats"
	"github.com/pidginhost/csm/internal/store"
)

// mailStatsTestNow is the clock the mail stats tests count on. A fixed clock
// keeps their records inside retention whatever day the tests run.
var mailStatsTestNow = time.Date(2026, 10, 20, 12, 20, 0, 0, time.Local)

const (
	mailStatsScanLine     = `2026-10-20 12:10:00 1tAbCd-000001-Ab CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=152 action="reject" decision=reject ip=203.0.113.7`
	mailStatsRejectLine   = `2026-10-20 12:10:00 1tAbCd-000001-Ab H=(mx.example.net) [203.0.113.7]:5 F=<a@example.com> rejected after DATA: Message rejected as spam`
	mailStatsSMTPAuthLine = `2026-10-20 12:11:00 dovecot_login authenticator failed for H=(mail.example.com) [198.51.100.40]:54321: 535 Incorrect authentication data (set_id=user@example.com)`
)

// newMailStatsTestDaemon returns a daemon whose mail decision counter reads
// the time from *now.
func newMailStatsTestDaemon(t *testing.T, now *time.Time) *Daemon {
	t.Helper()
	d := newTestDaemon(t)
	d.mailStatsNow = func() time.Time { return *now }
	d.mailStats = mailstats.New(d.mailStatsNow)
	return d
}

func TestHandleEximLineCountsMarkersAndRejects(t *testing.T) {
	now := mailStatsTestNow
	d := newMailStatsTestDaemon(t, &now)
	// The login count matches a grep of the log, so an address the brute
	// force tracker skips still counts.
	cfg := &config.Config{InfraIPs: []string{"198.51.100.40"}}
	for _, line := range []string{mailStatsScanLine, mailStatsRejectLine, mailStatsSMTPAuthLine} {
		d.handleEximLine(line, alert.Observation{ObservedAt: now}, cfg)
	}
	ov := d.mailStats.Overview(now.Add(-time.Hour), now)
	if ov.Totals.Scanned != 1 || ov.Totals.Rejected != 1 || ov.Totals.Rejects[mailstats.ClassSpam] != 1 || ov.Totals.LoginsSMTP != 1 {
		t.Fatalf("totals = %+v", ov.Totals)
	}
	if len(ov.Series) != 1 || ov.Series[0].T != time.Date(2026, 10, 20, 12, 0, 0, 0, time.Local).Unix() {
		t.Fatalf("series = %+v, want one bucket at the lines' own time, not the read time", ov.Series)
	}
}

// The scan marker and the antivirus reject of one message carry the same
// message ID, so the counter takes that scan out of clean.
func TestHandleEximLineMovesMalwareScanOutOfClean(t *testing.T) {
	now := mailStatsTestNow
	d := newMailStatsTestDaemon(t, &now)
	for _, line := range []string{
		`2026-10-20 12:10:00 1tAbCd-000002-Ab CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=12 action="no action" decision=none ip=203.0.113.8`,
		`2026-10-20 12:10:01 1tAbCd-000002-Ab H=(mx.example.net) [203.0.113.8]:25 F=<a@example.com> rejected after DATA: This message contains a virus or other harmful content (Example.Test-1)`,
	} {
		d.handleEximLine(line, alert.Observation{ObservedAt: now}, &config.Config{})
	}
	ov := d.mailStats.Overview(now.Add(-time.Hour), now)
	if ov.Totals.Scanned != 1 || ov.Totals.Clean != 0 || ov.Totals.Rejects[mailstats.ClassMalware] != 1 {
		t.Fatalf("totals = %+v, want the scan counted but not as clean", ov.Totals)
	}
	if len(ov.Series) != 1 || ov.Series[0].Clean != 0 || ov.Series[0].Malware != 1 {
		t.Fatalf("series = %+v, want one malware message and nothing clean", ov.Series)
	}
}

func TestHandleMailLineCountsAttempts(t *testing.T) {
	now := mailStatsTestNow
	d := newMailStatsTestDaemon(t, &now)
	cfg := &config.Config{InfraIPs: []string{"203.0.113.9"}}
	d.handleMailLine("Oct 20 12:10:00 mail.example.com dovecot: imap-login: Login aborted: Connection closed (auth failed, 3 attempts in 6 secs): user=<u@example.com>, method=PLAIN, rip=203.0.113.9",
		alert.Observation{ObservedAt: now}, cfg)
	d.handleMailLine("Oct 20 12:11:00 mail.example.com dovecot: imap-login: Logged in: user=<u@example.com>, method=PLAIN, rip=203.0.113.9",
		alert.Observation{ObservedAt: now}, cfg)
	// A source without an observation time falls back to the counter's clock.
	d.handleMailLine("Oct 20 12:12:00 mail.example.com dovecot: pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 2 secs): user=<u@example.com>, method=PLAIN, rip=203.0.113.9",
		alert.Observation{}, cfg)

	ov := d.mailStats.Overview(now.Add(-time.Hour), now)
	if ov.Totals.LoginsMailbox != 4 || ov.Totals.LoginsSMTP != 0 {
		t.Fatalf("totals = %+v, want 4 mailbox attempts", ov.Totals)
	}
	if len(ov.Series) != 1 || ov.Series[0].T != time.Date(2026, 10, 20, 12, 0, 0, 0, time.Local).Unix() {
		t.Fatalf("series = %+v, want one bucket at the lines' own time", ov.Series)
	}
}

// Counts survive a restart: the first daemon merges the empty store, counts
// and saves, and the next one restores what it saved.
func TestMailStatsPersistAcrossRestart(t *testing.T) {
	openStoreForTest(t)
	now := mailStatsTestNow
	first := newMailStatsTestDaemon(t, &now)
	first.restoreMailStats()
	first.handleEximLine(mailStatsRejectLine, alert.Observation{ObservedAt: now}, &config.Config{})
	first.persistMailStats()

	second := newMailStatsTestDaemon(t, &now)
	second.restoreMailStats()
	if got := second.mailStats.Overview(now.Add(-time.Hour), now).Totals.Rejects[mailstats.ClassSpam]; got != 1 {
		t.Fatalf("restored spam rejects = %d, want 1", got)
	}
	if got := second.mailStats.Rejects(now.Add(-time.Hour), now, nil, 10); len(got) != 1 || got[0].IP != "203.0.113.7" {
		t.Fatalf("restored reject ring = %+v", got)
	}
}

// The counter is built with the daemon, but counting starts when the log
// watchers do, right after the restore. The stop recorded at restore ends
// there.
func TestRestoreMailStatsGapEndsAtRestore(t *testing.T) {
	db := openStoreForTest(t)
	built := mailStatsTestNow
	now := built
	d := newMailStatsTestDaemon(t, &now)
	if err := db.SetMetaString("mailstats:flushed_at", built.Add(-10*time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	now = built.Add(5 * time.Minute)
	d.restoreMailStats()
	ov := d.mailStats.Overview(built.Add(-time.Hour), now)
	if ov.UncountedMinutes != 15 || len(ov.Gaps) != 1 || !ov.Gaps[0].Start.Equal(built.Add(-10*time.Minute)) || !ov.Gaps[0].End.Equal(now) {
		t.Fatalf("uncounted %d, gaps %+v, want 15 minutes ending at the restore", ov.UncountedMinutes, ov.Gaps)
	}
}

func TestRestoreMailStatsWithoutStoreKeepsStartOnRetry(t *testing.T) {
	db := openStoreForTest(t)
	built := mailStatsTestNow
	flushed := built.Add(-10 * time.Minute)
	if err := db.SetMetaString("mailstats:flushed_at", flushed.UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	now := built
	d := newMailStatsTestDaemon(t, &now)
	store.SetGlobal(nil)
	started := built.Add(5 * time.Minute)
	now = started
	d.restoreMailStats()
	if got := d.mailStats.Overview(built, now).CountingSince; !got.Equal(started) {
		t.Errorf("memory counting since %v, want reader start %v", got, started)
	}

	store.SetGlobal(db)
	now = started.Add(10 * time.Minute)
	d.persistMailStats()
	ov := d.mailStats.Overview(flushed, now)
	if ov.UncountedMinutes != 15 || len(ov.Gaps) != 1 || !ov.Gaps[0].Start.Equal(flushed) || !ov.Gaps[0].End.Equal(started) {
		t.Fatalf("uncounted %d, gaps %+v, want 15 minutes ending when readers started", ov.UncountedMinutes, ov.Gaps)
	}
	if !ov.CountingSince.Equal(started) {
		t.Errorf("restored counting since %v, want reader start %v", ov.CountingSince, started)
	}
}

// One store error at startup must not leave the run memory-only: each save
// retries the load, which merges the stored counts once, and the save then
// writes. Only the first failure and the recovery are logged.
func TestMailStatsRetriesFailedLoad(t *testing.T) {
	now := mailStatsTestNow
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	saved := mailstats.New(func() time.Time { return now })
	if err = saved.Load(db, now); err != nil {
		t.Fatal(err)
	}
	saved.RecordQuarantine(now, "")
	if err = saved.Flush(db, now); err != nil {
		t.Fatal(err)
	}
	// Reads through a closed handle fail, the way a broken store does.
	_ = db.Close()
	prevStore := store.Global()
	t.Cleanup(func() { store.SetGlobal(prevStore) })
	store.SetGlobal(db)

	logs := captureCSMLog(t)
	t.Cleanup(func() { logs() })
	d := newMailStatsTestDaemon(t, &now)
	d.restoreMailStats()
	d.handleEximLine(mailStatsRejectLine, alert.Observation{ObservedAt: now}, &config.Config{})
	d.persistMailStats()

	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	store.SetGlobal(reopened)
	d.persistMailStats()
	d.persistMailStats()

	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	if got := d.mailStats.Overview(from, to).Totals; got.Quarantined != 1 || got.Rejects[mailstats.ClassSpam] != 1 {
		t.Fatalf("totals after the retry = %+v, want the stored quarantine merged once plus the live reject", got)
	}
	fresh := mailstats.New(func() time.Time { return now })
	if err = fresh.Load(reopened, now); err != nil {
		t.Fatal(err)
	}
	if got := fresh.Overview(from, to).Totals; got.Quarantined != 1 || got.Rejects[mailstats.ClassSpam] != 1 {
		t.Fatalf("stored totals = %+v, want the merged counts written", got)
	}
	out := logs()
	if n := strings.Count(out, "mail stats load failed"); n != 1 {
		t.Fatalf("load failure logged %d times, want once:\n%s", n, out)
	}
	if n := strings.Count(out, "mail stats load succeeded"); n != 1 {
		t.Fatalf("load recovery logged %d times, want once:\n%s", n, out)
	}
}

// Without a state store the periodic writer still prunes, so the counter
// stays bounded. It exits on stop.
func TestMailStatsPersistenceLoopPrunesWithoutStore(t *testing.T) {
	prevStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prevStore) })
	prevInterval := mailStatsPersistInterval
	mailStatsPersistInterval = 5 * time.Millisecond
	t.Cleanup(func() { mailStatsPersistInterval = prevInterval })

	now := mailStatsTestNow
	d := newMailStatsTestDaemon(t, &now)
	d.handleEximLine(mailStatsRejectLine, alert.Observation{ObservedAt: now}, &config.Config{})
	from, to := now.Add(-time.Hour), now
	if got := d.mailStats.Overview(from, to).Totals.Rejects[mailstats.ClassSpam]; got != 1 {
		t.Fatalf("spam rejects before pruning = %d, want 1", got)
	}
	now = now.Add(mailstats.Retention + time.Hour)
	d.startMailStatsPersistence()

	deadline := time.Now().Add(5 * time.Second)
	for d.mailStats.Overview(from, to).Totals.Rejects[mailstats.ClassSpam] != 0 {
		if time.Now().After(deadline) {
			t.Fatal("periodic writer never pruned a bucket past retention")
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(d.stopCh)
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("periodic writer did not exit on stop")
	}
}

// The restore runs when the log watchers start, before the first line is
// read.
func TestStartLogWatchersRestoresMailStats(t *testing.T) {
	db := openStoreForTest(t)
	now := mailStatsTestNow
	saved := mailstats.New(func() time.Time { return now })
	if err := saved.Load(db, now); err != nil {
		t.Fatal(err)
	}
	saved.RecordQuarantine(now, "")
	if err := saved.Flush(db, now); err != nil {
		t.Fatal(err)
	}

	d := newMailStatsTestDaemon(t, &now)
	d.hijackDetector = NewPasswordHijackDetector(d.cfg, d.alertCh, d.stopCh)
	d.startLogWatchers()
	t.Cleanup(func() {
		close(d.stopCh)
		d.wg.Wait()
	})

	if got := d.mailStats.Overview(now.Add(-time.Hour), now.Add(time.Hour)).Totals.Quarantined; got != 1 {
		t.Fatalf("restored quarantines = %d, want 1", got)
	}
}

// An arrival counts for the hosting account of its submitter: the domain
// owner of an authenticated mailbox, or the local caller when it is a
// hosting account. A submitter that resolves to no account counts only as
// unresolved. Inbound mail has no submitter, and a bounce from the null
// sender is not a send.
func TestEximArrivalCountsSubmitterAccount(t *testing.T) {
	t.Cleanup(checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
		if domain == "example.com" {
			return "exampleacct", true
		}
		return "", false
	}))
	t.Cleanup(checks.SetHostingAccountLookupForTest(func(name string) string {
		if name == "exampleacct" {
			return name
		}
		return ""
	}))
	now := mailStatsTestNow
	d := newMailStatsTestDaemon(t, &now)
	for _, line := range []string{
		`2026-10-20 12:10:00 1tAbCd-000011-Ab <= user@example.com H=(client.example.net) [203.0.113.20]:50000 P=esmtpsa A=dovecot_login:user@example.com S=1200 for b@example.net`,
		`2026-10-20 12:10:30 1tAbCd-000012-Ab <= exampleacct@host.example.com U=exampleacct P=local S=800 for b@example.net`,
		`2026-10-20 12:10:45 1tAbCd-000015-Ab <= <> R=1tAbCd-000012-Ab U=mailnull P=local S=1500 for exampleacct@host.example.com`,
		`2026-10-20 12:11:00 1tAbCd-000013-Ab <= other@example.net H=(client.example.net) [203.0.113.21]:50001 P=esmtpsa A=dovecot_login:other@example.net S=900 for b@example.net`,
		`2026-10-20 12:11:30 1tAbCd-000014-Ab <= a@example.net H=mx.example.net [198.51.100.9]:41000 P=esmtps S=2000 for user@example.com`,
		`2026-10-20 12:12:00 1tAbCd-000011-Ab => b@example.net R=dkim_lookuphost T=dkim_remote_smtp H=mx.example.net [198.51.100.10]`,
	} {
		d.handleEximLine(line, alert.Observation{ObservedAt: now}, &config.Config{})
	}
	got := d.mailStats.TopSenders(now.Add(-time.Hour), now, 0)
	want := mailstats.SendersReport{Accounts: []mailstats.AccountSends{{Account: "exampleacct", Messages: 2}}, Total: 3, Unresolved: 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("senders = %+v, want %+v", got, want)
	}
}
