package daemon

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// evictionWarning returns the only finding on the alert channel, which must
// be the eviction warning.
func evictionWarning(t *testing.T, d *Daemon) alert.Finding {
	t.Helper()
	got := drainAlerts(d.alertCh)
	if len(got) != 1 || got[0].Check != "spam_evidence_evicted" {
		t.Fatalf("findings = %+v, want one spam_evidence_evicted", got)
	}
	return got[0]
}

// checkEvictionWarning compares f with the report of a pass over eleven
// single-verdict senders in network at budget 10, which drops two.
func checkEvictionWarning(t *testing.T, f alert.Finding, network string, at time.Time) {
	t.Helper()
	want := "Spam evidence budget reached: dropped 2 records, weakest evidence first; the most crowded network, " + network + ", held 11"
	if f.Severity != alert.Warning || f.Message != want || !f.Timestamp.Equal(at) {
		t.Fatalf("finding = %v %q at %v, want Warning %q at %v", f.Severity, f.Message, f.Timestamp, want, at)
	}
	const details = "Records with attack findings, a block or a recent mail login attack are never dropped. Records with two or more verdicts are dropped only when such records fill nine tenths of the budget. The named network held the most spam-only records when the drop began. That count alone does not show who sent the flood; a small count means the senders are spread over many networks."
	if f.Details != details || f.SourceIP != "" {
		t.Fatalf("details %q, source address %q; want %q and no source address", f.Details, f.SourceIP, details)
	}
}

func TestSpamEvidenceEvictionRaisesWarning(t *testing.T) {
	d := newTestDaemon(t)
	adb := useTestAttackDB(t)
	adb.SetMailBudget(10)
	cfg := &config.Config{}
	cfg.EmailProtection.Antispam = config.AntispamConfig{Enabled: true, RejectScore: 15, TagScore: 6}
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	sender := func(n int) string { return fmt.Sprintf("2001:db8:5:%x::1", n) }

	for n := 1; n <= 10; n++ {
		d.recordSpamEvidence(scanOf(spamLine(sender(n))), at, cfg)
	}
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("findings within the budget: %+v", got)
	}
	d.recordSpamEvidence(scanOf(spamLine(sender(11))), at, cfg)
	checkEvictionWarning(t, evictionWarning(t, d), "2001:db8:5::/48", at)

	for n := 12; n <= 13; n++ {
		d.recordSpamEvidence(scanOf(spamLine(sender(n))), at, cfg)
	}
	if got := len(adb.AllRecords()); got != 9 {
		t.Fatalf("records = %d, want 9 after two eviction passes", got)
	}
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("findings after the second eviction pass: %+v", got)
	}
}

func TestStalwartVerdictEvictionRaisesWarning(t *testing.T) {
	d := newTestDaemon(t)
	adb := useTestAttackDB(t)
	adb.SetMailBudget(10)
	cfg := &config.Config{}
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	sender := func(n int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:6:%x::1", n)) }

	for n := 1; n <= 10; n++ {
		d.recordStalwartVerdict(sender(n), true, at, cfg)
	}
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("findings within the budget: %+v", got)
	}
	d.recordStalwartVerdict(sender(11), true, at, cfg)
	checkEvictionWarning(t, evictionWarning(t, d), "2001:db8:6::/48", at)

	for n := 12; n <= 13; n++ {
		d.recordStalwartVerdict(sender(n), true, at, cfg)
	}
	if got := len(adb.AllRecords()); got != 9 {
		t.Fatalf("records = %d, want 9 after two eviction passes", got)
	}
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("findings after the second eviction pass: %+v", got)
	}
}

func TestMailEvictionWarningAccumulatesSuppressedDrops(t *testing.T) {
	d := newTestDaemon(t)
	adb := useTestAttackDB(t)
	adb.SetMailBudget(10)
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	for n := 1; n <= 11; n++ {
		d.recordMailVerdict(adb, fmt.Sprintf("2001:db8:7:%x::1", n), true, at)
	}
	checkEvictionWarning(t, evictionWarning(t, d), "2001:db8:7::/48", at)
	for n := 12; n <= 13; n++ {
		d.recordMailVerdict(adb, fmt.Sprintf("2001:db8:7:%x::1", n), true, at.Add(23*time.Hour))
	}
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("warning before a day elapsed: %+v", got)
	}
	for n := 14; n <= 15; n++ {
		d.recordMailVerdict(adb, fmt.Sprintf("2001:db8:7:%x::1", n), true, at.Add(24*time.Hour))
	}
	f := evictionWarning(t, d)
	want := "Spam evidence budget reached: dropped 4 records, weakest evidence first; the most crowded network, 2001:db8:7::/48, held 11"
	if f.Message != want || !f.Timestamp.Equal(at.Add(24*time.Hour)) {
		t.Fatalf("next warning = %q at %v, want %q after one day", f.Message, f.Timestamp, want)
	}
	if got := len(adb.AllRecords()); got != 9 {
		t.Fatalf("records = %d, want 9 after three eviction passes", got)
	}
}

// A flood that stops leaves drops no later verdict reports: the periodic
// check hands them to the same warning.
func TestPendingEvictionRaisesWarning(t *testing.T) {
	d := newTestDaemon(t)
	adb := useTestAttackDB(t)
	adb.SetMailBudget(10)
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	later := at.Add(24 * time.Hour)
	for n := 1; n <= 11; n++ {
		d.recordMailVerdict(adb, fmt.Sprintf("2001:db8:7:%x::1", n), true, at)
	}
	checkEvictionWarning(t, evictionWarning(t, d), "2001:db8:7::/48", at)
	d.warnSpamEvidenceEvicted(adb.PendingEviction(later), later)
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("warning with nothing pending: %+v", got)
	}

	for n := 12; n <= 13; n++ {
		d.recordMailVerdict(adb, fmt.Sprintf("2001:db8:7:%x::1", n), true, at.Add(time.Hour))
	}
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("warning before a day elapsed: %+v", got)
	}
	d.warnSpamEvidenceEvicted(adb.PendingEviction(later), later)
	checkEvictionWarning(t, evictionWarning(t, d), "2001:db8:7::/48", later)
	d.warnSpamEvidenceEvicted(adb.PendingEviction(later), later)
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("pending drops warned twice: %+v", got)
	}
}

func TestMailEvictionWarningLogsWhenQueueFull(t *testing.T) {
	d := newTestDaemon(t)
	d.alertCh = make(chan alert.Finding, 1)
	d.alertCh <- alert.Finding{Check: "test_alert"}
	adb := useTestAttackDB(t)
	adb.SetMailBudget(10)
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	logged := captureAppliedBlockStderr(t, func() {
		for n := 1; n <= 11; n++ {
			d.recordMailVerdict(adb, fmt.Sprintf("2001:db8:5:%x::1", n), true, at)
		}
	})
	want := "spam_evidence_evicted: Spam evidence budget reached: dropped 2 records, weakest evidence first; the most crowded network, 2001:db8:5::/48, held 11\n"
	if !strings.HasSuffix(logged, want) || strings.Count(logged, "\n") != 1 {
		t.Fatalf("stderr = %q, want one eviction warning ending in %q", logged, want)
	}
	if got := atomic.LoadInt64(&d.droppedAlerts); got != 1 {
		t.Fatalf("dropped alerts = %d, want 1", got)
	}
	if got := drainAlerts(d.alertCh); len(got) != 1 || got[0].Check != "test_alert" {
		t.Fatalf("queue = %+v, want the original finding only", got)
	}
	if got := len(adb.AllRecords()); got != 9 {
		t.Fatalf("records = %d, want 9 despite the full queue", got)
	}
}
