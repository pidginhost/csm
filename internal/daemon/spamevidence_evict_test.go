package daemon

import (
	"fmt"
	"net/netip"
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
	want := "Spam evidence budget reached: dropped 2 records of single or faded evidence; " + network + " held 11"
	if f.Severity != alert.Warning || f.Message != want || !f.Timestamp.Equal(at) {
		t.Fatalf("finding = %v %q at %v, want Warning %q at %v", f.Severity, f.Message, f.Timestamp, want, at)
	}
	if f.Details == "" || f.SourceIP != "" {
		t.Fatalf("details %q, source address %q; want details and no source address", f.Details, f.SourceIP)
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

	d.recordSpamEvidence(scanOf(spamLine(sender(12))), at, cfg)
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("findings after the twelfth sender: %+v", got)
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

	d.recordStalwartVerdict(sender(12), true, at, cfg)
	if got := drainAlerts(d.alertCh); len(got) != 0 {
		t.Fatalf("findings after the twelfth sender: %+v", got)
	}
}
