package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
)

// dryRunBlocker is the firewall with auto_response.dry_run on: it applies
// nothing and reports each block it would have made.
type dryRunBlocker struct{ applyWiringBlocker }

func (b *dryRunBlocker) BlockIPOutcome(ip, reason string, timeout time.Duration) (firewall.BlockOutcome, error) {
	if _, err := b.applyWiringBlocker.BlockIPOutcome(ip, reason, timeout); err != nil {
		return "", err
	}
	return firewall.BlockOutcomeDryRun, nil
}

func (b *dryRunBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	_, err := b.BlockIPOutcome(ip, reason, timeout)
	return err
}

// Spec 5.5: only a verified full-address block marks an address blocked
// in the attack database. In dry run a scan's would-be block is a Warning
// finding, not a block, so the attack database keeps the address
// unblocked; a block that applied still marks it.
func TestDispatchBatchMarksOnlyAppliedBlocks(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		cfg, live, _ := suppressionResponseSetup(t)
		blocker := checks.IPBlocker(live)
		calls := func() int { return len(live.calls) }
		if dryRun {
			fake := &dryRunBlocker{}
			blocker, calls = fake, func() int { return len(fake.calls) }
		}
		checks.SetIPBlocker(blocker)
		db := attackdb.NewForTest(nil)
		previous := attackdb.Global()
		attackdb.SetGlobal(db)
		t.Cleanup(func() { attackdb.SetGlobal(previous) })
		d := suppressionTestDaemon(t, cfg, nil)

		d.dispatchBatch([]alert.Finding{smtpBruteForceFinding("192.0.2.27")})

		if calls() != 1 {
			t.Fatalf("dry run %t: block calls = %d, want 1", dryRun, calls())
		}
		rec := db.LookupIP("192.0.2.27")
		if rec == nil || rec.AutoBlocked == dryRun {
			t.Fatalf("dry run %t: attack record = %+v", dryRun, rec)
		}
	}
}

// The async block sources (challenge escalation, central, incident) mark
// only their applied blocks too.
func TestRecordAppliedBlocksMarksOnlyAppliedBlocks(t *testing.T) {
	cfg, _, _ := suppressionResponseSetup(t)
	db := attackdb.NewForTest(map[string]*attackdb.IPRecord{"192.0.2.28": {IP: "192.0.2.28"}, "192.0.2.29": {IP: "192.0.2.29"}})
	previous := attackdb.Global()
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	d := suppressionTestDaemon(t, cfg, nil)

	d.recordAppliedBlocks([]alert.Finding{
		{Severity: alert.Critical, Check: "auto_block", Message: "AUTO-BLOCK: 192.0.2.28 blocked", SourceIP: "192.0.2.28"},
		{Severity: alert.Warning, Check: "auto_block", Message: "AUTO-BLOCK [dry-run]: 192.0.2.29 would be blocked", SourceIP: "192.0.2.29"},
	})

	if rec := db.LookupIP("192.0.2.28"); rec == nil || !rec.AutoBlocked {
		t.Fatalf("applied block not marked: %+v", rec)
	}
	if rec := db.LookupIP("192.0.2.29"); rec == nil || rec.AutoBlocked {
		t.Fatalf("dry-run warning marked its address blocked: %+v", rec)
	}
}
