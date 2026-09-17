//go:build linux && nftkernel

package firewall

import (
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestKernelRulesetSnapshotTracksApplyAndDetectsTamper(t *testing.T) {
	isolatedFirewallNamespace(t)
	e, err := NewEngine(&FirewallConfig{Enabled: true, IPv6: true}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	current, applied, err := e.RulesetSnapshot()
	if err != nil || applied == "" || current != applied {
		t.Fatalf("initial snapshot current=%q applied=%q err=%v", current, applied, err)
	}
	if err := e.BlockIPForce("198.51.100.9", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	if current, _, err := e.RulesetSnapshot(); err != nil || current != applied {
		t.Fatalf("dynamic set membership changed structural snapshot: err=%v", err)
	}
	e.conn.InsertRule(&nftables.Rule{Table: e.table, Chain: e.chainIn, Exprs: []expr.Any{
		&expr.Verdict{Kind: expr.VerdictAccept},
	}})
	if err := e.conn.Flush(); err != nil {
		t.Fatal(err)
	}
	current, baseline, err := e.RulesetSnapshot()
	if err != nil || current == applied || baseline != applied {
		t.Fatalf("external accept was not distinguishable from applied rules: err=%v", err)
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if current, applied, err := e.RulesetSnapshot(); err != nil || current != applied {
		t.Fatalf("re-apply did not restore the snapshot: err=%v", err)
	}
}
