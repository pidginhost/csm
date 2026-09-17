package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	bolt "go.etcd.io/bbolt"
)

// BenchmarkFirewallTerminalTransitionAtCap measures the cost every durable
// action pays once the journal is full: recording the outcome walks the whole
// retained index to enforce the caps.
func BenchmarkFirewallTerminalTransitionAtCap(b *testing.B) {
	db, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	s := firewall.ActionStore(db)
	if _, err := s.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		b.Fatal(err)
	}
	at := time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC)
	admit := func(id string, when time.Time) {
		state, revision, err := s.ReadFirewallState()
		if err != nil {
			b.Fatal(err)
		}
		// Replace one block so each action has a distinct, fixed-size state.
		// Growing snapshots hit the byte cap before the action cap and make
		// the measured workload change with the benchmark iteration count.
		next := firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "198.51.100.1", Reason: "bench", BlockedAt: when}}}
		plan := firewall.FirewallAction{
			Request:   firewall.ActionRequest{ID: id, Operation: "block", Target: "198.51.100.1", Actor: "bench", Source: "manual"},
			Before:    state,
			After:     next,
			Revision:  revision,
			CreatedAt: when,
		}
		if _, _, err := s.AdmitFirewallAction(plan); err != nil {
			b.Fatal(err)
		}
		for _, phase := range []string{"executing", "applied"} {
			if _, err := s.TransitionFirewallAction(id, phase, "", when); err != nil {
				b.Fatal(err)
			}
		}
	}
	deliver := func() {
		pending, err := s.FirewallAuditPending()
		if err != nil {
			b.Fatal(err)
		}
		for _, a := range pending {
			if err := s.AcknowledgeFirewallAudit(a.Request.ID, a.AuditVersion); err != nil {
				b.Fatal(err)
			}
		}
	}
	// Fill the journal to the retained-action cap first.
	for i := range firewallActionRetention.Actions {
		id := fmt.Sprintf("fill-%06d", i)
		admit(id, at.Add(time.Duration(i)*time.Second))
		if _, err := s.TransitionFirewallAction(id, "verified", "", at.Add(time.Duration(i)*time.Second)); err != nil {
			b.Fatal(err)
		}
		deliver()
	}
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		entries, _, err := readFirewallActionHistory(tx)
		if err != nil {
			return err
		}
		if len(entries) != firewallActionRetention.Actions {
			return fmt.Errorf("retained %d actions, want %d", len(entries), firewallActionRetention.Actions)
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		b.StopTimer()
		id := fmt.Sprintf("bench-%06d", i)
		when := at.Add(time.Duration(firewallActionRetention.Actions+i) * time.Second)
		admit(id, when)
		b.StartTimer()
		if _, err := s.TransitionFirewallAction(id, "verified", "", when); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		deliver()
		b.StartTimer()
	}
}
