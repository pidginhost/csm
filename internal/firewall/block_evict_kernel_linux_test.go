//go:build linux && nftkernel

package firewall

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// kernelVictim applies an admission block of ip that lasts ttl and returns
// it as a victim the ledger could claim.
func kernelVictim(t *testing.T, e *Engine, ip string, ttl time.Duration) BlockVictim {
	t.Helper()
	m := kernelBlockMember(victimAction(1), ip, ttl)
	if results, err := e.ApplyBlockBatch([]BlockMember{m}); err != nil || effects(results) != "applied/" {
		t.Fatalf("victim batch = %+v, %v", results, err)
	}
	return BlockVictim{Action: m.Action, IP: ip, ExpiresAt: m.ExpiresAt}
}

// In a full set a member takes its victim's slot in one transaction: the
// kernel then holds the member and not the victim, and the readback
// proves both, in each address family.
func TestKernelBlockBatchEvictsAVictimInOneTransaction(t *testing.T) {
	for _, ip := range []string{"203.0.113.60", "2001:db8::60"} {
		t.Run(ip, func(t *testing.T) {
			e := newKernelBatchEngine(t)
			e.cfg.DenyTempIPLimit = 1
			victim := kernelVictim(t, e, ip, time.Hour)
			m := kernelBlockMember("act_evict", "203.0.113.21", time.Hour)
			m.Victim = victim
			results, err := e.ApplyBlockBatch([]BlockMember{m})
			if err != nil || effects(results) != "applied/" || results[0].Victim != VictimRemoved {
				t.Fatalf("results %+v, %v", results, err)
			}
			v4, v6 := kernelBlockElements(t, e, e.setBlocked), kernelBlockElements(t, e, e.setBlocked6)
			_, member := v4[m.IP]
			_, kept4 := v4[ip]
			_, kept6 := v6[ip]
			if !member || kept4 || kept6 {
				t.Fatalf("kernel holds %v and %v", v4, v6)
			}
		})
	}
}

// A victim that expires between the snapshot and the send makes the
// kernel reject the deletion with ENOENT, and with it the whole
// transaction: the member is not added and the victim is reported spared.
func TestKernelBlockBatchRejectsAVictimThatExpired(t *testing.T) {
	e := newKernelBatchEngine(t)
	e.cfg.DenyTempIPLimit = 1
	victim := kernelVictim(t, e, "203.0.113.60", 2*time.Second)
	m := kernelBlockMember("act_evict", "203.0.113.21", time.Hour)
	m.Victim = victim
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
		// The intent write runs after the snapshot proved the victim.
		time.Sleep(time.Until(victim.ExpiresAt) + 500*time.Millisecond)
		return prev(path, perm, v)
	}
	results, err := e.ApplyBlockBatch([]BlockMember{m})
	if err != nil || effects(results) != "failed/" || results[0].Victim != VictimSpared || !errors.Is(results[0].Err, syscall.ENOENT) {
		t.Fatalf("results %+v, %v", results, err)
	}
	v4 := kernelBlockElements(t, e, e.setBlocked)
	if _, member := v4[m.IP]; member {
		t.Fatalf("a rejected transaction added the member: %v", v4)
	}
}
