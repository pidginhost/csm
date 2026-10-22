//go:build linux

package firewall

import (
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/pidginhost/csm/internal/actionlog"
)

// retireEngine reads live from a read-only kernel fixture, with its lease
// clock at at.
func retireEngine(t *testing.T, live []nftables.SetElement, at time.Time) engineActionKernel {
	t.Helper()
	e := newBlockedSetWireTestEngine(t, leaseActionReadConn(t, live))
	e.expiryClock = func() time.Time { return at }
	e.leaseClock = func() (time.Time, time.Time) { return at, at }
	e.lifecycle = &Lifecycle{RetirementClockTrusted: func() (bool, error) { return true, nil }}
	return engineActionKernel{e}
}

// liveElements is what the kernel holds for state's IPv4 blocks at at.
func liveElements(state FirewallState, at time.Time) []nftables.SetElement {
	var out []nftables.SetElement
	for _, elem := range desiredActionSets(state, false, at)["blocked_ips"] {
		var left time.Duration
		if !elem.ExpiresAt.IsZero() {
			left = elem.ExpiresAt.Sub(at)
		}
		out = append(out, nftables.SetElement{Key: elem.Key, Comment: elem.Comment, Timeout: left, Expires: left})
	}
	return out
}

// The kernel proves a retirement only when its blocked sets hold exactly the
// retired state at the lease clock's instant.
func TestProveFirewallRetirementReadsTheKernel(t *testing.T) {
	at := time.Date(2026, 1, 2, 6, 0, 0, 0, time.UTC)
	a := withBatchKernelEvidence(retireFixture(at))
	k := retireEngine(t, liveElements(a.Before, at), at)
	if proven, ok, err := k.ProveFirewallRetirement(a); err != nil || !ok || !proven.Equal(at) {
		t.Fatalf("retirement over the retired state = %v, %v, %v", proven, ok, err)
	}
	// The lease clock says the members expired, but the kernel still holds
	// one for another hour: the lease runs ahead of the kernel.
	still := liveElements(a.After, a.CreatedAt.Add(time.Minute))
	for i := range still {
		if still[i].Timeout > 0 {
			still[i].Timeout, still[i].Expires = time.Hour, time.Hour
		}
	}
	k = retireEngine(t, still, at)
	if _, ok, err := k.ProveFirewallRetirement(a); err != nil || ok {
		t.Fatalf("retirement with a member still in the kernel = %v, %v", ok, err)
	}
	// Before the members expire there is nothing to prove, whatever the
	// kernel holds.
	early := a.CreatedAt.Add(30 * time.Minute)
	k = retireEngine(t, nil, early)
	if _, ok, err := k.ProveFirewallRetirement(a); err != nil || ok {
		t.Fatalf("retirement before expiry = %v, %v", ok, err)
	}
	// A set the evidence says exists is gone from the kernel.
	gone := a
	gone.KernelBefore = append([]ActionSet(nil), a.KernelBefore...)
	gone.KernelAfter = append([]ActionSet(nil), a.KernelAfter...)
	gone.KernelBefore[1].Exists, gone.KernelAfter[1].Exists = true, true
	k = retireEngine(t, liveElements(a.Before, at), at)
	if _, ok, err := k.ProveFirewallRetirement(gone); err != nil || ok {
		t.Fatalf("retirement with a set gone = %v, %v", ok, err)
	}
	changed := a
	changed.KernelBefore = append([]ActionSet(nil), a.KernelBefore...)
	changed.KernelBefore[1].Exists = true
	if _, ok, err := retireEngine(t, liveElements(a.Before, at), at).ProveFirewallRetirement(changed); err != nil || ok {
		t.Fatalf("retirement across a set topology change = %v, %v", ok, err)
	}
	broken := a
	broken.KernelAfter = nil
	if _, ok, err := retireEngine(t, nil, at).ProveFirewallRetirement(broken); err == nil || ok {
		t.Fatalf("retirement over incomplete evidence = %v, %v", ok, err)
	}
}

// A retired action's events report expired_unproven, one per member.
func TestFirewallAuditMarksRetiredOutcome(t *testing.T) {
	sink := captureFirewallAudit(t)
	a := batchEvidence()
	a.Phase, a.Retired = "unknown", true
	if err := writeFirewallActionAudit(a); err != nil {
		t.Fatal(err)
	}
	if len(sink.batch) != 1 || len(sink.batch[0]) != 2 {
		t.Fatalf("retired batch audit = %#v", sink.batch)
	}
	for _, r := range sink.batch[0] {
		if r.Result != actionlog.Result("expired_unproven") {
			t.Errorf("retired member record result = %q", r.Result)
		}
	}
}
