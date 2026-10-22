//go:build linux

package firewall

import (
	"errors"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// A reply's remaining lifetime belongs to the read, not the later instant
// at which recovery resumes processing it.
func TestProveFirewallRetirementPinsReadTime(t *testing.T) {
	at := time.Date(2026, 1, 2, 6, 0, 0, 0, time.UTC)
	a := retireFixture(at)
	kept := BlockedEntry{IP: "192.0.2.2", BlockedAt: a.CreatedAt, ExpiresAt: at.Add(time.Hour)}
	a.Before.Blocked = append(a.Before.Blocked, kept)
	a.After.Blocked = append(a.After.Blocked, kept)
	a = withBatchKernelEvidence(a)
	a.KernelBefore[0].Elements = desiredActionSets(a.Before, true, a.CreatedAt)["blocked_ips"]
	live := liveElements(a.Before, at)
	if _, ok, err := retireEngine(t, live, at).ProveFirewallRetirement(a); err != nil || !ok {
		t.Fatalf("matching kept lease did not prove retirement: proven %v, error %v", ok, err)
	}
	// The kept row expires early in the kernel, outside verification slack.
	live[1].Expires = 30 * time.Minute
	k := retireEngine(t, live, at)
	clock := at
	k.e.leaseClock = func() (time.Time, time.Time) { return clock, clock }
	dial := k.e.conn.TestDial
	reads := 0
	k.e.conn.TestDial = func(req []netlink.Message) ([]netlink.Message, error) {
		reply, err := dial(req)
		if len(req) > 0 && uint16(req[0].Header.Type)&0xff == unix.NFT_MSG_GETSETELEM {
			reads++
			clock = at.Add(30 * time.Minute)
		}
		return reply, err
	}
	if _, ok, err := k.ProveFirewallRetirement(a); err != nil || ok {
		t.Fatalf("shortened kept lease proved retirement: proven %v, error %v", ok, err)
	}
	if reads != 1 {
		t.Fatalf("element reads = %d, want 1", reads)
	}
}

func TestProveFirewallRetirementRejectsSlowRead(t *testing.T) {
	at := time.Now().UTC().Round(0)
	a := withBatchKernelEvidence(retireFixture(at))
	k := retireEngine(t, liveElements(a.Before, at), at)
	dial := k.e.conn.TestDial
	reads := 0
	k.e.conn.TestDial = func(req []netlink.Message) ([]netlink.Message, error) {
		reply, err := dial(req)
		if len(req) > 0 && uint16(req[0].Header.Type)&0xff == unix.NFT_MSG_GETSETELEM {
			reads++
			// The socket deadline cannot catch a pause after the reply arrives.
			time.Sleep(2100 * time.Millisecond)
		}
		return reply, err
	}
	if _, ok, err := k.ProveFirewallRetirement(a); ok || err == nil {
		t.Fatalf("stale read proved retirement: proven %v, error %v", ok, err)
	}
	if reads != 1 {
		t.Fatalf("element reads = %d, want 1", reads)
	}
}

func TestProveFirewallRetirementRequiresTrustedClock(t *testing.T) {
	at := time.Now().UTC().Round(0)
	a := withBatchKernelEvidence(retireFixture(at))
	cause := errors.New("clock unavailable")
	for _, mode := range []string{"no lifecycle", "missing", "degraded", "failed", "failed with true", "trusted"} {
		t.Run(mode, func(t *testing.T) {
			k := retireEngine(t, liveElements(a.Before, at), at)
			calls, reads := 0, 0
			k.e.lifecycle.RetirementClockTrusted = func() (bool, error) {
				calls++
				switch mode {
				case "failed":
					return false, cause
				case "failed with true":
					return true, cause
				default:
					return mode == "trusted", nil
				}
			}
			switch mode {
			case "no lifecycle":
				k.e.lifecycle = nil
			case "missing":
				k.e.lifecycle.RetirementClockTrusted = nil
			}
			dial := k.e.conn.TestDial
			k.e.conn.TestDial = func(req []netlink.Message) ([]netlink.Message, error) {
				reads++
				return dial(req)
			}
			k.e.mu.Lock()
			provenAt, ok, err := k.ProveFirewallRetirement(a)
			k.e.mu.Unlock()
			failed := mode == "failed" || mode == "failed with true"
			wantCalls := 1
			if mode == "no lifecycle" || mode == "missing" {
				wantCalls = 0
			}
			if ok != (mode == "trusted") || failed && !errors.Is(err, cause) || !failed && err != nil || calls != wantCalls {
				t.Fatalf("clock attestation: proven %v, error %v, calls %d", ok, err, calls)
			}
			if !ok && (reads != 0 || !provenAt.IsZero()) || ok && (reads == 0 || !provenAt.Equal(at)) {
				t.Fatalf("clock proof order: reads %d, instant %v", reads, provenAt)
			}
		})
	}
}

func TestProveFirewallRetirementKeepsVictimAndIPv6Proof(t *testing.T) {
	at := time.Now().UTC().Round(0)
	a := withBatchKernelEvidence(retireFixture(at))
	// A removed timed victim still held by the kernel defeats a lease clock
	// that says it has expired, just as a live member does.
	victim := BlockedEntry{IP: "203.0.113.90", BlockedAt: a.CreatedAt.Add(-time.Hour), ExpiresAt: a.CreatedAt.Add(time.Minute)}
	a.Before.Blocked = append(a.Before.Blocked, victim)
	k := retireEngine(t, liveElements(a.Before, a.CreatedAt), at)
	if _, ok, err := k.ProveFirewallRetirement(a); err != nil || ok {
		t.Fatalf("live victim retired: %v %v", ok, err)
	}
	// The engine has no configured IPv6 set. Evidence and a kept IPv6 row
	// still require that row; an empty or missing set cannot prove it.
	a = retireFixture(at)
	kept := BlockedEntry{IP: "2001:db8::99", Reason: "kept"}
	a.Before.Blocked = append(a.Before.Blocked, kept)
	a.After.Blocked = append(a.After.Blocked, kept)
	a = withBatchKernelEvidence(a)
	// ValidateEvidence accepts an absent IPv6 set with no recorded elements.
	// The retirement proof must nevertheless require this committed row.
	a.KernelBefore[1].Exists = false
	a.KernelBefore[1].Elements = nil
	a.KernelAfter[1].Exists = false
	a.KernelAfter[1].Elements = nil
	k = retireEngine(t, liveElements(a.Before, at), at)
	if _, ok, err := k.ProveFirewallRetirement(a); err != nil || ok {
		t.Fatalf("missing kept IPv6 row retired: %v %v", ok, err)
	}
}

func TestProveFirewallRetirementRequiresBlockEvidence(t *testing.T) {
	at := time.Now().UTC().Round(0)
	row := BlockedEntry{IP: "203.0.113.80", ExpiresAt: at.Add(-time.Hour)}
	a := FirewallAction{Request: ActionRequest{Operation: "block", Target: row.IP, TTL: time.Hour}, Phase: "unknown", CreatedAt: at.Add(-2 * time.Hour), Before: FirewallState{Blocked: []BlockedEntry{row}}, After: FirewallState{Blocked: []BlockedEntry{row}}}
	k := retireEngine(t, liveElements(a.Before, a.CreatedAt), at)
	if _, ok, err := k.ProveFirewallRetirement(a); err != nil || ok {
		t.Fatalf("retired without saved block evidence: %v %v", ok, err)
	}
}

type retirementClockStore struct {
	*batchPlanStore
	action  FirewallAction
	retired bool
}

func (s *retirementClockStore) PendingFirewallActions() ([]FirewallAction, error) {
	return []FirewallAction{s.action}, nil
}

func (s *retirementClockStore) TransitionFirewallAction(_ string, phase, detail string, at time.Time) (FirewallAction, error) {
	s.action.Phase, s.action.Detail, s.action.UpdatedAt = phase, detail, at
	return s.action, nil
}

func (s *retirementClockStore) RetireFirewallAction(string, time.Time) (FirewallAction, error) {
	s.action.Retired, s.retired = true, true
	return s.action, nil
}

func TestProveFirewallRetirementAttestsUnderEngineLock(t *testing.T) {
	at := time.Now().UTC().Round(0)
	a := withBatchKernelEvidence(retireFixture(at))
	k := retireEngine(t, liveElements(a.Before, at), at)
	store := &retirementClockStore{batchPlanStore: &batchPlanStore{state: a.Before}, action: a}
	k.e.lifecycle.Store = store
	calls := 0
	k.e.lifecycle.RetirementClockTrusted = func() (bool, error) {
		calls++
		if k.e.mu.TryLock() {
			k.e.mu.Unlock()
			return false, errors.New("clock attested outside engine lock")
		}
		return true, nil
	}
	if err := k.e.RecoverActions(); err != nil || calls != 1 || !store.retired {
		t.Fatalf("engine recovery: error %v, attestations %d, retired %v", err, calls, store.retired)
	}
}
