//go:build linux

package firewall

import (
	"errors"
	"net"
	"testing"

	"github.com/google/nftables"
)

// C1: one dump per set per call, and the snapshot must answer for every IP in
// it. The per-IP IsBlockedLive path dumps the whole set on every lookup, which
// made a reconcile pass cost one full dump per tracked IP.
func TestEngineLiveBlockedSetDumpsEachSetOnce(t *testing.T) {
	v4 := &nftables.Set{Name: "csm_blocked"}
	v6 := &nftables.Set{Name: "csm_blocked6"}
	dumps := map[string]int{}

	e := &Engine{
		setBlocked:  v4,
		setBlocked6: v6,
		liveBlockedDump: func(set *nftables.Set) ([]nftables.SetElement, error) {
			dumps[set.Name]++
			if set.Name == v4.Name {
				return []nftables.SetElement{
					{Key: net.ParseIP("203.0.113.7").To4()},
					{Key: net.ParseIP("203.0.113.8").To4()},
				}, nil
			}
			return []nftables.SetElement{{Key: net.ParseIP("2001:db8::1").To16()}}, nil
		},
	}

	snap, err := e.LiveBlockedSet()
	if err != nil {
		t.Fatalf("LiveBlockedSet: %v", err)
	}
	if dumps[v4.Name] != 1 || dumps[v6.Name] != 1 {
		t.Errorf("dumps = %v, want exactly one per set", dumps)
	}
	if !snap.HasV4 || !snap.HasV6 {
		t.Errorf("coverage = (v4 %v, v6 %v), want both covered", snap.HasV4, snap.HasV6)
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.8", "2001:db8::1"} {
		if blocked, known := snap.Contains(ip); !blocked || !known {
			t.Errorf("Contains(%q) = (%v, %v), want (true, true)", ip, blocked, known)
		}
	}
	if blocked, known := snap.Contains("203.0.113.9"); blocked || !known {
		t.Errorf("Contains(unblocked) = (%v, %v), want (false, true)", blocked, known)
	}
}

// A nil set means that family is not managed at all (firewall.ipv6 disabled).
// It must come back uncovered, never as an empty "nothing blocked" set.
func TestEngineLiveBlockedSetLeavesMissingFamilyUncovered(t *testing.T) {
	v4 := &nftables.Set{Name: "csm_blocked"}
	e := &Engine{
		setBlocked: v4,
		liveBlockedDump: func(*nftables.Set) ([]nftables.SetElement, error) {
			return []nftables.SetElement{{Key: net.ParseIP("203.0.113.7").To4()}}, nil
		},
	}

	snap, err := e.LiveBlockedSet()
	if err != nil {
		t.Fatalf("LiveBlockedSet: %v", err)
	}
	if snap.HasV6 {
		t.Error("v6 reported as covered despite a nil set")
	}
	if blocked, known := snap.Contains("2001:db8::1"); blocked || known {
		t.Errorf("v6 lookup = (%v, %v), want (false, false) so callers keep the cached answer", blocked, known)
	}
}

func TestEngineLiveBlockedSetPropagatesDumpError(t *testing.T) {
	wantErr := errors.New("netlink boom")
	e := &Engine{
		setBlocked: &nftables.Set{Name: "csm_blocked"},
		liveBlockedDump: func(*nftables.Set) ([]nftables.SetElement, error) {
			return nil, wantErr
		},
	}

	if _, err := e.LiveBlockedSet(); !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want it to wrap %v so the caller keeps cached state", err, wantErr)
	}
}

func TestEngineLiveBlockedSetErrorsWithoutSets(t *testing.T) {
	e := &Engine{}
	if _, err := e.LiveBlockedSet(); err == nil {
		t.Error("expected an error when neither blocked set exists, got nil")
	}
}
