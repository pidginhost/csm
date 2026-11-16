//go:build linux

package firewall

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// liveDump makes e count its blocks from set dumps that hold one timed
// element per address in ips. A set named in unread fails its dump.
func liveDump(e *Engine, unread *nftables.Set, ips ...string) {
	e.liveBlockCounts = nil
	e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
		if set == unread {
			return nil, errors.New("dump failed")
		}
		var out []nftables.SetElement
		for _, ip := range ips {
			if of, key, err := e.resolveIPSet(ip, e.setBlocked, e.setBlocked6); err == nil && of == set {
				out = append(out, nftables.SetElement{Key: key, Timeout: time.Hour, Expires: time.Hour})
			}
		}
		return out, nil
	}
}

// At the cap a new block replaces a block the kernel still holds. A saved
// row whose element is gone frees no slot, so it is passed over, in the
// spray rows as in the rest, and for an operator's block beside admission
// rows.
func TestLegacyVictimHoldsALiveElement(t *testing.T) {
	gone := BlockedEntry{IP: "192.0.2.41", ExpiresAt: time.Now().Add(time.Minute)}
	spray := BlockedEntry{IP: "192.0.2.42", ExpiresAt: time.Now().Add(2 * time.Minute), Automatic: true, LoginSpray: true}
	live := BlockedEntry{IP: "192.0.2.43", ExpiresAt: time.Now().Add(time.Hour)}
	owned := BlockedEntry{IP: "192.0.2.46", ExpiresAt: time.Now().Add(time.Hour), ActionID: "act_owned"}
	for _, automatic := range []bool{false, true} {
		e := capEngine(t, 0, gone, spray, live)
		liveDump(e, nil, live.IP)
		if victim, err := capVictim(e, "198.51.100.41", automatic); err != nil || victim != live.IP {
			t.Errorf("automatic=%v: victim %q, %v; want the row with an element", automatic, victim, err)
		}
		e = capEngine(t, 0, gone, spray)
		liveDump(e, nil, "203.0.113.41")
		_, err := capVictim(e, "198.51.100.41", automatic)
		if err == nil || !strings.Contains(err.Error(), "no temp entry to evict") {
			t.Errorf("automatic=%v: no row with an element = %v; want no entry to evict", automatic, err)
		}
	}
	e := capEngine(t, 0, owned, gone, live)
	liveDump(e, nil, owned.IP, live.IP)
	if victim, err := capVictim(e, "198.51.100.41", false); err != nil || victim != live.IP {
		t.Errorf("beside an admission row: victim %q, %v; want the row with an element", victim, err)
	}
}

// Durable planning shares the limit decision but keeps its committed victim.
func TestLegacyVictimDurablePlanUsesTheLiveRow(t *testing.T) {
	at := time.Now().Round(0)
	gone := BlockedEntry{IP: "192.0.2.47", ExpiresAt: at.Add(time.Minute)}
	live := BlockedEntry{IP: "192.0.2.48", ExpiresAt: at.Add(time.Hour)}
	e, plans := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 1}, FirewallState{Blocked: []BlockedEntry{gone, live}})
	liveDump(e, nil, live.IP)
	req := ActionRequest{ID: "live-victim", Target: "198.51.100.47", Reason: "fixture", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}
	if _, err := e.BlockIPRequest(req, nil); !errors.Is(err, errBatchPlanStop) {
		t.Fatalf("planning = %v; want the captured plan", err)
	}
	if len(plans.admitted) != 1 || len(plans.admitted[0].Members) != 1 {
		t.Fatalf("plans = %+v; want one member", plans.admitted)
	}
	victims := plans.admitted[0].Members[0].Victims
	if len(victims) != 1 || victims[0] != live {
		t.Fatalf("victims = %+v; want the complete live row", victims)
	}
}

// A partial operator image must not discard rows from the readable family.
func TestLegacyVictimOperatorNeedsAWholeImage(t *testing.T) {
	owned := BlockedEntry{IP: "192.0.2.49", ActionID: "act_owned", ExpiresAt: time.Now().Add(time.Hour)}
	gone := BlockedEntry{IP: "192.0.2.50", ExpiresAt: time.Now().Add(time.Minute)}
	live := BlockedEntry{IP: "192.0.2.51", ExpiresAt: time.Now().Add(time.Hour)}
	e := capEngine(t, 0, owned, gone, live)
	e.cfg.IPv6 = true
	e.setBlocked6 = &nftables.Set{Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr}
	liveDump(e, e.setBlocked6, owned.IP, live.IP)
	if victim, err := capVictim(e, "198.51.100.49", false); err != nil || victim != gone.IP {
		t.Fatalf("operator partial image: victim %q, %v; want the row fallback", victim, err)
	}
}

// A count that could not read every set has no image of the kernel. The
// rows then stand in for it, and the row closest to expiry keeps its turn.
func TestLegacyVictimNeedsAWholeImage(t *testing.T) {
	gone := BlockedEntry{IP: "192.0.2.44", ExpiresAt: time.Now().Add(time.Minute)}
	live := BlockedEntry{IP: "192.0.2.45", ExpiresAt: time.Now().Add(time.Hour)}
	e := capEngine(t, 0, gone, live)
	liveDump(e, e.setBlocked, live.IP)
	if victim, err := capVictim(e, "198.51.100.44", true); err != nil || victim != gone.IP {
		t.Errorf("unread set: victim %q, %v; want the row closest to expiry", victim, err)
	}
	e = capEngine(t, 0, gone, live)
	e.setBlocked6 = &nftables.Set{Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr}
	liveDump(e, e.setBlocked6, live.IP)
	if victim, err := capVictim(e, "198.51.100.44", true); err != nil || victim != gone.IP {
		t.Errorf("one unread family: victim %q, %v; want the row closest to expiry", victim, err)
	}
}

func TestLegacyVictimEmptyImageIsNotAnUnreadImage(t *testing.T) {
	row := BlockedEntry{IP: "192.0.2.52", ExpiresAt: time.Now().Add(time.Hour)}
	state := FirewallState{Blocked: []BlockedEntry{row}}
	e := capEngine(t, 0, row)
	liveDump(e, nil)
	e.mu.Lock()
	defer e.mu.Unlock()
	perm, temp, live, ok := e.livePermTempCountsLocked(state)
	if !ok || perm != 0 || temp != 0 || live == nil || len(live) != 0 {
		t.Fatalf("empty automatic image: %d/%d, %v, %v", perm, temp, live, ok)
	}
	if got := heldRows(state, live); len(got.Blocked) != 0 {
		t.Fatalf("empty image kept rows: %+v", got.Blocked)
	}
	count, live := e.operatorTempCountLocked(state, "")
	if count != 0 || live == nil || len(live) != 0 {
		t.Fatalf("empty operator image: count %d, image %v", count, live)
	}
	if got := heldRows(state, live); len(got.Blocked) != 0 {
		t.Fatalf("empty operator image kept rows: %+v", got.Blocked)
	}
	liveDump(e, e.setBlocked)
	_, _, live, ok = e.livePermTempCountsLocked(state)
	if ok || live != nil {
		t.Fatalf("unread image = %v, ok %v", live, ok)
	}
	if got := heldRows(state, live); len(got.Blocked) != 1 || got.Blocked[0] != row {
		t.Fatalf("unread image lost its row: %+v", got.Blocked)
	}
	count, live = e.operatorTempCountLocked(state, "")
	if count != 1 || live != nil {
		t.Fatalf("unread operator image: count %d, image %v", count, live)
	}
}
