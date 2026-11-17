//go:build linux

package firewall

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// capEngine is an engine at a temporary limit of one over the saved rows.
// Its live count answers temp temporary blocks, or fails when temp is
// negative so the rows stand in for the count.
func capEngine(t *testing.T, temp int, rows ...BlockedEntry) *Engine {
	t.Helper()
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{DenyTempIPLimit: 1}, setBlocked: namedIPv4Set("blocked_ips")}
	e.liveBlockCounts = func() (int, int, error) {
		if temp < 0 {
			return 0, 0, errors.New("live counts unavailable")
		}
		return 0, temp, nil
	}
	state := FirewallState{Blocked: rows}
	if err := e.saveState(&state); err != nil {
		t.Fatal(err)
	}
	return e
}

// capVictim plans an hour's block of ip and returns the block it replaces.
func capVictim(e *Engine, ip string, automatic bool) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _, _, victim, err := e.blockIPTarget(ip, time.Hour, automatic)
	return victim, err
}

// A saved temporary block of an address family the firewall does not
// filter holds no kernel element. At the cap it is never the block a new
// one replaces, and it fills no slot when the rows stand in for the
// kernel's count.
func TestLegacyCapIgnoresRowsOfAnUnfilteredFamily(t *testing.T) {
	v6 := BlockedEntry{IP: "2001:db8::31", Automatic: true, ExpiresAt: time.Now().Add(time.Minute)}
	v4 := BlockedEntry{IP: "192.0.2.31", Automatic: true, ExpiresAt: time.Now().Add(time.Hour)}
	for _, automatic := range []bool{false, true} {
		victim, err := capVictim(capEngine(t, 1, v6, v4), "198.51.100.31", automatic)
		if err != nil || victim != v4.IP {
			t.Errorf("automatic=%v: victim %q, %v; want the IPv4 row", automatic, victim, err)
		}
		victim, err = capVictim(capEngine(t, -1, v6), "198.51.100.31", automatic)
		if err != nil || victim != "" {
			t.Errorf("automatic=%v: victim %q, %v; want room below the cap", automatic, victim, err)
		}
		_, err = capVictim(capEngine(t, 1, v6), "198.51.100.31", automatic)
		if err == nil || !strings.Contains(err.Error(), "no temp entry to evict") {
			t.Errorf("automatic=%v: a full set with no row to replace = %v; want no entry to evict", automatic, err)
		}
	}
}

// An operator's block beside admission rows counts the other occupants.
// When the rows stand in for an unreadable set, a row of an unfiltered
// family is not one of them.
func TestLegacyOperatorCapIgnoresRowsOfAnUnfilteredFamily(t *testing.T) {
	e := capEngine(t, 0,
		BlockedEntry{IP: "192.0.2.32", ExpiresAt: time.Now().Add(time.Hour), ActionID: "act_cap"},
		BlockedEntry{IP: "2001:db8::32", Automatic: true, ExpiresAt: time.Now().Add(time.Minute)})
	e.liveBlockedDump = func(*nftables.Set) ([]nftables.SetElement, error) { return nil, errors.New("dump failed") }
	if victim, err := capVictim(e, "198.51.100.32", false); err != nil || victim != "" {
		t.Fatalf("victim %q, %v; want room below the cap", victim, err)
	}
}

// A missing IPv4 set must not leave an unusable victim for an IPv6 block.
func TestLegacyCapSkipsANilIPv4Set(t *testing.T) {
	v4 := BlockedEntry{IP: "192.0.2.34", Automatic: true, ExpiresAt: time.Now().Add(time.Minute)}
	v6 := BlockedEntry{IP: "2001:db8::34", Automatic: true, ExpiresAt: time.Now().Add(time.Hour)}
	for _, temp := range []int{1, -1} {
		e := capEngine(t, temp, v4, v6)
		e.setBlocked = nil
		e.setBlocked6 = &nftables.Set{Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr}
		if victim, err := capVictim(e, "2001:db8::35", true); err != nil || victim != v6.IP {
			t.Errorf("count %d: victim %q, %v; want the usable IPv6 row", temp, victim, err)
		}
	}
}

// With IPv6 filtered the row keeps its slot and its turn as the victim.
func TestLegacyCapKeepsRowsOfAFilteredFamily(t *testing.T) {
	v6 := BlockedEntry{IP: "2001:db8::33", Automatic: true, ExpiresAt: time.Now().Add(time.Minute)}
	v4 := BlockedEntry{IP: "192.0.2.33", Automatic: true, ExpiresAt: time.Now().Add(time.Hour)}
	for _, temp := range []int{1, -1} {
		e := capEngine(t, temp, v6, v4)
		e.setBlocked6 = &nftables.Set{Name: "blocked_ips6", KeyType: nftables.TypeIP6Addr}
		if victim, err := capVictim(e, "198.51.100.33", true); err != nil || victim != v6.IP {
			t.Fatalf("live count %d: victim %q, %v; want the IPv6 row", temp, victim, err)
		}
	}
}
