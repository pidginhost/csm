//go:build linux

package firewall

import (
	"errors"
	"testing"
	"time"
)

const loginSprayTestTTL = 720 * time.Hour

// sprayCapEngine is a legacy engine whose temporary set is full with rows.
func sprayCapEngine(t *testing.T, rows []BlockedEntry) *Engine {
	t.Helper()
	conn, _ := nftConnReturningErrsThenOK(t)
	e := newBlockedSetWireTestEngine(t, conn)
	e.cfg.DenyTempIPLimit = len(rows)
	e.liveBlockCounts = func() (int, int, error) { return 0, len(rows), nil }
	writeRawFirewallState(t, e, FirewallState{Blocked: rows})
	return e
}

func sprayRow(ip string, at time.Time, left time.Duration) BlockedEntry {
	return BlockedEntry{IP: ip, Reason: "CSM auto-block: SMTP brute force from " + ip, BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(left), Automatic: true, LoginSpray: true}
}

func automaticRow(ip, reason string, at time.Time, left time.Duration) BlockedEntry {
	return BlockedEntry{IP: ip, Reason: reason, BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(left), Automatic: true}
}

// assertEvicted checks that exactly victim left the state, every other
// prior row stayed, and target holds the new block.
func assertEvicted(t *testing.T, e *Engine, prior []BlockedEntry, victim, target string) BlockedEntry {
	t.Helper()
	state := readRawFirewallState(t, e)
	for _, row := range prior {
		_, kept := blockedStateEntry(state, row.IP)
		if kept == (row.IP == victim) {
			t.Fatalf("row %s kept = %t, want only %s evicted: %+v", row.IP, kept, victim, state.Blocked)
		}
	}
	row, ok := blockedStateEntry(state, target)
	if !ok {
		t.Fatalf("new block %s missing: %+v", target, state.Blocked)
	}
	return row
}

// At the cap a new WAF block takes the place of the spray row that ends
// first, not the 24h brute row or the WAF row, which end sooner.
func TestEvictionPrefersLoginSprayRows(t *testing.T) {
	at := time.Now()
	rows := []BlockedEntry{
		sprayRow("192.0.2.90", at, 29*24*time.Hour),
		sprayRow("192.0.2.91", at, 10*24*time.Hour),
		sprayRow("192.0.2.92", at, 20*24*time.Hour),
		automaticRow("198.51.100.90", "CSM auto-block: Mail auth brute force", at, time.Hour),
		automaticRow("203.0.113.90", "CSM auto-block: WAF attack", at, 2*time.Hour),
	}
	e := sprayCapEngine(t, rows)
	if _, err := e.BlockIPOutcome("203.0.113.91", "CSM auto-block: WAF attack", time.Hour); err != nil {
		t.Fatalf("block: %v", err)
	}
	if row := assertEvicted(t, e, rows, "192.0.2.91", "203.0.113.91"); row.LoginSpray {
		t.Fatalf("WAF row tagged as spray: %+v", row)
	}
}

// With no spray row the soonest-ending row goes, as before.
func TestEvictionFallsBackWithoutLoginSprayRows(t *testing.T) {
	at := time.Now()
	rows := []BlockedEntry{
		automaticRow("203.0.113.92", "CSM auto-block: WAF attack", at, 2*time.Hour),
		automaticRow("198.51.100.92", "CSM auto-block: Mail auth brute force", at, time.Hour),
	}
	e := sprayCapEngine(t, rows)
	if _, err := e.BlockIPOutcome("203.0.113.93", "CSM auto-block: WAF attack", time.Hour); err != nil {
		t.Fatalf("block: %v", err)
	}
	assertEvicted(t, e, rows, "198.51.100.92", "203.0.113.93")
}

// A spray block into a cap full of spray rows replaces the one that ends
// first, and its own row carries the tag.
func TestEvictionLoginSprayIntoFullSprayCap(t *testing.T) {
	at := time.Now()
	rows := []BlockedEntry{
		sprayRow("192.0.2.94", at, 29*24*time.Hour),
		sprayRow("192.0.2.95", at, 3*24*time.Hour),
		sprayRow("192.0.2.96", at, 20*24*time.Hour),
	}
	e := sprayCapEngine(t, rows)
	req := ActionRequest{Operation: "block", Target: "198.51.100.96", Reason: "CSM auto-block: SMTP brute force", TTL: loginSprayTestTTL, Automatic: true, Actor: "daemon", LoginSpray: true}
	if _, err := e.BlockIPRequest(req, nil); err != nil {
		t.Fatalf("block: %v", err)
	}
	if row := assertEvicted(t, e, rows, "192.0.2.95", "198.51.100.96"); !row.LoginSpray || !row.ExpiresAt.Equal(e.expiryClock().Add(loginSprayTestTTL)) {
		t.Fatalf("new spray row = %+v, want tagged, %s long", row, loginSprayTestTTL)
	}
}

// A spray row an unproven attempt or an admission action wrote is never
// chosen, so the preference cannot reach a row the old rule protects.
func TestEvictionLoginSprayKeepsExclusions(t *testing.T) {
	at := time.Now().Round(0)
	unverified := sprayRow("192.0.2.97", at, time.Minute)
	unverified.ActionID, unverified.Unverified = "act_unknown", true
	owned := sprayRow("192.0.2.98", at, 2*time.Minute)
	owned.ActionID = "act_owner"
	brute := automaticRow("198.51.100.97", "CSM auto-block: Mail auth brute force", at, time.Hour)
	eligible := sprayRow("203.0.113.97", at, 20*24*time.Hour)

	legacy := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}, expiryClock: func() time.Time { return at }}
	unproven := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}, expiryClock: func() time.Time { return at }}
	unproven.SetBlockActionsUnproven(errors.New("ledger unreadable"))
	for name, e := range map[string]*Engine{"legacy": legacy, "unproven ledger": unproven} {
		for _, automatic := range []bool{false, true} {
			e.mu.Lock()
			victim, ok := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{unverified, owned, brute, eligible}}, "", automatic)
			fallback, fallbackOK := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{unverified, owned, brute}}, "", automatic)
			e.mu.Unlock()
			if !ok || victim != eligible.IP || !fallbackOK || fallback != brute.IP {
				t.Fatalf("%s automatic=%t: victims %q %t and %q %t, want %s then %s", name, automatic, victim, ok, fallback, fallbackOK, eligible.IP, brute.IP)
			}
		}
	}

	// Under the durable lifecycle the policy overlay holds a spray row whose
	// attempt is unsettled or failed.
	held := sprayRow("192.0.2.99", at, time.Minute)
	held.ActionID = "unsettled"
	for _, mark := range []string{"unverified", "failed"} {
		e, _ := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
		if mark == "unverified" {
			e.unverifiedBlockActions = map[string]bool{held.ActionID: true}
		} else {
			e.failedBlockActions = map[string]bool{held.ActionID: true}
		}
		e.mu.Lock()
		victim, ok := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{held, brute}}, "", false)
		e.mu.Unlock()
		if !ok || victim != brute.IP {
			t.Fatalf("durable %s: victim %q %t, want %s", mark, victim, ok, brute.IP)
		}
	}
}

// Only an automatic timed request tags its row: an operator block and a
// permanent block never do, whatever the request says.
func TestBlockRequestTagsLoginSprayRow(t *testing.T) {
	for _, tc := range []struct {
		name      string
		automatic bool
		spray     bool
		ttl       time.Duration
		want      bool
	}{
		{"automatic timed spray block", true, true, loginSprayTestTTL, true},
		{"automatic timed other block", true, false, time.Hour, false},
		{"operator timed block", false, true, loginSprayTestTTL, false},
		{"automatic permanent block", true, true, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := nftConnReturningErrsThenOK(t)
			e := newBlockedSetWireTestEngine(t, conn)
			writeRawFirewallState(t, e, FirewallState{})
			req := ActionRequest{Operation: "block", Target: "192.0.2.100", Reason: "CSM auto-block: SMTP brute force", TTL: tc.ttl, Automatic: tc.automatic, Actor: "daemon", LoginSpray: tc.spray}
			if _, err := e.BlockIPRequest(req, nil); err != nil {
				t.Fatalf("block: %v", err)
			}
			row, ok := blockedStateEntry(readRawFirewallState(t, e), req.Target)
			if !ok || row.LoginSpray != tc.want {
				t.Fatalf("row = %+v, %t; want spray tag %t", row, ok, tc.want)
			}
		})
	}
}
