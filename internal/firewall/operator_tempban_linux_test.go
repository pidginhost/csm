//go:build linux

package firewall

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func operatorRow(ip string, at time.Time, left time.Duration) BlockedEntry {
	return BlockedEntry{IP: ip, Reason: "operator: abuse report", BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(left)}
}

// An automatic block never picks an operator's temporary block or a row
// saved before rows carried the automatic flag; an operator block still
// may. This holds on every engine the picker runs on.
func TestEvictionVictimSparesOperatorRowsForAutomaticBlocks(t *testing.T) {
	at := time.Now().Round(0)
	operator := operatorRow("192.0.2.110", at, time.Minute)
	unflagged := BlockedEntry{IP: "192.0.2.111", Reason: "CSM auto-block: WAF attack", BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(2 * time.Minute)}
	automatic := automaticRow("198.51.100.110", "CSM auto-block: WAF attack", at, time.Hour)

	legacy := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}, expiryClock: func() time.Time { return at }}
	unproven := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}, expiryClock: func() time.Time { return at }}
	unproven.SetBlockActionsUnproven(errors.New("ledger unreadable"))
	durable, _ := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	for name, e := range map[string]*Engine{"legacy": legacy, "unproven ledger": unproven, "durable": durable} {
		e.mu.Lock()
		auto, autoOK := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{operator, unflagged, automatic}}, "", true)
		manual, manualOK := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{operator, unflagged, automatic}}, "", false)
		none, noneOK := e.evictionVictimLocked(FirewallState{Blocked: []BlockedEntry{operator, unflagged}}, "", true)
		e.mu.Unlock()
		if !autoOK || auto != automatic.IP {
			t.Fatalf("%s: automatic block picked %q %t, want the automatic row %s", name, auto, autoOK, automatic.IP)
		}
		if !manualOK || manual != operator.IP {
			t.Fatalf("%s: operator block picked %q %t, want the soonest row %s", name, manual, manualOK, operator.IP)
		}
		if noneOK {
			t.Fatalf("%s: automatic block picked %q among operator and unflagged rows only", name, none)
		}
	}
}

// At the cap an automatic block replaces the automatic row even when an
// operator's temporary block ends sooner.
func TestAutomaticBlockReplacesAutomaticRowNotOperatorBlock(t *testing.T) {
	at := time.Now()
	rows := []BlockedEntry{
		operatorRow("192.0.2.112", at, time.Minute),
		automaticRow("198.51.100.112", "CSM auto-block: WAF attack", at, time.Hour),
	}
	e := sprayCapEngine(t, rows)
	if _, err := e.BlockIPOutcome("203.0.113.112", "CSM auto-block: WAF attack", time.Hour); err != nil {
		t.Fatalf("block: %v", err)
	}
	assertEvicted(t, e, rows, "198.51.100.112", "203.0.113.112")
}

// An operator's temporary block may still replace another operator's
// temporary block at the cap.
func TestOperatorBlockReplacesOperatorBlock(t *testing.T) {
	at := time.Now()
	rows := []BlockedEntry{
		operatorRow("192.0.2.113", at, time.Minute),
		automaticRow("198.51.100.113", "CSM auto-block: WAF attack", at, time.Hour),
	}
	e := sprayCapEngine(t, rows)
	if err := e.BlockIPForce("203.0.113.113", "operator: abuse report", time.Hour); err != nil {
		t.Fatalf("block: %v", err)
	}
	assertEvicted(t, e, rows, "192.0.2.113", "203.0.113.113")
}

// With only operator and unflagged rows at the cap an automatic block is
// refused and the saved state is unchanged.
func TestAutomaticBlockRefusedWhenOnlyOperatorBlocksRemain(t *testing.T) {
	at := time.Now()
	rows := []BlockedEntry{
		operatorRow("192.0.2.114", at, time.Minute),
		{IP: "192.0.2.115", Reason: "CSM auto-block: WAF attack", BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(time.Hour)},
	}
	e := sprayCapEngine(t, rows)
	_, err := e.BlockIPOutcome("203.0.113.114", "CSM auto-block: WAF attack", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "no temp entry to evict") {
		t.Fatalf("block err = %v, want the limit refusal", err)
	}
	state := readRawFirewallState(t, e)
	for _, row := range rows {
		if _, ok := blockedStateEntry(state, row.IP); !ok {
			t.Fatalf("row %s left the state: %+v", row.IP, state.Blocked)
		}
	}
	if _, ok := blockedStateEntry(state, "203.0.113.114"); ok {
		t.Fatalf("refused block was saved: %+v", state.Blocked)
	}
}

// Normalizing aliases keeps the longest lifetime without letting an
// automatic alias erase the ownership of an operator's shorter block.
func TestAutomaticBlockSparesDuplicateOwnership(t *testing.T) {
	at := time.Now()
	for _, operatorIP := range []string{"192.0.2.116", "::ffff:192.0.2.116"} {
		for _, reverse := range []bool{false, true} {
			for _, flagged := range []bool{false, true} {
				rows := []BlockedEntry{
					operatorRow(operatorIP, at, time.Minute),
					automaticRow("192.0.2.116", "automatic", at, time.Hour),
				}
				rows[0].Automatic = flagged
				if reverse {
					rows[0], rows[1] = rows[1], rows[0]
				}
				e := capEngine(t, 1, rows...)
				victim, err := capVictim(e, "203.0.113.116", true)
				if flagged {
					if err != nil || victim != "192.0.2.116" {
						t.Fatalf("automatic aliases: victim=%q err=%v", victim, err)
					}
				} else if err == nil || victim != "" {
					t.Fatalf("operator alias %s reverse=%v: victim=%q err=%v", operatorIP, reverse, victim, err)
				}
				state := e.loadStateFile()
				if len(state.Blocked) != 1 || state.Blocked[0].Automatic != flagged || !state.Blocked[0].ExpiresAt.Equal(at.Add(time.Hour)) {
					t.Fatalf("normalized ownership or expiry changed: %+v", state.Blocked)
				}
			}
		}
	}
}
