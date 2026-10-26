//go:build linux

package firewall

import (
	"errors"
	"testing"
	"time"

	"github.com/google/nftables"
)

// An automatic block never replaces a row an admission action wrote, even
// when its kernel element is gone or its attempt is unproven: admission
// owns that address until the owner retires the row (design C8). The block
// is already in place as far as the legacy path is concerned. A row no
// action wrote still reaches the block path when its element is gone.
func TestAutomaticBlockNeverReplacesAnAdmissionRow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		action     string
		unverified bool
		want       BlockOutcome
	}{
		{"verified_action", "act_owner", false, BlockOutcomeNoop},
		{"unverified_action", "act_owner", true, BlockOutcomeNoop},
		{"legacy_row", "", false, BlockOutcomeDryRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{
				cfg:           &FirewallConfig{Enabled: true},
				statePath:     t.TempDir(),
				setBlocked:    &nftables.Set{Name: "blocked_ips"},
				dryRunEnabled: func() bool { return true },
				liveBlockLookup: func(*nftables.Set, []byte) (bool, error) {
					return false, nil
				},
			}
			row := BlockedEntry{IP: "192.0.2.44", Reason: "owner block", BlockedAt: time.Now().Add(-time.Minute),
				ExpiresAt: time.Now().Add(time.Hour), ActionID: tc.action, Unverified: tc.unverified}
			writeEngineStateFile(t, e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
			outcome, err := e.BlockIPOutcome(row.IP, "repeat finding", time.Hour)
			if err != nil || outcome != tc.want {
				t.Fatalf("outcome = %q, %v; want %q", outcome, err, tc.want)
			}
			e.mu.Lock()
			got, _ := blockedStateEntry(e.loadStateFile(), row.IP)
			e.mu.Unlock()
			if got.ActionID != tc.action || got.Reason != row.Reason {
				t.Fatalf("row = %+v", got)
			}
		})
	}
}

// At the temporary cap an automatic block never evicts a row an admission
// action wrote (design C8); it is refused when no other row can make room.
// Nor does an operator's block: it is added above the limit instead.
func TestAutomaticBlockNeverEvictsAnAdmissionRow(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{DenyTempIPLimit: 1}, setBlocked: namedIPv4Set("blocked_ips")}
		state := FirewallState{Blocked: []BlockedEntry{{IP: "192.0.2.31", ExpiresAt: time.Now().Add(time.Hour), ActionID: "act_cap"}}}
		if err := e.saveState(&state); err != nil {
			t.Fatal(err)
		}
		if _, err := e.validateBlockIP("198.51.100.31", time.Hour, automatic); automatic != (err != nil) {
			t.Fatalf("automatic=%v: validation = %v; want a refusal only for an automatic block", automatic, err)
		}
		e.mu.Lock()
		victim, ok := e.evictionVictimLocked(state, "", automatic)
		e.mu.Unlock()
		if ok {
			t.Fatalf("automatic=%v: victim = %q", automatic, victim)
		}
	}
}

// Permanent promotion never rewrites a row an admission action wrote:
// admission refuses permanent blocks until strike memory exists, and a
// rewrite would drop the action that owns the block (design C8).
func TestPromoteToPermanentBlockRefusesAdmissionRows(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	row := BlockedEntry{IP: "203.0.113.10", Reason: "owner block", BlockedAt: f.at, ExpiresAt: f.at.Add(time.Hour), ActionID: "act_owner"}
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
	writes := f.countWrites(t)
	err := f.e.PromoteToPermanentBlock(row.IP, "escalation")
	if !errors.Is(err, ErrAdmissionOwnsBlock) {
		t.Fatalf("promotion = %v, want ErrAdmissionOwnsBlock", err)
	}
	rows := f.storedRows(t)
	if f.sends != 0 || *writes != 0 || len(rows) != 1 || !SameBlockedEntry(rows[row.IP], row) {
		t.Fatalf("refused promotion changed state or kernel: rows %+v, sends %d, writes %d", rows, f.sends, *writes)
	}
}
