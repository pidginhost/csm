//go:build linux

package firewall

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// TestBlockIPOutcome_DenyLimitCountsFromLiveSet asserts the temporary
// deny-limit gate counts entries from the live nft set rather than the
// possibly-stale state.json cache.
//
// Scenario: state.json says 3 temp entries (one stale), live nft has
// 2. DenyTempIPLimit is 3. With the old behaviour the third entry
// (stale state) would push temp>=cap and refuse the new block; with
// the live-counted fix the cap sees 2 and admits the block.
func TestBlockIPOutcome_DenyLimitCountsFromLiveSet(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true, DenyTempIPLimit: 3},
		statePath:     dir,
		dryRunEnabled: func() bool { return true },
		liveBlockLookup: func(_ *nftables.Set, _ []byte) (bool, error) {
			// new IP is not live yet; allow validateBlockIP to proceed.
			return false, nil
		},
		liveBlockCounts: func() (int, int, error) {
			return 0, 2, nil
		},
	}
	// Seed state.json with 3 stale temp blocks to exceed the cap if
	// the count was sourced from state.
	_ = e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.1", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	_ = e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.2", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	_ = e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.3", Reason: "x", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

	outcome, err := e.BlockIPOutcome("198.51.100.4", "new", time.Hour)
	if err != nil {
		t.Fatalf("BlockIPOutcome: %v", err)
	}
	if outcome != BlockOutcomeDryRun {
		t.Errorf("outcome = %q, want %q (cap should admit when live count is below cap)", outcome, BlockOutcomeDryRun)
	}
}

// TestBlockIPOutcome_DenyLimitTripsOnLiveCount also confirms the gate
// still fires when the live count is at the cap, so we did not
// accidentally turn the cap off.
func TestBlockIPOutcome_DenyLimitTripsOnLiveCount(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{
		cfg:           &FirewallConfig{Enabled: true, DenyTempIPLimit: 2},
		statePath:     dir,
		dryRunEnabled: func() bool { return true },
		liveBlockLookup: func(_ *nftables.Set, _ []byte) (bool, error) {
			return false, nil
		},
		liveBlockCounts: func() (int, int, error) {
			return 0, 2, nil
		},
	}

	_, err := e.BlockIPOutcome("198.51.100.5", "new", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "temporary deny limit reached") {
		t.Fatalf("expected temporary deny limit refusal, got %v", err)
	}
}

func TestCountLiveBlockElementsUsesStateClassification(t *testing.T) {
	stateTempByIP := blockedStateTempByIP(FirewallState{Blocked: []BlockedEntry{
		{IP: "198.51.100.10", BlockedAt: time.Now()},
		{IP: "2001:db8::1", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
	}})

	elements := []nftables.SetElement{
		// CSM state says permanent, even if nft reports timeout attrs.
		{Key: net.ParseIP("198.51.100.10").To4(), Timeout: time.Hour, Expires: 30 * time.Minute},
		// No CSM state: inherited/default expiration still means temporary.
		{Key: net.ParseIP("198.51.100.20").To4(), Expires: 30 * time.Minute},
		// CSM state says temporary, even if the live attrs are absent.
		{Key: net.ParseIP("2001:db8::1").To16()},
		// No state and no expiration attrs means permanent.
		{Key: net.ParseIP("2001:db8::2").To16()},
	}

	perm, temp := countLiveBlockElements(elements, stateTempByIP)
	if perm != 2 || temp != 2 {
		t.Fatalf("countLiveBlockElements = perm %d temp %d, want perm 2 temp 2", perm, temp)
	}
}

func TestCountLiveBlockElementsUsesKernelForUnverifiedRows(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expiresAt  time.Time
		timeout    time.Duration
		perm, temp int
	}{
		{"timed_intent_permanent_element", time.Now().Add(time.Hour), 0, 1, 0},
		{"permanent_intent_timed_element", time.Time{}, time.Hour, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.10", ExpiresAt: tc.expiresAt, Unverified: true}}}
			elements := []nftables.SetElement{{Key: net.ParseIP("203.0.113.10").To4(), Timeout: tc.timeout}}
			perm, temp := countLiveBlockElements(elements, blockedStateTempByIP(state))
			if perm != tc.perm || temp != tc.temp {
				t.Fatalf("counts = %d permanent, %d temporary; want %d and %d from the kernel", perm, temp, tc.perm, tc.temp)
			}
		})
	}
}

func TestReplacementCountsUseKernelForUnverifiedRows(t *testing.T) {
	for _, tc := range []struct {
		name                                        string
		stateTimeout, kernelTimeout, requestTimeout time.Duration
		wantVictim                                  string
		wantError                                   bool
	}{
		{"temporary_replaces_temporary", 0, time.Hour, time.Hour, "", false},
		{"temporary_replaces_permanent", time.Hour, 0, time.Hour, "203.0.113.40", false},
		{"permanent_replaces_permanent", time.Hour, 0, 0, "", false},
		{"permanent_replaces_temporary_at_cap", 0, time.Hour, 0, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := FirewallState{Blocked: []BlockedEntry{
				{IP: "203.0.113.10", ActionID: "act_unknown", Unverified: true},
				{IP: "203.0.113.40", Reason: "operator"},
			}}
			f := newBatchFixture(t, state)
			if tc.stateTimeout > 0 {
				state.Blocked[0].ExpiresAt = f.at.Add(tc.stateTimeout)
			}
			otherTimeout := time.Duration(0)
			if tc.kernelTimeout == 0 {
				otherTimeout = time.Hour
				state.Blocked[1].ExpiresAt = f.at.Add(otherTimeout)
			}
			f.live["203.0.113.10"], f.live["203.0.113.40"] = tc.kernelTimeout, otherTimeout
			f.e.cfg.DenyIPLimit, f.e.cfg.DenyTempIPLimit = 1, 1
			f.e.liveBlockCounts = func() (int, int, error) { return 1, 1, nil }
			f.e.liveBlockLookup = func(*nftables.Set, []byte) (bool, error) { return true, nil }
			f.e.mu.Lock()
			_, _, existing, victim, err := f.e.blockIPTargetFromState("203.0.113.10", tc.requestTimeout, false, state)
			f.e.mu.Unlock()
			if (err != nil) != tc.wantError || existing || victim != tc.wantVictim {
				t.Fatalf("replacement = existing %t, victim %q, error %v; want victim %q, error %t", existing, victim, err, tc.wantVictim, tc.wantError)
			}
		})
	}
}

func TestPromoteToPermanentBlockRefusesUnverifiedRows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		expiry time.Duration
	}{{"permanent", 0}, {"timed", time.Hour}, {"expired", -time.Hour}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			row := BlockedEntry{IP: "203.0.113.10", ActionID: "act_unknown", Unverified: true}
			if tc.expiry != 0 {
				row.ExpiresAt = f.at.Add(tc.expiry)
			}
			writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
			writes := f.countWrites(t)
			if err := f.e.PromoteToPermanentBlock(row.IP, "escalation"); err == nil {
				t.Fatal("an unverified attempt was promoted to a permanent block")
			}
			rows := f.storedRows(t)
			if f.sends != 0 || *writes != 0 || len(rows) != 1 || !SameBlockedEntry(rows[row.IP], row) {
				t.Fatalf("refused promotion changed state or kernel: rows %+v, sends %d, writes %d", rows, f.sends, *writes)
			}
		})
	}
}
