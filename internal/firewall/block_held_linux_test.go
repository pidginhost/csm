//go:build linux

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The held check is retirement's answer reversed, and it changes
// nothing: a block is held while its address has an element that no
// other action's verified row proves. A forward wall step that makes its
// expiry look past, or a family the snapshot cannot read, keeps it held;
// only a removal answers false.
func TestHeldBlockActionsChecksTheKernel(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.60", Reason: "auto", ActionID: "act_held", ExpiresAt: at.Add(time.Hour)},
		{IP: "203.0.113.61", Reason: "auto", ActionID: "act_flushed", ExpiresAt: at.Add(time.Hour)},
		{IP: "203.0.113.62", Reason: "auto", ActionID: "act_stepped", ExpiresAt: at.Add(time.Hour)},
		{IP: "203.0.113.63", Reason: "operator", ExpiresAt: at.Add(2 * time.Hour)},
		{IP: "2001:db8::66", Reason: "auto", ActionID: "act_held6", ExpiresAt: at.Add(time.Hour)},
	}})
	f.live["203.0.113.60"] = time.Hour
	f.live["203.0.113.62"] = 3 * time.Hour
	f.live["203.0.113.63"] = 2 * time.Hour
	f.live["2001:db8::66"] = time.Hour
	bootReads := 0
	f.e.SetBootClock(func() (string, time.Duration, error) {
		bootReads++
		return leaseBootA, time.Hour, nil
	})
	clock := &leaseSteps{wall: at, elapsed: at}
	f.e.leaseClock = clock.read
	writes := f.countWrites(t)
	before, err := os.ReadFile(filepath.Join(f.e.statePath, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	asked := []BlockAction{
		{Action: "act_held", IP: "203.0.113.60"},
		{Action: "act_flushed", IP: "203.0.113.61"},
		{Action: "act_stepped", IP: "203.0.113.62"},
		{Action: "act_replaced", IP: "203.0.113.63"},
		{Action: "act_unblocked", IP: "203.0.113.64"},
		{Action: "act_held6", IP: "2001:DB8::66"},
	}
	held, err := f.e.HeldBlockActions(asked)
	want := []bool{true, false, true, false, false, true}
	if err != nil || len(held) != len(want) {
		t.Fatalf("held = %v, %v", held, err)
	}
	for i := range want {
		if held[i] != want[i] {
			t.Errorf("%s held = %t, want %t", asked[i].Action, held[i], want[i])
		}
	}
	if *writes != 0 {
		t.Fatalf("the held check made %d state writes", *writes)
	}
	if rows := storedBlockedActions(t, f.e.statePath); len(rows) != 5 || rows["203.0.113.61"] != "act_flushed" {
		t.Fatalf("stored rows = %v; want every row kept", rows)
	}
	clock.wall = at.Add(2 * time.Hour)
	if held, err = f.e.HeldBlockActions(asked[2:3]); err != nil || !reflect.DeepEqual(held, []bool{true}) {
		t.Fatalf("a forward step released a live element: %v %v", held, err)
	}
	after, err := os.ReadFile(filepath.Join(f.e.statePath, "state.json"))
	if err != nil || string(after) != string(before) || *writes != 0 || f.sends != 0 {
		t.Fatalf("held check mutated state or kernel: %v, writes %d, sends %d", err, *writes, f.sends)
	}
	if bootReads != 0 || f.e.leaseResumed {
		t.Fatalf("held check entered removal checkpoint: boot reads %d, resumed %t", bootReads, f.e.leaseResumed)
	}
	if _, statErr := os.Stat(filepath.Join(f.e.statePath, leaseCheckpointFile)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("held check took a removal checkpoint: %v", statErr)
	}
	f.e.cfg.IPv6 = false
	if held, err = f.e.HeldBlockActions([]BlockAction{{Action: "act_gone6", IP: "2001:db8::67"}}); err != nil || len(held) != 1 || !held[0] {
		t.Fatalf("an unreadable family = %v, %v; want held", held, err)
	}
	f.e.cfg.IPv6, f.e.setBlocked6 = true, nil
	if held, err = f.e.HeldBlockActions([]BlockAction{{Action: "act_gone6", IP: "2001:db8::67"}}); err != nil || !reflect.DeepEqual(held, []bool{true}) {
		t.Fatalf("a missing IPv6 set = %v, %v; want held", held, err)
	}
	if held, err = f.e.HeldBlockActions(nil); err != nil || len(held) != 0 {
		t.Fatalf("an empty check = %v, %v", held, err)
	}
}

// An error answers nothing: a list over the bound, a malformed address,
// a failed dump or held confirm batches.
func TestHeldBlockActionsRefusesTheWholeCall(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	one := []BlockAction{{Action: "act_one", IP: "203.0.113.5"}}
	tooMany := make([]BlockAction, MaxHeldBlockActions+1)
	for i := range tooMany {
		tooMany[i] = one[0]
	}
	check := func(name string, asked []BlockAction, want error) {
		t.Helper()
		held, err := f.e.HeldBlockActions(asked)
		if err == nil || held != nil || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: %v, %v; want no answer and error %v", name, held, err, want)
		}
	}
	check("too many", tooMany, nil)
	check("not an address", []BlockAction{{Action: "act_one", IP: "203.0.113.0/24"}}, nil)
	f.err = errors.New("fixture dump failure")
	check("failed dump", one, f.err)
	f.err = nil
	f.e.HoldBlockBatches(true)
	check("held batches", one, ErrConfirmPending)
	f.e.HoldBlockBatches(false)
	if held, err := f.e.HeldBlockActions(one); err != nil || len(held) != 1 || held[0] {
		t.Fatalf("after the hold: %v, %v", held, err)
	}
}

// An unreadable state file must remain in place, so a later held check
// cannot mistake a failed read for an empty state after recovery renamed it.
func TestHeldBlockActionsLeavesUnreadableStateUntouched(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	path := filepath.Join(f.e.statePath, "state.json")
	bad := []byte(`{"blocked":`)
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	writes := f.countWrites(t)
	for range 2 {
		held, err := f.e.HeldBlockActions([]BlockAction{{Action: "act_one", IP: "203.0.113.5"}})
		if !errors.Is(err, ErrBlockBatchState) || held != nil {
			t.Errorf("unreadable state answered a held check: %v, %v", held, err)
		}
		if data, readErr := os.ReadFile(path); readErr != nil || string(data) != string(bad) {
			t.Errorf("held check changed unreadable state: %q, %v", data, readErr)
		}
	}
	entries, err := os.ReadDir(f.e.statePath)
	if err != nil || len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("held check changed the state directory: %v, %v", entries, err)
	}
	if *writes != 0 || f.sends != 0 || f.e.stateCache != nil || f.e.StateSetAside() != "" {
		t.Fatalf("held check entered state recovery: writes %d, sends %d, cache %+v, aside %q", *writes, f.sends, f.e.stateCache, f.e.StateSetAside())
	}
}

// Aliased imported rows cannot prove each other gone. A different action
// is clear only while another row actually proves the live element.
func TestHeldBlockActionsAliasesAndProof(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	rows := []BlockedEntry{
		{IP: "2001:db8::70", Automatic: true, ExpiresAt: f.at.Add(time.Hour)},
		{IP: "2001:DB8::70", Source: "other", Automatic: true, ExpiresAt: f.at.Add(time.Hour)},
	}
	if retireID(rows[0]) == retireID(rows[1]) {
		t.Fatal("fixture imports must have distinct identities")
	}
	writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: rows})
	f.live["2001:db8::70"] = time.Hour
	asked := []BlockAction{{Action: retireID(rows[0]), IP: rows[0].IP}, {Action: retireID(rows[1]), IP: rows[1].IP}, {Action: "act_other", IP: rows[0].IP}}
	if held, err := f.e.HeldBlockActions(asked); err != nil || !reflect.DeepEqual(held, []bool{true, true, false}) {
		t.Fatalf("aliased imports: %v %v", held, err)
	}
	for _, why := range []string{"unverified", "timeout"} {
		t.Run(why, func(t *testing.T) {
			row := BlockedEntry{IP: "203.0.113.71", ActionID: "act_replacement", ExpiresAt: f.at.Add(time.Hour)}
			g := newBatchFixture(t, FirewallState{})
			g.live[row.IP] = 2 * time.Hour
			if why == "unverified" {
				g.live[row.IP], row.Unverified = time.Hour, true
			}
			writeEngineStateFile(t, g.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
			if held, err := g.e.HeldBlockActions([]BlockAction{{Action: "act_old", IP: row.IP}}); err != nil || !reflect.DeepEqual(held, []bool{true}) {
				t.Fatalf("unproven replacement released a block: %v %v", held, err)
			}
		})
	}
}
